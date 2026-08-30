"""Persistent configuration and secret storage for PBP Monitoring."""

from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken


TARGET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
# Directory names below the evidence volume. Matches the Web UI component
# pattern so a queued deletion can never name a path the dashboard cannot serve.
SAFE_RUN_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
# Sentinel for "every firewall" / "every run". It cannot collide with a real
# directory name because SAFE_RUN_COMPONENT rejects it.
ALL_RUNS = "*"
PBKDF2_ITERATIONS = 600_000

DEFAULT_SETTINGS: dict[str, str] = {
    "poll_seconds": "5",
    "max_monitor_seconds": "900",
    "incident_idle_ttl_seconds": "300",
    "recovery_threshold": "40",
    "low_samples_to_stop": "3",
    "request_timeout": "15",
    "max_session_lookups": "10",
    "session_retry_seconds": "5",
    "large_session_min_kb": "1048576",
    "large_session_min_age_seconds": "600",
    "generate_html_report": "true",
    "generate_text_export": "true",
    "syslog_fresh_seconds": "300",
    "target_check_hours": "24",
    "webhook_url": "",
}


def dp_core_identity(device_identity: dict[str, str] | None) -> str | None:
    """Return the model and PAN-OS release a core map was captured on.

    Function groups are assigned per platform and per release, so a map is only
    trustworthy while both still match.
    """
    identity = device_identity or {}
    model = str(identity.get("model") or "").strip()
    version = str(identity.get("software_version") or "").strip()
    if not model or not version:
        return None
    return f"{model}|{version}"


def _decode_core_functions(payload: Any) -> tuple[dict[str, Any], ...]:
    if not payload:
        return ()
    try:
        entries = json.loads(str(payload))
    except (TypeError, ValueError):
        return ()
    if not isinstance(entries, list):
        return ()
    return tuple(entry for entry in entries if isinstance(entry, dict))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()



@dataclass(frozen=True)
class RunDeletion:
    """One queued removal of stored incident evidence."""

    deletion_id: int
    target: str
    run_id: str
    requested_at: str

    @property
    def deletes_everything(self) -> bool:
        return self.target == ALL_RUNS and self.run_id == ALL_RUNS


@dataclass(frozen=True)
class StoredTarget:
    target_id: int
    name: str
    panos_url: str
    api_key: str
    target_serial: str | None
    serials: tuple[str, ...]
    syslog_sources: tuple[str, ...]
    tls_verify: str
    enabled: bool
    hostname: str | None = None
    model: str | None = None
    sw_version: str | None = None
    dp_core_functions: tuple[dict[str, Any], ...] = ()
    dp_core_functions_identity: str | None = None
    last_check_at: str | None = None
    last_check_kind: str | None = None
    last_check_status: str | None = None
    last_check_detail: str | None = None
    check_requested_at: str | None = None


class ConfigStore:
    """SQLite-backed configuration with encrypted PAN-OS API keys."""

    def __init__(self, path: Path, key_path: Path | None = None):
        self.path = Path(path)
        self.key_path = Path(key_path) if key_path else self.path.with_name("master.key")

    def initialize(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.key_path.exists():
            try:
                self._write_private(self.key_path, Fernet.generate_key())
            except FileExistsError:
                pass
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    panos_url TEXT NOT NULL,
                    api_key_ciphertext TEXT NOT NULL,
                    target_serial TEXT,
                    serials_json TEXT NOT NULL,
                    syslog_sources_json TEXT NOT NULL,
                    tls_verify TEXT NOT NULL DEFAULT 'false',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    hostname TEXT,
                    model TEXT,
                    sw_version TEXT,
                    dp_core_functions_json TEXT,
                    dp_core_functions_identity TEXT,
                    last_check_at TEXT,
                    last_check_kind TEXT,
                    last_check_status TEXT,
                    last_check_detail TEXT,
                    check_requested_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS admin_auth (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    iterations INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS run_deletions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    UNIQUE (target, run_id)
                );
                """
            )
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(targets)").fetchall()
            }
            if "tls_verify" not in columns:
                legacy = connection.execute(
                    "SELECT value FROM settings WHERE key='tls_verify'"
                ).fetchone()
                legacy_value = str(legacy["value"]) if legacy else "false"
                connection.execute(
                    "ALTER TABLE targets ADD COLUMN tls_verify TEXT NOT NULL DEFAULT 'false'"
                )
                connection.execute(
                    "UPDATE targets SET tls_verify=?", (legacy_value,)
                )
            for column in (
                "hostname",
                "model",
                "sw_version",
                "dp_core_functions_json",
                "dp_core_functions_identity",
                "last_check_at",
                "last_check_kind",
                "last_check_status",
                "last_check_detail",
                "check_requested_at",
            ):
                if column not in columns:
                    connection.execute(f"ALTER TABLE targets ADD COLUMN {column} TEXT")
            connection.execute("DELETE FROM settings WHERE key='tls_verify'")
            now = _utc_now()
            connection.executemany(
                "INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",
                [(key, value, now) for key, value in DEFAULT_SETTINGS.items()],
            )
            connection.execute(
                "INSERT OR IGNORE INTO meta(key,value) VALUES('revision','1')"
            )
            connection.execute(
                """INSERT INTO meta(key,value) VALUES('schema_version','6')
                   ON CONFLICT(key) DO UPDATE SET value='6'"""
            )
        self._chmod_private(self.path)

    @staticmethod
    def _write_private(path: Path, payload: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(path, flags, 0o600)
        try:
            os.write(descriptor, payload)
        finally:
            os.close(descriptor)

    @staticmethod
    def _chmod_private(path: Path) -> None:
        try:
            path.chmod(0o600)
        except OSError:
            pass

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _fernet(self) -> Fernet:
        try:
            key = self.key_path.read_bytes().strip()
            return Fernet(key)
        except (OSError, ValueError) as exc:
            raise ValueError("configuration master key is missing or invalid") from exc

    def revision(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM meta WHERE key='revision'"
            ).fetchone()
        return int(row["value"]) if row else 0

    def recovery_key(self) -> str:
        """Return the installation recovery key for one-time admin delivery."""
        try:
            return self.key_path.read_text(encoding="ascii").strip()
        except OSError as exc:
            raise ValueError("configuration master key cannot be read") from exc

    def anonymization_salt(self) -> str:
        """Return the per-installation salt that pseudonymizes support exports.

        It is generated once and kept, so the same address keeps the same token
        across every bundle a deployment produces: an offender seen during two
        incidents stays recognizable as one offender. It never leaves the
        configuration volume, which is what makes a token irreversible for
        whoever receives the export.
        """
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM meta WHERE key='anonymization_salt'"
            ).fetchone()
            if row and str(row["value"]).strip():
                return str(row["value"])
            salt = secrets.token_hex(32)
            connection.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES('anonymization_salt',?)",
                (salt,),
            )
        return salt

    def recovery_key_acknowledged(self) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM meta WHERE key='recovery_key_acknowledged'"
            ).fetchone()
        return bool(row and str(row["value"]).lower() == "true")

    def acknowledge_recovery_key(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO meta(key,value) VALUES('recovery_key_acknowledged','true')
                   ON CONFLICT(key) DO UPDATE SET value='true'"""
            )

    @staticmethod
    def _bump_revision(connection: sqlite3.Connection) -> None:
        connection.execute(
            "UPDATE meta SET value=CAST(value AS INTEGER)+1 WHERE key='revision'"
        )

    def get_settings(self) -> dict[str, str]:
        with self._connect() as connection:
            rows = connection.execute("SELECT key,value FROM settings").fetchall()
        values = dict(DEFAULT_SETTINGS)
        values.update({str(row["key"]): str(row["value"]) for row in rows})
        return values

    def update_settings(self, values: dict[str, str]) -> None:
        unknown = set(values) - set(DEFAULT_SETTINGS)
        if unknown:
            raise ValueError(f"unknown setting: {sorted(unknown)[0]}")
        merged = self.get_settings()
        merged.update({key: str(value).strip() for key, value in values.items()})
        positive_floats = (
            "poll_seconds", "max_monitor_seconds", "incident_idle_ttl_seconds",
            "request_timeout",
        )
        for key in positive_floats:
            value = float(merged[key])
            if not (value > 0 and value < float("inf")):
                raise ValueError(f"{key} must be a positive finite number")
        retry = float(merged["session_retry_seconds"])
        if not (retry >= 0 and retry < float("inf")):
            raise ValueError("session_retry_seconds must be a finite non-negative number")
        integer_ranges = {
            "recovery_threshold": (0, 100),
            "low_samples_to_stop": (1, 1_000_000),
            "max_session_lookups": (0, 1_000_000),
            "large_session_min_age_seconds": (0, 31_536_000),
        }
        for key, (minimum, maximum) in integer_ranges.items():
            value = int(merged[key])
            if not minimum <= value <= maximum:
                raise ValueError(f"{key} must be between {minimum} and {maximum}")
        # The largest-sessions query walks the session table on the management
        # plane. A low volume threshold would match most of the table during an
        # incident, so only 0 (collection disabled) or a real threshold is
        # accepted. Mirrors LARGE_SESSION_MIN_KB_FLOOR in the orchestrator.
        min_kb = int(merged["large_session_min_kb"])
        if min_kb != 0 and not 1000 <= min_kb <= 1_000_000_000:
            raise ValueError(
                "large_session_min_kb must be 0 (disabled) or between 1000 and "
                "1000000000 kilobytes"
            )
        fresh = float(merged["syslog_fresh_seconds"])
        if not (fresh > 0 and fresh < float("inf")):
            raise ValueError("syslog_fresh_seconds must be a positive finite number")
        check_hours = float(merged["target_check_hours"])
        if not (0 <= check_hours <= 8760):
            raise ValueError(
                "target_check_hours must be between 0 (disabled) and 8760"
            )
        for key in ("generate_html_report", "generate_text_export"):
            if merged[key].lower() not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
                raise ValueError(f"{key} must be true or false")
        webhook = merged.get("webhook_url", "").strip()
        if webhook:
            parsed = urlsplit(webhook)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("webhook_url must be an http(s) URL, or empty to disable")
        now = _utc_now()
        with self._connect() as connection:
            connection.executemany(
                """INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at""",
                [(key, str(value).strip(), now) for key, value in values.items()],
            )
            self._bump_revision(connection)

    @staticmethod
    def _normalized_sources(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
        sources: list[str] = []
        for value in values:
            value = str(value).strip()
            if value:
                try:
                    sources.append(str(ipaddress.ip_address(value)))
                except ValueError as exc:
                    raise ValueError(f"invalid Syslog source IP: {value}") from exc
        if not sources:
            raise ValueError("at least one Syslog source IP is required")
        return tuple(dict.fromkeys(sources))

    @staticmethod
    def _normalize_url(value: str) -> str:
        from .orchestrator import normalize_panos_url

        return normalize_panos_url(value)

    def save_target(
        self,
        *,
        name: str,
        panos_url: str,
        api_key: str | None,
        target_serial: str | None = None,
        serials: list[str] | tuple[str, ...],
        syslog_sources: list[str] | tuple[str, ...],
        tls_verify: str = "false",
        enabled: bool = True,
        device_identity: dict[str, str] | None = None,
        dp_core_functions: list[dict[str, Any]] | None = None,
        target_id: int | None = None,
    ) -> int:
        """Persist a firewall; `device_identity` carries `show system info` fields.

        `dp_core_functions` is the static core-to-function-group map read once
        from the firewall. It is stored with the identity it was captured on so
        a PAN-OS upgrade can invalidate it. `None` keeps the stored copy.
        """
        name = name.strip()
        if not TARGET_NAME.fullmatch(name):
            raise ValueError("target name must contain only letters, digits, dot, dash or underscore")
        panos_url = self._normalize_url(panos_url)
        normalized_sources = self._normalized_sources(syslog_sources)
        normalized_serials = tuple(
            dict.fromkeys(str(value).strip() for value in serials if str(value).strip())
        )
        target_serial = str(target_serial or "").strip() or None
        identity = device_identity or {}
        device = tuple(
            str(identity.get(field) or "").strip() or None
            for field in ("hostname", "model", "software_version")
        )
        core_map: tuple[str | None, str | None] | None = None
        if dp_core_functions is not None:
            core_map = (
                json.dumps(list(dp_core_functions)) if dp_core_functions else None,
                dp_core_identity(identity) if dp_core_functions else None,
            )
        tls_verify = str(tls_verify).strip() or "false"
        if tls_verify.lower() in {"0", "no", "off"}:
            tls_verify = "false"
        elif tls_verify.lower() in {"1", "yes", "on"}:
            tls_verify = "true"
        if target_serial and target_serial not in normalized_serials:
            normalized_serials = (*normalized_serials, target_serial)
        now = _utc_now()
        with self._connect() as connection:
            other_rows = connection.execute(
                "SELECT id,name,serials_json FROM targets WHERE id != ?",
                (target_id if target_id is not None else -1,),
            ).fetchall()
            for serial in normalized_serials:
                if any(
                    serial.lower()
                    in {str(item).lower() for item in json.loads(row["serials_json"])}
                    for row in other_rows
                ):
                    raise ValueError(f"serial {serial!r} already belongs to another firewall")
            if target_id is None:
                if not api_key or not api_key.strip():
                    raise ValueError("API key is required for a new firewall")
                ciphertext = self._fernet().encrypt(api_key.strip().encode()).decode()
                cursor = connection.execute(
                    """INSERT INTO targets
                       (name,panos_url,api_key_ciphertext,target_serial,serials_json,
                        syslog_sources_json,tls_verify,enabled,hostname,model,sw_version,
                        dp_core_functions_json,dp_core_functions_identity,
                        created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        name, panos_url, ciphertext, target_serial,
                        json.dumps(normalized_serials), json.dumps(normalized_sources),
                        tls_verify, int(enabled), *device, *(core_map or (None, None)),
                        now, now,
                    ),
                )
                result = int(cursor.lastrowid)
            else:
                row = connection.execute(
                    """SELECT api_key_ciphertext,hostname,model,sw_version,
                              dp_core_functions_json,dp_core_functions_identity
                       FROM targets WHERE id=?""",
                    (target_id,),
                ).fetchone()
                if row is None:
                    raise ValueError("firewall no longer exists")
                ciphertext = str(row["api_key_ciphertext"])
                if api_key and api_key.strip():
                    ciphertext = self._fernet().encrypt(api_key.strip().encode()).decode()
                if not device_identity:
                    device = (row["hostname"], row["model"], row["sw_version"])
                if core_map is None:
                    core_map = (
                        row["dp_core_functions_json"],
                        row["dp_core_functions_identity"],
                    )
                connection.execute(
                    """UPDATE targets SET name=?,panos_url=?,api_key_ciphertext=?,
                       target_serial=?,serials_json=?,syslog_sources_json=?,tls_verify=?,enabled=?,
                       hostname=?,model=?,sw_version=?,
                       dp_core_functions_json=?,dp_core_functions_identity=?,updated_at=?
                       WHERE id=?""",
                    (
                        name, panos_url, ciphertext, target_serial,
                        json.dumps(normalized_serials), json.dumps(normalized_sources),
                        tls_verify, int(enabled), *device, *core_map, now, target_id,
                    ),
                )
                result = target_id
            self._bump_revision(connection)
        return result

    def request_target_check(self, target_id: int) -> None:
        """Queue a full validation for one firewall.

        The Web UI mounts the evidence volume read-only and the collector
        exposes no port, so the shared database carries the request instead.
        """
        with self._connect() as connection:
            updated = connection.execute(
                "UPDATE targets SET check_requested_at=? WHERE id=?",
                (_utc_now(), target_id),
            ).rowcount
        if not updated:
            raise ValueError("firewall no longer exists")

    def record_target_check(
        self,
        target_id: int,
        *,
        kind: str,
        status: str,
        detail: str | None = None,
        clear_request: bool = False,
    ) -> None:
        """Store the outcome of a check without disturbing the running config."""
        with self._connect() as connection:
            if clear_request:
                connection.execute(
                    """UPDATE targets SET last_check_at=?,last_check_kind=?,
                       last_check_status=?,last_check_detail=?,check_requested_at=NULL
                       WHERE id=?""",
                    (_utc_now(), kind, status, detail, target_id),
                )
            else:
                connection.execute(
                    """UPDATE targets SET last_check_at=?,last_check_kind=?,
                       last_check_status=?,last_check_detail=? WHERE id=?""",
                    (_utc_now(), kind, status, detail, target_id),
                )

    def request_run_deletion(self, target: str, run_id: str) -> None:
        """Queue the removal of one stored incident run.

        The Web UI mounts the evidence volume read-only, so the request travels
        through the shared database and the collector performs the deletion.
        Re-requesting a run already queued is a no-op rather than an error, so a
        double click cannot pile up work.
        """
        if not SAFE_RUN_COMPONENT.fullmatch(target):
            raise ValueError("invalid firewall name")
        if not SAFE_RUN_COMPONENT.fullmatch(run_id):
            raise ValueError("invalid run identifier")
        self._queue_run_deletion(target, run_id)

    def request_all_runs_deletion(self) -> None:
        """Queue the removal of every stored incident run, for every firewall."""
        self._queue_run_deletion(ALL_RUNS, ALL_RUNS)

    def _queue_run_deletion(self, target: str, run_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO run_deletions(target,run_id,requested_at)
                   VALUES(?,?,?)
                   ON CONFLICT(target,run_id) DO UPDATE SET requested_at=excluded.requested_at""",
                (target, run_id, _utc_now()),
            )

    def pending_run_deletions(self) -> list[RunDeletion]:
        """Return the queued deletions, oldest first."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id,target,run_id,requested_at FROM run_deletions ORDER BY id"
            ).fetchall()
        return [
            RunDeletion(
                deletion_id=int(row["id"]),
                target=str(row["target"]),
                run_id=str(row["run_id"]),
                requested_at=str(row["requested_at"]),
            )
            for row in rows
        ]

    def clear_run_deletion(self, deletion_id: int) -> None:
        """Drop one queued deletion once the collector has acted on it."""
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM run_deletions WHERE id=?", (deletion_id,)
            )

    def refresh_target_device(
        self,
        target_id: int,
        *,
        device_identity: dict[str, str],
        dp_core_functions: list[dict[str, Any]] | None = None,
    ) -> None:
        """Update the identity and core map a check found to have changed."""
        device = tuple(
            str(device_identity.get(field) or "").strip() or None
            for field in ("hostname", "model", "software_version")
        )
        with self._connect() as connection:
            row = connection.execute(
                """SELECT dp_core_functions_json,dp_core_functions_identity
                   FROM targets WHERE id=?""",
                (target_id,),
            ).fetchone()
            if row is None:
                raise ValueError("firewall no longer exists")
            if dp_core_functions is None:
                core_map = (
                    row["dp_core_functions_json"],
                    row["dp_core_functions_identity"],
                )
            else:
                core_map = (
                    json.dumps(list(dp_core_functions)) if dp_core_functions else None,
                    dp_core_identity(device_identity) if dp_core_functions else None,
                )
            connection.execute(
                """UPDATE targets SET hostname=?,model=?,sw_version=?,
                   dp_core_functions_json=?,dp_core_functions_identity=?,updated_at=?
                   WHERE id=?""",
                (*device, *core_map, _utc_now(), target_id),
            )
            self._bump_revision(connection)

    def delete_target(self, target_id: int) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM targets WHERE id=?", (target_id,))
            self._bump_revision(connection)

    def list_targets(self, *, include_secrets: bool = False) -> list[StoredTarget | dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM targets ORDER BY name COLLATE NOCASE").fetchall()
        result: list[StoredTarget | dict[str, Any]] = []
        fernet = self._fernet() if include_secrets and rows else None
        for row in rows:
            common = {
                "target_id": int(row["id"]),
                "name": str(row["name"]),
                "panos_url": str(row["panos_url"]),
                "target_serial": row["target_serial"],
                "serials": tuple(json.loads(row["serials_json"])),
                "syslog_sources": tuple(json.loads(row["syslog_sources_json"])),
                "tls_verify": str(row["tls_verify"]),
                "enabled": bool(row["enabled"]),
                "hostname": row["hostname"],
                "model": row["model"],
                "sw_version": row["sw_version"],
                "dp_core_functions": _decode_core_functions(
                    row["dp_core_functions_json"]
                ),
                "dp_core_functions_identity": row["dp_core_functions_identity"],
                "last_check_at": row["last_check_at"],
                "last_check_kind": row["last_check_kind"],
                "last_check_status": row["last_check_status"],
                "last_check_detail": row["last_check_detail"],
                "check_requested_at": row["check_requested_at"],
            }
            if include_secrets:
                try:
                    api_key = fernet.decrypt(str(row["api_key_ciphertext"]).encode()).decode()
                except InvalidToken as exc:
                    raise ValueError("an encrypted API key cannot be decrypted") from exc
                result.append(StoredTarget(api_key=api_key, **common))
            else:
                result.append({**common, "api_key_configured": bool(row["api_key_ciphertext"])})
        return result

    def has_admin_password(self) -> bool:
        with self._connect() as connection:
            return connection.execute("SELECT 1 FROM admin_auth WHERE singleton=1").fetchone() is not None

    def set_admin_password(self, password: str) -> None:
        if len(password) < 8:
            raise ValueError("admin password must contain at least 8 characters")
        salt = secrets.token_bytes(32)
        derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
        now = _utc_now()
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO admin_auth(singleton,salt,password_hash,iterations,updated_at)
                   VALUES(1,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET
                   salt=excluded.salt,password_hash=excluded.password_hash,
                   iterations=excluded.iterations,updated_at=excluded.updated_at""",
                (
                    base64.b64encode(salt).decode(),
                    base64.b64encode(derived).decode(),
                    PBKDF2_ITERATIONS,
                    now,
                ),
            )

    def verify_admin_password(self, password: str) -> bool:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM admin_auth WHERE singleton=1").fetchone()
        if row is None:
            return False
        salt = base64.b64decode(row["salt"])
        expected = base64.b64decode(row["password_hash"])
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(row["iterations"]))
        return hmac.compare_digest(actual, expected)
