"""Deployment diagnostics: persistent logs and the support bundle.

A capture archive explains what the firewall answered. It cannot explain what
the collector itself did, because the process logs live only on stdout and the
effective configuration is nowhere in the evidence. That gap is what makes a
customer incident impossible to diagnose without reaching their infrastructure.

This module closes it with two pieces:

* :func:`configure_file_logging` mirrors the process log into a size-bounded
  rotating file inside a volume, so the history survives ``docker logs``.
* :func:`write_support_bundle` packages those logs together with an environment
  fingerprint, the redacted configuration, the run inventory and the recent
  Syslog journals into one archive an operator can send.

The bundle is evidence, not a secret store. PAN-OS API keys, the administrator
password material, the recovery key and the one-time setup code never enter it.
Management addresses, hostnames, serials and offender source addresses do: they
are the evidence itself, and the documentation states so plainly.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import logging.handlers
import os
import platform
import re
import secrets
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from . import __version__

LOG = logging.getLogger(__name__)

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
LOG_FILE_MAX_BYTES = 2 * 1024 * 1024
LOG_FILE_BACKUPS = 3

#: Records carrying this attribute are kept out of the persistent log file.
#: The administrator setup code is deliberately shown once, in the container
#: log an operator must already be able to read; a file that later travels
#: inside a support bundle is not that place.
SENSITIVE_ATTRIBUTE = "pbp_sensitive"

#: Only these three journals are exported, and only their tail.
SYSLOG_JOURNAL_TAIL_BYTES = 512 * 1024
LOG_TAIL_BYTES = 2 * 1024 * 1024
BUNDLE_FORMAT_VERSION = 1

SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")

_SCRUB_PATTERNS = (
    # Defence in depth. The client authenticates with X-PAN-KEY and redacts its
    # own key before persisting anything, so neither form should ever appear;
    # a log file that travels must not depend on that being true.
    (re.compile(r"(?i)\b(key|api_key|apikey)=([^\s&\"']+)"), r"\1=<redacted>"),
    (re.compile(r"(?i)(x-pan-key\s*[:=]\s*)([^\s\"']+)"), r"\1<redacted>"),
    (re.compile(r"(?i)(setup code[^:]*:\s*)(\S+)"), r"\1<redacted>"),
)


class SensitiveRecordFilter(logging.Filter):
    """Keep records flagged as sensitive out of the persistent log file."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not getattr(record, SENSITIVE_ATTRIBUTE, False)


def scrub_log_text(text: str) -> str:
    """Remove credential-shaped values from text before it is exported."""
    for pattern, replacement in _SCRUB_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# The trailing boundary rejects a further dotted number, which would mean a
# longer numeric string, but not an ordinary sentence-ending period: PAN-OS
# writes "authenticated for user 'x'. From: 10.0.0.1." and that address must
# still be replaced.
IPV4_CANDIDATE = re.compile(r"(?<![0-9A-Za-z.])\d{1,3}(?:\.\d{1,3}){3}(?![0-9A-Za-z])(?!\.\d)")
IPV6_CANDIDATE = re.compile(r"(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?(?![0-9A-Za-z:])")
MAC_CANDIDATE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")

#: Values below this length are never treated as literal identifiers: a short
#: firewall name would match fragments of unrelated words.
MINIMUM_LITERAL_LENGTH = 3


class Anonymizer:
    """Replace identifying values with tokens that stay stable across exports.

    Addresses, MAC addresses, serial numbers, firewall names and hostnames are
    replaced by a token derived from a per-installation salt kept in the
    configuration volume. The same address therefore reads as the same token
    everywhere in an export and across successive exports — an offender seen in
    two incidents is still recognizable as one offender — while whoever
    receives the export cannot recover the address: the salt never leaves the
    site, and the operator can list the mapping locally whenever a token has to
    be translated back.

    Two deliberate exceptions keep the export diagnosable: loopback and
    unspecified addresses are left alone, because they identify nobody and name
    the collector's own sockets, and a firewall name or hostname equal to the
    platform model is left alone, because tokenizing it would erase the model
    from every command output that reports it.
    """

    def __init__(self, salt: str, literals: Iterable[tuple[str, str]] = ()):
        self._salt = (salt or "").encode("utf-8")
        self.mapping: dict[str, str] = {}
        self._literals: list[tuple[re.Pattern[str], str]] = []
        seen: set[str] = set()
        for value, kind in sorted(literals, key=lambda item: len(item[0]), reverse=True):
            text = str(value or "").strip()
            if len(text) < MINIMUM_LITERAL_LENGTH or text in seen:
                continue
            seen.add(text)
            # The boundary excludes alphanumerics only. Dots, dashes and
            # underscores are exactly what separates an identifier from its
            # context — `triggers-fw-a`, `fw-a.example`, and the serial inside
            # a PAN-OS filename such as `PA_0212...._dt_12.2.2.tgz` — so
            # treating them as part of the value let it through untouched.
            self._literals.append(
                (
                    re.compile(rf"(?<![0-9A-Za-z]){re.escape(text)}(?![0-9A-Za-z])"),
                    kind,
                )
            )
            # Registering it now keeps the mapping complete even when a value
            # never appears in the exported text.
            self.token(text, kind)

    def token(self, value: str, kind: str) -> str:
        existing = self.mapping.get(value)
        if existing is not None:
            return existing
        digest = hmac.new(
            self._salt, f"{kind}:{value}".encode("utf-8"), hashlib.sha256
        ).hexdigest()[:10]
        token = f"{kind}-{digest}"
        self.mapping[value] = token
        return token

    def _address(self, match: re.Match[str], kind: str) -> str:
        text = match.group(0)
        candidate, _, prefix = text.partition("/")
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return text
        if address.is_loopback or address.is_unspecified:
            return text
        token = self.token(candidate, kind)
        return f"{token}/{prefix}" if prefix else token

    def apply(self, text: str) -> str:
        for pattern, kind in self._literals:
            text = pattern.sub(lambda match, kind=kind: self.token(match.group(0), kind), text)
        text = MAC_CANDIDATE.sub(lambda match: self.token(match.group(0), "mac"), text)
        text = IPV4_CANDIDATE.sub(lambda match: self._address(match, "ip"), text)
        text = IPV6_CANDIDATE.sub(lambda match: self._address(match, "ip6"), text)
        return text

    def apply_bytes(self, payload: bytes) -> bytes:
        return self.apply(payload.decode("utf-8", errors="replace")).encode("utf-8")

    def mapping_csv(self) -> bytes:
        """Render the token mapping the operator keeps, and never sends."""
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(("token", "original_value"))
        for value, token in sorted(self.mapping.items(), key=lambda item: item[1]):
            writer.writerow((token, value))
        return output.getvalue().encode("utf-8-sig")


def build_anonymizer(config_store: Any) -> Anonymizer:
    """Build an anonymizer seeded with what this deployment knows about itself."""
    if config_store is None:
        # No configuration means no known identifiers and no persisted salt.
        # Addresses are still tokenized, under a salt valid for this export
        # only, so the operator can still send something.
        return Anonymizer(secrets.token_hex(32))
    try:
        salt = config_store.anonymization_salt()
        targets = config_store.list_targets()
    except Exception as exc:
        LOG.warning("Anonymization falls back to a temporary salt: %s", exc)
        return Anonymizer(secrets.token_hex(32))
    models = {
        str(target.get("model") or "").strip()
        for target in targets
        if isinstance(target, dict)
    }
    literals: list[tuple[str, str]] = []
    for target in targets:
        if not isinstance(target, dict):
            continue
        for value in (target.get("name"), target.get("hostname")):
            text = str(value or "").strip()
            # A name equal to the platform model would take the model down with
            # it, in every command output that reports one.
            if text and text not in models:
                literals.append((text, "fw"))
        for serial in (*(target.get("serials") or ()), target.get("target_serial")):
            text = str(serial or "").strip()
            if text:
                literals.append((text, "serial"))
    return Anonymizer(salt, literals)


def default_log_dir(base: Path) -> Path:
    return Path(base) / "logs"


def configure_file_logging(
    directory: Path | None,
    component: str,
    *,
    max_bytes: int = LOG_FILE_MAX_BYTES,
    backup_count: int = LOG_FILE_BACKUPS,
) -> Path | None:
    """Mirror the root logger into a rotating file and return its path.

    A collector that cannot write its log must still collect. Every failure
    here is reported once and swallowed: losing the persistent log costs
    diagnosability, refusing to start costs the incident itself.
    """
    if directory is None:
        return None
    if not SAFE_COMPONENT.fullmatch(component):
        raise ValueError(f"invalid log component name: {component!r}")
    path = Path(directory) / f"{component}.log"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
    except OSError as exc:
        LOG.warning("Persistent logging disabled, %s is not writable: %s", path, exc)
        return None
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    handler.addFilter(SensitiveRecordFilter())
    logging.getLogger().addHandler(handler)
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass
    LOG.info("Persistent log file enabled at %s", path)
    return path


def _dependency_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    try:
        import cryptography

        versions["cryptography"] = str(cryptography.__version__)
    except Exception:  # pragma: no cover - absent only in a broken install
        versions["cryptography"] = "unavailable"
    return versions


def environment_snapshot(now: datetime | None = None) -> dict[str, Any]:
    """Describe the runtime the collector is actually executing in."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    local = datetime.now().astimezone()
    return {
        "application_version": __version__,
        "generated_at": current.isoformat(),
        "python_version": sys.version.split()[0],
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "node": platform.node(),
        "in_container": Path("/.dockerenv").exists(),
        "process": {
            "pid": os.getpid(),
            "uid": getattr(os, "geteuid", lambda: None)(),
            "gid": getattr(os, "getegid", lambda: None)(),
            "argv0": sys.argv[0] if sys.argv else "",
        },
        "local_timezone": local.tzname(),
        "local_utc_offset": local.strftime("%z"),
        "dependencies": _dependency_versions(),
        "environment_flags": {
            name: os.environ.get(name, "")
            for name in (
                "OUTPUT_DIR",
                "SYSLOG_HOST",
                "SYSLOG_PORT",
                "LOG_LEVEL",
                "PBP_CONFIG_DB",
                "PBP_LOG_DIR",
                "WEB_LOG_FRESH_SECONDS",
                "WEB_HTTPS_PUBLIC_PORT",
                "WEB_TLS_HOSTNAMES",
            )
        },
    }


def _safe_webhook(value: str) -> dict[str, Any]:
    """Describe a webhook without disclosing the token most of them embed."""
    text = str(value or "").strip()
    if not text:
        return {"configured": False}
    try:
        parts = urlsplit(text)
    except ValueError:
        return {"configured": True, "parse_error": True}
    return {
        "configured": True,
        "scheme": parts.scheme,
        "host": parts.hostname or "",
        "port": parts.port,
        "path_present": bool(parts.path.strip("/")),
        "query_present": bool(parts.query),
    }


def redacted_configuration(store: Any) -> dict[str, Any]:
    """Return every setting that shapes behaviour, and no secret material.

    Nothing derived from the administrator password state is reported here, not
    even whether one exists. Whether setup was completed is already legible in
    the dashboard log, which serves the setup page instead of the sign-in page,
    so the bundle loses no diagnostic value by keeping password state out of an
    artifact that leaves the site.
    """
    if store is None:
        return {"available": False}
    try:
        settings = dict(store.get_settings())
        targets = store.list_targets()
        payload: dict[str, Any] = {
            "available": True,
            "revision": store.revision(),
            "recovery_key_acknowledged": store.recovery_key_acknowledged(),
            "settings": {
                key: value
                for key, value in settings.items()
                if key != "webhook_url"
            },
            "webhook": _safe_webhook(settings.get("webhook_url", "")),
            "targets": [
                {
                    "name": target.get("name"),
                    "panos_url": target.get("panos_url"),
                    "target_serial": target.get("target_serial"),
                    "mode": "panorama" if target.get("target_serial") else "direct",
                    "serials": list(target.get("serials") or ()),
                    "syslog_sources": list(target.get("syslog_sources") or ()),
                    "tls_verify": target.get("tls_verify"),
                    "enabled": target.get("enabled"),
                    "api_key_configured": target.get("api_key_configured"),
                    "hostname": target.get("hostname"),
                    "model": target.get("model"),
                    "sw_version": target.get("sw_version"),
                    "dp_core_functions_identity": target.get(
                        "dp_core_functions_identity"
                    ),
                    "dp_core_function_rows": len(target.get("dp_core_functions") or ()),
                    "last_check_at": target.get("last_check_at"),
                    "last_check_kind": target.get("last_check_kind"),
                    "last_check_status": target.get("last_check_status"),
                    "last_check_detail": target.get("last_check_detail"),
                    "check_requested_at": target.get("check_requested_at"),
                }
                for target in targets
                if isinstance(target, dict)
            ],
        }
    except Exception as exc:  # a broken store must still yield a bundle
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}
    return payload


def _target_roots(data_dir: Path) -> list[tuple[str, Path]]:
    targets = Path(data_dir) / "targets"
    found: list[tuple[str, Path]] = []
    if targets.is_dir():
        for path in sorted(targets.iterdir()):
            if path.is_dir() and SAFE_COMPONENT.fullmatch(path.name):
                found.append((path.name, path))
    if not found and (Path(data_dir) / "incidents").is_dir():
        found.append(("standalone", Path(data_dir)))
    return found


def _directory_size(path: Path) -> tuple[int, int]:
    files = 0
    total = 0
    for child in path.rglob("*"):
        if child.is_file() and not child.is_symlink():
            files += 1
            try:
                total += child.stat().st_size
            except OSError:
                continue
    return files, total


def run_inventory(data_dir: Path) -> list[dict[str, Any]]:
    """List every stored run, incidents and read-only API checks alike."""
    inventory: list[dict[str, Any]] = []
    for target, root in _target_roots(Path(data_dir)):
        for kind, folder, capture in (
            ("incident", "incidents", "incident.jsonl"),
            ("api_check", "api-checks", "api-check.jsonl"),
        ):
            container = root / folder
            if not container.is_dir():
                continue
            for directory in sorted(container.iterdir()):
                if not directory.is_dir() or not SAFE_COMPONENT.fullmatch(
                    directory.name
                ):
                    continue
                files, total = _directory_size(directory)
                try:
                    modified = datetime.fromtimestamp(
                        directory.stat().st_mtime, timezone.utc
                    ).isoformat()
                except OSError:
                    modified = None
                inventory.append(
                    {
                        "target": target,
                        "kind": kind,
                        "run_id": directory.name,
                        "capture_present": (directory / capture).is_file(),
                        "report_present": (directory / "report.html").is_file(),
                        "raw_files": (
                            sum(1 for _ in (directory / "raw").glob("*"))
                            if (directory / "raw").is_dir()
                            else 0
                        ),
                        "files": files,
                        "size_bytes": total,
                        "modified_at": modified,
                    }
                )
    inventory.sort(key=lambda item: (item["target"], item["kind"], item["run_id"]))
    return inventory


def storage_usage(data_dir: Path) -> dict[str, Any]:
    """Report what the capture volume holds, so a full disk explains itself."""
    root = Path(data_dir)
    areas: dict[str, Any] = {}
    if root.is_dir():
        for child in sorted(root.iterdir()):
            if child.is_dir():
                files, total = _directory_size(child)
                areas[child.name] = {"files": files, "size_bytes": total}
            elif child.is_file():
                try:
                    areas[child.name] = {"files": 1, "size_bytes": child.stat().st_size}
                except OSError:
                    continue
    usage: dict[str, Any] = {"data_dir": str(root), "areas": areas}
    try:
        stats = os.statvfs(root)
        usage["filesystem"] = {
            "total_bytes": stats.f_frsize * stats.f_blocks,
            "available_bytes": stats.f_frsize * stats.f_bavail,
        }
    except (OSError, AttributeError):
        usage["filesystem"] = None
    return usage


def tail_bytes(path: Path, limit: int) -> bytes:
    """Return at most ``limit`` trailing bytes, starting on a line boundary."""
    try:
        with Path(path).open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            end = handle.tell()
            start = max(0, end - limit)
            handle.seek(start)
            data = handle.read()
    except OSError:
        return b""
    if start > 0:
        _, separator, remainder = data.partition(b"\n")
        data = remainder if separator else b""
    return data


def _log_files(log_dirs: Iterable[Path]) -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for directory in log_dirs:
        path = Path(directory)
        if not path.is_dir():
            continue
        for child in sorted(path.iterdir()):
            if not child.is_file() or child.is_symlink():
                continue
            if ".log" not in child.name:
                continue
            resolved = child.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            found.append((child.name, child))
    return found


def _latest_api_check(root: Path) -> Path | None:
    container = root / "api-checks"
    if not container.is_dir():
        return None
    candidates = [
        directory
        for directory in container.iterdir()
        if directory.is_dir()
        and SAFE_COMPONENT.fullmatch(directory.name)
        and (directory / "api-check.jsonl").is_file()
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda directory: directory.name)


BUNDLE_README = """PBP Monitoring support bundle
=============================

Send this archive to the maintainer to diagnose a collector problem remotely.

What it contains
----------------
environment.json     the runtime actually executing: application, Python and
                     cryptography versions, platform, timezone, container flag
configuration.json   every collector setting and every registered firewall,
                     without any credential
runs.json            the inventory of stored incident and API-check runs
storage.json         what the capture volume holds and how full it is
logs/                the collector and web UI process logs, most recent last
syslog/              the tail of the Syslog reception, routing and trigger
                     journals, including messages the collector refused
api-checks/          the most recent read-only API validation of each firewall,
                     with the raw PAN-OS XML of every command
manifest.json        SHA-256 of every file above

What it never contains
----------------------
PAN-OS API keys, the administrator password or its hash, the installation
recovery key, and the one-time administrator setup code.

What it does contain about your network
---------------------------------------
Firewall management addresses, hostnames, serial numbers, PAN-OS releases, and
the source addresses and session identifiers recorded as offenders during an
incident. Review the archive before sending it if that is a concern.

An anonymized bundle is available instead, from the same admin card or with
`pbp-support --anonymize`. It replaces every address, MAC address, serial and
firewall name with a token such as `ip-3f2c1a9b4d`, stable across exports so an
offender stays recognizable, and irreversible for whoever receives it. Check
`manifest.json`: `"anonymized": true` says which kind you are holding. To
translate a token back, list the mapping on your own installation with
`pbp-support --anonymize --mapping mapping.csv`, and keep that file: it is the
one thing that must never be sent.

No part of producing this bundle contacts the firewall.
"""


def write_support_bundle(
    destination: Any,
    *,
    data_dir: Path,
    config_store: Any = None,
    log_dirs: Iterable[Path] = (),
    now: datetime | None = None,
    log_tail_bytes: int = LOG_TAIL_BYTES,
    journal_tail_bytes: int = SYSLOG_JOURNAL_TAIL_BYTES,
    anonymizer: Anonymizer | None = None,
) -> dict[str, Any]:
    """Write a deployment-wide diagnostic archive and return its manifest.

    With an `anonymizer`, every exported path and payload goes through it, so
    the archive names no address, MAC address, serial or firewall of the site
    it came from.
    """
    root = Path(data_dir)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    stamp = current.strftime("%Y%m%dT%H%M%SZ")
    prefix = f"pbp-support-{stamp}"
    entries: list[tuple[str, bytes, str]] = [
        ("README.txt", BUNDLE_README.encode("utf-8"), "generated"),
        (
            "environment.json",
            _json_bytes(environment_snapshot(current)),
            "generated",
        ),
        (
            "configuration.json",
            _json_bytes(redacted_configuration(config_store)),
            "generated",
        ),
        ("runs.json", _json_bytes(run_inventory(root)), "generated"),
        ("storage.json", _json_bytes(storage_usage(root)), "generated"),
    ]

    for name, path in _log_files(log_dirs):
        payload = tail_bytes(path, log_tail_bytes)
        if not payload:
            continue
        scrubbed = scrub_log_text(payload.decode("utf-8", errors="replace"))
        entries.append((f"logs/{name}", scrubbed.encode("utf-8"), "tail"))

    for name, journal in (
        ("received", root / "syslog-received.jsonl"),
        ("routing", root / "syslog-routing.jsonl"),
    ):
        payload = tail_bytes(journal, journal_tail_bytes)
        if payload:
            entries.append((f"syslog/{name}.jsonl", payload, "tail"))

    for target, target_root in _target_roots(root):
        payload = tail_bytes(target_root / "syslog-triggers.jsonl", journal_tail_bytes)
        if payload:
            entries.append((f"syslog/triggers-{target}.jsonl", payload, "tail"))
        latest = _latest_api_check(target_root)
        if latest is None:
            continue
        for path in sorted(latest.rglob("*")):
            if not path.is_file() or path.is_symlink() or path.name == "report.html":
                continue
            try:
                entries.append(
                    (
                        f"api-checks/{target}/{latest.name}/"
                        f"{path.relative_to(latest).as_posix()}",
                        path.read_bytes(),
                        "capture",
                    )
                )
            except OSError:
                continue

    if anonymizer is not None:
        entries = [
            (anonymizer.apply(relative), anonymizer.apply_bytes(payload), source)
            for relative, payload, source in entries
        ]

    manifest_files: list[dict[str, Any]] = []
    with zipfile.ZipFile(
        destination,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
        allowZip64=True,
    ) as archive:
        for relative, payload, source in entries:
            manifest_files.append(
                {
                    "path": relative,
                    "size_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "source": source,
                }
            )
            archive.writestr(f"{prefix}/{relative}", payload)
        manifest = {
            "format_version": BUNDLE_FORMAT_VERSION,
            "application": "PBP Monitoring",
            "application_version": __version__,
            "bundle": prefix,
            "generated_at": current.isoformat(),
            "anonymized": anonymizer is not None,
            "files": manifest_files,
        }
        archive.writestr(f"{prefix}/manifest.json", _json_bytes(manifest))
    return manifest


def _json_bytes(payload: Any) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n").encode(
        "utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    """Write a support bundle from inside a running container.

    Reaching the web UI is the normal route. This command exists for the case
    where the web UI is itself the problem:

        docker compose exec -T collector pbp-support > pbp-support.zip
    """
    import argparse

    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(os.getenv("OUTPUT_DIR", "/data")),
        help="capture directory to describe (default: %(default)s)",
    )
    parser.add_argument(
        "--config-db",
        type=Path,
        default=Path(os.getenv("PBP_CONFIG_DB", "/config/config.db")),
        help="configuration database to read settings from (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="archive path, or - for standard output (default: -)",
    )
    parser.add_argument(
        "--anonymize",
        action="store_true",
        help="replace every address, MAC address, serial and firewall name with"
        " a token that is stable across exports",
    )
    parser.add_argument(
        "--mapping",
        type=Path,
        help="with --anonymize, write the token mapping here; keep this file,"
        " it is the one thing that must never be sent",
    )
    args = parser.parse_args(argv)
    if args.mapping and not args.anonymize:
        parser.error("--mapping requires --anonymize")
    logging.basicConfig(level="WARNING", format=LOG_FORMAT)

    store = None
    if args.config_db.is_file():
        try:
            from .config_store import ConfigStore

            store = ConfigStore(args.config_db)
        except Exception as exc:
            LOG.warning("Configuration is not readable: %s", exc)

    log_dirs = [default_log_dir(args.data_dir), default_log_dir(args.config_db.parent)]
    anonymizer = build_anonymizer(store) if args.anonymize else None
    if args.output == "-":
        buffer = getattr(sys.stdout, "buffer", sys.stdout)
        manifest = write_support_bundle(
            buffer,
            data_dir=args.data_dir,
            config_store=store,
            log_dirs=log_dirs,
            anonymizer=anonymizer,
        )
    else:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("wb") as handle:
            manifest = write_support_bundle(
                handle,
                data_dir=args.data_dir,
                config_store=store,
                log_dirs=log_dirs,
                anonymizer=anonymizer,
            )
        LOG.warning("Support bundle written to %s", target)
    if args.mapping and anonymizer is not None:
        args.mapping.parent.mkdir(parents=True, exist_ok=True)
        args.mapping.write_bytes(anonymizer.mapping_csv())
        try:
            os.chmod(args.mapping, 0o600)
        except OSError:
            pass
        LOG.warning(
            "Token mapping written to %s. Keep it: it must never be sent.",
            args.mapping,
        )
    LOG.warning(
        "Support bundle contains %d files%s",
        len(manifest["files"]),
        " (anonymized)" if anonymizer is not None else "",
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
