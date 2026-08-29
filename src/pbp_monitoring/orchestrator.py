#!/usr/bin/env python3
"""Event-driven PAN-OS packet-buffer investigation collector.

Listens for a PAN-OS syslog trigger, polls operational commands through the
PAN-OS XML API, extracts candidate session IDs, and immediately enriches them.
"""

from __future__ import annotations

import argparse
import asyncio
from collections import deque
import ipaddress
import json
import logging
import math
import os
import re
import signal
import ssl
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from . import __version__
from .config_store import ConfigStore, StoredTarget, dp_core_identity
from .text_export import write_record_text_export


LOG = logging.getLogger("pbp-orchestrator")

TRIGGER_REGEX = re.compile(
    r"Packet buffer congestion|PBP Packet Drop|"
    r"PBP Session Discarded|PBP IP Blocked",
    re.IGNORECASE,
)


def resource_monitor_window_seconds(poll_seconds: float) -> int:
    """Cover one poll interval plus bounded scheduling and API jitter."""
    return min(60, max(1, math.ceil(poll_seconds) + 2))


def resource_monitor_command(poll_seconds: float) -> str:
    window = resource_monitor_window_seconds(poll_seconds)
    return (
        "<show><running><resource-monitor><second><last>"
        f"{window}</last></second></resource-monitor></running></show>"
    )

OP_COMMANDS = {
    "packet_buffer_protection": "<show><session><packet-buffer-protection/></session></show>",
    "session_info": "<show><session><info/></session></show>",
    "ingress_backlogs": "<show><running><resource-monitor><ingress-backlogs/></resource-monitor></running></show>",
    "resource_monitor": resource_monitor_command(5),
    "dataplane_pool_statistics": "<debug><dataplane><pool><statistics/></pool></dataplane></debug>",
    "global_counters_delta": "<show><counter><global><filter><delta>yes</delta></filter></global></counter></show>",
}

SYSTEM_INFO_COMMAND = "<show><system><info/></system></show>"
DP_CORE_FUNCTIONS_COMMAND = "<show><statistics/></show>"
CLOCK_COMMAND = "<show><clock/></show>"

DEVICE_IDENTITY_FIELDS = ("serial", "model", "software_version")
SYSLOG_SOURCE_MARKER = "PBP_SYSLOG_SOURCE"
# PAN-OS does not label the serial in a Syslog line, it positions it:
# FUTURE_USE, receive time, serial, type, subtype. The log type is the anchor
# that separates a real PAN-OS log from an arbitrary comma-separated string.
PANOS_LOG_TYPE_FIELD = 3
PANOS_SERIAL_FIELD = 2
PANOS_LOG_TYPES = frozenset(
    {
        "TRAFFIC", "THREAT", "SYSTEM", "CONFIG", "HIP-MATCH", "CORRELATION",
        "GLOBALPROTECT", "USERID", "IPTAG", "IP-TAG", "DECRYPTION", "SCTP",
        "AUTHENTICATION", "GTP", "TUNNEL", "URL", "DATA", "WILDFIRE",
    }
)
SERIAL_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}")
# Why a Syslog emitter was refused. These slugs are persisted in the reception
# journal, so keep them stable.
SYSLOG_REJECTIONS = {
    "source_not_registered": "source is not a declared Syslog source",
    "device_serial_missing": "the message carries no device serial",
    "device_serial_not_registered": (
        "the device serial is not the one registered for this Syslog source"
    ),
}
SYSLOG_STATUS_RECORD_LIMIT = 200
SYSLOG_STATUS_MAX_BYTES = 4 * 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_env_file(path: Path) -> None:
    """Load a simple KEY=VALUE file without overriding the process environment."""
    if not path.is_file():
        return
    file_values: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8-sig").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"{path}:{line_number}: expected KEY=VALUE")
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError(f"{path}:{line_number}: invalid environment variable name")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if name in file_values and file_values[name] != value:
            raise ValueError(f"{path}:{line_number}: conflicting duplicate for {name}")
        file_values[name] = value
        os.environ.setdefault(name, value)


def normalize_panos_url(raw_url: str) -> str:
    parsed_url = urlsplit(raw_url.strip())
    if parsed_url.scheme.lower() != "https":
        raise ValueError("PAN-OS URL must use HTTPS")
    if (
        not parsed_url.hostname
        or parsed_url.username
        or parsed_url.password
        or parsed_url.path not in {"", "/"}
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise ValueError("PAN-OS URL must contain only a firewall or Panorama host")
    return urlunsplit(("https", parsed_url.netloc, "", "", ""))


def _parse_tls_verify(value: Any) -> bool | str:
    normalized = str(value).strip()
    if normalized.lower() in {"false", "0", "no", "off", ""}:
        return False
    if normalized.lower() in {"true", "1", "yes", "on"}:
        return True
    return normalized


@dataclass(frozen=True)
class TargetProfile:
    name: str
    panos_url: str
    api_key: str = field(repr=False)
    target_serial: str | None = None
    serials: tuple[str, ...] = ()
    syslog_sources: tuple[str, ...] = ()
    tls_verify: bool | str = False
    dp_core_functions: tuple[dict[str, Any], ...] = ()
    dp_core_functions_identity: str | None = None


def load_target_profiles(path: Path) -> tuple[TargetProfile, ...]:
    """Load the target inventory, including the common single-IP shorthand."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON at line {exc.lineno}") from exc
    entries = payload.get("targets") if isinstance(payload, dict) else payload
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{path}: targets must be a non-empty list")

    profiles: list[TargetProfile] = []
    names: set[str] = set()
    serial_owners: dict[str, str] = {}
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: target {index} must be an object")
        name = str(entry.get("name", "")).strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
            raise ValueError(f"{path}: target {index} has an invalid name")
        if name in names:
            raise ValueError(f"{path}: duplicate target name {name!r}")
        names.add(name)
        literal_api_key = str(entry.get("api_key", "")).strip()
        api_key_env = str(entry.get("api_key_env", "")).strip()
        if bool(literal_api_key) == bool(api_key_env):
            raise ValueError(
                f"{path}: target {name!r} must define exactly one of "
                "api_key or api_key_env"
            )
        if api_key_env:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", api_key_env):
                raise ValueError(
                    f"{path}: target {name!r} has an invalid api_key_env"
                )
            api_key = os.getenv(api_key_env, "")
            if not api_key.strip():
                raise ValueError(
                    f"{path}: environment variable {api_key_env} is missing or empty"
                )
        else:
            api_key = literal_api_key
        literal_ip = str(entry.get("ip", "")).strip()
        literal_url = str(entry.get("url", "")).strip()
        url_env = str(entry.get("url_env", "")).strip()
        if sum(bool(value) for value in (literal_ip, literal_url, url_env)) != 1:
            raise ValueError(
                f"{path}: target {name!r} must define exactly one of "
                "ip, url or url_env"
            )
        if literal_ip:
            try:
                management_ip = ipaddress.ip_address(literal_ip)
            except ValueError as exc:
                raise ValueError(
                    f"{path}: target {name!r} has an invalid IP address"
                ) from exc
            url_host = (
                f"[{management_ip}]" if management_ip.version == 6 else str(management_ip)
            )
            raw_url = f"https://{url_host}"
        elif url_env:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", url_env):
                raise ValueError(f"{path}: target {name!r} has an invalid url_env")
            raw_url = os.getenv(url_env, "")
            if not raw_url.strip():
                raise ValueError(
                    f"{path}: environment variable {url_env} is missing or empty"
                )
        else:
            raw_url = literal_url
        target_serial_value = str(entry.get("target_serial", "")).strip() or None
        raw_serials = entry.get("serials", [])
        if not isinstance(raw_serials, list):
            raise ValueError(f"{path}: target {name!r} serials must be a list")
        if entry.get("serial") not in (None, ""):
            raw_serials = [entry["serial"], *raw_serials]
        serials = tuple(
            dict.fromkeys(
                str(value).strip() for value in raw_serials if str(value).strip()
            )
        )
        if target_serial_value and target_serial_value not in serials:
            serials = (*serials, target_serial_value)
        raw_sources = entry.get(
            "syslog_sources",
            [str(management_ip)] if literal_ip else [],
        )
        if not isinstance(raw_sources, list) or not raw_sources:
            raise ValueError(
                f"{path}: target {name!r} syslog_sources must be a non-empty list"
            )
        sources: list[str] = []
        for value in raw_sources:
            try:
                sources.append(str(ipaddress.ip_address(str(value).strip())))
            except ValueError as exc:
                raise ValueError(
                    f"{path}: target {name!r} has an invalid Syslog source"
                ) from exc
        for serial in serials:
            owner = serial_owners.setdefault(serial.lower(), name)
            if owner != name:
                raise ValueError(f"{path}: serial {serial!r} belongs to multiple targets")
        profiles.append(
            TargetProfile(
                name=name,
                panos_url=normalize_panos_url(raw_url),
                api_key=api_key,
                target_serial=target_serial_value,
                serials=serials,
                syslog_sources=tuple(dict.fromkeys(sources)),
                tls_verify=_parse_tls_verify(
                    entry.get("tls_verify", os.getenv("PANOS_TLS_VERIFY", "false"))
                ),
            )
        )
    return tuple(profiles)


@dataclass(frozen=True)
class Config:
    panos_url: str
    api_key: str = field(repr=False)
    target_serial: str | None
    tls_verify: bool | str
    syslog_host: str
    syslog_port: int
    poll_seconds: float
    max_monitor_seconds: float
    incident_idle_ttl_seconds: float
    recovery_threshold: int
    low_samples_to_stop: int
    request_timeout: float
    max_session_lookups: int
    session_retry_seconds: float
    output_dir: Path
    generate_html_report: bool
    generate_text_export: bool = True
    target_name: str | None = None
    target_profiles: tuple[TargetProfile, ...] = ()
    config_revision: int | None = None
    dp_core_functions: tuple[dict[str, Any], ...] = ()
    dp_core_functions_identity: str | None = None

    def __post_init__(self) -> None:
        numeric_rules = (
            ("SYSLOG_PORT", self.syslog_port, 1 <= self.syslog_port <= 65535),
            (
                "POLL_SECONDS",
                self.poll_seconds,
                math.isfinite(self.poll_seconds) and self.poll_seconds > 0,
            ),
            (
                "MAX_MONITOR_SECONDS",
                self.max_monitor_seconds,
                math.isfinite(self.max_monitor_seconds)
                and self.max_monitor_seconds > 0,
            ),
            (
                "INCIDENT_IDLE_TTL_SECONDS",
                self.incident_idle_ttl_seconds,
                math.isfinite(self.incident_idle_ttl_seconds)
                and self.incident_idle_ttl_seconds > 0,
            ),
            (
                "RECOVERY_THRESHOLD",
                self.recovery_threshold,
                0 <= self.recovery_threshold <= 100,
            ),
            (
                "LOW_SAMPLES_TO_STOP",
                self.low_samples_to_stop,
                self.low_samples_to_stop >= 1,
            ),
            (
                "REQUEST_TIMEOUT",
                self.request_timeout,
                math.isfinite(self.request_timeout) and self.request_timeout > 0,
            ),
            (
                "MAX_SESSION_LOOKUPS",
                self.max_session_lookups,
                self.max_session_lookups >= 0,
            ),
            (
                "SESSION_RETRY_SECONDS",
                self.session_retry_seconds,
                math.isfinite(self.session_retry_seconds)
                and self.session_retry_seconds >= 0,
            ),
        )
        for name, value, valid in numeric_rules:
            if not valid:
                raise ValueError(f"{name} has an invalid value: {value!r}")

    @classmethod
    def from_env(cls) -> "Config":
        config_db = os.getenv("PBP_CONFIG_DB", "").strip()
        if config_db:
            return cls.from_store(ConfigStore(Path(config_db)))
        targets_file = os.getenv("PANOS_TARGETS_FILE", "").strip()
        target_profiles = (
            load_target_profiles(Path(targets_file)) if targets_file else ()
        )
        if target_profiles:
            primary = target_profiles[0]
            panos_url = primary.panos_url
            api_key = primary.api_key
            target_serial = primary.target_serial
            tls_verify = primary.tls_verify
        else:
            panos_url = normalize_panos_url(os.environ["PANOS_URL"])
            api_key = os.environ["PANOS_API_KEY"]
            if not api_key.strip():
                raise ValueError("PANOS_API_KEY must not be empty")
            target_serial = os.getenv("PANOS_TARGET_SERIAL") or None
            tls_verify = _parse_tls_verify(os.getenv("PANOS_TLS_VERIFY", "false"))

        return cls(
            panos_url=panos_url,
            api_key=api_key,
            target_serial=target_serial,
            tls_verify=tls_verify,
            syslog_host=os.getenv("SYSLOG_HOST", "0.0.0.0"),
            syslog_port=int(os.getenv("SYSLOG_PORT", "5514")),
            poll_seconds=float(os.getenv("POLL_SECONDS", "5")),
            max_monitor_seconds=float(os.getenv("MAX_MONITOR_SECONDS", "900")),
            incident_idle_ttl_seconds=float(
                os.getenv("INCIDENT_IDLE_TTL_SECONDS", "300")
            ),
            recovery_threshold=int(os.getenv("RECOVERY_THRESHOLD", "40")),
            low_samples_to_stop=int(os.getenv("LOW_SAMPLES_TO_STOP", "3")),
            request_timeout=float(os.getenv("REQUEST_TIMEOUT", "15")),
            max_session_lookups=int(os.getenv("MAX_SESSION_LOOKUPS", "10")),
            session_retry_seconds=float(os.getenv("SESSION_RETRY_SECONDS", "5")),
            output_dir=Path(os.getenv("OUTPUT_DIR", "./captures")),
            generate_html_report=env_bool("GENERATE_HTML_REPORT", True),
            generate_text_export=env_bool("GENERATE_TEXT_EXPORT", True),
            target_profiles=target_profiles,
        )

    @classmethod
    def from_store(cls, store: ConfigStore) -> "Config":
        """Load validated runtime settings and decrypted targets from SQLite."""
        store.initialize()
        values = store.get_settings()
        stored_targets = store.list_targets(include_secrets=True)
        profiles: list[TargetProfile] = []
        serial_owners: dict[str, str] = {}
        for item in stored_targets:
            if not isinstance(item, StoredTarget) or not item.enabled:
                continue
            for serial in item.serials:
                owner = serial_owners.setdefault(serial.lower(), item.name)
                if owner != item.name:
                    raise ValueError(f"serial {serial!r} belongs to multiple targets")
            profiles.append(
                TargetProfile(
                    name=item.name,
                    panos_url=item.panos_url,
                    api_key=item.api_key,
                    target_serial=item.target_serial,
                    serials=item.serials,
                    syslog_sources=item.syslog_sources,
                    tls_verify=_parse_tls_verify(item.tls_verify),
                    dp_core_functions=item.dp_core_functions,
                    dp_core_functions_identity=item.dp_core_functions_identity,
                )
            )
        primary = profiles[0] if profiles else None
        return cls(
            panos_url=primary.panos_url if primary else "https://configuration.invalid",
            api_key=primary.api_key if primary else "",
            target_serial=primary.target_serial if primary else None,
            tls_verify=primary.tls_verify if primary else False,
            dp_core_functions=primary.dp_core_functions if primary else (),
            dp_core_functions_identity=(
                primary.dp_core_functions_identity if primary else None
            ),
            syslog_host=os.getenv("SYSLOG_HOST", "0.0.0.0"),
            syslog_port=int(os.getenv("SYSLOG_PORT", "5514")),
            poll_seconds=float(values["poll_seconds"]),
            max_monitor_seconds=float(values["max_monitor_seconds"]),
            incident_idle_ttl_seconds=float(values["incident_idle_ttl_seconds"]),
            recovery_threshold=int(values["recovery_threshold"]),
            low_samples_to_stop=int(values["low_samples_to_stop"]),
            request_timeout=float(values["request_timeout"]),
            max_session_lookups=int(values["max_session_lookups"]),
            session_retry_seconds=float(values["session_retry_seconds"]),
            output_dir=Path(os.getenv("OUTPUT_DIR", "./captures")),
            generate_html_report=values["generate_html_report"].lower() in {"1", "true", "yes", "on"},
            generate_text_export=values["generate_text_export"].lower() in {"1", "true", "yes", "on"},
            target_profiles=tuple(profiles),
            config_revision=store.revision(),
        )

    def for_target(self, profile: TargetProfile) -> "Config":
        return replace(
            self,
            panos_url=profile.panos_url,
            api_key=profile.api_key,
            target_serial=profile.target_serial,
            tls_verify=profile.tls_verify,
            output_dir=self.output_dir / "targets" / profile.name,
            target_name=profile.name,
            target_profiles=(),
            dp_core_functions=profile.dp_core_functions,
            dp_core_functions_identity=profile.dp_core_functions_identity,
        )


@dataclass(frozen=True)
class PanOSResponse:
    result_xml: str
    raw_response: str


class PanOSAPIError(RuntimeError):
    def __init__(self, message: str, *, raw_response: str = ""):
        super().__init__(message)
        self.raw_response = raw_response


class RejectRedirectHandler(HTTPRedirectHandler):
    """PAN-OS API endpoints must never redirect authenticated requests."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        raise PanOSAPIError("PAN-OS API redirect refused")


class PanOSClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        if cfg.tls_verify is False:
            LOG.warning(
                "TLS certificate verification is disabled for target %s",
                cfg.target_name or cfg.panos_url,
            )
            self.ssl_context = ssl._create_unverified_context()
        elif isinstance(cfg.tls_verify, str):
            self.ssl_context = ssl.create_default_context(cafile=cfg.tls_verify)
        else:
            self.ssl_context = ssl.create_default_context()
        self.opener = build_opener(
            HTTPSHandler(context=self.ssl_context),
            RejectRedirectHandler(),
        )

    def op_response(self, command_xml: str) -> PanOSResponse:
        params = {"type": "op", "cmd": command_xml}
        if self.cfg.target_serial:
            params["target"] = self.cfg.target_serial
        request = Request(
            f"{self.cfg.panos_url}/api/",
            data=urlencode(params).encode("utf-8"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        request.add_unredirected_header("X-PAN-KEY", self.cfg.api_key)
        try:
            with self.opener.open(
                request,
                timeout=self.cfg.request_timeout,
            ) as response:
                response_text = response.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            response_text = exc.read().decode("utf-8", errors="replace")
            raise PanOSAPIError(
                f"PAN-OS returned HTTP error {exc.code}",
                raw_response=response_text,
            ) from exc
        try:
            root = ET.fromstring(response_text)
        except ET.ParseError as exc:
            raise PanOSAPIError(
                "PAN-OS returned invalid XML",
                raw_response=response_text,
            ) from exc
        if root.attrib.get("status") != "success":
            message = " ".join(text.strip() for text in root.itertext() if text.strip())
            raise PanOSAPIError(
                message or "PAN-OS operation failed",
                raw_response=response_text,
            )
        result = root.find("result")
        result_xml = (
            ET.tostring(result, encoding="unicode") if result is not None else response_text
        )
        return PanOSResponse(result_xml=result_xml, raw_response=response_text)

    def op(self, command_xml: str) -> str:
        """Return the result XML for callers that do not need the raw envelope."""
        return self.op_response(command_xml).result_xml

    def session(self, session_id: int) -> str:
        return self.op(f"<show><session><id>{session_id}</id></session></show>")

    def session_response(self, session_id: int) -> PanOSResponse:
        return self.op_response(f"<show><session><id>{session_id}</id></session></show>")


def extract_session_ids(*outputs: str) -> list[int]:
    """Extract session IDs without confusing IPv4 addresses with IDs."""
    found: set[int] = set()
    xml_tag = re.compile(r"<(?:session-id|sess-id|session_id)>\s*(\d+)\s*</", re.I)
    pbp_row = re.compile(r"(?m)^\s*(\d+)\s*\|")
    top_row = re.compile(
        r"(?m)^\s*(\d+)\s+\d+(?:\.\d+)?%\s+"
        r"(?:\d+|flow_[A-Za-z0-9_-]+)\s+\d+\b"
    )
    detail_row = re.compile(
        r"(?m)^\s*(\d+)\s+(?:\d{1,3}|[A-Za-z][A-Za-z0-9_-]*)\s+"
        r"\S+\s+[0-9A-Fa-f:.]+\s+"
    )
    for output in outputs:
        for regex in (xml_tag, pbp_row, top_row, detail_row):
            found.update(int(value) for value in regex.findall(output))
    return sorted(found)


def panos_result_text(output: str) -> str:
    """Return human-readable result text while tolerating legacy/plain captures."""
    if not output:
        return ""
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return output
    result = root if root.tag == "result" else root.find("result")
    if result is None:
        return output
    return "".join(result.itertext())


def _percentages(pattern: str, output: str) -> list[float]:
    return [float(value) for value in re.findall(pattern, output, re.I)]


def _local_tag(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1].lower()


def _child_text(element: ET.Element, name: str) -> str | None:
    wanted = name.lower()
    for child in element:
        if _local_tag(child) == wanted and child.text:
            return child.text.strip()
    return None


def _float_value(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value.strip().rstrip("%"))
    except ValueError:
        return None


def _int_value(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return None
    try:
        return int(value.strip().replace(",", ""))
    except ValueError:
        return None


def _first_child_text(element: ET.Element, *names: str) -> str | None:
    for name in names:
        value = _child_text(element, name)
        if value is not None:
            return value
    return None


def _first_descendant_text(element: ET.Element, *names: str) -> str | None:
    wanted = {name.lower() for name in names}
    for descendant in element.iter():
        if _local_tag(descendant) in wanted and descendant.text:
            value = descendant.text.strip()
            if value:
                return value
    return None


def _entity_type(subject: str) -> str:
    if subject.isdigit():
        return "session"
    try:
        ipaddress.ip_address(subject)
    except ValueError:
        return "unknown"
    return "source_ip"


def _structured_pbp_offenders(output: str) -> list[dict[str, Any]]:
    """Read the monitored-entry table from the structured XML form.

    PAN-OS returns one ``<entry>`` per monitored session or blocked source IP,
    carrying the same eight fields as the columns of the CLI table. The
    dataplane is part of the enclosing element name, as in
    ``sw.comm.s1.dp0.packet-buffer-protection``.
    """
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return []
    offenders: list[dict[str, Any]] = []
    dp_ranks: dict[str | None, int] = {}
    for element in root.iter():
        tag = _local_tag(element)
        if not tag.endswith("packet-buffer-protection"):
            continue
        dp_match = re.search(r"(?:^|\.)(dp\d+)(?:\.|$)", tag)
        current_dp = dp_match.group(1) if dp_match else None
        for entry in element.iter():
            if _local_tag(entry) != "entry":
                continue
            subject = (_child_text(entry, "value") or "").strip()
            entity_type = _entity_type(subject) if subject else "unknown"
            if entity_type == "unknown":
                continue
            samples = _int_value(_child_text(entry, "pcs"))
            percentage = _float_value(_child_text(entry, "perc"))
            packets_total = _int_value(_child_text(entry, "num-total"))
            packets_dropped = _int_value(_child_text(entry, "num-dropped"))
            if (
                samples is None
                or percentage is None
                or packets_total is None
                or packets_dropped is None
            ):
                continue
            drop_state_raw = _child_text(entry, "drop-state")
            dp_ranks[current_dp] = dp_ranks.get(current_dp, 0) + 1
            offenders.append(
                {
                    "rank": len(offenders) + 1,
                    "dp_rank": dp_ranks[current_dp],
                    "dp": current_dp,
                    "entity_type": entity_type,
                    "session_id": int(subject) if entity_type == "session" else None,
                    "source_ip": subject if entity_type == "source_ip" else None,
                    "zone": _child_text(entry, "zone"),
                    "samples": samples,
                    "percentage": percentage,
                    "drop_state": (drop_state_raw or "").strip().lower() == "yes",
                    "drop_state_raw": drop_state_raw or None,
                    "packets_total": packets_total,
                    "packets_dropped": packets_dropped,
                    "time_till_discard_seconds": _int_value(
                        _child_text(entry, "time-till-discard")
                    ),
                }
            )
    return offenders


def extract_pbp_offenders(output: str) -> list[dict[str, Any]]:
    """Parse PBP offender rows without losing direction, order, or IP entries."""
    structured = _structured_pbp_offenders(output)
    if structured:
        return structured
    text = panos_result_text(output)
    offenders: list[dict[str, Any]] = []
    current_dp: str | None = None
    dp_ranks: dict[str | None, int] = {}
    for line in text.splitlines():
        dp_match = re.fullmatch(r"\s*(dp\d+)\s*", line, re.I)
        if dp_match:
            current_dp = dp_match.group(1).lower()
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 8:
            continue
        samples = _int_value(parts[2])
        percentage = _float_value(parts[3])
        packets_total = _int_value(parts[5])
        packets_dropped = _int_value(parts[6])
        if (
            not parts[0]
            or samples is None
            or percentage is None
            or packets_total is None
            or packets_dropped is None
        ):
            continue
        entity_type = _entity_type(parts[0])
        if entity_type == "unknown":
            continue
        dp_ranks[current_dp] = dp_ranks.get(current_dp, 0) + 1
        record: dict[str, Any] = {
            "rank": len(offenders) + 1,
            "dp_rank": dp_ranks[current_dp],
            "dp": current_dp,
            "entity_type": entity_type,
            "session_id": int(parts[0]) if entity_type == "session" else None,
            "source_ip": parts[0] if entity_type == "source_ip" else None,
            "zone": parts[1] or None,
            "samples": samples,
            "percentage": percentage,
            "drop_state": parts[4].strip().lower() == "yes",
            "drop_state_raw": parts[4] or None,
            "packets_total": packets_total,
            "packets_dropped": packets_dropped,
            "time_till_discard_seconds": _int_value(parts[7]),
        }
        offenders.append(record)
    return offenders


def _panos_flag(value: str | None) -> bool | None:
    """Interpret the boolean-like element text used by operational XML."""
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"true", "yes", "1"}:
        return True
    if normalized in {"false", "no", "0"}:
        return False
    return None


def _structured_pbp_state(output: str) -> dict[str, Any]:
    """Read PBP mode and activation flags from the structured XML form.

    A chassis reports one element per dataplane, so a single dataplane in
    mitigation is enough to consider the firewall affected.
    """
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return {}
    enabled: list[bool] = []
    running: list[bool] = []
    monitor_only: list[bool] = []
    modes: list[str] = []
    for element in root.iter():
        if not _local_tag(element).endswith("packet-buffer-protection"):
            continue
        for name, sink in (
            ("is-module-enabled", enabled),
            ("is-running", running),
            ("is-monitor-only", monitor_only),
        ):
            flag = _panos_flag(_child_text(element, name))
            if flag is not None:
                sink.append(flag)
        if _panos_flag(_child_text(element, "use-latency")):
            modes.append("latency")
        elif _panos_flag(_child_text(element, "use-buffer")):
            modes.append("packet_buffer")
    state: dict[str, Any] = {}
    if enabled:
        state["enabled"] = any(enabled)
    if running:
        state["active"] = any(running)
    if monitor_only:
        state["monitor_only"] = any(monitor_only)
    if modes:
        state["mode"] = "latency" if "latency" in modes else "packet_buffer"
    return state


def extract_pbp_status(
    output: str,
    offenders: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Extract PBP mode and activation state without changing configuration."""
    text = panos_result_text(output)
    lowered = text.lower()
    if "latency measurement based" in lowered or "latency based" in lowered:
        mode = "latency"
    elif "packet buffer count based" in lowered:
        mode = "packet_buffer"
    else:
        mode = "unknown"
    if "packet buffer protection is disabled" in lowered:
        enabled: bool | None = False
    elif text.strip():
        enabled = True
    else:
        enabled = None
    if "not activated" in lowered or "system resource usage is low" in lowered:
        active: bool | None = False
    elif offenders or "drop probability" in lowered:
        active = True
    else:
        active = None
    congestion_values = _percentages(
        r"Congestion:\s*\d+/\d+\s*\((\d+(?:\.\d+)?)%\)",
        text,
    ) or _structured_pbp_percentages(output)
    drop_probability = _float_value(
        next(
            iter(
                re.findall(
                    r"Drop probability:\s*(\d+(?:\.\d+)?)%",
                    text,
                    re.I,
                )
            ),
            None,
        )
    )
    status: dict[str, Any] = {
        "enabled": enabled,
        "active": active,
        "mode": mode,
        "monitor_only": bool(
            re.search(r"\bmonitor(?:[- ]only| mode)\b", text, re.I)
        ),
        "congestion_percentage": max(congestion_values) if congestion_values else None,
        "drop_probability_percentage": drop_probability,
    }
    # The structured form is authoritative when the release returns it.
    status.update(_structured_pbp_state(output))
    return status


_SESSION_INFO_XML_FIELDS = (
    ("num-max", "supported"),
    ("num-active", "allocated"),
    ("num-tcp", "tcp"),
    ("num-udp", "udp"),
    ("num-icmp", "icmp"),
    ("num-sctp-sess", "sctp_sessions"),
    ("num-sctp-assoc", "sctp_associations"),
    ("num-gtpc", "gtpc"),
    ("num-gtpu-active", "gtpu_active"),
    ("num-gtpu-pending", "gtpu_pending"),
    ("num-http2-5gc", "http2_5gc"),
    ("num-pfcpc", "pfcp"),
    ("num-imsi", "imsi"),
    ("num-bcast", "bcast"),
    ("num-mcast", "mcast"),
    ("num-predict", "predict"),
    ("num-installed", "created_since_bootup"),
    ("cps", "connection_rate_cps"),
    ("pps", "packet_rate_pps"),
    ("kbps", "throughput_kbps"),
)
_SESSION_INFO_TEXT_FIELDS = (
    ("Number of sessions supported", "supported"),
    ("Number of allocated sessions", "allocated"),
    ("Number of active TCP sessions", "tcp"),
    ("Number of active UDP sessions", "udp"),
    ("Number of active ICMP sessions", "icmp"),
    ("Number of active GTPc sessions", "gtpc"),
    ("Number of active HTTP2-5gc sessions", "http2_5gc"),
    ("Number of active GTPu sessions", "gtpu_active"),
    ("Number of pending GTPu sessions", "gtpu_pending"),
    ("Number of active BCAST sessions", "bcast"),
    ("Number of active MCAST sessions", "mcast"),
    ("Number of active predict sessions", "predict"),
    ("Number of active SCTP sessions", "sctp_sessions"),
    ("Number of active SCTP associations", "sctp_associations"),
    ("Number of active PFCP sessions", "pfcp"),
    ("Number of active IMSI sessions", "imsi"),
    ("Number of sessions created since bootup", "created_since_bootup"),
    ("Session table utilization", "utilization_percentage"),
    ("Packet rate", "packet_rate_pps"),
    ("Throughput", "throughput_kbps"),
    ("New connection establish rate", "connection_rate_cps"),
)
_SESSION_INFO_COUNTS = tuple(
    key for _, key in _SESSION_INFO_XML_FIELDS if key != "supported"
) + ("supported",)


def _session_number(value: str | None) -> int | float | None:
    """Keep counters as integers and rates as the number PAN-OS reported."""
    number = _float_value(value)
    if number is None:
        return None
    return int(number) if number.is_integer() else number


def _session_utilization(allocated: Any, supported: Any) -> float | None:
    """Derive the session table utilization the API does not return as a field."""
    if not isinstance(allocated, (int, float)) or not isinstance(supported, (int, float)):
        return None
    if supported <= 0:
        return None
    return round(float(allocated) * 100.0 / float(supported), 2)


def _session_info_totals(dataplanes: list[dict[str, Any]]) -> dict[str, Any]:
    """Sum per-dataplane counters so a chassis reports one device-wide view."""
    totals: dict[str, Any] = {}
    for key in _SESSION_INFO_COUNTS:
        values = [
            dataplane[key]
            for dataplane in dataplanes
            if isinstance(dataplane.get(key), (int, float))
        ]
        totals[key] = sum(values) if values else None
    totals["utilization_percentage"] = _session_utilization(
        totals.get("allocated"),
        totals.get("supported"),
    )
    if totals["utilization_percentage"] is None:
        reported = [
            dataplane["utilization_percentage"]
            for dataplane in dataplanes
            if isinstance(dataplane.get("utilization_percentage"), (int, float))
        ]
        totals["utilization_percentage"] = max(reported) if reported else None
    return totals


def extract_session_info(output: str) -> dict[str, Any]:
    """Parse the session table, protocol mix, and traffic rates of each dataplane.

    ``show session info`` is the only command that states how many sessions
    exist while the buffers are under pressure. A flood denied before session
    setup raises the packet rate without moving the session counters, which is
    exactly what separates it from a session-based flood.
    """
    dataplanes: list[dict[str, Any]] = []

    def add(dataplane: str | None, values: dict[str, Any]) -> None:
        if not any(value is not None for value in values.values()):
            return
        record: dict[str, Any] = {"dp": dataplane}
        for key in _SESSION_INFO_COUNTS:
            record[key] = values.get(key)
        # PAN-OS prints the utilization truncated to a whole percent, which
        # hides the movement of a session table this far from its limit.
        utilization = _session_utilization(
            values.get("allocated"),
            values.get("supported"),
        )
        if utilization is None:
            reported = values.get("utilization_percentage")
            utilization = reported if isinstance(reported, (int, float)) else None
        record["utilization_percentage"] = utilization
        dataplanes.append(record)

    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        root = None

    if root is not None:
        for element in root.iter():
            children = {_local_tag(child): child for child in element}
            if "num-max" not in children and "num-active" not in children:
                continue
            values: dict[str, Any] = {}
            for tag, key in _SESSION_INFO_XML_FIELDS:
                child = children.get(tag)
                values[key] = _session_number(
                    child.text if child is not None else None
                )
            dp_element = children.get("dp")
            dataplane = (
                dp_element.text.strip()
                if dp_element is not None and dp_element.text
                else None
            )
            add(dataplane, values)
        if dataplanes:
            return {"dataplanes": dataplanes, "totals": _session_info_totals(dataplanes)}

    current_dp: str | None = None
    values = {}
    for line in panos_result_text(output).splitlines():
        target = re.match(r"\s*target-dp\s*:\s*(\S+)", line, re.I)
        if target:
            add(current_dp, values)
            current_dp = target.group(1)
            values = {}
            continue
        label, separator, remainder = line.partition(":")
        if not separator:
            continue
        name = label.strip().lower()
        key = next(
            (
                field
                for text, field in _SESSION_INFO_TEXT_FIELDS
                if text.lower() == name
            ),
            None,
        )
        if key is None:
            continue
        number = re.search(r"-?\d+(?:\.\d+)?", remainder)
        if number:
            values[key] = _session_number(number.group(0))
    add(current_dp, values)
    return {"dataplanes": dataplanes, "totals": _session_info_totals(dataplanes)}


def extract_ingress_backlogs(output: str) -> dict[str, list[dict[str, Any]]]:
    """Parse per-DP ingress usage, ranked sessions, and their inline details."""
    text = panos_result_text(output)
    dataplanes: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    current_slot: str | None = None
    current_dp: str | None = None
    section: str | None = None
    context_ranks: dict[tuple[str | None, str | None], int] = {}

    def add_dataplane(
        slot: str | None,
        dp: str | None,
        atomic: float | None,
        total: float | None,
    ) -> None:
        if atomic is None and total is None:
            return
        existing = next(
            (
                item
                for item in dataplanes
                if item.get("slot") == slot and item.get("dp") == dp
            ),
            None,
        )
        if existing is None:
            dataplanes.append(
                {
                    "slot": slot,
                    "dp": dp,
                    "atomic_percentage": atomic,
                    "total_percentage": total,
                }
            )
        else:
            if atomic is not None:
                existing["atomic_percentage"] = atomic
            if total is not None:
                existing["total_percentage"] = total

    def matching_candidate(
        slot: str | None,
        dp: str | None,
        session_id: int,
    ) -> dict[str, Any] | None:
        exact = next(
            (
                item
                for item in reversed(candidates)
                if item.get("slot") == slot
                and item.get("dp") == dp
                and item.get("session_id") == session_id
            ),
            None,
        )
        if exact is not None:
            return exact
        same_id = [
            item for item in candidates if item.get("session_id") == session_id
        ]
        return same_id[0] if slot is None and dp is None and len(same_id) == 1 else None

    context_pattern = re.compile(
        r"SLOT\s*:\s*([^,\s-]+)\s*,\s*DP\s*:\s*([^\s-]+)",
        re.I,
    )
    usage_pattern = re.compile(
        r"USAGE\s*-\s*ATOMIC\s*:\s*(\d+(?:\.\d+)?)%?\s+"
        r"TOTAL\s*:\s*(\d+(?:\.\d+)?)%?",
        re.I,
    )
    for line in text.splitlines():
        context_match = context_pattern.search(line)
        if context_match:
            current_slot = context_match.group(1)
            current_dp = context_match.group(2)
            section = None
        usage_match = usage_pattern.search(line)
        if usage_match:
            add_dataplane(
                current_slot,
                current_dp,
                float(usage_match.group(1)),
                float(usage_match.group(2)),
            )
            continue
        normalized = line.strip().upper()
        if normalized.startswith("TOP SESSIONS"):
            section = "top"
            continue
        if normalized.startswith("SESSION DETAILS"):
            section = "details"
            continue
        tokens = line.split()
        if section == "top" and len(tokens) >= 4:
            session_id = _int_value(tokens[0])
            percentage = _float_value(tokens[1])
            if session_id is None or percentage is None:
                continue
            groups = []
            for index in range(2, len(tokens) - 1, 2):
                count = _int_value(tokens[index + 1])
                if count is not None:
                    groups.append({"group_id": tokens[index], "count": count})
            if not groups:
                continue
            context = (current_slot, current_dp)
            context_ranks[context] = context_ranks.get(context, 0) + 1
            candidates.append(
                {
                    "rank": len(candidates) + 1,
                    "dp_rank": context_ranks[context],
                    "slot": current_slot,
                    "dp": current_dp,
                    "session_id": session_id,
                    "percentage": percentage,
                    "group_id": groups[0]["group_id"],
                    "count": groups[0]["count"],
                    "groups": groups,
                }
            )
            continue
        if section == "details" and len(tokens) >= 10:
            session_id = _int_value(tokens[0])
            protocol = _int_value(tokens[1])
            source_port = _int_value(tokens[4])
            destination_port = _int_value(tokens[6])
            if (
                session_id is None
                or protocol is None
                or not 0 <= protocol <= 255
                or source_port is None
                or destination_port is None
            ):
                continue
            candidate = matching_candidate(current_slot, current_dp, session_id)
            if candidate is None:
                context = (current_slot, current_dp)
                context_ranks[context] = context_ranks.get(context, 0) + 1
                candidate = {
                    "rank": len(candidates) + 1,
                    "dp_rank": context_ranks[context],
                    "slot": current_slot,
                    "dp": current_dp,
                    "session_id": session_id,
                    "percentage": None,
                    "group_id": None,
                    "count": None,
                    "groups": [],
                }
                candidates.append(candidate)
            candidate.update(
                {
                    "protocol": protocol,
                    "source_zone": tokens[2],
                    "source_ip": tokens[3],
                    "source_port": source_port,
                    "destination_ip": tokens[5],
                    "destination_port": destination_port,
                    "ingress_interface": tokens[7],
                    "egress_interface": tokens[8],
                    "type": tokens[9] if len(tokens) >= 11 else None,
                    "application": " ".join(tokens[10:] if len(tokens) >= 11 else tokens[9:]),
                }
            )

    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        root = None
    if root is not None:
        for element in root.iter():
            slot = _first_child_text(element, "SLOT", "slot")
            dp = _first_child_text(element, "DP", "dp")
            atomic = _float_value(_first_child_text(element, "ATOMIC", "atomic"))
            total = _float_value(_first_child_text(element, "TOTAL", "total"))
            if slot is not None or dp is not None:
                add_dataplane(slot, dp, atomic, total)

            session_id = _int_value(
                _first_child_text(
                    element,
                    "SESS-ID",
                    "session-id",
                    "sess-id",
                    "session_id",
                )
            )
            percentage = _float_value(
                _first_child_text(element, "PCT", "percentage", "percent")
            )
            group_id = _first_child_text(element, "GRP-ID", "group-id", "group_id")
            count = _int_value(_first_child_text(element, "COUNT", "count"))
            source_ip = _first_child_text(element, "SRC", "source", "source-ip")
            destination_ip = _first_child_text(
                element,
                "DST",
                "destination",
                "destination-ip",
            )
            if session_id is None or (
                percentage is None
                and group_id is None
                and source_ip is None
                and destination_ip is None
            ):
                continue
            candidate = matching_candidate(slot, dp, session_id)
            if candidate is None:
                context = (slot, dp)
                context_ranks[context] = context_ranks.get(context, 0) + 1
                candidate = {
                    "rank": len(candidates) + 1,
                    "dp_rank": context_ranks[context],
                    "slot": slot,
                    "dp": dp,
                    "session_id": session_id,
                    "groups": [],
                }
                candidates.append(candidate)
            structured_fields = {
                "percentage": percentage,
                "group_id": group_id,
                "count": count,
                "protocol": _int_value(
                    _first_child_text(element, "PROTO", "protocol")
                ),
                "source_zone": _first_child_text(
                    element,
                    "SZONE",
                    "source-zone",
                    "source_zone",
                ),
                "source_ip": source_ip,
                "source_port": _int_value(
                    _first_child_text(element, "SPORT", "source-port")
                ),
                "destination_ip": destination_ip,
                "destination_port": _int_value(
                    _first_child_text(element, "DPORT", "destination-port")
                ),
                "ingress_interface": _first_child_text(
                    element,
                    "IGR-IF",
                    "ingress-interface",
                ),
                "egress_interface": _first_child_text(
                    element,
                    "EGR-IF",
                    "egress-interface",
                ),
                "type": _first_child_text(element, "TYPE", "type"),
                "application": _first_child_text(element, "APP", "application"),
            }
            candidate.update(
                {
                    name: value
                    for name, value in structured_fields.items()
                    if value is not None
                }
            )
            if group_id is not None and count is not None:
                candidate["groups"] = [{"group_id": group_id, "count": count}]

    return {"dataplanes": dataplanes, "candidates": candidates}


def build_candidate_entities(
    pbp_offenders: list[dict[str, Any]],
    ingress_candidates: list[dict[str, Any]],
    fallback_session_ids: list[int] | None = None,
    trigger_session_ids: list[int] | None = None,
    trigger_source_ips: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Aggregate and rank session/IP evidence for immediate enrichment."""
    entities: dict[tuple[str, str], dict[str, Any]] = {}
    order = 0

    def ensure(entity_type: str, identifier: str) -> dict[str, Any]:
        nonlocal order
        key = (entity_type, identifier)
        if key not in entities:
            order += 1
            entities[key] = {
                "entity_type": entity_type,
                "session_id": int(identifier) if entity_type == "session" else None,
                "source_ip": identifier if entity_type == "source_ip" else None,
                "drop_state": False,
                "pbp_percentage_total": 0.0,
                "pbp_percentage_max": None,
                "pbp_samples": 0,
                "ingress_percentage_max": None,
                "ingress_count": 0,
                "zones": set(),
                "group_ids": set(),
                "evidence_sources": set(),
                "_first_order": order,
            }
        return entities[key]

    for offender in pbp_offenders:
        entity_type = str(offender.get("entity_type") or "unknown")
        identifier = (
            str(offender.get("session_id"))
            if entity_type == "session"
            else str(offender.get("source_ip") or "")
        )
        if entity_type not in {"session", "source_ip"} or not identifier:
            continue
        entity = ensure(entity_type, identifier)
        entity["evidence_sources"].add("packet_buffer_protection")
        entity["drop_state"] = entity["drop_state"] or bool(
            offender.get("drop_state")
        )
        percentage = offender.get("percentage")
        if isinstance(percentage, (int, float)):
            entity["pbp_percentage_total"] += float(percentage)
            current_max = entity["pbp_percentage_max"]
            entity["pbp_percentage_max"] = (
                float(percentage)
                if current_max is None
                else max(float(current_max), float(percentage))
            )
        samples = offender.get("samples")
        if isinstance(samples, int):
            entity["pbp_samples"] += samples
        if offender.get("zone"):
            entity["zones"].add(str(offender["zone"]))

    for candidate in ingress_candidates:
        session_id = candidate.get("session_id")
        if not isinstance(session_id, int):
            continue
        entity = ensure("session", str(session_id))
        entity["evidence_sources"].add("ingress_backlogs")
        percentage = candidate.get("percentage")
        if isinstance(percentage, (int, float)):
            current_max = entity["ingress_percentage_max"]
            entity["ingress_percentage_max"] = (
                float(percentage)
                if current_max is None
                else max(float(current_max), float(percentage))
            )
        count = candidate.get("count")
        if isinstance(count, int):
            entity["ingress_count"] += count
        if candidate.get("source_zone"):
            entity["zones"].add(str(candidate["source_zone"]))
        if candidate.get("group_id"):
            entity["group_ids"].add(str(candidate["group_id"]))

    for session_id in fallback_session_ids or []:
        entity = ensure("session", str(session_id))
        if not entity["evidence_sources"]:
            entity["evidence_sources"].add("raw_session_id")
    for session_id in trigger_session_ids or []:
        ensure("session", str(session_id))["evidence_sources"].add("syslog_trigger")
    for source_ip in trigger_source_ips or []:
        try:
            normalized_ip = str(ipaddress.ip_address(source_ip))
        except ValueError:
            continue
        ensure("source_ip", normalized_ip)["evidence_sources"].add("syslog_trigger")

    def ranking_key(entity: dict[str, Any]) -> tuple[Any, ...]:
        percentages = [
            float(value)
            for value in (
                entity.get("pbp_percentage_total"),
                entity.get("ingress_percentage_max"),
            )
            if isinstance(value, (int, float))
        ]
        strongest_percentage = max(percentages, default=0.0)
        corroborated = len(entity["evidence_sources"] & {
            "packet_buffer_protection",
            "ingress_backlogs",
        }) == 2
        return (
            0 if entity.get("drop_state") else 1,
            -strongest_percentage,
            0 if corroborated else 1,
            -int(entity.get("pbp_samples") or 0),
            -int(entity.get("ingress_count") or 0),
            int(entity["_first_order"]),
        )

    ranked = sorted(entities.values(), key=ranking_key)
    for rank, entity in enumerate(ranked, start=1):
        entity["rank"] = rank
        entity["corroborated"] = len(
            entity["evidence_sources"]
            & {"packet_buffer_protection", "ingress_backlogs"}
        ) == 2
        entity["zones"] = sorted(entity["zones"])
        entity["group_ids"] = sorted(entity["group_ids"])
        entity["evidence_sources"] = sorted(entity["evidence_sources"])
        entity.pop("_first_order", None)
    return ranked


def _line_value(text: str, label_pattern: str) -> str | None:
    match = re.search(
        rf"(?im)^\s*(?:{label_pattern})\s*:\s*([^\r\n]+?)\s*$",
        text,
    )
    return match.group(1).strip() if match else None


def _parse_flow_block(block: str) -> dict[str, Any]:
    source_text = _line_value(block, r"source")
    destination_text = _line_value(block, r"dst|destination")

    def address_and_zone(value: str | None) -> tuple[str | None, str | None]:
        if not value:
            return None, None
        match = re.match(r"(\S+)(?:\s*\[([^\]]+)\])?", value)
        return (match.group(1), match.group(2)) if match else (value, None)

    source_ip, source_zone = address_and_zone(source_text)
    destination_ip, destination_zone = address_and_zone(destination_text)
    protocol_text = _line_value(block, r"proto|protocol")
    source_port_match = re.search(r"(?im)\bsport\s*:\s*(\d+)", block)
    destination_port_match = re.search(r"(?im)\bdport\s*:\s*(\d+)", block)
    state_match = re.search(r"(?im)\bstate\s*:\s*(\S+)", block)
    type_match = re.search(r"(?im)\btype\s*:\s*(\S+)", block)
    return {
        "source_ip": source_ip,
        "source_zone": source_zone,
        "destination_ip": destination_ip,
        "destination_zone": destination_zone,
        "protocol": _int_value(protocol_text) if protocol_text else None,
        "source_port": int(source_port_match.group(1)) if source_port_match else None,
        "destination_port": (
            int(destination_port_match.group(1))
            if destination_port_match
            else None
        ),
        "state": state_match.group(1) if state_match else None,
        "type": type_match.group(1) if type_match else None,
        "source_user": _line_value(block, r"src[ -]user"),
        "destination_user": _line_value(block, r"dst[ -]user"),
    }


def extract_session_summary(
    output: str,
    fallback_session_id: int | None = None,
) -> dict[str, Any]:
    """Normalize the forensic fields from a ``show session id`` snapshot."""
    text = panos_result_text(output)
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        root = None
    session_match = re.search(r"(?im)^\s*session\s+(\d+)\s*$", text)
    xml_session_id = (
        _int_value(_first_descendant_text(root, "session-id", "session_id", "id"))
        if root is not None
        else None
    )
    session_id = (
        int(session_match.group(1))
        if session_match
        else xml_session_id
        if xml_session_id is not None
        else fallback_session_id
    )
    bad_key = bool(re.search(r"(?im)^\s*bad key\s*:", text))
    c2s_match = re.search(
        r"(?ims)^\s*c2s flow\s*:\s*(.*?)(?=^\s*s2c flow\s*:|\Z)",
        text,
    )
    s2c_match = re.search(
        r"(?ims)^\s*s2c flow\s*:\s*(.*?)(?=^\s*(?:start time|timeout|time to live|"
        r"total byte count|layer7 packet count|vsys|application|rule|session to be|"
        r"ingress interface|egress interface|session tracker stage)\s*:|\Z)",
        text,
    )
    c2s = _parse_flow_block(c2s_match.group(1)) if c2s_match else {}
    s2c = _parse_flow_block(s2c_match.group(1)) if s2c_match else {}

    def structured_flow(*names: str) -> dict[str, Any]:
        if root is None:
            return {}
        wanted = {name.lower() for name in names}
        flow_element = next(
            (element for element in root.iter() if _local_tag(element) in wanted),
            None,
        )
        if flow_element is None:
            return {}
        values = {
            "source_ip": _first_child_text(flow_element, "source", "src"),
            "source_zone": _first_child_text(
                flow_element,
                "source-zone",
                "source_zone",
                "zone",
            ),
            "destination_ip": _first_child_text(
                flow_element,
                "destination",
                "dst",
            ),
            "destination_zone": _first_child_text(
                flow_element,
                "destination-zone",
                "destination_zone",
            ),
            "protocol": _int_value(
                _first_child_text(flow_element, "protocol", "proto")
            ),
            "source_port": _int_value(
                _first_child_text(flow_element, "source-port", "sport")
            ),
            "destination_port": _int_value(
                _first_child_text(flow_element, "destination-port", "dport")
            ),
            "state": _first_child_text(flow_element, "state"),
            "type": _first_child_text(flow_element, "type"),
            "source_user": _first_child_text(
                flow_element,
                "source-user",
                "src-user",
            ),
            "destination_user": _first_child_text(
                flow_element,
                "destination-user",
                "dst-user",
            ),
        }
        return {name: value for name, value in values.items() if value is not None}

    if not c2s:
        c2s = structured_flow("c2s", "c2s-flow", "c2s_flow")
    if not s2c:
        s2c = structured_flow("s2c", "s2c-flow", "s2c_flow")

    metadata: dict[str, Any] = {
        "start_time": _line_value(text, r"start time"),
        "timeout": _line_value(text, r"timeout"),
        "time_to_live": _line_value(text, r"time to live"),
        "vsys": _line_value(text, r"vsys"),
        "application": _line_value(text, r"application"),
        "rule": _line_value(text, r"rule"),
        "ingress_interface": _line_value(text, r"ingress interface"),
        "egress_interface": _line_value(text, r"egress interface"),
        "layer7_processing": _line_value(text, r"layer7 processing"),
        "offload": _line_value(text, r"offload"),
        "total_bytes_c2s": _int_value(
            _line_value(text, r"total byte count\s*\(c2s\)")
        ),
        "total_bytes_s2c": _int_value(
            _line_value(text, r"total byte count\s*\(s2c\)")
        ),
        "layer7_packets_c2s": _int_value(
            _line_value(text, r"layer7 packet count\s*\(c2s\)")
        ),
        "layer7_packets_s2c": _int_value(
            _line_value(text, r"layer7 packet count\s*\(s2c\)")
        ),
    }
    metadata = {name: value for name, value in metadata.items() if value is not None}
    if root is not None:
        structured_metadata = {
            "start_time": _first_descendant_text(root, "start-time", "start_time"),
            "timeout": _first_descendant_text(root, "timeout"),
            "time_to_live": _first_descendant_text(root, "time-to-live", "ttl"),
            "vsys": _first_descendant_text(root, "vsys"),
            "application": _first_descendant_text(root, "application", "app"),
            "rule": _first_descendant_text(root, "rule"),
            "ingress_interface": _first_descendant_text(
                root,
                "ingress-interface",
                "ingress_interface",
            ),
            "egress_interface": _first_descendant_text(
                root,
                "egress-interface",
                "egress_interface",
            ),
            "layer7_processing": _first_descendant_text(
                root,
                "layer7-processing",
                "layer7_processing",
            ),
            "offload": _first_descendant_text(root, "offload"),
            "total_bytes_c2s": _int_value(
                _first_descendant_text(root, "total-bytes-c2s", "bytes-c2s")
            ),
            "total_bytes_s2c": _int_value(
                _first_descendant_text(root, "total-bytes-s2c", "bytes-s2c")
            ),
            "layer7_packets_c2s": _int_value(
                _first_descendant_text(root, "layer7-packets-c2s", "packets-c2s")
            ),
            "layer7_packets_s2c": _int_value(
                _first_descendant_text(root, "layer7-packets-s2c", "packets-s2c")
            ),
        }
        for name, value in structured_metadata.items():
            if name not in metadata and value is not None:
                metadata[name] = value
    tracker_stages = {
        name.strip(): value.strip()
        for name, value in re.findall(
            r"(?im)^\s*session tracker stage\s+([^:]+)\s*:\s*([^\r\n]+)",
            text,
        )
    }
    if tracker_stages:
        metadata["tracker_stages"] = tracker_stages

    parsed = bool(c2s or s2c or metadata)
    return {
        "session_id": session_id,
        "status": "bad_key" if bad_key else "parsed" if parsed else "unparsed",
        "available": parsed and not bad_key,
        "bad_key": bad_key,
        "c2s": c2s,
        "s2c": s2c,
        **metadata,
    }


def summarize_session_details(
    details: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    summaries: dict[str, dict[str, Any]] = {}
    for session_id_text, record in details.items():
        session_id = _int_value(session_id_text)
        if not command_succeeded(record):
            summaries[session_id_text] = {
                "session_id": session_id,
                "status": "lookup_failed",
                "available": False,
                "bad_key": False,
                "c2s": {},
                "s2c": {},
            }
            continue
        summaries[session_id_text] = extract_session_summary(
            command_result(record),
            session_id,
        )
    return summaries


def derive_session_rates(
    summaries: dict[str, dict[str, Any]],
    previous_samples: dict[str, dict[str, Any]],
    sampled_at_monotonic: float,
) -> dict[str, dict[str, Any]]:
    """Derive bounded candidate-session throughput from cumulative byte counters."""
    rates: dict[str, dict[str, Any]] = {}
    for session_id_text, summary in summaries.items():
        session_id = _int_value(summary.get("session_id")) or _int_value(
            session_id_text
        )
        result: dict[str, Any] = {
            "session_id": session_id,
            "status": "unavailable",
        }
        if not summary.get("available"):
            rates[session_id_text] = result
            continue

        current_c2s = _int_value(summary.get("total_bytes_c2s"))
        current_s2c = _int_value(summary.get("total_bytes_s2c"))
        if current_c2s is None or current_s2c is None:
            result["status"] = "missing_byte_counters"
            rates[session_id_text] = result
            continue

        previous = previous_samples.get(session_id_text)
        if previous is None:
            result["status"] = "baseline"
        else:
            previous_summary = previous["summary"]
            previous_start = previous_summary.get("start_time")
            current_start = summary.get("start_time")
            interval = sampled_at_monotonic - float(previous["sampled_at_monotonic"])
            previous_c2s = _int_value(previous_summary.get("total_bytes_c2s"))
            previous_s2c = _int_value(previous_summary.get("total_bytes_s2c"))
            if previous_start and current_start and previous_start != current_start:
                result["status"] = "session_reused"
            elif interval <= 0:
                result["status"] = "invalid_interval"
            elif previous_c2s is None or previous_s2c is None:
                result["status"] = "missing_previous_byte_counters"
            elif current_c2s < previous_c2s or current_s2c < previous_s2c:
                result["status"] = "counter_reset"
            else:
                delta_c2s = current_c2s - previous_c2s
                delta_s2c = current_s2c - previous_s2c
                delta_total = delta_c2s + delta_s2c
                result.update(
                    {
                        "status": "calculated",
                        "sample_interval_seconds": round(interval, 3),
                        "delta_bytes_c2s": delta_c2s,
                        "delta_bytes_s2c": delta_s2c,
                        "delta_bytes_total": delta_total,
                        "bits_per_second_c2s": round(8.0 * delta_c2s / interval, 3),
                        "bits_per_second_s2c": round(8.0 * delta_s2c / interval, 3),
                        "bits_per_second_total": round(8.0 * delta_total / interval, 3),
                    }
                )

        previous_samples[session_id_text] = {
            "sampled_at_monotonic": sampled_at_monotonic,
            "summary": summary,
        }
        rates[session_id_text] = result
    return rates


def _structured_pbp_percentages(output: str) -> list[float]:
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return []
    values: list[float] = []
    for element in root.iter():
        if not _local_tag(element).endswith("packet-buffer-protection"):
            continue
        explicit = _float_value(_child_text(element, "congestion-percent"))
        if explicit is not None:
            values.append(explicit)
            continue
        congestion = _float_value(_child_text(element, "congestion"))
        maximum = _float_value(_child_text(element, "congestion-max"))
        if congestion is not None and maximum is not None and maximum > 0:
            values.append(round(100.0 * congestion / maximum, 3))
    return values


def _structured_ingress_percentages(output: str, tag: str) -> list[float]:
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return []
    values: list[float] = []
    wanted = tag.lower()
    for element in root.iter():
        if _local_tag(element) != wanted:
            continue
        value = _float_value(element.text)
        if value is not None:
            values.append(value)
    return values


FASTPATH_FUNCTION = "flow_fastpath"
TASK_LINE = re.compile(
    r"^\s*task\s+(?P<core>\d+)\s*\(\s*pid\s*:\s*(?P<pid>\d+)\s*\)\s*(?P<modules>.*)$",
    re.I,
)


def extract_dp_core_functions(statistics: str) -> list[dict[str, Any]]:
    """Return the static core-to-function-group map for every dataplane.

    PAN-OS assigns each dataplane core a fixed set of function groups, so cores
    are not interchangeable and a quiet core is not necessarily an idle one.
    The map is constant for a platform and PAN-OS release, which is why it is
    collected once per incident rather than on every poll.
    """
    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(dataplane: str, core_id: str, functions: list[str]) -> None:
        identity = (dataplane, core_id)
        if identity in seen or not functions:
            return
        seen.add(identity)
        entries.append(
            {
                "dataplane": dataplane,
                "core_id": core_id,
                "functions": functions,
                "forwards_traffic": FASTPATH_FUNCTION in functions,
            }
        )

    try:
        root = ET.fromstring(statistics)
    except ET.ParseError:
        root = None

    if root is not None:
        for element in root.iter():
            if _local_tag(element) != "entry":
                continue
            dataplane = _child_text(element, "dp")
            if not dataplane:
                continue
            for core in element.iter():
                if _local_tag(core) != "entry" or core is element:
                    continue
                core_id = _child_text(core, "id")
                if core_id is None:
                    continue
                functions = [
                    member.text.strip()
                    for module in core
                    if _local_tag(module) == "modules"
                    for member in module
                    if _local_tag(member) == "member" and member.text
                ]
                add(dataplane.strip().lower(), core_id, functions)
        if entries:
            return entries

    for line in panos_result_text(statistics).splitlines():
        match = TASK_LINE.match(line)
        if not match:
            continue
        functions = match.group("modules").split()
        add("dp0", match.group("core"), functions)
    return entries


def extract_resource_cpu_cores(resource_monitor: str) -> list[dict[str, Any]]:
    """Return per-core CPU series and summaries from the per-second view."""
    samples: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(resource_monitor)
    except ET.ParseError:
        root = None

    if root is not None:
        dataplanes = [
            element
            for element in root.iter()
            if re.fullmatch(r"(?:s\d+)?dp\d+", _local_tag(element), re.I)
        ]
        if not dataplanes:
            dataplanes = [root]
        for dataplane in dataplanes:
            dataplane_name = _local_tag(dataplane)
            if dataplane is root:
                dataplane_name = "dp0"
            for second in dataplane.iter():
                if _local_tag(second) != "second":
                    continue
                current: dict[str, dict[str, Any]] = {}
                for container in second:
                    container_name = _local_tag(container)
                    if container_name not in {
                        "cpu-load",
                        "cpu-load-average",
                        "cpu-load-maximum",
                    }:
                        continue
                    for index, entry in enumerate(container):
                        value_text = _child_text(entry, "value")
                        if not value_text:
                            continue
                        series = [
                            value
                            for item in re.split(r"[\s,]+", value_text.strip())
                            if (value := _float_value(item)) is not None
                        ]
                        if not series:
                            continue
                        core_id = _child_text(entry, "coreid")
                        core_key = str(core_id if core_id is not None else index)
                        sample = current.setdefault(
                            core_key,
                            {"dataplane": dataplane_name, "core_id": core_key},
                        )
                        if container_name == "cpu-load-average":
                            sample["average_series"] = series
                        elif container_name == "cpu-load-maximum":
                            sample["maximum_series"] = series
                        else:
                            sample["average_series"] = series
                            sample["maximum_series"] = series
                for sample in current.values():
                    average_series = sample.get("average_series") or sample.get(
                        "maximum_series", []
                    )
                    maximum_series = sample.get("maximum_series") or average_series
                    if not average_series or not maximum_series:
                        continue
                    sample.update(
                        {
                            "average": average_series[0],
                            "maximum": maximum_series[0],
                            "utilization": maximum_series[0],
                            "window_average": sum(average_series)
                            / len(average_series),
                            "window_peak": max(maximum_series),
                            "seconds_at_or_above_90": sum(
                                value >= 90 for value in maximum_series
                            ),
                            "sample_count": max(
                                len(average_series), len(maximum_series)
                            ),
                        }
                    )
                    samples.append(sample)
        if samples:
            return samples

    text = panos_result_text(resource_monitor)
    lines = text.splitlines()
    current_window: str | None = None
    in_cpu_table = False
    window_pattern = re.compile(
        r"Resource monitoring sampling data\s*\(per\s+([^)]+)\)", re.I
    )
    text_series: dict[str, list[float]] = {}
    for index, line in enumerate(lines):
        window_match = window_pattern.search(line)
        if window_match:
            current_window = window_match.group(1).strip().lower()
            in_cpu_table = False
            continue
        if current_window not in (None, "second"):
            continue
        if re.search(r"CPU load \(%\) during last", line, re.I):
            in_cpu_table = True
            continue
        if in_cpu_table and re.search(r"Resource utilization \(%\)", line, re.I):
            break
        if not in_cpu_table:
            continue
        header_match = re.match(r"\s*core\s+(.+)$", line, re.I)
        if not header_match:
            continue
        core_ids = re.findall(r"\d+", header_match.group(1))
        for value_line in lines[index + 1 :]:
            if re.match(r"\s*core\b", value_line, re.I) or re.search(
                r"Resource utilization \(%\)", value_line, re.I
            ):
                break
            if not value_line.strip():
                continue
            values = re.findall(r"\*|\d+(?:\.\d+)?", value_line)
            if len(values) < len(core_ids):
                continue
            for core_id, value in zip(core_ids, values):
                if value != "*":
                    text_series.setdefault(core_id, []).append(float(value))
    for core_id, series in text_series.items():
        samples.append(
            {
                "dataplane": "dp0",
                "core_id": int(core_id),
                "average_series": series,
                "maximum_series": series,
                "average": series[0],
                "maximum": series[0],
                "utilization": series[0],
                "window_average": sum(series) / len(series),
                "window_peak": max(series),
                "seconds_at_or_above_90": sum(value >= 90 for value in series),
                "sample_count": len(series),
            }
        )
    return samples


def _extract_latest_resource_percentages(resource_monitor: str) -> dict[str, list[float]]:
    metrics: dict[str, list[float]] = {
        "resource_monitor_dp_cpu": [],
        "resource_monitor_session": [],
        "resource_monitor_packet_buffer": [],
        "resource_monitor_packet_descriptor": [],
        "resource_monitor_packet_descriptor_on_chip": [],
        "resource_monitor_sw_tags_descriptor": [],
    }
    cpu_samples = extract_resource_cpu_cores(resource_monitor)
    cpu_by_dataplane: dict[str, list[float]] = {}
    for sample in cpu_samples:
        cpu_by_dataplane.setdefault(str(sample["dataplane"]), []).append(
            float(sample["utilization"])
        )
    metrics["resource_monitor_dp_cpu"] = [
        max(values) for values in cpu_by_dataplane.values() if values
    ]
    try:
        root = ET.fromstring(resource_monitor)
    except ET.ParseError:
        root = None
    if root is not None:
        metric_names = {
            "session": "resource_monitor_session",
            "packet buffer": "resource_monitor_packet_buffer",
            "packet descriptor": "resource_monitor_packet_descriptor",
            "packet descriptor (on-chip)": (
                "resource_monitor_packet_descriptor_on_chip"
            ),
            "sw tags descriptor": "resource_monitor_sw_tags_descriptor",
        }
        for second in root.iter():
            if _local_tag(second) != "second":
                continue
            for utilization in second:
                if _local_tag(utilization) != "resource-utilization":
                    continue
                for entry in utilization:
                    name = (_child_text(entry, "name") or "").strip().lower()
                    metric_name = metric_names.get(name)
                    value_text = _child_text(entry, "value")
                    if metric_name is None or not value_text:
                        continue
                    latest = _float_value(value_text.split(",", 1)[0])
                    if latest is not None:
                        metrics[metric_name].append(latest)
        if any(metrics.values()):
            return metrics

    text = panos_result_text(resource_monitor)
    lines = text.splitlines()
    current_window: str | None = None
    saw_window_header = False
    window_pattern = re.compile(
        r"Resource monitoring sampling data\s*\(per\s+([^)]+)\)", re.I
    )
    labels = (
        (
            re.compile(r"^\s*session\s*:\s*$", re.I),
            "resource_monitor_session",
        ),
        (
            re.compile(r"^\s*packet descriptor\s*\(on-chip\)\s*:\s*$", re.I),
            "resource_monitor_packet_descriptor_on_chip",
        ),
        (
            re.compile(r"^\s*packet descriptor\s*:\s*$", re.I),
            "resource_monitor_packet_descriptor",
        ),
        (
            re.compile(r"^\s*packet buffer\s*:\s*$", re.I),
            "resource_monitor_packet_buffer",
        ),
        (
            re.compile(r"^\s*sw tags descriptor\s*:\s*$", re.I),
            "resource_monitor_sw_tags_descriptor",
        ),
    )

    for index, line in enumerate(lines):
        window_match = window_pattern.search(line)
        if window_match:
            current_window = window_match.group(1).strip().lower()
            saw_window_header = True
            continue
        if saw_window_header and current_window != "second":
            continue
        metric_name = next(
            (name for pattern, name in labels if pattern.match(line)),
            None,
        )
        if metric_name is None:
            continue
        for value_line in lines[index + 1 :]:
            if not value_line.strip():
                continue
            values = re.findall(r"\d+(?:\.\d+)?", value_line)
            if values:
                metrics[metric_name].append(float(values[0]))
            break
    return metrics


def extract_dataplane_pool_statistics(output: str) -> dict[str, Any]:
    """Parse available/total dataplane pools and the packet-buffer headroom."""
    text = panos_result_text(output)
    section: str | None = None
    pools: list[dict[str, Any]] = []
    low_free_buffer_limit: int | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("[") and stripped.lower().endswith("pools"):
            section = stripped
            continue
        low_limit_match = re.search(
            r"Low free buffer limit\s*:\s*(\d+)",
            line,
            re.IGNORECASE,
        )
        if low_limit_match:
            low_free_buffer_limit = int(low_limit_match.group(1))
            continue
        pool_match = re.match(
            r"^\s*\[\s*(\d+)\]\s*(.+?)\s*:\s*(\d+)\s*/\s*(\d+)(?:\s+\S+)?\s*$",
            line,
        )
        if not pool_match:
            continue
        available = int(pool_match.group(3))
        total = int(pool_match.group(4))
        used = max(0, total - available)
        pools.append(
            {
                "section": section,
                "index": int(pool_match.group(1)),
                "name": pool_match.group(2).strip(),
                "available": available,
                "total": total,
                "used": used,
                "available_percentage": (
                    round(100.0 * available / total, 3) if total > 0 else None
                ),
                "used_percentage": (
                    round(100.0 * used / total, 3) if total > 0 else None
                ),
            }
        )

    packet_buffers = next(
        (
            pool.copy()
            for pool in pools
            if pool["name"].strip().lower() == "packet buffers"
            and (pool.get("section") or "").lower()
            in {"pow atomic memory pools", "hardware pools"}
        ),
        None,
    )
    if packet_buffers is None:
        packet_buffers = next(
            (
                pool.copy()
                for pool in pools
                if pool["name"].strip().lower() == "packet buffers"
            ),
            None,
        )
    if packet_buffers is not None:
        packet_buffers["low_free_buffer_limit"] = low_free_buffer_limit
        packet_buffers["below_low_free_buffer_limit"] = (
            packet_buffers["available"] < low_free_buffer_limit
            if low_free_buffer_limit is not None
            else None
        )
    return {
        "packet_buffers": packet_buffers,
        "pools": pools,
        "parsed": bool(pools),
    }


def extract_global_counters(output: str) -> dict[str, Any]:
    """Normalize PAN-OS global counter deltas while preserving raw output."""
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        root = None
    if root is not None:
        dataplane = _first_descendant_text(root, "dp", "dataplane")
        structured_counters: list[dict[str, Any]] = []
        elapsed_seconds: float | None = None
        for global_element in root.iter():
            if _local_tag(global_element) != "global":
                continue
            elapsed_milliseconds = _float_value(
                _first_child_text(global_element, "t")
            )
            if elapsed_milliseconds is not None:
                elapsed_seconds = round(elapsed_milliseconds / 1000.0, 3)
            for entry in global_element.iter():
                if _local_tag(entry) != "entry":
                    continue
                name = _first_child_text(entry, "name")
                value = _int_value(_first_child_text(entry, "value"))
                rate = _int_value(_first_child_text(entry, "rate"))
                severity = _first_child_text(entry, "severity")
                category = _first_child_text(entry, "category")
                aspect = _first_child_text(entry, "aspect")
                description = _first_child_text(entry, "desc", "description")
                if not name or value is None or rate is None:
                    continue
                structured_counters.append(
                    {
                        "name": name,
                        "value": value,
                        "rate": rate,
                        "severity": (severity or "").lower() or None,
                        "category": (category or "").lower() or None,
                        "aspect": (aspect or "").lower() or None,
                        "description": description,
                        "id": _int_value(_first_child_text(entry, "id")),
                        "dataplane": dataplane,
                    }
                )
        if structured_counters or elapsed_seconds is not None:
            return {
                "elapsed_seconds": elapsed_seconds,
                "counters": structured_counters,
                "flow_counters": [
                    counter
                    for counter in structured_counters
                    if counter["category"] == "flow"
                ],
                "significant_counters": [
                    counter
                    for counter in structured_counters
                    if counter["severity"] in {"warn", "error", "drop"}
                ],
                "parsed": True,
            }

    text = panos_result_text(output)
    elapsed_match = re.search(
        r"Elapsed time since last sampling\s*:\s*(\d+(?:\.\d+)?)\s*seconds",
        text,
        re.IGNORECASE,
    )
    counters: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = re.match(
            r"^\s*(\S+)\s+(-?\d+)\s+(-?\d+)\s+"
            r"(warn|info|error|drop)\s+(\S+)\s+(\S+)\s+(.+?)\s*$",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue
        counters.append(
            {
                "name": match.group(1),
                "value": int(match.group(2)),
                "rate": int(match.group(3)),
                "severity": match.group(4).lower(),
                "category": match.group(5).lower(),
                "aspect": match.group(6).lower(),
                "description": match.group(7).strip(),
            }
        )
    return {
        "elapsed_seconds": (
            float(elapsed_match.group(1)) if elapsed_match else None
        ),
        "counters": counters,
        "flow_counters": [
            counter for counter in counters if counter["category"] == "flow"
        ],
        "significant_counters": [
            counter
            for counter in counters
            if counter["severity"] in {"warn", "error", "drop"}
        ],
        "parsed": bool(counters) or elapsed_match is not None,
    }


def extract_live_percentages(
    pbp: str,
    ingress: str,
    resource_monitor: str | None = None,
    dataplane_pool_statistics: str | None = None,
) -> dict[str, list[float]]:
    metrics = {
        "packet_buffer_congestion": (
            _percentages(
                r"Congestion:\s*\d+/\d+\s*\((\d+(?:\.\d+)?)%\)", pbp
            )
            or _structured_pbp_percentages(pbp)
        ),
        "descriptor_atomic": (
            _percentages(r"ATOMIC:\s*(\d+(?:\.\d+)?)%", ingress)
            or _structured_ingress_percentages(ingress, "ATOMIC")
        ),
        "descriptor_total": (
            _percentages(r"TOTAL:\s*(\d+(?:\.\d+)?)%", ingress)
            or _structured_ingress_percentages(ingress, "TOTAL")
        ),
    }
    if resource_monitor is not None:
        metrics.update(_extract_latest_resource_percentages(resource_monitor))
    if dataplane_pool_statistics is not None:
        packet_buffers = extract_dataplane_pool_statistics(
            dataplane_pool_statistics
        ).get("packet_buffers")
        used_percentage = (
            packet_buffers.get("used_percentage")
            if isinstance(packet_buffers, dict)
            else None
        )
        metrics["dataplane_pool_packet_buffer_used"] = (
            [float(used_percentage)]
            if isinstance(used_percentage, (int, float))
            else []
        )
    return metrics


def extract_system_info(output: str) -> dict[str, str]:
    """Extract stable device identity fields while preserving raw XML elsewhere."""
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return {}
    field_tags = {
        "hostname": ("hostname",),
        "device_name": ("devicename", "device-name"),
        "serial": ("serial",),
        "model": ("model",),
        "software_version": ("sw-version", "software-version"),
        "system_time": ("time", "system-time"),
    }
    identity: dict[str, str] = {}
    for name, tags in field_tags.items():
        for tag in tags:
            value = root.findtext(f".//{tag}")
            if value and value.strip():
                identity[name] = value.strip()
                break
    return identity


def extract_firewall_clock(output: str) -> str | None:
    value = panos_result_text(output).strip()
    return value or None


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    line = json.dumps(payload, ensure_ascii=False) + "\n"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        size = os.fstat(descriptor).st_size
        if size:
            os.lseek(descriptor, size - 1, os.SEEK_SET)
            if os.read(descriptor, 1) != b"\n":
                # A crash mid-write left a torn line: close it first, so the
                # loss stays confined to the truncated record instead of also
                # corrupting the one being appended.
                line = "\n" + line
        os.write(descriptor, line.encode("utf-8"))
    finally:
        os.close(descriptor)


def append_recent_syslog(path: Path, payload: dict[str, Any]) -> None:
    """Append a reception-status record and compact this non-evidence journal."""
    append_jsonl(path, payload)
    try:
        if path.stat().st_size <= SYSLOG_STATUS_MAX_BYTES:
            return
        with path.open("rb") as source:
            recent = deque(source, maxlen=SYSLOG_STATUS_RECORD_LIMIT)
        # The newest records alone can exceed the size threshold (a registered
        # sender's full message bodies are stored). Trim by size as well, or
        # compaction never converges and every subsequent datagram rewrites
        # and fsyncs the whole file on the event loop.
        total = sum(len(record) for record in recent)
        while len(recent) > 1 and total > SYSLOG_STATUS_MAX_BYTES:
            total -= len(recent.popleft())
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=path.parent,
                delete=False,
            ) as handle:
                temporary_path = Path(handle.name)
                handle.writelines(recent)
                handle.flush()
                os.fsync(handle.fileno())
            if os.name == "posix":
                os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, path)
            temporary_path = None
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
    except OSError:
        LOG.exception("Unable to compact Syslog reception status journal")


def incident_capture_path(output_dir: Path, run_id: str) -> Path:
    """Return the private evidence path for one monitoring incident."""
    return output_dir / "incidents" / run_id / "incident.jsonl"


def unique_run_id(output_dir: Path, path_builder=incident_capture_path) -> str:
    """Return a run identifier whose capture directory does not exist yet.

    The timestamp has one-second granularity, so a monitor that ends and a new
    trigger arriving within the same second would otherwise merge two incidents
    into one evidence file. A monotonic suffix keeps every run distinct.
    """
    base = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = base
    suffix = 2
    while path_builder(output_dir, run_id).parent.exists():
        run_id = f"{base}-{suffix}"
        suffix += 1
    return run_id


def api_check_capture_path(output_dir: Path, run_id: str) -> Path:
    """Keep validation artifacts separate from triggered incidents."""
    return output_dir / "api-checks" / run_id / "api-check.jsonl"


def command_result(record: Any) -> str:
    """Read a command result from the current or legacy JSONL representation."""
    if isinstance(record, str):
        return record
    if isinstance(record, dict):
        value = record.get("result", "")
        return value if isinstance(value, str) else str(value)
    return ""


def command_succeeded(record: Any) -> bool:
    if isinstance(record, str):
        return not record.startswith("ERROR:")
    return isinstance(record, dict) and record.get("ok") is True


def panos_csv_serial(message: str) -> str | None:
    """Return the serial PAN-OS positions in the third field of a Syslog line."""
    fields = message.split(",")
    if len(fields) <= PANOS_LOG_TYPE_FIELD:
        return None
    if fields[PANOS_LOG_TYPE_FIELD].strip().upper() not in PANOS_LOG_TYPES:
        return None
    serial = fields[PANOS_SERIAL_FIELD].strip()
    return serial if SERIAL_PATTERN.fullmatch(serial) else None


def extract_trigger_metadata(message: str) -> dict[str, Any]:
    """Extract only explicitly labelled forensic fields from a Syslog trigger."""
    metadata: dict[str, Any] = {}
    event_names = (
        ("packet_buffer_congestion", "Packet buffer congestion"),
        ("pbp_packet_drop", "PBP Packet Drop"),
        ("pbp_session_discarded", "PBP Session Discarded"),
        ("pbp_ip_blocked", "PBP IP Blocked"),
    )
    for event_type, marker in event_names:
        if marker.lower() in message.lower():
            metadata["trigger_type"] = event_type
            break
    threat_match = re.search(
        r"(?i)(?:\b(?:threat[-_ ]?id|id)\s*[=:]\s*|"
        r"\bPBP\s+(?:Packet\s+Drop|Session\s+Discarded|IP\s+Blocked)\s*\()"
        r"(850[789])\b",
        message,
    )
    if threat_match:
        metadata["threat_id"] = int(threat_match.group(1))
    session_match = re.search(
        r"(?i)\bsession(?:[-_ ]?id)?\s*[=:]\s*(\d+)\b",
        message,
    )
    if session_match:
        metadata["session_id"] = int(session_match.group(1))
    csv_serial = panos_csv_serial(message)
    if csv_serial:
        # The positional field is structural, so it is preferred over a labelled
        # occurrence, which can appear anywhere inside a log payload.
        metadata["device_serial"] = csv_serial
    else:
        serial_match = re.search(
            r"(?i)\b(?:device[-_ ]?)?serial(?:[-_ ]?(?:number|no))?\s*[=:]\s*"
            r"([A-Za-z0-9_-]+)",
            message,
        )
        if serial_match:
            metadata["device_serial"] = serial_match.group(1)
    syslog_source_match = re.search(
        rf"(?i)\b{SYSLOG_SOURCE_MARKER}=([0-9A-Fa-f:.]+)",
        message,
    )
    if syslog_source_match:
        try:
            metadata["syslog_source_ip"] = str(
                ipaddress.ip_address(syslog_source_match.group(1))
            )
        except ValueError:
            pass
    for field, pattern in (
        ("source_ip", r"(?:src|source)(?:[-_ ]?ip)?"),
        ("destination_ip", r"(?:dst|destination)(?:[-_ ]?ip)?"),
    ):
        match = re.search(
            rf"(?i)\b{pattern}\s*[=:]\s*([0-9A-Fa-f:.]+)",
            message,
        )
        if not match:
            continue
        try:
            metadata[field] = str(ipaddress.ip_address(match.group(1)))
        except ValueError:
            pass
    return metadata


def evaluate_resource_state(
    percentages: dict[str, list[float]],
    recovery_threshold: int,
) -> tuple[list[str], bool, bool]:
    """Return parser warnings, sample eligibility, and recovery state."""
    buffer_values = (
        percentages.get("packet_buffer_congestion", [])
        + percentages.get("resource_monitor_packet_buffer", [])
    )
    descriptor_values = (
        percentages.get("descriptor_atomic", [])
        + percentages.get("descriptor_total", [])
        + percentages.get("resource_monitor_packet_descriptor", [])
        + percentages.get("resource_monitor_packet_descriptor_on_chip", [])
        + percentages.get("resource_monitor_sw_tags_descriptor", [])
    )
    warnings = []
    if not buffer_values:
        warnings.append("no current packet-buffer percentage parsed")
    if not descriptor_values:
        warnings.append("no current packet-descriptor percentage parsed")
    eligible = not warnings
    values = buffer_values + descriptor_values
    return warnings, eligible, eligible and max(values) < recovery_threshold


def device_identity_warnings(device: dict[str, str]) -> list[str]:
    """Describe missing fields needed to identify the sampled appliance."""
    warnings = [
        f"system info missing {field}"
        for field in DEVICE_IDENTITY_FIELDS
        if not device.get(field)
    ]
    if not (device.get("hostname") or device.get("device_name")):
        warnings.append("system info missing hostname/device_name")
    return warnings


def select_session_lookups(
    session_ids: list[int],
    last_queried: dict[int, float],
    now: float,
    retry_seconds: float,
    limit: int,
) -> list[int]:
    """Prioritize unseen session IDs, then retry eligible IDs fairly."""
    unique_ids = list(dict.fromkeys(session_ids))
    unseen = [session_id for session_id in unique_ids if session_id not in last_queried]
    retries = [
        session_id
        for session_id in unique_ids
        if session_id in last_queried
        and now - last_queried[session_id] >= retry_seconds
    ]
    return (unseen + retries)[:limit]


class MonitorController:
    def __init__(self, cfg: Config, client: PanOSClient):
        self.cfg = cfg
        self.client = client
        self.monitor_task: asyncio.Task[None] | None = None
        self.last_trigger_monotonic = time.monotonic()
        self.trigger_sequence = 0
        self.run_id: str | None = None
        self.trigger_session_ids: set[int] = set()
        self.trigger_source_ips: set[str] = set()
        self.report_tasks: set[asyncio.Task[None]] = set()

    def trigger(
        self,
        message: str,
        peer: str,
        *,
        transport_source_ip: str | None = None,
        routing: dict[str, Any] | None = None,
    ) -> None:
        self.last_trigger_monotonic = time.monotonic()
        self.trigger_sequence += 1
        starts_monitor = self.monitor_task is None or self.monitor_task.done()
        if starts_monitor:
            self.run_id = unique_run_id(self.cfg.output_dir)
            self.trigger_session_ids.clear()
            self.trigger_source_ips.clear()
        if self.run_id is None:  # defensive fallback for externally manipulated state
            self.run_id = unique_run_id(self.cfg.output_dir)
        timestamp = utc_now()
        metadata = extract_trigger_metadata(message)
        if isinstance(metadata.get("session_id"), int):
            self.trigger_session_ids.add(metadata["session_id"])
        if isinstance(metadata.get("source_ip"), str):
            self.trigger_source_ips.add(metadata["source_ip"])
        trigger_record = {
            "timestamp": timestamp,
            "run_id": self.run_id,
            "event": "trigger_received",
            "trigger_sequence": self.trigger_sequence,
            "reinforcement": not starts_monitor,
            "peer": peer,
            "transport_source_ip": transport_source_ip,
            "target_name": self.cfg.target_name,
            "message": message,
            "metadata": metadata,
            "routing": routing,
        }
        try:
            append_jsonl(
                self.cfg.output_dir / "syslog-triggers.jsonl",
                trigger_record,
            )
            append_jsonl(
                incident_capture_path(self.cfg.output_dir, self.run_id),
                trigger_record,
            )
        except Exception:
            # The journal is evidence, but collection is the mission: a full
            # disk or a permission error must not stop the monitor from
            # starting while the firewall is under pressure.
            LOG.exception("Unable to journal the trigger for run %s", self.run_id)
        if starts_monitor:
            self.monitor_task = asyncio.create_task(self._monitor(self.run_id))
            LOG.warning("Trigger received from %s; starting monitor %s", peer, self.run_id)
        else:
            LOG.info("Additional trigger received; monitor %s is already active", self.run_id)

    def _redact_secret(self, value: str) -> str:
        return value.replace(self.cfg.api_key, "<redacted>") if self.cfg.api_key else value

    async def _resolve_core_functions(
        self,
        device: dict[str, str],
        *,
        force: bool = False,
    ) -> tuple[list[dict[str, Any]], str, dict[str, Any] | None]:
        """Return the dataplane core map, calling the firewall only when needed.

        The map is captured once when the firewall is saved, so an incident
        normally reuses it and spends no API call on a firewall that is already
        under pressure. A PAN-OS upgrade can reassign function groups, so a
        stored map is only trusted while the model and release still match.
        """
        running = dp_core_identity(device)
        stored = [dict(entry) for entry in self.cfg.dp_core_functions]
        if not force and stored and running and self.cfg.dp_core_functions_identity == running:
            return stored, "configuration", None
        if stored and not force:
            LOG.warning(
                "Stored dataplane core map for %s was captured on %s but the "
                "firewall reports %s; reading it again and save the firewall to "
                "refresh the stored copy",
                self.cfg.target_name or self.cfg.panos_url,
                self.cfg.dp_core_functions_identity or "an unknown release",
                running or "an unknown release",
            )
        _, payload = await self._collect_command(
            "dp_core_functions", DP_CORE_FUNCTIONS_COMMAND
        )
        return extract_dp_core_functions(command_result(payload)), "firewall", payload

    async def _collect_command(
        self,
        name: str,
        command: str,
    ) -> tuple[str, dict[str, Any]]:
        started_at = utc_now()
        started = time.monotonic()
        try:
            response = await asyncio.to_thread(self.client.op_response, command)
        except Exception as exc:  # a failed command must not discard its siblings
            raw_response = (
                exc.raw_response if isinstance(exc, PanOSAPIError) else ""
            )
            return name, {
                "ok": False,
                "started_at": started_at,
                "finished_at": utc_now(),
                "duration_seconds": round(time.monotonic() - started, 3),
                "result": "",
                "raw_response": self._redact_secret(raw_response),
                "error": self._redact_secret(f"{type(exc).__name__}: {exc}"),
            }
        return name, {
            "ok": True,
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_seconds": round(time.monotonic() - started, 3),
            "result": response.result_xml,
            "raw_response": self._redact_secret(response.raw_response),
            "error": None,
        }

    async def _op_commands(
        self,
        global_counter_primer: asyncio.Task[tuple[str, dict[str, Any]]] | None = None,
    ) -> dict[str, dict[str, Any]]:
        clock_task = asyncio.create_task(
            self._collect_command("clock", CLOCK_COMMAND)
        )
        # Give the clock request the first scheduling opportunity without making
        # volatile diagnostics wait for its network timeout.
        await asyncio.sleep(0)

        async def collect_op_command(
            name: str,
            command: str,
        ) -> tuple[str, dict[str, Any]]:
            if name == "global_counters_delta" and global_counter_primer is not None:
                await global_counter_primer
            return await self._collect_command(name, command)

        commands = dict(OP_COMMANDS)
        commands["resource_monitor"] = resource_monitor_command(
            self.cfg.poll_seconds
        )
        pairs = await asyncio.gather(
            clock_task,
            *(collect_op_command(name, cmd) for name, cmd in commands.items())
        )
        return dict(pairs)

    async def _session_details(self, ids: list[int]) -> dict[str, dict[str, Any]]:
        semaphore = asyncio.Semaphore(4)

        async def fetch(session_id: int) -> tuple[str, dict[str, Any]]:
            async with semaphore:
                _, value = await self._collect_command(
                    f"session_{session_id}",
                    f"<show><session><id>{session_id}</id></session></show>",
                )
                return str(session_id), value

        return dict(await asyncio.gather(*(fetch(sid) for sid in ids)))

    def _schedule_report(self, output_file: Path) -> None:
        if not self.cfg.generate_html_report:
            return

        async def render() -> None:
            try:
                from .reporting import generate_html_report

                report = await asyncio.to_thread(
                    generate_html_report,
                    output_file,
                    output_file.with_name("report.html"),
                )
                LOG.info("HTML report written to %s", report)
            except Exception:
                LOG.exception("Unable to generate HTML report for %s", output_file)

        task = asyncio.create_task(render())
        self.report_tasks.add(task)
        task.add_done_callback(self.report_tasks.discard)

    async def wait_for_reports(self) -> None:
        if self.report_tasks:
            await asyncio.gather(*tuple(self.report_tasks), return_exceptions=True)

    def _write_text_export(
        self,
        output_file: Path,
        record: dict[str, Any],
    ) -> None:
        if not self.cfg.generate_text_export:
            return
        try:
            write_record_text_export(output_file, record)
        except Exception:
            LOG.exception(
                "Unable to generate TXT export for %s batch %s",
                output_file,
                record.get("cycle", "startup"),
            )

    async def _monitor(self, run_id: str) -> None:
        start = time.monotonic()
        started_at = utc_now()
        low_samples = 0
        session_last_queried: dict[int, float] = {}
        output_file = incident_capture_path(self.cfg.output_dir, run_id)
        stop_reason = "maximum_duration"
        cycle_number = 0
        seen_trigger_sequence = self.trigger_sequence
        system_info_task = asyncio.create_task(
            self._collect_command("system_info", SYSTEM_INFO_COMMAND)
        )
        global_counter_primer_task = asyncio.create_task(
            self._collect_command(
                "global_counters_baseline",
                OP_COMMANDS["global_counters_delta"],
            )
        )
        session_rate_samples: dict[str, dict[str, Any]] = {}
        try:
            while time.monotonic() - start < self.cfg.max_monitor_seconds:
                cycle_number += 1
                cycle_start = time.monotonic()
                cycle_started_at = utc_now()
                if cycle_number == 1:
                    (_, system_info), outputs = await asyncio.gather(
                        system_info_task,
                        self._op_commands(global_counter_primer_task),
                    )
                    _, global_counter_baseline = global_counter_primer_task.result()
                    device = extract_system_info(command_result(system_info))
                    identity_warnings = device_identity_warnings(device)
                    (
                        core_functions,
                        core_functions_source,
                        dp_core_functions,
                    ) = await self._resolve_core_functions(device)
                    startup_warnings = list(identity_warnings)
                    if not core_functions:
                        startup_warnings.append(
                            "dataplane core function groups could not be read"
                        )
                    startup_record = {
                        "timestamp": started_at,
                        "collector_version": __version__,
                        "run_id": run_id,
                        "event": "monitor_started",
                        "target_name": self.cfg.target_name,
                        "device": device,
                        "identity_complete": not identity_warnings,
                        "parse_warnings": startup_warnings,
                        "dp_core_functions": core_functions,
                        "dp_core_functions_source": core_functions_source,
                        "commands": {
                            "system_info": system_info,
                            **(
                                {"dp_core_functions": dp_core_functions}
                                if dp_core_functions is not None
                                else {}
                            ),
                            "global_counters_baseline": global_counter_baseline,
                        },
                    }
                    append_jsonl(output_file, startup_record)
                    self._write_text_export(output_file, startup_record)
                else:
                    outputs = await self._op_commands()
                pbp_result = command_result(outputs.get("packet_buffer_protection"))
                ingress_result = command_result(outputs.get("ingress_backlogs"))
                dataplane_pool_result = command_result(
                    outputs.get("dataplane_pool_statistics")
                )
                pbp_offenders = extract_pbp_offenders(pbp_result)
                pbp_status = extract_pbp_status(pbp_result, pbp_offenders)
                session_info = extract_session_info(
                    command_result(outputs.get("session_info"))
                )
                ingress_backlogs = extract_ingress_backlogs(ingress_result)
                dataplane_pools = extract_dataplane_pool_statistics(
                    dataplane_pool_result
                )
                global_counters = extract_global_counters(
                    command_result(outputs.get("global_counters_delta"))
                )
                fallback_ids = extract_session_ids(pbp_result, ingress_result)
                candidate_entities = build_candidate_entities(
                    pbp_offenders,
                    ingress_backlogs["candidates"],
                    fallback_ids,
                    sorted(self.trigger_session_ids),
                    sorted(self.trigger_source_ips),
                )
                ids = [
                    int(entity["session_id"])
                    for entity in candidate_entities
                    if entity.get("entity_type") == "session"
                    and isinstance(entity.get("session_id"), int)
                ]
                now = time.monotonic()
                lookup_ids = select_session_lookups(
                    ids,
                    session_last_queried,
                    now,
                    self.cfg.session_retry_seconds,
                    self.cfg.max_session_lookups,
                )
                details = await self._session_details(lookup_ids)
                session_summaries = summarize_session_details(details)
                session_rates = derive_session_rates(
                    session_summaries,
                    session_rate_samples,
                    time.monotonic(),
                )
                for sid in lookup_ids:
                    session_last_queried[sid] = now

                percentages = extract_live_percentages(
                    command_result(outputs.get("packet_buffer_protection")),
                    command_result(outputs.get("ingress_backlogs")),
                    command_result(outputs.get("resource_monitor")),
                    dataplane_pool_result,
                )
                parse_warnings, measurement_complete, is_low = (
                    evaluate_resource_state(
                        percentages,
                        self.cfg.recovery_threshold,
                    )
                )
                trigger_reinforced = self.trigger_sequence != seen_trigger_sequence
                if trigger_reinforced:
                    seen_trigger_sequence = self.trigger_sequence
                    low_samples = 0
                low_samples = low_samples + 1 if is_low and not trigger_reinforced else 0

                cycle_record = {
                        "timestamp": cycle_started_at,
                        "completed_at": utc_now(),
                        "run_id": run_id,
                        "target_name": self.cfg.target_name,
                        "cycle": cycle_number,
                        "elapsed_seconds": round(time.monotonic() - start, 3),
                        "cycle_duration_seconds": round(
                            time.monotonic() - cycle_start, 3
                        ),
                        "firewall_clock": extract_firewall_clock(
                            command_result(outputs.get("clock"))
                        ),
                        "percentages": percentages,
                        "resource_monitor_cpu_cores": extract_resource_cpu_cores(
                            command_result(outputs.get("resource_monitor"))
                        ),
                        "parse_warnings": parse_warnings,
                        "recovery_sample_eligible": measurement_complete,
                        "resources_below_threshold": is_low,
                        "candidate_session_ids": ids,
                        "candidate_entities": candidate_entities,
                        "pbp_status": pbp_status,
                        "pbp_offenders": pbp_offenders,
                        "session_info": session_info,
                        "ingress_backlogs": ingress_backlogs,
                        "dataplane_pools": dataplane_pools,
                        "global_counters_delta": global_counters,
                        "global_counters_delta_status": (
                            "primed_interval"
                            if cycle_number > 1
                            or command_succeeded(global_counter_baseline)
                            else "baseline_untrusted"
                        ),
                        "session_details": details,
                        "session_summaries": session_summaries,
                        "session_rates": session_rates,
                        "commands": outputs,
                    }
                append_jsonl(output_file, cycle_record)
                self._write_text_export(output_file, cycle_record)
                LOG.info(
                    "Monitor %s: percentages=%s sessions=%s low=%s/%s",
                    run_id,
                    percentages,
                    ids,
                    low_samples,
                    self.cfg.low_samples_to_stop,
                )

                trigger_is_old = (
                    time.monotonic() - self.last_trigger_monotonic
                    > self.cfg.poll_seconds
                )
                if low_samples >= self.cfg.low_samples_to_stop and trigger_is_old:
                    LOG.warning("Monitor %s stopped: resources recovered", run_id)
                    stop_reason = "resources_recovered"
                    break
                if (
                    time.monotonic() - self.last_trigger_monotonic
                    >= self.cfg.incident_idle_ttl_seconds
                ):
                    LOG.warning(
                        "Monitor %s stopped: no trigger received within idle TTL",
                        run_id,
                    )
                    stop_reason = "alert_idle_timeout"
                    break
                sleep_for = max(0.0, self.cfg.poll_seconds - (time.monotonic() - cycle_start))
                await asyncio.sleep(sleep_for)
            else:
                LOG.warning("Monitor %s stopped: maximum duration reached", run_id)
        except asyncio.CancelledError:
            stop_reason = "cancelled"
            raise
        except Exception:
            stop_reason = "monitor_error"
            LOG.exception("Monitor %s stopped after an unexpected error", run_id)
        finally:
            for startup_task in (system_info_task, global_counter_primer_task):
                if not startup_task.done():
                    startup_task.cancel()
                    await asyncio.gather(startup_task, return_exceptions=True)
            try:
                append_jsonl(
                    output_file,
                    {
                        "timestamp": utc_now(),
                        "run_id": run_id,
                        "event": "monitor_stopped",
                        "target_name": self.cfg.target_name,
                        "reason": stop_reason,
                        "cycles": cycle_number,
                        "elapsed_seconds": round(time.monotonic() - start, 3),
                    },
                )
            except Exception:
                # The report must still be produced from whatever evidence was
                # captured, even when the stop marker cannot be written.
                LOG.exception("Unable to write the stop record for run %s", run_id)
            self._schedule_report(output_file)


class MultiTargetRouter:
    """Route one Syslog trigger to the emitting target, with a safe probe fallback."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.profiles = cfg.target_profiles
        self.controllers = {
            profile.name: MonitorController(
                target_cfg := cfg.for_target(profile),
                PanOSClient(target_cfg),
            )
            for profile in self.profiles
        }
        self.profile_by_name = {profile.name: profile for profile in self.profiles}
        self.by_serial = {
            serial.lower(): profile.name
            for profile in self.profiles
            for serial in profile.serials
        }
        self.by_source: dict[str, list[str]] = {}
        for profile in self.profiles:
            for source in profile.syslog_sources:
                self.by_source.setdefault(source, []).append(profile.name)
        self.pending: dict[
            str,
            list[tuple[str, str, str | None, dict[str, Any]]],
        ] = {}
        self.routing_tasks: set[asyncio.Task[None]] = set()

    def classify_message(
        self, message: str, transport_source_ip: str | None
    ) -> list[str]:
        """Attribute a received log without probing or changing firewall state."""
        metadata = extract_trigger_metadata(message)
        serial = metadata.get("device_serial")
        source = metadata.get("syslog_source_ip") or transport_source_ip
        candidates = self.by_source.get(source, []) if isinstance(source, str) else []
        serial_target = (
            self.by_serial.get(str(serial).lower()) if isinstance(serial, str) else None
        )
        if serial_target and serial_target in candidates:
            return [serial_target]
        return list(candidates) if len(candidates) == 1 else []

    def _rejection_reason(self, source: Any, serial: Any) -> str | None:
        """Return why an emitter must be refused, or None when it is expected.

        The Syslog source address is the first gate. The device serial captured
        from the firewall when it was saved is the second: PAN-OS states it in
        every log, so a message that does not carry that serial is not evidence
        from that firewall, whatever address it appears to come from.

        A target saved without a serial on record cannot be checked that way and
        keeps the source-only rule, which is what it had before.
        """
        if not isinstance(source, str) or source not in self.by_source:
            return "source_not_registered"
        registered = {
            value.lower()
            for name in self.by_source[source]
            for value in self.profile_by_name[name].serials
        }
        if not registered:
            return None
        if not isinstance(serial, str) or not serial:
            return "device_serial_missing"
        if serial.lower() not in registered:
            return "device_serial_not_registered"
        return None

    def rejection_reason(
        self, message: str, transport_source_ip: str | None
    ) -> str | None:
        """Return why this message must not be attributed, or None to accept."""
        metadata = extract_trigger_metadata(message)
        return self._rejection_reason(
            metadata.get("syslog_source_ip") or transport_source_ip,
            metadata.get("device_serial"),
        )

    def _dispatch(
        self,
        target_names: list[str],
        message: str,
        peer: str,
        transport_source_ip: str | None,
        routing: dict[str, Any],
    ) -> None:
        for target_name in target_names:
            self.controllers[target_name].trigger(
                message,
                peer,
                transport_source_ip=transport_source_ip,
                routing={**routing, "selected_target": target_name},
            )

    def _reject(self, source: str | None, peer: str, reason: str) -> None:
        LOG.warning(
            "Rejected PBP Syslog trigger from %s (%s): %s",
            source or peer,
            peer,
            reason,
        )

    def trigger(
        self,
        message: str,
        peer: str,
        *,
        transport_source_ip: str | None = None,
        routing: dict[str, Any] | None = None,
    ) -> None:
        del routing  # routing is established here, not by the transport
        metadata = extract_trigger_metadata(message)
        serial = metadata.get("device_serial")
        source = metadata.get("syslog_source_ip") or transport_source_ip
        reason = self._rejection_reason(source, serial)
        if reason is not None:
            self._reject(
                source if isinstance(source, str) else None,
                peer,
                SYSLOG_REJECTIONS[reason],
            )
            return
        candidate_names = self.by_source[source]
        # The gate above already proved a present serial belongs to one of the
        # candidates, so this lookup can only select an allowlisted target.
        serial_target = (
            self.by_serial.get(str(serial).lower())
            if isinstance(serial, str)
            else None
        )
        if serial_target is not None:
            target_name = serial_target
            route_method = "device_serial_and_syslog_source"
        elif len(candidate_names) == 1:
            target_name = candidate_names[0]
            route_method = (
                "single_configured_target"
                if len(self.profiles) == 1
                else "syslog_source"
            )
        else:
            target_name = None
            route_method = None
        if target_name is not None:
            self._dispatch(
                [target_name],
                message,
                peer,
                transport_source_ip,
                {
                    "method": route_method,
                    "device_serial": serial,
                    "syslog_source_ip": source,
                    "fanout": False,
                },
            )
            return

        pending_key = f"{serial or ''}|{source or peer}"
        queue = self.pending.setdefault(pending_key, [])
        queue.append((message, peer, transport_source_ip, metadata))
        if len(queue) > 1:
            return
        task = asyncio.create_task(
            self._probe_and_dispatch(pending_key, candidate_names)
        )
        self.routing_tasks.add(task)
        task.add_done_callback(self.routing_tasks.discard)

    async def _probe_target(
        self,
        target_name: str,
    ) -> tuple[str, dict[str, Any]]:
        controller = self.controllers[target_name]
        pairs = await asyncio.gather(
            controller._collect_command("system_info", SYSTEM_INFO_COMMAND),
            controller._collect_command(
                "packet_buffer_protection",
                OP_COMMANDS["packet_buffer_protection"],
            ),
            controller._collect_command(
                "dataplane_pool_statistics",
                OP_COMMANDS["dataplane_pool_statistics"],
            ),
        )
        commands = dict(pairs)
        device = extract_system_info(command_result(commands.get("system_info")))
        pbp_result = command_result(commands.get("packet_buffer_protection"))
        pools = extract_dataplane_pool_statistics(
            command_result(commands.get("dataplane_pool_statistics"))
        )
        pbp_status = extract_pbp_status(pbp_result)
        congestion = pbp_status.get("congestion_percentage")
        packet_buffers = pools.get("packet_buffers")
        below_low_limit = (
            packet_buffers.get("below_low_free_buffer_limit") is True
            if isinstance(packet_buffers, dict)
            else False
        )
        affected = (
            pbp_status.get("active") is True
            or below_low_limit
            or (
                isinstance(congestion, (int, float))
                and congestion >= controller.cfg.recovery_threshold
            )
        )
        reachable = any(command_succeeded(record) for record in commands.values())
        return target_name, {
            "reachable": reachable,
            "affected": affected,
            "device": device,
            "pbp_status": pbp_status,
            "packet_buffers": packet_buffers,
            "commands": commands,
        }

    async def _probe_and_dispatch(
        self,
        pending_key: str,
        candidate_names: list[str],
    ) -> None:
        try:
            probes = dict(
                await asyncio.gather(
                    *(self._probe_target(name) for name in candidate_names)
                )
            )
            affected = [
                name for name, probe in probes.items() if probe.get("affected") is True
            ]
            if affected:
                selected = affected
                method = "parallel_probe_affected"
            else:
                reachable = [
                    name
                    for name, probe in probes.items()
                    if probe.get("reachable") is True
                ]
                selected = reachable or candidate_names
                method = "parallel_probe_ambiguous_fanout"
            queued = self.pending.pop(pending_key, [])
            routing_record = {
                "timestamp": utc_now(),
                "event": "target_routing_probe",
                "routing_key": pending_key,
                "selected_targets": selected,
                "method": method,
                "queued_triggers": len(queued),
                "probes": probes,
            }
            append_jsonl(
                self.cfg.output_dir / "syslog-routing.jsonl",
                routing_record,
            )
            LOG.warning(
                "Shared allowlisted Syslog source routed by %s to %s",
                method,
                ", ".join(selected),
            )
            for message, peer, transport_source_ip, metadata in queued:
                self._dispatch(
                    selected,
                    message,
                    peer,
                    transport_source_ip,
                    {
                        "method": method,
                        "device_serial": metadata.get("device_serial"),
                        "syslog_source_ip": metadata.get("syslog_source_ip")
                        or transport_source_ip,
                        "fanout": len(selected) > 1,
                    },
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            self.pending.pop(pending_key, None)
            LOG.exception("Unable to route an unmapped Syslog trigger")

    async def close(self) -> None:
        for task in tuple(self.routing_tasks):
            if not task.done():
                task.cancel()
        if self.routing_tasks:
            await asyncio.gather(*tuple(self.routing_tasks), return_exceptions=True)
        monitor_tasks = [
            controller.monitor_task
            for controller in self.controllers.values()
            if controller.monitor_task and not controller.monitor_task.done()
        ]
        for task in monitor_tasks:
            task.cancel()
        if monitor_tasks:
            await asyncio.gather(*monitor_tasks, return_exceptions=True)
        await asyncio.gather(
            *(controller.wait_for_reports() for controller in self.controllers.values()),
            return_exceptions=True,
        )

    def is_target_busy(self, name: str) -> bool:
        """Report whether one firewall is currently being polled for an incident."""
        if self.pending:
            # A routing probe is in flight and may poll any candidate firewall.
            return True
        controller = self.controllers.get(name)
        return bool(
            controller is not None
            and controller.monitor_task is not None
            and not controller.monitor_task.done()
        )

    def is_busy(self) -> bool:
        return bool(self.pending) or any(
            controller.monitor_task is not None
            and not controller.monitor_task.done()
            for controller in self.controllers.values()
        )


class ManagedRouter:
    """Reload SQLite configuration between incidents without restarting the service."""

    def __init__(self, cfg: Config, store: ConfigStore):
        self.cfg = cfg
        self.store = store
        self.revision = cfg.config_revision
        self.router = MultiTargetRouter(cfg) if cfg.target_profiles else None
        self.close_tasks: set[asyncio.Task[None]] = set()

    def _reload_if_needed(self) -> None:
        try:
            revision = self.store.revision()
            if revision == self.revision:
                return
            if self.router is not None and self.router.is_busy():
                LOG.info("Configuration revision %s deferred until active incidents finish", revision)
                return
            new_cfg = Config.from_store(self.store)
            old_router = self.router
            self.cfg = new_cfg
            self.revision = new_cfg.config_revision
            self.router = MultiTargetRouter(new_cfg) if new_cfg.target_profiles else None
            if old_router is not None:
                task = asyncio.create_task(old_router.close())
                self.close_tasks.add(task)
                task.add_done_callback(self.close_tasks.discard)
            LOG.info(
                "Loaded configuration revision %s with %s enabled firewall(s)",
                self.revision,
                len(new_cfg.target_profiles),
            )
        except Exception:
            LOG.exception("Unable to reload configuration; retaining the last valid revision")

    def classify_message(self, message: str, transport_source_ip: str | None) -> list[str]:
        self._reload_if_needed()
        return (
            self.router.classify_message(message, transport_source_ip)
            if self.router is not None
            else []
        )

    def rejection_reason(
        self, message: str, transport_source_ip: str | None
    ) -> str | None:
        self._reload_if_needed()
        return (
            self.router.rejection_reason(message, transport_source_ip)
            if self.router is not None
            else "source_not_registered"
        )

    def trigger(
        self,
        message: str,
        peer: str,
        *,
        transport_source_ip: str | None = None,
        routing: dict[str, Any] | None = None,
    ) -> None:
        self._reload_if_needed()
        if self.router is None:
            LOG.warning("Rejected PBP Syslog trigger from %s: no firewall is configured", peer)
            return
        self.router.trigger(
            message,
            peer,
            transport_source_ip=transport_source_ip,
            routing=routing,
        )

    async def close(self) -> None:
        if self.router is not None:
            await self.router.close()
        if self.close_tasks:
            await asyncio.gather(*tuple(self.close_tasks), return_exceptions=True)


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, cfg: Config, controller: Any):
        self.cfg = cfg
        self.controller = controller

    def _reception_record(
        self,
        message: str,
        addr: tuple[str, int],
        is_trigger: bool,
        target_names: list[str],
    ) -> dict[str, Any]:
        """Build the journal entry, without the payload of an unknown sender."""
        metadata = extract_trigger_metadata(message)
        record: dict[str, Any] = {
            "timestamp": utc_now(),
            "peer": f"{addr[0]}:{addr[1]}",
            "transport_source_ip": addr[0],
            "trigger": is_trigger,
            "target_names": target_names,
        }
        checker = getattr(type(self.controller), "rejection_reason", None)
        reason = (
            checker(self.controller, message, addr[0]) if callable(checker) else None
        )
        if reason is None:
            record["metadata"] = metadata
            record["message"] = message
            return record
        # A sender nobody declared must stay visible enough to be registered,
        # but its text is never persisted. Only the source address the gateway
        # observed survives, and it is already validated as an IP address.
        source = metadata.get("syslog_source_ip")
        record["metadata"] = {"syslog_source_ip": source} if source else {}
        # A refused message must not stand in for the firewall it claims to come
        # from, or a stray sender would keep its reception indicator alive while
        # the firewall itself has stopped forwarding.
        record["target_names"] = []
        record["suppressed"] = reason
        return record

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        message = data.decode("utf-8", errors="replace").strip()
        is_trigger = TRIGGER_REGEX.search(message) is not None
        classifier = getattr(type(self.controller), "classify_message", None)
        target_names = (
            classifier(self.controller, message, addr[0])
            if callable(classifier)
            else ([self.cfg.target_name] if self.cfg.target_name else [])
        )
        try:
            append_recent_syslog(
                self.cfg.output_dir / "syslog-received.jsonl",
                self._reception_record(message, addr, is_trigger, target_names),
            )
        except Exception:
            LOG.exception("Unable to record Syslog reception status")
        if is_trigger:
            try:
                self.controller.trigger(
                    message,
                    f"{addr[0]}:{addr[1]}",
                    transport_source_ip=addr[0],
                )
            except Exception:
                LOG.exception(
                    "Unable to start or reinforce a monitor from a Syslog trigger"
                )

    def error_received(self, exc: Exception) -> None:
        LOG.error("Syslog listener error: %s", exc)


async def run_api_check(cfg: Config) -> tuple[Path, bool]:
    """Run one allowlisted, read-only collection batch without opening Syslog."""
    cfg.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_id = unique_run_id(cfg.output_dir, api_check_capture_path)
    output_file = api_check_capture_path(cfg.output_dir, run_id)
    client = PanOSClient(cfg)
    controller = MonitorController(cfg, client)
    started = time.monotonic()
    started_at = utc_now()
    cycle_started = time.monotonic()
    cycle_started_at = utc_now()
    global_counter_primer_task = asyncio.create_task(
        controller._collect_command(
            "global_counters_baseline",
            OP_COMMANDS["global_counters_delta"],
        )
    )
    (_, system_info), outputs = await asyncio.gather(
        controller._collect_command("system_info", SYSTEM_INFO_COMMAND),
        controller._op_commands(global_counter_primer_task),
    )
    _, global_counter_baseline = global_counter_primer_task.result()
    device = extract_system_info(command_result(system_info))
    identity_warnings = device_identity_warnings(device)
    core_functions, core_functions_source, dp_core_functions = (
        await controller._resolve_core_functions(device, force=True)
    )
    startup_warnings = list(identity_warnings)
    if not core_functions:
        startup_warnings.append("dataplane core function groups could not be read")
    startup_record = {
        "timestamp": started_at,
        "collector_version": __version__,
        "run_id": run_id,
        "event": "monitor_started",
        "mode": "api_check",
        "target_name": cfg.target_name,
        "device": device,
        "identity_complete": not identity_warnings,
        "parse_warnings": startup_warnings,
        "dp_core_functions": core_functions,
        "dp_core_functions_source": core_functions_source,
        "commands": {
            "system_info": system_info,
            "dp_core_functions": dp_core_functions,
            "global_counters_baseline": global_counter_baseline,
        },
    }
    append_jsonl(output_file, startup_record)
    controller._write_text_export(output_file, startup_record)
    pbp_result = command_result(outputs.get("packet_buffer_protection"))
    ingress_result = command_result(outputs.get("ingress_backlogs"))
    dataplane_pool_result = command_result(outputs.get("dataplane_pool_statistics"))
    pbp_offenders = extract_pbp_offenders(pbp_result)
    pbp_status = extract_pbp_status(pbp_result, pbp_offenders)
    session_info = extract_session_info(command_result(outputs.get("session_info")))
    ingress_backlogs = extract_ingress_backlogs(ingress_result)
    dataplane_pools = extract_dataplane_pool_statistics(dataplane_pool_result)
    global_counters = extract_global_counters(
        command_result(outputs.get("global_counters_delta"))
    )
    fallback_ids = extract_session_ids(pbp_result, ingress_result)
    candidate_entities = build_candidate_entities(
        pbp_offenders,
        ingress_backlogs["candidates"],
        fallback_ids,
    )
    ids = [
        int(entity["session_id"])
        for entity in candidate_entities
        if entity.get("entity_type") == "session"
        and isinstance(entity.get("session_id"), int)
    ]
    lookup_ids = ids[: cfg.max_session_lookups]
    details = await controller._session_details(lookup_ids)
    session_summaries = summarize_session_details(details)
    session_rates = derive_session_rates(session_summaries, {}, time.monotonic())
    percentages = extract_live_percentages(
        command_result(outputs.get("packet_buffer_protection")),
        command_result(outputs.get("ingress_backlogs")),
        command_result(outputs.get("resource_monitor")),
        dataplane_pool_result,
    )
    parse_warnings, measurement_complete, is_low = evaluate_resource_state(
        percentages,
        cfg.recovery_threshold,
    )
    firewall_clock = extract_firewall_clock(command_result(outputs.get("clock")))
    validation_errors = list(identity_warnings)
    if not command_succeeded(system_info):
        validation_errors.append("system_info command failed")
    if not command_succeeded(global_counter_baseline):
        validation_errors.append("global counter baseline command failed")
    validation_errors.extend(
        f"{name} command failed"
        for name, record in outputs.items()
        if not command_succeeded(record)
    )
    if not firewall_clock:
        validation_errors.append("firewall clock could not be parsed")
    validation_errors.extend(parse_warnings)
    validation_errors.extend(
        f"session detail failed for {session_id}"
        for session_id, record in details.items()
        if not command_succeeded(record)
    )
    cycle_record = {
            "timestamp": cycle_started_at,
            "completed_at": utc_now(),
            "run_id": run_id,
            "cycle": 1,
            "mode": "api_check",
            "target_name": cfg.target_name,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "cycle_duration_seconds": round(time.monotonic() - cycle_started, 3),
            "firewall_clock": firewall_clock,
            "percentages": percentages,
            "resource_monitor_cpu_cores": extract_resource_cpu_cores(
                command_result(outputs.get("resource_monitor"))
            ),
            "parse_warnings": parse_warnings,
            "recovery_sample_eligible": measurement_complete,
            "resources_below_threshold": is_low,
            "validation_errors": validation_errors,
            "candidate_session_ids": ids,
            "candidate_entities": candidate_entities,
            "pbp_status": pbp_status,
            "pbp_offenders": pbp_offenders,
            "session_info": session_info,
            "ingress_backlogs": ingress_backlogs,
            "dataplane_pools": dataplane_pools,
            "global_counters_delta": global_counters,
            "global_counters_delta_status": (
                "primed_interval"
                if command_succeeded(global_counter_baseline)
                else "baseline_untrusted"
            ),
            "session_details": details,
            "session_summaries": session_summaries,
            "session_rates": session_rates,
            "commands": outputs,
        }
    append_jsonl(output_file, cycle_record)
    controller._write_text_export(output_file, cycle_record)
    succeeded = not validation_errors
    append_jsonl(
        output_file,
        {
            "timestamp": utc_now(),
            "run_id": run_id,
            "event": "monitor_stopped",
            "target_name": cfg.target_name,
            "reason": "api_check_complete" if succeeded else "api_check_partial_failure",
            "cycles": 1,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        },
    )
    controller._schedule_report(output_file)
    await controller.wait_for_reports()
    return output_file, succeeded


async def run_configured_api_checks(cfg: Config) -> list[tuple[Path, bool]]:
    target_configs = (
        [cfg.for_target(profile) for profile in cfg.target_profiles]
        if cfg.target_profiles
        else [cfg]
    )
    return list(await asyncio.gather(*(run_api_check(item) for item in target_configs)))


CHECK_TICK_SECONDS = 10.0


def _check_detail(device: dict[str, str], core_count: int, refreshed: bool) -> str:
    parts = [
        f"PAN-OS {device.get('software_version') or 'unknown'}",
        f"{core_count} dataplane cores mapped" if core_count else "core map unavailable",
    ]
    if refreshed:
        parts.append("stored identity refreshed")
    return "; ".join(parts)


async def run_target_keepalive(cfg: Config, store: ConfigStore, target: StoredTarget) -> bool:
    """Confirm one firewall is reachable and its stored identity still current.

    Read-only and deliberately small: `show system info` every time, and
    `show statistics` only when the stored core map is missing or was captured
    on a different model or PAN-OS release. A firewall in steady state costs one
    API call a day.
    """
    controller = MonitorController(cfg, PanOSClient(cfg))
    _, system_info = await controller._collect_command("system_info", SYSTEM_INFO_COMMAND)
    if not command_succeeded(system_info):
        store.record_target_check(
            target.target_id,
            kind="keepalive",
            status="failed",
            detail=str(system_info.get("error") or "show system info failed"),
        )
        LOG.warning(
            "Keepalive failed for %s: %s", target.name, system_info.get("error")
        )
        return False

    device = extract_system_info(command_result(system_info))
    running = dp_core_identity(device)
    stale = not target.dp_core_functions or target.dp_core_functions_identity != running
    core_functions: list[dict[str, Any]] | None = None
    if stale:
        core_functions, _, _ = await controller._resolve_core_functions(
            device, force=True
        )

    identity_changed = (
        (target.model or None) != (device.get("model") or None)
        or (target.sw_version or None) != (device.get("software_version") or None)
    )
    if identity_changed or core_functions is not None:
        store.refresh_target_device(
            target.target_id,
            device_identity=device,
            dp_core_functions=core_functions,
        )
    if identity_changed:
        LOG.info(
            "Keepalive refreshed %s: model %s, PAN-OS %s",
            target.name,
            device.get("model") or "unknown",
            device.get("software_version") or "unknown",
        )
    count = (
        len(core_functions)
        if core_functions is not None
        else len(target.dp_core_functions)
    )
    store.record_target_check(
        target.target_id,
        kind="keepalive",
        status="ok",
        detail=_check_detail(device, count, identity_changed or core_functions is not None),
    )
    return True


async def run_target_validation(cfg: Config, store: ConfigStore, target: StoredTarget) -> bool:
    """Run the full read-only validation batch for one firewall on request."""
    try:
        capture, ok = await run_api_check(cfg)
    except Exception as exc:  # a failed validation must not stop the listener
        LOG.exception("Validation failed for %s", target.name)
        store.record_target_check(
            target.target_id,
            kind="validation",
            status="failed",
            detail=f"{type(exc).__name__}: {exc}",
            clear_request=True,
        )
        return False
    store.record_target_check(
        target.target_id,
        kind="validation",
        status="ok" if ok else "failed",
        detail=f"run {capture.parent.name}",
        clear_request=True,
    )
    LOG.info(
        "Validation for %s finished as %s (%s)",
        target.name,
        "success" if ok else "failure",
        capture.parent.name,
    )
    return ok


def _check_is_due(last_check_at: str | None, interval_hours: float, now: datetime) -> bool:
    if interval_hours <= 0:
        return False
    if not last_check_at:
        return True
    try:
        previous = datetime.fromisoformat(str(last_check_at))
    except ValueError:
        return True
    if previous.tzinfo is None:
        previous = previous.replace(tzinfo=timezone.utc)
    return (now - previous).total_seconds() >= interval_hours * 3600


async def run_target_checks_once(router: "ManagedRouter") -> int:
    """Run every due keepalive and every requested validation, one firewall at a time.

    A firewall with an active incident is skipped: it is already being polled
    every few seconds while under packet-buffer pressure, and a check must never
    compete with the diagnostic batches.
    """
    # The loop runs outside the Syslog datagram path, so it must refresh the
    # in-memory profiles itself or a firewall saved after startup stays
    # invisible until an unrelated datagram arrives.
    router._reload_if_needed()
    store = router.store
    try:
        targets = [
            target
            for target in store.list_targets(include_secrets=True)
            if isinstance(target, StoredTarget) and target.enabled
        ]
        interval_hours = float(store.get_settings()["target_check_hours"])
    except (OSError, ValueError, KeyError):
        LOG.exception("Unable to read the firewall check schedule")
        return 0

    now = datetime.now(timezone.utc)
    performed = 0
    for target in targets:
        if router.router is not None and router.router.is_target_busy(target.name):
            continue
        profile = next(
            (
                item
                for item in router.cfg.target_profiles
                if item.name == target.name
            ),
            None,
        )
        if profile is None:
            continue
        target_cfg = router.cfg.for_target(profile)
        try:
            if target.check_requested_at:
                await run_target_validation(target_cfg, store, target)
            elif _check_is_due(target.last_check_at, interval_hours, now):
                await run_target_keepalive(target_cfg, store, target)
            else:
                continue
        except Exception:  # one firewall must not stop the others
            LOG.exception("Firewall check failed for %s", target.name)
        performed += 1
    return performed


async def run_target_check_loop(router: "ManagedRouter") -> None:
    while True:
        await asyncio.sleep(CHECK_TICK_SECONDS)
        try:
            await run_target_checks_once(router)
        except asyncio.CancelledError:
            raise
        except Exception:  # the listener must survive any check failure
            LOG.exception("Firewall check cycle failed")


async def run_daemon(cfg: Config) -> None:
    cfg.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    controller: MonitorController | MultiTargetRouter | ManagedRouter
    check_task: asyncio.Task[None] | None = None
    config_db = os.getenv("PBP_CONFIG_DB", "").strip()
    if config_db:
        controller = ManagedRouter(cfg, ConfigStore(Path(config_db)))
        LOG.info("Managed configuration enabled at revision %s", cfg.config_revision)
        check_task = asyncio.create_task(run_target_check_loop(controller))
    elif cfg.target_profiles:
        controller = MultiTargetRouter(cfg)
        LOG.info(
            "Multi-target routing enabled for: %s",
            ", ".join(profile.name for profile in cfg.target_profiles),
        )
    else:
        controller = MonitorController(cfg, PanOSClient(cfg))
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(cfg, controller),
        local_addr=(cfg.syslog_host, cfg.syslog_port),
    )
    LOG.info("Listening for PAN-OS syslog on udp://%s:%s", cfg.syslog_host, cfg.syslog_port)

    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # Windows event loops do not expose this API
            signal.signal(sig, lambda *_args: loop.call_soon_threadsafe(stop.set))
    try:
        await stop.wait()
    finally:
        transport.close()
        if check_task is not None:
            check_task.cancel()
            await asyncio.gather(check_task, return_exceptions=True)
        if isinstance(controller, (MultiTargetRouter, ManagedRouter)):
            await controller.close()
        else:
            if controller.monitor_task and not controller.monitor_task.done():
                controller.monitor_task.cancel()
                await asyncio.gather(controller.monitor_task, return_exceptions=True)
            await controller.wait_for_reports()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help="environment file for local execution (default: .env)",
    )
    parser.add_argument(
        "--check-api",
        action="store_true",
        help="run one read-only collection batch and exit",
    )
    return parser.parse_args(argv)


def cli(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        load_env_file(args.env_file)
        logging.getLogger().setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
        cfg = Config.from_env()
        if args.check_api:
            results = asyncio.run(run_configured_api_checks(cfg))
            for output_file, _succeeded in results:
                LOG.info("API validation capture written to %s", output_file)
            return 0 if all(succeeded for _path, succeeded in results) else 1
        asyncio.run(run_daemon(cfg))
        return 0
    except (KeyError, ValueError, OSError) as exc:
        if isinstance(exc, KeyError):
            LOG.error("Missing required environment variable: %s", exc.args[0])
        else:
            LOG.error("Unable to start: %s", exc)
        return 2


def main(argv: list[str] | None = None) -> int:
    """Configure process logging and run the command-line interface."""
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return cli(argv)


if __name__ == "__main__":
    sys.exit(main())
