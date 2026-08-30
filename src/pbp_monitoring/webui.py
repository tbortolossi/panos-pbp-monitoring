#!/usr/bin/env python3
"""Read-only local Web UI for PBP Syslog reception and incident artifacts."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import logging
import os
import re
import secrets
import ssl
import threading
import zipfile
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import parse_qs, quote, unquote, urlsplit

from . import __version__, diagnostics
from .adminui import AdminController
from .config_store import ALL_RUNS, DEFAULT_SETTINGS, TARGET_NAME, ConfigStore
from .web_tls import ensure_self_signed_certificate


LOG = logging.getLogger("pbp-web")
SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
SAFE_REDIRECT_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
#: Received-log filter selecting what no declared firewall claims: refused
#: messages, and messages from a sender that is not a registered source. A
#: target name cannot start with a dash, so the sentinel never collides with
#: a firewall the operator declared.
UNATTRIBUTED_LOGS = "-unattributed"


class ThreadingTLSHTTPServer(ThreadingHTTPServer):
    """Accept TLS clients without letting one stalled handshake block all peers."""

    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler: type[BaseHTTPRequestHandler],
        ssl_context: ssl.SSLContext,
    ) -> None:
        self.ssl_context = ssl_context
        super().__init__(server_address, request_handler)

    def get_request(self) -> tuple[Any, Any]:
        raw_socket, address = super().get_request()
        try:
            tls_socket = self.ssl_context.wrap_socket(
                raw_socket,
                server_side=True,
                do_handshake_on_connect=False,
            )
            tls_socket.settimeout(15)
            return tls_socket, address
        except BaseException:
            raw_socket.close()
            raise


def _escape(value: Any) -> str:
    return html.escape(str(value if value not in (None, "") else "—"), quote=True)


def _https_redirect_location(host_header: str, request_target: str, https_port: int) -> str:
    """Build a same-host HTTPS location without trusting an arbitrary header value."""
    if not host_header or any(character in host_header for character in "\r\n/\\"):
        raise ValueError("invalid Host header")
    try:
        parsed = urlsplit(f"//{host_header}")
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError("invalid Host header") from exc
    if not hostname or parsed.username or parsed.password:
        raise ValueError("invalid Host header")
    try:
        hostname_ascii = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid Host header") from exc
    if ":" in hostname_ascii:
        authority = f"[{hostname_ascii}]"
    elif SAFE_REDIRECT_HOST.fullmatch(hostname_ascii):
        authority = hostname_ascii
    else:
        raise ValueError("invalid Host header")
    if https_port != 443:
        authority = f"{authority}:{https_port}"
    target = request_target if request_target.startswith("/") else "/"
    if any(character in target for character in "\r\n"):
        raise ValueError("invalid request target")
    return f"https://{authority}{target}"


def redirect_handler_factory(https_port: int) -> type[BaseHTTPRequestHandler]:
    """Return an HTTP handler which only redirects to the HTTPS listener."""

    class HTTPSRedirectHandler(BaseHTTPRequestHandler):
        server_version = f"PBPRedirect/{__version__}"

        def _redirect(self) -> None:
            try:
                location = _https_redirect_location(
                    self.headers.get("Host", ""), self.path, https_port
                )
            except ValueError:
                self.send_error(400, "Invalid Host header")
                return
            self.send_response(308)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()

        do_GET = _redirect
        do_HEAD = _redirect
        do_POST = _redirect

        def log_message(self, format: str, *args: Any) -> None:
            LOG.info("HTTP redirect %s - %s", self.client_address[0], format % args)

    return HTTPSRedirectHandler


def _filtered_jsonl(path: Path, predicate: Any) -> bytes:
    selected: list[bytes] = []
    if not path.is_file():
        return b""
    try:
        with path.open("rb") as handle:
            for raw_line in handle:
                try:
                    value = json.loads(raw_line.decode("utf-8-sig"))
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    continue
                if isinstance(value, dict) and predicate(value):
                    selected.append(raw_line.rstrip(b"\r\n") + b"\n")
    except OSError:
        return b""
    return b"".join(selected)


def _run_syslog_exports(run_dir: Path, target: str, run_id: str) -> dict[str, bytes]:
    capture = next(
        (name for folder, name in RUN_FAMILIES if run_dir.parent.name == folder),
        None,
    )
    if capture is None:
        return {}
    target_root = run_dir.parent.parent
    data_root = (
        target_root.parent.parent
        if target_root.parent.name == "targets"
        else target_root
    )
    first = _first_json_record(run_dir / capture)
    tail = _tail_json_records(run_dir / capture, 1)
    started_at = _parse_time(first.get("timestamp"))
    ended_at = _parse_time(tail[-1].get("timestamp")) if tail else None

    triggers = _filtered_jsonl(
        target_root / "syslog-triggers.jsonl",
        lambda record: str(record.get("run_id", "")) == run_id,
    )

    def received_during_run(record: dict[str, Any]) -> bool:
        timestamp = _parse_time(record.get("timestamp"))
        if not (started_at and ended_at and timestamp):
            return False
        if not started_at <= timestamp <= ended_at:
            return False
        # A refused message carries no target attribution by design, and it is
        # exactly the evidence behind "the collector never reacted". Keeping it
        # costs one line per refusal and answers the most common report.
        if record.get("suppressed"):
            return True
        target_names = record.get("target_names")
        return isinstance(target_names, list) and target in {
            str(name) for name in target_names
        }

    received = _filtered_jsonl(
        data_root / "syslog-received.jsonl",
        received_during_run,
    )
    return {
        "support/syslog-triggers.jsonl": triggers,
        "support/syslog-received.jsonl": received,
    }


def write_run_archive(
    destination: Any,
    run_dir: Path,
    *,
    target: str,
    run_id: str,
    config_store: ConfigStore | None = None,
    anonymizer: diagnostics.Anonymizer | None = None,
) -> None:
    """Write a portable ZIP containing one run and a checksummed manifest.

    The capture explains what the firewall answered. The environment and the
    redacted configuration explain what the collector was, and how it was set
    up, when it asked; a run archive that omits them cannot settle why a
    customer deployment behaves differently from the lab.
    """
    root = Path(run_dir).resolve()
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    manifest_files: list[dict[str, Any]] = []
    prefix = f"pbp-run-{target}-{run_id}"
    if anonymizer is not None:
        prefix = f"pbp-run-{anonymizer.apply(target)}-{run_id}"
    with zipfile.ZipFile(
        destination,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
        allowZip64=True,
    ) as archive:
        for path in files:
            relative = path.relative_to(root).as_posix()
            if anonymizer is not None:
                payload = anonymizer.apply_bytes(path.read_bytes())
                relative = anonymizer.apply(relative)
                manifest_files.append(
                    {
                        "path": relative,
                        "size_bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                )
                archive.writestr(f"{prefix}/{relative}", payload)
                continue
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
            manifest_files.append(
                {
                    "path": relative,
                    "size_bytes": path.stat().st_size,
                    "sha256": digest.hexdigest(),
                }
            )
            archive.write(path, f"{prefix}/{relative}")
        support_context = {
            "support/environment.json": _support_json(
                diagnostics.environment_snapshot()
            ),
            "support/configuration.json": _support_json(
                diagnostics.redacted_configuration(config_store)
            ),
        }
        generated = {
            **{
                relative: (payload, "filtered support export")
                for relative, payload in _run_syslog_exports(
                    root, target, run_id
                ).items()
            },
            **{
                relative: (payload, "generated support context")
                for relative, payload in support_context.items()
            },
        }
        if anonymizer is not None:
            generated = {
                anonymizer.apply(relative): (anonymizer.apply_bytes(payload), source)
                for relative, (payload, source) in generated.items()
            }
        for relative, (payload, source) in generated.items():
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
            "format_version": 1,
            "application": "PBP Monitoring",
            "application_version": __version__,
            "target": anonymizer.apply(target) if anonymizer else target,
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "anonymized": anonymizer is not None,
            "files": manifest_files,
        }
        archive.writestr(
            f"{prefix}/manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        )


def _support_json(payload: Any) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n"
    ).encode("utf-8")


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _tail_json_records(path: Path, limit: int, max_bytes: int = 2 * 1024 * 1024) -> list[dict[str, Any]]:
    if limit <= 0 or not path.is_file():
        return []
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            end = handle.tell()
            start = max(0, end - max_bytes)
            handle.seek(start)
            data = handle.read()
    except OSError:
        return []
    lines = data.splitlines()
    if start > 0 and lines:
        lines = lines[1:]
    records: list[dict[str, Any]] = []
    for raw in reversed(lines):
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            continue
        if isinstance(value, dict):
            records.append(value)
            if len(records) >= limit:
                break
    records.reverse()
    return records


def _first_json_record(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line in handle:
                try:
                    value = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if isinstance(value, dict):
                    return value
    except OSError:
        pass
    return {}


def _run_id_time(run_id: str) -> str | None:
    try:
        parsed = datetime.strptime(run_id, "%Y%m%dT%H%M%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None
    return parsed.isoformat()


def _display_utc(value: Any) -> str:
    parsed = _parse_time(value)
    return parsed.strftime("%Y-%m-%d %H:%M:%S UTC") if parsed else str(value or "—")


def _text_export_metadata(path: Path) -> dict[str, Any]:
    metadata: dict[str, str] = {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            for _line_number, line in zip(range(20), handle):
                if ": " not in line:
                    continue
                key, value = line.rstrip("\r\n").split(": ", 1)
                metadata[key] = value
    except OSError:
        pass
    return {
        "name": path.name,
        "batch": metadata.get("Batch") or ("Startup" if path.name == "startup.txt" else "—"),
        "collector_time": metadata.get("Collector time"),
        "firewall_time": metadata.get("Firewall time"),
        "duration_seconds": metadata.get("Cycle duration seconds"),
        "size_bytes": path.stat().st_size if path.is_file() else 0,
    }


def collect_text_exports(raw_dir: Path) -> list[dict[str, Any]]:
    """Return bounded-header metadata for human-readable TXT artifacts."""
    if not raw_dir.is_dir():
        return []
    paths = sorted(raw_dir.glob("batch-*.txt"))
    startup = raw_dir / "startup.txt"
    if startup.is_file():
        paths.insert(0, startup)
    return [_text_export_metadata(path) for path in paths]


def render_text_export_index(
    target: str,
    run_id: str,
    exports: list[dict[str, Any]],
) -> str:
    target_url = quote(target, safe="")
    run_url = quote(run_id, safe="")
    rows: list[str] = []
    for item in exports:
        filename = str(item.get("name", ""))
        file_url = quote(filename, safe="")
        size_kib = float(item.get("size_bytes", 0)) / 1024
        batch_label = "Startup" if filename == "startup.txt" else f"Batch {item.get('batch')}"
        rows.append(
            "<tr>"
            f"<td><strong>{_escape(batch_label)}</strong><code>{_escape(filename)}</code></td>"
            f"<td>{_escape(_display_utc(item.get('collector_time')))}</td>"
            f"<td>{_escape(item.get('firewall_time'))}</td>"
            f"<td class=\"number\">{_escape(item.get('duration_seconds'))}</td>"
            f"<td class=\"number\">{size_kib:.1f} KiB</td>"
            f'<td class="actions"><a href="/artifacts/{target_url}/{run_url}/raw/{file_url}">View</a>'
            f'<a class="secondary" href="/artifacts/{target_url}/{run_url}/raw/{file_url}?download=1">Download</a></td>'
            "</tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="6" class="muted">No TXT export.</td></tr>')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>TXT exports { _escape(run_id) }</title><style>
:root{{--ink:#172033;--muted:#64748b;--line:#dbe3ee;--soft:#f4f7fb;--accent:#155e75}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--soft);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}}
header{{padding:28px max(20px,calc((100vw - 1200px)/2));color:#fff;background:linear-gradient(125deg,#0f172a,#155e75)}}h1{{margin:0;font-size:clamp(24px,4vw,38px)}}header p{{margin:6px 0 0;color:#d9f4f2}}
main{{width:min(1200px,calc(100% - 28px));margin:22px auto 42px}}.toolbar{{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px}}.toolbar span{{color:var(--muted)}}
.table-wrap{{overflow:auto;max-height:75vh;border:1px solid var(--line);border-radius:12px;background:#fff;scrollbar-gutter:stable}}table{{width:100%;border-collapse:collapse;white-space:nowrap}}th,td{{padding:11px 13px;border-bottom:1px solid var(--line);text-align:left;vertical-align:middle}}th{{position:sticky;top:0;z-index:2;background:#eef3f8;color:#334155;font-size:12px;text-transform:uppercase}}
td:first-child strong,td:first-child code{{display:block}}td:first-child code{{margin-top:2px;color:var(--muted);font-size:11px}}.number{{text-align:right;font-variant-numeric:tabular-nums}}.actions{{display:flex;gap:8px}}a{{display:inline-block;padding:6px 10px;border-radius:7px;background:var(--accent);color:#fff;text-decoration:none;font-weight:700}}a.secondary{{border:1px solid #bae6fd;background:#f0f9ff;color:#0369a1}}.back{{background:transparent;color:#0369a1;padding:0}}.muted{{color:var(--muted)}}
</style></head><body><header><h1>TXT batch exports</h1><p>Run {_escape(run_id)} &middot; target {_escape(target)}</p></header><main><div class="toolbar"><a class="back" href="/">&larr; Back to dashboard</a><span>{len(exports)} files</span></div>
<div class="table-wrap"><table><thead><tr><th>Batch</th><th>Execution time (UTC)</th><th>Firewall time</th><th>Duration (s)</th><th>Size</th><th>Actions</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></main></body></html>"""


#: How much of a report is read to find its opening body tag. The evidence bar
#: is inserted in that chunk and the remainder of the file is streamed, so a
#: report of any size keeps its exports without ever being held in memory.
REPORT_HEAD_BYTES = 1024 * 1024
_BODY_TAG = re.compile(rb"<body[^>]*>", re.IGNORECASE)


def _human_size(size_bytes: int) -> str:
    """Render a byte count the way an operator reads a file listing."""
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MiB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.0f} KiB"
    return f"{size_bytes} B"


def _export_link(
    href: str,
    label: str,
    detail: str,
    title: str,
    *,
    secondary: bool = False,
) -> str:
    """One export offered by the report bar, named by format and by size."""
    css = ' class="secondary"' if secondary else ""
    return (
        f'<a{css} href="{href}" title="{_escape(title)}">{_escape(label)}'
        f'<span class="pbp-bar-meta">{_escape(detail)}</span></a>'
    )


def render_report_evidence_bar(target: str, run_id: str, run_dir: Path) -> str:
    """Build the evidence bar shown above a report served by the Web UI.

    The report is where an operator decides that a case needs the raw evidence,
    so the run's artifacts belong on that page rather than only in the dashboard
    row. Each one is named by its format and its weight, because the choice
    being made there is which file to attach to a TAC case. The bar is added
    when the page is served, never written to disk: a report copied out for a
    TAC case must carry neither links that resolve only inside this deployment
    nor a button offering a bundle that names the customer's network.
    """
    target_url = quote(target, safe="")
    run_url = quote(run_id, safe="")
    raw_dir = run_dir / "raw"
    text_files = len(list(raw_dir.glob("*.txt"))) if raw_dir.is_dir() else 0
    jsonl = run_dir / "incident.jsonl"
    links: list[str] = []
    if jsonl.is_file():
        links.append(
            _export_link(
                f"/artifacts/{target_url}/{run_url}/incident.jsonl",
                "JSONL",
                _human_size(jsonl.stat().st_size),
                "Structured records and the exact raw command output of the run",
            )
        )
    if text_files:
        links.append(
            _export_link(
                f"/artifacts/{target_url}/{run_url}/raw/",
                "TXT",
                f"{text_files} file{'' if text_files == 1 else 's'}",
                "Human-readable export of every command and its response, one file per batch",
            )
        )
    if jsonl.is_file():
        links.append(
            _export_link(
                f"/artifacts/{target_url}/{run_url}/run.zip",
                "ZIP",
                "support archive",
                "Every artifact of this run, the deployment environment and a manifest, for a TAC case",
            )
        )
        links.append(
            _export_link(
                f"/artifacts/{target_url}/{run_url}/run.zip?anonymize=1",
                "ZIP",
                "anonymized",
                "The same archive with addresses, hostnames and serials replaced by tokens",
                secondary=True,
            )
        )
    if links:
        exports_html = '<span class="pbp-bar-label">Exports</span>' + "".join(links)
        note = (
            "This page is the standalone HTML report: keep the file as it is, or "
            "print it from the browser to obtain a PDF."
        )
    else:
        exports_html = '<span class="pbp-bar-note">No stored evidence for this run.</span>'
        note = ""
    note_html = f'<span class="pbp-bar-note">{note}</span>' if note else ""
    return (
        "<style>"
        ".pbp-bar{display:flex;flex-wrap:wrap;align-items:center;gap:10px;"
        "padding:10px max(20px,calc((100vw - 1200px)/2));background:#0b1220;"
        "color:#e2e8f0;font:13px/1.4 system-ui,-apple-system,'Segoe UI',sans-serif}"
        ".pbp-bar a{display:inline-flex;align-items:baseline;gap:6px;padding:5px 10px;"
        "border-radius:7px;background:#155e75;color:#fff;text-decoration:none;font-weight:700}"
        ".pbp-bar a.secondary{background:#f0f9ff;color:#0369a1}"
        ".pbp-bar a.back{background:#1e293b;border:1px solid #64748b;color:#e2e8f0}"
        ".pbp-bar .pbp-bar-run{margin-right:auto;color:#94a3b8}"
        ".pbp-bar .pbp-bar-label{color:#94a3b8;font-size:11px;font-weight:700;"
        "letter-spacing:.06em;text-transform:uppercase}"
        ".pbp-bar .pbp-bar-meta{color:#cbd5e1;font-size:11px;font-weight:400}"
        ".pbp-bar a.secondary .pbp-bar-meta{color:#0c4a6e}"
        ".pbp-bar .pbp-bar-note{flex-basis:100%;color:#94a3b8}"
        "@media print{.pbp-bar{display:none}}"
        "</style>"
        '<div class="pbp-bar">'
        '<a class="back" href="/">&larr; Back to dashboard</a>'
        f'<span class="pbp-bar-run">{_escape(target)} &middot; run {_escape(run_id)}</span>'
        f"{exports_html}{note_html}</div>"
    )


def annotate_report_head(head: bytes, evidence_bar: str) -> bytes | None:
    """Insert the evidence bar just after the report's opening body tag.

    Only the opening chunk of the report is taken, and bytes are searched
    rather than decoded text: an incident report is as large as the evidence
    it carries, and the exports must not depend on the whole file fitting in
    memory. `None` says the chunk carries no body tag, and the report is then
    served unchanged, because the evidence matters more than the bar.
    """
    match = _BODY_TAG.search(head)
    if match is None:
        return None
    return head[: match.end()] + evidence_bar.encode("utf-8") + head[match.end() :]


def _target_roots(data_dir: Path) -> list[tuple[str, Path]]:
    targets = data_dir / "targets"
    found: list[tuple[str, Path]] = []
    if targets.is_dir():
        for path in sorted(targets.iterdir()):
            if path.is_dir() and SAFE_COMPONENT.fullmatch(path.name):
                found.append((path.name, path))
    if not found and (data_dir / "incidents").is_dir():
        found.append(("standalone", data_dir))
    return found


def _attributed_firewalls(
    record: dict[str, Any], targets: Sequence[dict[str, Any]]
) -> list[str]:
    """Declared firewalls a received log belongs to.

    A refused message is attributed to none of them by design: the collector
    rejected it before it could be tied to a firewall, and that is exactly what
    the unattributed filter has to surface. Without a configuration store the
    record's own attribution is kept, so the column still says something.
    """
    if record.get("suppressed"):
        return []
    names = record.get("target_names")
    claimed = [str(name) for name in names] if isinstance(names, list) else []
    if not targets:
        return claimed
    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    source = metadata.get("syslog_source_ip") or record.get("transport_source_ip")
    serial = metadata.get("device_serial")
    return [
        target["name"]
        for target in targets
        if target["name"] in claimed
        or (
            source in target["syslog_sources"]
            and (not serial or str(serial) in target["serials"])
        )
    ]


def collect_dashboard_state(
    data_dir: Path,
    *,
    log_limit: int = 20,
    run_limit: int = 20,
    now: datetime | None = None,
    freshness_seconds: float = 300,
    config_store: ConfigStore | None = None,
    log_filter: str | None = None,
) -> dict[str, Any]:
    """Build a bounded dashboard snapshot without loading full incident files.

    ``log_filter`` restricts the received-log table to one declared firewall, or
    to :data:`UNATTRIBUTED_LOGS` for what none of them claims. It never touches
    the reception watchdogs: global freshness and every firewall card keep
    reading the whole journal tail, so a filtered view cannot hide an outage.
    """
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    status_logs = _tail_json_records(data_dir / "syslog-received.jsonl", 200)
    latest_time = _parse_time(status_logs[-1].get("timestamp")) if status_logs else None
    age_seconds = (
        max(0.0, (current - latest_time).total_seconds()) if latest_time else None
    )
    syslog_healthy = age_seconds is not None and age_seconds <= freshness_seconds

    runs: list[dict[str, Any]] = []
    for target, root in _target_roots(data_dir):
        incidents = root / "incidents"
        if not incidents.is_dir():
            continue
        for directory in incidents.iterdir():
            if not directory.is_dir() or not SAFE_COMPONENT.fullmatch(directory.name):
                continue
            capture = directory / "incident.jsonl"
            first = _first_json_record(capture)
            tail = _tail_json_records(capture, 3)
            last = tail[-1] if tail else {}
            stopped = last.get("event") == "monitor_stopped"
            runs.append(
                {
                    "target": target,
                    "run_id": directory.name,
                    "started_at": first.get("timestamp")
                    or _run_id_time(directory.name),
                    "status": "completed" if stopped else "active",
                    "stop_reason": last.get("reason") if stopped else None,
                    "cycles": last.get("cycles") if stopped else last.get("cycle"),
                    "peak_packet_buffer_pct": (
                        last.get("peak_packet_buffer_pct") if stopped else None
                    ),
                    "top_sources": (
                        last.get("top_sources")
                        if stopped and isinstance(last.get("top_sources"), list)
                        else []
                    ),
                    "updated_at": last.get("timestamp"),
                    "report": (directory / "report.html").is_file(),
                    "jsonl": capture.is_file(),
                    "text_files": len(list((directory / "raw").glob("*.txt")))
                    if (directory / "raw").is_dir()
                    else 0,
                }
            )
    runs.sort(key=lambda item: item["run_id"], reverse=True)
    firewall_statuses: list[dict[str, Any]] = []
    check_interval_hours = float(DEFAULT_SETTINGS["target_check_hours"])
    targets: list[dict[str, Any]] = []
    if config_store is not None and config_store.path.is_file():
        try:
            targets = config_store.list_targets()
        except (OSError, ValueError):
            targets = []
        try:
            check_interval_hours = float(
                config_store.get_settings()["target_check_hours"]
            )
        except (KeyError, OSError, ValueError):
            pass
    attribution = [_attributed_firewalls(record, targets) for record in status_logs]
    for target in targets:
        matching = [
            record
            for record, names in zip(status_logs, attribution)
            if target["name"] in names
        ]
        last = matching[-1] if matching else None
        last_time = _parse_time(last.get("timestamp")) if last else None
        target_age = max(0.0, (current - last_time).total_seconds()) if last_time else None
        active_run = next(
            (
                run["run_id"]
                for run in runs
                if run["target"] == target["name"] and run["status"] == "active"
            ),
            None,
        )
        check_time = _parse_time(target.get("last_check_at"))
        check_age = (
            max(0.0, (current - check_time).total_seconds())
            if check_time
            else None
        )
        firewall_statuses.append(
            {
                "name": target["name"],
                "enabled": target["enabled"],
                "healthy": bool(target["enabled"] and target_age is not None and target_age <= freshness_seconds),
                "last_received_at": last.get("timestamp") if last else None,
                "age_seconds": target_age,
                "active_run": active_run,
                "last_check_at": target.get("last_check_at"),
                "last_check_kind": target.get("last_check_kind"),
                "last_check_status": target.get("last_check_status"),
                "last_check_detail": target.get("last_check_detail"),
                "check_requested_at": target.get("check_requested_at"),
                "check_age_seconds": check_age,
            }
        )
    pending_deletions: list[dict[str, str]] = []
    if config_store is not None and config_store.path.is_file():
        try:
            pending_deletions = [
                {"target": item.target, "run_id": item.run_id}
                for item in config_store.pending_run_deletions()
            ]
        except Exception:  # a broken queue must never blank the dashboard
            LOG.exception("Unable to read the queued incident-run deletions")
    attributed = list(zip(status_logs, attribution))
    if log_filter == UNATTRIBUTED_LOGS:
        selected = [item for item in attributed if not item[1]]
    elif log_filter:
        selected = [item for item in attributed if log_filter in item[1]]
    else:
        selected = attributed
    return {
        "generated_at": current.isoformat(),
        "syslog_healthy": syslog_healthy,
        "syslog_age_seconds": age_seconds,
        "logs": [
            {**record, "firewalls": names}
            for record, names in reversed(selected[-log_limit:])
        ],
        "log_filter": log_filter or "",
        "log_firewalls": [target["name"] for target in targets],
        "unattributed_logs": sum(1 for names in attribution if not names),
        "runs": runs[:run_limit],
        "runs_total": len(runs),
        "firewalls": firewall_statuses,
        "check_interval_hours": check_interval_hours,
        "pending_deletions": pending_deletions,
    }


SUPPRESSION_REASONS = {
    "source_not_registered": "source is not a registered firewall",
    "device_serial_missing": "no device serial in the message",
    "device_serial_not_registered": "device serial is not the registered one",
}


def _check_signal(
    firewall: dict[str, Any], interval_hours: float
) -> tuple[str, str]:
    """State and text of the API signal: is the firewall still answering?

    Green means the last read-only check passed. Red is kept for a check that
    actually failed. A queued validation, a firewall never checked yet, or a
    schedule left unhonoured for more than twice the configured interval, is
    amber: nothing proves the firewall is unreachable, only that no recent call
    confirmed it. A run in progress is its own proof, since the collector is
    then polling the API every few seconds.
    """
    if firewall.get("check_requested_at"):
        return "warn", "API check: validation queued"
    checked_at = firewall.get("last_check_at")
    if not checked_at:
        return "warn", "API check: never run"
    status = str(firewall.get("last_check_status") or "")
    kind = str(firewall.get("last_check_kind") or "check")
    passed = status == "ok"
    line = f"API check: {kind} {'passed' if passed else 'FAILED'} at {_display_utc(checked_at)}"
    detail = str(firewall.get("last_check_detail") or "")
    if detail:
        line = f"{line} - {detail}"
    if not passed:
        return "bad", line
    age = firewall.get("check_age_seconds")
    overdue = (
        interval_hours > 0
        and not firewall.get("active_run")
        and isinstance(age, (int, float))
        and age > 2 * interval_hours * 3600
    )
    if overdue:
        return "warn", f"{line} - overdue, expected every {interval_hours:g} hours"
    return "ok", line


def _firewall_signals(
    firewall: dict[str, Any], interval_hours: float
) -> list[tuple[str, str]]:
    """The three signals of a firewall card, each with its own state."""
    age = firewall.get("age_seconds")
    syslog_line = (
        f"Syslog: last log {_display_utc(firewall.get('last_received_at'))}"
        f" ({int(age)} seconds ago)"
        if isinstance(age, (int, float))
        else "Syslog: no attributed log received"
    )
    active_run = firewall.get("active_run")
    return [
        ("ok" if firewall.get("healthy") else "bad", syslog_line),
        _check_signal(firewall, interval_hours),
        (
            ("bad", f"Incident: run {active_run} in progress")
            if active_run
            else ("ok", "Incident: no run in progress")
        ),
    ]


def _firewall_headline(
    firewall: dict[str, Any], signals: list[tuple[str, str]]
) -> tuple[str, str]:
    """General state of a firewall card, derived from its three signals.

    A run in progress colours its own signal red, because packet buffers are
    under pressure right now, but the card stays amber: the collector is doing
    its job. Red on the card is reserved for the two signals that mean the
    collector itself is blind, a firewall that stopped sending logs or an API
    that stopped answering, and it wins over a run in progress.
    """
    watchdog_states = [state for state, _text in signals[:2]]
    if "bad" in watchdog_states:
        return "bad", "needs attention"
    if firewall.get("active_run"):
        return "busy", "monitoring run in progress"
    if "warn" in watchdog_states:
        return "busy", "check pending"
    return "ok", "healthy"


def _run_cell(content: str, report_url: str | None) -> str:
    """Render a run cell that opens the run's report when it is clicked.

    The report is what the row is read for, and it is now the only way to it:
    the row no longer repeats the exports the report page already offers. The
    anchor fills the cell and inherits its type, so the table still reads as a
    table. A run whose report does not exist yet, an active monitor, keeps a
    plain cell.
    """
    if report_url is None:
        return f"<td>{content}</td>"
    return (
        f'<td><a class="rowlink" href="{report_url}"'
        ' title="Open the HTML report of this run">'
        f"{content}</a></td>"
    )


def _delete_cell(csrf: str | None, run: dict[str, Any], queued: bool) -> str:
    """Render the per-run deletion control.

    A run still being collected keeps its evidence: the collector refuses to
    remove a directory it is writing, so the button is not offered at all.
    """
    if queued:
        return '<span class="muted">Deleting&hellip;</span>'
    if not csrf or run.get("status") == "active":
        return "&mdash;"
    return (
        '<form class="inline" method="post" action="/runs/delete">'
        f'<input type="hidden" name="csrf" value="{_escape(csrf)}">'
        f'<input type="hidden" name="target" value="{_escape(run.get("target"))}">'
        f'<input type="hidden" name="run_id" value="{_escape(run.get("run_id"))}">'
        '<button class="danger" type="submit">Delete</button></form>'
    )


def render_dashboard(
    state: dict[str, Any],
    refresh_seconds: int = 5,
    csrf: str | None = None,
) -> str:
    """Render the dashboard.

    ``csrf`` carries the administrator session token. Without it the
    deletion controls are omitted rather than rendered inert, so the page
    never offers an action the request could not authorise.
    """
    healthy = bool(state.get("syslog_healthy"))
    age = state.get("syslog_age_seconds")
    status_class = "ok" if healthy else "bad"
    status_text = "Syslog reception is active" if healthy else "Syslog reception is missing or stale"
    age_text = (
        f"Last log received {int(age)} seconds ago"
        if isinstance(age, (int, float))
        else "No log received"
    )

    log_rows: list[str] = []
    for record in state.get("logs", []):
        metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        kind = metadata.get("trigger_type") or (
            "trigger" if record.get("trigger") else "other"
        )
        suppressed = record.get("suppressed")
        if isinstance(suppressed, str) and suppressed:
            message = "not stored: " + SUPPRESSION_REASONS.get(
                suppressed, "sender is not a registered firewall"
            )
        else:
            message = str(record.get("message", ""))
            if len(message) > 320:
                message = message[:317] + "..."
        firewalls = record.get("firewalls")
        attributed = (
            ", ".join(str(name) for name in firewalls)
            if isinstance(firewalls, list)
            else ""
        )
        log_rows.append(
            "<tr>"
            f"<td>{_escape(record.get('timestamp'))}</td>"
            f"<td>{_escape(metadata.get('syslog_source_ip') or record.get('transport_source_ip'))}</td>"
            f"<td>{_escape(attributed) if attributed else '&mdash;'}</td>"
            f"<td><span class=\"badge {'trigger' if record.get('trigger') else ''}\">{_escape(kind)}</span></td>"
            f"<td class=\"message\">{_escape(message)}</td>"
            "</tr>"
        )
    log_filter = str(state.get("log_filter") or "")
    if not log_rows:
        empty = "No log observed." if not log_filter else "No log matches this filter."
        log_rows.append(f'<tr><td colspan="5" class="muted">{empty}</td></tr>')

    # Filtering happens on the server: the dashboard reloads itself every few
    # seconds, so a client-side filter would reset under the operator's hands.
    chips: list[tuple[str, str]] = [("", "All firewalls")]
    chips += [(str(name), str(name)) for name in state.get("log_firewalls", [])]
    if len(chips) > 1:
        chips.append(
            (UNATTRIBUTED_LOGS, f"Unattributed ({int(state.get('unattributed_logs') or 0)})")
        )
        log_filters = '<nav class="chips">' + "".join(
            f'<a class="chip{" on" if value == log_filter else ""}" href="/'
            f'{"?firewall=" + quote(value, safe="") if value else ""}">{_escape(label)}</a>'
            for value, label in chips
        ) + "</nav>"
    else:
        log_filters = ""

    queued_deletions = {
        (str(item.get("target")), str(item.get("run_id")))
        for item in state.get("pending_deletions", [])
        if isinstance(item, dict)
    }
    deleting_everything = (ALL_RUNS, ALL_RUNS) in queued_deletions

    run_rows: list[str] = []
    rows_open_a_report = False
    for run in state.get("runs", []):
        target = quote(str(run.get("target", "")), safe="")
        run_id = quote(str(run.get("run_id", "")), safe="")
        queued = deleting_everything or (
            str(run.get("target")),
            str(run.get("run_id")),
        ) in queued_deletions
        report_url = (
            f"/reports/{target}/{run_id}/report.html" if run.get("report") else None
        )
        active = run.get("status") == "active"
        peak = run.get("peak_packet_buffer_pct")
        peak_text = (
            f"{peak:g}%" if isinstance(peak, (int, float)) else "—"
        )
        top_sources = run.get("top_sources") or []
        top_text = ", ".join(str(source) for source in top_sources[:3]) or "—"
        badge = (
            f"<span class=\"badge {'active' if active else 'done'}\">"
            f"{'Active' if active else 'Completed'}</span>"
        )
        # A run being collected has no report yet, and a run whose report
        # could not be produced never will: the row leads nowhere, so the
        # records written so far are offered here instead. Every other run
        # is read through its report, which carries the full set of exports.
        if report_url is None and run.get("jsonl"):
            badge += (
                f'<a class="evidence" href="/artifacts/{target}/{run_id}'
                '/incident.jsonl" title="The records of this run, as JSONL">'
                "JSONL</a>"
            )
        row_open = '<tr class="linked">' if report_url else "<tr>"
        run_rows.append(
            row_open
            + _run_cell(_escape(run.get("target")), report_url)
            + _run_cell(f"<code>{_escape(run.get('run_id'))}</code>", report_url)
            + _run_cell(_escape(run.get("started_at")), report_url)
            + _run_cell(badge, report_url)
            + _run_cell(_escape(run.get("cycles")), report_url)
            + _run_cell(_escape(peak_text), report_url)
            + _run_cell(f"<code>{_escape(top_text)}</code>", report_url)
            + _run_cell(_escape(run.get("stop_reason")), report_url)
            + f"<td>{_delete_cell(csrf, run, queued)}</td>"
            + "</tr>"
        )
        if report_url:
            rows_open_a_report = True
    if not run_rows:
        run_rows.append('<tr><td colspan="9" class="muted">No run recorded.</td></tr>')

    check_interval_hours = float(
        state.get("check_interval_hours") or DEFAULT_SETTINGS["target_check_hours"]
    )
    firewall_cards: list[str] = []
    for firewall in state.get("firewalls", []):
        signals = _firewall_signals(firewall, check_interval_hours)
        state_class, headline = _firewall_headline(firewall, signals)
        signal_items = "".join(
            f'<li class="{signal_state}"><span class="mark"></span>'
            f"<span>{_escape(text)}</span></li>"
            for signal_state, text in signals
        )
        firewall_cards.append(
            f'<div class="status {state_class}"><span class="dot"></span><div>'
            f'<strong>{_escape(firewall.get("name"))}: {_escape(headline)}</strong>'
            f'<ul class="signals">{signal_items}</ul>'
            "</div></div>"
        )

    if firewall_cards:
        status_panel = f'<div class="status-grid">{"".join(firewall_cards)}</div>'
    else:
        status_panel = (
            f'<div class="status {status_class}"><span class="dot"></span><div>'
            f"<strong>{_escape(status_text)}</strong>"
            f"<span>{_escape(age_text)}</span>"
            "<span>No firewall is registered yet: declare one in the "
            '<a href="/admin">admin page</a> to get its own reception, API '
            "check and incident signals.</span>"
            "</div></div>"
        )

    runs_hint = (
        '<span class="muted">Click a row to open its report</span>'
        if rows_open_a_report
        else ""
    )
    total_runs = int(state.get("runs_total") or len(state.get("runs", [])))
    if not csrf or not total_runs:
        delete_all_control = ""
    elif deleting_everything:
        delete_all_control = '<span class="muted">Deleting every run&hellip;</span>'
    else:
        delete_all_control = (
            '<form class="inline" method="post" action="/runs/delete-all">'
            f'<input type="hidden" name="csrf" value="{_escape(csrf)}">'
            f'<button class="danger" type="submit">Delete all {total_runs}'
            f' run{"" if total_runs == 1 else "s"}</button>'
            "</form>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="{max(2, int(refresh_seconds))}">
<meta name="referrer" content="no-referrer"><title>PBP Monitoring</title>
<style>
:root{{--ink:#172033;--muted:#64748b;--line:#dbe3ee;--soft:#f4f7fb;--ok:#15803d;--bad:#b42318;--busy:#b45309;--accent:#155e75}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--soft);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}}
header{{padding:28px max(20px,calc((100vw - 1280px)/2));color:#fff;background:linear-gradient(125deg,#0f172a,#155e75)}}
h1{{margin:0;font-size:clamp(25px,4vw,40px)}}header p{{margin:5px 0 0;color:#d9f4f2}}main{{width:min(1280px,calc(100% - 28px));margin:22px auto 42px}}
.status{{display:flex;align-items:flex-start;gap:13px;padding:16px 18px;border:1px solid var(--line);border-radius:12px;background:#fff}}
.status-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}}
.dot{{flex:0 0 auto;width:18px;height:18px;border-radius:50%;background:var(--bad);box-shadow:0 0 0 5px #fee2e2}}.status.ok .dot{{background:var(--ok);box-shadow:0 0 0 5px #dcfce7}}
.status.busy .dot{{background:var(--busy);box-shadow:0 0 0 5px #fef3c7}}.status .dot{{margin-top:3px}}.status>div{{min-width:0}}.status span{{display:block}}
.status strong{{display:block;font-size:17px}}.muted,.status span{{color:var(--muted)}}section{{margin-top:24px}}h2{{margin:0 0 12px}}
.signals{{margin:5px 0 0;padding:0;list-style:none}}.signals li{{display:flex;align-items:baseline;gap:9px;padding:1px 0}}
.signals .mark{{flex:0 0 auto;width:9px;height:9px;border-radius:50%;background:var(--bad);box-shadow:0 0 0 2px #fee2e2}}
.signals li.ok .mark{{background:var(--ok);box-shadow:0 0 0 2px #dcfce7}}.signals li.warn .mark{{background:var(--busy);box-shadow:0 0 0 2px #fef3c7}}
.table-wrap{{overflow:auto;max-height:55vh;border:1px solid var(--line);border-radius:12px;background:#fff;scrollbar-gutter:stable}}table{{width:100%;border-collapse:collapse;white-space:nowrap}}
th,td{{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{position:sticky;top:0;background:#eef3f8;font-size:12px;text-transform:uppercase}}
td a.rowlink{{display:block;margin:-10px -12px;padding:10px 12px;color:inherit;font-weight:inherit;text-decoration:none}}
tr.linked:hover td{{background:#eff6ff}}tr.linked:focus-within td{{background:#e0f2fe}}
td a.evidence{{display:inline-block;margin-top:4px;padding:0;font-size:11px}}
.message{{max-width:680px;white-space:normal;overflow-wrap:anywhere;font:12px/1.45 ui-monospace,Consolas,monospace}}.badge{{display:inline-block;padding:2px 8px;border-radius:999px;background:#e2e8f0;font-size:11px;font-weight:700}}
.section-head{{display:flex;align-items:baseline;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px}}.section-head h2{{margin:0}}
.section-head .muted{{margin-right:auto}}
.chips{{display:flex;flex-wrap:wrap;gap:6px}}.chip{{padding:3px 11px;border:1px solid var(--line);border-radius:999px;background:#fff;color:var(--muted);font-size:12px;font-weight:650;text-decoration:none}}
.chip:hover{{border-color:var(--accent)}}.chip.on{{border-color:var(--accent);background:#e0f2fe;color:var(--accent)}}
button.danger{{padding:5px 11px;border:1px solid #fca5a5;border-radius:8px;background:#fff;color:var(--bad);font:inherit;font-weight:650;cursor:pointer}}button.danger:hover{{background:#fef2f2}}form.inline{{display:inline}}
.badge.trigger,.badge.active{{background:#fef3c7;color:#92400e}}.badge.done{{background:#dcfce7;color:#166534}}a{{color:#0369a1;font-weight:650}}code{{color:#075985}}
</style></head><body><header><h1>PBP Monitoring <small style="font-size:14px;font-weight:600">v{_escape(__version__)}</small></h1><p>Dashboard &middot; refreshes every {max(2, int(refresh_seconds))} seconds &middot; <a style="color:white" href="/admin">Admin</a></p></header><main>
{status_panel}
<section><div class="section-head"><h2>20 most recent received logs</h2>{log_filters}</div><div class="table-wrap"><table><thead><tr><th>Time (UTC)</th><th>Observed source</th><th>Firewall</th><th>Type</th><th>Message</th></tr></thead><tbody>{''.join(log_rows)}</tbody></table></div></section>
<section><div class="section-head"><h2>Recent runs</h2>{runs_hint}{delete_all_control}</div><div class="table-wrap"><table><thead><tr><th>Target</th><th>Run ID</th><th>Start time (UTC)</th><th>Status</th><th>Batches</th><th>Peak buffer</th><th>Top sources</th><th>Stop reason</th><th>Delete</th></tr></thead><tbody>{''.join(run_rows)}</tbody></table></div></section>
</main></body></html>"""


#: The two run families a capture directory can belong to, and the JSONL each
#: one is identified by.
RUN_FAMILIES = (("incidents", "incident.jsonl"), ("api-checks", "api-check.jsonl"))


def _artifact_path(data_dir: Path, target: str, run_id: str, *parts: str) -> Path | None:
    components = (target, run_id, *parts)
    if any(not SAFE_COMPONENT.fullmatch(component) for component in components):
        return None
    root = (data_dir / "targets" / target / "incidents" / run_id).resolve()
    candidate = root.joinpath(*parts).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def _run_root(data_dir: Path, target: str, run_id: str) -> tuple[Path, str] | None:
    """Locate a run directory whichever family it belongs to.

    A read-only API validation is where a credential, TLS or unsupported
    command problem shows first, so it must be exportable exactly like an
    incident.
    """
    if not SAFE_COMPONENT.fullmatch(target) or not SAFE_COMPONENT.fullmatch(run_id):
        return None
    # The requested names select an existing directory entry; they are never
    # joined into a path. Nothing the request carries can therefore reach the
    # filesystem, whatever a future change does to the validation above.
    target_root = _matching_child(data_dir / "targets", target)
    if target_root is None:
        return None
    for folder, capture in RUN_FAMILIES:
        run_dir = _matching_child(target_root / folder, run_id)
        if run_dir is not None and (run_dir / capture).is_file():
            return run_dir, capture
    return None


def _incident_run_dir(data_dir: Path, target: str, run_id: str) -> Path | None:
    """Locate an incident run directory without joining a request into a path.

    The requested names select an existing directory entry, exactly as
    `_run_root` does, so nothing the request carries reaches the filesystem.
    """
    if not SAFE_COMPONENT.fullmatch(target) or not SAFE_COMPONENT.fullmatch(run_id):
        return None
    target_root = _matching_child(data_dir / "targets", target)
    if target_root is None:
        return None
    return _matching_child(target_root / "incidents", run_id)


def _matching_child(parent: Path, name: str) -> Path | None:
    """Return the child of `parent` literally named `name`, or None."""
    try:
        for child in parent.iterdir():
            if child.name == name and child.is_dir() and not child.is_symlink():
                return child
    except OSError:
        return None
    return None


def handler_factory(
    data_dir: Path,
    freshness_seconds: float,
    config_db: Path | None = None,
    *,
    tls_enabled: bool = False,
    tls_cert: Path | None = None,
) -> type[BaseHTTPRequestHandler]:
    config_store = ConfigStore(config_db) if config_db else None
    admin = (
        AdminController(
            config_store,
            allow_remote=True,
            secure_cookie=tls_enabled,
            data_dir=data_dir,
            log_dirs=(
                diagnostics.default_log_dir(data_dir),
                diagnostics.default_log_dir(config_db.parent),
            ),
            tls_cert=tls_cert,
        )
        if config_store
        else None
    )

    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = f"PBPWeb/{__version__}"

        def _headers(self, status: int, content_type: str, length: int | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
            if tls_enabled:
                self.send_header("Strict-Transport-Security", "max-age=31536000")
            if length is not None:
                self.send_header("Content-Length", str(length))
            self.end_headers()

        def _send_bytes(self, payload: bytes, content_type: str, status: int = 200) -> None:
            self._headers(status, content_type, len(payload))
            if self.command != "HEAD":
                self.wfile.write(payload)

        def _serve_file(self, path: Path, content_type: str, *, attachment: bool = False) -> None:
            if not path.is_file():
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(path.stat().st_size))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            if attachment:
                self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
            self.end_headers()
            if self.command != "HEAD":
                with path.open("rb") as handle:
                    while chunk := handle.read(1024 * 1024):
                        self.wfile.write(chunk)

        def _serve_report(self, run_dir: Path, target: str, run_id: str) -> None:
            """Serve a stored report with the run's evidence links added.

            The bar goes into the opening chunk and the rest of the report is
            streamed from disk, so the run of a real packet-buffer incident,
            whose report weighs tens of megabytes, still offers its JSONL, its
            TXT batches and its support archive. A report that carries no body
            tag is streamed unchanged rather than withheld.
            """
            report = run_dir / "report.html"
            try:
                with report.open("rb") as handle:
                    size = os.fstat(handle.fileno()).st_size
                    head = handle.read(REPORT_HEAD_BYTES)
                    annotated = annotate_report_head(
                        head,
                        render_report_evidence_bar(target, run_id, run_dir),
                    )
                    if annotated is None:
                        self._serve_file(report, "text/html; charset=utf-8")
                        return
                    self._headers(
                        200,
                        "text/html; charset=utf-8",
                        size + len(annotated) - len(head),
                    )
                    if self.command == "HEAD":
                        return
                    self.wfile.write(annotated)
                    while chunk := handle.read(1024 * 1024):
                        self.wfile.write(chunk)
            except OSError:
                self._serve_file(report, "text/html; charset=utf-8")

        def _serve_run_archive(
            self,
            run_dir: Path,
            target: str,
            run_id: str,
            *,
            anonymize: bool = False,
        ) -> None:
            if not run_dir.is_dir():
                self.send_error(404)
                return
            anonymizer = (
                diagnostics.build_anonymizer(config_store) if anonymize else None
            )
            label = anonymizer.apply(target) if anonymizer else target
            filename = f"pbp-run-{label}-{run_id}-v{__version__}.zip"
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            if self.command != "HEAD":
                write_run_archive(
                    self.wfile,
                    run_dir,
                    target=target,
                    run_id=run_id,
                    config_store=config_store,
                    anonymizer=anonymizer,
                )

        def do_HEAD(self) -> None:
            self.do_GET()

        def _see_other(self, location: str) -> None:
            self.send_response(303)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def _queue_run_deletion(self, path: str) -> None:
            """Record the operator's deletion request for the collector.

            The evidence volume is mounted read-only here, so the Web UI never
            removes a capture itself: it writes the intent to the shared
            database and the collector performs the removal.
            """
            if admin is None or config_store is None:
                self.send_error(404)
                return
            if not admin.is_authenticated(self):
                self._see_other("/admin")
                return
            token = admin.session_csrf(self)
            try:
                form = admin.read_form(self)
            except ValueError:
                self.send_error(400)
                return
            if not token or not secrets.compare_digest(form.get("csrf", ""), token):
                self.send_error(403)
                return
            try:
                if path == "/runs/delete-all":
                    config_store.request_all_runs_deletion()
                    LOG.warning("Deletion of every incident run requested by the operator")
                else:
                    target = form.get("target", "")
                    run_id = form.get("run_id", "")
                    config_store.request_run_deletion(target, run_id)
                    LOG.warning(
                        "Deletion of incident run %s on %s requested by the operator",
                        run_id,
                        target,
                    )
            except ValueError:
                self.send_error(400)
                return
            except OSError:
                LOG.exception("Unable to queue the incident-run deletion")
                self.send_error(503)
                return
            self._see_other("/")

        def do_POST(self) -> None:
            path = unquote(urlsplit(self.path).path)
            if admin is not None and admin.handle(self, path):
                return
            if path in ("/runs/delete", "/runs/delete-all"):
                self._queue_run_deletion(path)
                return
            self.send_error(404)

        def do_GET(self) -> None:
            request_url = urlsplit(self.path)
            path = unquote(request_url.path)
            if admin is not None and admin.handle(self, path):
                return
            if path == "/healthz":
                self._send_bytes(b"ok\n", "text/plain; charset=utf-8")
                return
            if admin is not None and not admin.is_authenticated(self):
                # Incident evidence carries serials, addresses, session tuples
                # and raw command output: it is gated by the same session as
                # the configuration, and fails closed.
                self.send_response(303)
                self.send_header("Location", "/admin")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
            if path == "/":
                effective_freshness = freshness_seconds
                if config_store is not None:
                    try:
                        effective_freshness = float(config_store.get_settings()["syslog_fresh_seconds"])
                    except (KeyError, OSError, ValueError):
                        pass
                requested = parse_qs(request_url.query).get("firewall", [""])[0]
                selected = (
                    requested
                    if requested == UNATTRIBUTED_LOGS or TARGET_NAME.fullmatch(requested)
                    else ""
                )
                state = collect_dashboard_state(
                    data_dir,
                    freshness_seconds=effective_freshness,
                    config_store=config_store,
                    log_filter=selected,
                )
                page = render_dashboard(
                    state,
                    csrf=admin.session_csrf(self) if admin is not None else None,
                )
                self._send_bytes(page.encode("utf-8"), "text/html; charset=utf-8")
                return
            parts = [part for part in path.split("/") if part]
            if len(parts) == 4 and parts[0] == "reports" and parts[3] == "report.html":
                run_dir = _incident_run_dir(data_dir, parts[1], parts[2])
                if run_dir is None or not (run_dir / "report.html").is_file():
                    self.send_error(404)
                    return
                self._serve_report(run_dir, parts[1], parts[2])
                return
            if len(parts) == 4 and parts[0] == "artifacts" and parts[3] == "incident.jsonl":
                artifact = _artifact_path(data_dir, parts[1], parts[2], "incident.jsonl")
                self._serve_file(artifact, "application/x-ndjson", attachment=True) if artifact else self.send_error(404)
                return
            if len(parts) == 4 and parts[0] == "artifacts" and parts[3] == "run.zip":
                located = _run_root(data_dir, parts[1], parts[2])
                if located is None:
                    self.send_error(404)
                else:
                    self._serve_run_archive(
                        located[0],
                        parts[1],
                        parts[2],
                        anonymize=parse_qs(request_url.query).get("anonymize")
                        == ["1"],
                    )
                return
            if len(parts) == 4 and parts[0] == "artifacts" and parts[3] == "raw":
                raw_dir = _artifact_path(data_dir, parts[1], parts[2], "raw")
                if raw_dir is None or not raw_dir.is_dir():
                    self.send_error(404)
                    return
                page = render_text_export_index(
                    parts[1],
                    parts[2],
                    collect_text_exports(raw_dir),
                )
                self._send_bytes(page.encode("utf-8"), "text/html; charset=utf-8")
                return
            if len(parts) == 5 and parts[0] == "artifacts" and parts[3] == "raw":
                artifact = _artifact_path(data_dir, parts[1], parts[2], "raw", parts[4])
                attachment = parse_qs(request_url.query).get("download") == ["1"]
                self._serve_file(
                    artifact,
                    "text/plain; charset=utf-8",
                    attachment=attachment,
                ) if artifact else self.send_error(404)
                return
            self.send_error(404)

        def log_message(self, format: str, *args: Any) -> None:
            LOG.info("%s - %s", self.client_address[0], format % args)

    return DashboardHandler


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path(os.getenv("WEB_DATA_DIR", "/data")))
    parser.add_argument("--host", default=os.getenv("WEB_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("WEB_PORT", "8080")))
    parser.add_argument("--redirect-port", type=int, default=int(os.getenv("WEB_HTTP_REDIRECT_PORT", "8081")))
    parser.add_argument("--https-public-port", type=int, default=int(os.getenv("WEB_HTTPS_PUBLIC_PORT", "8088")))
    parser.add_argument("--fresh-seconds", type=float, default=float(os.getenv("WEB_LOG_FRESH_SECONDS", "300")))
    parser.add_argument("--config-db", type=Path, default=Path(os.getenv("PBP_CONFIG_DB", "/config/config.db")))
    parser.add_argument("--tls-cert", type=Path, default=Path(os.getenv("WEB_TLS_CERT", "").strip() or "/config/web-tls.crt"))
    parser.add_argument("--tls-key", type=Path, default=Path(os.getenv("WEB_TLS_KEY", "").strip() or "/config/web-tls.key"))
    parser.add_argument("--tls-hostnames", default=os.getenv("WEB_TLS_HOSTNAMES", "localhost,127.0.0.1"))
    args = parser.parse_args(argv)
    if (
        not 1 <= args.port <= 65535
        or not 1 <= args.redirect_port <= 65535
        or not 1 <= args.https_public_port <= 65535
        or args.port == args.redirect_port
        or args.fresh_seconds <= 0
    ):
        parser.error("ports and fresh-seconds must be positive, valid, and distinct")
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format=diagnostics.LOG_FORMAT)
    # The dashboard mounts the capture volume read-only, so its own log
    # lives beside the configuration database instead.
    configured_log_dir = os.getenv("PBP_LOG_DIR", "").strip()
    diagnostics.configure_file_logging(
        Path(configured_log_dir)
        if configured_log_dir
        else diagnostics.default_log_dir(args.config_db.parent),
        "webui",
    )
    configured_certificate = bool(
        os.getenv("WEB_TLS_CERT", "").strip() or os.getenv("WEB_TLS_KEY", "").strip()
    )
    if configured_certificate:
        if not args.tls_cert.is_file() or not args.tls_key.is_file():
            parser.error("WEB_TLS_CERT and WEB_TLS_KEY must identify readable files")
    else:
        ensure_self_signed_certificate(
            args.tls_cert,
            args.tls_key,
            [value.strip() for value in args.tls_hostnames.split(",")],
        )
    tls_enabled = True

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.tls_cert, args.tls_key)
    server = ThreadingTLSHTTPServer(
        (args.host, args.port),
        handler_factory(
            args.data_dir,
            args.fresh_seconds,
            args.config_db,
            tls_enabled=tls_enabled,
            tls_cert=args.tls_cert,
        ),
        context,
    )
    redirect_server = ThreadingHTTPServer(
        (args.host, args.redirect_port),
        redirect_handler_factory(args.https_public_port),
    )
    redirect_thread = threading.Thread(target=redirect_server.serve_forever, daemon=True)
    redirect_thread.start()
    LOG.info(
        "Dashboard listening on %s://%s:%s",
        "https" if tls_enabled else "http",
        args.host,
        args.port,
    )
    LOG.info(
        "HTTP redirect listening on http://%s:%s and targeting HTTPS port %s",
        args.host,
        args.redirect_port,
        args.https_public_port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        redirect_server.shutdown()
        redirect_server.server_close()
        redirect_thread.join(timeout=2)
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
