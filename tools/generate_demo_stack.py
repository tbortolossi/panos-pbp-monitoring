#!/usr/bin/env python3
"""Screenshot every page the collector serves, from a fictitious incident.

Documentation screenshots must not be taken from the lab stack. Its pages carry
a real device serial, a real management address and a real hostname, so every
manual capture would need a disclosure review before being committed, and the
review would have to be repeated at each user-interface change.

This tool renders the shipped server and report code against invented data
instead. It starts the real web server in-process on the loopback interface,
signs in over HTTP, fetches each page, and hands the saved HTML to a headless
Chromium. The images can therefore be regenerated after any UI change and
committed as they are.

Nothing here contacts a firewall or issues an operational command. Every
address is drawn from the documentation ranges of RFC 5737, the serial is
invented, and the raw command output embedded in the fictitious capture is
synthetic.

Rendering needs a Chromium binary on the host. `--check` builds the whole demo
stack and stops before rendering, which is what CI runs: it proves the
generator still matches the pages without comparing pixels across
distributions.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener

from pbp_monitoring import __version__
from pbp_monitoring import config_store as config_store_module
from pbp_monitoring import webui
from pbp_monitoring.config_store import ConfigStore
from pbp_monitoring import reporting
from pbp_monitoring.reporting import generate_html_report
from pbp_monitoring.text_export import export_jsonl_text

# Every identifier below is invented. The addresses come from the documentation
# ranges reserved by RFC 5737, which are never routed to a real network, and the
# serial is the placeholder the test fixtures already use.
DEMO_TARGET = "lab-fw-01"
DEMO_SERIAL = "012345678901"
DEMO_PANOS_URL = "https://192.0.2.1"
DEMO_SYSLOG_SOURCE = "192.0.2.10"
DEMO_COLLECTOR_IP = "192.0.2.20"
DEMO_OFFENDER = "203.0.113.7"
DEMO_SECOND_OFFENDER = "203.0.113.9"
DEMO_VICTIM = "198.51.100.15"
DEMO_SERVICE = "198.51.100.20"
DEMO_UNKNOWN_SENDER = "192.0.2.77"

# A throwaway credential for a throwaway store that never leaves a temporary
# directory. It unlocks nothing: the demo store is discarded when the tool ends.
DEMO_PASSWORD = "demonstration-password-not-a-secret"

# The whole capture is anchored to one instant so two runs of this tool produce
# byte-identical pages. Without it every rendered timestamp, age and freshness
# indicator would follow the wall clock and every screenshot would differ.
DEMO_NOW = datetime(2026, 8, 29, 10, 5, 0, tzinfo=timezone.utc)
DEMO_INCIDENT_START = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)
DEMO_RUN_ID = DEMO_INCIDENT_START.strftime("%Y%m%dT%H%M%SZ")

DEMO_TRIGGER_MESSAGE = (
    f"PBP_SYSLOG_SOURCE={DEMO_SYSLOG_SOURCE} <14>Aug 29 10:00:00 {DEMO_TARGET} "
    f"1,2026/08/29 10:00:00,{DEMO_SERIAL},THREAT,flood,2561,"
    f"2026/08/29 10:00:00,{DEMO_OFFENDER},{DEMO_VICTIM},0.0.0.0,0.0.0.0,"
    '"allow-outbound,legacy",,,not-applicable,vsys1,outside,inside,'
    "ethernet1/1,ethernet1/2,default,2026/08/29 10:00:00,123456,1,"
    '54321,443,0,0,0x0,udp,drop,"",PBP Packet Drop(8507),any,critical,'
    "client-to-server"
)

# The pages lay their content out in `main{width:min(1280px,...)}`, so a wider
# window only adds background. This is that design width plus the 28px the rule
# reserves, which is the widest the content will ever be.
VIEWPORT_WIDTH = 1308
# A window taller than this is refused by the compositor, so a very long report
# is captured down to this height rather than failing outright.
MAX_VIEWPORT_HEIGHT = 8000
MEASURE_MARKER = "PBPSIZE"

CHROMIUM_CANDIDATES = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "chrome",
)


# The static core-to-function map a firewall reports once per run. Core 0 keeps
# the management and timer duties, the rest forward traffic, which is what makes
# a single saturated forwarding core meaningful in the report.
DEMO_CORE_FUNCTIONS = [
    {
        "dataplane": "dp0",
        "core_id": 0,
        "functions": ["pan_timer", "flow_mgmt"],
        "forwards_traffic": False,
    },
    *(
        {
            "dataplane": "dp0",
            "core_id": core,
            "functions": ["flow_lookup", "flow_fastpath", "flow_ctrl"],
            "forwards_traffic": True,
        }
        for core in (1, 2, 3)
    ),
]

def _timestamp(offset_seconds: float) -> str:
    """Return an ISO timestamp `offset_seconds` after the incident start."""
    return (DEMO_INCIDENT_START + timedelta(seconds=offset_seconds)).isoformat()


def _synthetic_command_outputs(buffer_pct: float) -> dict[str, Any]:
    """Return the raw operational output a cycle preserves for TAC evidence.

    The XML is written by hand rather than captured from a firewall. It carries
    the fields the report renders, in the shape PAN-OS returns them, and no
    device-specific content.
    """
    return {
        "packet_buffer_protection": {
            "result": (
                "<response status=\"success\"><result>\n"
                f"Packet buffer congestion: {buffer_pct}%\n"
                f"Session 38492 {DEMO_OFFENDER}/54321 -> {DEMO_VICTIM}/443 "
                "proto 17 drop-state on\n"
                "</result></response>"
            ),
            "raw_response": (
                "<response status=\"success\"><result>"
                f"<entry><session>38492</session><pct>{buffer_pct}</pct></entry>"
                "</result></response>"
            ),
            "error": None,
        },
        "clock": {
            "result": "Sat Aug 29 10:00:00 UTC 2026",
            "raw_response": (
                "<response status=\"success\"><result>"
                "Sat Aug 29 10:00:00 UTC 2026</result></response>"
            ),
            "error": None,
        },
    }


def _demo_cycle(number: int, offset_seconds: float, buffer_pct: float) -> dict[str, Any]:
    """Build one polling cycle of the fictitious incident."""
    return {
        "timestamp": _timestamp(offset_seconds),
        "collector_version": __version__,
        "run_id": DEMO_RUN_ID,
        "target_name": DEMO_TARGET,
        "cycle": number,
        "elapsed_seconds": float(offset_seconds),
        "percentages": {
            "packet_buffer_congestion": [buffer_pct],
            "descriptor_atomic": [round(buffer_pct * 0.7, 1)],
            "descriptor_total": [round(buffer_pct * 0.8, 1)],
            "resource_monitor_session": [round(18 + buffer_pct * 0.2, 1)],
        },
        "resource_monitor_cpu_cores": [
            {"dataplane": "dp0", "core_id": 0, "utilization": 6},
            {"dataplane": "dp0", "core_id": 1, "utilization": min(99, int(buffer_pct) + 12)},
            {"dataplane": "dp0", "core_id": 2, "utilization": 11},
            {"dataplane": "dp0", "core_id": 3, "utilization": 9},
        ],
        "candidate_session_ids": [38492, 38507],
        "candidate_entities": [
            {
                "rank": 1,
                "entity_type": "session",
                "session_id": 38492,
                "drop_state": True,
                "pbp_percentage_total": round(buffer_pct * 0.6, 1),
                "pbp_samples": 4088,
                "ingress_percentage_max": round(buffer_pct * 0.9, 1),
                "ingress_count": 3640,
                "evidence_sources": ["packet_buffer_protection", "ingress_backlogs"],
                "zones": ["outside"],
                "group_ids": ["flow_slowpath"],
            },
            {
                "rank": 2,
                "entity_type": "session",
                "session_id": 38507,
                "pbp_percentage_total": round(buffer_pct * 0.2, 1),
                "evidence_sources": ["packet_buffer_protection"],
                "zones": ["outside"],
            },
        ],
        "session_summaries": {
            "38492": {
                "status": "parsed",
                "application": "quic",
                "rule": "allow-outbound",
                "c2s": {
                    "source_ip": DEMO_OFFENDER,
                    "source_port": 54321,
                    "destination_ip": DEMO_VICTIM,
                    "destination_port": 443,
                    "protocol": 17,
                },
            },
            "38507": {
                "status": "parsed",
                "application": "quic",
                "rule": "allow-outbound",
                "c2s": {
                    "source_ip": DEMO_SECOND_OFFENDER,
                    "source_port": 51820,
                    "destination_ip": DEMO_VICTIM,
                    "destination_port": 443,
                    "protocol": 17,
                },
            },
        },
        "session_rates": {
            "38492": {"status": "derived", "bits_per_second_total": 940_000_000},
            "38507": {"status": "derived", "bits_per_second_total": 210_000_000},
        },
        "commands": _synthetic_command_outputs(buffer_pct),
    }


def demo_incident_records() -> list[dict[str, Any]]:
    """Build the fictitious incident: a UDP flood that saturates the buffers.

    The curve rises to a peak and recovers, so the report shows a complete
    incident rather than a snapshot: a trigger, an escalation, corroboration
    from the zone-protection flood logs, the offending sources, and a stop.
    """
    records: list[dict[str, Any]] = [
        {
            "timestamp": _timestamp(0),
            "collector_version": __version__,
            "run_id": DEMO_RUN_ID,
            "target_name": DEMO_TARGET,
            "event": "monitor_started",
            # The report reads the firewall identity from this record; without
            # it the header reads "Unidentified" and the core map is unknown.
            "device": {
                "hostname": DEMO_TARGET,
                "device_name": DEMO_TARGET,
                "serial": DEMO_SERIAL,
                "model": "PA-440",
                "software_version": "11.1.4-h7",
                "system_time": "Sat Aug 29 10:00:00 UTC 2026",
            },
            "identity_complete": True,
            "dp_core_functions": DEMO_CORE_FUNCTIONS,
            "dp_core_functions_source": "firewall",
        },
        {
            "timestamp": _timestamp(0.5),
            "run_id": DEMO_RUN_ID,
            "target_name": DEMO_TARGET,
            "event": "trigger_received",
            "trigger_sequence": 1,
            "reinforcement": False,
            "peer": f"{DEMO_SYSLOG_SOURCE}:514",
            "transport_source_ip": DEMO_SYSLOG_SOURCE,
            "message": DEMO_TRIGGER_MESSAGE,
            "metadata": {
                "trigger_type": "pbp_packet_drop",
                "threat_id": 8507,
                "device_serial": DEMO_SERIAL,
                "syslog_source_ip": DEMO_SYSLOG_SOURCE,
                "source_ip": DEMO_OFFENDER,
                "destination_ip": DEMO_VICTIM,
                "source_port": 54321,
                "destination_port": 443,
                "ingress_interface": "ethernet1/1",
            },
        }
    ]
    for number, (offset, buffer_pct) in enumerate(
        [(2, 41.0), (32, 68.5), (62, 84.0), (92, 78.5), (122, 52.0), (152, 33.0)],
        start=1,
    ):
        records.append(_demo_cycle(number, offset, buffer_pct))
        if number == 2:
            records.append(
                {
                    "timestamp": _timestamp(offset + 4),
                    "run_id": DEMO_RUN_ID,
                    "event": "flood_corroboration",
                    "metadata": {"destination_ip": DEMO_VICTIM},
                }
            )
        if number == 3:
            records.append(
                {
                    "timestamp": _timestamp(offset + 6),
                    "run_id": DEMO_RUN_ID,
                    "event": "offender_live_sessions",
                    "sources": [
                        {
                            "source_ip": DEMO_OFFENDER,
                            "ok": True,
                            "session_count": 2,
                            "entries": [
                                {
                                    "destination_ip": DEMO_VICTIM,
                                    "destination_port": "443",
                                    "protocol": "17",
                                    "application": "quic",
                                    "from_zone": "outside",
                                    "to_zone": "inside",
                                    "start_time": "Sat Aug 29 10:00:04 2026",
                                },
                                {
                                    "destination_ip": DEMO_SERVICE,
                                    "destination_port": "443",
                                    "protocol": "17",
                                    "application": "quic",
                                    "from_zone": "outside",
                                    "to_zone": "inside",
                                    "start_time": "Sat Aug 29 10:00:05 2026",
                                },
                            ],
                        }
                    ],
                }
            )
    records.append(
        {
            "timestamp": _timestamp(160),
            "run_id": DEMO_RUN_ID,
            "target_name": DEMO_TARGET,
            "event": "monitor_stopped",
            "reason": "resources_recovered",
            "cycles": 6,
            "elapsed_seconds": 160.0,
            "peak_packet_buffer_pct": 84.0,
            "top_sources": [DEMO_OFFENDER, DEMO_SECOND_OFFENDER],
        }
    )
    return records


def _system_log(moment: datetime, utilization: int) -> str:
    """Build the routine System log a healthy firewall keeps forwarding."""
    stamp = moment.strftime("%Y/%m/%d %H:%M:%S")
    return (
        f"<14>{moment.strftime('%b %d %H:%M:%S')} {DEMO_TARGET} "
        f"1,{stamp},{DEMO_SERIAL},SYSTEM,general,0,{stamp},,general,,0,0,"
        f'general,informational,"Session table utilization is {utilization}%",'
        "1234,0x0"
    )


def demo_syslog_records() -> list[dict[str, Any]]:
    """Build the reception journal the dashboard reads.

    One entry is deliberately a suppressed one: an unregistered sender is
    journalled without its payload, and the dashboard has to show that state as
    plainly as an accepted message.
    """
    records: list[dict[str, Any]] = []
    for seconds, utilization in ((305, 74), (240, 61), (120, 38), (12, 21)):
        moment = DEMO_NOW - timedelta(seconds=seconds)
        trigger = seconds == 305
        metadata = {
            "syslog_source_ip": DEMO_SYSLOG_SOURCE,
            "device_serial": DEMO_SERIAL,
        }
        if trigger:
            metadata.update({"trigger_type": "pbp_packet_drop", "threat_id": 8507})
        records.append(
            {
                "timestamp": moment.isoformat(),
                "peer": f"{DEMO_SYSLOG_SOURCE}:514",
                "transport_source_ip": DEMO_SYSLOG_SOURCE,
                "trigger": trigger,
                "target_names": [DEMO_TARGET],
                "metadata": metadata,
                "message": DEMO_TRIGGER_MESSAGE
                if trigger
                else _system_log(moment, utilization),
            }
        )
    records.append(
        {
            "timestamp": (DEMO_NOW - timedelta(seconds=48)).isoformat(),
            "peer": f"{DEMO_UNKNOWN_SENDER}:514",
            "transport_source_ip": DEMO_UNKNOWN_SENDER,
            "trigger": False,
            "target_names": [],
            "metadata": {"syslog_source_ip": DEMO_UNKNOWN_SENDER},
            "suppressed": "source_not_registered",
        }
    )
    records.sort(key=lambda record: record["timestamp"])
    return records


@dataclass(frozen=True)
class DemoStack:
    """Where the fictitious deployment lives on disk."""

    root: Path
    data_dir: Path
    config_db: Path
    target_id: int
    run_dir: Path


@contextmanager
def _frozen_clock() -> Iterator[None]:
    """Pin the clocks the pages render, so two runs produce the same images.

    `config_store` stamps every write with the current time, the dashboard ages
    its entries against it, and the report footer records when it was
    generated. All three are redirected to the demo instant for the duration of
    the build, so a regenerated image differs only when the interface does.
    """
    real_utc_now = config_store_module._utc_now
    real_collect = webui.collect_dashboard_state
    real_datetime = reporting.datetime
    frozen = DEMO_NOW.isoformat()

    def collect_at_demo_now(data_dir: Path, **kwargs: Any) -> dict[str, Any]:
        return real_collect(data_dir, **{**kwargs, "now": DEMO_NOW})

    class FrozenDatetime(real_datetime):
        @classmethod
        def now(cls, tz: Any = None) -> Any:
            return DEMO_NOW if tz else DEMO_NOW.replace(tzinfo=None)

    config_store_module._utc_now = lambda: frozen
    webui.collect_dashboard_state = collect_at_demo_now
    reporting.datetime = FrozenDatetime
    try:
        yield
    finally:
        config_store_module._utc_now = real_utc_now
        webui.collect_dashboard_state = real_collect
        reporting.datetime = real_datetime


def build_demo_stack(root: Path) -> DemoStack:
    """Write the fictitious capture, evidence and configuration under `root`."""
    data_dir = root / "data"
    run_dir = data_dir / "targets" / DEMO_TARGET / "incidents" / DEMO_RUN_ID
    run_dir.mkdir(parents=True, exist_ok=True)

    capture = run_dir / "incident.jsonl"
    with capture.open("w", encoding="utf-8") as handle:
        for record in demo_incident_records():
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    with (data_dir / "syslog-received.jsonl").open("w", encoding="utf-8") as handle:
        for record in demo_syslog_records():
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    # The report and the TXT exports are produced by the shipped generators, so
    # a screenshot shows what an operator actually downloads.
    generate_html_report(capture, run_dir / "report.html")
    export_jsonl_text(capture, run_dir / "raw")

    config_db = root / "config" / "config.db"
    store = ConfigStore(config_db)
    store.initialize()
    store.set_admin_password(DEMO_PASSWORD)
    # The recovery key is a real secret of this throwaway store. Acknowledging
    # it keeps the one-time banner, and anything key-shaped, out of the images.
    store.acknowledge_recovery_key()
    target_id = store.save_target(
        name=DEMO_TARGET,
        panos_url=DEMO_PANOS_URL,
        api_key="demo-api-key-not-a-secret",
        serials=[DEMO_SERIAL],
        syslog_sources=[DEMO_SYSLOG_SOURCE],
        tls_verify="false",
        enabled=True,
        device_identity={
            "hostname": DEMO_TARGET,
            "model": "PA-440",
            "software_version": "11.1.4-h7",
        },
    )
    store.record_target_check(
        target_id,
        kind="api",
        status="ok",
        detail="system info read, serial matches",
    )
    return DemoStack(
        root=root,
        data_dir=data_dir,
        config_db=config_db,
        target_id=target_id,
        run_dir=run_dir,
    )


@contextmanager
def _serving(data_dir: Path, config_db: Path) -> Iterator[str]:
    """Run the real web server on the loopback interface and yield its base URL."""
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        webui.handler_factory(data_dir, 300, config_db),
    )
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _sign_in(base: str) -> Any:
    """Return an opener carrying an authenticated administrator session."""
    opener = build_opener(HTTPCookieProcessor(CookieJar()))
    login_page = opener.open(base + "/admin").read().decode("utf-8")
    match = re.search(r'name="csrf" value="([^"]+)"', login_page)
    if match is None:
        raise RuntimeError("the sign-in page did not expose a CSRF token")
    body = urlencode({"csrf": match.group(1), "password": DEMO_PASSWORD}).encode()
    opener.open(Request(base + "/admin/login", data=body)).read()
    return opener


def demo_pages(stack: DemoStack) -> list[tuple[str, str]]:
    """Return the authenticated (file name, request path) pairs, in reading order."""
    syslog_options = urlencode(
        {
            "collector_ip": DEMO_COLLECTOR_IP,
            "syslog_port": "514",
            "log_profile": "default",
        }
    )
    run = f"{DEMO_TARGET}/{DEMO_RUN_ID}"
    return [
        ("dashboard", "/"),
        ("admin-configuration", f"/admin?{syslog_options}"),
        ("admin-firewall-form", f"/admin?edit={stack.target_id}&{syslog_options}"),
        ("incident-report", f"/reports/{run}/report.html"),
        ("text-exports", f"/artifacts/{run}/raw"),
    ]


def chromium_binary(explicit: str | None = None) -> str | None:
    """Locate a Chromium-family browser, or return None when there is none."""
    if explicit:
        return shutil.which(explicit) or (explicit if Path(explicit).is_file() else None)
    for candidate in CHROMIUM_CANDIDATES:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _run_chromium(binary: str, *arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            binary,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--hide-scrollbars",
            "--force-color-profile=srgb",
            *arguments,
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )


CSP_META = re.compile(
    r"(?i)<meta[^>]+http-equiv\s*=\s*[\"']?Content-Security-Policy[\"']?[^>]*>"
)


def _without_csp(html: str) -> str:
    """Drop the inline CSP so the measuring script may run.

    The HTML report declares `script-src 'none'` in a meta tag, which is exactly
    right for a file handed to TAC but stops the page from reporting its own
    height. The tag carries no layout, and only this measuring copy loses it:
    the image is always captured from the untouched page.
    """
    return CSP_META.sub("", html)


def _measure_document(
    binary: str, html: str, workdir: Path, *, width: int = VIEWPORT_WIDTH
) -> tuple[int, int]:
    """Render the page once to learn the full size of the document.

    Chromium's `--screenshot` captures exactly the window, so a page taller than
    the window silently loses its end. The page reports its own dimensions
    through the document title, which `--dump-dom` prints back.
    """
    probe = workdir / "measure.html"
    probe.write_text(
        _without_csp(html)
        + "<script>var d=document.documentElement;"
        f'document.title="{MEASURE_MARKER}:"+d.scrollWidth+"x"+d.scrollHeight;'
        "</script>",
        encoding="utf-8",
    )
    result = _run_chromium(
        binary,
        f"--window-size={width},900",
        "--dump-dom",
        probe.as_uri(),
    )
    sizes = [
        (int(measured_width), int(measured_height))
        for measured_width, measured_height in re.findall(
            rf"{MEASURE_MARKER}:(\d+)x(\d+)", result.stdout
        )
    ]
    if not sizes:
        raise RuntimeError(
            "Chromium did not report the page size; "
            f"stderr: {result.stderr.strip()[:400]}"
        )
    return max(sizes)


def capture_page(
    binary: str, html: str, destination: Path, workdir: Path
) -> tuple[int, int]:
    """Write one full-page PNG and return the captured size in pixels."""
    width = VIEWPORT_WIDTH
    _, measured_height = _measure_document(binary, html, workdir, width=width)
    height = min(max(measured_height, 400), MAX_VIEWPORT_HEIGHT)
    page = workdir / "page.html"
    page.write_text(html, encoding="utf-8")
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = _run_chromium(
        binary,
        f"--window-size={width},{height}",
        f"--screenshot={destination}",
        page.as_uri(),
    )
    if not destination.is_file():
        raise RuntimeError(
            f"Chromium wrote no image for {destination.name}; "
            f"stderr: {result.stderr.strip()[:400]}"
        )
    return width, height


def _fetch(opener: Any, base: str, path: str) -> str:
    with opener.open(base + path) as response:
        if response.status != 200:
            raise RuntimeError(f"{path} returned HTTP {response.status}")
        return response.read().decode("utf-8")


def _render_pages(root: Path) -> list[tuple[str, str]]:
    """Collect the HTML of every served page, in first-run order.

    The first two pages only exist before an administrator is configured, and
    the rest only after sign-in, so the server is started twice against the same
    directory rather than faking either state.
    """
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    config_db = root / "config" / "config.db"

    # Creating the controller logs the one-time setup code of this throwaway
    # store. It unlocks nothing once the tool exits, but printing something
    # shaped like a credential in a terminal is a habit worth not forming.
    admin_log = logging.getLogger("pbp-adminui")
    previous_level = admin_log.level
    admin_log.setLevel(logging.ERROR)

    first_run = ConfigStore(config_db)
    first_run.initialize()
    plain = build_opener()
    with _serving(data_dir, config_db) as base:
        pages = [("admin-setup", _fetch(plain, base, "/admin"))]

    stack = build_demo_stack(root)
    with _serving(stack.data_dir, stack.config_db) as base:
        pages.append(("admin-sign-in", _fetch(build_opener(), base, "/admin")))
        opener = _sign_in(base)
        for name, path in demo_pages(stack):
            pages.append((name, _fetch(opener, base, path)))
    admin_log.setLevel(previous_level)
    return pages


def generate(output_dir: Path, *, binary: str | None, check_only: bool) -> int:
    """Build the demo stack and, unless `check_only`, capture every page."""
    with tempfile.TemporaryDirectory(prefix="pbp-demo-") as temporary:
        root = Path(temporary)
        with _frozen_clock():
            rendered = _render_pages(root)

        for name, html in rendered:
            _assert_anonymized(name, html)

        if check_only:
            print(f"Built {len(rendered)} demo pages; rendering skipped (--check).")
            for name, html in rendered:
                print(f"  {name}: {len(html)} characters")
            return 0

        if binary is None:
            print(
                "No Chromium binary found. Install one, or pass --chromium PATH.\n"
                f"Looked for: {', '.join(CHROMIUM_CANDIDATES)}.",
                file=sys.stderr,
            )
            return 2

        output_dir.mkdir(parents=True, exist_ok=True)
        for name, html in rendered:
            destination = output_dir / f"{name}.png"
            size = capture_page(binary, html, destination, root)
            print(f"  {destination} ({size[0]}x{size[1]})")
    print(f"Wrote {len(rendered)} screenshots to {output_dir}.")
    return 0


def _assert_anonymized(name: str, html: str) -> None:
    """Fail loudly if a page carries anything but the invented identifiers.

    The tool is the only thing standing between the lab stack and a committed
    image, so a page that somehow reached real data must never be written out.
    """
    for pattern, label in (
        (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "an RFC 1918 10/8 address"),
        (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "an RFC 1918 192.168/16 address"),
        (r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", "an RFC 1918 172.16/12 address"),
    ):
        match = re.search(pattern, html)
        if match:
            raise RuntimeError(
                f"page {name!r} contains {label} ({match.group(0)}); refusing to render"
            )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "docs" / "images",
        help="directory receiving the PNG files (default: docs/images)",
    )
    parser.add_argument(
        "--chromium",
        help="path to the Chromium binary to render with",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="build the demo stack and verify every page, without rendering",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(argv)
    binary = None if arguments.check else chromium_binary(arguments.chromium)
    return generate(
        arguments.output_dir,
        binary=binary,
        check_only=arguments.check,
    )


if __name__ == "__main__":
    raise SystemExit(main())
