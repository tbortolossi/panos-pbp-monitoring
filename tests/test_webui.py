import hashlib
import http.cookiejar
import io
import json
import logging
import re
import tempfile
import threading
import unittest
import zipfile
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    Request,
    build_opener,
)

from pbp_monitoring.webui import (
    annotate_report_head,
    handler_factory,
    _incident_run_dir,
    render_report_evidence_bar,
    _artifact_path,
    _run_root,
    _https_redirect_location,
    collect_dashboard_state,
    collect_text_exports,
    render_dashboard,
    UNATTRIBUTED_LOGS,
    render_text_export_index,
    redirect_handler_factory,
    write_run_archive,
)
from pbp_monitoring import __version__, diagnostics
from pbp_monitoring.config_store import ALL_RUNS, ConfigStore
from tests.support import (
    SERVER_POLL_INTERVAL,
    start_fast_password_hashing,
    stop_fast_password_hashing,
)


def setUpModule():
    start_fast_password_hashing()


def tearDownModule():
    stop_fast_password_hashing()


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _SetupCodeCatcher(logging.Handler):
    def __init__(self):
        super().__init__()
        self.code = None

    def emit(self, record):
        match = re.search(r"setup code: (\S+)", record.getMessage())
        if match:
            self.code = match.group(1)


class ArtifactAuthenticationTests(unittest.TestCase):
    """Incident evidence must be gated by the administrator session."""

    def _server(self, root: Path):
        catcher = _SetupCodeCatcher()
        logger = logging.getLogger("pbp-adminui")
        logger.addHandler(catcher)
        try:
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                handler_factory(root / "data", 300, root / "config" / "config.db"),
            )
        finally:
            logger.removeHandler(catcher)
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": SERVER_POLL_INTERVAL},
            daemon=True,
        )
        thread.start()
        return server, thread, catcher.code

    def test_unauthenticated_requests_are_redirected_to_the_admin_area(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            server, thread, _ = self._server(Path(temporary_directory))
            base = f"http://127.0.0.1:{server.server_port}"
            opener = build_opener(_NoRedirect())
            try:
                for path in (
                    "/",
                    "/reports/fw/run/report.html",
                    "/artifacts/fw/run/incident.jsonl",
                    "/artifacts/fw/run/run.zip",
                    "/artifacts/fw/run/raw",
                    "/artifacts/fw/run/raw/batch-0001.txt",
                ):
                    with self.assertRaises(HTTPError) as context:
                        opener.open(base + path)
                    self.assertEqual(context.exception.code, 303, path)
                    self.assertEqual(context.exception.headers["Location"], "/admin")
                health = opener.open(base + "/healthz")
                self.assertEqual(health.status, 200)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def _sign_in(self, opener, base: str, setup_code: str) -> None:
        setup = opener.open(base + "/admin").read().decode()
        csrf = re.search(r'name="csrf" value="([^"]+)"', setup).group(1)
        login = opener.open(
            Request(
                base + "/admin/setup",
                data=urlencode(
                    {
                        "csrf": csrf,
                        "setup_code": setup_code,
                        "password": "long-test-password",
                        "confirm": "long-test-password",
                    }
                ).encode(),
            )
        ).read().decode()
        csrf = re.search(r'name="csrf" value="([^"]+)"', login).group(1)
        opener.open(
            Request(
                base + "/admin/login",
                data=urlencode({"csrf": csrf, "password": "long-test-password"}).encode(),
            )
        )

    def test_report_page_offers_the_run_evidence_without_altering_the_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            run_dir = root / "data" / "targets" / "fw-a" / "incidents" / "run-1"
            (run_dir / "raw").mkdir(parents=True)
            stored = "<html><body><h1>Incident report</h1></body></html>"
            (run_dir / "report.html").write_text(stored, encoding="utf-8")
            (run_dir / "incident.jsonl").write_text(
                json.dumps({"event": "monitor_started"}) + "\n", encoding="utf-8"
            )
            (run_dir / "raw" / "batch-0001.txt").write_text("output", encoding="utf-8")
            server, thread, setup_code = self._server(root)
            base = f"http://127.0.0.1:{server.server_port}"
            opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
            try:
                self._sign_in(opener, base, setup_code)
                page = opener.open(base + "/reports/fw-a/run-1/report.html").read().decode()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
            self.assertIn('href="/artifacts/fw-a/run-1/incident.jsonl"', page)
            self.assertIn(
                'href="/artifacts/fw-a/run-1/raw/" title="Human-readable export'
                ' of every command and its response, one file per batch">TXT'
                '<span class="pbp-bar-meta">1 file</span>',
                page,
            )
            self.assertIn('href="/artifacts/fw-a/run-1/run.zip"', page)
            self.assertIn('href="/artifacts/fw-a/run-1/run.zip?anonymize=1"', page)
            self.assertIn("Back to dashboard", page)
            self.assertIn("<h1>Incident report</h1>", page)
            self.assertLess(page.index("pbp-bar"), page.index("<h1>Incident report</h1>"))
            self.assertEqual(
                (run_dir / "report.html").read_text(encoding="utf-8"),
                stored,
                "the stored report must stay free of deployment-local links",
            )

    def test_a_report_heavier_than_a_chunk_still_offers_its_evidence(self):
        """A real incident report weighs tens of megabytes and must keep its exports.

        The bar used to be dropped above a size cap, which left the runs whose
        evidence matters most, the long collections, with no way to reach their
        JSONL or their support archive from the Web UI.
        """
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            run_dir = root / "data" / "targets" / "fw-a" / "incidents" / "run-1"
            (run_dir / "raw").mkdir(parents=True)
            filler = "<p>packet buffer sample</p>" * 400_000
            stored = f"<html><body><h1>Incident report</h1>{filler}</body></html>"
            (run_dir / "report.html").write_text(stored, encoding="utf-8")
            (run_dir / "incident.jsonl").write_text(
                json.dumps({"event": "monitor_started"}) + "\n", encoding="utf-8"
            )
            self.assertGreater(
                (run_dir / "report.html").stat().st_size,
                8 * 1024 * 1024,
                "the fixture must exceed the size that used to drop the bar",
            )
            server, thread, setup_code = self._server(root)
            base = f"http://127.0.0.1:{server.server_port}"
            opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
            try:
                self._sign_in(opener, base, setup_code)
                response = opener.open(base + "/reports/fw-a/run-1/report.html")
                page = response.read().decode()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
            self.assertIn('href="/artifacts/fw-a/run-1/incident.jsonl"', page)
            self.assertIn('href="/artifacts/fw-a/run-1/run.zip"', page)
            self.assertIn("<h1>Incident report</h1>", page)
            # The whole report is served, not only the annotated first chunk.
            self.assertTrue(page.endswith("</body></html>"))
            self.assertEqual(
                int(response.headers["Content-Length"]),
                len(page.encode("utf-8")),
                "a streamed report must announce the length it actually sends",
            )
            self.assertEqual(
                (run_dir / "report.html").read_text(encoding="utf-8"),
                stored,
                "the stored report must stay free of deployment-local links",
            )

    def test_signed_in_administrator_reaches_dashboard_and_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            run_dir = root / "data" / "targets" / "fw-a" / "incidents" / "run-1"
            run_dir.mkdir(parents=True)
            (run_dir / "report.html").write_text("fixture report", encoding="utf-8")
            server, thread, setup_code = self._server(root)
            base = f"http://127.0.0.1:{server.server_port}"
            opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
            try:
                setup = opener.open(base + "/admin").read().decode()
                csrf = re.search(r'name="csrf" value="([^"]+)"', setup).group(1)
                login = opener.open(
                    Request(
                        base + "/admin/setup",
                        data=urlencode(
                            {
                                "csrf": csrf,
                                "setup_code": setup_code,
                                "password": "long-test-password",
                                "confirm": "long-test-password",
                            }
                        ).encode(),
                    )
                ).read().decode()
                csrf = re.search(r'name="csrf" value="([^"]+)"', login).group(1)
                opener.open(
                    Request(
                        base + "/admin/login",
                        data=urlencode(
                            {"csrf": csrf, "password": "long-test-password"}
                        ).encode(),
                    )
                )
                dashboard = opener.open(base + "/").read().decode()
                self.assertIn("PBP Monitoring", dashboard)
                # An unknown or hostile firewall filter is dropped rather than
                # rendered: the dashboard falls back to every received log.
                filtered = opener.open(base + "/?firewall=../etc/passwd")
                self.assertEqual(filtered.status, 200)
                self.assertIn("PBP Monitoring", filtered.read().decode())
                report = opener.open(base + "/reports/fw-a/run-1/report.html")
                self.assertEqual(report.status, 200)
                self.assertIn("fixture report", report.read().decode())
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


class WebUITests(unittest.TestCase):
    def test_a_run_without_evidence_gets_a_bar_that_promises_nothing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            run_dir = Path(temporary_directory)
            bar = render_report_evidence_bar("fw-a", "run-1", run_dir)
            self.assertNotIn("/artifacts/", bar)
            self.assertIn("No stored evidence", bar)
            self.assertIn('href="/"', bar)

    def test_an_evidence_bar_escapes_the_run_it_names(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            bar = render_report_evidence_bar(
                "<script>", "run&1", Path(temporary_directory)
            )
            self.assertNotIn("<script>", bar)
            self.assertIn("&lt;script&gt;", bar)
            self.assertIn("run&amp;1", bar)

    def test_the_report_bar_names_every_export_with_its_format_and_weight(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            run_dir = Path(temporary_directory)
            (run_dir / "raw").mkdir()
            (run_dir / "incident.jsonl").write_bytes(b"x" * 4096)
            (run_dir / "raw" / "batch-0001.txt").write_text("out", encoding="utf-8")
            (run_dir / "raw" / "batch-0002.txt").write_text("out", encoding="utf-8")
            bar = render_report_evidence_bar("fw-a", "run-1", run_dir)

        self.assertIn(">Exports<", bar)
        self.assertIn('>JSONL<span class="pbp-bar-meta">4 KiB</span>', bar)
        self.assertIn('>TXT<span class="pbp-bar-meta">2 files</span>', bar)
        self.assertIn('>ZIP<span class="pbp-bar-meta">support archive</span>', bar)
        self.assertIn('>ZIP<span class="pbp-bar-meta">anonymized</span>', bar)
        # The report itself is an export too: the page says how to keep it.
        self.assertIn("print it from the browser", bar)
        self.assertIn('<a class="back" href="/">&larr; Back to dashboard</a>', bar)

    def test_a_completed_run_row_opens_its_report(self):
        def run(run_id, status, report):
            return {
                "target": "PA-440",
                "run_id": run_id,
                "started_at": "2026-01-01T00:00:00Z",
                "status": status,
                "stop_reason": "resources_recovered" if report else None,
                "cycles": 3,
                "peak_packet_buffer_pct": 42,
                "top_sources": ["203.0.113.7"],
                "report": report,
                "jsonl": True,
                "text_files": 2,
            }

        page = render_dashboard(
            {
                "syslog_healthy": True,
                "logs": [],
                "runs": [run("run-done", "completed", True), run("run-live", "active", False)],
            }
        )
        rows = re.findall(r"<tr.*?</tr>", page, re.S)
        completed = next(row for row in rows if "run-done" in row)
        running = next(row for row in rows if "run-live" in row)

        self.assertIn('<tr class="linked">', completed)
        self.assertEqual(completed.count('class="rowlink"'), 8)
        self.assertIn(
            '<a class="rowlink" href="/reports/PA-440/run-done/report.html"',
            completed,
        )
        self.assertIn("Click a row to open its report", page)
        # A monitor still running has no report yet, so its row stays plain
        # rather than leading to another run's page.
        self.assertNotIn("rowlink", running)
        self.assertNotIn("run-live/report.html", page)
        # It keeps a single link to the records already written, because no
        # report page exists yet to offer them.
        self.assertIn(
            '<a class="evidence" href="/artifacts/PA-440/run-live/incident.jsonl"',
            running,
        )
        self.assertNotIn("incident.jsonl", completed)

    def test_a_run_whose_report_is_missing_still_offers_its_records(self):
        page = render_dashboard(
            {
                "syslog_healthy": True,
                "logs": [],
                "runs": [
                    {
                        "target": "PA-440",
                        "run_id": "run-stopped",
                        "started_at": "2026-01-01T00:00:00Z",
                        "status": "completed",
                        "stop_reason": "resources_recovered",
                        "cycles": 3,
                        "peak_packet_buffer_pct": 42,
                        "top_sources": [],
                        "report": False,
                        "jsonl": True,
                        "text_files": 2,
                    }
                ],
            }
        )

        # HTML report generation can be disabled, or can fail. The run is then
        # read from its capture, so the row still leads to it.
        self.assertNotIn('class="rowlink"', page)
        self.assertIn(
            '<a class="evidence" href="/artifacts/PA-440/run-stopped/incident.jsonl"',
            page,
        )
        self.assertNotIn("Click a row to open its report", page)

    def test_a_report_lookup_cannot_escape_the_capture_directory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            (data / "targets" / "fw-a" / "incidents" / "run-1").mkdir(parents=True)
            self.assertIsNone(_incident_run_dir(data, "..", "run-1"))
            self.assertIsNone(_incident_run_dir(data, "fw-a", ".."))
            self.assertIsNone(_incident_run_dir(data, "fw-a", "run-2"))
            self.assertEqual(
                _incident_run_dir(data, "fw-a", "run-1"),
                data / "targets" / "fw-a" / "incidents" / "run-1",
            )

    def test_a_report_without_a_body_tag_is_served_unchanged(self):
        self.assertIsNone(annotate_report_head(b"fixture report", "<div>bar</div>"))
        self.assertEqual(
            annotate_report_head(b'<html><BODY class="x">t</BODY></html>', "<i>bar</i>"),
            b'<html><BODY class="x"><i>bar</i>t</BODY></html>',
        )

    def test_http_listener_redirects_to_same_host_https_and_rejects_bad_host(self):
        self.assertEqual(
            _https_redirect_location("pbp.example.test:8080", "/admin?x=1", 8088),
            "https://pbp.example.test:8088/admin?x=1",
        )
        with self.assertRaises(ValueError):
            _https_redirect_location("bad/host", "/", 8088)

        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        server = ThreadingHTTPServer(
            ("127.0.0.1", 0), redirect_handler_factory(8088)
        )
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": SERVER_POLL_INTERVAL},
            daemon=True,
        )
        thread.start()
        try:
            with self.assertRaises(HTTPError) as response:
                build_opener(NoRedirect()).open(
                    f"http://127.0.0.1:{server.server_port}/admin?setup=1"
                )
            self.assertEqual(response.exception.code, 308)
            self.assertEqual(
                response.exception.headers["Location"],
                "https://127.0.0.1:8088/admin?setup=1",
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_a_suppressed_record_does_not_keep_a_firewall_healthy(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            store = ConfigStore(data / "configuration" / "config.db")
            store.initialize()
            store.save_target(
                name="fw-a", panos_url="https://192.0.2.10", api_key="key-a",
                target_serial=None, serials=["012345678901"],
                syslog_sources=["192.0.2.10"],
            )
            suppressed = {
                "timestamp": "2026-08-28T12:00:00+00:00",
                "transport_source_ip": "192.0.2.3",
                "target_names": [],
                "trigger": True,
                "metadata": {"syslog_source_ip": "192.0.2.10"},
                "suppressed": "device_serial_not_registered",
            }
            (data / "syslog-received.jsonl").write_text(
                json.dumps(suppressed) + "\n", encoding="utf-8"
            )
            state = collect_dashboard_state(
                data,
                now=datetime(2026, 8, 28, 12, 1, tzinfo=timezone.utc),
                config_store=store,
            )
            rendered = render_dashboard(state)
            self.assertFalse(state["firewalls"][0]["healthy"])
            self.assertIsNone(state["firewalls"][0]["last_received_at"])
            self.assertIn("fw-a: needs attention", rendered)
            self.assertIn("not stored: device serial is not the registered one", rendered)

    def test_received_logs_can_be_filtered_to_one_firewall(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            store = ConfigStore(data / "configuration" / "config.db")
            store.initialize()
            store.save_target(
                name="fw-a", panos_url="https://192.0.2.10", api_key="key-a",
                target_serial=None, serials=[], syslog_sources=["192.0.2.10"],
            )
            store.save_target(
                name="fw-b", panos_url="https://192.0.2.11", api_key="key-b",
                target_serial=None, serials=[], syslog_sources=["192.0.2.11"],
            )
            records = [
                {
                    "timestamp": "2026-08-28T12:00:00+00:00",
                    "transport_source_ip": "192.0.2.10",
                    "target_names": ["fw-a"],
                    "trigger": False,
                    "metadata": {"syslog_source_ip": "192.0.2.10"},
                    "message": "system log from fw-a",
                },
                {
                    "timestamp": "2026-08-28T12:00:30+00:00",
                    "transport_source_ip": "192.0.2.11",
                    "target_names": ["fw-b"],
                    "trigger": False,
                    "metadata": {"syslog_source_ip": "192.0.2.11"},
                    "message": "system log from fw-b",
                },
            ]
            (data / "syslog-received.jsonl").write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            state = collect_dashboard_state(
                data,
                now=datetime(2026, 8, 28, 12, 1, tzinfo=timezone.utc),
                config_store=store,
                log_filter="fw-b",
            )
            rendered = render_dashboard(state)
            self.assertEqual(
                [record["message"] for record in state["logs"]],
                ["system log from fw-b"],
            )
            self.assertNotIn("system log from fw-a", rendered)
            self.assertIn('<a class="chip on" href="/?firewall=fw-b">fw-b</a>', rendered)
            # The filter is a view over the table only: both watchdogs keep
            # reading the whole journal, so neither card loses its freshness.
            self.assertTrue(state["firewalls"][0]["healthy"])
            self.assertTrue(state["firewalls"][1]["healthy"])

    def test_unattributed_filter_shows_the_logs_no_firewall_claims(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            store = ConfigStore(data / "configuration" / "config.db")
            store.initialize()
            store.save_target(
                name="fw-a", panos_url="https://192.0.2.10", api_key="key-a",
                target_serial=None, serials=[], syslog_sources=["192.0.2.10"],
            )
            records = [
                {
                    "timestamp": "2026-08-28T12:00:00+00:00",
                    "transport_source_ip": "192.0.2.10",
                    "target_names": ["fw-a"],
                    "trigger": False,
                    "metadata": {"syslog_source_ip": "192.0.2.10"},
                    "message": "system log from fw-a",
                },
                {
                    "timestamp": "2026-08-28T12:00:30+00:00",
                    "transport_source_ip": "198.51.100.9",
                    "target_names": [],
                    "trigger": False,
                    "metadata": {"syslog_source_ip": "198.51.100.9"},
                    "suppressed": "source_not_registered",
                },
            ]
            (data / "syslog-received.jsonl").write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            state = collect_dashboard_state(
                data,
                now=datetime(2026, 8, 28, 12, 1, tzinfo=timezone.utc),
                config_store=store,
                log_filter=UNATTRIBUTED_LOGS,
            )
            rendered = render_dashboard(state)
            self.assertEqual(state["unattributed_logs"], 1)
            self.assertEqual(
                [record.get("suppressed") for record in state["logs"]],
                ["source_not_registered"],
            )
            self.assertNotIn("system log from fw-a", rendered)
            self.assertIn("Unattributed (1)", rendered)
            self.assertIn("not stored: source is not a registered firewall", rendered)

    def test_reception_state_is_reported_per_firewall_not_globally(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            store = ConfigStore(data / "configuration" / "config.db")
            store.initialize()
            target_id = store.save_target(
                name="fw-a", panos_url="https://192.0.2.10", api_key="key-a",
                target_serial=None, serials=[], syslog_sources=["192.0.2.10"],
            )
            store.record_target_check(target_id, kind="keepalive", status="ok", detail="")
            store.save_target(
                name="fw-b", panos_url="https://192.0.2.11", api_key="key-b",
                target_serial=None, serials=[], syslog_sources=["192.0.2.11"],
            )
            received = {
                "timestamp": "2026-08-28T12:00:00+00:00",
                "transport_source_ip": "192.0.2.10",
                "target_names": ["fw-a"],
                "trigger": False,
                "metadata": {},
                "message": "system log",
            }
            (data / "syslog-received.jsonl").write_text(json.dumps(received) + "\n", encoding="utf-8")
            state = collect_dashboard_state(
                data,
                now=datetime(2026, 8, 28, 12, 1, tzinfo=timezone.utc),
                config_store=store,
            )
            rendered = render_dashboard(state)
            self.assertTrue(state["syslog_healthy"])
            self.assertTrue(state["firewalls"][0]["healthy"])
            self.assertFalse(state["firewalls"][1]["healthy"])
            self.assertIn("fw-a: healthy", rendered)
            self.assertIn("Syslog: last log 2026-08-28 12:00:00 UTC", rendered)
            self.assertIn(
                '<li class="ok"><span class="mark"></span>'
                "<span>Incident: no run in progress</span></li>",
                rendered,
            )
            self.assertIn("fw-b: needs attention", rendered)
            self.assertIn("Syslog: no attributed log received", rendered)
            self.assertIn("API check: never run", rendered)
            self.assertIn("Incident: no run in progress", rendered)
            self.assertNotIn("Syslog reception is active", rendered)

    def test_without_a_registered_firewall_reception_is_still_reported(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            received = {
                "timestamp": "2026-08-28T12:00:00+00:00",
                "transport_source_ip": "192.0.2.10",
                "target_names": [],
                "trigger": False,
                "metadata": {},
                "message": "system log",
            }
            (data / "syslog-received.jsonl").write_text(
                json.dumps(received) + "\n", encoding="utf-8"
            )
            state = collect_dashboard_state(
                data, now=datetime(2026, 8, 28, 12, 1, tzinfo=timezone.utc)
            )
            rendered = render_dashboard(state)
            self.assertEqual(state["firewalls"], [])
            self.assertIn("Syslog reception is active", rendered)
            self.assertIn("No firewall is registered yet", rendered)

    def test_a_firewall_card_shows_a_run_in_progress_and_the_last_api_check(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            store = ConfigStore(data / "configuration" / "config.db")
            store.initialize()
            target_id = store.save_target(
                name="fw-a", panos_url="https://192.0.2.10", api_key="key-a",
                target_serial=None, serials=[], syslog_sources=["192.0.2.10"],
            )
            store.record_target_check(
                target_id, kind="keepalive", status="ok",
                detail="PAN-OS 12.2.2; 4 dataplane cores mapped",
            )
            received = {
                "timestamp": "2026-08-28T12:00:00+00:00",
                "transport_source_ip": "192.0.2.10",
                "target_names": ["fw-a"],
                "trigger": True,
                "metadata": {},
                "message": "packet buffer congestion",
            }
            (data / "syslog-received.jsonl").write_text(
                json.dumps(received) + "\n", encoding="utf-8"
            )
            run_dir = data / "targets" / "fw-a" / "incidents" / "20260828T120000Z"
            run_dir.mkdir(parents=True)
            (run_dir / "incident.jsonl").write_text(
                json.dumps(
                    {
                        "timestamp": "2026-08-28T12:00:00+00:00",
                        "run_id": "20260828T120000Z",
                        "cycle": 4,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            state = collect_dashboard_state(
                data,
                now=datetime(2026, 8, 28, 12, 1, tzinfo=timezone.utc),
                config_store=store,
            )
            rendered = render_dashboard(state)

            firewall = state["firewalls"][0]
            self.assertEqual(firewall["active_run"], "20260828T120000Z")
            self.assertEqual(firewall["last_check_status"], "ok")
            self.assertIn("fw-a: monitoring run in progress", rendered)
            self.assertIn(
                '<li class="bad"><span class="mark"></span>'
                "<span>Incident: run 20260828T120000Z in progress</span></li>",
                rendered,
            )
            self.assertIn("API check: keepalive passed at", rendered)
            self.assertIn("4 dataplane cores mapped", rendered)
            self.assertIn('class="status busy"', rendered)

    def test_a_failed_api_check_marks_the_firewall_card(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            store = ConfigStore(data / "configuration" / "config.db")
            store.initialize()
            target_id = store.save_target(
                name="fw-a", panos_url="https://192.0.2.10", api_key="key-a",
                target_serial=None, serials=[], syslog_sources=["192.0.2.10"],
            )
            store.record_target_check(
                target_id, kind="keepalive", status="failed",
                detail="PanOSAPIError: unable to reach the firewall",
            )
            received = {
                "timestamp": "2026-08-28T12:00:00+00:00",
                "transport_source_ip": "192.0.2.10",
                "target_names": ["fw-a"],
                "trigger": False,
                "metadata": {},
                "message": "system log",
            }
            (data / "syslog-received.jsonl").write_text(
                json.dumps(received) + "\n", encoding="utf-8"
            )

            state = collect_dashboard_state(
                data,
                now=datetime(2026, 8, 28, 12, 1, tzinfo=timezone.utc),
                config_store=store,
            )
            rendered = render_dashboard(state)

            self.assertTrue(state["firewalls"][0]["healthy"])
            self.assertIn("fw-a: needs attention", rendered)
            self.assertIn('class="status bad"', rendered)
            self.assertIn("API check: keepalive FAILED at", rendered)
            self.assertIn("unable to reach the firewall", rendered)
            self.assertIn(
                '<li class="ok"><span class="mark"></span><span>Syslog: last log',
                rendered,
            )
            self.assertIn('<li class="bad"><span class="mark"></span><span>API check:', rendered)

    def test_an_overdue_scheduled_check_is_amber_rather_than_green(self):
        state = {
            "syslog_healthy": True,
            "syslog_age_seconds": 12,
            "logs": [],
            "runs": [],
            "runs_total": 0,
            "check_interval_hours": 24.0,
            "firewalls": [
                {
                    "name": "fw-a",
                    "enabled": True,
                    "healthy": True,
                    "last_received_at": "2026-08-28T12:00:00+00:00",
                    "age_seconds": 12,
                    "active_run": None,
                    "last_check_at": "2026-08-25T12:00:00+00:00",
                    "last_check_kind": "keepalive",
                    "last_check_status": "ok",
                    "last_check_detail": "PAN-OS 12.2.2",
                    "check_requested_at": None,
                    "check_age_seconds": 3 * 86400,
                }
            ],
            "pending_deletions": [],
        }

        rendered = render_dashboard(state)

        self.assertIn("fw-a: check pending", rendered)
        self.assertIn('class="status busy"', rendered)
        self.assertIn(
            '<li class="warn"><span class="mark"></span><span>API check:', rendered
        )
        self.assertIn("overdue, expected every 24 hours", rendered)

    def test_dashboard_reports_fresh_logs_runs_and_escaped_content(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            log = {
                "timestamp": "2026-08-28T12:00:01+00:00",
                "transport_source_ip": "172.19.0.3",
                "target_names": ["PA-440"],
                "trigger": True,
                "metadata": {"trigger_type": "pbp_packet_drop", "syslog_source_ip": "172.19.0.1"},
                "message": '<script>alert("x")</script> PBP Packet Drop(8507)',
            }
            (data / "syslog-received.jsonl").write_text(json.dumps(log) + "\n", encoding="utf-8")
            run = data / "targets" / "PA-440" / "incidents" / "20260828T120000Z"
            (run / "raw").mkdir(parents=True)
            records = [
                {"cycle": 1, "timestamp": "2026-08-28T12:00:01+00:00"},
                {
                    "event": "monitor_stopped",
                    "timestamp": "2026-08-28T12:00:02+00:00",
                    "reason": "resources_recovered",
                    "cycles": 1,
                    "peak_packet_buffer_pct": 62.5,
                    "top_sources": ["203.0.113.7"],
                },
            ]
            (run / "incident.jsonl").write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
            (run / "report.html").write_text("report", encoding="utf-8")
            (run.parent.parent / "syslog-triggers.jsonl").write_text(
                json.dumps(
                    {
                        "timestamp": "2026-08-28T12:00:01+00:00",
                        "run_id": "20260828T120000Z",
                        "message": "PBP Packet Drop",
                    }
                )
                + "\n"
                + json.dumps({"run_id": "another-run", "message": "excluded"})
                + "\n",
                encoding="utf-8",
            )
            (run / "raw" / "batch-0001.txt").write_text(
                "PBP MONITORING BATCH\n"
                "Batch: 1\n"
                "Collector time: 2026-08-28T12:00:01+00:00\n"
                "Firewall time: Fri Aug 28 14:00:01 CEST 2026\n"
                "Cycle duration seconds: 4.25\n",
                encoding="utf-8",
            )

            state = collect_dashboard_state(data, now=datetime(2026, 8, 28, 12, 1, tzinfo=timezone.utc))
            rendered = render_dashboard(state)

            self.assertTrue(state["syslog_healthy"])
            self.assertEqual(state["runs"][0]["status"], "completed")
            self.assertEqual(state["runs"][0]["text_files"], 1)
            self.assertEqual(
                state["runs"][0]["started_at"],
                "2026-08-28T12:00:01+00:00",
            )
            self.assertIn("Syslog reception is active", rendered)
            self.assertIn("Start time (UTC)", rendered)
            self.assertIn("2026-08-28T12:00:01+00:00", rendered)
            self.assertLess(
                rendered.index("20 most recent received logs"),
                rendered.index("Recent runs"),
            )
            # The exports of a completed run are offered by its report,
            # reached by clicking the row, and by nothing else on this page.
            self.assertNotIn("Artifacts", rendered)
            self.assertNotIn("run.zip", rendered)
            self.assertNotIn("/raw/", rendered)
            self.assertNotIn("incident.jsonl", rendered)
            self.assertIn("/reports/PA-440/20260828T120000Z/report.html", rendered)
            self.assertIn("Peak buffer", rendered)
            self.assertIn("62.5%", rendered)
            self.assertIn("203.0.113.7", rendered)
            self.assertIn("pbp_packet_drop", rendered)
            self.assertNotIn("<script>", rendered.lower())
            self.assertIn("&lt;script&gt;", rendered)

            exports = collect_text_exports(run / "raw")
            export_page = render_text_export_index("PA-440", "20260828T120000Z", exports)
            self.assertEqual(exports[0]["batch"], "1")
            self.assertIn("Execution time (UTC)", export_page)
            self.assertIn("2026-08-28 12:00:01 UTC", export_page)
            self.assertIn("Fri Aug 28 14:00:01 CEST 2026", export_page)
            self.assertIn("4.25", export_page)
            self.assertIn("View", export_page)
            self.assertIn("Download", export_page)

            archive_buffer = io.BytesIO()
            write_run_archive(
                archive_buffer,
                run,
                target="PA-440",
                run_id="20260828T120000Z",
            )
            archive_buffer.seek(0)
            with zipfile.ZipFile(archive_buffer) as archive:
                prefix = "pbp-run-PA-440-20260828T120000Z/"
                manifest = json.loads(archive.read(prefix + "manifest.json"))
                self.assertEqual(manifest["application_version"], __version__)
                self.assertIn(prefix + "incident.jsonl", archive.namelist())
                self.assertIn(prefix + "support/syslog-triggers.jsonl", archive.namelist())
                self.assertIn(prefix + "support/syslog-received.jsonl", archive.namelist())
                trigger_export = archive.read(
                    prefix + "support/syslog-triggers.jsonl"
                ).decode()
                self.assertIn("PBP Packet Drop", trigger_export)
                self.assertNotIn("excluded", trigger_export)
                self.assertIn(
                    "pbp_packet_drop",
                    archive.read(prefix + "support/syslog-received.jsonl").decode(),
                )
                captured = next(
                    item for item in manifest["files"]
                    if item["path"] == "incident.jsonl"
                )
                self.assertEqual(
                    captured["sha256"],
                    hashlib.sha256((run / "incident.jsonl").read_bytes()).hexdigest(),
                )

    def test_missing_or_stale_log_is_red_and_paths_cannot_escape(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            state = collect_dashboard_state(data)
            self.assertFalse(state["syslog_healthy"])
            self.assertIn("missing or stale", render_dashboard(state))
            self.assertIsNone(_artifact_path(data, "..", "run", "report.html"))
            self.assertIsNone(_artifact_path(data, "fw", "..", "report.html"))


if __name__ == "__main__":
    unittest.main()


class RunDeletionUITests(unittest.TestCase):
    """Deleting evidence is an authenticated, CSRF-protected operator action."""

    def _state(self, runs, pending=(), total=None):
        return {
            "syslog_healthy": True,
            "syslog_age_seconds": 1,
            "logs": [],
            "runs": runs,
            "runs_total": len(runs) if total is None else total,
            "firewalls": [],
            "pending_deletions": list(pending),
        }

    def _run(self, run_id, status="completed"):
        return {
            "target": "fw-a",
            "run_id": run_id,
            "started_at": "2026-01-01T00:00:00Z",
            "status": status,
            "stop_reason": "resources_recovered" if status == "completed" else None,
            "cycles": 3,
            "peak_packet_buffer_pct": 42,
            "top_sources": [],
            "updated_at": "2026-01-01T00:01:00Z",
            "report": False,
            "jsonl": True,
            "text_files": 0,
        }

    def test_a_completed_run_offers_delete_while_an_active_one_does_not(self):
        page = render_dashboard(
            self._state([self._run("run-done"), self._run("run-live", "active")]),
            csrf="token-value",
        )

        self.assertIn('action="/runs/delete"', page)
        self.assertIn('name="run_id" value="run-done"', page)
        self.assertNotIn('name="run_id" value="run-live"', page)
        self.assertIn('name="csrf" value="token-value"', page)

    def test_delete_all_counts_every_stored_run_not_only_the_listed_page(self):
        page = render_dashboard(
            self._state([self._run("run-done")], total=29), csrf="token-value"
        )

        self.assertIn('action="/runs/delete-all"', page)
        self.assertIn("Delete all 29 runs", page)

        single = render_dashboard(
            self._state([self._run("run-done")]), csrf="token-value"
        )
        self.assertIn("Delete all 1 run<", single)

    def test_a_queued_deletion_replaces_the_button_with_its_pending_state(self):
        page = render_dashboard(
            self._state(
                [self._run("run-done")],
                pending=[{"target": "fw-a", "run_id": "run-done"}],
            ),
            csrf="token-value",
        )
        self.assertNotIn('action="/runs/delete"', page)
        self.assertIn("Deleting", page)

        everything = render_dashboard(
            self._state(
                [self._run("run-done"), self._run("run-other")],
                pending=[{"target": ALL_RUNS, "run_id": ALL_RUNS}],
            ),
            csrf="token-value",
        )
        self.assertNotIn('action="/runs/delete"', everything)
        self.assertNotIn('action="/runs/delete-all"', everything)
        self.assertIn("Deleting every run", everything)

    def test_without_a_session_token_no_deletion_control_is_rendered(self):
        page = render_dashboard(self._state([self._run("run-done")]))

        self.assertNotIn("/runs/delete", page)
        self.assertNotIn("<button", page)


class RunDeletionRequestTests(unittest.TestCase):
    """The read-only Web UI records the intent; it never touches the volume."""

    def _server(self, root: Path):
        catcher = _SetupCodeCatcher()
        logger = logging.getLogger("pbp-adminui")
        logger.addHandler(catcher)
        try:
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                handler_factory(root / "data", 300, root / "config" / "config.db"),
            )
        finally:
            logger.removeHandler(catcher)
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": SERVER_POLL_INTERVAL},
            daemon=True,
        )
        thread.start()
        return server, thread, catcher.code

    def _sign_in(self, base: str, setup_code: str):
        opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        setup = opener.open(base + "/admin").read().decode()
        csrf = re.search(r'name="csrf" value="([^"]+)"', setup).group(1)
        signed_in = opener.open(
            Request(
                base + "/admin/setup",
                data=urlencode(
                    {
                        "csrf": csrf,
                        "setup_code": setup_code,
                        "password": "long-test-password",
                        "confirm": "long-test-password",
                    }
                ).encode(),
            )
        ).read().decode()
        csrf = re.search(r'name="csrf" value="([^"]+)"', signed_in).group(1)
        opener.open(
            Request(
                base + "/admin/login",
                data=urlencode({"csrf": csrf, "password": "long-test-password"}).encode(),
            )
        )
        dashboard = opener.open(base + "/").read().decode()
        return opener, re.search(r'name="csrf" value="([^"]+)"', dashboard).group(1)

    def test_signed_in_delete_requests_are_queued_for_the_collector(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            run_dir = root / "data" / "targets" / "fw-a" / "incidents" / "run-1"
            run_dir.mkdir(parents=True)
            (run_dir / "incident.jsonl").write_text('{"event":"x"}\n', encoding="utf-8")
            server, thread, setup_code = self._server(root)
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                opener, csrf = self._sign_in(base, setup_code)
                opener.open(
                    Request(
                        base + "/runs/delete",
                        data=urlencode(
                            {"csrf": csrf, "target": "fw-a", "run_id": "run-1"}
                        ).encode(),
                    )
                )
                opener.open(
                    Request(
                        base + "/runs/delete-all",
                        data=urlencode({"csrf": csrf}).encode(),
                    )
                )

                store = ConfigStore(root / "config" / "config.db")
                queued = {
                    (item.target, item.run_id) for item in store.pending_run_deletions()
                }
                self.assertEqual(
                    queued, {("fw-a", "run-1"), (ALL_RUNS, ALL_RUNS)}
                )
                # The Web UI mounts the volume read-only: nothing is removed here.
                self.assertTrue((run_dir / "incident.jsonl").is_file())
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_a_wrong_token_or_no_session_queues_nothing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            run_dir = root / "data" / "targets" / "fw-a" / "incidents" / "run-1"
            run_dir.mkdir(parents=True)
            (run_dir / "incident.jsonl").write_text('{"event":"x"}\n', encoding="utf-8")
            server, thread, setup_code = self._server(root)
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                anonymous = build_opener(_NoRedirect())
                with self.assertRaises(HTTPError) as context:
                    anonymous.open(
                        Request(
                            base + "/runs/delete-all",
                            data=urlencode({"csrf": "guessed"}).encode(),
                        )
                    )
                self.assertEqual(context.exception.code, 303)
                self.assertEqual(context.exception.headers["Location"], "/admin")

                opener, _ = self._sign_in(base, setup_code)
                with self.assertRaises(HTTPError) as context:
                    opener.open(
                        Request(
                            base + "/runs/delete",
                            data=urlencode(
                                {"csrf": "wrong", "target": "fw-a", "run_id": "run-1"}
                            ).encode(),
                        )
                    )
                self.assertEqual(context.exception.code, 403)

                with self.assertRaises(HTTPError) as context:
                    opener.open(
                        Request(
                            base + "/runs/delete",
                            data=urlencode(
                                {"csrf": _dashboard_token(opener, base), "target": "fw-a", "run_id": "../etc"}
                            ).encode(),
                        )
                    )
                self.assertEqual(context.exception.code, 400)

                store = ConfigStore(root / "config" / "config.db")
                self.assertEqual(store.pending_run_deletions(), [])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


def _dashboard_token(opener, base: str) -> str:
    page = opener.open(base + "/").read().decode()
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


class SupportEvidenceArchiveTests(unittest.TestCase):
    """An archive must explain the deployment, not only the firewall."""

    def _deployment(self, root: Path) -> Path:
        check = root / "targets" / "fw-a" / "api-checks" / "20260830T080000Z"
        (check / "raw").mkdir(parents=True)
        (check / "api-check.jsonl").write_text(
            json.dumps(
                {
                    "timestamp": "2026-08-30T08:00:00+00:00",
                    "event": "monitor_started",
                    "mode": "api_check",
                    "commands": {
                        "system_info": {
                            "ok": False,
                            "error": "PanOSAPIError: Invalid credential",
                        }
                    },
                }
            )
            + "\n"
            + json.dumps(
                {
                    "timestamp": "2026-08-30T08:00:05+00:00",
                    "event": "monitor_stopped",
                    "reason": "api_check_complete",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (check / "raw" / "batch-0001.txt").write_text(
            "=== COMMAND: system_info ===\nStatus: FAILED\n", encoding="utf-8"
        )
        (root / "syslog-received.jsonl").write_text(
            json.dumps(
                {
                    "timestamp": "2026-08-30T08:00:01+00:00",
                    "target_names": [],
                    "suppressed": "device_serial_not_registered",
                    "metadata": {"syslog_source_ip": "192.0.2.10"},
                }
            )
            + "\n"
            + json.dumps(
                {
                    "timestamp": "2026-08-30T08:00:02+00:00",
                    "target_names": ["fw-b"],
                    "message": "belongs to another firewall",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return check

    def test_api_check_run_is_exported_like_an_incident(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            check = self._deployment(data)
            located = _run_root(data, "fw-a", "20260830T080000Z")
            self.assertIsNotNone(located)
            self.assertEqual(located[0], check.resolve())
            self.assertEqual(located[1], "api-check.jsonl")

            buffer = io.BytesIO()
            write_run_archive(
                buffer, check, target="fw-a", run_id="20260830T080000Z"
            )
            buffer.seek(0)
            with zipfile.ZipFile(buffer) as archive:
                prefix = "pbp-run-fw-a-20260830T080000Z/"
                names = archive.namelist()
                self.assertIn(prefix + "api-check.jsonl", names)
                self.assertIn(prefix + "raw/batch-0001.txt", names)
                self.assertIn(
                    "Invalid credential",
                    archive.read(prefix + "api-check.jsonl").decode(),
                )

    def test_a_run_lookup_cannot_escape_the_capture_directory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            self._deployment(data)
            self.assertIsNone(_run_root(data, "..", "20260830T080000Z"))
            self.assertIsNone(_run_root(data, "fw-a", ".."))
            self.assertIsNone(_run_root(data, "fw-a", "absent-run"))
            self.assertIsNone(_run_root(data, "absent-firewall", "20260830T080000Z"))

    def test_archive_carries_the_environment_and_the_redacted_configuration(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            data = root / "data"
            data.mkdir()
            check = self._deployment(data)
            store = ConfigStore(root / "config.db")
            store.initialize()
            store.save_target(
                name="fw-a",
                panos_url="https://192.0.2.10",
                api_key="super-secret-api-key",
                target_serial=None,
                serials=["001122334455"],
                syslog_sources=["192.0.2.10"],
            )
            buffer = io.BytesIO()
            write_run_archive(
                buffer,
                check,
                target="fw-a",
                run_id="20260830T080000Z",
                config_store=store,
            )
            buffer.seek(0)
            with zipfile.ZipFile(buffer) as archive:
                prefix = "pbp-run-fw-a-20260830T080000Z/"
                environment = json.loads(
                    archive.read(prefix + "support/environment.json")
                )
                configuration = json.loads(
                    archive.read(prefix + "support/configuration.json")
                )
                blob = b"".join(archive.read(name) for name in archive.namelist())
                manifest = json.loads(archive.read(prefix + "manifest.json"))
            self.assertEqual(environment["application_version"], __version__)
            self.assertEqual(configuration["targets"][0]["mode"], "direct")
            self.assertNotIn(b"super-secret-api-key", blob)
            self.assertIn(
                "support/environment.json",
                {entry["path"] for entry in manifest["files"]},
            )

    def test_an_anonymized_run_archive_names_no_address_or_firewall(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            data = root / "data"
            data.mkdir()
            check = self._deployment(data)
            store = ConfigStore(root / "config.db")
            store.initialize()
            store.save_target(
                name="paris-edge",
                panos_url="https://192.0.2.10",
                api_key="key",
                target_serial=None,
                serials=["001122334455"],
                syslog_sources=["192.0.2.10"],
            )
            anonymizer = diagnostics.build_anonymizer(store)
            buffer = io.BytesIO()
            write_run_archive(
                buffer,
                check,
                target="paris-edge",
                run_id="20260830T080000Z",
                config_store=store,
                anonymizer=anonymizer,
            )
            buffer.seek(0)
            with zipfile.ZipFile(buffer) as archive:
                names = archive.namelist()
                blob = b"".join(archive.read(name) for name in names)
                manifest = json.loads(
                    archive.read(next(n for n in names if n.endswith("manifest.json")))
                )
            self.assertTrue(manifest["anonymized"])
            for original in anonymizer.mapping:
                self.assertNotIn(original.encode(), blob)
            # The firewall name is part of the archive prefix as well.
            self.assertFalse(any("paris-edge" in name for name in names))
            # The manifest digest must describe what the archive actually holds.
            entry = next(
                item for item in manifest["files"] if item["path"] == "api-check.jsonl"
            )
            with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as archive:
                stored = archive.read(
                    next(n for n in names if n.endswith("api-check.jsonl"))
                )
            self.assertEqual(entry["sha256"], hashlib.sha256(stored).hexdigest())

    def test_refused_syslog_message_is_kept_in_the_run_export(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            check = self._deployment(data)
            buffer = io.BytesIO()
            write_run_archive(
                buffer, check, target="fw-a", run_id="20260830T080000Z"
            )
            buffer.seek(0)
            with zipfile.ZipFile(buffer) as archive:
                received = archive.read(
                    "pbp-run-fw-a-20260830T080000Z/support/syslog-received.jsonl"
                ).decode()
            # The refusal is the evidence behind "nothing ever triggered"; a
            # message belonging to another firewall still must not leak here.
            self.assertIn("device_serial_not_registered", received)
            self.assertNotIn("belongs to another firewall", received)


if __name__ == "__main__":
    unittest.main()
