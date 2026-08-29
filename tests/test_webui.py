import hashlib
import io
import json
import tempfile
import threading
import unittest
import zipfile
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, build_opener

from pbp_monitoring.webui import (
    _artifact_path,
    _https_redirect_location,
    collect_dashboard_state,
    collect_text_exports,
    render_dashboard,
    render_text_export_index,
    redirect_handler_factory,
    write_run_archive,
)
from pbp_monitoring.config_store import ConfigStore


class WebUITests(unittest.TestCase):
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
        thread = threading.Thread(target=server.serve_forever, daemon=True)
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

    def test_dashboard_has_global_and_per_firewall_reception_state(self):
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
            self.assertIn("fw-a: receiving logs", rendered)
            self.assertIn("fw-b: logs missing or stale", rendered)

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
                {"event": "monitor_stopped", "timestamp": "2026-08-28T12:00:02+00:00", "reason": "resources_recovered", "cycles": 1},
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
            self.assertIn("HTML report", rendered)
            self.assertIn("Start time (UTC)", rendered)
            self.assertIn("2026-08-28T12:00:01+00:00", rendered)
            self.assertLess(
                rendered.index("20 most recent received logs"),
                rendered.index("Recent runs"),
            )
            self.assertIn("TXT (1)", rendered)
            self.assertIn("ZIP support", rendered)
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
                self.assertEqual(manifest["application_version"], "0.5.0")
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
