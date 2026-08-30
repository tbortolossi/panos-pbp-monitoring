import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from pbp_monitoring import __version__
from pbp_monitoring.reporting import generate_html_report, main


class ReportingTests(unittest.TestCase):
    def _write_records(self, path: Path, records: list[dict]) -> bytes:
        content = "".join(
            json.dumps(record, ensure_ascii=False) + "\n" for record in records
        ).encode("utf-8")
        path.write_bytes(content)
        return content

    def test_report_contains_summary_timeline_raw_data_and_hash(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "pbp-monitor-test.jsonl"
            malicious = '<script>alert("x")</script>&'
            source_bytes = self._write_records(
                capture,
                [
                    {
                        "timestamp": "2026-08-27T10:00:00+00:00",
                        "collector_version": "0.2.0",
                        "run_id": "run<&>",
                        "target_name": "ha-a<&>",
                        "elapsed_seconds": 0.25,
                        "percentages": {
                            "packet_buffer_congestion": [41, 72],
                            "descriptor_atomic": [92],
                            "descriptor_total": [93],
                        },
                        "resource_monitor_cpu_cores": [
                            {"dataplane": "dp0", "core_id": 0, "utilization": 4},
                            {"dataplane": "dp0", "core_id": 1, "utilization": 100},
                        ],
                        "candidate_session_ids": [38492],
                        "candidate_entities": [
                            {
                                "rank": 1,
                                "entity_type": "session",
                                "session_id": 38492,
                                "drop_state": True,
                                "pbp_percentage_total": 72,
                                "pbp_samples": 4088,
                                "ingress_percentage_max": 92,
                                "ingress_count": 3640,
                                "evidence_sources": [
                                    "packet_buffer_protection",
                                    "ingress_backlogs",
                                ],
                                "zones": ["trust"],
                                "group_ids": ["flow_slowpath"],
                            }
                        ],
                        "session_summaries": {
                            "38492": {
                                "status": "parsed",
                                "application": "ssl<&>",
                                "rule": "allow-web",
                                "c2s": {
                                    "source_ip": "192.0.2.10",
                                    "source_port": 52648,
                                    "destination_ip": "198.51.100.20",
                                    "destination_port": 443,
                                    "protocol": 6,
                                },
                            }
                        },
                        "session_details": {"38492": malicious},
                        "commands": {
                            "packet_buffer_protection": "<result>PBP & raw</result>",
                            "clock": {
                                "result": "Thu Aug 27 10:00:00 UTC 2026",
                                "raw_response": "<response><result>clock raw</result></response>",
                                "error": None,
                            },
                        },
                    },
                    {
                        "timestamp": "2026-08-27T10:00:05+00:00",
                        "run_id": "run<&>",
                        "elapsed_seconds": 5,
                        "parse_warnings": ["unexpected format <parser>"],
                        "recovery_sample_eligible": False,
                        "percentages": {
                            "packet_buffer_congestion": [38],
                            "descriptor_atomic": [40],
                            "descriptor_total": [42],
                            "resource_monitor_packet_descriptor_on_chip": [87.5],
                        },
                        "resource_monitor_cpu_cores": [
                            {"dataplane": "dp0", "core_id": 0, "utilization": 5},
                            {"dataplane": "dp0", "core_id": 1, "utilization": 20},
                        ],
                        "candidate_session_ids": [38492, "5<6"],
                        "session_rates": {
                            "38492": {
                                "status": "calculated",
                                "bits_per_second_total": 8_000_000,
                            }
                        },
                        "session_details": {
                            "5<6": {"error": "ERROR: disappeared", "result": None}
                        },
                        "commands": {
                            "ingress_backlogs": {
                                "ok": False,
                                "raw_response": "RAW<&>",
                                "result": {"usage": 42},
                                "error": "",
                            }
                        },
                    },
                    {
                        "timestamp": "2026-08-27T10:00:05.5+00:00",
                        "run_id": "run<&>",
                        "event": "trigger_received",
                        "message": "PBP Packet Drop <unsafe>",
                    },
                    {
                        "timestamp": "2026-08-27T10:00:06+00:00",
                        "run_id": "run<&>",
                        "event": "monitor_stopped",
                        "reason": "resources_recovered",
                        "elapsed_seconds": 6.5,
                    },
                ],
            )

            with patch.dict(os.environ, {"PANOS_API_KEY": "must-not-leak"}):
                report = generate_html_report(capture)

            self.assertEqual(report, capture.with_suffix(".html"))
            self.assertEqual(capture.read_bytes(), source_bytes)
            rendered = report.read_text(encoding="utf-8")

            self.assertIn("Summary", rendered)
            self.assertIn("Collector version", rendered)
            self.assertIn(f"PBP Monitoring v{__version__}", rendered)
            self.assertIn("ha-a&lt;&amp;&gt;", rendered)
            self.assertIn("Timeline", rendered)
            self.assertIn('class="table-wrap timeline-wrap"', rendered)
            self.assertIn('class="timeline"', rendered)
            self.assertIn("Offender attribution", rendered)
            self.assertIn("Dataplane CPU core tracking", rendered)
            self.assertIn("Per-core summary", rendered)
            self.assertIn("CPU imbalance timeline", rendered)
            self.assertIn("dp0/core 1", rendered)
            self.assertIn("Imbalance signal", rendered)
            self.assertIn("High", rendered)
            self.assertIn("Peak Mbit/s", rendered)
            self.assertIn(">8</td>", rendered)
            self.assertIn("Batch details", rendered)
            self.assertIn("PBP congestion", rendered)
            self.assertIn("92%", rendered)
            self.assertIn("Resource monitor descriptor on-chip", rendered)
            self.assertIn("87.5%", rendered)
            self.assertIn("Thu Aug 27 10:00:00 UTC 2026", rendered)
            self.assertIn("packet_buffer_protection", rendered)
            self.assertIn("Exact raw API response", rendered)
            self.assertIn("RAW&lt;&amp;&gt;", rendered)
            self.assertIn(
                "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;", rendered
            )
            self.assertNotIn("<script>", rendered.lower())
            self.assertNotIn("must-not-leak", rendered)
            self.assertIn(hashlib.sha256(source_bytes).hexdigest(), rendered)
            self.assertIn("resources_recovered", rendered)
            self.assertIn("6.5 s", rendered)
            self.assertIn("parse_warnings", rendered)
            self.assertIn("unexpected format &lt;parser&gt;", rendered)
            self.assertIn("Content-Security-Policy", rendered)
            self.assertIn("Primary PBP", rendered)
            self.assertIn("flow_slowpath", rendered)
            self.assertIn("192.0.2.10:52648 -&gt; 198.51.100.20:443", rendered)
            self.assertIn("ssl&lt;&amp;&gt;", rendered)
            self.assertIn("Correlated triggers", rendered)
            self.assertIn("PBP Packet Drop &lt;unsafe&gt;", rendered)
            self.assertIn("Capture overview", rendered)
            self.assertIn("Incident state", rendered)
            self.assertIn("Peak resource utilization", rendered)
            self.assertIn("Packet buffers", rendered)
            self.assertIn("Packet descriptors", rendered)
            self.assertIn("System load", rendered)
            self.assertIn('class="card metric-card"', rendered)
            self.assertIn('<details class="section-disclosure">', rendered)
            self.assertNotIn('<details class="section-disclosure" open>', rendered)
            self.assertNotIn("http://", rendered)
            self.assertNotIn("https://", rendered)

            leftovers = list(Path(temporary_directory).glob(".*.tmp"))
            self.assertEqual(leftovers, [])
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)

    def test_top_sources_pressure_curve_and_probable_cause_are_rendered(self):
        def cycle(number: int) -> dict:
            return {
                "timestamp": f"2026-08-29T10:0{number}:00+00:00",
                "run_id": "fixture-run",
                "cycle": number,
                "elapsed_seconds": float(number),
                "percentages": {
                    "packet_buffer_congestion": [60 + number],
                    "resource_monitor_session": [30],
                },
                "candidate_entities": [
                    {
                        "entity_type": "session",
                        "session_id": 101,
                        "drop_state": True,
                        "pbp_percentage_total": 41.0,
                        "rank": 1,
                        "evidence_sources": ["packet_buffer_protection"],
                        "zones": ["outside"],
                    },
                    {
                        "entity_type": "session",
                        "session_id": 102,
                        "pbp_percentage_total": 12.0,
                        "rank": 2,
                        "evidence_sources": ["packet_buffer_protection"],
                        "zones": ["outside"],
                    },
                ],
                "session_summaries": {
                    "101": {
                        "status": "parsed",
                        "application": "quic",
                        "rule": "allow-out",
                        "c2s": {
                            "source_ip": "203.0.113.7",
                            "destination_ip": "198.51.100.20",
                            "source_port": 1111,
                            "destination_port": 443,
                            "protocol": 17,
                        },
                    },
                    "102": {
                        "status": "parsed",
                        "application": "quic",
                        "rule": "allow-out",
                        "c2s": {
                            "source_ip": "203.0.113.7",
                            "destination_ip": "198.51.100.21",
                            "source_port": 2222,
                            "destination_port": 443,
                            "protocol": 17,
                        },
                    },
                },
                "session_rates": {
                    "101": {"status": "derived", "bits_per_second_total": 8_000_000},
                    "102": {"status": "derived", "bits_per_second_total": 4_000_000},
                },
            }

        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "incident.jsonl"
            self._write_records(capture, [cycle(1), cycle(2)])

            rendered = generate_html_report(capture).read_text(encoding="utf-8")

            self.assertIn("Top sources", rendered)
            self.assertIn("<code>203.0.113.7</code></td><td>2</td>", rendered)
            self.assertIn("Probable cause", rendered)
            self.assertIn(
                "The strongest evidence points to session <code>101</code>",
                rendered,
            )
            self.assertIn("Pressure over time", rendered)
            self.assertIn("Packet buffer</span>", rendered)
            self.assertIn(
                "Buffer, descriptor, and session-table utilization per batch",
                rendered,
            )

    def test_flood_corroboration_is_stated_in_the_probable_cause(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "incident.jsonl"
            self._write_records(
                capture,
                [
                    {
                        "timestamp": "2026-08-29T10:00:00+00:00",
                        "run_id": "fixture-run",
                        "cycle": 1,
                        "elapsed_seconds": 1.0,
                        "percentages": {"packet_buffer_congestion": [62]},
                    },
                    {
                        "timestamp": "2026-08-29T10:00:30+00:00",
                        "run_id": "fixture-run",
                        "event": "flood_corroboration",
                        "metadata": {"destination_ip": "198.51.100.15"},
                    },
                ],
            )

            rendered = generate_html_report(capture).read_text(encoding="utf-8")

            self.assertIn("flood log(s) corroborated the incident", rendered)
            self.assertIn("targeting 198.51.100.15", rendered)

    def test_offender_live_sessions_render_their_flows(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "incident.jsonl"
            self._write_records(
                capture,
                [
                    {
                        "timestamp": "2026-08-29T10:00:00+00:00",
                        "run_id": "fixture-run",
                        "cycle": 1,
                        "elapsed_seconds": 1.0,
                        "percentages": {"packet_buffer_congestion": [62]},
                    },
                    {
                        "timestamp": "2026-08-29T10:01:00+00:00",
                        "run_id": "fixture-run",
                        "event": "offender_live_sessions",
                        "sources": [
                            {
                                "source_ip": "203.0.113.7",
                                "ok": True,
                                "session_count": 2,
                                "entries": [
                                    {
                                        "destination_ip": "198.51.100.20",
                                        "destination_port": "443",
                                        "protocol": "17",
                                        "application": "quic<&>",
                                        "from_zone": "outside",
                                        "to_zone": "inside",
                                        "start_time": "Sat Aug 29 23:15:12 2026",
                                    }
                                ],
                            }
                        ],
                    },
                ],
            )

            rendered = generate_html_report(capture).read_text(encoding="utf-8")

            self.assertIn("Live sessions of top sources", rendered)
            self.assertIn("198.51.100.20", rendered)
            self.assertIn("quic&lt;&amp;&gt;", rendered)
            self.assertNotIn("quic<&>", rendered)

    def test_offender_traffic_logs_render_their_recovered_flows(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "incident.jsonl"
            self._write_records(
                capture,
                [
                    {
                        "timestamp": "2026-08-29T10:00:00+00:00",
                        "run_id": "fixture-run",
                        "cycle": 1,
                        "elapsed_seconds": 1.0,
                        "percentages": {"packet_buffer_congestion": [62]},
                    },
                    {
                        "timestamp": "2026-08-29T10:01:00+00:00",
                        "run_id": "fixture-run",
                        "event": "offender_traffic_logs",
                        "sources": [
                            {
                                "source_ip": "203.0.113.7",
                                "ok": True,
                                "entries": [
                                    {
                                        "receive_time": "2026/08/29 10:00:05",
                                        "source_ip": "203.0.113.7",
                                        "destination_ip": "198.51.100.15",
                                        "destination_port": "443",
                                        "protocol": "udp",
                                        "application": "not-applicable",
                                        "rule": "deny-flood<&>",
                                        "action": "deny",
                                        "from_zone": "outside",
                                        "to_zone": "inside",
                                    }
                                ],
                            },
                            {
                                "source_ip": "203.0.113.8",
                                "ok": False,
                                "error": "log job 272 did not finish within 20s",
                            },
                        ],
                    },
                ],
            )

            report = generate_html_report(capture)
            rendered = report.read_text(encoding="utf-8")

            self.assertIn("Traffic log evidence for unenriched sources", rendered)
            self.assertIn("198.51.100.15", rendered)
            self.assertIn("deny-flood&lt;&amp;&gt;", rendered)
            self.assertIn("did not finish within 20s", rendered)
            self.assertNotIn("deny-flood<&>", rendered)

    def test_invalid_truncated_and_non_object_lines_are_warnings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "partial.jsonl"
            capture.write_bytes(
                b'{"timestamp":"2026-08-27T10:00:00Z","commands":"ERROR: legacy <raw>"}\n'
                b'{not-json}\n'
                b'[]\n'
                b'{"timestamp":'
            )

            report = generate_html_report(capture)
            rendered = report.read_text(encoding="utf-8")

            self.assertIn("ERROR: legacy &lt;raw&gt;", rendered)
            self.assertIn("Line 2 ignored", rendered)
            self.assertIn("Line 3 ignored", rendered)
            self.assertIn("Line 4 ignored", rendered)
            self.assertIn("invalid or truncated JSON", rendered)
            self.assertIn("Partial errors", rendered)

    def test_successful_command_does_not_render_empty_error_field(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "success.jsonl"
            self._write_records(
                capture,
                [
                    {
                        "timestamp": "2026-08-27T10:00:00+00:00",
                        "commands": {
                            "clock": {
                                "ok": True,
                            "result": "clock output",
                            "raw_response": "<response/>",
                            "error": None,
                            "started_at": "2026-08-27T10:00:00.123456+00:00",
                            "finished_at": "2026-08-27T10:00:01.456789+00:00",
                            "duration_seconds": 1.333333,
                            }
                        },
                    }
                ],
            )

            rendered = generate_html_report(capture).read_text(encoding="utf-8")

            self.assertNotIn('class="payload-label">Error</h5>', rendered)
            self.assertIn("clock output", rendered)
            self.assertIn('<dl class="command-metadata">', rendered)
            self.assertIn("Success", rendered)
            self.assertIn("2026-08-27 10:00:00.123 UTC", rendered)
            self.assertIn("1.33 s", rendered)
            self.assertNotIn('class="payload-label">Ok</h5>', rendered)
            self.assertNotIn(">true</pre>", rendered)
            self.assertIn('<details class="exact-response">', rendered)
            self.assertIn("<summary>Exact raw API response</summary>", rendered)
            self.assertNotIn('<details class="exact-response" open>', rendered)
            self.assertLess(
                rendered.index("clock output"),
                rendered.index("Exact raw API response"),
            )

    def test_bom_after_a_blank_line_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "bom.jsonl"
            capture.write_bytes(
                b"\n\xef\xbb\xbf"
                b'{"timestamp":"2026-08-27T10:00:00Z","commands":"valid raw"}\n'
            )

            rendered = generate_html_report(capture).read_text(encoding="utf-8")

            self.assertIn("valid raw", rendered)
            self.assertNotIn("Line 2 ignored", rendered)

    def test_future_top_level_structured_command_is_supported(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "future.jsonl"
            self._write_records(
                capture,
                [
                    {
                        "timestamp": "2026-08-27T10:00:00Z",
                        "commands": {
                            "raw_response": "<response>whole</response>",
                            "result": "parsed result",
                            "error": "timeout <unsafe>",
                        },
                        "session_details": "legacy session detail",
                    }
                ],
            )

            rendered = generate_html_report(capture).read_text(encoding="utf-8")

            self.assertIn("parsed result", rendered)
            self.assertIn("&lt;response&gt;whole&lt;/response&gt;", rendered)
            self.assertIn("timeout &lt;unsafe&gt;", rendered)
            self.assertIn("legacy session detail", rendered)

    def test_custom_output_and_cli(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "capture.jsonl"
            output = Path(temporary_directory) / "reports" / "report.html"
            self._write_records(capture, [{"commands": {"clock": "now"}}])

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = main([str(capture), "--output", str(output)])

            self.assertEqual(result, 0)
            self.assertTrue(output.is_file())
            self.assertIn(str(output), stdout.getvalue())

    def test_destination_must_not_overwrite_source(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "capture.jsonl"
            original = self._write_records(capture, [{"commands": "raw"}])

            with self.assertRaises(ValueError):
                generate_html_report(capture, capture)

            self.assertEqual(capture.read_bytes(), original)

    def test_failed_atomic_replace_preserves_existing_report(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "capture.jsonl"
            report = capture.with_suffix(".html")
            self._write_records(capture, [{"commands": "new raw"}])
            report.write_text("existing report", encoding="utf-8")

            with patch(
                "pbp_monitoring.reporting.os.replace",
                side_effect=OSError("replace failed"),
            ):
                with self.assertRaises(OSError):
                    generate_html_report(capture)

            self.assertEqual(report.read_text(encoding="utf-8"), "existing report")
            self.assertEqual(list(Path(temporary_directory).glob(".*.tmp")), [])



class CpuChartTests(unittest.TestCase):
    """The charts must answer one question: did every core rise, or just one?"""

    FUNCTIONS = [
        {
            "dataplane": "dp0",
            "core_id": "0",
            "functions": ["pan_timer"],
            "forwards_traffic": False,
        },
        {
            "dataplane": "dp0",
            "core_id": "1",
            "functions": ["flow_lookup", "flow_fastpath", "flow_mgmt"],
            "forwards_traffic": True,
        },
        {
            "dataplane": "dp0",
            "core_id": "2",
            "functions": ["flow_lookup", "flow_fastpath", "flow_ctrl"],
            "forwards_traffic": True,
        },
        {
            "dataplane": "dp0",
            "core_id": "3",
            "functions": ["flow_lookup", "flow_fastpath"],
            "forwards_traffic": True,
        },
        {
            "dataplane": "dp1",
            "core_id": "1",
            "functions": ["flow_lookup", "flow_fastpath"],
            "forwards_traffic": True,
        },
        {
            "dataplane": "dp1",
            "core_id": "2",
            "functions": ["flow_lookup", "flow_fastpath"],
            "forwards_traffic": True,
        },
        {
            "dataplane": "dp1",
            "core_id": "3",
            "functions": ["flow_lookup", "flow_fastpath"],
            "forwards_traffic": True,
        },
    ]

    def _core(self, dataplane: str, core_id: str, value: float) -> dict:
        return {
            "dataplane": dataplane,
            "core_id": core_id,
            "utilization": value,
            "average": value,
            "maximum": value,
            "window_average": value,
            "window_peak": value,
            "seconds_at_or_above_90": 1 if value >= 90 else 0,
            "sample_count": 5,
        }

    def _render(self, loads: dict[str, dict[str, float]], functions: list | None) -> str:
        startup = {
            "timestamp": "2026-08-27T10:00:00+00:00",
            "run_id": "chart-run",
            "event": "monitor_started",
            "collector_version": "test",
            "device": {"serial": "fixture", "model": "PA-fixture"},
            "identity_complete": True,
        }
        if functions is not None:
            startup["dp_core_functions"] = functions
        records = [startup]
        for batch in range(1, 5):
            cores = [
                self._core(dataplane, core_id, value)
                for dataplane, per_core in loads.items()
                for core_id, value in per_core.items()
            ]
            records.append(
                {
                    "timestamp": f"2026-08-27T10:0{batch}:00+00:00",
                    "run_id": "chart-run",
                    "cycle": batch,
                    "elapsed_seconds": float(batch),
                    "percentages": {"packet_buffer_congestion": [50]},
                    "resource_monitor_cpu_cores": cores,
                    "commands": {},
                }
            )
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "chart.jsonl"
            capture.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            report = generate_html_report(capture, capture.with_suffix(".html"))
            return report.read_text(encoding="utf-8")

    def test_one_saturated_core_is_reported_as_flow_hash_concentration(self):
        html = self._render(
            {"dp0": {"0": 0.0, "1": 12.0, "2": 12.0, "3": 98.0}},
            self.FUNCTIONS,
        )

        self.assertIn("verdict-isolated", html)
        self.assertIn("An isolated hot core is what flow-hash concentration looks like", html)
        self.assertIn("core 3 · fastpath only", html)

    def test_every_core_rising_together_is_not_blamed_on_one_session(self):
        html = self._render(
            {"dp1": {"1": 79.0, "2": 81.0, "3": 80.0}},
            self.FUNCTIONS,
        )

        self.assertIn("verdict-collective", html)
        self.assertIn("aggregate load rather than one session pinned to a core", html)
        self.assertNotIn("An isolated hot core", html)

    def test_each_dataplane_is_charted_separately(self):
        html = self._render(
            {
                "dp0": {"0": 0.0, "1": 12.0, "2": 12.0, "3": 98.0},
                "dp1": {"1": 79.0, "2": 81.0, "3": 80.0},
            },
            self.FUNCTIONS,
        )

        self.assertEqual(html.count('<svg class="chart"'), 4)
        self.assertIn("An isolated hot core", html)
        self.assertIn("aggregate load rather than one session", html)
        self.assertNotIn("<script", html.lower())

    def test_cores_are_labelled_and_non_forwarding_cores_are_not_compared(self):
        html = self._render(
            {"dp0": {"0": 0.0, "1": 12.0, "2": 12.0, "3": 98.0}},
            self.FUNCTIONS,
        )

        self.assertIn("core 0 · pan_timer", html)
        self.assertIn("core 1 · flow_mgmt", html)
        self.assertIn("core 2 · flow_ctrl", html)
        self.assertIn("4 cores, 3 forwarding traffic", html)

    def test_charts_still_render_when_function_groups_are_missing(self):
        html = self._render({"dp0": {"1": 12.0, "2": 12.0, "3": 98.0}}, None)

        self.assertEqual(html.count('<svg class="chart"'), 2)
        self.assertIn("function groups unavailable", html)
        self.assertIn("Core function groups were not collected", html)
        self.assertIn(">core 3<", html.replace('class="axis heat-label">', ">"))

    def test_report_symbols_are_not_double_encoded(self):
        html = self._render({"dp0": {"1": 12.0, "2": 98.0}}, self.FUNCTIONS)

        self.assertIn("Hot points \u2265 90%", html)
        self.assertIn("Max\u2013min spread", html)
        self.assertIn("high max\u2013min spread", html)
        self.assertNotIn("\u00e2", html)

    def test_charts_are_omitted_when_no_core_was_sampled(self):
        html = self._render({}, self.FUNCTIONS)

        self.assertNotIn('<svg class="chart"', html)
        self.assertIn("No per-core CPU samples were recorded.", html)


class DropCounterTests(unittest.TestCase):
    """A flood denied by policy creates no session, so the report must name it."""

    def _counter(
        self,
        name: str,
        value: int,
        rate: int,
        aspect: str,
        description: str,
        severity: str = "drop",
    ) -> dict:
        return {
            "name": name,
            "value": value,
            "rate": rate,
            "severity": severity,
            "category": "flow",
            "aspect": aspect,
            "description": description,
        }

    def _render(self, cycles: list[dict]) -> str:
        records: list[dict] = [
            {
                "timestamp": "2026-08-27T10:00:00+00:00",
                "run_id": "drop-run",
                "event": "monitor_started",
                "collector_version": "test",
                "device": {"serial": "fixture", "model": "PA-fixture"},
            }
        ]
        for batch, cycle in enumerate(cycles, 1):
            record = {
                "timestamp": f"2026-08-27T10:0{batch}:00+00:00",
                "run_id": "drop-run",
                "cycle": batch,
                "elapsed_seconds": float(batch),
                "percentages": {"packet_buffer_congestion": [61]},
                "commands": {},
            }
            record.update(cycle)
            records.append(record)
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "drops.jsonl"
            capture.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            report = generate_html_report(capture, capture.with_suffix(".html"))
            return report.read_text(encoding="utf-8")

    def test_denied_flood_without_a_session_is_attributed_to_the_source_ip(self):
        html = self._render(
            [
                {
                    "candidate_entities": [
                        {
                            "rank": 1,
                            "entity_type": "source_ip",
                            "source_ip": "192.0.2.55",
                            "drop_state": True,
                            "evidence_sources": ["packet_buffer_protection"],
                        }
                    ],
                    "global_counters_delta_status": "primed_interval",
                    "global_counters_delta": {
                        "elapsed_seconds": 5.0,
                        "counters": [
                            self._counter(
                                "flow_policy_deny",
                                418000,
                                83600,
                                "session",
                                "Session setup: denied by policy",
                            ),
                            self._counter(
                                "flow_dos_red_topology",
                                1200,
                                240,
                                "dos",
                                "Packets dropped by RED",
                            ),
                        ],
                    },
                }
            ]
        )

        self.assertIn("Denied and dropped traffic", html)
        self.assertIn("flow_policy_deny", html)
        self.assertIn("Policy deny", html)
        self.assertIn("DoS / zone protection", html)
        self.assertIn('<p class="verdict verdict-isolated">', html)
        self.assertIn("UDP or GRE flood denied by a", html)
        self.assertIn("1 source IP(s) were ranked without an enriched session", html)
        self.assertIn("Denied packets", html)
        self.assertIn(">419200<", html)

    def test_pbp_red_drops_are_not_counted_as_denied_traffic(self):
        html = self._render(
            [
                {
                    "candidate_entities": [
                        {
                            "rank": 1,
                            "entity_type": "source_ip",
                            "source_ip": "192.0.2.55",
                            "drop_state": True,
                            "evidence_sources": ["packet_buffer_protection"],
                        }
                    ],
                    "global_counters_delta_status": "primed_interval",
                    "global_counters_delta": {
                        "elapsed_seconds": 5.0,
                        "counters": [
                            self._counter(
                                "flow_dos_pbp_cnt_drop",
                                550,
                                11,
                                "dos",
                                "Packets dropped by packet buffer protection RED trigger by buffer",
                            ),
                            self._counter(
                                "flow_dos_pbp_drop",
                                550,
                                11,
                                "dos",
                                "Packets dropped by packet buffer protection RED",
                            ),
                            self._counter(
                                "flow_policy_deny",
                                71,
                                2,
                                "session",
                                "Session setup: denied by policy",
                            ),
                        ],
                    },
                }
            ]
        )

        self.assertIn("PBP RED drops", html)
        self.assertNotIn("DoS / zone protection", html)
        self.assertIn("policy deny 71, DoS or zone protection 0", html)
        self.assertIn("71 packets were dropped before session setup", html)
        self.assertNotIn("1171", html)
        self.assertIn("PBP itself discarded 1100 packets by RED", html)
        self.assertIn(
            '<span class="card-label">Denied packets</span><strong>71</strong>', html
        )

    def test_untrusted_baseline_batch_is_excluded_from_the_denied_total(self):
        untrusted = {
            "global_counters_delta_status": "baseline_untrusted",
            "global_counters_delta": {
                "counters": [
                    self._counter(
                        "flow_policy_deny",
                        900000,
                        1,
                        "session",
                        "Session setup: denied by policy",
                    )
                ]
            },
        }
        primed = {
            "global_counters_delta_status": "primed_interval",
            "global_counters_delta": {
                "counters": [
                    self._counter(
                        "flow_policy_deny",
                        7,
                        1,
                        "session",
                        "Session setup: denied by policy",
                    )
                ]
            },
        }
        html = self._render([untrusted, primed])

        self.assertIn("Counted batches: 1.", html)
        self.assertIn("1 batch(es) excluded", html)
        self.assertNotIn("900000", html.split("Batch details")[0])

    def test_informational_counters_are_not_reported_as_drops(self):
        html = self._render(
            [
                {
                    "global_counters_delta_status": "primed_interval",
                    "global_counters_delta": {
                        "counters": [
                            self._counter(
                                "flow_tcp_non_syn",
                                40,
                                8,
                                "session",
                                "Non SYN TCP packets without session match",
                                severity="info",
                            ),
                            self._counter(
                                "flow_fwd_l3_mcast_drop",
                                12,
                                2,
                                "forward",
                                "Packets dropped: no route for multicast",
                            ),
                        ]
                    },
                }
            ]
        )

        self.assertNotIn("flow_tcp_non_syn", html.split("Batch details")[0])
        self.assertIn("flow_fwd_l3_mcast_drop", html)
        self.assertIn("Forwarding", html)
        self.assertIn('<p class="verdict verdict-collective">', html)
        self.assertIn("No packet was denied by a Security policy rule", html)

    def test_capture_without_counters_states_it_instead_of_an_empty_table(self):
        html = self._render([{"commands": {}}])

        self.assertIn("No drop counter was recorded in this capture.", html)
        self.assertNotIn('<p class="verdict', html)


class SessionTableTests(unittest.TestCase):
    """show session info tells whether the flood created sessions at all."""

    def _session_info(self, **values) -> dict:
        totals = {
            "supported": 200000,
            "allocated": values.get("allocated"),
            "tcp": values.get("tcp"),
            "udp": values.get("udp"),
            "icmp": 0,
            "created_since_bootup": values.get("created"),
            "connection_rate_cps": values.get("cps"),
            "packet_rate_pps": values.get("pps"),
            "throughput_kbps": values.get("kbps"),
            "utilization_percentage": round(
                values.get("allocated", 0) * 100 / 200000, 2
            ),
        }
        return {"dataplanes": [{"dp": "*.dp0", **totals}], "totals": totals}

    def _render(self, cycles: list[dict]) -> str:
        records: list[dict] = [
            {
                "timestamp": "2026-08-27T10:00:00+00:00",
                "run_id": "session-run",
                "event": "monitor_started",
                "collector_version": "test",
                "device": {"serial": "fixture", "model": "PA-fixture"},
            }
        ]
        for batch, cycle in enumerate(cycles, 1):
            record = {
                "timestamp": f"2026-08-27T10:0{batch}:00+00:00",
                "run_id": "session-run",
                "cycle": batch,
                "elapsed_seconds": float(batch),
                "percentages": {"packet_buffer_congestion": [61]},
                "commands": {},
            }
            record.update(cycle)
            records.append(record)
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "sessions.jsonl"
            capture.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            report = generate_html_report(capture, capture.with_suffix(".html"))
            return report.read_text(encoding="utf-8")

    def test_session_counters_and_rates_are_reported_for_every_batch(self):
        html = self._render(
            [
                {
                    "session_info": self._session_info(
                        allocated=421,
                        tcp=206,
                        udp=215,
                        created=1254101,
                        cps=4,
                        pps=160,
                        kbps=623,
                    )
                },
                {
                    "session_info": self._session_info(
                        allocated=460,
                        tcp=210,
                        udp=250,
                        created=1254301,
                        cps=9,
                        pps=310,
                        kbps=940,
                    )
                },
            ]
        )

        self.assertIn("Session table", html)
        self.assertIn("Peak allocated sessions", html)
        self.assertIn(">460 / 200000<", html)
        self.assertIn("Peak new connections", html)
        self.assertIn("Peak packet rate", html)
        self.assertIn("Peak throughput", html)
        # Sessions created between the first and the last batch.
        self.assertIn("Sessions created", html)
        self.assertIn(">200<", html)
        self.assertIn(">623<", html)

    def test_a_flood_without_new_sessions_is_named_in_the_verdict(self):
        html = self._render(
            [
                {
                    "session_info": self._session_info(
                        allocated=420, tcp=205, udp=215, created=1000, cps=4, pps=150,
                        kbps=600,
                    )
                },
                {
                    "session_info": self._session_info(
                        allocated=424, tcp=205, udp=219, created=1020, cps=5, pps=9000,
                        kbps=800,
                    )
                },
            ]
        )

        self.assertIn("Packets arrived without sessions being created", html)

    def test_a_saturated_session_table_is_reported_as_a_constraint(self):
        html = self._render(
            [
                {
                    "session_info": self._session_info(
                        allocated=180000, tcp=90000, udp=90000, created=10,
                        cps=900, pps=90000, kbps=800000,
                    )
                }
            ]
        )

        self.assertIn("accelerates session aging", html)

    def test_capture_without_session_info_states_it_instead_of_an_empty_table(self):
        html = self._render([{"commands": {}}])

        self.assertIn("No session table snapshot was recorded in this capture.", html)


class ReadabilityTests(unittest.TestCase):
    """The report must answer the operator's first questions without scrolling."""

    def _render(self, records: list[dict]) -> str:
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "incident.jsonl"
            capture.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            report = generate_html_report(capture, capture.with_suffix(".html"))
            return report.read_text(encoding="utf-8")

    def _capture(self, peaks: list[float], triggers: int = 0) -> list[dict]:
        records: list[dict] = [
            {
                "timestamp": "2026-08-29T14:14:55.600197+00:00",
                "run_id": "glance-run",
                "event": "monitor_started",
                "device": {"model": "PA-fixture"},
            }
        ]
        for index, peak in enumerate(peaks, 1):
            records.append(
                {
                    "timestamp": f"2026-08-29T14:{15 + index:02d}:00+00:00",
                    "run_id": "glance-run",
                    "cycle": index,
                    "elapsed_seconds": 60.0 * index,
                    "percentages": {"packet_buffer_congestion": [peak]},
                    "commands": {},
                }
            )
        for number in range(triggers):
            records.append(
                {
                    "timestamp": f"2026-08-29T14:16:{30 + number:02d}+00:00",
                    "run_id": "glance-run",
                    "event": "trigger_received",
                    "message": "PBP alert",
                }
            )
        records.append(
            {
                "timestamp": "2026-08-29T14:20:00+00:00",
                "run_id": "glance-run",
                "event": "monitor_stopped",
                "reason": "maximum_duration",
            }
        )
        return records

    def test_low_pressure_is_named_below_the_alert_level(self):
        html = self._render(self._capture([4.2, 4.46, 4.3]))

        self.assertIn('<section class="glance" data-level="ok"', html)
        self.assertIn("<strong>Low pressure.</strong>", html)
        self.assertIn("peaked at 4.46%, below the 50% PBP alert level", html)
        self.assertIn("Probable cause", html)

    def test_elevated_and_critical_pressure_follow_the_pbp_thresholds(self):
        elevated = self._render(self._capture([30.0, 65.0]))
        critical = self._render(self._capture([30.0, 91.5]))

        self.assertIn('data-level="warn"', elevated)
        self.assertIn("<strong>Elevated pressure.</strong>", elevated)
        self.assertIn('<section class="glance" data-level="bad"', critical)
        self.assertIn("<strong>Critical pressure.</strong>", critical)
        self.assertIn("at or above the 80% PBP activate level", critical)

    def test_header_times_duration_and_stop_reason_are_human_readable(self):
        html = self._render(self._capture([4.0, 4.1]))

        self.assertIn("2026-08-29 14:14:55 UTC", html)
        self.assertIn("2026-08-29 14:20:00 UTC", html)
        self.assertIn("<strong>2 min 00 s</strong>", html)
        self.assertIn("Maximum duration reached", html)
        self.assertIn("maximum_duration", html)

    def test_sections_are_reachable_from_a_navigation_bar(self):
        html = self._render(self._capture([4.0, 4.1]))

        self.assertIn('<nav class="toc"', html)
        for anchor in (
            "glance-title",
            "summary-title",
            "pressure-title",
            "attribution-title",
            "drop-counters-title",
            "cpu-tracking-title",
            "timeline-title",
            "cycles-title",
            "events-title",
        ):
            self.assertIn(f'href="#{anchor}"', html)
            self.assertIn(f'id="{anchor}"', html)

    def test_pressure_axis_fits_the_data_and_marks_received_triggers(self):
        quiet = self._render(self._capture([4.0, 4.5, 4.2], triggers=2))
        loud = self._render(self._capture([30.0, 85.0]))

        self.assertIn("scaled to 10% to fit the data", quiet)
        self.assertIn("Trigger received (2)", quiet)
        self.assertIn("peak 4.5% · batch 2", quiet)
        self.assertNotIn("PBP alert 50%", quiet)
        self.assertIn("scaled to 100% to fit the data", loud)
        self.assertIn("PBP alert 50%", loud)
        self.assertIn("PBP activate 80%", loud)

    def test_metrics_never_collected_are_hidden_from_the_timeline(self):
        html = self._render(self._capture([4.0, 4.1]))

        self.assertIn("Columns never returned by the firewall are hidden", html)
        self.assertNotIn("<th>Descriptor ATOMIC %</th>", html)
        self.assertIn("<th>PBP congestion %</th>", html)
        self.assertIn("Not collected", html)

    def test_batch_summaries_show_their_buffer_reading_and_clock_time(self):
        html = self._render(self._capture([4.0, 87.0]))

        self.assertIn('data-level="ok">buffers 4%</span>', html)
        self.assertIn('data-level="bad">buffers 87%</span>', html)
        self.assertIn('title="2026-08-29T14:17:00+00:00">14:17:00</time>', html)

    def test_calm_cpu_tables_are_collapsed_but_kept(self):
        records = self._capture([4.0, 4.1])
        for record in records:
            if "cycle" in record:
                record["resource_monitor_cpu_cores"] = [
                    {"dataplane": "dp0", "core_id": 1, "utilization": 3},
                    {"dataplane": "dp0", "core_id": 2, "utilization": 2},
                ]
        html = self._render(records)

        self.assertIn('<details class="section-disclosure cpu-tables">', html)
        self.assertIn("no hot core", html)
        self.assertIn("Per-core summary", html)
        self.assertIn("CPU imbalance timeline", html)


class LargeSessionSectionTests(unittest.TestCase):
    """An elephant session must be readable even though it writes no log."""

    def _session(self, **values) -> dict:
        session = {
            "session_id": 5258,
            "source_ip": "198.51.100.20",
            "destination_ip": "203.0.113.30",
            "source_port": "44321",
            "destination_port": "443",
            "protocol": "6",
            "application": "ssl",
            "from_zone": "LAN",
            "to_zone": "INTERNET",
            "ingress_interface": "ethernet1/1",
            "egress_interface": "ethernet1/2",
            "state": "ACTIVE",
            "start_time": "Thu Aug 27 09:00:00 2026",
            "total_bytes": 4_500_000_000,
            "duration_seconds": 3600.0,
            "average_bits_per_second": 10_000_000.0,
            "rate_status": "baseline",
        }
        session.update(values)
        return session

    def _render(self, cycles: list[dict]) -> str:
        records: list[dict] = [
            {
                "timestamp": "2026-08-27T10:00:00+00:00",
                "run_id": "large-run",
                "event": "monitor_started",
                "collector_version": "test",
                "device": {"serial": "fixture", "model": "PA-fixture"},
            }
        ]
        for batch, cycle in enumerate(cycles, 1):
            record = {
                "timestamp": f"2026-08-27T10:0{batch}:00+00:00",
                "run_id": "large-run",
                "cycle": batch,
                "elapsed_seconds": float(batch),
                "percentages": {"packet_buffer_congestion": [61]},
                "commands": {},
            }
            record.update(cycle)
            records.append(record)
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "large.jsonl"
            capture.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            report = generate_html_report(capture, capture.with_suffix(".html"))
            return report.read_text(encoding="utf-8")

    def test_a_large_session_is_listed_with_its_age_volume_and_rates(self):
        html = self._render(
            [
                {
                    "large_sessions": {
                        "status": "collected",
                        "min_kb": 1048576,
                        "min_age_seconds": 600,
                        "truncated": False,
                        "session_count": 1,
                        "sessions": [self._session()],
                    }
                },
                {
                    "large_sessions": {
                        "status": "collected",
                        "min_kb": 1048576,
                        "min_age_seconds": 600,
                        "truncated": False,
                        "session_count": 1,
                        "sessions": [
                            self._session(
                                total_bytes=4_506_250_000,
                                duration_seconds=3605.0,
                                rate_status="calculated",
                                bits_per_second=10_000_000.0,
                            )
                        ],
                    }
                },
            ]
        )

        self.assertIn("Largest sessions", html)
        self.assertIn("more than 1.05 GB of cumulative traffic", html)
        self.assertIn("open for more than 10 min 00 s", html)
        self.assertIn("198.51.100.20", html)
        self.assertIn("4.51 GB", html)
        self.assertIn("1 h 00 min", html)
        # Average and peak both land on ten megabits per second.
        self.assertIn(">10<", html)

    def test_a_recycled_index_is_reported_as_a_separate_session(self):
        html = self._render(
            [
                {
                    "large_sessions": {
                        "status": "collected",
                        "min_kb": 1048576,
                        "min_age_seconds": 600,
                        "session_count": 1,
                        "sessions": [self._session()],
                    }
                },
                {
                    "large_sessions": {
                        "status": "collected",
                        "min_kb": 1048576,
                        "min_age_seconds": 600,
                        "session_count": 1,
                        "sessions": [
                            self._session(
                                start_time="Thu Aug 27 09:30:00 2026",
                                application="rsync",
                                rate_status="session_reused",
                            )
                        ],
                    }
                },
            ]
        )

        self.assertIn("ssl", html)
        self.assertIn("rsync", html)

    def test_no_matching_session_is_stated_instead_of_an_empty_table(self):
        html = self._render(
            [
                {
                    "large_sessions": {
                        "status": "collected",
                        "min_kb": 1048576,
                        "min_age_seconds": 600,
                        "session_count": 0,
                        "sessions": [],
                    }
                }
            ]
        )

        self.assertIn("no single transfer explains the buffer pressure", html)

    def test_a_disabled_collection_says_so(self):
        html = self._render(
            [
                {
                    "large_sessions": {
                        "status": "disabled",
                        "min_kb": 0,
                        "min_age_seconds": 600,
                        "session_count": 0,
                        "sessions": [],
                    }
                }
            ]
        )

        self.assertIn("Largest-session tracking is disabled", html)

    def test_an_older_capture_without_the_command_still_renders(self):
        html = self._render([{}])

        self.assertIn("predates largest-session tracking", html)


if __name__ == "__main__":
    unittest.main()
