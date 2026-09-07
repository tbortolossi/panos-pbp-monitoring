import base64
import hashlib
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from pbp_monitoring import __version__
from pbp_monitoring.diagnosis import EVIDENCE_ANCHORS, collect_findings
from pbp_monitoring.reporting import (
    REPORT_SCRIPT,
    REPORT_SCRIPT_CSP_HASH,
    _build_report_parts,
    _read_jsonl,
    generate_html_report,
)
from pbp_monitoring.reporting_v2 import (
    REPORT_V2_FILENAME,
    REPORT_V2_SCRIPT,
    REPORT_V2_SCRIPT_CSP_HASH,
    generate_html_report_v2,
    main,
)


def _drop_blocks(rendered: str, opening: str, closing: str) -> str:
    """Cut out every `opening`…`closing` span, by literal boundaries.

    The report is written by this project, so its style and script blocks are
    exact known strings. Matching them literally rather than with a tag pattern
    keeps this helper a measuring tool and not a sanitizer.
    """
    while (start := rendered.find(opening)) != -1:
        end = rendered.find(closing, start)
        if end == -1:
            return rendered[:start]
        rendered = rendered[:start] + rendered[end + len(closing) :]
    return rendered


def _visible(rendered: str) -> str:
    """The text a reader meets before opening a single disclosure."""
    body = _drop_blocks(rendered, "<style>", "</style>")
    body = _drop_blocks(body, "<script>", "</script>")
    closed = re.compile(r"<details(?![^>]*\sopen)[^>]*>(.*?)</details>", re.S)
    while True:
        def keep(match: re.Match[str]) -> str:
            summary = re.search(r"<summary.*?</summary>", match.group(1), re.S)
            return summary.group(0) if summary else ""

        folded = closed.sub(keep, body)
        if folded == body:
            break
        body = folded
    return body


class LayeredReportTests(unittest.TestCase):
    """The v2 report leads with the verdict and folds what was rejected."""

    def _capture(self, directory: Path, records: list[dict]) -> tuple[Path, bytes]:
        capture = directory / "incident.jsonl"
        content = "".join(
            json.dumps(record, ensure_ascii=False) + "\n" for record in records
        ).encode("utf-8")
        capture.write_bytes(content)
        return capture, content

    def _incident_records(self) -> list[dict]:
        """A run PBP itself blamed on one session, plus a quiet ARP counter."""
        return [
            {
                "timestamp": "2026-08-27T10:00:00+00:00",
                "collector_version": "0.2.0",
                "run_id": "run-1",
                "target_name": "lab-fw-01",
                "event": "monitor_started",
                "device": {
                    "device_name": "lab-fw-01",
                    "model": "PA-440",
                    "software_version": "11.1.4-h7",
                    "uptime": "40 days, 1:02:03",
                },
            },
            {
                "timestamp": "2026-08-27T10:00:01+00:00",
                "run_id": "run-1",
                "elapsed_seconds": 1,
                "percentages": {
                    "packet_buffer_congestion": [88],
                    "descriptor_atomic": [91],
                },
                "candidate_session_ids": [38492],
                "candidate_entities": [
                    {
                        "rank": 1,
                        "entity_type": "session",
                        "session_id": 38492,
                        "drop_state": True,
                        "pbp_percentage_total": 72,
                        "ingress_percentage_max": 75.6,
                        "evidence_sources": [
                            "packet_buffer_protection",
                            "ingress_backlogs",
                        ],
                    }
                ],
                "session_summaries": {
                    "38492": {
                        "status": "parsed",
                        "application": "quic",
                        "rule": "allow-outbound",
                        "c2s": {
                            "source_ip": "203.0.113.7",
                            "source_port": 54321,
                            "destination_ip": "198.51.100.15",
                            "destination_port": 443,
                            "protocol": 17,
                        },
                    }
                },
                "commands": {"packet_buffer_protection": "<result>raw</result>"},
            },
            {
                "timestamp": "2026-08-27T10:00:06+00:00",
                "run_id": "run-1",
                "elapsed_seconds": 6,
                "percentages": {"packet_buffer_congestion": [42]},
            },
            {
                "timestamp": "2026-08-27T10:00:07+00:00",
                "run_id": "run-1",
                "event": "monitor_stopped",
                "reason": "resources_recovered",
                "elapsed_seconds": 7,
            },
        ]

    def test_the_verdict_and_its_numbers_come_before_any_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, source_bytes = self._capture(directory, self._incident_records())

            with patch.dict(os.environ, {"PANOS_API_KEY": "must-not-leak"}):
                report = generate_html_report_v2(
                    capture, directory / REPORT_V2_FILENAME
                )

            rendered = report.read_text(encoding="utf-8")

        self.assertLess(
            rendered.index('id="verdict-title"'), rendered.index('id="cause-title"')
        )
        self.assertLess(
            rendered.index('id="cause-title"'), rendered.index('id="pressure-title"')
        )
        self.assertIn("Packet buffers", rendered)
        self.assertIn("88%", rendered)
        self.assertIn("Packet descriptors", rendered)
        self.assertIn("91%", rendered)
        # The layered report is still enough on its own to open a TAC case.
        self.assertIn("PA-440", rendered)
        self.assertIn("11.1.4-h7", rendered)
        self.assertIn(hashlib.sha256(source_bytes).hexdigest(), rendered)
        self.assertIn(f"PBP Monitoring v{__version__}", rendered)
        self.assertNotIn("must-not-leak", rendered)

    def test_only_supported_causes_are_visible_and_the_rest_stay_folded(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, _ = self._capture(directory, self._incident_records())
            report = generate_html_report_v2(capture, directory / REPORT_V2_FILENAME)
            rendered = report.read_text(encoding="utf-8")

        visible = _visible(rendered)
        self.assertIn("Offender named by PBP", visible)
        self.assertIn("Session holding the ingress backlog", visible)
        # A rejected cause is named only on the summary line that folds it, and
        # the conclusion no longer repeats the findings above it.
        self.assertIn("ruled out", visible)
        self.assertNotIn("Conclusion for the case", visible.split("<summary")[0])
        self.assertIn("Conclusion for the case", rendered)
        self.assertIn("The full four-step investigation", rendered)
        self.assertLess(len(_visible(rendered)), len(rendered))

    def test_the_layered_report_shows_less_at_once_than_the_flat_one(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, _ = self._capture(directory, self._incident_records())
            flat = generate_html_report(capture, directory / "report.html")
            layered = generate_html_report_v2(capture, directory / REPORT_V2_FILENAME)
            flat_words = len(_visible(flat.read_text(encoding="utf-8")).split())
            layered_words = len(_visible(layered.read_text(encoding="utf-8")).split())

        self.assertLess(layered_words, flat_words)

    def test_a_capture_without_a_batch_still_renders_its_appendix(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, _ = self._capture(
                directory,
                [
                    {
                        "timestamp": "2026-08-27T10:00:00+00:00",
                        "run_id": "run-empty",
                        "event": "monitor_started",
                    }
                ],
            )
            report = generate_html_report_v2(capture, directory / REPORT_V2_FILENAME)
            rendered = report.read_text(encoding="utf-8")

        self.assertIn("No batch collected", rendered)
        self.assertNotIn('id="cause-title"', rendered)
        self.assertIn('id="events-title"', rendered)

    def test_the_report_carries_only_its_own_folding_script(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, _ = self._capture(directory, self._incident_records())
            report = generate_html_report_v2(capture, directory / REPORT_V2_FILENAME)
            rendered = report.read_text(encoding="utf-8")

        self.assertEqual(rendered.count("<script>"), 1)
        self.assertIn(f"<script>{REPORT_V2_SCRIPT}</script>", rendered)
        self.assertIn(REPORT_V2_SCRIPT_CSP_HASH, rendered)
        # The control folds the sections and the layer-2 blocks, and stops
        # there: opening every raw command response would print for hours.
        self.assertIn(
            'querySelectorAll("section:not(.glance)>details.section-fold,details.dismissed")',
            rendered,
        )

    def test_both_reports_state_the_on_box_ingress_collection_identically(self):
        # The layered report draws the same evidence sections as the flat one,
        # so neither can tell TAC something different about whether the tech
        # support file carries the 100 ms ingress samples.
        records = self._incident_records()
        records[0]["inflight_monitoring"] = {
            "parsed": True,
            "enabled": False,
            "duration_seconds": 3,
            "threshold_percent": 80,
            "trigger_pending": False,
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, _ = self._capture(directory, records)
            flat = generate_html_report(
                capture, directory / "report.html"
            ).read_text(encoding="utf-8")
            layered = generate_html_report_v2(
                capture, directory / REPORT_V2_FILENAME
            ).read_text(encoding="utf-8")

        for rendered in (flat, layered):
            self.assertIn(
                "On-box ingress-backlog auto-collection: <strong>disabled</strong>",
                rendered,
            )
            self.assertIn("set session inflight_monitoring yes", rendered)
            self.assertIn("On-box auto-collection", rendered)

    def _both_reports(self, inflight: dict) -> tuple[str, str]:
        records = self._incident_records()
        records[0]["inflight_monitoring"] = inflight
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, _ = self._capture(directory, records)
            flat = generate_html_report(
                capture, directory / "report.html"
            ).read_text(encoding="utf-8")
            layered = generate_html_report_v2(
                capture, directory / REPORT_V2_FILENAME
            ).read_text(encoding="utf-8")
        return flat, layered

    def test_a_partly_read_on_box_setting_reads_the_same_in_both_reports(self):
        # Only the duration was returned. Both reports, and the fact line
        # inside each, must call the 80% an assumed PAN-OS default rather than
        # a value this firewall reported.
        assumed = "80% for 5 s, PAN-OS defaults: the nodes were not returned"
        for rendered in self._both_reports(
            {"parsed": True, "status": "read", "enabled": True, "duration_seconds": 5}
        ):
            self.assertIn(f"enabled ({assumed})", rendered)
            # Every printing of the pair carries the caveat: not one place in
            # either report states the 80% as the firewall's own setting.
            self.assertEqual(rendered.count("80% for 5 s"), rendered.count(assumed))

    def test_a_non_boolean_on_box_flag_reads_as_unknown_in_both_reports(self):
        for rendered in self._both_reports(
            {"parsed": True, "status": "read", "enabled": "on"}
        ):
            self.assertIn("On-box ingress-backlog auto-collection: not read", rendered)
            self.assertIn("On-box auto-collection", rendered)
            self.assertNotIn("auto-collection was enabled", rendered)

    def test_the_destination_must_differ_from_the_capture(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, _ = self._capture(directory, self._incident_records())
            with self.assertRaises(ValueError):
                generate_html_report_v2(capture, capture)

    def test_without_an_output_the_report_takes_the_name_the_dashboard_serves(self):
        # A regeneration run by hand must refresh the file the run's row opens.
        # A differently named copy would be invisible in the Web UI and would
        # still be packed into every run archive and support bundle, evicting
        # real evidence from their size budget.
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, _ = self._capture(directory, self._incident_records())
            output = StringIO()
            with redirect_stdout(output):
                code = main([str(capture)])

            self.assertEqual(code, 0)
            self.assertEqual(
                output.getvalue().strip(), str(directory / REPORT_V2_FILENAME)
            )
            self.assertTrue((directory / REPORT_V2_FILENAME).is_file())
            self.assertEqual(
                sorted(path.name for path in directory.glob("*.html")),
                [REPORT_V2_FILENAME],
            )

    def test_the_command_line_writes_the_report_it_prints(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, _ = self._capture(directory, self._incident_records())
            destination = directory / REPORT_V2_FILENAME
            output = StringIO()
            with redirect_stdout(output):
                code = main([str(capture), "-o", str(destination)])

        self.assertEqual(code, 0)
        self.assertEqual(output.getvalue().strip(), str(destination))


class ThresholdNoiseTests(unittest.TestCase):
    """A firewall at rest whose PBP fires must never read as an incident."""

    def _capture(self, directory: Path, mitigating_from: float) -> Path:
        """A run with idle buffers where PBP mitigates all the same."""
        records = [
            {
                "timestamp": "2026-08-30T18:40:00+00:00",
                "run_id": "run-noise",
                "target_name": "lab-fw",
                "event": "monitor_started",
                "device": {
                    "device_name": "lab-fw",
                    "model": "PA-440",
                    "software_version": "12.2.2",
                },
                "pbp_settings": {
                    "status": "parsed",
                    "enabled": True,
                    "alert_percent": 50.0,
                    "activate_percent": 80.0,
                },
            },
            {
                "timestamp": "2026-08-30T18:40:05+00:00",
                "run_id": "run-noise",
                "elapsed_seconds": 5,
                "percentages": {"packet_buffer_congestion": [4.51]},
                "pbp_status": {
                    "enabled": True,
                    "active": True,
                    "mode": "packet_buffer",
                    "monitor_only": False,
                    "congestion_percentage": mitigating_from,
                },
                "candidate_session_ids": [4242],
                "candidate_entities": [
                    {
                        "rank": 1,
                        "entity_type": "session",
                        "session_id": 4242,
                        "drop_state": True,
                        "pbp_percentage_total": 31.0,
                        "evidence_sources": ["packet_buffer_protection"],
                    }
                ],
            },
            {
                "timestamp": "2026-08-30T18:40:10+00:00",
                "run_id": "run-noise",
                "event": "monitor_stopped",
                "reason": "resources_recovered",
                "elapsed_seconds": 10,
            },
        ]
        capture = directory / "incident.jsonl"
        capture.write_text(
            "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
        )
        return capture

    def _render(self, mitigating_from: float = 4.14) -> str:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture = self._capture(directory, mitigating_from)
            report = generate_html_report_v2(capture, directory / REPORT_V2_FILENAME)
            return report.read_text(encoding="utf-8")

    def test_pbp_ranking_is_never_presented_as_a_supported_cause(self):
        """The trap: at 4.5% buffers the ranking is ordinary traffic."""
        rendered = self._render()

        self.assertNotIn('class="finding-rank"', rendered)
        self.assertIn('<div class="threshold-noise">', rendered)
        self.assertIn("No incident on this firewall", rendered)
        self.assertIn("ordinary traffic, not a cause", rendered)
        # And it is kept, folded, because it is the firewall's own designation.
        self.assertIn("What PBP ranked", rendered)
        self.assertIn("4242", rendered)

    def test_the_layer_names_the_threshold_configuration_as_what_to_review(self):
        rendered = self._render()

        self.assertIn("packet-buffer-protection threshold configuration", rendered)
        self.assertIn("every alert it raises is noise", rendered)

    def test_mitigation_below_the_read_activate_threshold_is_called_out(self):
        """PBP cannot mitigate below its own activate threshold."""
        rendered = self._render(mitigating_from=4.14)

        self.assertIn("alert 50% and activate 80%", rendered)
        self.assertIn("those are not the thresholds that were in force", rendered)
        self.assertIn("Read the packet-buffer-protection settings on the device", rendered)

    def test_the_mitigation_tile_flags_only_a_lowered_threshold(self):
        low = self._render(mitigating_from=4.14)
        self.assertIn('<div class="proof-item" data-level="warn"><span>PBP mitigated from', low)

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture = directory / "incident.jsonl"
            capture.write_text(
                "".join(
                    json.dumps(record) + "\n"
                    for record in [
                        {
                            "timestamp": "2026-08-30T18:40:00+00:00",
                            "run_id": "run-real",
                            "event": "monitor_started",
                            "device": {"model": "PA-440"},
                        },
                        {
                            "timestamp": "2026-08-30T18:40:05+00:00",
                            "run_id": "run-real",
                            "elapsed_seconds": 5,
                            "percentages": {"packet_buffer_congestion": [84.0]},
                            "pbp_status": {
                                "enabled": True,
                                "active": True,
                                "mode": "packet_buffer",
                                "congestion_percentage": 84.0,
                            },
                        },
                    ]
                ),
                encoding="utf-8",
            )
            high = generate_html_report_v2(
                capture, directory / REPORT_V2_FILENAME
            ).read_text(encoding="utf-8")

        self.assertIn('<div class="proof-item" data-level="ok"><span>PBP mitigated from', high)
        self.assertNotIn('<div class="threshold-noise">', high)


class ProofTileTests(unittest.TestCase):
    """A tile states the severity the diagnosis decided, never its own."""

    def _render(self, records: list[dict]) -> str:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture = directory / "incident.jsonl"
            capture.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            report = generate_html_report_v2(capture, directory / REPORT_V2_FILENAME)
            return report.read_text(encoding="utf-8")

    def test_default_latency_thresholds_still_colour_the_latency_tile(self):
        """A 300 ms queue is exhaustion whether or not the read named a limit.

        The firewall answered the settings read with nothing, so the diagnosis
        judges the latency against the PAN-OS defaults and calls step 1 latency
        exhaustion. A tile that only reacted to an explicitly configured alert
        level printed a calm green 300 ms directly above that verdict.
        """
        rendered = self._render(
            [
                {
                    "timestamp": "2026-09-01T10:00:00+00:00",
                    "run_id": "run-latency",
                    "event": "monitor_started",
                    "device": {"model": "PA-3220", "software_version": "11.1.4"},
                },
                {
                    "timestamp": "2026-09-01T10:00:05+00:00",
                    "run_id": "run-latency",
                    "elapsed_seconds": 5,
                    "percentages": {"packet_buffer_congestion": [12]},
                    "buffer_latency": {
                        "status": "enabled",
                        "peak_ms": 300,
                        "dataplanes": [{"last_max_ms": 300, "last_avg_ms": 3}],
                    },
                },
            ]
        )

        self.assertIn(
            '<div class="proof-item" data-level="bad"><span>Buffer latency</span>'
            "<strong>300 ms</strong></div>",
            rendered,
        )
        self.assertIn("Dataplane latency reached 300 ms", rendered)

    def test_a_lowered_alert_threshold_colours_the_buffer_tile(self):
        """The tiles read the thresholds this firewall runs with.

        With the alert level configured at 5%, a 30% buffer is above it and
        step 1 says so. A tile ranking the same number against the 50% PAN-OS
        default would call it nominal.
        """
        rendered = self._render(
            [
                {
                    "timestamp": "2026-09-01T10:00:00+00:00",
                    "run_id": "run-lowered",
                    "event": "monitor_started",
                    "device": {"model": "PA-440", "software_version": "11.1.4"},
                    "pbp_settings": {
                        "status": "parsed",
                        "enabled": True,
                        "alert_percent": 5.0,
                        "activate_percent": 90.0,
                    },
                },
                {
                    "timestamp": "2026-09-01T10:00:05+00:00",
                    "run_id": "run-lowered",
                    "elapsed_seconds": 5,
                    "percentages": {"packet_buffer_congestion": [30]},
                },
            ]
        )

        self.assertIn(
            '<div class="proof-item" data-level="warn"><span>Packet buffers</span>'
            "<strong>30%</strong></div>",
            rendered,
        )


#: An idle firewall whose PBP fires all the same, freshly rebooted. The
#: recent-boot signal is appended to step 4 from the device uptime alone: it is
#: not something PBP ranked, and must not be filed under the label that says so.
_LOW_SIGNIFICANCE_RECORDS = [
    {
                "timestamp": "2026-09-01T18:40:00+00:00",
                "run_id": "run-boot",
                "target_name": "lab-fw",
                "event": "monitor_started",
                "device": {
                    "device_name": "lab-fw",
                    "model": "PA-440",
                    "software_version": "11.1.4",
                    "uptime": "0 days, 5:11:02",
                },
                "pbp_settings": {
                    "status": "parsed",
                    "enabled": True,
                    "alert_percent": 50.0,
                    "activate_percent": 80.0,
                },
            },
            {
                "timestamp": "2026-09-01T18:40:05+00:00",
                "run_id": "run-boot",
                "elapsed_seconds": 5,
                "percentages": {"packet_buffer_congestion": [4.51]},
                "pbp_status": {
                    "enabled": True,
                    "active": True,
                    "mode": "packet_buffer",
                    "congestion_percentage": 4.14,
                },
                "candidate_session_ids": [4242],
                "candidate_entities": [
                    {
                        "rank": 1,
                        "entity_type": "session",
                        "session_id": 4242,
                        "drop_state": True,
                        "pbp_percentage_total": 31.0,
                        "evidence_sources": ["packet_buffer_protection"],
                    }
                ],
            },
]

_LOW_SIGNIFICANCE_CAPTURE = "".join(
    json.dumps(record) + "\n" for record in _LOW_SIGNIFICANCE_RECORDS
)


class LowSignificanceLabellingTests(unittest.TestCase):
    """Only PBP's ranking may be presented as what PBP ranked."""

    def _render(self) -> str:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture = directory / "incident.jsonl"
            capture.write_text(_LOW_SIGNIFICANCE_CAPTURE, encoding="utf-8")
            report = generate_html_report_v2(capture, directory / REPORT_V2_FILENAME)
            return report.read_text(encoding="utf-8")

    def test_a_recent_boot_is_not_filed_as_something_pbp_ranked(self):
        rendered = self._render()
        ranked = rendered.index("What PBP ranked")
        others = rendered.index("Other signals observed")

        self.assertLess(ranked, others)
        self.assertIn("Offender named by PBP", rendered[ranked:others])
        self.assertNotIn("Recent boot or upgrade", rendered[ranked:others])
        self.assertIn("Recent boot or upgrade", rendered[others:])

    def test_the_findings_themselves_say_which_are_the_ranking(self):
        """Any consumer, not only this renderer, can tell the two apart."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture = directory / "incident.jsonl"
            capture.write_text(_LOW_SIGNIFICANCE_CAPTURE, encoding="utf-8")
            records, warnings, source_hash = _read_jsonl(capture)
            parts = _build_report_parts(capture, records, warnings, source_hash)

        findings = collect_findings(parts["diagnosis"])
        by_key = {item["key"]: item for item in findings["confirmed"]}

        self.assertTrue(by_key["pbp"]["ranking_derived"])
        self.assertFalse(by_key["recent_boot"]["ranking_derived"])
        self.assertTrue(all(item["low_significance"] for item in by_key.values()))


class NavigationTests(unittest.TestCase):
    """Every link in a report's navigation opens a section of that report."""

    def _reports(self, directory: Path) -> dict[str, str]:
        capture = directory / "incident.jsonl"
        capture.write_text(_LOW_SIGNIFICANCE_CAPTURE, encoding="utf-8")
        return {
            "v1": generate_html_report(
                capture, directory / "report.html"
            ).read_text(encoding="utf-8"),
            "v2": generate_html_report_v2(
                capture, directory / REPORT_V2_FILENAME
            ).read_text(encoding="utf-8"),
        }

    def test_no_navigation_link_points_at_a_section_the_page_lacks(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            reports = self._reports(Path(temporary_directory))

        for name, rendered in reports.items():
            navigation = rendered[
                rendered.index('<nav class="toc"') : rendered.index("</nav>")
            ]
            anchors = re.findall(r'href="#([a-z0-9-]+)"', navigation)
            self.assertTrue(anchors, name)
            for anchor in anchors:
                with self.subTest(report=name, anchor=anchor):
                    self.assertIn(f'id="{anchor}"', rendered)


class ScriptPinningTests(unittest.TestCase):
    """A report's policy names the exact script that report carries."""

    def test_each_report_pins_the_folding_script_it_embeds(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture = directory / "incident.jsonl"
            capture.write_text(_LOW_SIGNIFICANCE_CAPTURE, encoding="utf-8")
            rendered = [
                generate_html_report(
                    capture, directory / "report.html"
                ).read_text(encoding="utf-8"),
                generate_html_report_v2(
                    capture, directory / REPORT_V2_FILENAME
                ).read_text(encoding="utf-8"),
            ]

        for page in rendered:
            script = page[
                page.rindex("<script>") + len("<script>") : page.rindex("</script>")
            ]
            digest = "sha256-" + base64.b64encode(
                hashlib.sha256(script.encode("utf-8")).digest()
            ).decode("ascii")
            with self.subTest(digest=digest):
                self.assertIn(f"script-src '{digest}'", page)
                self.assertIn(
                    digest,
                    (REPORT_SCRIPT_CSP_HASH, REPORT_V2_SCRIPT_CSP_HASH),
                )

    def test_the_layered_script_is_the_flat_one_with_a_wider_selector(self):
        self.assertNotEqual(REPORT_SCRIPT, REPORT_V2_SCRIPT)
        self.assertEqual(
            REPORT_V2_SCRIPT.replace(
                ",details.dismissed", ""
            ).replace("folds", "sections"),
            REPORT_SCRIPT,
        )


class FindingCollectionTests(unittest.TestCase):
    """`collect_findings` is what lets the report lead with what holds."""

    def _diagnosis(self) -> dict:
        return {
            "context": {},
            "headline": {"level": "bad", "label": "x", "text": "y"},
            "conclusion": [],
            "steps": [
                {
                    "number": 1,
                    "key": "pressure",
                    "state": "positive",
                    "level": "bad",
                    "verdict": "buffers were short",
                    "anchor": "pressure-title",
                },
                {
                    "number": 2,
                    "key": "pbp",
                    "finding_title": "Offender named by PBP",
                    "state": "positive",
                    "level": "bad",
                    "verdict": "PBP marked one session",
                    "named": ["session 1"],
                    "anchor": "attribution-title",
                },
                {
                    "number": 3,
                    "key": "backlogs",
                    "finding_title": "Session holding the ingress backlog",
                    "state": "negative",
                    "level": "ok",
                    "verdict": "no session held the queue",
                    "named": [],
                    "anchor": "ingress-title",
                },
                {
                    "number": 4,
                    "key": "elsewhere",
                    "state": "positive",
                    "level": "bad",
                    "verdict": "one hypothesis holds",
                    "anchor": "cpu-tracking-title",
                    "hypotheses": [
                        {
                            "key": "elephant",
                            "title": "Elephant session",
                            "state": "positive",
                            "text": "one flow",
                        },
                        {
                            "key": "storm",
                            "title": "Storm of new sessions",
                            "state": "negative",
                            "text": "no storm",
                        },
                        {
                            "key": "interfaces",
                            "title": "Interface errors",
                            "state": "unavailable",
                            "text": "not collected",
                        },
                    ],
                },
            ],
        }

    def test_each_conclusion_lands_in_exactly_one_bucket(self):
        findings = collect_findings(self._diagnosis())

        self.assertEqual(
            [item["title"] for item in findings["confirmed"]],
            ["Offender named by PBP", "Elephant session"],
        )
        self.assertEqual(
            [item["title"] for item in findings["ruled_out"]],
            ["Session holding the ingress backlog", "Storm of new sessions"],
        )
        self.assertEqual(
            [item["title"] for item in findings["unavailable"]], ["Interface errors"]
        )

    def test_step_one_is_the_verdict_and_never_a_cause(self):
        findings = collect_findings(self._diagnosis())
        keys = {
            item["key"]
            for bucket in findings.values()
            for item in bucket
        }
        self.assertNotIn("pressure", keys)

    def test_a_finding_links_to_the_section_that_proves_it(self):
        findings = collect_findings(self._diagnosis())
        anchors = {item["key"]: item["anchor"] for item in findings["confirmed"]}

        self.assertEqual(anchors["pbp"], "attribution-title")
        self.assertEqual(anchors["elephant"], "large-sessions-title")

    def test_every_hypothesis_the_diagnosis_can_raise_has_an_evidence_section(self):
        """A finding with no section to open would be a dead end for the reader."""
        from pbp_monitoring import diagnosis as diagnosis_module

        source = Path(diagnosis_module.__file__).read_text(encoding="utf-8")
        raised = set(re.findall(r'"key": "([a-z_]+)"', source))
        raised -= {"pressure", "pbp", "backlogs", "elsewhere"}

        self.assertTrue(raised)
        self.assertEqual(raised - set(EVIDENCE_ANCHORS), set())


if __name__ == "__main__":
    unittest.main()
