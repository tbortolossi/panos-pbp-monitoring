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
from pbp_monitoring.reporting import generate_html_report
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

    def test_the_destination_must_differ_from_the_capture(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            capture, _ = self._capture(directory, self._incident_records())
            with self.assertRaises(ValueError):
                generate_html_report_v2(capture, capture)

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
