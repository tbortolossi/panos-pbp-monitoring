"""The replay tool is what turns a customer archive into a regression test.

It must read every shape a capture arrives in, report a parser that raises
instead of hiding it, and never be tempted to reach a firewall.
"""

import io
import json
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

from tools.replay_capture import PARSERS, iter_capture_records, main, replay_record

SYSTEM_INFO = (
    "<result><system><hostname>fw-a</hostname><model>PA-440</model>"
    "<serial>001122334455</serial><sw-version>12.2.2</sw-version>"
    "</system></result>"
)

RECORD = {
    "run_id": "20260830T080000Z",
    "timestamp": "2026-08-30T08:00:00+00:00",
    "commands": {
        "system_info": {"ok": True, "result": SYSTEM_INFO, "error": None},
        "clock": {"ok": False, "result": "", "error": "TimeoutError: timed out"},
        "future_command": {"ok": True, "result": "<result/>", "error": None},
    },
}


class ReplayTests(unittest.TestCase):
    def test_stored_xml_is_parsed_by_the_shipped_parser(self):
        outcomes = {item["command"]: item for item in replay_record(RECORD, None)}
        self.assertEqual(outcomes["system_info"]["status"], "parsed")
        self.assertEqual(outcomes["system_info"]["parsed"]["model"], "PA-440")
        self.assertEqual(outcomes["system_info"]["parsed"]["software_version"], "12.2.2")

    def test_a_failed_collection_is_reported_rather_than_parsed(self):
        outcomes = {item["command"]: item for item in replay_record(RECORD, None)}
        self.assertEqual(outcomes["clock"]["status"], "empty")
        self.assertEqual(outcomes["clock"]["collection_error"], "TimeoutError: timed out")

    def test_a_command_without_a_parser_is_named_not_skipped(self):
        outcomes = {item["command"]: item for item in replay_record(RECORD, None)}
        self.assertEqual(outcomes["future_command"]["status"], "unmapped")

    def test_a_parser_that_raises_is_surfaced_as_a_failure(self):
        def explode(_output):
            raise ValueError("unexpected element")

        original = PARSERS["system_info"]
        PARSERS["system_info"] = explode
        try:
            outcomes = {item["command"]: item for item in replay_record(RECORD, None)}
        finally:
            PARSERS["system_info"] = original
        self.assertEqual(outcomes["system_info"]["status"], "parser_raised")
        self.assertIn("unexpected element", outcomes["system_info"]["parser_error"])

    def test_a_single_command_can_be_replayed_alone(self):
        outcomes = replay_record(RECORD, {"system_info"})
        self.assertEqual([item["command"] for item in outcomes], ["system_info"])

    def test_a_run_archive_and_a_bare_capture_are_both_accepted(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            capture = root / "incident.jsonl"
            capture.write_text(json.dumps(RECORD) + "\n", encoding="utf-8")
            archive_path = root / "run.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("pbp-run-fw-a-run-1/incident.jsonl", json.dumps(RECORD))

            self.assertEqual(len(list(iter_capture_records(capture))), 1)
            self.assertEqual(len(list(iter_capture_records(archive_path))), 1)
            self.assertEqual(len(list(iter_capture_records(root))), 1)

            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main([str(archive_path), "--command", "system_info"])
            self.assertEqual(code, 0)
            self.assertIn("system_info", buffer.getvalue())
            self.assertIn("0 parser failures", buffer.getvalue())

    def test_failures_only_reports_what_needs_fixing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "api-check.jsonl"
            capture.write_text(json.dumps(RECORD) + "\n", encoding="utf-8")
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                main([str(capture), "--failures-only", "--format", "json"])
            reported = json.loads(buffer.getvalue())
            self.assertEqual([item["command"] for item in reported], ["clock"])


if __name__ == "__main__":
    unittest.main()
