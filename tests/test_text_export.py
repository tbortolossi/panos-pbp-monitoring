import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from pbp_monitoring.text_export import export_jsonl_text, write_record_text_export


class TextExportTests(unittest.TestCase):
    def test_startup_and_batch_exports_preserve_result_raw_and_errors(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            incident = Path(temporary_directory) / "incident.jsonl"
            startup = {
                "event": "monitor_started",
                "run_id": "20260828T120000Z",
                "commands": {"system_info": {"ok": True, "result": "system result", "raw_response": "<raw-system/>", "error": None}},
            }
            cycle = {
                "run_id": "20260828T120000Z",
                "cycle": 7,
                "timestamp": "2026-08-28T12:00:07+00:00",
                "firewall_clock": "Fri Aug 28 14:00:07 CEST 2026",
                "commands": {"packet_buffer_protection": {"ok": False, "result": "PBP output", "raw_response": "<raw-pbp/>", "error": "partial failure"}},
                "session_details": {"42": {"ok": True, "result": "session output", "raw_response": "<raw-session/>", "error": None}},
            }

            startup_path = write_record_text_export(incident, startup)
            cycle_path = write_record_text_export(incident, cycle)

            self.assertEqual(startup_path.name, "startup.txt")
            self.assertEqual(cycle_path.name, "batch-0007.txt")
            rendered = cycle_path.read_text(encoding="utf-8")
            self.assertIn("COMMAND: packet_buffer_protection", rendered)
            self.assertIn("PBP output", rendered)
            self.assertIn("<raw-pbp/>", rendered)
            self.assertIn("partial failure", rendered)
            self.assertIn("SESSION: 42", rendered)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(cycle_path.stat().st_mode), 0o600)

    def test_existing_jsonl_can_be_exported_to_an_explicit_directory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            capture = root / "incident.jsonl"
            records = [
                {"event": "monitor_started", "run_id": "run", "commands": {}},
                {"cycle": 1, "run_id": "run", "commands": {"clock": "raw"}},
                {"event": "monitor_stopped", "run_id": "run"},
            ]
            capture.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
            destination = root / "txt"

            written = export_jsonl_text(capture, destination)

            self.assertEqual([path.name for path in written], ["startup.txt", "batch-0001.txt"])
            self.assertTrue((destination / "batch-0001.txt").is_file())
            self.assertFalse((destination / "raw").exists())


if __name__ == "__main__":
    unittest.main()
