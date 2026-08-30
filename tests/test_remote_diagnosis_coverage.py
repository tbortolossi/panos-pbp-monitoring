"""Guards that keep a customer deployment diagnosable as the collector grows.

A support export is only useful while it still describes everything the
collector produces. That coupling is invisible: adding a PAN-OS command or a
new journal breaks nothing, passes every other test, and quietly removes the
evidence a remote diagnosis would have relied on months later.

These two tests make the coupling fail loudly instead. They are the mechanical
half of change rule 11 in CLAUDE.md.
"""

import json
import re
import tempfile
import unittest
from pathlib import Path

from pbp_monitoring import diagnostics, orchestrator
from tools.replay_capture import PARSERS

#: Commands collected outside the per-batch table: the clock, the startup
#: identity, and the two collected once at monitor start.
ADDITIONAL_COLLECTED_COMMANDS = frozenset(
    {
        "clock",
        "system_info",
        "pbp_settings",
        "dp_core_functions",
        "global_counters_baseline",
        "large_sessions",
    }
)

ORCHESTRATOR_SOURCE = Path(orchestrator.__file__).read_text(encoding="utf-8")

#: Journals the collector writes at the root of the capture directory. Scraped
#: from the source so a new one cannot be added without this test noticing.
ROOT_JOURNALS = frozenset(
    re.findall(r'output_dir / "([a-z-]+\.jsonl)"', ORCHESTRATOR_SOURCE)
) - {"syslog-triggers.jsonl"}


class ReplayCoverageTests(unittest.TestCase):
    def test_every_collected_command_can_be_replayed(self):
        collected = set(orchestrator.OP_COMMANDS) | ADDITIONAL_COLLECTED_COMMANDS
        missing = sorted(collected - set(PARSERS))
        self.assertEqual(
            missing,
            [],
            "Commands collected from PAN-OS but absent from "
            "tools/replay_capture.py: a capture carrying them could not be "
            "replayed against the parsers, so a customer archive could not "
            "reproduce their parsing failure. Add each to PARSERS.",
        )

    def test_the_scraped_journal_list_still_finds_something(self):
        # A rename in the orchestrator would otherwise silently empty the list
        # and make the export test below vacuous.
        self.assertIn("syslog-received.jsonl", ROOT_JOURNALS)


class BundleCoverageTests(unittest.TestCase):
    def test_every_journal_the_collector_writes_is_exported(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            for journal in ROOT_JOURNALS:
                (data / journal).write_text(
                    json.dumps({"journal": journal}) + "\n", encoding="utf-8"
                )
            target = data / "targets" / "fw-a"
            target.mkdir(parents=True)
            (target / "syslog-triggers.jsonl").write_text(
                json.dumps({"run_id": "run-1"}) + "\n", encoding="utf-8"
            )
            archive = data / "bundle.zip"
            with archive.open("wb") as handle:
                manifest = diagnostics.write_support_bundle(handle, data_dir=data)

        exported = "\n".join(entry["path"] for entry in manifest["files"])
        for journal in sorted(ROOT_JOURNALS) + ["syslog-triggers.jsonl"]:
            stem = journal.removeprefix("syslog-").removesuffix(".jsonl")
            self.assertIn(
                stem,
                exported,
                f"{journal} is written by the collector but no support bundle "
                "entry carries it, so a remote diagnosis would never see it. "
                "Export it from write_support_bundle.",
            )


if __name__ == "__main__":
    unittest.main()
