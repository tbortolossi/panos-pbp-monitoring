"""Guards that keep a customer deployment diagnosable as the collector grows.

A support export is only useful while it still describes everything the
collector produces. That coupling is invisible: adding a PAN-OS command or a
new journal breaks nothing, passes every other test, and quietly removes the
evidence a remote diagnosis would have relied on months later.

These two tests make the coupling fail loudly instead. They are the mechanical
half of change rule 11 in CLAUDE.md.
"""

import ast
import json
import re
import tempfile
import unittest
from pathlib import Path

from pbp_monitoring import diagnostics, orchestrator
from tools.replay_capture import PARSERS, RAW_RESPONSE_EVENTS

#: Commands collected outside the per-batch table: the clock, the startup
#: identity, the ones collected once at monitor start, and the whole-table
#: interface counter read a batch runs on its stride.
ADDITIONAL_COLLECTED_COMMANDS = frozenset(
    {
        "clock",
        "system_info",
        "pbp_settings",
        "dp_core_functions",
        "global_counters_baseline",
        "large_sessions",
        "interface_counters",
        "interface_counters_all",
    }
) | frozenset(orchestrator.INCIDENT_START_COMMANDS)

ORCHESTRATOR_SOURCE = Path(orchestrator.__file__).read_text(encoding="utf-8")

#: Journals the collector writes at the root of the capture directory. Scraped
#: from the source so a new one cannot be added without this test noticing.
ROOT_JOURNALS = frozenset(
    re.findall(r'output_dir / "([a-z-]+\.jsonl)"', ORCHESTRATOR_SOURCE)
) - {"syslog-triggers.jsonl"}


def _events_persisting_raw_responses() -> set[str]:
    """Journal events that store a raw PAN-OS response outside `commands`.

    Read from the orchestrator's own syntax tree: any function that builds a
    dictionary with a literal `raw_response` key and names an `event` writes
    XML that `record["commands"]` does not carry. The replay tool has to know
    about each of them, or that XML is unreachable from a customer archive.
    """
    events: set[str] = set()
    for node in ast.walk(ast.parse(ORCHESTRATOR_SOURCE)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        pairs = [
            (key, value)
            for dictionary in ast.walk(node)
            if isinstance(dictionary, ast.Dict)
            for key, value in zip(dictionary.keys, dictionary.values)
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        ]
        if not any(key.value == "raw_response" for key, _ in pairs):
            continue
        events.update(
            value.value
            for key, value in pairs
            if key.value == "event"
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        )
    return events


RAW_RESPONSE_EVENT_NAMES = _events_persisting_raw_responses()


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

    def test_every_once_per_incident_read_is_declared_optional(self):
        """A start command missing from the evidence tables fails a check.

        The read-only API check reports a command it cannot classify as an
        error, so a once-per-incident read forgotten here would turn a
        firewall that answers everything the monitor needs into an
        `api_check_partial_failure` — for a firewall with no HA, no zone
        protection profile, or a PAN-OS release without the node.
        """
        classified = set(orchestrator.OPTIONAL_COMMAND_EVIDENCE) | set(
            orchestrator.PLATFORM_DEPENDENT_COMMAND_EVIDENCE
        )
        missing = sorted(set(orchestrator.INCIDENT_START_COMMANDS) - classified)
        self.assertEqual(
            missing,
            [],
            "Once-per-incident reads absent from OPTIONAL_COMMAND_EVIDENCE and "
            "PLATFORM_DEPENDENT_COMMAND_EVIDENCE: their failure would be "
            "reported as a failed API check instead of the piece of evidence "
            "it costs. Declare each with what it collects.",
        )

    def test_every_event_storing_a_raw_response_can_be_replayed(self):
        missing = sorted(RAW_RESPONSE_EVENT_NAMES - set(RAW_RESPONSE_EVENTS))
        self.assertEqual(
            missing,
            [],
            "Journal events that persist raw PAN-OS XML outside the commands "
            "table but are absent from RAW_RESPONSE_EVENTS in "
            "tools/replay_capture.py: the replay tool only reads "
            "record['commands'], so their XML travels in every customer "
            "archive and no one can replay it. Map each to its parser.",
        )

    def test_the_scraped_raw_response_event_list_still_finds_something(self):
        # A refactor that moved those records out of a function would empty the
        # scrape and make the coverage test above vacuous.
        self.assertIn("pbp_threat_logs", RAW_RESPONSE_EVENT_NAMES)
        self.assertIn("offender_traffic_logs", RAW_RESPONSE_EVENT_NAMES)

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
