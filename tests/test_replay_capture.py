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

THREAT_LOG_XML = (
    '<response status="success"><result><log><logs><entry>'
    "<receive_time>2026/08/30 08:00:01</receive_time><tid>8507</tid>"
    "<threat_name>Packet buffer protection RED drop</threat_name>"
    "<src>198.51.100.7</src><dst>203.0.113.9</dst><proto>udp</proto>"
    "</entry></logs></log></result></response>"
)

#: The PBP threat-log query keeps its XML on the journal record itself, not in
#: a `commands` table, exactly as the collector writes it at monitor stop.
THREAT_LOG_RECORD = {
    "run_id": "20260830T080000Z",
    "timestamp": "2026-08-30T08:05:00+00:00",
    "event": "pbp_threat_logs",
    "ok": True,
    "raw_response": THREAT_LOG_XML,
}

TRAFFIC_LOG_XML = (
    '<response status="success"><result><log><logs><entry>'
    "<receive_time>2026/08/30 08:00:02</receive_time><src>198.51.100.7</src>"
    "<dst>203.0.113.9</dst><proto>udp</proto><action>allow</action>"
    "</entry></logs></log></result></response>"
)

TRAFFIC_LOG_RECORD = {
    "run_id": "20260830T080000Z",
    "timestamp": "2026-08-30T08:06:00+00:00",
    "event": "offender_traffic_logs",
    "sources": [
        {"source_ip": "198.51.100.7", "ok": True, "raw_response": TRAFFIC_LOG_XML},
        {"source_ip": "198.51.100.8", "ok": False, "error": "log job 3 did not finish"},
    ],
}


CONGESTION_LOG_XML = (
    '<response status="success"><result><log><logs><entry>'
    "<time_generated>2026/08/30 03:00:34</time_generated>"
    "<opaque>Packet buffer congestion (utilization) is 4170/97280 (72%)"
    "(alert threshold is 50%).</opaque>"
    "</entry></logs></log></result></response>"
)

#: The congestion system-log query keeps its XML on the journal record too. It
#: is the only PBP trace a monitor-only latency-mode device leaves, so a
#: customer archive that could not replay it would carry the evidence and no
#: way to read it.
CONGESTION_LOG_RECORD = {
    "run_id": "20260830T080000Z",
    "timestamp": "2026-08-30T08:07:00+00:00",
    "event": "congestion_system_logs",
    "ok": True,
    "raw_response": CONGESTION_LOG_XML,
}

#: The once-per-incident state and history reads travel as ordinary commands.
INCIDENT_STATE_RECORD = {
    "run_id": "20260830T080000Z",
    "timestamp": "2026-08-30T08:00:00+00:00",
    "event": "monitor_started",
    "commands": {
        "zone_protection": {
            "ok": True,
            "error": None,
            "result": (
                "<result><entry><dp>dp0</dp><entries><entry>"
                "<zone>INTERNET</zone><tcp>False</tcp>"
                "<pbp-drop>3984</pbp-drop></entry></entries></entry></result>"
            ),
        },
        "ha_state": {
            "ok": True,
            "error": None,
            "result": "<result><enabled>no</enabled></result>",
        },
        "inflight_monitoring": {
            "ok": True,
            "error": None,
            "result": (
                "<result>cfg.session.inflight_monitoring: False\n"
                "cfg.session.ingress_backlogs_duration: 3\n"
                "cfg.session.ingress_backlogs_threshold: 80\n</result>"
            ),
        },
        "global_counters_raw": {
            "ok": True,
            "error": None,
            "result": (
                "<result><dp>dp0</dp><global><t>1</t><counters><entry>"
                "<name>flow_dos_pbp_block_host</name><value>14</value>"
                "<rate>0</rate><severity>drop</severity><category>flow</category>"
                "<aspect>dos</aspect><desc>Blocked</desc><id>801</id>"
                "</entry></counters></global></result>"
            ),
        },
        "resource_monitor_history": {
            "ok": True,
            "error": None,
            "result": (
                "<result><resource-monitor><data-processors><dp0><day>"
                "<resource-utilization><entry>"
                "<name>packet buffer (maximum)</name><value>88,60,20</value>"
                "</entry></resource-utilization></day>"
                "</dp0></data-processors></resource-monitor></result>"
            ),
        },
        "interface_status": {
            "ok": True,
            "error": None,
            "result": (
                "<result><ifnet><entry><name>ethernet1/1</name>"
                "<zone>INTERNET</zone></entry></ifnet></result>"
            ),
        },
        "interface_counters_all": {
            "ok": True,
            "error": None,
            "result": (
                "<result><hw><entry><name>ethernet1/1</name><port>"
                "<rx-broadcast>645165</rx-broadcast></port></entry></hw></result>"
            ),
        },
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

    def test_a_replayed_backlog_row_carries_the_internal_tag_reason(self):
        """The reason is the parser's, so a customer archive replays it with
        no state from the run that collected it."""
        record = {
            "run_id": "20260830T080000Z",
            "timestamp": "2026-08-30T08:00:00+00:00",
            "commands": {
                "ingress_backlogs": {
                    "ok": True,
                    "result": (
                        "<result>-- SLOT: s1, DP: dp0 --\n"
                        "USAGE - ATOMIC: 4% TOTAL: 4%\n"
                        "TOP SESSIONS:\n"
                        "SESS-ID PCT GRP-ID COUNT Special Notes\n"
                        "4194327 4% flow_fastpath 43 "
                        "Special TAG values, NOT valid session id</result>"
                    ),
                    "error": None,
                }
            },
        }

        outcomes = {item["command"]: item for item in replay_record(record, None)}
        candidate = outcomes["ingress_backlogs"]["parsed"]["candidates"][0]

        self.assertEqual(outcomes["ingress_backlogs"]["status"], "parsed")
        self.assertEqual(candidate["special_reason"], "noted")
        self.assertEqual(
            candidate["special_note"],
            "Special TAG values, NOT valid session id",
        )

    def test_a_single_command_can_be_replayed_alone(self):
        outcomes = replay_record(RECORD, {"system_info"})
        self.assertEqual([item["command"] for item in outcomes], ["system_info"])

    def test_a_stop_time_log_query_is_replayed_from_its_event_record(self):
        outcomes = {item["command"]: item for item in replay_record(THREAT_LOG_RECORD, None)}
        threat = outcomes["pbp_threat_logs"]
        self.assertEqual(threat["status"], "parsed")
        self.assertEqual(threat["parsed"][0]["threat_id"], 8507)
        self.assertEqual(threat["parsed"][0]["source_ip"], "198.51.100.7")

    def test_each_offender_source_of_a_log_query_is_replayed_and_named(self):
        outcomes = {
            item["command"]: item for item in replay_record(TRAFFIC_LOG_RECORD, None)
        }
        parsed = outcomes["offender_traffic_logs[198.51.100.7]"]
        self.assertEqual(parsed["status"], "parsed")
        self.assertEqual(parsed["parsed"][0]["destination_ip"], "203.0.113.9")
        unfinished = outcomes["offender_traffic_logs[198.51.100.8]"]
        self.assertEqual(unfinished["status"], "empty")
        self.assertEqual(unfinished["collection_error"], "log job 3 did not finish")

    def test_an_event_record_can_be_replayed_alone_by_its_name(self):
        outcomes = replay_record(THREAT_LOG_RECORD, {"pbp_threat_logs"})
        self.assertEqual([item["command"] for item in outcomes], ["pbp_threat_logs"])
        self.assertEqual(replay_record(THREAT_LOG_RECORD, {"system_info"}), [])

    def test_the_congestion_query_is_replayed_from_its_event_record(self):
        outcomes = {
            item["command"]: item
            for item in replay_record(CONGESTION_LOG_RECORD, None)
        }
        congestion = outcomes["congestion_system_logs"]

        self.assertEqual(congestion["status"], "parsed")
        self.assertEqual(congestion["parsed"][0]["percent"], 72.0)
        self.assertEqual(congestion["parsed"][0]["used"], 4170)

    def test_every_once_per_incident_read_is_replayed_by_its_own_parser(self):
        outcomes = {
            item["command"]: item
            for item in replay_record(INCIDENT_STATE_RECORD, None)
        }

        self.assertEqual(
            {name: item["status"] for name, item in outcomes.items()},
            {
                "zone_protection": "parsed",
                "ha_state": "parsed",
                "inflight_monitoring": "parsed",
                "global_counters_raw": "parsed",
                "resource_monitor_history": "parsed",
                "interface_status": "parsed",
                "interface_counters_all": "parsed",
            },
        )
        self.assertEqual(
            outcomes["zone_protection"]["parsed"]["zones"][0]["pbp_drop"], 3984
        )
        self.assertIs(outcomes["ha_state"]["parsed"]["enabled"], False)
        # A customer archive must replay the on-box ingress-backlog state too:
        # it decides whether the tech support file holds the 100 ms samples.
        self.assertIs(
            outcomes["inflight_monitoring"]["parsed"]["enabled"], False
        )
        self.assertEqual(
            outcomes["inflight_monitoring"]["parsed"]["threshold_percent"], 80
        )
        self.assertEqual(
            outcomes["global_counters_raw"]["parsed"]["counters"][
                "flow_dos_pbp_block_host"
            ]["value"],
            14,
        )
        self.assertEqual(
            outcomes["interface_counters_all"]["parsed"]["ethernet1/1"][
                "counters"
            ]["rx_broadcast"],
            645165,
        )

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
