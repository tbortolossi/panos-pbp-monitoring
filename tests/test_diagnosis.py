"""The report walks the PBP investigation and never contradicts itself."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pbp_monitoring.diagnosis import (
    HYPOTHESIS_COUNTERS,
    SIGNAL_COUNTER_FAMILIES,
    build_diagnosis,
    collect_findings,
    collected_field,
    command_outcome,
    command_outcomes,
    hardware_generation,
    ingress_backlog_collection,
)
from pbp_monitoring.reporting import (
    _SIGNAL_COUNTER_FAMILIES,
    generate_html_report,
)
from tests.support import REJECTED_NODE, TIMED_OUT


def _cycle(number: int, buffer_pct: float, **extra: object) -> dict:
    record: dict = {
        "timestamp": f"2026-08-30T10:{number:02d}:00+00:00",
        "run_id": "diagnosis-run",
        "cycle": number,
        "elapsed_seconds": 10.0 * number,
        "percentages": {"packet_buffer_congestion": [buffer_pct]},
        "commands": {},
    }
    record.update(extra)
    return record


def _render(records: list[dict]) -> str:
    with tempfile.TemporaryDirectory() as temporary:
        capture = Path(temporary) / "incident.jsonl"
        capture.write_text(
            "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
        )
        return generate_html_report(capture).read_text(encoding="utf-8")


def _facts(step: dict) -> list[tuple[str, str]]:
    return [(label, value) for label, value, _ in step["facts"]]


def _diagnose(cycles: list[dict], events: list[dict] | None = None, **kwargs: object) -> dict:
    defaults = {
        "attribution": [],
        "drop_summary": {"items": [], "family_totals": {}, "denied_total": 0.0, "counted_batches": 0},
        "session_series": [],
        "large_sessions": {"status": None, "sessions": []},
        "cpu_verdicts": [],
        "device": {"model": "PA-5220", "software_version": "10.2.9"},
    }
    defaults.update(kwargs)
    return build_diagnosis(cycles=cycles, events=events or [], **defaults)


class PlatformTests(unittest.TestCase):
    def test_a_vm_series_measures_the_same_in_flight_queue_as_an_x86(self):
        """A VM-Series runs the x86 dataplane, so the metric means the same."""
        virtual = hardware_generation("PA-VM")
        x86 = hardware_generation("PA-440")
        cavium = hardware_generation("PA-5220")

        self.assertEqual(
            virtual["ingress_backlog_metric"], x86["ingress_backlog_metric"]
        )
        self.assertTrue(virtual["ingress_backlog_in_flight"])
        self.assertTrue(x86["ingress_backlog_in_flight"])
        self.assertFalse(cavium["ingress_backlog_in_flight"])
        # Only a VM-Series explains the rejection by the x86 exclusion; the
        # other families print the generic reason.
        self.assertIn("left VM-Series", virtual["ingress_backlog_absent_reason"])
        self.assertNotIn("VM-Series", x86["ingress_backlog_absent_reason"])
        self.assertNotIn("VM-Series", cavium["ingress_backlog_absent_reason"])

    def test_cavium_and_x86_families_are_told_apart_from_the_model(self):
        self.assertEqual(hardware_generation("PA-5220")["family"], "cavium")
        self.assertEqual(hardware_generation("PA-3260")["family"], "cavium")
        self.assertEqual(hardware_generation("PA-7080")["family"], "cavium")
        self.assertEqual(hardware_generation("PA-440")["family"], "x86")
        self.assertEqual(hardware_generation("PA-1410")["family"], "x86")
        self.assertEqual(hardware_generation("PA-5450")["family"], "x86")
        self.assertEqual(hardware_generation("PA-VM")["family"], "virtual")
        self.assertIsNone(hardware_generation("")["on_chip_descriptors"])

    def test_an_x86_platform_never_reports_on_chip_descriptors_as_missing(self):
        html = _render(
            [
                {"run_id": "r", "event": "monitor_started", "device": {"model": "PA-440"}},
                _cycle(1, 4.0),
                _cycle(2, 4.2),
            ]
        )

        self.assertIn("none on this x86 platform (gen4)", html)
        self.assertNotIn("On-chip descriptors</dt><dd>not returned", html)


class PressureStepTests(unittest.TestCase):
    def test_a_lowered_threshold_is_named_instead_of_an_attack(self):
        """The lab PA-440 case: PBP active at 4% because alert was set to 1%."""
        trigger = {
            "run_id": "r",
            "event": "trigger_received",
            "message": "Packet buffer congestion (utilization) is 4310/97280 (4%)"
            "(alert threshold is 1%).",
        }
        cycles = [
            _cycle(
                number,
                4.4,
                pbp_status={"enabled": True, "active": True, "mode": "packet_buffer",
                            "congestion_percentage": 4.22 + number / 10},
                candidate_entities=[
                    {
                        "entity_type": "session",
                        "session_id": 118001,
                        "drop_state": True,
                        "pbp_percentage_total": 56,
                        "rank": 1,
                        "evidence_sources": ["packet_buffer_protection"],
                        "zones": ["LAN"],
                    }
                ],
                session_summaries={
                    "118001": {
                        "status": "parsed",
                        "application": "paloalto-updates",
                        "c2s": {"source_ip": "192.0.2.53", "destination_ip": "198.51.100.33",
                                "source_port": 47342, "destination_port": 443, "protocol": 6},
                    }
                },
            )
            for number in (1, 2, 3)
        ]
        html = _render([{"run_id": "r", "event": "monitor_started", "device": {"model": "PA-440"}}, trigger, *cycles])

        self.assertIn('<section class="glance" data-level="ok"', html)
        self.assertIn("<strong>Low pressure.</strong>", html)
        self.assertIn("alert threshold 1% (from the firewall)", html)
        self.assertIn("PBP mitigating from 4.32%", html)
        self.assertIn("the trigger is a threshold setting on this firewall", html)
        self.assertIn("do not designate an offender", html)
        self.assertNotIn("consistent with a UDP or GRE flood", html)

    def test_exhausted_descriptors_with_low_buffers_are_the_latency_case(self):
        diagnosis = _diagnose(
            [
                _cycle(1, 14.0, percentages={"packet_buffer_congestion": [14],
                                             "resource_monitor_packet_descriptor_on_chip": [100]}),
            ]
        )
        pressure = diagnosis["steps"][0]

        self.assertEqual(pressure["state"], "positive")
        self.assertIn("Packet descriptors were exhausted while the buffers stayed at 14%", pressure["verdict"])
        self.assertEqual(diagnosis["headline"]["label"], "No responsible party identified")

    def test_the_alert_threshold_comes_from_the_firewall_log_when_present(self):
        diagnosis = _diagnose(
            [_cycle(1, 60.0)],
            [{"event": "trigger_received", "message": "(alert threshold is 40%)."}],
        )

        self.assertEqual(diagnosis["context"]["alert_percent"], 40.0)
        self.assertEqual(diagnosis["context"]["alert_source"], "firewall")
        self.assertEqual(_diagnose([_cycle(1, 60.0)])["context"]["alert_source"], "default")


class OffenderStepTests(unittest.TestCase):
    def _attribution(self) -> list[dict]:
        return [
            {
                "entity_type": "session", "identifier": "38492", "drop_state": True,
                "pbp_percentage": 49, "evidence_sources": ["packet_buffer_protection"],
                "zones": ["untrust"], "group_ids": [],
                "session_summary": {"status": "parsed", "application": "dns",
                                    "c2s": {"source_ip": "203.0.113.4", "destination_ip": "198.51.100.20",
                                            "source_port": 53, "destination_port": 54666, "protocol": 17}},
            },
            {
                "entity_type": "source_ip", "identifier": "203.0.113.9", "drop_state": True,
                "pbp_percentage": 12, "evidence_sources": ["packet_buffer_protection"],
                "zones": ["untrust"], "group_ids": [],
            },
        ]

    def test_pbp_red_entries_are_named_with_their_flow_and_a_caveat(self):
        events = [
            {
                "event": "offender_traffic_logs",
                "sources": [
                    {
                        "source_ip": "203.0.113.9", "ok": True,
                        "entries": [
                            {"action": "deny", "rule": "block-syslog", "application": "syslog"},
                            {"action": "deny", "rule": "block-syslog", "application": "syslog"},
                        ],
                    }
                ],
            }
        ]
        diagnosis = _diagnose([_cycle(1, 84.0)], events, attribution=self._attribution())
        named = diagnosis["steps"][1]

        self.assertEqual(named["state"], "positive")
        self.assertIn("not a proof by itself", named["verdict"])
        self.assertIn("session <code>38492</code> (203.0.113.4:53 -&gt; 198.51.100.20:54666 / proto 17 · app dns", named["named"][0])
        self.assertIn("2 of 2 recent flows denied by rule block-syslog", named["named"][1])
        self.assertEqual(diagnosis["headline"]["label"], "Offender named by the firewall")
        self.assertIn("PBP designated: session <code>38492</code>", diagnosis["conclusion"][2])

    def test_the_headline_keeps_its_markup(self):
        html = _render(
            [
                _cycle(
                    1, 84.0,
                    candidate_entities=[{"entity_type": "session", "session_id": 7, "drop_state": True,
                                         "pbp_percentage_total": 50, "rank": 1,
                                         "evidence_sources": ["packet_buffer_protection"]}],
                    session_summaries={"7": {"status": "parsed", "application": "quic",
                                             "c2s": {"source_ip": "203.0.113.1", "destination_ip": "198.51.100.2"}}},
                )
            ]
        )

        self.assertIn("PBP marked session <code>7</code> (203.0.113.1 -&gt; 198.51.100.2 · app quic) for RED.", html)
        self.assertNotIn("&lt;code&gt;", html)

    def test_an_alert_only_pbp_learned_nobody(self):
        diagnosis = _diagnose(
            [_cycle(1, 62.0, pbp_status={"enabled": True, "active": False, "mode": "packet_buffer"})]
        )

        self.assertEqual(diagnosis["steps"][1]["state"], "negative")
        self.assertIn("PBP never activated", diagnosis["steps"][1]["verdict"])
        self.assertIn("PBP designated nobody: it never activated", diagnosis["conclusion"][2])

    def test_a_pbp_read_that_timed_out_everywhere_is_failed_not_a_negative(self):
        """A firewall too loaded to answer must never read as "PBP never activated"."""
        cycles = [
            _cycle(
                number,
                84.0,
                commands={"packet_buffer_protection": dict(TIMED_OUT)},
                pbp_status={"error": "TimeoutError: the read timed out"},
                pbp_offenders={"error": "TimeoutError: the read timed out"},
            )
            for number in (1, 2)
        ]
        diagnosis = _diagnose(cycles)
        step = diagnosis["steps"][1]
        facts = dict(_facts(step))

        self.assertEqual(step["state"], "failed")
        self.assertEqual(step["level"], "warn")
        self.assertIn("PBP read failed in all 2 of the 2 batches", step["verdict"])
        self.assertNotIn("PBP never activated", step["verdict"])
        self.assertEqual(facts["PBP activated"], "unknown")
        self.assertEqual(facts["Batches with the PBP read"], "0")
        self.assertEqual(facts["Batches with a failed read"], "2")
        self.assertIn("read failed in 2 of 2 batches", step["unavailable_reason"])
        self.assertIn(
            "Whether PBP designated anyone is unknown",
            " ".join(diagnosis["conclusion"]),
        )
        # A step that could not be read is still reported, not dropped.
        findings = collect_findings(diagnosis)
        self.assertIn(
            "Offender named by PBP",
            [item["title"] for item in findings["unavailable"]],
        )
        self.assertNotIn(
            "Offender named by PBP",
            [item["title"] for item in findings["ruled_out"]],
        )

    def test_a_mixed_pbp_run_keeps_its_verdict_and_names_the_lost_batches(self):
        cycles = [
            _cycle(
                1,
                84.0,
                commands={"packet_buffer_protection": {"ok": True, "result": "<result/>"}},
                pbp_status={"enabled": True, "active": False, "mode": "packet_buffer"},
            ),
            _cycle(
                2,
                84.0,
                commands={"packet_buffer_protection": dict(TIMED_OUT)},
                pbp_status={"error": "TimeoutError: the read timed out"},
            ),
        ]
        step = _diagnose(cycles)["steps"][1]

        self.assertEqual(step["state"], "negative")
        self.assertIn("PBP never activated", step["verdict"])
        self.assertIn(
            "the PBP read failed in 1 of the 2 batches", step["verdict"]
        )
        self.assertEqual(dict(_facts(step))["PBP activated"], "no")

    def test_a_legacy_capture_without_the_raw_pbp_command_reads_as_before(self):
        """A capture written before the gate carries the parsed status alone."""
        cycles = [
            _cycle(1, 62.0, pbp_status={"enabled": True, "active": False, "mode": "packet_buffer"})
        ]
        step = _diagnose(cycles)["steps"][1]

        self.assertEqual(step["state"], "negative")
        self.assertIn("PBP never activated", step["verdict"])
        self.assertNotIn("failed", step["verdict"])

    def test_a_capture_holding_no_pbp_evidence_at_all_stays_a_negative(self):
        """No command and no parsed status is not a failed read: nothing asked."""
        step = _diagnose([_cycle(1, 62.0)])["steps"][1]

        self.assertEqual(step["state"], "negative")
        self.assertIn("PBP never activated", step["verdict"])


def _tag_attribution(**extra: object) -> dict:
    """A backlog entry PAN-OS named an internal tag in its Special Notes."""
    item = {
        "entity_type": "session", "identifier": "4194327", "drop_state": False,
        "ingress_percentage": 88, "ingress_count": 43,
        "evidence_sources": ["ingress_backlogs"], "zones": [],
        "group_ids": ["flow_slowpath"],
        "special_reason": "noted",
        "special_note": "Special TAG values, NOT valid session id",
        # A tag is never looked up, so it has no session summary at all.
        "ingress_detail": {"application": "undecided"},
    }
    item.update(extra)
    return item


class IngressBacklogStepTests(unittest.TestCase):
    def test_an_internal_tag_is_named_as_one_and_answers_no_question(self):
        cycles = [
            _cycle(
                1, 14.0,
                ingress_backlogs={"dataplanes": [{"slot": "s1", "dp": "dp0", "atomic_percentage": 88, "total_percentage": 89}], "candidates": []},
            )
        ]

        backlogs = _diagnose(cycles, attribution=[_tag_attribution()])["steps"][2]

        self.assertIn("internal tag <code>4194327</code>", backlogs["named"][0])
        self.assertIn("host proxy for WildFire", backlogs["named"][0])
        self.assertIn("not a session", backlogs["named"][0])
        self.assertIn("holding 88% of the queue", backlogs["named"][0])
        self.assertIn(
            "Special TAG values, NOT valid session id", backlogs["named"][0]
        )
        # Neither signature may fire: a tag is the firewall's own traffic, and
        # `flow_slowpath` alone is not the policy-deny shape without Bad Key.
        self.assertNotIn("traffic denied by policy", backlogs["verdict"])
        self.assertNotIn("undecided or unknown application", backlogs["verdict"])
        self.assertIn("Only internal tags held the work queue", backlogs["verdict"])
        self.assertEqual(backlogs["state"], "negative")
        self.assertIn(("Internal tags listed", "1", "none"), backlogs["facts"])
        self.assertIn(("Sessions listed", "0", "none"), backlogs["facts"])

    def test_a_tag_beside_a_denied_session_leaves_the_deny_rule_standing(self):
        attribution = [
            _tag_attribution(ingress_percentage=90, group_ids=["flow_fastpath"]),
            {
                "entity_type": "session", "identifier": "2022536315", "drop_state": False,
                "ingress_percentage": 88, "evidence_sources": ["ingress_backlogs"],
                "zones": [], "group_ids": ["flow_slowpath"],
                "session_summary": {"status": "bad_key"},
                "ingress_detail": {"source_ip": "203.0.113.7", "destination_ip": "198.51.100.14",
                                   "source_port": 514, "destination_port": 514, "protocol": 17,
                                   "application": "undecided"},
            },
        ]
        cycles = [
            _cycle(
                1, 14.0,
                ingress_backlogs={"dataplanes": [{"slot": "s1", "dp": "dp0", "atomic_percentage": 90, "total_percentage": 91}], "candidates": []},
            )
        ]

        backlogs = _diagnose(cycles, attribution=attribution)["steps"][2]

        self.assertEqual(backlogs["state"], "positive")
        self.assertIn("1 session held at least", backlogs["verdict"])
        self.assertIn("traffic denied by policy", backlogs["verdict"])
        self.assertIn("undecided or unknown application", backlogs["verdict"])
        self.assertNotIn("4194327", backlogs["verdict"].split("Special Notes")[0])
        self.assertIn("A further 1 entry", backlogs["verdict"])
        self.assertIn("203.0.113.7:514 -&gt; 198.51.100.14:514", backlogs["named"][0])
        self.assertIn("Bad Key", backlogs["named"][0])
        self.assertIn("internal tag <code>4194327</code>", backlogs["named"][1])

    def test_a_slowpath_session_without_a_key_is_the_policy_deny_signature(self):
        attribution = [
            {
                "entity_type": "session", "identifier": "2022536315", "drop_state": False,
                "ingress_percentage": 88, "ingress_count": 3640,
                "evidence_sources": ["ingress_backlogs"], "zones": [], "group_ids": ["flow_slowpath"],
                "session_summary": {"status": "bad_key"},
                "ingress_detail": {"source_ip": "203.0.113.7", "destination_ip": "198.51.100.14",
                                   "source_port": 514, "destination_port": 514, "protocol": 17,
                                   "application": "undecided"},
            }
        ]
        cycles = [
            _cycle(
                1, 14.0,
                percentages={"packet_buffer_congestion": [14],
                             "resource_monitor_packet_descriptor_on_chip": [100]},
                ingress_backlogs={"dataplanes": [{"slot": "s1", "dp": "dp0", "atomic_percentage": 88, "total_percentage": 89}], "candidates": []},
            )
        ]
        diagnosis = _diagnose(cycles, attribution=attribution)
        backlogs = diagnosis["steps"][2]

        self.assertEqual(backlogs["state"], "positive")
        self.assertIn("Bad Key", backlogs["named"][0])
        self.assertIn("203.0.113.7:514 -&gt; 198.51.100.14:514", backlogs["named"][0])
        self.assertIn("traffic denied by policy and re-evaluated packet by packet", backlogs["verdict"])
        self.assertIn("undecided or unknown application", backlogs["verdict"])
        self.assertEqual(diagnosis["headline"]["label"], "Offender in the ingress backlog")

    def test_an_empty_backlog_on_x86_names_the_in_flight_work_metric(self):
        cycles = [_cycle(1, 60.0, ingress_backlogs={"dataplanes": [{"slot": "1", "dp": "0", "atomic_percentage": 0.0, "total_percentage": 0.0}], "candidates": []})]
        diagnosis = _diagnose(cycles, device={"model": "PA-440"})
        verdict = diagnosis["steps"][2]["verdict"]

        self.assertEqual(diagnosis["steps"][2]["state"], "negative")
        self.assertIn("in-flight work entries", verdict)
        self.assertIn("max-inflight-num", verdict)
        self.assertNotIn("hardware queue of the Cavium chassis", verdict)

    def test_an_empty_backlog_on_a_cavium_chassis_keeps_its_wording(self):
        cycles = [_cycle(1, 60.0, ingress_backlogs={"dataplanes": [{"slot": "1", "dp": "0", "atomic_percentage": 0.0, "total_percentage": 0.0}], "candidates": []})]
        diagnosis = _diagnose(cycles, device={"model": "PA-5220"})
        verdict = diagnosis["steps"][2]["verdict"]

        self.assertEqual(diagnosis["steps"][2]["state"], "negative")
        self.assertIn(
            "Whatever filled the buffers was not one session waiting in the queue",
            verdict,
        )
        self.assertNotIn("in-flight work entries", verdict)

    def test_a_vm_series_rejection_is_unavailable_and_not_a_negative(self):
        cycles = [
            _cycle(
                number,
                60.0,
                commands={"ingress_backlogs": dict(REJECTED_NODE)},
                ingress_backlogs={"dataplanes": [], "candidates": []},
            )
            for number in (1, 2)
        ]
        diagnosis = _diagnose(cycles, device={"model": "PA-VM"})
        step = diagnosis["steps"][2]

        self.assertEqual(step["state"], "unavailable")
        self.assertTrue(step["node_unsupported"])
        self.assertIn("not available on this platform", step["verdict"])
        self.assertIn("VM-Series out of that support", step["verdict"])
        self.assertIn("note about the platform, not a collection fault", step["verdict"])
        self.assertIn("show counter global filter delta yes", step["verdict"])
        self.assertNotIn("No session held", step["verdict"])
        self.assertEqual(dict(_facts(step))["Batches with the command"], "0")
        self.assertEqual(dict(_facts(step))["Batches without the node"], "2")
        self.assertIn(
            "not available on this platform",
            " ".join(diagnosis["conclusion"]),
        )

    def test_every_batch_rejecting_the_node_is_unavailable_on_any_platform(self):
        cycles = [
            _cycle(
                1,
                60.0,
                commands={"ingress_backlogs": dict(REJECTED_NODE)},
                ingress_backlogs={"dataplanes": [], "candidates": []},
            )
        ]
        diagnosis = _diagnose(cycles, device={"model": "PA-440"})
        step = diagnosis["steps"][2]

        self.assertEqual(step["state"], "unavailable")
        self.assertIn("rejected the command", step["verdict"])
        self.assertNotIn("No session held", step["verdict"])

    def test_a_vm_series_that_answers_is_read_from_its_data(self):
        """A returned answer is evidence, whatever the model is said to support."""
        cycles = [
            _cycle(
                1,
                60.0,
                commands={"ingress_backlogs": {"ok": True, "result": "<entry/>"}},
                ingress_backlogs={"dataplanes": [{"slot": "1", "dp": "0", "atomic_percentage": 12.0, "total_percentage": 14.0}], "candidates": []},
            )
        ]
        diagnosis = _diagnose(cycles, device={"model": "PA-VM"})
        step = diagnosis["steps"][2]

        self.assertEqual(step["state"], "negative")
        self.assertFalse(step["node_unsupported"])
        self.assertIn("in-flight work entries", step["verdict"])
        self.assertIn("queue peak ATOMIC 12%, TOTAL 14%", step["verdict"])
        self.assertNotIn("not available on this platform", step["verdict"])
        self.assertNotIn("left VM-Series out", step["verdict"])
        self.assertEqual(dict(_facts(step))["Batches with the command"], "1")

    def test_a_supported_platform_that_rejects_the_node_is_still_unavailable(self):
        """The firewall's answer decides, not the family the model belongs to."""
        cycles = [
            _cycle(
                1,
                60.0,
                commands={"ingress_backlogs": dict(REJECTED_NODE)},
                ingress_backlogs={"dataplanes": [], "candidates": []},
            )
        ]
        diagnosis = _diagnose(cycles, device={"model": "PA-5220"})
        step = diagnosis["steps"][2]

        self.assertEqual(step["state"], "unavailable")
        self.assertTrue(step["node_unsupported"])
        self.assertIn("answered that it has no", step["verdict"])
        self.assertNotIn("left VM-Series out", step["verdict"])

    def test_every_batch_failing_for_another_reason_is_a_failed_step(self):
        cycles = [
            _cycle(
                number,
                60.0,
                commands={"ingress_backlogs": dict(TIMED_OUT)},
                ingress_backlogs={"dataplanes": [], "candidates": []},
            )
            for number in (1, 2)
        ]
        diagnosis = _diagnose(cycles, device={"model": "PA-440"})
        step = diagnosis["steps"][2]

        self.assertEqual(step["state"], "failed")
        self.assertFalse(step["node_unsupported"])
        self.assertIn("failed in all 2 of the 2 batches", step["verdict"])
        self.assertNotIn("No session held", step["verdict"])
        # A step that could not be read is still reported, not dropped.
        findings = collect_findings(diagnosis)
        self.assertIn(
            "Session holding the ingress backlog",
            [item["title"] for item in findings["unavailable"]],
        )

    def test_a_timed_out_backlog_read_is_counted_as_a_failed_batch(self):
        cycles = [
            _cycle(
                1,
                60.0,
                commands={"ingress_backlogs": dict(TIMED_OUT)},
                ingress_backlogs={"dataplanes": [], "candidates": []},
            ),
            _cycle(
                2,
                60.0,
                commands={"ingress_backlogs": {"ok": True, "result": "<entry/>"}},
                ingress_backlogs={"dataplanes": [{"slot": "1", "dp": "0", "atomic_percentage": 0.0, "total_percentage": 0.0}], "candidates": []},
            ),
        ]
        diagnosis = _diagnose(cycles, device={"model": "PA-5220"})
        step = diagnosis["steps"][2]

        self.assertEqual(step["state"], "negative")
        self.assertFalse(step["node_unsupported"])
        self.assertIn("in any of the 1 batches that ran the command", step["verdict"])
        self.assertIn("failed for another reason in 1 of the 2 batches", step["verdict"])
        self.assertEqual(dict(_facts(step))["Batches with a failed read"], "1")

    def test_the_conclusion_says_the_read_failed_rather_than_was_not_collected(self):
        cycles = [
            _cycle(
                1,
                60.0,
                commands={"ingress_backlogs": dict(TIMED_OUT)},
                ingress_backlogs={"dataplanes": [], "candidates": []},
            )
        ]
        conclusion = " ".join(_diagnose(cycles, device={"model": "PA-440"})["conclusion"])

        self.assertIn("ingress backlog read failed in every batch", conclusion)
        self.assertIn("worth repairing", conclusion)
        self.assertNotIn("The ingress backlog was not collected", conclusion)

    def test_a_legacy_capture_without_the_raw_command_is_not_a_negative(self):
        """`extract_ingress_backlogs` returns a dict even for an empty answer."""
        cycles = [
            _cycle(number, 60.0, ingress_backlogs={"dataplanes": [], "candidates": []})
            for number in (1, 2)
        ]
        step = _diagnose(cycles, device={"model": "PA-440"})["steps"][2]

        self.assertEqual(step["state"], "unavailable")
        self.assertNotIn("No session held", step["verdict"])
        self.assertEqual(dict(_facts(step))["Batches with the command"], "0")

    def test_a_legacy_capture_that_carries_dataplanes_still_counts(self):
        cycles = [
            _cycle(1, 60.0, ingress_backlogs={"dataplanes": [{"slot": "1", "dp": "0", "atomic_percentage": 0.0, "total_percentage": 0.0}], "candidates": []})
        ]
        step = _diagnose(cycles, device={"model": "PA-440"})["steps"][2]

        self.assertEqual(step["state"], "negative")
        self.assertEqual(dict(_facts(step))["Batches with the command"], "1")

    def test_a_mixed_run_names_every_batch_that_answered_nothing(self):
        """The counts in the verdict must add up to the batches that asked."""
        cycles = [
            _cycle(1, 60.0, commands={"ingress_backlogs": {"ok": True, "result": "<entry/>"}},
                   ingress_backlogs={"dataplanes": [{"slot": "1", "dp": "0", "atomic_percentage": 1.0, "total_percentage": 2.0}], "candidates": []}),
            _cycle(2, 60.0, commands={"ingress_backlogs": dict(REJECTED_NODE)},
                   ingress_backlogs={"dataplanes": [], "candidates": []}),
            _cycle(3, 60.0, commands={"ingress_backlogs": dict(TIMED_OUT)},
                   ingress_backlogs={"dataplanes": [], "candidates": []}),
        ]
        step = _diagnose(cycles, device={"model": "PA-440"})["steps"][2]
        facts = dict(_facts(step))

        self.assertEqual(step["state"], "negative")
        self.assertIn("in any of the 1 batches that ran the command", step["verdict"])
        self.assertIn("rejected it as an absent node in 1", step["verdict"])
        self.assertIn("the read failed for another reason in 1", step["verdict"])
        self.assertIn("of the 3 batches", step["verdict"])
        self.assertEqual(facts["Batches with the command"], "1")
        self.assertEqual(facts["Batches without the node"], "1")
        self.assertEqual(facts["Batches with a failed read"], "1")

    def test_a_rejected_node_verdict_does_not_count_its_batches_twice(self):
        cycles = [
            _cycle(1, 60.0, commands={"ingress_backlogs": dict(REJECTED_NODE)},
                   ingress_backlogs={"dataplanes": [], "candidates": []}),
            _cycle(2, 60.0, commands={"ingress_backlogs": dict(TIMED_OUT)},
                   ingress_backlogs={"dataplanes": [], "candidates": []}),
        ]
        step = _diagnose(cycles, device={"model": "PA-VM"})["steps"][2]

        self.assertEqual(step["state"], "unavailable")
        self.assertIn("rejected in 1 of the 2 batches", step["verdict"])
        self.assertIn("the read failed for another reason in 1", step["verdict"])
        self.assertNotIn("rejected it as an absent node", step["verdict"])

    def test_a_capture_without_the_command_says_so(self):
        diagnosis = _diagnose([_cycle(1, 60.0)])

        self.assertEqual(diagnosis["steps"][2]["state"], "unavailable")
        self.assertFalse(diagnosis["steps"][2]["node_unsupported"])

    def _backlog_step(self, inflight: dict | None) -> dict:
        started = {
            "run_id": "diagnosis-run",
            "event": "monitor_started",
            "device": {"model": "PA-5220", "software_version": "10.2.9"},
        }
        if inflight is not None:
            started["inflight_monitoring"] = inflight
        return _diagnose([_cycle(1, 60.0)], [started])["steps"][2]

    def test_an_enabled_on_box_collection_names_the_tech_support_log(self):
        step = self._backlog_step(
            {
                "parsed": True,
                "enabled": True,
                "duration_seconds": 3,
                "threshold_percent": 80,
                "trigger_pending": False,
            }
        )

        self.assertIn(("On-box auto-collection", "enabled (80% for 3 s)", "none"), step["facts"])
        self.assertIn("on-box auto-collection was enabled", step["verdict"])
        self.assertIn("/var/log/pan/pan_ingress_backlogs.log", step["verdict"])
        self.assertIn("every 100 ms", step["verdict"])
        self.assertNotIn("set session inflight_monitoring yes", step["verdict"])

    def test_a_disabled_on_box_collection_recommends_the_operator_enable_it(self):
        step = self._backlog_step(
            {
                "parsed": True,
                "enabled": False,
                "duration_seconds": 3,
                "threshold_percent": 80,
                "trigger_pending": False,
            }
        )

        # Informational, not amber: disabled is the PAN-OS default and would
        # colour nearly every capture.
        self.assertIn(("On-box auto-collection", "disabled", "none"), step["facts"])
        self.assertIn("on-box auto-collection was disabled", step["verdict"])
        self.assertIn("set session inflight_monitoring yes", step["verdict"])
        # The collector stays observational: the report recommends, the
        # operator decides, and nothing here is done on the firewall.
        self.assertIn("the operator's decision", step["verdict"])

    def test_an_unread_on_box_collection_state_is_reported_as_unknown(self):
        step = self._backlog_step(None)

        self.assertIn(("On-box auto-collection", "not read", "none"), step["facts"])
        self.assertIn("on-box auto-collection state was not read", step["verdict"])
        self.assertNotIn("set session inflight_monitoring yes", step["verdict"])

    def test_a_release_without_the_feature_reads_differently_from_a_lost_read(self):
        # Nothing to enable, and the tech support file is known to hold no
        # pan_ingress_backlogs.log: that is an answer, not an unknown.
        step = self._backlog_step({"parsed": False, "status": "absent"})

        self.assertIn(
            ("On-box auto-collection", "not available on this PAN-OS release", "none"),
            step["facts"],
        )
        self.assertIn("is not available on this PAN-OS release", step["verdict"])
        self.assertIn("nothing to enable", step["verdict"])
        self.assertNotIn("was not read", step["verdict"])

    def test_a_partly_read_on_box_setting_is_never_asserted_as_the_firewalls(self):
        # Only the duration came back. The threshold shown is the PAN-OS
        # default, and every rendering must say so rather than presenting 80%
        # as a value this firewall returned.
        step = self._backlog_step(
            {"parsed": True, "status": "read", "enabled": True, "duration_seconds": 5}
        )

        self.assertIn(
            (
                "On-box auto-collection",
                "enabled (80% for 5 s, PAN-OS defaults: the nodes were not returned)",
                "none",
            ),
            step["facts"],
        )
        self.assertIn("PAN-OS defaults: the nodes were not returned", step["verdict"])

    def test_a_non_boolean_enabled_value_is_read_as_unknown_not_as_enabled(self):
        # A release answering something neither renderer expects must not be
        # reported as collecting the backlogs when it may not be.
        step = self._backlog_step(
            {"parsed": True, "status": "read", "enabled": "maybe"}
        )

        self.assertIn(("On-box auto-collection", "not read", "none"), step["facts"])
        self.assertIn("state was not read", step["verdict"])


class CommandOutcomeTests(unittest.TestCase):
    """One classification of a stored command record, shared by every reader."""

    def test_the_four_outcomes_are_told_apart_from_the_stored_record(self):
        self.assertEqual(
            command_outcome({"ok": True, "result": "<result/>"}, "ingress_backlogs"),
            "succeeded",
        )
        self.assertEqual(
            command_outcome(dict(REJECTED_NODE), "ingress_backlogs"), "unsupported"
        )
        self.assertEqual(
            command_outcome(dict(TIMED_OUT), "ingress_backlogs"), "failed"
        )
        self.assertEqual(command_outcome(None, "ingress_backlogs"), "missing")

    def test_only_a_platform_dependent_command_may_be_called_unsupported(self):
        """A mandatory command an old release rejects is a real gap, not a note."""
        self.assertEqual(
            command_outcome(dict(REJECTED_NODE), "packet_buffer_protection"), "failed"
        )

    def test_a_legacy_string_record_keeps_its_meaning(self):
        self.assertEqual(command_outcome("<result/>", "session_info"), "succeeded")
        self.assertEqual(command_outcome("ERROR: timed out", "session_info"), "failed")

    def test_the_counts_add_up_to_the_batches_that_asked(self):
        cycles = [
            _cycle(1, 60.0, commands={"ingress_backlogs": {"ok": True, "result": "<r/>"}}),
            _cycle(2, 60.0, commands={"ingress_backlogs": dict(REJECTED_NODE)}),
            _cycle(3, 60.0, commands={"ingress_backlogs": dict(TIMED_OUT)}),
            _cycle(4, 60.0),
        ]
        counts = command_outcomes(cycles, "ingress_backlogs")

        self.assertEqual(counts, {"batches": 3, "succeeded": 1, "unsupported": 1, "failed": 1})
        self.assertEqual(
            counts["batches"],
            counts["succeeded"] + counts["unsupported"] + counts["failed"],
        )

    def test_the_step_three_counter_is_the_same_helper(self):
        cycles = [
            _cycle(1, 60.0, commands={"ingress_backlogs": dict(TIMED_OUT)}),
            _cycle(2, 60.0, ingress_backlogs={"dataplanes": [{"slot": "1", "dp": "0"}], "candidates": []}),
        ]

        self.assertEqual(
            ingress_backlog_collection(cycles),
            {"batches": 2, "succeeded": 1, "unsupported": 0, "failed": 1},
        )

    def test_a_failed_read_marker_is_not_read_as_a_collected_field(self):
        self.assertIsNone(collected_field({"pbp_status": {"error": "TimeoutError: x"}}, "pbp_status"))
        self.assertIsNone(collected_field({}, "pbp_status"))
        self.assertEqual(
            collected_field({"pbp_status": {"active": False}}, "pbp_status"),
            {"active": False},
        )


class ElsewhereStepTests(unittest.TestCase):
    def test_an_isolated_hot_core_supports_the_elephant_hypothesis(self):
        diagnosis = _diagnose(
            [_cycle(1, 84.0)],
            cpu_verdicts=[{"dataplane": "dp0", "state": "isolated", "hottest_core": "3",
                           "hottest_value": 97, "median": 12}],
        )
        elsewhere = diagnosis["steps"][3]
        elephant = elsewhere["hypotheses"][0]

        self.assertEqual(elephant["state"], "positive")
        self.assertIn("dp0 core 3 peaked at 97%", elephant["text"])
        self.assertEqual(diagnosis["headline"]["label"], "Elephant session")

    def test_a_denied_burst_needs_a_rate_that_can_fill_buffers(self):
        few = _diagnose(
            [_cycle(1, 84.0)],
            drop_summary={"items": [{"family_key": "policy", "peak_rate": 2}],
                          "family_totals": {"policy": 71}, "denied_total": 71, "counted_batches": 50},
        )
        many = _diagnose(
            [_cycle(1, 84.0)],
            drop_summary={"items": [{"family_key": "policy", "peak_rate": 4200}],
                          "family_totals": {"policy": 90000}, "denied_total": 90000, "counted_batches": 5},
        )

        self.assertEqual(few["steps"][3]["hypotheses"][1]["state"], "negative")
        self.assertIn("far too few to fill a buffer pool", few["steps"][3]["hypotheses"][1]["text"])
        self.assertEqual(many["steps"][3]["hypotheses"][1]["state"], "positive")
        self.assertIn("refused 90000 packets before session setup", many["steps"][3]["hypotheses"][1]["text"])

    def test_flood_logs_corroborate_the_denied_burst(self):
        diagnosis = _diagnose(
            [_cycle(1, 62.0)],
            [{"event": "flood_corroboration", "metadata": {"destination_ip": "198.51.100.15"}}],
        )
        burst = diagnosis["steps"][3]["hypotheses"][1]

        self.assertEqual(burst["state"], "positive")
        self.assertIn("1 zone-protection or DoS flood log(s) corroborated the incident targeting 198.51.100.15", burst["text"])

    def test_interface_error_growth_is_a_hypothesis_of_its_own(self):
        cycles = [
            _cycle(1, 84.0, interface_counters={"ethernet1/1": {"counters": {"rx_missed_error": 10, "tx_error": 0}}}),
            _cycle(2, 85.0, interface_counters={"ethernet1/1": {"counters": {"rx_missed_error": 5010, "tx_error": 0}}}),
        ]
        moved = _diagnose(cycles)["steps"][3]["hypotheses"][3]
        still = _diagnose([cycles[0], cycles[0]])["steps"][3]["hypotheses"][3]

        self.assertEqual(moved["state"], "positive")
        self.assertIn("<code>ethernet1/1</code>: rx_missed_error +5000", moved["named"][0])
        self.assertEqual(still["state"], "negative")

    def test_low_pressure_lists_the_signals_without_blaming_them(self):
        diagnosis = _diagnose(
            [_cycle(1, 4.0)],
            cpu_verdicts=[{"dataplane": "dp0", "state": "isolated", "hottest_core": "1",
                           "hottest_value": 95, "median": 3}],
        )

        self.assertEqual(diagnosis["steps"][3]["state"], "negative")
        self.assertIn("would be a supported finding", diagnosis["steps"][3]["verdict"])
        self.assertEqual(diagnosis["headline"]["label"], "Low pressure")
        self.assertNotIn("Elephant session:", " ".join(diagnosis["conclusion"]))

    def test_a_session_table_that_never_answered_cannot_rule_out_a_storm(self):
        cycles = [
            _cycle(
                number,
                84.0,
                commands={"session_info": dict(TIMED_OUT)},
                session_info={"error": "TimeoutError: the read timed out"},
            )
            for number in (1, 2)
        ]
        diagnosis = _diagnose(cycles, attribution=[])
        storm = next(
            item
            for item in diagnosis["steps"][3]["hypotheses"]
            if item["key"] == "storm"
        )

        self.assertEqual(storm["state"], "unavailable")
        self.assertIn(
            "session table read failed in all 2 of the 2 batches", storm["text"]
        )
        self.assertIn(
            "neither confirmed nor excluded", storm["text"]
        )
        self.assertIn(
            "session table read failed in 2 of 2 batches",
            storm["unavailable_reason"],
        )
        self.assertIn(
            "Storm of new sessions",
            [item["title"] for item in collect_findings(diagnosis)["unavailable"]],
        )

    def test_a_failed_session_read_is_named_beside_the_denied_verdict(self):
        diagnosis = _diagnose(
            [
                _cycle(
                    1,
                    84.0,
                    commands={"session_info": dict(TIMED_OUT)},
                    session_info={"error": "TimeoutError: the read timed out"},
                )
            ],
            drop_summary={"items": [{"family_key": "policy", "peak_rate": 2}],
                          "family_totals": {"policy": 71}, "denied_total": 71,
                          "counted_batches": 50},
        )
        denied = next(
            item
            for item in diagnosis["steps"][3]["hypotheses"]
            if item["key"] == "denied"
        )

        # The counters answer this hypothesis on their own, so it keeps its
        # verdict; the corroboration it could not read is named, not implied.
        self.assertEqual(denied["state"], "negative")
        self.assertIn("session table read failed in all 1 of the 1 batches", denied["text"])

    def test_a_session_table_read_that_answered_still_rules_the_storm_out(self):
        diagnosis = _diagnose(
            [
                _cycle(
                    1,
                    84.0,
                    commands={"session_info": {"ok": True, "result": "<result/>"}},
                    session_info={"totals": {"allocated": 400, "cps": 4}},
                )
            ],
            session_series=[{"batch": 1, "allocated": 400, "cps": 4, "pps": 100}],
        )
        storm = next(
            item
            for item in diagnosis["steps"][3]["hypotheses"]
            if item["key"] == "storm"
        )

        self.assertEqual(storm["state"], "negative")
        self.assertIn("New connections peaked at 4/s", storm["text"])

    def test_real_pressure_with_no_cause_points_at_a_tech_support_file(self):
        diagnosis = _diagnose([_cycle(1, 91.0), _cycle(2, 90.0)])

        self.assertEqual(diagnosis["headline"]["label"], "No responsible party identified")
        self.assertIn("Tech Support File", diagnosis["headline"]["text"])
        self.assertIn("software-defect scenario", diagnosis["conclusion"][-1])


class CapturedEvidenceTests(unittest.TestCase):
    """Configured thresholds, buffer latency and threat logs feed the steps."""

    def _started(self, **settings: object) -> dict:
        base = {"status": "parsed", "enabled": True, "alert_percent": 50.0,
                "activate_percent": 80.0, "latency_alert_ms": 50.0,
                "latency_activate_ms": 200.0, "latency_max_tolerate_ms": 500.0}
        base.update(settings)
        return {"run_id": "r", "event": "monitor_started",
                "device": {"model": "PA-5220", "software_version": "10.2.9"},
                "pbp_settings": base}

    def test_configured_thresholds_win_over_the_syslog_text_and_the_defaults(self):
        diagnosis = _diagnose(
            [_cycle(1, 4.4, pbp_status={"enabled": True, "active": True, "congestion_percentage": 4.3})],
            [self._started(alert_percent=1.0, activate_percent=2.0),
             {"event": "trigger_received", "message": "(alert threshold is 1%)."}],
        )
        context = diagnosis["context"]
        pressure = diagnosis["steps"][0]

        self.assertEqual(context["alert_source"], "configuration")
        self.assertEqual(context["alert_percent"], 1.0)
        self.assertEqual(context["activate_percent"], 2.0)
        self.assertIn("with the activate threshold configured at 2%", pressure["verdict"])
        self.assertIn("alert 1% and activate 2%, read from the running configuration", pressure["facts"][-1][1])
        self.assertIn("alert 1% / activate 2% thresholds configured on the firewall", diagnosis["conclusion"][1])

    def test_a_read_taken_during_a_commit_is_contradicted_by_the_mitigation(self):
        """The lab case of 2026-08-30: the config read said 50/80 while PBP was
        already mitigating at 4%. The report states the contradiction; it must
        not name a cause the capture cannot prove, because a threshold set
        outside that xpath explains it just as well as a landing commit."""
        diagnosis = _diagnose(
            [_cycle(1, 4.4, pbp_status={"enabled": True, "active": True, "congestion_percentage": 4.3})],
            [self._started(alert_percent=50.0, activate_percent=80.0),
             {"event": "trigger_received", "message": "(alert threshold is 1%)."}],
        )
        context = diagnosis["context"]
        thresholds = diagnosis["steps"][0]["facts"][-1][1]

        self.assertEqual(context["alert_source"], "inconsistent")
        self.assertEqual(context["alert_percent"], 1.0)
        self.assertIn("yet PBP was mitigating at 4.3%, which it cannot do below its activate threshold", thresholds)
        self.assertIn("so the read does not describe the thresholds that were in force", thresholds)
        self.assertNotIn("commit", thresholds)
        self.assertIn("congestion log says alert 1%", thresholds)
        self.assertNotIn("configured at 80%", diagnosis["steps"][0]["verdict"])
        self.assertIn(
            "PBP's own mitigation contradicting the values it returned",
            diagnosis["conclusion"][1],
        )

    def test_an_incident_decaying_below_the_threshold_contradicts_nothing(self):
        """Congestion falling back while PBP is still listed active is decay.

        Only the level at which mitigation started can contradict the read; a
        later, lower batch must not make the report call a correct settings
        read inconsistent.
        """
        decaying = _diagnose(
            [
                _cycle(1, 85.0, pbp_status={"enabled": True, "active": True,
                                            "congestion_percentage": 85.0}),
                _cycle(2, 60.0, pbp_status={"enabled": True, "active": True,
                                            "congestion_percentage": 60.0}),
            ],
            [self._started(alert_percent=50.0, activate_percent=80.0)],
        )
        rounding = _diagnose(
            [_cycle(1, 80.0, pbp_status={"enabled": True, "active": True,
                                         "congestion_percentage": 79.4})],
            [self._started(alert_percent=50.0, activate_percent=80.0)],
        )
        lab = _diagnose(
            [_cycle(1, 4.4, pbp_status={"enabled": True, "active": True,
                                        "congestion_percentage": 4.3})],
            [self._started(alert_percent=50.0, activate_percent=80.0)],
        )

        self.assertEqual(decaying["context"]["alert_source"], "configuration")
        self.assertEqual(decaying["context"]["mitigating_from_percent"], 85.0)
        self.assertNotIn(
            "does not describe the thresholds that were in force",
            decaying["steps"][0]["facts"][-1][1],
        )
        self.assertEqual(rounding["context"]["alert_source"], "configuration")
        self.assertEqual(lab["context"]["alert_source"], "inconsistent")

    def test_settings_unreadable_at_start_are_stated_as_an_unknown_start(self):
        reread = {"event": "pbp_settings_reread", "changed_since_start": False,
                  "start_settings_unknown": True,
                  "pbp_settings": {"status": "parsed", "enabled": True,
                                   "alert_percent": 20.0, "activate_percent": 40.0}}
        diagnosis = _diagnose(
            [_cycle(1, 60.0)],
            [{"run_id": "r", "event": "monitor_started",
              "device": {"model": "PA-5220", "software_version": "10.2.9"},
              "pbp_settings": {"status": "unparsed"}},
             reread],
        )
        context = diagnosis["context"]
        thresholds = diagnosis["steps"][0]["facts"][-1][1]

        self.assertEqual(context["alert_source"], "configuration")
        self.assertEqual(context["activate_percent"], 40.0)
        self.assertTrue(context["settings_start_unknown"])
        self.assertFalse(context["settings_changed_during_run"])
        self.assertIn("the start-of-run settings are unknown", thresholds)
        self.assertNotIn("a commit landed during the incident", thresholds)

    def test_threat_logs_without_a_time_filter_never_confirm_the_incident(self):
        """An unbounded query returns the device's most recent PBP logs.

        They may belong to an earlier episode, so they corroborate at most:
        they must not designate a source or turn step 2 positive.
        """
        threat = {
            "event": "pbp_threat_logs", "ok": True, "time_bounded": False,
            "since_firewall_time": None,
            "entries": [
                {"threat_id": 8509, "source_ip": "203.0.113.9", "threat_name": "PBP IP Blocked"},
                {"threat_id": 8507, "source_ip": "203.0.113.9", "threat_name": "PBP Packet Drop"},
            ],
        }
        diagnosis = _diagnose(
            [_cycle(1, 84.0, pbp_status={"enabled": True, "active": False})],
            [self._started(), threat],
        )
        named = diagnosis["steps"][1]

        self.assertEqual(named["state"], "negative")
        self.assertEqual(named["named"], [])
        self.assertNotIn("threat log confirms it", named["verdict"])
        self.assertIn("could not be limited to the incident window", named["verdict"])
        self.assertIn("corroborate at best", named["verdict"])
        self.assertIn("not limited to the incident window", named["facts"][-1][1])
        self.assertEqual(named["facts"][-1][2], "ok")
        self.assertNotIn(
            "Source blocking and its collateral",
            [item["title"] for item in collect_findings(diagnosis)["confirmed"]],
        )

    def test_the_read_at_stop_wins_when_the_settings_changed(self):
        reread = {"event": "pbp_settings_reread", "changed_since_start": True,
                  "pbp_settings": {"status": "parsed", "enabled": True, "alert_percent": 1.0, "activate_percent": 2.0}}
        diagnosis = _diagnose(
            [_cycle(1, 4.4, pbp_status={"enabled": True, "active": True, "congestion_percentage": 4.3})],
            [self._started(alert_percent=50.0, activate_percent=80.0), reread],
        )
        context = diagnosis["context"]

        self.assertEqual(context["alert_source"], "configuration")
        self.assertEqual(context["activate_percent"], 2.0)
        self.assertTrue(context["settings_changed_during_run"])
        self.assertIn("a commit landed during the incident", diagnosis["steps"][0]["facts"][-1][1])

    def test_latency_above_the_activate_threshold_is_the_latency_case(self):
        cycles = [
            _cycle(1, 12.0, buffer_latency={"status": "parsed", "peak_ms": 260.0, "latest_ms": 240.0, "dataplanes": []}),
            _cycle(2, 11.0, buffer_latency={"status": "parsed", "peak_ms": 90.0, "latest_ms": 60.0, "dataplanes": []}),
        ]
        buffer_based = _diagnose(cycles, [self._started()])
        latency_based = _diagnose(
            [dict(cycle, pbp_status={"enabled": True, "active": True, "mode": "latency"}) for cycle in cycles],
            [self._started()],
        )

        self.assertEqual(buffer_based["context"]["latency_peak_ms"], 260.0)
        self.assertEqual(buffer_based["steps"][0]["state"], "positive")
        self.assertIn("Dataplane latency reached 260 ms while the buffers stayed at 12%", buffer_based["steps"][0]["verdict"])
        self.assertIn("runs buffer-based PBP, which does not see it", buffer_based["steps"][0]["verdict"])
        self.assertIn("mitigating on latency rather than on buffer utilization", latency_based["steps"][0]["verdict"])
        self.assertEqual(buffer_based["steps"][0]["facts"][-1][0], "Buffer latency peak")
        self.assertEqual(buffer_based["steps"][0]["facts"][-1][2], "bad")

    def test_threat_logs_designate_when_no_batch_caught_a_red_entry(self):
        threat = {
            "event": "pbp_threat_logs", "ok": True, "time_bounded": True,
            "since_firewall_time": "2026/08/30 09:59:00",
            "entries": [
                {"threat_id": 8509, "source_ip": "203.0.113.9", "threat_name": "PBP IP Blocked"},
                {"threat_id": 8507, "source_ip": "203.0.113.9", "threat_name": "PBP Packet Drop"},
                {"threat_id": 8507, "source_ip": "203.0.113.7", "threat_name": "PBP Packet Drop"},
            ],
        }
        diagnosis = _diagnose(
            [_cycle(1, 84.0, pbp_status={"enabled": True, "active": False})],
            [self._started(), threat],
        )
        named = diagnosis["steps"][1]

        self.assertEqual(named["state"], "positive")
        self.assertIn("but the firewall's threat log did", named["verdict"])
        self.assertIn("2 × PBP Packet Drop (8507), 1 × PBP IP Blocked (8509)", named["verdict"])
        self.assertIn("<code>203.0.113.9</code> was placed in the block table (8509)", named["verdict"])
        self.assertEqual(named["named"][0], "source IP <code>203.0.113.9</code> — PBP Packet Drop, PBP IP Blocked")
        self.assertEqual(diagnosis["headline"]["label"], "Offender named by the firewall")
        self.assertEqual(named["facts"][-1][0], "PBP threat logs")

    def test_a_failed_threat_query_is_stated_not_hidden(self):
        diagnosis = _diagnose(
            [_cycle(1, 84.0)],
            [self._started(), {"event": "pbp_threat_logs", "ok": False, "error": "log job 60 did not finish within 20s"}],
        )

        self.assertEqual(diagnosis["steps"][1]["facts"][-1][1], "query failed: log job 60 did not finish within 20s")

    def test_the_report_renders_the_latency_table_and_the_threat_log_section(self):
        html = _render(
            [
                self._started(),
                _cycle(1, 60.0, buffer_latency={"status": "parsed", "peak_ms": 7.0, "latest_ms": 3.0,
                                                "dataplanes": [{"dataplane": "s1.dp0", "enabled": True, "latest_ms": 3.0,
                                                                "last_avg_ms": [2.0, 1.0], "last_max_ms": [7.0, 4.0]}]}),
                _cycle(2, 61.0, buffer_latency={"status": "parsed", "peak_ms": 5.0, "latest_ms": 5.0, "dataplanes": []}),
                {"run_id": "r", "event": "pbp_threat_logs", "ok": True, "since_firewall_time": "2026/08/30 12:04:06",
                 "entries": [{"receive_time": "2026/08/30 12:15:26", "threat_id": 8507, "threat_name": "PBP Packet Drop",
                              "source_ip": "203.0.113.7", "destination_ip": "0.0.0.0", "source_port": "0",
                              "destination_port": "0", "protocol": "tcp", "application": "not-applicable",
                              "from_zone": "LAN", "action": "drop", "session_id": "0", "repeat_count": "1"}]},
            ]
        )

        self.assertIn("<h3>Buffer latency</h3>", html)
        self.assertIn("<td>s1.dp0</td>", html)
        self.assertIn('href="#pbp-threat-logs-title"', html)
        self.assertIn("PBP threat logs", html)
        self.assertIn("1 entries since 2026/08/30 12:04:06 on the firewall clock", html)
        self.assertIn("8507 <span class=\"muted\">PBP Packet Drop</span>", html)
        self.assertIn("buffer latency peak 7 ms", html)
        self.assertIn("configured alert 50% · activate 80%", html)

    def test_rows_collected_before_a_disabled_batch_are_not_dropped(self):
        """One batch reporting "disabled" late in the run must not make the
        report throw away per-dataplane rows already collected from earlier
        batches: that is the same evidence the diagnosis used for
        latency_peak_ms, and the two must not disagree about whether latency
        was measured."""
        html = _render(
            [
                self._started(),
                _cycle(1, 60.0, buffer_latency={
                    "status": "parsed", "peak_ms": 7.0, "latest_ms": 3.0,
                    "dataplanes": [{"dataplane": "s1.dp0", "enabled": True, "latest_ms": 3.0,
                                    "last_avg_ms": [2.0, 1.0], "last_max_ms": [7.0, 4.0]}],
                }),
                _cycle(2, 61.0, buffer_latency={"status": "disabled", "dataplanes": []}),
            ]
        )

        self.assertIn("<h3>Buffer latency</h3>", html)
        self.assertIn("<td>s1.dp0</td>", html)
        self.assertIn("buffer latency peak 7 ms", html)
        self.assertIn("Measurement status changed during the run", html)

    def test_ingress_backlog_peak_table_names_each_metrics_own_batch(self):
        """ATOMIC and TOTAL must peak independently. Batch 2 has the real
        ATOMIC peak (90) and batch 5 has the real TOTAL peak (70); a single
        shared "Peak batch" column stamped by whichever metric moved last
        would print batch 5 next to a 90 it never reached."""
        html = _render(
            [
                self._started(),
                _cycle(1, 10.0, ingress_backlogs={
                    "dataplanes": [{"slot": "1", "dp": "0", "atomic_percentage": 20, "total_percentage": 10}],
                    "candidates": [],
                }),
                _cycle(2, 10.0, ingress_backlogs={
                    "dataplanes": [{"slot": "1", "dp": "0", "atomic_percentage": 90, "total_percentage": 40}],
                    "candidates": [],
                }),
                _cycle(3, 10.0, ingress_backlogs={
                    "dataplanes": [{"slot": "1", "dp": "0", "atomic_percentage": 30, "total_percentage": 20}],
                    "candidates": [],
                }),
                _cycle(4, 10.0, ingress_backlogs={
                    "dataplanes": [{"slot": "1", "dp": "0", "atomic_percentage": 10, "total_percentage": 30}],
                    "candidates": [],
                }),
                _cycle(5, 10.0, ingress_backlogs={
                    "dataplanes": [{"slot": "1", "dp": "0", "atomic_percentage": 40, "total_percentage": 70}],
                    "candidates": [],
                }),
            ]
        )

        self.assertIn("Peak ATOMIC %", html)
        self.assertIn("Peak TOTAL %", html)
        self.assertNotIn("<th>Peak batch</th>", html)
        queue_table = html[html.index("Peak ATOMIC %") : html.index("Peak ATOMIC %") + 800]
        self.assertIn(">90<br><span class=\"muted\">batch 2</span>", queue_table)
        self.assertIn(">70<br><span class=\"muted\">batch 5</span>", queue_table)
        self.assertNotIn(">90<br><span class=\"muted\">batch 5</span>", queue_table)


def _signal_summary(**families: list[dict]) -> dict:
    return {
        "families": [
            {"key": key, "label": key, "note": "", "counters": counters}
            for key, counters in families.items()
        ],
        "counted_batches": 2,
    }


def _signal(name: str, total: float, peak_rate: float) -> dict:
    return {"name": name, "total": total, "peak_rate": peak_rate, "batches": 2}


class SignatureTests(unittest.TestCase):
    """Corpus signatures fire on positive evidence and never claim negatives."""

    def _hypotheses(self, diagnosis: dict) -> dict[str, dict]:
        step = next(s for s in diagnosis["steps"] if s["key"] == "elsewhere")
        return {h["key"]: h for h in step["hypotheses"]}

    def test_no_corpus_signature_appears_without_its_evidence(self):
        diagnosis = _diagnose([_cycle(1, 85.0), _cycle(2, 86.0)])

        keys = set(self._hypotheses(diagnosis))
        self.assertTrue(
            keys.isdisjoint(
                {
                    "l2_storm",
                    "fragmentation",
                    "proxy_retransmit",
                    "held_resources",
                    "unprotected_flood",
                    "chassis_imbalance",
                    "session_collapse",
                    "block_collateral",
                    "recent_boot",
                }
            ),
            keys,
        )

    def test_an_arp_storm_names_the_l2_remedy_and_the_reboot_futility(self):
        diagnosis = _diagnose(
            [_cycle(1, 99.0), _cycle(2, 99.0)],
            signal_summary=_signal_summary(
                arp_storm=[
                    _signal("flow_arp_pkt_rcv", 1_534_439_152, 465_000),
                    _signal("flow_arp_rcv_gratuitous", 1_534_411_208, 465_000),
                ]
            ),
        )

        hypothesis = self._hypotheses(diagnosis)["l2_storm"]
        self.assertEqual(hypothesis["state"], "positive")
        self.assertIn("gratuitous", hypothesis["text"])
        self.assertIn("reboot changes nothing", hypothesis["text"])
        self.assertIn("show counter interface all", hypothesis["text"])

    def test_fragmentation_with_allocation_errors_is_exhaustion_not_usage(self):
        diagnosis = _diagnose(
            [_cycle(1, 92.0)],
            signal_summary=_signal_summary(
                fragmentation=[
                    _signal("flow_ipfrag_recv", 728_739_507, 515),
                    _signal("flow_ipfrag_merge", 153_011_417, 99),
                    _signal("flow_ipfrag_pkt_alloc_err", 1_745_926, 0),
                ],
                allocation_failure=[_signal("pkt_alloc_failure", 2_344_949, 0)],
            ),
        )

        hypothesis = self._hypotheses(diagnosis)["fragmentation"]
        self.assertIn("exhausting the pool", hypothesis["text"])
        self.assertIn("discard-ip-frag", hypothesis["text"])

    def test_proxy_retransmit_pressure_warns_against_blocking_victims(self):
        cycles = [_cycle(1, 80.0)]
        cycles[0]["percentages"]["resource_monitor_packet_descriptor_on_chip"] = [97.0]
        diagnosis = _diagnose(
            cycles,
            signal_summary=_signal_summary(
                proxy_retransmit=[_signal("tcp_fptcp_rxmt", 354_765, 500)]
            ),
        )

        hypothesis = self._hypotheses(diagnosis)["proxy_retransmit"]
        self.assertIn("97", hypothesis["text"])
        self.assertIn("punishes victims", hypothesis["text"])

    def test_held_pools_and_decoupled_buffers_state_the_leak_signature(self):
        session_series = [
            {"allocated": 6016.0, "pps": 618.0, "cps": 5.0, "utilization": 1.0}
        ] * 3
        diagnosis = _diagnose(
            [_cycle(1, 85.0), _cycle(2, 86.0), _cycle(3, 86.0)],
            session_series=session_series,
            diagnostic_pools=[
                {
                    "name": "Timer Pool",
                    "dataplane": "s1dp0",
                    "used_percentage": 99.9,
                    "available": 3,
                    "total": 4096,
                }
            ],
        )

        hypothesis = self._hypotheses(diagnosis)["held_resources"]
        self.assertIn("held, not processed", hypothesis["text"])
        self.assertIn("pan_task", hypothesis["text"])
        self.assertIn("SSL-proxy leak class", hypothesis["text"])
        self.assertIn("Timer Pool", hypothesis["named"][0])

    def test_a_full_packet_buffer_pool_under_pressure_is_the_flood_not_a_leak(self):
        """The packet-buffer pool is full because the buffers are: that is the
        incident, not memory nobody frees. The leak signature must not fire on
        it while the buffers are under pressure, and must still fire on the
        same pool when they are not."""
        pools = [
            {
                "name": "Packet Buffers",
                "dataplane": "s1dp0",
                "used_percentage": 84.8,
                "available": 14_785,
                "total": 97_280,
            }
        ]
        flood = _diagnose(
            [_cycle(1, 92.0), _cycle(2, 93.0)],
            cpu_verdicts=[{"dataplane": "s1.dp0", "state": "collective",
                           "hottest_core": "3", "hottest_value": 95, "median": 90}],
            signal_summary=_signal_summary(
                arp_storm=[_signal("flow_arp_pkt_rcv", 1_534_439_152, 465_000)]
            ),
            diagnostic_pools=pools,
        )
        idle = _diagnose(
            [_cycle(1, 12.0), _cycle(2, 12.0)],
            diagnostic_pools=pools,
        )

        self.assertNotIn("held_resources", self._hypotheses(flood))
        self.assertNotIn(
            "Held resources (leak signature)",
            [item["title"] for item in collect_findings(flood)["confirmed"]],
        )
        self.assertIn("held, not processed", self._hypotheses(idle)["held_resources"]["text"])

    def test_pbp_dropping_with_silent_zone_counters_suspects_the_zone(self):
        session_series = [
            {"allocated": 1000.0, "pps": 1000.0, "cps": 10.0, "utilization": 1.0},
            {"allocated": 1050.0, "pps": 30_000.0, "cps": 20.0, "utilization": 1.0},
        ]
        diagnosis = _diagnose(
            [_cycle(1, 97.0), _cycle(2, 97.0)],
            session_series=session_series,
            signal_summary=_signal_summary(
                pbp=[_signal("flow_dos_pbp_drop", 46_940_350, 641)]
            ),
        )

        hypothesis = self._hypotheses(diagnosis)["unprotected_flood"]
        self.assertIn("no zone-protection flood counter moved", hypothesis["text"])
        self.assertIn("show zone-protection", hypothesis["text"])

    def test_one_saturated_dataplane_beside_an_idle_median_is_named(self):
        record = _cycle(1, 92.0)
        record["percentages"]["resource_monitor_dataplanes"] = [
            {"dataplane": "s2dp1", "packet_buffer": 92.0},
            {"dataplane": "s8dp0", "packet_buffer": 7.0},
            {"dataplane": "s9dp0", "packet_buffer": 6.0},
        ]
        diagnosis = _diagnose([record])

        hypothesis = self._hypotheses(diagnosis)["chassis_imbalance"]
        self.assertIn("s2dp1", hypothesis["text"])
        self.assertIn("not capacity", hypothesis["text"])

    def test_two_dataplane_chassis_can_fire_the_imbalance_signature(self):
        """The median must describe the peer dataplanes only. Folding the
        saturated dataplane into its own baseline means a 2-DP chassis's
        median can never fall at or below the imbalance threshold (95 and 3
        average to 49), so the textbook case — one DP pinned, the other
        idle — could never be named at all."""
        record = _cycle(1, 95.0)
        record["percentages"]["resource_monitor_dataplanes"] = [
            {"dataplane": "dp0", "packet_buffer": 95.0},
            {"dataplane": "dp1", "packet_buffer": 3.0},
        ]
        diagnosis = _diagnose([record])

        hypothesis = self._hypotheses(diagnosis)["chassis_imbalance"]
        self.assertIn("dp0", hypothesis["text"])
        self.assertIn("95", hypothesis["text"])

    def test_a_balanced_two_dataplane_chassis_does_not_fire_the_imbalance_signature(self):
        record = _cycle(1, 90.0)
        record["percentages"]["resource_monitor_dataplanes"] = [
            {"dataplane": "dp0", "packet_buffer": 90.0},
            {"dataplane": "dp1", "packet_buffer": 85.0},
        ]
        diagnosis = _diagnose([record])

        self.assertNotIn("chassis_imbalance", self._hypotheses(diagnosis))

    def test_sessions_draining_under_a_pinned_buffer_is_terminal(self):
        session_series = [
            {"allocated": 477_120.0, "pps": 1000.0, "cps": 100.0, "utilization": 5.0},
            {"allocated": 90_000.0, "pps": 400.0, "cps": 10.0, "utilization": 1.0},
        ]
        diagnosis = _diagnose(
            [_cycle(1, 87.0), _cycle(2, 87.0)],
            session_series=session_series,
        )

        hypothesis = self._hypotheses(diagnosis)["session_collapse"]
        self.assertIn("no longer admitting sessions", hypothesis["text"])

    def test_blocked_sources_are_named_with_their_collateral(self):
        events = [
            {
                "run_id": "r",
                "event": "pbp_threat_logs",
                "ok": True,
                "time_bounded": True,
                "since_firewall_time": "2026/08/30 09:59:00",
                "entries": [{"threat_id": 8509, "source_ip": "198.51.100.9"}],
            }
        ]
        diagnosis = _diagnose(
            [_cycle(1, 97.0)],
            events,
            signal_summary=_signal_summary(
                pbp=[_signal("flow_dos_pbp_block_host", 17, 0)],
                block_collateral=[_signal("flow_dos_drop_ip_blocked", 3_402_125, 39)],
            ),
        )

        hypothesis = self._hypotheses(diagnosis)["block_collateral"]
        self.assertIn("3402125", hypothesis["text"].replace(" ", "").replace(",", ""))
        self.assertIn("198.51.100.9", hypothesis["named"][0])
        self.assertIn("NAT gateway", hypothesis["text"])

    def test_a_fresh_boot_raises_the_known_issue_hypothesis(self):
        diagnosis = _diagnose(
            [_cycle(1, 87.0)],
            device={
                "model": "PA-5250",
                "software_version": "11.2.10-h6",
                "uptime": "0 days, 21:24:13",
            },
        )

        hypothesis = self._hypotheses(diagnosis)["recent_boot"]
        self.assertIn("0 days, 21:24:13", hypothesis["text"])
        self.assertIn("11.2.10-h6", hypothesis["text"])
        self.assertIn("known issue", hypothesis["text"])

    def test_a_backup_elephant_is_guarded_against_blocking(self):
        diagnosis = _diagnose(
            [_cycle(1, 97.0), _cycle(2, 97.0)],
            large_sessions={
                "status": "collected",
                "sessions": [
                    {
                        "session_id": 4242,
                        "source_ip": "100.64.1.229",
                        "destination_ip": "100.64.1.230",
                        "destination_port": 1556,
                        "application": "netbackup",
                        "peak_bits_per_second": 4.0e9,
                        "batches": 2,
                    }
                ],
            },
        )

        step = next(s for s in diagnosis["steps"] if s["key"] == "elsewhere")
        elephant = next(h for h in step["hypotheses"] if h["key"] == "elephant")
        self.assertIn("netbackup", elephant["text"])
        self.assertIn("backup window", elephant["text"])
        self.assertIn("media server", elephant["text"])


class UnusableNumberTests(unittest.TestCase):
    """A number no float can hold is skipped, never fatal."""

    def test_an_integer_too_large_to_convert_does_not_lose_the_report(self):
        """JSON integers have no upper bound; a float has one.

        A corrupted line, or a firewall answering with an absurd value, used to
        render fine in the evidence tables of the flat report and abort the
        diagnosis of the very same capture.
        """
        oversized = int("9" * 400)
        diagnosis = _diagnose(
            [
                _cycle(1, 61.0),
                {
                    "timestamp": "2026-08-30T10:02:00+00:00",
                    "run_id": "diagnosis-run",
                    "cycle": 2,
                    "elapsed_seconds": 20.0,
                    "percentages": {"packet_buffer_congestion": [oversized]},
                    "commands": {},
                },
            ]
        )

        pressure = next(s for s in diagnosis["steps"] if s["key"] == "pressure")
        self.assertEqual(pressure["buffer_peak"], 61.0)

    def test_the_flat_report_renders_the_same_capture(self):
        html = _render(
            [
                _cycle(1, 61.0),
                {
                    "timestamp": "2026-08-30T10:02:00+00:00",
                    "run_id": "diagnosis-run",
                    "cycle": 2,
                    "elapsed_seconds": 20.0,
                    "percentages": {"packet_buffer_congestion": [int("9" * 400)]},
                    "commands": {},
                },
            ]
        )

        self.assertIn("PBP Report", html)


class CounterRegistryTests(unittest.TestCase):
    """The signatures and the family table read one registry of counters."""

    def test_no_signature_reads_a_counter_the_family_table_ignores(self):
        """A threshold on a counter nobody aggregates can never fire.

        Nothing in a report would say so: the signature would simply stay
        silent, and the incident class it encodes would go unnamed.
        """
        declared = {
            str(definition["family"]): set(definition["names"])
            for definition in SIGNAL_COUNTER_FAMILIES
        }

        self.assertTrue(HYPOTHESIS_COUNTERS)
        for family, groups in HYPOTHESIS_COUNTERS.items():
            self.assertIn(family, declared)
            for role, names in groups.items():
                self.assertTrue(names, f"{family}.{role}")
                for name in names:
                    with self.subTest(family=family, role=role, counter=name):
                        self.assertIn(name, declared[family])

    def test_the_report_family_table_reads_the_same_registry(self):
        """One registry, not a second copy the report keeps for itself."""
        self.assertIs(_SIGNAL_COUNTER_FAMILIES, SIGNAL_COUNTER_FAMILIES)


def _started(**extra: object) -> dict:
    record: dict = {
        "timestamp": "2026-08-30T09:59:00+00:00",
        "run_id": "diagnosis-run",
        "event": "monitor_started",
        "device": {"model": "PA-5220", "software_version": "10.2.9"},
    }
    record.update(extra)
    return record


def _history(*, series: list[float], window: str = "day") -> dict:
    return {
        "parsed": True,
        "windows": [
            {
                "dataplane": "dp0",
                "window": window,
                "metrics": {
                    "packet_buffer": {
                        "maximum_series": series,
                        "maximum": {
                            "latest": series[0],
                            "oldest": series[-1],
                            "peak": max(series),
                            "mean": round(sum(series) / len(series), 3),
                            "samples": len(series),
                        },
                    },
                    "session": {
                        "maximum": {
                            "latest": 1.0,
                            "oldest": 1.0,
                            "peak": 1.0,
                            "mean": 1.0,
                            "samples": len(series),
                        }
                    },
                },
                "cpu": {"maximum_peak": 20.0},
            }
        ],
    }


def _congestion(times: list[str]) -> dict:
    return {
        "timestamp": "2026-08-30T10:30:00+00:00",
        "run_id": "diagnosis-run",
        "event": "congestion_system_logs",
        "ok": True,
        "entries": [
            {"time_generated": moment, "percent": 72.0} for moment in times
        ],
    }


class IncidentStateSignatureTests(unittest.TestCase):
    """The findings the once-per-incident state and history reads unlock.

    None of them can be derived from the per-batch loop: a leak and a flood
    end at the same percentage, an unprotected zone is invisible to every
    counter, and a passive unit looks exactly like a leaking active one.
    """

    def _hypothesis(self, diagnosis: dict, key: str) -> dict | None:
        return next(
            (
                hypothesis
                for step in diagnosis["steps"]
                for hypothesis in step.get("hypotheses") or []
                if hypothesis["key"] == key
            ),
            None,
        )

    def test_a_level_that_only_climbed_is_named_a_leak_not_a_flood(self):
        diagnosis = _diagnose(
            [_cycle(1, 91.0), _cycle(2, 92.0)],
            [
                _started(
                    resource_monitor_history=_history(
                        series=[88.0, 70.0, 52.0, 33.0, 12.0, 11.0]
                    )
                )
            ],
        )
        finding = self._hypothesis(diagnosis, "buffer_leak_history")

        self.assertIsNotNone(finding)
        self.assertEqual(finding["state"], "positive")
        self.assertIn("only ever rose", finding["text"])
        self.assertIn("session table stayed near empty", finding["text"])
        self.assertEqual(diagnosis["context"]["buffer_history"]["shape"], "climbing")

    def test_a_level_that_spiked_and_recovered_is_not_called_a_leak(self):
        diagnosis = _diagnose(
            [_cycle(1, 91.0)],
            [
                _started(
                    resource_monitor_history=_history(
                        series=[4.0, 88.0, 5.0, 4.0, 4.0, 4.0]
                    )
                )
            ],
        )

        self.assertIsNone(self._hypothesis(diagnosis, "buffer_leak_history"))
        self.assertEqual(diagnosis["context"]["buffer_history"]["shape"], "burst")

    def test_a_capture_without_the_history_claims_nothing_about_a_trend(self):
        diagnosis = _diagnose([_cycle(1, 91.0)], [_started()])

        self.assertIsNone(self._hypothesis(diagnosis, "buffer_leak_history"))
        self.assertEqual(
            diagnosis["context"]["buffer_history"]["shape"], "unavailable"
        )

    def test_pbp_dropping_in_a_zone_with_no_flood_protection_is_named(self):
        diagnosis = _diagnose(
            [_cycle(1, 91.0)],
            [
                _started(
                    zone_protection={
                        "parsed": True,
                        "zones": [
                            {
                                "zone": "INTERNET",
                                "profile": "Default_Zone_Protection",
                                "flood_protection": {"tcp": False, "udp": False},
                                "flood_protection_enabled": False,
                                "pbp_drop": 3984,
                                "pbp_counters": {"pbp_drop": 3984},
                            }
                        ],
                    }
                )
            ],
        )
        finding = self._hypothesis(diagnosis, "unprotected_zone")

        self.assertIsNotNone(finding)
        self.assertIn("every flood type disabled", finding["text"])
        self.assertIn("INTERNET", finding["named"][0])

    def test_a_protected_zone_raises_no_unprotected_finding(self):
        diagnosis = _diagnose(
            [_cycle(1, 91.0)],
            [
                _started(
                    zone_protection={
                        "parsed": True,
                        "zones": [
                            {
                                "zone": "INTERNET",
                                "flood_protection": {"tcp": True},
                                "flood_protection_enabled": True,
                                "pbp_drop": 3984,
                                "pbp_counters": {"pbp_drop": 3984},
                            }
                        ],
                    }
                )
            ],
        )

        self.assertIsNone(self._hypothesis(diagnosis, "unprotected_zone"))

    def test_the_same_three_hours_every_night_reads_as_a_schedule(self):
        nights = [
            f"2026/08/{day:02d} 03:{minute:02d}:34"
            for day in range(20, 27)
            for minute in (0, 20, 40)
        ]
        diagnosis = _diagnose([_cycle(1, 91.0)], [_started(), _congestion(nights)])
        finding = self._hypothesis(diagnosis, "scheduled_recurrence")

        self.assertIsNotNone(finding)
        self.assertIn("does not keep office hours", finding["text"])
        recurrence = diagnosis["context"]["recurrence"]
        self.assertEqual(recurrence["dated_entries"], 21)
        self.assertTrue(recurrence["peak_window"]["scheduled"])
        self.assertEqual(recurrence["peak_window"]["start_hour"], 3)

    def test_congestion_spread_over_the_day_is_not_called_a_schedule(self):
        spread = [
            f"2026/08/20 {hour:02d}:10:00" for hour in range(24)
        ]
        diagnosis = _diagnose([_cycle(1, 91.0)], [_started(), _congestion(spread)])

        self.assertIsNone(self._hypothesis(diagnosis, "scheduled_recurrence"))
        self.assertFalse(
            diagnosis["context"]["recurrence"]["peak_window"]["scheduled"]
        )

    def test_a_passive_unit_is_stated_before_anything_else_is_read(self):
        diagnosis = _diagnose(
            [_cycle(1, 99.0)],
            [
                _started(
                    ha_state={
                        "parsed": True,
                        "enabled": True,
                        "local_state": "passive",
                        "peer_state": "active",
                        "passive": True,
                    }
                )
            ],
        )
        finding = self._hypothesis(diagnosis, "passive_ha_unit")

        self.assertIsNotNone(finding)
        self.assertIn("forwards no production traffic", finding["text"])
        self.assertTrue(diagnosis["context"]["ha"]["passive"])

    def test_an_active_unit_raises_no_passive_finding(self):
        diagnosis = _diagnose(
            [_cycle(1, 99.0)],
            [
                _started(
                    ha_state={
                        "parsed": True,
                        "enabled": True,
                        "local_state": "active",
                        "passive": False,
                    }
                )
            ],
        )

        self.assertIsNone(self._hypothesis(diagnosis, "passive_ha_unit"))

    def test_the_new_findings_all_point_at_a_section_of_the_report(self):
        html = _render(
            [
                _started(
                    resource_monitor_history=_history(
                        series=[88.0, 70.0, 52.0, 33.0, 12.0, 11.0]
                    ),
                    zone_protection={
                        "parsed": True,
                        "zones": [
                            {
                                "zone": "INTERNET",
                                "flood_protection": {"tcp": False},
                                "flood_protection_enabled": False,
                                "pbp_drop": 3984,
                                "pbp_counters": {"pbp_drop": 3984},
                            }
                        ],
                    },
                    ha_state={
                        "parsed": True,
                        "enabled": False,
                    },
                ),
                _cycle(1, 91.0),
                _cycle(2, 92.0),
            ]
        )

        self.assertIn('id="history-title"', html)
        self.assertIn('id="zones-title"', html)
        self.assertIn("only ever rose", html)
        self.assertIn("every flood type is disabled", html)


if __name__ == "__main__":
    unittest.main()
