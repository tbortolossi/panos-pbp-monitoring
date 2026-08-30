"""The report walks the PBP investigation and never contradicts itself."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pbp_monitoring.diagnosis import build_diagnosis, hardware_generation
from pbp_monitoring.reporting import generate_html_report


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


class IngressBacklogStepTests(unittest.TestCase):
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

    def test_an_empty_backlog_on_x86_is_not_read_as_proof(self):
        cycles = [_cycle(1, 60.0, ingress_backlogs={"dataplanes": [{"slot": "1", "dp": "0", "atomic_percentage": 0.0, "total_percentage": 0.0}], "candidates": []})]
        diagnosis = _diagnose(cycles, device={"model": "PA-440"})

        self.assertEqual(diagnosis["steps"][2]["state"], "negative")
        self.assertIn("an empty result is not proof", diagnosis["steps"][2]["verdict"])

    def test_a_capture_without_the_command_says_so(self):
        diagnosis = _diagnose([_cycle(1, 60.0)])

        self.assertEqual(diagnosis["steps"][2]["state"], "unavailable")


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
        self.assertIn("would be supported", diagnosis["steps"][3]["verdict"])
        self.assertEqual(diagnosis["headline"]["label"], "Low pressure")
        self.assertNotIn("Elephant session:", " ".join(diagnosis["conclusion"]))

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
        """The lab case of 2026-08-30: monitor started mid-commit, config read
        said 50/80 while PBP was already mitigating at 4%."""
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
        self.assertIn("while a commit was landing", thresholds)
        self.assertIn("congestion log says alert 1%", thresholds)
        self.assertNotIn("configured at 80%", diagnosis["steps"][0]["verdict"])
        self.assertIn("a commit was landing when the monitor started", diagnosis["conclusion"][1])

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
            "event": "pbp_threat_logs", "ok": True,
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
        self.assertIn("Step 2 · PBP threat logs", html)
        self.assertIn("1 entries since 2026/08/30 12:04:06 on the firewall clock", html)
        self.assertIn("8507 <span class=\"muted\">PBP Packet Drop</span>", html)
        self.assertIn("buffer latency peak 7 ms", html)
        self.assertIn("configured alert 50% · activate 80%", html)


if __name__ == "__main__":
    unittest.main()
