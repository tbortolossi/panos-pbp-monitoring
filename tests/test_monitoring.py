import asyncio
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from pbp_monitoring.orchestrator import (
    CLOCK_COMMAND,
    OP_COMMANDS,
    SYSTEM_INFO_COMMAND,
    Config,
    MultiTargetRouter,
    MonitorController,
    PanOSAPIError,
    PanOSResponse,
    SyslogProtocol,
    TargetProfile,
    extract_trigger_metadata,
    run_api_check,
    run_configured_api_checks,
    resource_monitor_command,
    resource_monitor_window_seconds,
    incident_capture_path,
    select_session_lookups,
)


def make_config(output_dir: Path, **overrides):
    values = {
        "panos_url": "https://firewall.invalid",
        "api_key": "fixture-key",
        "target_serial": None,
        "tls_verify": True,
        "syslog_host": "127.0.0.1",
        "syslog_port": 5514,
        "poll_seconds": 0.001,
        "max_monitor_seconds": 0.05,
        "incident_idle_ttl_seconds": 1,
        "recovery_threshold": 40,
        "low_samples_to_stop": 1,
        "request_timeout": 1,
        "max_session_lookups": 10,
        "session_retry_seconds": 30,
        "output_dir": output_dir,
        "generate_html_report": False,
    }
    values.update(overrides)
    return Config(**values)


def response(result: str) -> PanOSResponse:
    raw = f'<response status="success">{result}</response>'
    return PanOSResponse(result_xml=result, raw_response=raw)


class FakeClient:
    def __init__(self, *, fail_resource_monitor: bool = False):
        self.fail_resource_monitor = fail_resource_monitor
        self.commands = []
        self.lock = threading.Lock()

    def op_response(self, command: str) -> PanOSResponse:
        with self.lock:
            self.commands.append(command)
        if command == SYSTEM_INFO_COMMAND:
            return response(
                "<result><system><hostname>fixture-fw</hostname>"
                "<devicename>fixture-device</devicename>"
                "<serial>fixture-serial</serial>"
                "<model>PA-VM</model><sw-version>11.2.4</sw-version>"
                "</system></result>"
            )
        if command == CLOCK_COMMAND:
            return response("<result>Thu Aug 27 10:00:00 UTC 2026</result>")
        if command == OP_COMMANDS["packet_buffer_protection"]:
            return response("<result>Congestion: 10/100 (10%)</result>")
        if command == OP_COMMANDS["ingress_backlogs"]:
            return response("<result>USAGE - ATOMIC: 11% TOTAL: 12%</result>")
        if "<resource-monitor><second><last>" in command:
            if self.fail_resource_monitor:
                raise PanOSAPIError("unsupported", raw_response="raw failure")
            return response(
                "<result>Resource monitoring sampling data (per second):\n"
                "CPU load (%) during last 5 seconds:\n"
                "core 0 1 2\n"
                "  * 1 2\n"
                "Resource utilization (%) during last 5 seconds:\n"
                "packet buffer:\n10 9 8\n"
                "packet descriptor:\n11 10 9\n"
                "packet descriptor (on-chip):\n12 11 10</result>"
            )
        if command == OP_COMMANDS["dataplane_pool_statistics"]:
            return response(
                "<result>Pow Atomic Memory Pools\n"
                "[ 0] Work Queue Entries : 284357/284672 0xd04be09f00\n"
                "[ 1] Packet Buffers : 93401/97280 0x8070bf3a40\n"
                "Low free buffer limit : 94208</result>"
            )
        if command == OP_COMMANDS["global_counters_delta"]:
            return response(
                "<result>Global counters:\n"
                "Elapsed time since last sampling: 5.000 seconds\n"
                "flow_dos_pbp_block_host 4 0 drop flow dos "
                "Packets dropped by PBP</result>"
            )
        raise AssertionError(f"Unexpected command: {command}")


class MonitorTests(unittest.TestCase):
    def test_syslog_status_journal_keeps_trigger_and_non_trigger_messages(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            controller = Mock()
            protocol = SyslogProtocol(make_config(output_dir), controller)

            protocol.datagram_received(b"ordinary system log", ("192.0.2.10", 514))
            protocol.datagram_received(b"PBP Packet Drop(8507)", ("192.0.2.10", 514))

            records = [
                json.loads(line)
                for line in (output_dir / "syslog-received.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual([record["trigger"] for record in records], [False, True])
            self.assertEqual(records[1]["metadata"]["threat_id"], 8507)
            controller.trigger.assert_called_once()

    def test_single_inventory_target_routes_without_probe(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            profiles = (
                TargetProfile(
                    "standalone",
                    "https://fw.invalid",
                    "key",
                    syslog_sources=("198.51.100.1",),
                ),
            )
            router = MultiTargetRouter(
                make_config(Path(temporary_directory), target_profiles=profiles)
            )
            router.controllers["standalone"].trigger = Mock()
            router._probe_target = AsyncMock()

            router.trigger(
                "PBP Packet Drop",
                "198.51.100.1:514",
                transport_source_ip="198.51.100.1",
            )

            router._probe_target.assert_not_awaited()
            router.controllers["standalone"].trigger.assert_called_once()
            routing = router.controllers["standalone"].trigger.call_args.kwargs["routing"]
            self.assertEqual(routing["method"], "single_configured_target")

    def test_single_inventory_rejects_non_allowlisted_syslog_source(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            profile = TargetProfile(
                "standalone",
                "https://fw.invalid",
                "key",
                syslog_sources=("198.51.100.1",),
            )
            router = MultiTargetRouter(
                make_config(
                    Path(temporary_directory),
                    target_profiles=(profile,),
                )
            )
            router.controllers["standalone"].trigger = Mock()

            router.trigger(
                "PBP Packet Drop",
                "203.0.113.99:514",
                transport_source_ip="203.0.113.99",
            )

            router.controllers["standalone"].trigger.assert_not_called()

    def test_multi_target_routes_by_serial_without_probe(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            profiles = (
                TargetProfile(
                    "fw-a",
                    "https://fw-a.invalid",
                    "key-a",
                    serials=("SER-A",),
                    syslog_sources=("198.51.100.2",),
                ),
                TargetProfile(
                    "fw-b",
                    "https://fw-b.invalid",
                    "key-b",
                    serials=("SER-B",),
                    syslog_sources=("198.51.100.1",),
                ),
            )
            router = MultiTargetRouter(
                make_config(Path(temporary_directory), target_profiles=profiles)
            )
            router.controllers["fw-a"].trigger = Mock()
            router.controllers["fw-b"].trigger = Mock()

            router.trigger(
                "PBP Packet Drop serial=SER-B",
                "198.51.100.1:514",
                transport_source_ip="198.51.100.1",
            )

            router.controllers["fw-a"].trigger.assert_not_called()
            router.controllers["fw-b"].trigger.assert_called_once()
            routing = router.controllers["fw-b"].trigger.call_args.kwargs["routing"]
            self.assertEqual(routing["method"], "device_serial_and_syslog_source")

    def test_multi_target_probe_is_coalesced_and_selects_affected_member(self):
        async def exercise(output_dir: Path):
            profiles = (
                TargetProfile(
                    "fw-a",
                    "https://fw-a.invalid",
                    "key-a",
                    syslog_sources=("198.51.100.1",),
                ),
                TargetProfile(
                    "fw-b",
                    "https://fw-b.invalid",
                    "key-b",
                    syslog_sources=("198.51.100.1",),
                ),
            )
            router = MultiTargetRouter(
                make_config(output_dir, target_profiles=profiles)
            )
            router.controllers["fw-a"].trigger = Mock()
            router.controllers["fw-b"].trigger = Mock()
            probe_calls = []

            async def probe(target_name):
                probe_calls.append(target_name)
                await asyncio.sleep(0)
                return target_name, {
                    "reachable": True,
                    "affected": target_name == "fw-b",
                    "commands": {},
                }

            router._probe_target = probe
            router.trigger(
                "PBP Packet Drop",
                "198.51.100.1:514",
                transport_source_ip="198.51.100.1",
            )
            router.trigger(
                "PBP Session Discarded",
                "198.51.100.1:514",
                transport_source_ip="198.51.100.1",
            )
            await asyncio.gather(*tuple(router.routing_tasks))
            return router, probe_calls

        with tempfile.TemporaryDirectory() as temporary_directory:
            router, probe_calls = asyncio.run(exercise(Path(temporary_directory)))

            self.assertEqual(sorted(probe_calls), ["fw-a", "fw-b"])
            router.controllers["fw-a"].trigger.assert_not_called()
            self.assertEqual(router.controllers["fw-b"].trigger.call_count, 2)

    def test_multi_target_ambiguous_probe_fans_out(self):
        async def exercise(output_dir: Path):
            profiles = (
                TargetProfile(
                    "fw-a",
                    "https://fw-a.invalid",
                    "key-a",
                    syslog_sources=("198.51.100.1",),
                ),
                TargetProfile(
                    "fw-b",
                    "https://fw-b.invalid",
                    "key-b",
                    syslog_sources=("198.51.100.1",),
                ),
            )
            router = MultiTargetRouter(
                make_config(output_dir, target_profiles=profiles)
            )
            router.controllers["fw-a"].trigger = Mock()
            router.controllers["fw-b"].trigger = Mock()

            async def probe(target_name):
                return target_name, {
                    "reachable": True,
                    "affected": False,
                    "commands": {},
                }

            router._probe_target = probe
            router.trigger(
                "PBP Packet Drop",
                "198.51.100.1:514",
                transport_source_ip="198.51.100.1",
            )
            await asyncio.gather(*tuple(router.routing_tasks))
            return router

        with tempfile.TemporaryDirectory() as temporary_directory:
            router = asyncio.run(exercise(Path(temporary_directory)))

            router.controllers["fw-a"].trigger.assert_called_once()
            router.controllers["fw-b"].trigger.assert_called_once()
            self.assertTrue(
                router.controllers["fw-a"].trigger.call_args.kwargs["routing"]["fanout"]
            )

    def test_api_check_runs_for_every_configured_target(self):
        profiles = (
            TargetProfile(
                "fw-a",
                "https://fw-a.invalid",
                "key-a",
                syslog_sources=("198.51.100.1",),
            ),
            TargetProfile(
                "fw-b",
                "https://fw-b.invalid",
                "key-b",
                syslog_sources=("198.51.100.2",),
            ),
        )
        cfg = make_config(Path("captures"), target_profiles=profiles)

        async def fake_check(target_cfg):
            return target_cfg.output_dir / "api-check.jsonl", True

        with patch(
            "pbp_monitoring.orchestrator.run_api_check",
            new=AsyncMock(side_effect=fake_check),
        ) as mocked:
            results = asyncio.run(run_configured_api_checks(cfg))

        self.assertEqual(mocked.await_count, 2)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(succeeded for _path, succeeded in results))

    def test_syslog_gateway_source_marker_is_normalized(self):
        metadata = extract_trigger_metadata(
            "PBP_SYSLOG_SOURCE=192.0.2.11 PBP Packet Drop serial=SER-B"
        )

        self.assertEqual(metadata["syslog_source_ip"], "192.0.2.11")
        self.assertEqual(metadata["device_serial"], "SER-B")

    def test_trigger_is_correlated_and_its_session_is_enriched(self):
        async def exercise(output_dir: Path):
            controller = MonitorController(
                make_config(output_dir, generate_html_report=True),
                FakeClient(),
            )
            controller.trigger(
                "PBP Session Discarded threat-id=8508 session-id=42 src=192.0.2.9",
                "192.0.2.1:514",
            )
            await controller.monitor_task
            await controller.wait_for_reports()
            return controller.run_id

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            run_id = asyncio.run(exercise(output_dir))
            trigger_records = [
                json.loads(line)
                for line in (output_dir / "syslog-triggers.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            incident_records = [
                json.loads(line)
                for line in incident_capture_path(output_dir, run_id)
                .read_text(encoding="utf-8")
                .splitlines()
            ]

            self.assertEqual(trigger_records[0]["run_id"], run_id)
            self.assertEqual(incident_records[0]["event"], "trigger_received")
            cycle = next(record for record in incident_records if "cycle" in record)
            self.assertIn(42, cycle["candidate_session_ids"])
            self.assertEqual(
                cycle["candidate_entities"][0]["evidence_sources"],
                ["syslog_trigger"],
            )
            self.assertEqual(cycle["session_summaries"]["42"]["status"], "lookup_failed")
            self.assertTrue(
                (incident_capture_path(output_dir, run_id).parent / "report.html").is_file()
            )

    def test_unseen_session_is_prioritized_over_eligible_retries(self):
        selected = select_session_lookups(
            [10, 20, 999],
            {10: 1.0, 20: 1.0},
            now=10.0,
            retry_seconds=0.0,
            limit=1,
        )

        self.assertEqual(selected, [999])

    def test_lookup_limit_uses_pbp_responsibility_not_numeric_id(self):
        class RankedClient(FakeClient):
            def op_response(self, command: str) -> PanOSResponse:
                if command == OP_COMMANDS["packet_buffer_protection"]:
                    return response(
                        "<result>Packet buffer count based\n"
                        "Congestion: 10/100 (10%)\n"
                        "1 | trust | 1 | 0 | No | 1 | 0 | 60\n"
                        "999 | trust | 7000 | 85 | Yes | 9000 | 1000 | 5"
                        "</result>"
                    )
                return super().op_response(command)

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            client = RankedClient()
            controller = MonitorController(
                make_config(output_dir, max_session_lookups=1),
                client,
            )
            controller.last_trigger_monotonic = 0

            asyncio.run(controller._monitor("ranked-run"))

            session_commands = [
                command
                for command in client.commands
                if command.startswith("<show><session><id>")
            ]
            self.assertEqual(
                session_commands,
                ["<show><session><id>999</id></session></show>"],
            )

    def test_system_info_once_and_clock_before_each_recovered_batch(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            client = FakeClient()
            cfg = make_config(output_dir)
            controller = MonitorController(cfg, client)
            controller.last_trigger_monotonic = 0

            asyncio.run(controller._monitor("fixture-run"))

            self.assertEqual(client.commands.count(SYSTEM_INFO_COMMAND), 1)
            self.assertEqual(client.commands.count(CLOCK_COMMAND), 1)
            self.assertEqual(
                client.commands.count(OP_COMMANDS["global_counters_delta"]),
                2,
            )
            clock_index = client.commands.index(CLOCK_COMMAND)
            for name, command in OP_COMMANDS.items():
                if name == "global_counters_delta":
                    continue
                if name == "resource_monitor":
                    command = resource_monitor_command(cfg.poll_seconds)
                self.assertGreater(client.commands.index(command), clock_index)

            records = [
                json.loads(line)
                for line in incident_capture_path(output_dir, "fixture-run")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(records[0]["event"], "monitor_started")
            self.assertEqual(records[0]["device"]["hostname"], "fixture-fw")
            self.assertIn("global_counters_baseline", records[0]["commands"])
            self.assertEqual(records[1]["firewall_clock"], "Thu Aug 27 10:00:00 UTC 2026")
            self.assertEqual(
                records[1]["global_counters_delta_status"],
                "primed_interval",
            )
            self.assertTrue(records[1]["recovery_sample_eligible"])
            self.assertEqual(records[-1]["reason"], "resources_recovered")

    def test_partial_metrics_do_not_count_as_recovery(self):
        class PartialClient(FakeClient):
            def op_response(self, command: str) -> PanOSResponse:
                if command == OP_COMMANDS["packet_buffer_protection"]:
                    raise PanOSAPIError("temporary failure", raw_response="raw error")
                return super().op_response(command)

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            client = PartialClient(fail_resource_monitor=True)
            cfg = make_config(
                output_dir,
                max_monitor_seconds=0.015,
                low_samples_to_stop=1,
            )
            controller = MonitorController(cfg, client)
            controller.last_trigger_monotonic = time.monotonic()

            asyncio.run(controller._monitor("partial-run"))

            records = [
                json.loads(line)
                for line in incident_capture_path(output_dir, "partial-run")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            cycles = [record for record in records if "cycle" in record]
            self.assertGreaterEqual(len(cycles), 1)
            self.assertTrue(all(not record["recovery_sample_eligible"] for record in cycles))
            self.assertEqual(records[-1]["reason"], "maximum_duration")
            failed = cycles[0]["commands"]["packet_buffer_protection"]
            self.assertFalse(failed["ok"])
            self.assertEqual(failed["raw_response"], "raw error")

    def test_monitor_stops_after_trigger_idle_ttl(self):
        class HighUsageClient(FakeClient):
            def op_response(self, command: str) -> PanOSResponse:
                if command == OP_COMMANDS["packet_buffer_protection"]:
                    return response("<result>Congestion: 90/100 (90%)</result>")
                if command == OP_COMMANDS["ingress_backlogs"]:
                    return response("<result>USAGE - ATOMIC: 91% TOTAL: 92%</result>")
                return super().op_response(command)

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            controller = MonitorController(
                make_config(
                    output_dir,
                    poll_seconds=0.002,
                    max_monitor_seconds=1,
                    incident_idle_ttl_seconds=0.005,
                ),
                HighUsageClient(),
            )
            controller.last_trigger_monotonic = time.monotonic()

            asyncio.run(controller._monitor("idle-run"))

            records = [
                json.loads(line)
                for line in incident_capture_path(output_dir, "idle-run")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(records[-1]["reason"], "alert_idle_timeout")

    def test_api_check_validates_parsers_and_writes_daemon_cycle_schema(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            client = FakeClient()
            cfg = make_config(output_dir)

            with patch("pbp_monitoring.orchestrator.PanOSClient", return_value=client):
                output_file, succeeded = asyncio.run(run_api_check(cfg))

            records = [
                json.loads(line)
                for line in output_file.read_text(encoding="utf-8").splitlines()
            ]
            cycle = next(record for record in records if "cycle" in record)
            self.assertTrue(succeeded)
            self.assertTrue(records[0]["identity_complete"])
            self.assertEqual(records[0]["collector_version"], "0.5.0")
            self.assertTrue(cycle["recovery_sample_eligible"])
            self.assertEqual(cycle["validation_errors"], [])
            self.assertIn("completed_at", cycle)
            self.assertIn("cycle_duration_seconds", cycle)
            cores = cycle["resource_monitor_cpu_cores"]
            self.assertEqual(
                [(core["core_id"], core["utilization"]) for core in cores],
                [(1, 1.0), (2, 2.0)],
            )
            self.assertEqual(cores[1]["sample_count"], 1)
            self.assertEqual(records[-1]["reason"], "api_check_complete")

    def test_resource_monitor_window_tracks_poll_interval_with_margin(self):
        self.assertEqual(resource_monitor_window_seconds(5), 7)
        self.assertEqual(resource_monitor_window_seconds(10.1), 13)
        self.assertEqual(resource_monitor_window_seconds(120), 60)
        self.assertIn("<last>7</last>", resource_monitor_command(5))

    def test_api_check_fails_when_successful_xml_cannot_be_parsed(self):
        class OpaqueClient(FakeClient):
            def op_response(self, command: str) -> PanOSResponse:
                if command in OP_COMMANDS.values() or "<resource-monitor><second><last>" in command:
                    return response("<result>format not recognized</result>")
                return super().op_response(command)

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            cfg = make_config(output_dir)

            with patch(
                "pbp_monitoring.orchestrator.PanOSClient",
                return_value=OpaqueClient(),
            ):
                output_file, succeeded = asyncio.run(run_api_check(cfg))

            records = [
                json.loads(line)
                for line in output_file.read_text(encoding="utf-8").splitlines()
            ]
            cycle = next(record for record in records if "cycle" in record)
            self.assertFalse(succeeded)
            self.assertFalse(cycle["recovery_sample_eligible"])
            self.assertIn("no current packet-buffer percentage parsed", cycle["validation_errors"])
            self.assertEqual(records[-1]["reason"], "api_check_partial_failure")

    def test_api_check_includes_failed_candidate_session_details(self):
        class CandidateClient(FakeClient):
            def op_response(self, command: str) -> PanOSResponse:
                if command == OP_COMMANDS["packet_buffer_protection"]:
                    return response(
                        "<result>Congestion: 10/100 (10%)\n"
                        "123 | trust | 5 | 0 | No</result>"
                    )
                if command.startswith("<show><session><id>"):
                    raise PanOSAPIError("session disappeared")
                return super().op_response(command)

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            cfg = make_config(output_dir)

            with patch(
                "pbp_monitoring.orchestrator.PanOSClient",
                return_value=CandidateClient(),
            ):
                output_file, succeeded = asyncio.run(run_api_check(cfg))

            records = [
                json.loads(line)
                for line in output_file.read_text(encoding="utf-8").splitlines()
            ]
            cycle = next(record for record in records if "cycle" in record)
            self.assertFalse(succeeded)
            self.assertFalse(cycle["session_details"]["123"]["ok"])
            self.assertIn("session detail failed for 123", cycle["validation_errors"])


if __name__ == "__main__":
    unittest.main()
