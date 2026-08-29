import asyncio
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from pbp_monitoring import __version__
from pbp_monitoring.config_store import ConfigStore
from pbp_monitoring.orchestrator import (
    CLOCK_COMMAND,
    DP_CORE_FUNCTIONS_COMMAND,
    OP_COMMANDS,
    SYSTEM_INFO_COMMAND,
    Config,
    ManagedRouter,
    MultiTargetRouter,
    MonitorController,
    run_target_checks_once,
    PanOSAPIError,
    PanOSResponse,
    SyslogProtocol,
    TargetProfile,
    extract_trigger_metadata,
    append_jsonl,
    append_recent_syslog,
    run_api_check,
    run_configured_api_checks,
    resource_monitor_command,
    resource_monitor_window_seconds,
    incident_capture_path,
    unique_run_id,
    panos_csv_serial,
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
        if command == DP_CORE_FUNCTIONS_COMMAND:
            return response(
                "<result><entry><dp>dp0</dp><entries>"
                "<entry><id>0</id><pid>1000</pid><modules>"
                "<member>pan_timer</member></modules></entry>"
                "<entry><id>1</id><pid>1001</pid><modules>"
                "<member>flow_lookup</member><member>flow_fastpath</member>"
                "<member>flow_ctrl</member></modules></entry>"
                "</entries></entry></result>"
            )
        if command == OP_COMMANDS["packet_buffer_protection"]:
            return response("<result>Congestion: 10/100 (10%)</result>")
        if command == OP_COMMANDS["session_info"]:
            return response(
                "<result><num-max>200000</num-max><num-active>421</num-active>"
                "<num-tcp>206</num-tcp><num-udp>215</num-udp><num-icmp>0</num-icmp>"
                "<num-installed>1254101</num-installed><cps>4</cps><pps>160</pps>"
                "<kbps>623</kbps><dp>*.dp0</dp></result>"
            )
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

    def test_panos_positional_serial_is_extracted_from_a_syslog_line(self):
        message = (
            "PBP_SYSLOG_SOURCE=198.51.100.1 <11>Aug 29 15:53:29 lab-fw-01 "
            "1,2026/08/29 15:53:24,012345678901,THREAT,flood,3074,"
            "2026/08/29 15:53:29,,PBP Packet Drop(8507),,,,,"
        )
        metadata = extract_trigger_metadata(message)
        self.assertEqual(metadata["device_serial"], "012345678901")
        self.assertEqual(metadata["syslog_source_ip"], "198.51.100.1")

    def test_a_line_that_is_not_a_panos_log_yields_no_serial(self):
        self.assertIsNone(panos_csv_serial("a,b,c,d,e"))
        self.assertIsNone(panos_csv_serial("ordinary system log"))

    def _serial_router(self, output_dir, serials=("012345678901",)):
        profiles = (
            TargetProfile(
                "PA-lab",
                "https://fw.invalid",
                "key",
                serials=tuple(serials),
                syslog_sources=("198.51.100.1",),
            ),
        )
        cfg = make_config(output_dir, target_profiles=profiles)
        router = MultiTargetRouter(cfg)
        router.controllers["PA-lab"].trigger = Mock()
        router._probe_target = AsyncMock()
        return cfg, router

    @staticmethod
    def _panos_trigger(serial: str) -> bytes:
        return (
            "PBP_SYSLOG_SOURCE=198.51.100.1 <11>Aug 29 15:53:29 lab-fw-01 "
            f"1,2026/08/29 15:53:24,{serial},THREAT,flood,3074,"
            "2026/08/29 15:53:29,,PBP Packet Drop(8507),,,,,"
        ).encode()

    def test_registered_serial_from_the_declared_source_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            cfg, router = self._serial_router(output_dir)
            protocol = SyslogProtocol(cfg, router)

            protocol.datagram_received(
                self._panos_trigger("012345678901"), ("192.0.2.3", 514)
            )

            router.controllers["PA-lab"].trigger.assert_called_once()
            record = json.loads(
                (output_dir / "syslog-received.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()[0]
            )
            self.assertNotIn("suppressed", record)
            self.assertEqual(record["target_names"], ["PA-lab"])
            self.assertEqual(record["metadata"]["device_serial"], "012345678901")

    def test_foreign_serial_from_the_declared_source_starts_no_monitor(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            cfg, router = self._serial_router(output_dir)
            protocol = SyslogProtocol(cfg, router)

            protocol.datagram_received(
                self._panos_trigger("099999999999"), ("192.0.2.3", 514)
            )

            router.controllers["PA-lab"].trigger.assert_not_called()
            record = json.loads(
                (output_dir / "syslog-received.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()[0]
            )
            self.assertEqual(record["suppressed"], "device_serial_not_registered")
            self.assertNotIn("message", record)
            self.assertEqual(record["target_names"], [])
            self.assertFalse(
                (output_dir / "targets" / "PA-lab" / "syslog-triggers.jsonl").exists()
            )

    def test_trigger_without_a_serial_is_refused_when_one_is_registered(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            cfg, router = self._serial_router(output_dir)
            protocol = SyslogProtocol(cfg, router)

            protocol.datagram_received(
                b"PBP_SYSLOG_SOURCE=198.51.100.1 PBP Packet Drop(8507)",
                ("192.0.2.3", 514),
            )

            router.controllers["PA-lab"].trigger.assert_not_called()
            record = json.loads(
                (output_dir / "syslog-received.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()[0]
            )
            self.assertEqual(record["suppressed"], "device_serial_missing")

    def test_target_without_a_registered_serial_keeps_the_source_only_rule(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            cfg, router = self._serial_router(output_dir, serials=())
            protocol = SyslogProtocol(cfg, router)

            protocol.datagram_received(
                b"PBP_SYSLOG_SOURCE=198.51.100.1 PBP Packet Drop(8507)",
                ("192.0.2.3", 514),
            )

            router.controllers["PA-lab"].trigger.assert_called_once()
            record = json.loads(
                (output_dir / "syslog-received.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()[0]
            )
            self.assertNotIn("suppressed", record)

    def test_unregistered_sender_is_journalled_without_its_message(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            profiles = (
                TargetProfile(
                    "declared",
                    "https://fw.invalid",
                    "key",
                    syslog_sources=("198.51.100.1",),
                ),
            )
            cfg = make_config(output_dir, target_profiles=profiles)
            router = MultiTargetRouter(cfg)
            protocol = SyslogProtocol(cfg, router)

            protocol.datagram_received(
                b"PBP_SYSLOG_SOURCE=203.0.113.9 secrets and PBP Packet Drop(8507)",
                ("192.0.2.3", 514),
            )

            record = json.loads(
                (output_dir / "syslog-received.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()[0]
            )
            self.assertEqual(record["suppressed"], "source_not_registered")
            self.assertNotIn("message", record)
            self.assertEqual(record["target_names"], [])
            self.assertEqual(record["metadata"], {"syslog_source_ip": "203.0.113.9"})
            self.assertTrue(record["trigger"])
            self.assertNotIn("secrets", json.dumps(record))

    def test_registered_sender_keeps_its_message_and_metadata(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            profiles = (
                TargetProfile(
                    "declared",
                    "https://fw.invalid",
                    "key",
                    syslog_sources=("198.51.100.1",),
                ),
            )
            cfg = make_config(output_dir, target_profiles=profiles)
            router = MultiTargetRouter(cfg)
            router.controllers["declared"].trigger = Mock()
            protocol = SyslogProtocol(cfg, router)

            protocol.datagram_received(
                b"PBP_SYSLOG_SOURCE=198.51.100.1 PBP Packet Drop(8507)",
                ("192.0.2.3", 514),
            )

            record = json.loads(
                (output_dir / "syslog-received.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()[0]
            )
            self.assertNotIn("suppressed", record)
            self.assertIn("PBP Packet Drop(8507)", record["message"])
            self.assertEqual(record["metadata"]["threat_id"], 8507)
            self.assertEqual(record["target_names"], ["declared"])

    def test_allowlisted_but_unattributed_sender_keeps_its_message(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            shared = ("198.51.100.1",)
            profiles = (
                TargetProfile("first", "https://a.invalid", "key", syslog_sources=shared),
                TargetProfile("second", "https://b.invalid", "key", syslog_sources=shared),
            )
            cfg = make_config(output_dir, target_profiles=profiles)
            router = MultiTargetRouter(cfg)
            router._probe_and_dispatch = AsyncMock()
            protocol = SyslogProtocol(cfg, router)

            protocol.datagram_received(
                b"PBP_SYSLOG_SOURCE=198.51.100.1 ordinary system log",
                ("192.0.2.3", 514),
            )

            record = json.loads(
                (output_dir / "syslog-received.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()[0]
            )
            self.assertNotIn("suppressed", record)
            self.assertIn("ordinary system log", record["message"])
            self.assertEqual(record["target_names"], [])

    def test_single_target_deployment_still_stores_every_message(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            controller = Mock(spec=["trigger"])
            protocol = SyslogProtocol(
                make_config(output_dir, target_name="solo"), controller
            )

            protocol.datagram_received(b"ordinary system log", ("192.0.2.10", 514))

            record = json.loads(
                (output_dir / "syslog-received.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()[0]
            )
            self.assertNotIn("suppressed", record)
            self.assertEqual(record["message"], "ordinary system log")

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

    def test_follow_up_triggers_reuse_the_routing_decision_while_active(self):
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
            await asyncio.gather(*tuple(router.routing_tasks))
            # Simulate the monitor the dispatched trigger would have started.
            active = asyncio.create_task(asyncio.sleep(30))
            router.controllers["fw-b"].monitor_task = active
            try:
                router.trigger(
                    "PBP Session Discarded",
                    "198.51.100.1:514",
                    transport_source_ip="198.51.100.1",
                )
                await asyncio.gather(
                    *tuple(router.routing_tasks), return_exceptions=True
                )
            finally:
                active.cancel()
                await asyncio.gather(active, return_exceptions=True)
            return router, probe_calls

        with tempfile.TemporaryDirectory() as temporary_directory:
            router, probe_calls = asyncio.run(exercise(Path(temporary_directory)))

            self.assertEqual(sorted(probe_calls), ["fw-a", "fw-b"])
            self.assertEqual(router.controllers["fw-b"].trigger.call_count, 2)
            router.controllers["fw-a"].trigger.assert_not_called()
            reuse = router.controllers["fw-b"].trigger.call_args.kwargs["routing"]
            self.assertEqual(reuse["method"], "reuse_active_routing")

    def test_a_trigger_after_the_monitor_ends_probes_again(self):
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
            await asyncio.gather(*tuple(router.routing_tasks))
            # No monitor is active for the selected target: the decision is
            # stale, so a new trigger must probe the candidates again.
            router.trigger(
                "PBP Packet Drop",
                "198.51.100.1:514",
                transport_source_ip="198.51.100.1",
            )
            await asyncio.gather(*tuple(router.routing_tasks))
            return probe_calls

        with tempfile.TemporaryDirectory() as temporary_directory:
            probe_calls = asyncio.run(exercise(Path(temporary_directory)))

            self.assertEqual(len(probe_calls), 4)

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
            self.assertEqual(cycle["session_info"]["totals"]["allocated"], 421)
            self.assertEqual(
                cycle["session_info"]["dataplanes"][0]["connection_rate_cps"], 4
            )
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
            self.assertEqual(client.commands.count(DP_CORE_FUNCTIONS_COMMAND), 1)
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
            self.assertEqual(
                records[0]["dp_core_functions"],
                [
                    {
                        "dataplane": "dp0",
                        "core_id": "0",
                        "functions": ["pan_timer"],
                        "forwards_traffic": False,
                    },
                    {
                        "dataplane": "dp0",
                        "core_id": "1",
                        "functions": ["flow_lookup", "flow_fastpath", "flow_ctrl"],
                        "forwards_traffic": True,
                    },
                ],
            )
            self.assertIn("dp_core_functions", records[0]["commands"])
            self.assertIn("global_counters_baseline", records[0]["commands"])
            self.assertEqual(records[1]["firewall_clock"], "Thu Aug 27 10:00:00 UTC 2026")
            self.assertEqual(
                records[1]["global_counters_delta_status"],
                "primed_interval",
            )
            self.assertTrue(records[1]["recovery_sample_eligible"])
            self.assertEqual(records[-1]["reason"], "resources_recovered")

    def test_stored_core_map_spares_the_firewall_an_api_call(self):
        stored = (
            {
                "dataplane": "dp0",
                "core_id": "1",
                "functions": ["flow_lookup", "flow_fastpath"],
                "forwards_traffic": True,
            },
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            client = FakeClient()
            controller = MonitorController(
                make_config(
                    output_dir,
                    dp_core_functions=stored,
                    dp_core_functions_identity="PA-VM|11.2.4",
                ),
                client,
            )
            controller.last_trigger_monotonic = 0

            asyncio.run(controller._monitor("cached-map-run"))

            self.assertNotIn(DP_CORE_FUNCTIONS_COMMAND, client.commands)
            startup = json.loads(
                incident_capture_path(output_dir, "cached-map-run")
                .read_text(encoding="utf-8")
                .splitlines()[0]
            )
            self.assertEqual(startup["dp_core_functions"], [dict(stored[0])])
            self.assertEqual(startup["dp_core_functions_source"], "configuration")
            self.assertNotIn("dp_core_functions", startup["commands"])
            self.assertEqual(startup["parse_warnings"], [])

    def test_a_panos_upgrade_makes_the_stored_core_map_be_read_again(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            client = FakeClient()
            controller = MonitorController(
                make_config(
                    output_dir,
                    dp_core_functions=(
                        {
                            "dataplane": "dp0",
                            "core_id": "1",
                            "functions": ["flow_lookup"],
                            "forwards_traffic": False,
                        },
                    ),
                    dp_core_functions_identity="PA-VM|11.1.0",
                ),
                client,
            )
            controller.last_trigger_monotonic = 0

            asyncio.run(controller._monitor("upgraded-run"))

            self.assertEqual(client.commands.count(DP_CORE_FUNCTIONS_COMMAND), 1)
            startup = json.loads(
                incident_capture_path(output_dir, "upgraded-run")
                .read_text(encoding="utf-8")
                .splitlines()[0]
            )
            self.assertEqual(startup["dp_core_functions_source"], "firewall")
            self.assertEqual(
                [entry["core_id"] for entry in startup["dp_core_functions"]],
                ["0", "1"],
            )
            self.assertIn("dp_core_functions", startup["commands"])

    def test_unreadable_core_functions_warn_without_stopping_collection(self):
        class NoStatisticsClient(FakeClient):
            def op_response(self, command: str) -> PanOSResponse:
                if command == DP_CORE_FUNCTIONS_COMMAND:
                    raise PanOSAPIError("unsupported", raw_response="raw failure")
                return super().op_response(command)

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            client = NoStatisticsClient()
            controller = MonitorController(make_config(output_dir), client)
            controller.last_trigger_monotonic = 0

            asyncio.run(controller._monitor("no-statistics-run"))

            records = [
                json.loads(line)
                for line in incident_capture_path(output_dir, "no-statistics-run")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            startup = records[0]
            self.assertEqual(startup["dp_core_functions"], [])
            self.assertIn(
                "dataplane core function groups could not be read",
                startup["parse_warnings"],
            )
            self.assertTrue(startup["identity_complete"])
            self.assertGreater(len(records), 2)

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
            self.assertEqual(records[0]["collector_version"], __version__)
            self.assertTrue(cycle["recovery_sample_eligible"])
            self.assertEqual(cycle["validation_errors"], [])
            self.assertEqual(cycle["session_info"]["totals"]["allocated"], 421)
            self.assertEqual(cycle["session_info"]["totals"]["tcp"], 206)
            self.assertEqual(cycle["session_info"]["totals"]["packet_rate_pps"], 160)
            self.assertEqual(
                cycle["session_info"]["totals"]["utilization_percentage"], 0.21
            )
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



class RunStartRateLimitTests(unittest.TestCase):
    """A forged trigger flood must not cycle unlimited monitoring runs."""

    def test_run_starts_beyond_the_window_limit_are_journalled_only(self):
        async def scenario(cfg):
            controller = MonitorController(cfg, FakeClient())
            started = 0
            with patch.object(
                controller, "_monitor", side_effect=lambda run_id: asyncio.sleep(0)
            ):
                with patch("pbp_monitoring.orchestrator.RUN_START_LIMIT", 3):
                    for _ in range(5):
                        controller.trigger("PBP Packet Drop (8507)", "192.0.2.1:514")
                        if controller.monitor_task is not None:
                            await asyncio.gather(
                                controller.monitor_task, return_exceptions=True
                            )
                    started = len(controller.run_starts)
            return started

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            started = asyncio.run(scenario(make_config(output_dir)))

            self.assertEqual(started, 3)
            journal = (output_dir / "syslog-triggers.jsonl").read_text(encoding="utf-8")
            records = [json.loads(line) for line in journal.splitlines()]
            limited = [
                record
                for record in records
                if record.get("event") == "trigger_rate_limited"
            ]
            self.assertEqual(len(limited), 2)

    def test_a_reinforcement_is_never_rate_limited(self):
        async def scenario(cfg):
            controller = MonitorController(cfg, FakeClient())
            active = asyncio.create_task(asyncio.sleep(30))
            controller.monitor_task = active
            try:
                with patch("pbp_monitoring.orchestrator.RUN_START_LIMIT", 0):
                    controller.trigger("PBP Packet Drop (8507)", "192.0.2.1:514")
                return controller.trigger_sequence
            finally:
                active.cancel()
                await asyncio.gather(active, return_exceptions=True)

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            sequence = asyncio.run(scenario(make_config(output_dir)))

            self.assertEqual(sequence, 1)
            journal = (output_dir / "syslog-triggers.jsonl").read_text(encoding="utf-8")
            record = json.loads(journal.splitlines()[0])
            self.assertEqual(record.get("event"), "trigger_received")


class RunIdTests(unittest.TestCase):
    """Two incidents in the same wall-clock second must not share a capture."""

    def test_unique_run_id_suffixes_a_same_second_collision(self):
        from datetime import datetime as real_datetime, timezone as real_timezone

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            frozen = real_datetime(2026, 8, 29, 10, 0, 0, tzinfo=real_timezone.utc)
            with patch("pbp_monitoring.orchestrator.datetime") as mocked:
                mocked.now.return_value = frozen
                first = unique_run_id(output_dir)
                incident_capture_path(output_dir, first).parent.mkdir(parents=True)
                second = unique_run_id(output_dir)
                incident_capture_path(output_dir, second).parent.mkdir(parents=True)
                third = unique_run_id(output_dir)

        self.assertEqual(first, "20260829T100000Z")
        self.assertEqual(second, "20260829T100000Z-2")
        self.assertEqual(third, "20260829T100000Z-3")

    def test_back_to_back_monitors_get_distinct_captures(self):
        async def scenario(cfg):
            controller = MonitorController(cfg, FakeClient())
            controller.trigger("PBP Packet Drop (8507)", "192.0.2.1:514")
            first = controller.run_id
            await asyncio.gather(controller.monitor_task, return_exceptions=True)
            controller.trigger("PBP Packet Drop (8507)", "192.0.2.1:514")
            second = controller.run_id
            await asyncio.gather(controller.monitor_task, return_exceptions=True)
            await controller.wait_for_reports()
            return first, second

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            first, second = asyncio.run(scenario(make_config(output_dir)))

            self.assertNotEqual(first, second)
            self.assertTrue(incident_capture_path(output_dir, first).exists())
            self.assertTrue(incident_capture_path(output_dir, second).exists())


class PersistenceResilienceTests(unittest.TestCase):
    """Evidence writes may fail; collection and reporting must carry on."""

    def test_append_jsonl_confines_a_torn_write_to_one_record(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "incident.jsonl"
            path.write_text('{"event": "cycle", "trunca', encoding="utf-8")

            append_jsonl(path, {"event": "next"})

            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[1]), {"event": "next"})

    def test_reception_journal_compaction_converges_below_the_size_cap(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "syslog-received.jsonl"
            with patch("pbp_monitoring.orchestrator.SYSLOG_STATUS_MAX_BYTES", 300):
                for index in range(10):
                    append_recent_syslog(path, {"n": index, "pad": "x" * 80})

            self.assertLessEqual(path.stat().st_size, 300)
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertTrue(lines)
            self.assertEqual(json.loads(lines[-1])["n"], 9)

    def test_a_journal_write_failure_still_starts_the_monitor(self):
        async def scenario(cfg):
            controller = MonitorController(cfg, FakeClient())
            with patch(
                "pbp_monitoring.orchestrator.append_jsonl",
                side_effect=OSError("disk full"),
            ):
                controller.trigger("PBP Packet Drop (8507)", "192.0.2.1:514")
                self.assertIsNotNone(controller.monitor_task)
            await asyncio.gather(controller.monitor_task, return_exceptions=True)
            await controller.wait_for_reports()
            return controller.run_id

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory)
            run_id = asyncio.run(scenario(make_config(output_dir)))

            capture = incident_capture_path(output_dir, run_id)
            self.assertTrue(capture.exists())

    def test_a_failing_trigger_does_not_break_the_datagram_handler(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            cfg = make_config(Path(temporary_directory))
            controller = Mock()
            controller.trigger.side_effect = OSError("disk full")
            protocol = SyslogProtocol(cfg, controller)

            protocol.datagram_received(
                b"PBP Session Discarded (8508)", ("192.0.2.1", 514)
            )

            controller.trigger.assert_called_once()

    def test_a_failed_stop_record_still_schedules_the_report(self):
        async def scenario(cfg):
            controller = MonitorController(cfg, FakeClient())
            with patch.object(controller, "_schedule_report") as schedule:
                with patch(
                    "pbp_monitoring.orchestrator.append_jsonl",
                    side_effect=OSError("disk full"),
                ):
                    await controller._monitor("fixture-run")
            schedule.assert_called_once()

        with tempfile.TemporaryDirectory() as temporary_directory:
            asyncio.run(scenario(make_config(Path(temporary_directory))))


class FirewallCheckTests(unittest.TestCase):
    """The daily check must be cheap, skip busy firewalls, and never raise."""

    CORE_MAP = [
        {
            "dataplane": "dp0",
            "core_id": "1",
            "functions": ["flow_lookup", "flow_fastpath", "flow_ctrl"],
            "forwards_traffic": True,
        }
    ]

    def _router(self, root: Path, *, identity: str, core_map=None, **identity_fields):
        store = ConfigStore(root / "config.db")
        store.initialize()
        store.save_target(
            name="fw-a",
            panos_url="https://192.0.2.10",
            api_key="key",
            serials=["fixture-serial"],
            syslog_sources=["192.0.2.10"],
            device_identity={
                "hostname": "fixture-fw",
                "model": identity_fields.get("model", "PA-VM"),
                "software_version": identity_fields.get("software_version", "11.2.4"),
            },
            dp_core_functions=self.CORE_MAP if core_map is None else core_map,
        )
        if identity is not None:
            with sqlite3.connect(store.path) as connection:
                connection.execute(
                    "UPDATE targets SET dp_core_functions_identity=?", (identity,)
                )
        with patch.dict(os.environ, {"OUTPUT_DIR": str(root / "data")}):
            cfg = Config.from_store(store)
        return ManagedRouter(cfg, store), store

    def test_an_unchanged_firewall_costs_one_api_call(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            router, store = self._router(Path(temporary_directory), identity="PA-VM|11.2.4")
            client = FakeClient()

            with patch("pbp_monitoring.orchestrator.PanOSClient", return_value=client):
                asyncio.run(run_target_checks_once(router))

            self.assertEqual(client.commands, [SYSTEM_INFO_COMMAND])
            recorded = store.list_targets()[0]
            self.assertEqual(recorded["last_check_status"], "ok")
            self.assertEqual(recorded["last_check_kind"], "keepalive")
            self.assertIn("1 dataplane cores mapped", recorded["last_check_detail"])

    def test_a_panos_upgrade_refreshes_the_stored_identity_and_core_map(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            router, store = self._router(
                Path(temporary_directory),
                identity="PA-VM|11.1.0",
                software_version="11.1.0",
            )
            client = FakeClient()

            with patch("pbp_monitoring.orchestrator.PanOSClient", return_value=client):
                asyncio.run(run_target_checks_once(router))

            self.assertEqual(client.commands.count(DP_CORE_FUNCTIONS_COMMAND), 1)
            refreshed = store.list_targets()[0]
            self.assertEqual(refreshed["sw_version"], "11.2.4")
            self.assertEqual(refreshed["dp_core_functions_identity"], "PA-VM|11.2.4")
            self.assertEqual(
                [entry["core_id"] for entry in refreshed["dp_core_functions"]],
                ["0", "1"],
            )
            self.assertIn("stored identity refreshed", refreshed["last_check_detail"])

    def test_an_unreachable_firewall_is_recorded_without_stopping_the_service(self):
        class UnreachableClient(FakeClient):
            def op_response(self, command: str) -> PanOSResponse:
                raise PanOSAPIError("unable to reach the firewall", raw_response="")

        with tempfile.TemporaryDirectory() as temporary_directory:
            router, store = self._router(Path(temporary_directory), identity="PA-VM|11.2.4")

            with patch(
                "pbp_monitoring.orchestrator.PanOSClient",
                return_value=UnreachableClient(),
            ):
                performed = asyncio.run(run_target_checks_once(router))

            self.assertEqual(performed, 1)
            recorded = store.list_targets()[0]
            self.assertEqual(recorded["last_check_status"], "failed")
            self.assertIn("unable to reach the firewall", recorded["last_check_detail"])

    def test_a_firewall_with_an_active_incident_is_left_alone(self):
        async def scenario(router, store):
            controller = router.router.controllers["fw-a"]
            controller.monitor_task = asyncio.create_task(asyncio.sleep(30))
            try:
                client = FakeClient()
                with patch(
                    "pbp_monitoring.orchestrator.PanOSClient", return_value=client
                ):
                    performed = await run_target_checks_once(router)
                return performed, client.commands
            finally:
                controller.monitor_task.cancel()
                await asyncio.gather(controller.monitor_task, return_exceptions=True)

        with tempfile.TemporaryDirectory() as temporary_directory:
            router, store = self._router(Path(temporary_directory), identity="PA-VM|11.2.4")

            performed, commands = asyncio.run(scenario(router, store))

            self.assertEqual(performed, 0)
            self.assertEqual(commands, [])
            self.assertIsNone(store.list_targets()[0]["last_check_at"])

    def test_a_requested_validation_runs_every_command_and_clears_the_request(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            router, store = self._router(root, identity="PA-VM|11.2.4")
            store.request_target_check(store.list_targets()[0]["target_id"])
            client = FakeClient()

            with patch("pbp_monitoring.orchestrator.PanOSClient", return_value=client):
                asyncio.run(run_target_checks_once(router))

            recorded = store.list_targets()[0]
            self.assertIsNone(recorded["check_requested_at"])
            self.assertEqual(recorded["last_check_kind"], "validation")
            self.assertEqual(recorded["last_check_status"], "ok")
            for command in OP_COMMANDS.values():
                if "<resource-monitor><second><last>" in command:
                    continue
                self.assertIn(command, client.commands)
            captures = list((root / "data" / "targets" / "fw-a" / "api-checks").iterdir())
            self.assertEqual(len(captures), 1)

    def test_a_firewall_saved_after_startup_is_checked_without_syslog_traffic(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            store = ConfigStore(root / "config.db")
            store.initialize()
            with patch.dict(os.environ, {"OUTPUT_DIR": str(root / "data")}):
                cfg = Config.from_store(store)
            router = ManagedRouter(cfg, store)
            store.save_target(
                name="fw-a",
                panos_url="https://192.0.2.10",
                api_key="key",
                serials=["fixture-serial"],
                syslog_sources=["192.0.2.10"],
                device_identity={
                    "hostname": "fixture-fw",
                    "model": "PA-VM",
                    "software_version": "11.2.4",
                },
                dp_core_functions=self.CORE_MAP,
            )
            store.request_target_check(store.list_targets()[0]["target_id"])
            client = FakeClient()

            with patch("pbp_monitoring.orchestrator.PanOSClient", return_value=client):
                performed = asyncio.run(run_target_checks_once(router))

            self.assertEqual(performed, 1)
            recorded = store.list_targets()[0]
            self.assertIsNone(recorded["check_requested_at"])
            self.assertEqual(recorded["last_check_kind"], "validation")

    def test_an_edited_firewall_is_checked_at_its_new_address(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            router, store = self._router(root, identity="PA-VM|11.2.4")
            recorded = store.list_targets(include_secrets=True)[0]
            store.save_target(
                target_id=recorded.target_id,
                name="fw-a",
                panos_url="https://192.0.2.20",
                api_key="key",
                serials=["fixture-serial"],
                syslog_sources=["192.0.2.20"],
                device_identity={
                    "hostname": "fixture-fw",
                    "model": "PA-VM",
                    "software_version": "11.2.4",
                },
                dp_core_functions=self.CORE_MAP,
            )
            store.request_target_check(store.list_targets()[0]["target_id"])
            captured_urls: list[str] = []

            def capture_client(cfg):
                captured_urls.append(cfg.panos_url)
                return FakeClient()

            with patch(
                "pbp_monitoring.orchestrator.PanOSClient",
                side_effect=capture_client,
            ):
                asyncio.run(run_target_checks_once(router))

            self.assertTrue(captured_urls)
            self.assertEqual(set(captured_urls), {"https://192.0.2.20"})

if __name__ == "__main__":
    unittest.main()
