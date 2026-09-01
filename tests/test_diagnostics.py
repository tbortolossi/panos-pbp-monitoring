"""Proofs for the persistent logs and the deployment support bundle.

The bundle is meant to travel from a customer to the maintainer. Two
properties matter more than its contents: it must never carry credential
material, and producing it must never be able to stop the collector.
"""

import csv
import io
import json
import logging
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from pbp_monitoring import __version__, diagnostics
from pbp_monitoring.diagnostics import Anonymizer, build_anonymizer
from pbp_monitoring.config_store import ConfigStore


def _detach(handler: logging.Handler) -> None:
    logging.getLogger().removeHandler(handler)
    handler.close()


class PersistentLogTests(unittest.TestCase):
    def test_collector_activity_is_written_to_a_rotating_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory) / "logs"
            path = diagnostics.configure_file_logging(directory, "collector")
            self.assertIsNotNone(path)
            handler = logging.getLogger().handlers[-1]
            try:
                logging.getLogger("pbp-test").warning("Monitor 20260830T0000Z started")
                handler.flush()
                self.assertIn("Monitor 20260830T0000Z started", path.read_text())
            finally:
                _detach(handler)

    def test_setup_code_never_reaches_the_persistent_log(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = diagnostics.configure_file_logging(
                Path(temporary_directory), "webui"
            )
            handler = logging.getLogger().handlers[-1]
            try:
                logging.getLogger("pbp-test").warning(
                    "Initial administrator setup requires the one-time setup code: %s",
                    "T0P-SECRET-CODE",
                    extra={diagnostics.SENSITIVE_ATTRIBUTE: True},
                )
                logging.getLogger("pbp-test").warning("ordinary line")
                handler.flush()
                written = path.read_text()
            finally:
                _detach(handler)
            self.assertNotIn("T0P-SECRET-CODE", written)
            self.assertIn("ordinary line", written)

    def test_unwritable_log_directory_does_not_stop_the_collector(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            blocker = Path(temporary_directory) / "logs"
            # A plain file where the log directory belongs makes mkdir fail.
            blocker.write_text("not a directory", encoding="utf-8")
            before = list(logging.getLogger().handlers)
            self.assertIsNone(
                diagnostics.configure_file_logging(blocker, "collector")
            )
            self.assertEqual(logging.getLogger().handlers, before)

    def test_an_invalid_component_name_is_refused(self):
        with self.assertRaises(ValueError):
            diagnostics.configure_file_logging(Path("/tmp"), "../escape")

    def test_credential_shaped_values_are_scrubbed_from_exported_logs(self):
        scrubbed = diagnostics.scrub_log_text(
            "GET /api/?type=op&key=LUFRPT1abc123 failed\n"
            "X-PAN-KEY: LUFRPT1abc123\n"
            "one-time setup code: hunter2xyz\n"
        )
        self.assertNotIn("LUFRPT1abc123", scrubbed)
        self.assertNotIn("hunter2xyz", scrubbed)
        self.assertIn("<redacted>", scrubbed)


class _Deployment:
    """A minimal on-disk deployment: one target, one API check, journals."""

    def __init__(self, root: Path):
        self.data = root / "data"
        self.config = root / "config"
        self.data.mkdir()
        self.config.mkdir()
        target = self.data / "targets" / "paris-edge"
        (target / "incidents" / "20260830T090000Z" / "raw").mkdir(parents=True)
        (target / "incidents" / "20260830T090000Z" / "incident.jsonl").write_text(
            json.dumps({"timestamp": "2026-08-30T09:00:00+00:00", "event": "monitor_started"})
            + "\n",
            encoding="utf-8",
        )
        check = target / "api-checks" / "20260830T080000Z"
        (check / "raw").mkdir(parents=True)
        (check / "api-check.jsonl").write_text(
            json.dumps(
                {
                    "timestamp": "2026-08-30T08:00:00+00:00",
                    "event": "monitor_started",
                    "mode": "api_check",
                    "device": {"model": "PA-440", "software_version": "12.2.2"},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (check / "raw" / "batch-0001.txt").write_text(
            "=== COMMAND: clock ===\n", encoding="utf-8"
        )
        (target / "syslog-triggers.jsonl").write_text(
            json.dumps({"run_id": "20260830T090000Z", "message": "PBP Packet Drop"})
            + "\n",
            encoding="utf-8",
        )
        (self.data / "syslog-received.jsonl").write_text(
            json.dumps({"timestamp": "2026-08-30T09:00:01+00:00", "target_names": ["paris-edge"]})
            + "\n"
            + json.dumps(
                {
                    "timestamp": "2026-08-30T09:00:02+00:00",
                    "target_names": [],
                    "suppressed": "device_serial_not_registered",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (self.data / "syslog-routing.jsonl").write_text(
            json.dumps({"routing_key": "10.0.0.1", "method": "serial"}) + "\n",
            encoding="utf-8",
        )
        logs = self.data / "logs"
        logs.mkdir()
        (logs / "collector.log").write_text(
            "2026-08-30 09:00:00 ERROR pbp-orchestrator Collection failed\n",
            encoding="utf-8",
        )
        self.store = ConfigStore(self.config / "config.db")
        self.store.initialize()
        self.store.update_settings({"poll_seconds": "7", "webhook_url": "https://hooks.example.net/services/T0KEN-VALUE"})
        self.store.save_target(
            name="paris-edge",
            panos_url="https://192.0.2.10",
            api_key="super-secret-api-key",
            target_serial="SER-PANORAMA",
            serials=["001122334455"],
            syslog_sources=["192.0.2.10"],
            tls_verify="false",
            device_identity={"model": "PA-440", "software_version": "12.2.2", "hostname": "paris-edge"},
        )

    def bundle(self, **kwargs):
        buffer = io.BytesIO()
        manifest = diagnostics.write_support_bundle(
            buffer,
            data_dir=self.data,
            config_store=self.store,
            log_dirs=(self.data / "logs", self.config / "logs"),
            now=datetime(2026, 8, 30, 10, 0, tzinfo=timezone.utc),
            **kwargs,
        )
        buffer.seek(0)
        return manifest, zipfile.ZipFile(buffer)


class SupportBundleTests(unittest.TestCase):
    PREFIX = "pbp-support-20260830T100000Z/"

    def test_bundle_never_carries_credential_material(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Deployment(Path(temporary_directory))
            _manifest, archive = deployment.bundle()
            with archive:
                blob = b"".join(archive.read(name) for name in archive.namelist())
            self.assertNotIn(b"super-secret-api-key", blob)
            self.assertNotIn(b"T0KEN-VALUE", blob)
            self.assertNotIn(
                deployment.store.recovery_key().encode(), blob
            )

    def test_bundle_reports_the_running_versions_and_every_setting(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Deployment(Path(temporary_directory))
            _manifest, archive = deployment.bundle()
            with archive:
                environment = json.loads(archive.read(self.PREFIX + "environment.json"))
                configuration = json.loads(
                    archive.read(self.PREFIX + "configuration.json")
                )
            self.assertEqual(environment["application_version"], __version__)
            self.assertIn("cryptography", environment["dependencies"])
            self.assertTrue(environment["python_version"])
            self.assertEqual(configuration["settings"]["poll_seconds"], "7")
            self.assertEqual(configuration["webhook"]["host"], "hooks.example.net")
            self.assertTrue(configuration["webhook"]["path_present"])
            target = configuration["targets"][0]
            self.assertEqual(target["name"], "paris-edge")
            self.assertEqual(target["mode"], "panorama")
            self.assertEqual(target["sw_version"], "12.2.2")
            self.assertTrue(target["api_key_configured"])
            self.assertNotIn("api_key", target)

    def test_bundle_carries_the_process_log_and_the_refused_syslog(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Deployment(Path(temporary_directory))
            _manifest, archive = deployment.bundle()
            with archive:
                names = archive.namelist()
                self.assertIn(self.PREFIX + "logs/collector.log", names)
                self.assertIn("Collection failed", archive.read(self.PREFIX + "logs/collector.log").decode())
                received = archive.read(self.PREFIX + "syslog/received.jsonl").decode()
                self.assertIn("device_serial_not_registered", received)
                self.assertIn(self.PREFIX + "syslog/routing.jsonl", names)
                self.assertIn(self.PREFIX + "syslog/triggers-paris-edge.jsonl", names)

    def test_bundle_carries_the_latest_api_check_with_its_raw_xml(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Deployment(Path(temporary_directory))
            _manifest, archive = deployment.bundle()
            with archive:
                names = archive.namelist()
            self.assertIn(
                self.PREFIX + "api-checks/paris-edge/20260830T080000Z/api-check.jsonl", names
            )
            self.assertIn(
                self.PREFIX + "api-checks/paris-edge/20260830T080000Z/raw/batch-0001.txt",
                names,
            )

    def test_bundle_inventories_both_run_families_and_the_storage(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Deployment(Path(temporary_directory))
            _manifest, archive = deployment.bundle()
            with archive:
                runs = json.loads(archive.read(self.PREFIX + "runs.json"))
                storage = json.loads(archive.read(self.PREFIX + "storage.json"))
            kinds = {run["kind"] for run in runs}
            self.assertEqual(kinds, {"incident", "api_check"})
            self.assertTrue(all(run["target"] == "paris-edge" for run in runs))
            self.assertTrue(any(run["capture_present"] for run in runs))
            self.assertIn("targets", storage["areas"])

    def test_every_file_is_listed_with_its_checksum(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Deployment(Path(temporary_directory))
            manifest, archive = deployment.bundle()
            with archive:
                names = set(archive.namelist())
                for entry in manifest["files"]:
                    self.assertIn(self.PREFIX + entry["path"], names)
                    self.assertEqual(len(entry["sha256"]), 64)
            self.assertEqual(manifest["application_version"], __version__)
            self.assertEqual(manifest["format_version"], diagnostics.BUNDLE_FORMAT_VERSION)

    def test_journal_export_is_bounded_and_starts_on_a_record_boundary(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Deployment(Path(temporary_directory))
            journal = deployment.data / "syslog-received.jsonl"
            with journal.open("a", encoding="utf-8") as handle:
                for index in range(2000):
                    handle.write(json.dumps({"timestamp": index, "message": "x" * 200}) + "\n")
            _manifest, archive = deployment.bundle(journal_tail_bytes=4096)
            with archive:
                payload = archive.read(self.PREFIX + "syslog/received.jsonl")
            self.assertLessEqual(len(payload), 4096)
            for line in payload.splitlines():
                json.loads(line)

    def test_an_unreadable_configuration_still_produces_a_bundle(self):
        class _Broken:
            def get_settings(self):
                raise RuntimeError("database is locked")

        with tempfile.TemporaryDirectory() as temporary_directory:
            data = Path(temporary_directory)
            buffer = io.BytesIO()
            diagnostics.write_support_bundle(
                buffer, data_dir=data, config_store=_Broken()
            )
            buffer.seek(0)
            with zipfile.ZipFile(buffer) as archive:
                name = next(
                    item for item in archive.namelist() if item.endswith("configuration.json")
                )
                configuration = json.loads(archive.read(name))
            self.assertFalse(configuration["available"])
            self.assertIn("database is locked", configuration["error"])


class SupportBundleCommandTests(unittest.TestCase):
    def test_the_command_writes_an_archive_without_a_configuration_database(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output = root / "out" / "bundle.zip"
            code = diagnostics.main(
                [
                    "--data-dir",
                    str(root),
                    "--config-db",
                    str(root / "absent.db"),
                    "--output",
                    str(output),
                ]
            )
            self.assertEqual(code, 0)
            with zipfile.ZipFile(output) as archive:
                self.assertTrue(
                    any(name.endswith("environment.json") for name in archive.namelist())
                )


class AnonymizerTests(unittest.TestCase):
    """A bundle a customer cannot send is a bundle nobody can diagnose."""

    def _anonymizer(self):
        return Anonymizer(
            "a" * 64,
            [("PA-440-paris", "fw"), ("021201122656", "serial"), ("fw", "fw")],
        )

    def test_addresses_serials_and_names_become_tokens(self):
        anonymizer = self._anonymizer()
        text = anonymizer.apply(
            "PA-440-paris serial 021201122656 at 10.0.0.253 "
            "mac 8c:36:7a:03:10:db offender 203.0.113.7 "
            "link fe80::8e36:7aff:fe03:10db/64"
        )
        for original in (
            "PA-440-paris",
            "021201122656",
            "10.0.0.253",
            "8c:36:7a:03:10:db",
            "203.0.113.7",
            "fe80::8e36:7aff:fe03:10db",
        ):
            self.assertNotIn(original, text)
        self.assertRegex(text, r"ip-[0-9a-f]{10}")
        self.assertRegex(text, r"serial-[0-9a-f]{10}")
        self.assertRegex(text, r"fw-[0-9a-f]{10}")
        self.assertRegex(text, r"mac-[0-9a-f]{10}")
        # The prefix length of an address must survive, it is diagnostic.
        self.assertIn("/64", text)

    def test_a_value_keeps_one_token_everywhere_and_across_exports(self):
        first = self._anonymizer().apply("10.0.0.253 talks to 10.0.0.253")
        second = self._anonymizer().apply("seen again: 10.0.0.253")
        token = first.split()[0]
        self.assertEqual(first.count(token), 2)
        self.assertIn(token, second)

    def test_a_different_installation_produces_different_tokens(self):
        mine = Anonymizer("a" * 64).apply("10.0.0.253")
        theirs = Anonymizer("b" * 64).apply("10.0.0.253")
        self.assertNotEqual(mine, theirs)

    def test_loopback_and_unspecified_addresses_stay_readable(self):
        text = self._anonymizer().apply(
            "Listening on udp://0.0.0.0:5514 and health on 127.0.0.1"
        )
        self.assertIn("0.0.0.0", text)
        self.assertIn("127.0.0.1", text)

    def test_an_address_ending_a_sentence_is_still_replaced(self):
        # Shape taken from a real PAN-OS system log.
        text = self._anonymizer().apply(
            "authenticated for user 'admin'.   From: 10.0.0.52."
        )
        self.assertNotIn("10.0.0.52", text)
        self.assertTrue(text.endswith("."))

    def test_a_serial_inside_a_filename_is_still_replaced(self):
        # Shape taken from a real PAN-OS scheduled-export log.
        text = self._anonymizer().apply(
            "Successfully sent: file 'PA_021201122656_dt_12.2.2_20260830.tgz'"
        )
        self.assertNotIn("021201122656", text)
        self.assertIn("12.2.2", text)

    def test_a_longer_dotted_number_is_not_mistaken_for_an_address(self):
        self.assertIn(
            "1.2.3.4.5", self._anonymizer().apply("build 1.2.3.4.5 shipped")
        )

    def test_a_value_that_is_not_an_address_is_left_alone(self):
        text = self._anonymizer().apply("sw-version 12.2.2 app 9141-10215 999.1.1.1")
        self.assertIn("12.2.2", text)
        self.assertIn("9141-10215", text)
        # 999 is not a valid octet, so it was never an address to hide.
        self.assertIn("999.1.1.1", text)

    def test_a_short_name_never_swallows_unrelated_words(self):
        # "fw" is below the literal floor: replacing it would rewrite every
        # occurrence of the word inside ordinary log lines.
        self.assertIn("firewall", self._anonymizer().apply("firewall unreachable"))

    def test_a_name_equal_to_the_platform_model_keeps_the_model_legible(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = ConfigStore(Path(temporary_directory) / "config.db")
            store.initialize()
            store.save_target(
                name="PA-440",
                panos_url="https://192.0.2.10",
                api_key="key",
                target_serial=None,
                serials=["021201122656"],
                syslog_sources=["192.0.2.10"],
                device_identity={
                    "model": "PA-440",
                    "hostname": "PA-440",
                    "software_version": "12.2.2",
                },
            )
            text = build_anonymizer(store).apply(
                "<model>PA-440</model><serial>021201122656</serial>"
            )
            self.assertIn("PA-440", text)
            self.assertNotIn("021201122656", text)

    def test_the_mapping_translates_every_token_back(self):
        anonymizer = self._anonymizer()
        anonymized = anonymizer.apply("offender 203.0.113.7")
        rows = list(
            csv.reader(io.StringIO(anonymizer.mapping_csv().decode("utf-8-sig")))
        )
        self.assertEqual(rows[0], ["token", "original_value"])
        for token, original in rows[1:]:
            anonymized = anonymized.replace(token, original)
        self.assertIn("203.0.113.7", anonymized)


class AnonymizedBundleTests(unittest.TestCase):
    PREFIX = "pbp-support-20260830T100000Z/"

    def test_an_anonymized_bundle_names_no_address_or_serial(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Deployment(Path(temporary_directory))
            anonymizer = build_anonymizer(deployment.store)
            _manifest, archive = deployment.bundle(anonymizer=anonymizer)
            with archive:
                names = archive.namelist()
                blob = b"".join(archive.read(name) for name in names)
                manifest = json.loads(archive.read(self.PREFIX + "manifest.json"))
            self.assertNotIn(b"192.0.2.10", blob)
            self.assertNotIn(b"001122334455", blob)
            self.assertNotIn(b"paris-edge", blob)
            self.assertTrue(manifest["anonymized"])
            self.assertTrue(any("triggers-fw-" in name for name in names))
            # The firewall name is a directory component of the export too.
            self.assertFalse(any("paris-edge" in name for name in names))

    def test_the_token_mapping_never_travels_inside_the_bundle(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Deployment(Path(temporary_directory))
            anonymizer = build_anonymizer(deployment.store)
            _manifest, archive = deployment.bundle(anonymizer=anonymizer)
            with archive:
                blob = b"".join(archive.read(name) for name in archive.namelist())
            self.assertIn("192.0.2.10", anonymizer.mapping)
            self.assertNotIn(b"original_value", blob)
            for original in anonymizer.mapping:
                self.assertNotIn(original.encode(), blob)

    def test_a_complete_bundle_still_states_that_it_is_not_anonymized(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Deployment(Path(temporary_directory))
            manifest, archive = deployment.bundle()
            with archive:
                blob = b"".join(archive.read(name) for name in archive.namelist())
            self.assertFalse(manifest["anonymized"])
            self.assertIn(b"192.0.2.10", blob)

    def test_the_command_writes_the_mapping_only_beside_an_anonymized_bundle(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            deployment = _Deployment(root)
            mapping = root / "mapping.csv"
            code = diagnostics.main(
                [
                    "--data-dir",
                    str(deployment.data),
                    "--config-db",
                    str(deployment.config / "config.db"),
                    "--output",
                    str(root / "bundle.zip"),
                    "--anonymize",
                    "--mapping",
                    str(mapping),
                ]
            )
            self.assertEqual(code, 0)
            self.assertIn("192.0.2.10", mapping.read_text(encoding="utf-8-sig"))
            with zipfile.ZipFile(root / "bundle.zip") as archive:
                blob = b"".join(archive.read(name) for name in archive.namelist())
            self.assertNotIn(b"192.0.2.10", blob)

    def test_the_mapping_flag_alone_is_refused(self):
        with self.assertRaises(SystemExit):
            diagnostics.main(["--mapping", "/tmp/should-not-be-written.csv"])


if __name__ == "__main__":
    unittest.main()


class _Incidents:
    """Several incident runs across two firewalls, with raw XML and reports."""

    def __init__(self, root: Path):
        self.data = root / "data"
        for target, runs in (
            ("fw-a", ("20260830T090000Z", "20260830T100000Z", "20260830T110000Z", "20260830T120000Z")),
            ("fw-b", ("20260829T090000Z",)),
        ):
            for run_id in runs:
                directory = self.data / "targets" / target / "incidents" / run_id
                (directory / "raw").mkdir(parents=True)
                (directory / "incident.jsonl").write_text(
                    json.dumps({"event": "monitor_started", "run_id": run_id, "peer": "192.0.2.77"})
                    + "\n",
                    encoding="utf-8",
                )
                (directory / "raw" / "batch-0001.txt").write_text(
                    "=== COMMAND: packet_buffer_protection ===\n<response status=\"success\"/>\n",
                    encoding="utf-8",
                )
                (directory / "report.html").write_text("<html>report</html>", encoding="utf-8")
                (directory / "report-v2.html").write_text(
                    "<html>layered report</html>", encoding="utf-8"
                )

    def bundle(self, **kwargs):
        buffer = io.BytesIO()
        manifest = diagnostics.write_support_bundle(
            buffer,
            data_dir=self.data,
            now=datetime(2026, 8, 30, 13, 0, tzinfo=timezone.utc),
            **kwargs,
        )
        buffer.seek(0)
        return manifest, zipfile.ZipFile(buffer)


class RecentIncidentExportTests(unittest.TestCase):
    PREFIX = "pbp-support-20260830T130000Z/"

    def test_the_newest_incidents_travel_with_their_raw_xml_but_not_their_report(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Incidents(Path(temporary_directory))
            _manifest, archive = deployment.bundle()
            with archive:
                names = set(archive.namelist())
                runs = json.loads(archive.read(self.PREFIX + "runs.json"))
            incidents = self.PREFIX + "incidents/"
            self.assertIn(incidents + "fw-a/20260830T120000Z/incident.jsonl", names)
            self.assertIn(incidents + "fw-a/20260830T120000Z/raw/batch-0001.txt", names)
            self.assertIn(incidents + "fw-a/20260830T100000Z/incident.jsonl", names)
            self.assertIn(incidents + "fw-b/20260829T090000Z/incident.jsonl", names)
            # The fourth, oldest run of fw-a stays behind the per-firewall limit.
            self.assertNotIn(incidents + "fw-a/20260830T090000Z/incident.jsonl", names)
            # Neither report travels: both regenerate from the JSONL beside them.
            self.assertFalse(any(name.endswith("report.html") for name in names))
            self.assertFalse(any(name.endswith("report-v2.html") for name in names))
            bundled = {(run["target"], run["run_id"]) for run in runs if run["bundled"]}
            self.assertEqual(
                bundled,
                {
                    ("fw-a", "20260830T120000Z"),
                    ("fw-a", "20260830T110000Z"),
                    ("fw-a", "20260830T100000Z"),
                    ("fw-b", "20260829T090000Z"),
                },
            )
            self.assertTrue(
                all(not run["bundled"] for run in runs if run["run_id"] == "20260830T090000Z")
            )

    def test_the_size_budget_keeps_whole_runs_and_drops_the_oldest_first(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Incidents(Path(temporary_directory))
            newest = deployment.data / "targets" / "fw-a" / "incidents" / "20260830T120000Z"
            size = sum(
                path.stat().st_size
                for path in newest.rglob("*")
                if path.is_file()
                and path.name not in {"report.html", "report-v2.html"}
            )
            _manifest, archive = deployment.bundle(incident_budget_bytes=size * 2 + 1)
            with archive:
                exported = [
                    name for name in archive.namelist() if "/incidents/" in name and name.endswith("incident.jsonl")
                ]
            self.assertEqual(
                sorted(exported),
                [
                    self.PREFIX + "incidents/fw-a/20260830T110000Z/incident.jsonl",
                    self.PREFIX + "incidents/fw-a/20260830T120000Z/incident.jsonl",
                ],
            )

    def test_incident_evidence_is_anonymized_with_the_rest(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Incidents(Path(temporary_directory))
            _manifest, archive = deployment.bundle(anonymizer=Anonymizer("salt"))
            with archive:
                blob = b"".join(archive.read(name) for name in archive.namelist())
            self.assertNotIn(b"192.0.2.77", blob)


class SyslogSummaryTests(unittest.TestCase):
    def test_the_reception_journal_is_counted_by_outcome_firewall_and_sender(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            journal = Path(temporary_directory) / "syslog-received.jsonl"
            records = [
                {"timestamp": "2026-08-30T09:00:00+00:00", "trigger": True, "target_names": ["fw-a"], "metadata": {"syslog_source_ip": "192.0.2.10"}},
                {"timestamp": "2026-08-30T09:00:01+00:00", "trigger": False, "target_names": [], "suppressed": "source_not_registered", "metadata": {"syslog_source_ip": "192.0.2.99"}},
                {"timestamp": "2026-08-30T09:00:02+00:00", "trigger": False, "target_names": [], "suppressed": "source_not_registered", "metadata": {"syslog_source_ip": "192.0.2.99"}},
                {"timestamp": "2026-08-30T09:00:03+00:00", "trigger": False, "target_names": [], "suppressed": "device_serial_missing", "metadata": {}, "transport_source_ip": "192.0.2.5"},
            ]
            journal.write_text(
                "\n".join(json.dumps(record) for record in records) + "\nnot json\n",
                encoding="utf-8",
            )
            summary = diagnostics.syslog_summary(journal)
        self.assertEqual(summary["records"], 4)
        self.assertEqual(summary["invalid_lines"], 1)
        self.assertEqual(summary["triggers"], 1)
        self.assertEqual(summary["accepted"], 1)
        self.assertEqual(summary["refused"], 3)
        self.assertEqual(
            summary["by_suppressed"], {"source_not_registered": 2, "device_serial_missing": 1}
        )
        self.assertEqual(summary["by_target"], {"fw-a": 1})
        self.assertEqual(list(summary["by_source"].items())[0], ("192.0.2.99", 2))
        self.assertEqual(summary["distinct_sources"], 3)
        self.assertEqual(summary["first_timestamp"], "2026-08-30T09:00:00+00:00")
        self.assertEqual(summary["last_timestamp"], "2026-08-30T09:00:03+00:00")

    def test_the_summary_travels_in_the_bundle(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Deployment(Path(temporary_directory))
            _manifest, archive = deployment.bundle()
            with archive:
                summary = json.loads(
                    archive.read(SupportBundleTests.PREFIX + "syslog/summary.json")
                )
        self.assertEqual(summary["by_suppressed"], {"device_serial_not_registered": 1})


class WebCertificateFactsTests(unittest.TestCase):
    def test_the_served_certificate_is_described_without_its_key(self):
        from pbp_monitoring.web_tls import ensure_self_signed_certificate

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            ensure_self_signed_certificate(
                root / "web-tls.crt", root / "web-tls.key", ["pbp.example.net", "192.0.2.20"]
            )
            facts = diagnostics.web_certificate_facts(root / "web-tls.crt")
            deployment = _Deployment(root / "deployment") if (root / "deployment").mkdir() is None else None
            _manifest, archive = deployment.bundle(tls_cert=root / "web-tls.crt")
            with archive:
                environment = json.loads(
                    archive.read(SupportBundleTests.PREFIX + "environment.json")
                )
                blob = b"".join(archive.read(name) for name in archive.namelist())
        certificate = facts["certificate"]
        self.assertTrue(certificate["self_signed"])
        self.assertIn("pbp.example.net", certificate["dns_names"])
        self.assertIn("192.0.2.20", certificate["ip_addresses"])
        self.assertFalse(certificate["expired"])
        self.assertGreater(certificate["days_remaining"], 0)
        self.assertEqual(len(certificate["sha256_fingerprint"]), 64)
        self.assertEqual(environment["web_tls"]["certificate"]["subject"], certificate["subject"])
        self.assertNotIn(b"PRIVATE KEY", blob)

    def test_an_absent_certificate_is_reported_not_fatal(self):
        facts = diagnostics.web_certificate_facts(Path("/nonexistent/web-tls.crt"))
        self.assertIsNone(facts["certificate"])
        self.assertIn("absent", facts["error"])

    def test_the_dashboard_hostnames_are_tokenized_in_an_anonymized_bundle(self):
        from unittest import mock

        from pbp_monitoring.web_tls import ensure_self_signed_certificate

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            ensure_self_signed_certificate(
                root / "web-tls.crt", root / "web-tls.key", ["pbp.customer.example", "localhost"]
            )
            with mock.patch.dict(
                "os.environ", {"WEB_TLS_HOSTNAMES": "pbp.customer.example,localhost,127.0.0.1"}
            ):
                hostnames = diagnostics.web_hostnames(root / "web-tls.crt")
                self.assertEqual(hostnames, ["pbp.customer.example"])
                (root / "deployment").mkdir()
                deployment = _Deployment(root / "deployment")
                anonymizer = build_anonymizer(deployment.store, hostnames)
                _manifest, archive = deployment.bundle(
                    tls_cert=root / "web-tls.crt", anonymizer=anonymizer
                )
                with archive:
                    blob = b"".join(archive.read(name) for name in archive.namelist())
        self.assertNotIn(b"pbp.customer.example", blob)
        self.assertIn(b"localhost", blob)
        self.assertIn("pbp.customer.example", anonymizer.mapping)


def _tar(members: dict[str, bytes], *, directory: str | None = None) -> io.BytesIO:
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        if directory:
            info = tarfile.TarInfo(directory)
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    buffer.seek(0)
    return buffer


class HostEvidenceTests(unittest.TestCase):
    def test_host_files_land_under_host_and_are_listed_in_the_manifest(self):
        evidence = diagnostics.read_host_evidence(
            _tar(
                {
                    "./compose-ps.txt": b"NAME  STATUS\ncollector  Up 3 hours (healthy)\n",
                    "./syslog-gateway.log": b"syslog-ng starting up; version='3.38'\n",
                },
                directory="./",
            )
        )
        self.assertEqual([name for name, _payload in evidence], ["compose-ps.txt", "syslog-gateway.log"])
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Deployment(Path(temporary_directory))
            manifest, archive = deployment.bundle(host_evidence=evidence)
            with archive:
                names = set(archive.namelist())
                gateway = archive.read(SupportBundleTests.PREFIX + "host/syslog-gateway.log")
        self.assertIn(SupportBundleTests.PREFIX + "host/compose-ps.txt", names)
        self.assertIn(b"syslog-ng starting up", gateway)
        sources = {entry["path"]: entry["source"] for entry in manifest["files"]}
        self.assertEqual(sources["host/compose-ps.txt"], "host")

    def test_unsafe_names_directories_and_oversized_files_are_ignored(self):
        evidence = diagnostics.read_host_evidence(
            _tar(
                {
                    "../etc/passwd": b"root:x:0:0\n",
                    "/absolute.txt": b"absolute\n",
                    "nested/ok.txt": b"nested is fine\n",
                    "huge.txt": b"x" * (diagnostics.HOST_EVIDENCE_MAX_FILE_BYTES + 1),
                    "fine.txt": b"fine\n",
                },
                directory="nested",
            )
        )
        self.assertEqual(sorted(name for name, _payload in evidence), ["fine.txt", "nested/ok.txt"])

    def test_host_evidence_is_scrubbed_and_anonymized_like_the_rest(self):
        evidence = diagnostics.read_host_evidence(
            _tar(
                {
                    "compose-config.yaml": b"environment:\n  PANOS_API_KEY=LUFRPT-secret\nhost: 198.51.100.7\n",
                }
            )
        )
        self.assertNotIn(b"LUFRPT-secret", evidence[0][1])
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Deployment(Path(temporary_directory))
            _manifest, archive = deployment.bundle(
                host_evidence=evidence, anonymizer=Anonymizer("salt")
            )
            with archive:
                payload = archive.read(SupportBundleTests.PREFIX + "host/compose-config.yaml")
        self.assertNotIn(b"198.51.100.7", payload)
        self.assertIn(b"ip-", payload)

    def test_the_command_reads_host_evidence_from_a_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "host.tar").write_bytes(_tar({"compose-ps.txt": b"collector Up\n"}).getvalue())
            output = root / "bundle.zip"
            code = diagnostics.main(
                [
                    "--data-dir",
                    str(root / "data"),
                    "--config-db",
                    str(root / "absent.db"),
                    "--output",
                    str(output),
                    "--host-evidence",
                    str(root / "host.tar"),
                ]
            )
            self.assertEqual(code, 0)
            with zipfile.ZipFile(output) as archive:
                names = archive.namelist()
        self.assertTrue(any(name.endswith("host/compose-ps.txt") for name in names))

    def test_unreadable_host_evidence_still_yields_a_bundle_that_says_so(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "host.tar").write_bytes(b"this is not a tar archive")
            output = root / "bundle.zip"
            code = diagnostics.main(
                [
                    "--data-dir",
                    str(root / "data"),
                    "--config-db",
                    str(root / "absent.db"),
                    "--output",
                    str(output),
                    "--host-evidence",
                    str(root / "host.tar"),
                ]
            )
            self.assertEqual(code, 0)
            with zipfile.ZipFile(output) as archive:
                error = next(name for name in archive.namelist() if name.endswith("host/error.txt"))
                self.assertIn(b"not readable", archive.read(error))


class HostScriptTests(unittest.TestCase):
    SCRIPT = Path(__file__).resolve().parent.parent / "pbp-support.sh"

    def test_the_host_script_is_executable_and_parses(self):
        import shutil
        import subprocess

        self.assertTrue(self.SCRIPT.is_file())
        self.assertTrue(self.SCRIPT.stat().st_mode & 0o111, "pbp-support.sh must be executable")
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("bash is not available")
        completed = subprocess.run([bash, "-n", str(self.SCRIPT)], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_the_host_script_feeds_the_collector_and_stays_read_only(self):
        text = self.SCRIPT.read_text(encoding="utf-8")
        self.assertIn("pbp-support $anonymize --host-evidence -", text)
        self.assertIn("compose logs --no-color --timestamps --tail 500 syslog-gateway", text)
        self.assertIn("compose run --rm --no-deps -T collector", text)
        for forbidden in ("compose down", "compose restart", "compose up", "docker rm ", "volume rm"):
            self.assertNotIn(forbidden, text)
