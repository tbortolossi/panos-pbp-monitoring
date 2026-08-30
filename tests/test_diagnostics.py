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
