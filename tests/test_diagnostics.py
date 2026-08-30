"""Proofs for the persistent logs and the deployment support bundle.

The bundle is meant to travel from a customer to the maintainer. Two
properties matter more than its contents: it must never carry credential
material, and producing it must never be able to stop the collector.
"""

import io
import json
import logging
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from pbp_monitoring import __version__, diagnostics
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
        target = self.data / "targets" / "fw-a"
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
            json.dumps({"timestamp": "2026-08-30T09:00:01+00:00", "target_names": ["fw-a"]})
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
            name="fw-a",
            panos_url="https://192.0.2.10",
            api_key="super-secret-api-key",
            target_serial="SER-PANORAMA",
            serials=["001122334455"],
            syslog_sources=["192.0.2.10"],
            tls_verify="false",
            device_identity={"model": "PA-440", "software_version": "12.2.2", "hostname": "fw-a"},
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
            self.assertEqual(target["name"], "fw-a")
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
                self.assertIn(self.PREFIX + "syslog/triggers-fw-a.jsonl", names)

    def test_bundle_carries_the_latest_api_check_with_its_raw_xml(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            deployment = _Deployment(Path(temporary_directory))
            _manifest, archive = deployment.bundle()
            with archive:
                names = archive.namelist()
            self.assertIn(
                self.PREFIX + "api-checks/fw-a/20260830T080000Z/api-check.jsonl", names
            )
            self.assertIn(
                self.PREFIX + "api-checks/fw-a/20260830T080000Z/raw/batch-0001.txt",
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
            self.assertTrue(all(run["target"] == "fw-a" for run in runs))
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


if __name__ == "__main__":
    unittest.main()
