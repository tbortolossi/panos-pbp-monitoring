import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pbp_monitoring.config_store import ConfigStore, StoredTarget
from pbp_monitoring.orchestrator import Config
from tests.support import (
    SHIPPED_PBKDF2_ITERATIONS,
    start_fast_password_hashing,
    stop_fast_password_hashing,
)


def setUpModule():
    start_fast_password_hashing()


def tearDownModule():
    stop_fast_password_hashing()


class ConfigStoreTests(unittest.TestCase):
    def test_api_key_is_encrypted_and_runtime_config_can_be_loaded(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            store = ConfigStore(root / "config.db")
            store.initialize()
            store.save_target(
                name="fw-a",
                panos_url="https://192.0.2.10",
                api_key="secret-api-key",
                target_serial="SER-A",
                serials=[],
                syslog_sources=["192.0.2.10"],
                tls_verify="true",
            )

            self.assertNotIn(b"secret-api-key", store.path.read_bytes())
            loaded = store.list_targets(include_secrets=True)
            self.assertIsInstance(loaded[0], StoredTarget)
            self.assertEqual(loaded[0].api_key, "secret-api-key")
            with patch.dict("os.environ", {"OUTPUT_DIR": str(root / "data")}, clear=True):
                config = Config.from_store(store)
            self.assertEqual(config.target_profiles[0].name, "fw-a")
            self.assertEqual(config.target_profiles[0].api_key, "secret-api-key")
            self.assertTrue(config.target_profiles[0].tls_verify)
            self.assertTrue(config.for_target(config.target_profiles[0]).tls_verify)

    def test_the_shipped_password_hashing_cost_stays_at_recommended_strength(self):
        """The suite lowers this cost; the shipped default must stay strong."""
        self.assertGreaterEqual(SHIPPED_PBKDF2_ITERATIONS, 600_000)

    def test_master_key_persists_and_password_is_salted(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = ConfigStore(Path(temporary_directory) / "config.db")
            store.initialize()
            key = store.key_path.read_bytes()
            self.assertEqual(store.recovery_key().encode(), key)
            self.assertFalse(store.recovery_key_acknowledged())
            store.acknowledge_recovery_key()
            self.assertTrue(store.recovery_key_acknowledged())
            store.initialize()
            self.assertEqual(store.key_path.read_bytes(), key)
            store.set_admin_password("long-enough-password")
            self.assertTrue(store.verify_admin_password("long-enough-password"))
            self.assertFalse(store.verify_admin_password("wrong-password"))
            self.assertNotIn(b"long-enough-password", store.path.read_bytes())
            store.set_admin_password("12345678")
            self.assertTrue(store.verify_admin_password("12345678"))
            with self.assertRaisesRegex(ValueError, "8 characters"):
                store.set_admin_password("1234567")

    def test_settings_are_validated_and_revision_changes(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = ConfigStore(Path(temporary_directory) / "config.db")
            store.initialize()
            revision = store.revision()
            store.update_settings({"recovery_threshold": "42"})
            self.assertEqual(store.get_settings()["recovery_threshold"], "42")
            self.assertGreater(store.revision(), revision)
            with self.assertRaises(ValueError):
                store.update_settings({"poll_seconds": "0"})

    def test_large_session_thresholds_keep_the_session_table_walk_bounded(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = ConfigStore(Path(temporary_directory) / "config.db")
            store.initialize()
            settings = store.get_settings()
            self.assertEqual(settings["large_session_min_kb"], "1048576")
            self.assertEqual(settings["large_session_min_age_seconds"], "600")
            store.update_settings(
                {"large_session_min_kb": "0", "large_session_min_age_seconds": "0"}
            )
            self.assertEqual(store.get_settings()["large_session_min_kb"], "0")
            with self.assertRaisesRegex(ValueError, "large_session_min_kb"):
                store.update_settings({"large_session_min_kb": "10"})
            with self.assertRaisesRegex(ValueError, "large_session_min_age_seconds"):
                store.update_settings({"large_session_min_age_seconds": "-1"})

    def test_webhook_url_accepts_https_and_empty_but_rejects_garbage(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = ConfigStore(Path(temporary_directory) / "config.db")
            store.initialize()
            store.update_settings({"webhook_url": "https://hooks.example.test/pbp"})
            self.assertEqual(
                store.get_settings()["webhook_url"],
                "https://hooks.example.test/pbp",
            )
            store.update_settings({"webhook_url": ""})
            self.assertEqual(store.get_settings()["webhook_url"], "")
            with self.assertRaisesRegex(ValueError, "webhook_url"):
                store.update_settings({"webhook_url": "ftp://nope"})
            with self.assertRaisesRegex(ValueError, "webhook_url"):
                store.update_settings({"webhook_url": "not a url"})

    def test_invalid_source_and_empty_new_key_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = ConfigStore(Path(temporary_directory) / "config.db")
            store.initialize()
            with self.assertRaises(ValueError):
                store.save_target(
                    name="fw-a", panos_url="https://192.0.2.10", api_key=None,
                    target_serial=None, serials=[], syslog_sources=["192.0.2.10"],
                )
            with self.assertRaisesRegex(ValueError, "Syslog source"):
                store.save_target(
                    name="fw-a", panos_url="https://192.0.2.10", api_key="key",
                    target_serial=None, serials=[], syslog_sources=["not-an-ip"],
                )

    def test_new_firewall_defaults_to_disabled_tls_verification(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = ConfigStore(Path(temporary_directory) / "config.db")
            store.initialize()
            store.save_target(
                name="fw-a", panos_url="https://192.0.2.10", api_key="key",
                target_serial=None, serials=[], syslog_sources=["192.0.2.10"],
            )

            target = store.list_targets()[0]
            self.assertEqual(target["tls_verify"], "false")
            self.assertFalse(Config.from_store(store).target_profiles[0].tls_verify)

    def test_global_tls_setting_is_migrated_to_existing_firewalls(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = Path(temporary_directory) / "config.db"
            connection = sqlite3.connect(database)
            try:
                connection.executescript(
                    """
                    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
                    INSERT INTO settings VALUES ('tls_verify','true','now');
                    CREATE TABLE targets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
                        panos_url TEXT NOT NULL, api_key_ciphertext TEXT NOT NULL,
                        target_serial TEXT, serials_json TEXT NOT NULL,
                        syslog_sources_json TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                    );
                    INSERT INTO targets
                    (name,panos_url,api_key_ciphertext,target_serial,serials_json,
                     syslog_sources_json,enabled,created_at,updated_at)
                    VALUES ('fw-a','https://192.0.2.10','encrypted',NULL,'[]',
                            '["192.0.2.10"]',1,'now','now');
                    """
                )
                connection.commit()
            finally:
                connection.close()
            store = ConfigStore(database)
            store.initialize()

            migrated = store.list_targets()[0]
            self.assertEqual(migrated["tls_verify"], "true")
            self.assertIsNone(migrated["hostname"])
            self.assertEqual(migrated["dp_core_functions"], ())
            self.assertIsNone(migrated["dp_core_functions_identity"])
            self.assertNotIn("tls_verify", store.get_settings())

    def test_device_identity_is_stored_and_kept_when_not_refreshed(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = ConfigStore(Path(temporary_directory) / "config.db")
            store.initialize()
            target_id = store.save_target(
                name="fw-a", panos_url="https://192.0.2.10", api_key="key",
                serials=["001122"], syslog_sources=["192.0.2.10"],
                device_identity={
                    "hostname": "lab-fw-01", "model": "PA-440", "software_version": "11.1.4-h7"
                },
            )
            stored = store.list_targets()[0]
            self.assertEqual(
                (stored["hostname"], stored["model"], stored["sw_version"]),
                ("lab-fw-01", "PA-440", "11.1.4-h7"),
            )

            store.save_target(
                target_id=target_id, name="fw-a", panos_url="https://192.0.2.10",
                api_key=None, serials=["001122"], syslog_sources=["192.0.2.10"],
            )

            self.assertEqual(store.list_targets()[0]["hostname"], "lab-fw-01")

    def test_core_map_is_stored_with_the_release_it_was_captured_on(self):
        core_functions = [
            {
                "dataplane": "dp0",
                "core_id": "1",
                "functions": ["flow_lookup", "flow_fastpath"],
                "forwards_traffic": True,
            }
        ]
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = ConfigStore(Path(temporary_directory) / "config.db")
            store.initialize()
            target_id = store.save_target(
                name="fw-a", panos_url="https://192.0.2.10", api_key="key",
                serials=["001122"], syslog_sources=["192.0.2.10"],
                device_identity={
                    "hostname": "lab-fw-01", "model": "PA-440", "software_version": "11.1.4-h7"
                },
                dp_core_functions=core_functions,
            )
            stored = store.list_targets(include_secrets=True)[0]
            self.assertEqual(stored.dp_core_functions, tuple(core_functions))
            self.assertEqual(stored.dp_core_functions_identity, "PA-440|11.1.4-h7")

            store.save_target(
                target_id=target_id, name="fw-a", panos_url="https://192.0.2.10",
                api_key=None, serials=["001122"], syslog_sources=["192.0.2.10"],
            )

            kept = store.list_targets(include_secrets=True)[0]
            self.assertEqual(kept.dp_core_functions, tuple(core_functions))
            self.assertEqual(kept.dp_core_functions_identity, "PA-440|11.1.4-h7")


    def test_a_requested_check_is_queued_then_cleared_by_its_result(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = ConfigStore(Path(temporary_directory) / "config.db")
            store.initialize()
            target_id = store.save_target(
                name="fw-a", panos_url="https://192.0.2.10", api_key="key",
                serials=["001122"], syslog_sources=["192.0.2.10"],
            )

            store.request_target_check(target_id)
            queued = store.list_targets()[0]
            self.assertTrue(queued["check_requested_at"])
            self.assertIsNone(queued["last_check_at"])

            store.record_target_check(
                target_id, kind="validation", status="ok",
                detail="run 20260829T120000Z", clear_request=True,
            )

            done = store.list_targets()[0]
            self.assertIsNone(done["check_requested_at"])
            self.assertEqual(done["last_check_status"], "ok")
            self.assertEqual(done["last_check_kind"], "validation")
            self.assertEqual(done["last_check_detail"], "run 20260829T120000Z")

    def test_refreshing_a_device_updates_its_core_map_and_the_revision(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = ConfigStore(Path(temporary_directory) / "config.db")
            store.initialize()
            target_id = store.save_target(
                name="fw-a", panos_url="https://192.0.2.10", api_key="key",
                serials=["001122"], syslog_sources=["192.0.2.10"],
                device_identity={
                    "hostname": "fw", "model": "PA-440", "software_version": "11.1.0"
                },
                dp_core_functions=[
                    {"dataplane": "dp0", "core_id": "1", "functions": ["flow_fastpath"],
                     "forwards_traffic": True}
                ],
            )
            before = store.revision()

            store.refresh_target_device(
                target_id,
                device_identity={
                    "hostname": "fw", "model": "PA-440", "software_version": "12.2.2"
                },
                dp_core_functions=[
                    {"dataplane": "dp0", "core_id": "1",
                     "functions": ["flow_fastpath", "flow_ctrl"], "forwards_traffic": True}
                ],
            )

            refreshed = store.list_targets(include_secrets=True)[0]
            self.assertEqual(refreshed.sw_version, "12.2.2")
            self.assertEqual(refreshed.dp_core_functions_identity, "PA-440|12.2.2")
            self.assertIn("flow_ctrl", refreshed.dp_core_functions[0]["functions"])
            self.assertNotEqual(store.revision(), before)

    def test_the_check_interval_is_bounded_and_can_be_disabled(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = ConfigStore(Path(temporary_directory) / "config.db")
            store.initialize()
            self.assertEqual(store.get_settings()["target_check_hours"], "24")

            store.update_settings({"target_check_hours": "0"})
            self.assertEqual(store.get_settings()["target_check_hours"], "0")

            with self.assertRaises(ValueError):
                store.update_settings({"target_check_hours": "-1"})

if __name__ == "__main__":
    unittest.main()


class RunDeletionQueueTests(unittest.TestCase):
    """The Web UI records deletions; the collector is what removes evidence."""

    def _store(self, root: Path) -> ConfigStore:
        store = ConfigStore(root / "config.db")
        store.initialize()
        return store

    def test_a_queued_deletion_is_idempotent_and_cleared_by_the_collector(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = self._store(Path(temporary_directory))

            store.request_run_deletion("fw-a", "20260101T000000Z")
            store.request_run_deletion("fw-a", "20260101T000000Z")

            pending = store.pending_run_deletions()
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0].target, "fw-a")
            self.assertEqual(pending[0].run_id, "20260101T000000Z")
            self.assertFalse(pending[0].deletes_everything)

            store.request_all_runs_deletion()
            pending = store.pending_run_deletions()
            self.assertEqual(len(pending), 2)
            self.assertTrue(pending[1].deletes_everything)

            for request in pending:
                store.clear_run_deletion(request.deletion_id)
            self.assertEqual(store.pending_run_deletions(), [])

    def test_a_traversing_or_empty_run_name_is_refused_before_it_is_stored(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = self._store(Path(temporary_directory))

            for target, run_id in (
                ("..", "run-1"),
                ("fw-a", ".."),
                ("fw-a", "../../etc"),
                ("fw a", "run-1"),
                ("", "run-1"),
                ("fw-a", ""),
                ("*", "run-1"),
            ):
                with self.assertRaises(ValueError):
                    store.request_run_deletion(target, run_id)

            self.assertEqual(store.pending_run_deletions(), [])
