import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pbp_monitoring.config_store import ConfigStore, StoredTarget
from pbp_monitoring.orchestrator import Config


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


if __name__ == "__main__":
    unittest.main()
