import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pbp_monitoring.orchestrator import Config, load_env_file


BASE_ENV = {
    "PANOS_URL": "https://firewall.invalid",
    "PANOS_API_KEY": "fixture-key",
}


def config_from_env(**overrides):
    environment = {**BASE_ENV, **overrides}
    with patch.dict(os.environ, environment, clear=True):
        return Config.from_env()


class ConfigurationTests(unittest.TestCase):
    def test_env_file_loads_locally_but_process_environment_wins(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            env_file = Path(temporary_directory) / ".env"
            env_file.write_text(
                "PANOS_URL=https://from-file.invalid\n"
                "PANOS_API_KEY=file-key\n"
                "GENERATE_HTML_REPORT=false\n",
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"PANOS_URL": "https://from-process.invalid"},
                clear=True,
            ):
                load_env_file(env_file)
                cfg = Config.from_env()

            self.assertEqual(cfg.panos_url, "https://from-process.invalid")
            self.assertEqual(cfg.api_key, "file-key")
            self.assertFalse(cfg.generate_html_report)
            self.assertTrue(cfg.generate_text_export)

    def test_text_export_can_be_disabled(self):
        cfg = config_from_env(GENERATE_TEXT_EXPORT="false")

        self.assertFalse(cfg.generate_text_export)

    def test_conflicting_duplicate_does_not_reveal_values(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            env_file = Path(temporary_directory) / ".env"
            env_file.write_text(
                "PANOS_API_KEY=first-secret\nPANOS_API_KEY=second-secret\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, "conflicting duplicate") as raised:
                    load_env_file(env_file)

            self.assertNotIn("first-secret", str(raised.exception))
            self.assertNotIn("second-secret", str(raised.exception))

    def test_http_management_url_is_rejected(self):
        with patch.dict(
            os.environ,
            {
                "PANOS_URL": "http://firewall.invalid",
                "PANOS_API_KEY": "fixture-key",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                Config.from_env()

    def test_multi_target_inventory_resolves_keys_from_environment(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            inventory = Path(temporary_directory) / "targets.json"
            inventory.write_text(
                json.dumps(
                    {
                        "targets": [
                            {
                                "name": "fw-a",
                                "url_env": "PANOS_URL_FW_A",
                                "api_key_env": "PANOS_API_KEY_FW_A",
                                "serial": "SER-A",
                                "syslog_sources": ["192.0.2.10"],
                            },
                            {
                                "name": "fw-b",
                                "url": "https://fw-b.invalid",
                                "api_key_env": "PANOS_API_KEY_FW_B",
                                "tls_verify": True,
                                "serials": ["SER-B"],
                                "syslog_sources": ["192.0.2.11"],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "PANOS_TARGETS_FILE": str(inventory),
                    "PANOS_API_KEY_FW_A": "key-a",
                    "PANOS_API_KEY_FW_B": "key-b",
                    "PANOS_URL_FW_A": "https://fw-a.invalid",
                },
                clear=True,
            ):
                cfg = Config.from_env()

            self.assertEqual([item.name for item in cfg.target_profiles], ["fw-a", "fw-b"])
            self.assertEqual(cfg.target_profiles[0].panos_url, "https://fw-a.invalid")
            self.assertEqual(cfg.target_profiles[1].api_key, "key-b")
            self.assertFalse(cfg.target_profiles[0].tls_verify)
            self.assertTrue(cfg.target_profiles[1].tls_verify)
            target_cfg = cfg.for_target(cfg.target_profiles[1])
            self.assertEqual(target_cfg.target_name, "fw-b")
            self.assertEqual(target_cfg.output_dir, Path("captures/targets/fw-b"))

    def test_multi_target_inventory_allows_shared_source_for_probe(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            inventory = Path(temporary_directory) / "targets.json"
            inventory.write_text(
                json.dumps(
                    [
                        {
                            "name": "fw-a",
                            "url": "https://fw-a.invalid",
                            "api_key_env": "KEY_A",
                            "syslog_sources": ["192.0.2.10"],
                        },
                        {
                            "name": "fw-b",
                            "url": "https://fw-b.invalid",
                            "api_key_env": "KEY_B",
                            "syslog_sources": ["192.0.2.10"],
                        },
                    ]
                ),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {
                    "PANOS_TARGETS_FILE": str(inventory),
                    "KEY_A": "key-a",
                    "KEY_B": "key-b",
                },
                clear=True,
            ):
                cfg = Config.from_env()

            self.assertEqual(len(cfg.target_profiles), 2)
            self.assertEqual(
                cfg.target_profiles[0].syslog_sources,
                cfg.target_profiles[1].syslog_sources,
            )

    def test_private_inventory_accepts_literal_url_and_key_without_repr_leak(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            inventory = Path(temporary_directory) / "targets.json"
            inventory.write_text(
                json.dumps(
                    {
                        "targets": [
                            {
                                "name": "standalone",
                                "url": "https://firewall.invalid",
                                "api_key": "literal-secret-key",
                                "syslog_sources": ["192.0.2.10"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"PANOS_TARGETS_FILE": str(inventory)},
                clear=True,
            ):
                cfg = Config.from_env()

            self.assertEqual(cfg.target_profiles[0].api_key, "literal-secret-key")
            self.assertNotIn("literal-secret-key", repr(cfg))
            self.assertNotIn("literal-secret-key", repr(cfg.target_profiles[0]))

    def test_ip_shorthand_derives_https_url_and_syslog_source(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            inventory = Path(temporary_directory) / "targets.json"
            inventory.write_text(
                json.dumps(
                    {
                        "targets": [
                            {
                                "name": "fw-a",
                                "ip": "192.0.2.10",
                                "api_key": "fixture-key",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"PANOS_TARGETS_FILE": str(inventory)},
                clear=True,
            ):
                cfg = Config.from_env()

            profile = cfg.target_profiles[0]
            self.assertEqual(profile.panos_url, "https://192.0.2.10")
            self.assertEqual(profile.syslog_sources, ("192.0.2.10",))

    def test_ip_shorthand_cannot_be_combined_with_url(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            inventory = Path(temporary_directory) / "targets.json"
            inventory.write_text(
                json.dumps(
                    {
                        "targets": [
                            {
                                "name": "fw-a",
                                "ip": "192.0.2.10",
                                "url": "https://firewall.invalid",
                                "api_key": "fixture-key",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(
                os.environ,
                {"PANOS_TARGETS_FILE": str(inventory)},
                clear=True,
            ):
                with self.assertRaisesRegex(ValueError, "exactly one"):
                    Config.from_env()

    def test_useful_numeric_boundaries_are_accepted(self):
        lower_bound = config_from_env(
            POLL_SECONDS="0.001",
            MAX_MONITOR_SECONDS="0.001",
            INCIDENT_IDLE_TTL_SECONDS="0.001",
            RECOVERY_THRESHOLD="0",
            LOW_SAMPLES_TO_STOP="1",
            REQUEST_TIMEOUT="0.001",
            MAX_SESSION_LOOKUPS="0",
            SESSION_RETRY_SECONDS="0",
            SYSLOG_PORT="1",
        )
        upper_bound = config_from_env(
            RECOVERY_THRESHOLD="100",
            SYSLOG_PORT="65535",
        )

        self.assertEqual(lower_bound.poll_seconds, 0.001)
        self.assertEqual(lower_bound.max_monitor_seconds, 0.001)
        self.assertEqual(lower_bound.incident_idle_ttl_seconds, 0.001)
        self.assertEqual(lower_bound.recovery_threshold, 0)
        self.assertEqual(lower_bound.low_samples_to_stop, 1)
        self.assertEqual(lower_bound.request_timeout, 0.001)
        self.assertEqual(lower_bound.max_session_lookups, 0)
        self.assertEqual(lower_bound.session_retry_seconds, 0)
        self.assertEqual(lower_bound.syslog_port, 1)
        self.assertEqual(upper_bound.recovery_threshold, 100)
        self.assertEqual(upper_bound.syslog_port, 65535)

    def test_out_of_range_numeric_values_are_rejected(self):
        invalid_values = (
            ("POLL_SECONDS", "0"),
            ("POLL_SECONDS", "-0.1"),
            ("POLL_SECONDS", "nan"),
            ("POLL_SECONDS", "inf"),
            ("MAX_MONITOR_SECONDS", "0"),
            ("MAX_MONITOR_SECONDS", "-1"),
            ("MAX_MONITOR_SECONDS", "nan"),
            ("MAX_MONITOR_SECONDS", "inf"),
            ("INCIDENT_IDLE_TTL_SECONDS", "0"),
            ("INCIDENT_IDLE_TTL_SECONDS", "-1"),
            ("INCIDENT_IDLE_TTL_SECONDS", "nan"),
            ("INCIDENT_IDLE_TTL_SECONDS", "inf"),
            ("RECOVERY_THRESHOLD", "-1"),
            ("RECOVERY_THRESHOLD", "101"),
            ("LOW_SAMPLES_TO_STOP", "0"),
            ("LOW_SAMPLES_TO_STOP", "-1"),
            ("REQUEST_TIMEOUT", "0"),
            ("REQUEST_TIMEOUT", "-0.1"),
            ("REQUEST_TIMEOUT", "nan"),
            ("REQUEST_TIMEOUT", "inf"),
            ("MAX_SESSION_LOOKUPS", "-1"),
            ("SESSION_RETRY_SECONDS", "-0.1"),
            ("SESSION_RETRY_SECONDS", "nan"),
            ("SESSION_RETRY_SECONDS", "inf"),
            ("SYSLOG_PORT", "0"),
            ("SYSLOG_PORT", "65536"),
        )

        for name, value in invalid_values:
            with self.subTest(name=name, value=value):
                with self.assertRaisesRegex(ValueError, name):
                    config_from_env(**{name: value})

    def test_non_numeric_values_are_rejected(self):
        invalid_values = (
            ("POLL_SECONDS", "not-a-number"),
            ("MAX_MONITOR_SECONDS", "not-a-number"),
            ("INCIDENT_IDLE_TTL_SECONDS", "not-a-number"),
            ("RECOVERY_THRESHOLD", "1.5"),
            ("LOW_SAMPLES_TO_STOP", "1.5"),
            ("REQUEST_TIMEOUT", "not-a-number"),
            ("MAX_SESSION_LOOKUPS", "1.5"),
            ("SESSION_RETRY_SECONDS", "not-a-number"),
            ("SYSLOG_PORT", "1.5"),
        )

        for name, value in invalid_values:
            with self.subTest(name=name, value=value):
                with self.assertRaises(ValueError):
                    config_from_env(**{name: value})


if __name__ == "__main__":
    unittest.main()
