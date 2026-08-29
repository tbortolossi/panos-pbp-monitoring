import contextlib
import http.cookiejar
import re
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener

from pbp_monitoring.adminui import AdminController
from pbp_monitoring import __version__
from pbp_monitoring.config_store import ConfigStore
from pbp_monitoring.panos_keygen import SystemInfoError
from pbp_monitoring.webui import handler_factory


DEVICE_IDENTITY = {
    "hostname": "lab-fw-01",
    "serial": "001122334455",
    "model": "PA-440",
    "software_version": "11.1.4-h7",
}

CORE_FUNCTIONS = [
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
]


@contextlib.contextmanager
def signed_in_admin(root: Path):
    """Start the admin server, complete setup, and sign in."""
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), handler_factory(root / "data", 300, root / "config" / "config.db")
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        setup = opener.open(base + "/admin").read().decode()
        csrf = re.search(r'name="csrf" value="([^"]+)"', setup).group(1)
        login = opener.open(
            Request(
                base + "/admin/setup",
                data=urlencode(
                    {"csrf": csrf, "password": "long-test-password", "confirm": "long-test-password"}
                ).encode(),
            )
        ).read().decode()
        csrf = re.search(r'name="csrf" value="([^"]+)"', login).group(1)
        page = opener.open(
            Request(
                base + "/admin/login",
                data=urlencode({"csrf": csrf, "password": "long-test-password"}).encode(),
            )
        ).read().decode()
        yield opener, base, re.search(r'name="csrf" value="([^"]+)"', page).group(1), page
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class AdminUITests(unittest.TestCase):
    def test_initial_password_login_and_authenticated_configuration_page(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                handler_factory(root / "data", 300, root / "config" / "config.db"),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                setup = opener.open(base + "/admin").read().decode()
                setup_csrf = re.search(r'name="csrf" value="([^"]+)"', setup).group(1)
                setup_body = urlencode(
                    {
                        "csrf": setup_csrf,
                        "password": "long-test-password",
                        "confirm": "long-test-password",
                    }
                ).encode()
                login = opener.open(Request(base + "/admin/setup", data=setup_body)).read().decode()
                self.assertIn("Administrator sign in", login)
                login_csrf = re.search(r'name="csrf" value="([^"]+)"', login).group(1)
                login_body = urlencode(
                    {"csrf": login_csrf, "password": "long-test-password"}
                ).encode()
                page = opener.open(Request(base + "/admin/login", data=login_body)).read().decode()
                self.assertIn("Collector settings", page)
                self.assertIn("Firewalls", page)
                self.assertIn("Save the installation recovery key", page)
                self.assertIn("Download CSV", page)
                self.assertIn("TLS verify", page)
                self.assertIn("Change administrator password", page)
                csv_response = opener.open(base + "/admin/recovery-key.csv")
                self.assertIn(
                    f"pbp-monitoring-recovery-key-v{__version__}.csv",
                    csv_response.headers["Content-Disposition"],
                )
                csv_payload = csv_response.read().decode("utf-8-sig")
                self.assertIn("product,version,recovery_key", csv_payload)
                self.assertIn(f"PBP Monitoring,{__version__}", csv_payload)
                admin_csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
                acknowledged = opener.open(
                    Request(
                        base + "/admin/recovery-key/ack",
                        data=urlencode({"csrf": admin_csrf}).encode(),
                    )
                ).read().decode()
                self.assertIn("Recovery key delivery acknowledged", acknowledged)
                self.assertNotIn("Save the installation recovery key", acknowledged)

                changed = opener.open(
                    Request(
                        base + "/admin/password",
                        data=urlencode(
                            {
                                "csrf": admin_csrf,
                                "current_password": "long-test-password",
                                "new_password": "new-test-password",
                                "confirm_password": "new-test-password",
                            }
                        ).encode(),
                    )
                ).read().decode()
                self.assertIn("Administrator sign in", changed)
                store = ConfigStore(root / "config" / "config.db")
                self.assertFalse(store.verify_admin_password("long-test-password"))
                self.assertTrue(store.verify_admin_password("new-test-password"))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_firewall_form_uses_a_single_address_and_no_panorama_serial(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            with signed_in_admin(Path(temporary_directory)) as (_opener, _base, _csrf, page):
                self.assertIn("Firewall IP", page)
                self.assertIn("Authentication method", page)
                self.assertIn(
                    '<input type="radio" id="auth-credentials" name="auth_method" value="credentials" checked>',
                    page,
                )
                self.assertIn('<div class="panel" id="panel-credentials">', page)
                self.assertIn('<div class="panel" id="panel-key">', page)
                self.assertNotIn('<select name="auth_method">', page)
                self.assertNotIn('name="auth_method" value="stored"', page)
                self.assertNotIn("Panorama target serial", page)
                self.assertNotIn("Management URL", page)
                self.assertNotIn("Allowed Syslog source IP(s)", page)
                self.assertIn('<select name="tls_verify">', page)

    def test_saving_generates_a_key_and_reads_the_serial_from_the_firewall(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with signed_in_admin(root) as (opener, base, csrf, _page):
                with patch(
                    "pbp_monitoring.adminui.generate_api_key", return_value="generated-key"
                ) as keygen, patch(
                    "pbp_monitoring.adminui.fetch_system_info", return_value=dict(DEVICE_IDENTITY)
                ) as system_info, patch(
                    "pbp_monitoring.adminui.fetch_dp_core_functions",
                    return_value=[dict(entry) for entry in CORE_FUNCTIONS],
                ):
                    saved = opener.open(
                        Request(
                            base + "/admin/target/save",
                            data=urlencode(
                                {
                                    "csrf": csrf,
                                    "target_id": "",
                                    "name": "PA-440",
                                    "firewall_ip": "192.0.2.10",
                                    "auth_method": "credentials",
                                    "api_key": "",
                                    "username": "pbp_monitor_admin",
                                    "password": "temporary-password",
                                    "tls_verify": "false",
                                    "enabled": "true",
                                }
                            ).encode(),
                        )
                    ).read().decode()
                self.assertIn("001122334455", saved)
                self.assertIn("lab-fw-01", saved)
                self.assertEqual(keygen.call_args.args[0], "https://192.0.2.10")
                self.assertEqual(system_info.call_args.args, ("https://192.0.2.10", "generated-key"))
                store = ConfigStore(root / "config" / "config.db")
                target = store.list_targets(include_secrets=True)[0]
                self.assertEqual(target.panos_url, "https://192.0.2.10")
                self.assertEqual(target.syslog_sources, ("192.0.2.10",))
                self.assertEqual(target.serials, ("001122334455",))
                self.assertEqual(target.api_key, "generated-key")
                self.assertEqual(target.tls_verify, "false")
                self.assertIsNone(target.target_serial)
                self.assertEqual(target.dp_core_functions, tuple(CORE_FUNCTIONS))
                self.assertEqual(target.dp_core_functions_identity, "PA-440|11.1.4-h7")
                self.assertIn("2 dataplane cores mapped", saved)

    def test_a_blank_name_falls_back_to_the_panos_hostname(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with signed_in_admin(root) as (opener, base, csrf, _page):
                with patch(
                    "pbp_monitoring.adminui.fetch_system_info", return_value=dict(DEVICE_IDENTITY)
                ), patch(
                    "pbp_monitoring.adminui.fetch_dp_core_functions",
                    return_value=[dict(entry) for entry in CORE_FUNCTIONS],
                ):
                    page = opener.open(
                        Request(
                            base + "/admin/target/save",
                            data=urlencode(
                                {
                                    "csrf": csrf,
                                    "target_id": "",
                                    "name": "",
                                    "firewall_ip": "192.0.2.10",
                                    "auth_method": "api_key",
                                    "api_key": "existing-key",
                                    "tls_verify": "true",
                                    "enabled": "true",
                                }
                            ).encode(),
                        )
                    ).read().decode()
                self.assertIn("PA-440", page)
                self.assertIn("PAN-OS 11.1.4-h7", page)
                store = ConfigStore(root / "config" / "config.db")
                target = store.list_targets()[0]
                self.assertEqual(target["name"], "lab-fw-01")
                self.assertEqual(target["hostname"], "lab-fw-01")
                self.assertEqual(target["model"], "PA-440")
                self.assertEqual(target["sw_version"], "11.1.4-h7")

    def test_unreachable_firewall_or_invalid_key_prevents_saving(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with signed_in_admin(root) as (opener, base, csrf, _page):
                with patch(
                    "pbp_monitoring.adminui.fetch_system_info",
                    side_effect=SystemInfoError("unable to reach the firewall"),
                ):
                    with self.assertRaises(HTTPError) as raised:
                        opener.open(
                            Request(
                                base + "/admin/target/save",
                                data=urlencode(
                                    {
                                        "csrf": csrf,
                                        "target_id": "",
                                        "name": "PA-440",
                                        "firewall_ip": "192.0.2.10",
                                        "auth_method": "api_key",
                                        "api_key": "existing-key",
                                        "tls_verify": "true",
                                        "enabled": "true",
                                    }
                                ).encode(),
                            )
                        )
                self.assertEqual(raised.exception.code, 400)
                self.assertIn("unable to reach the firewall", raised.exception.read().decode())
                store = ConfigStore(root / "config" / "config.db")
                self.assertEqual(store.list_targets(), [])

    def test_a_hostname_is_rejected_because_it_cannot_be_a_syslog_source(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            with signed_in_admin(Path(temporary_directory)) as (opener, base, csrf, _page):
                with self.assertRaises(HTTPError) as raised:
                    opener.open(
                        Request(
                            base + "/admin/target/save",
                            data=urlencode(
                                {
                                    "csrf": csrf,
                                    "target_id": "",
                                    "name": "PA-440",
                                    "firewall_ip": "fw.example.net",
                                    "auth_method": "api_key",
                                    "api_key": "existing-key",
                                    "tls_verify": "false",
                                    "enabled": "true",
                                }
                            ).encode(),
                        )
                    )
                self.assertEqual(raised.exception.code, 400)
                self.assertIn("IPv4 or IPv6 address", raised.exception.read().decode())

    def test_editing_keeps_the_stored_key_panorama_serial_and_extra_sources(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            store = ConfigStore(root / "config" / "config.db")
            store.initialize()
            target_id = store.save_target(
                name="PA-440",
                panos_url="https://192.0.2.10",
                api_key="stored-key",
                target_serial="PANORAMA-SER",
                serials=["old-serial"],
                syslog_sources=["192.0.2.10", "198.51.100.7"],
                tls_verify="false",
            )
            with signed_in_admin(root) as (opener, base, csrf, _page):
                form = opener.open(base + f"/admin?edit={target_id}").read().decode()
                self.assertIn(
                    '<input type="radio" id="auth-stored" name="auth_method" value="stored" checked>',
                    form,
                )
                self.assertIn('<div class="form-actions">', form)
                self.assertIn("198.51.100.7", form)
                with patch(
                    "pbp_monitoring.adminui.fetch_system_info", return_value=dict(DEVICE_IDENTITY)
                ) as system_info, patch(
                    "pbp_monitoring.adminui.fetch_dp_core_functions",
                    return_value=[dict(entry) for entry in CORE_FUNCTIONS],
                ):
                    opener.open(
                        Request(
                            base + "/admin/target/save",
                            data=urlencode(
                                {
                                    "csrf": csrf,
                                    "target_id": str(target_id),
                                    "name": "PA-440",
                                    "firewall_ip": "192.0.2.11",
                                    "auth_method": "stored",
                                    "api_key": "",
                                    "tls_verify": "true",
                                    "enabled": "true",
                                }
                            ).encode(),
                        )
                    ).read()
                self.assertEqual(system_info.call_args.args, ("https://192.0.2.11", "stored-key"))
                target = store.list_targets(include_secrets=True)[0]
                self.assertEqual(target.api_key, "stored-key")
                self.assertEqual(target.panos_url, "https://192.0.2.11")
                self.assertEqual(target.syslog_sources, ("192.0.2.11", "198.51.100.7"))
                self.assertEqual(target.serials, ("001122334455", "PANORAMA-SER"))
                self.assertEqual(target.target_serial, "PANORAMA-SER")
                self.assertEqual(target.tls_verify, "true")

    def test_remote_admin_is_enabled_by_web_handler(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = ConfigStore(Path(temporary_directory) / "config.db")
            remote = type("Remote", (), {"client_address": ("192.0.2.20", 12345)})()
            remote_enabled = AdminController(store)
            self.assertTrue(remote_enabled._is_loopback(remote))


    def test_the_test_button_queues_a_validation_for_the_collector(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with signed_in_admin(root) as (opener, base, csrf, _page):
                with patch(
                    "pbp_monitoring.adminui.generate_api_key", return_value="generated-key"
                ), patch(
                    "pbp_monitoring.adminui.fetch_system_info", return_value=dict(DEVICE_IDENTITY)
                ), patch(
                    "pbp_monitoring.adminui.fetch_dp_core_functions",
                    return_value=[dict(entry) for entry in CORE_FUNCTIONS],
                ):
                    opener.open(
                        Request(
                            base + "/admin/target/save",
                            data=urlencode(
                                {
                                    "csrf": csrf,
                                    "target_id": "",
                                    "name": "PA-440",
                                    "firewall_ip": "192.0.2.10",
                                    "auth_method": "credentials",
                                    "api_key": "",
                                    "username": "pbp_monitor_admin",
                                    "password": "temporary-password",
                                    "tls_verify": "false",
                                    "enabled": "true",
                                }
                            ).encode(),
                        )
                    ).read()

                store = ConfigStore(root / "config" / "config.db")
                target_id = store.list_targets()[0]["target_id"]
                self.assertIsNone(store.list_targets()[0]["check_requested_at"])

                page = opener.open(
                    Request(
                        base + "/admin/target/check",
                        data=urlencode({"csrf": csrf, "target_id": str(target_id)}).encode(),
                    )
                ).read().decode()

                self.assertTrue(store.list_targets()[0]["check_requested_at"])
                self.assertIn("validation requested", page.lower())
                self.assertIn("Validation queued", page)

    def test_the_configuration_page_reloads_only_while_a_validation_is_queued(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "config").mkdir(parents=True, exist_ok=True)
            store = ConfigStore(root / "config" / "config.db")
            store.initialize()
            target_id = store.save_target(
                name="PA-440",
                panos_url="https://192.0.2.10",
                api_key="stored-key",
                serials=["001122334455"],
                syslog_sources=["192.0.2.10"],
            )
            with signed_in_admin(root) as (opener, base, csrf, _page):
                settled = opener.open(base + "/admin").read().decode()
                self.assertNotIn('http-equiv="refresh"', settled)

                queued = opener.open(
                    Request(
                        base + "/admin/target/check",
                        data=urlencode({"csrf": csrf, "target_id": str(target_id)}).encode(),
                    )
                ).read().decode()
                self.assertIn('<meta http-equiv="refresh" content="5">', queued)

                editing = opener.open(base + f"/admin?edit={target_id}").read().decode()
                self.assertNotIn('http-equiv="refresh"', editing)

                store.record_target_check(
                    target_id,
                    kind="validation",
                    status="ok",
                    detail="run 20260829T172715Z",
                    clear_request=True,
                )
                finished = opener.open(base + "/admin").read().decode()
                self.assertNotIn('http-equiv="refresh"', finished)
                self.assertIn("Passed", finished)


if __name__ == "__main__":
    unittest.main()
