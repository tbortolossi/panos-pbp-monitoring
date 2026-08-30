import contextlib
import http.cookiejar
import io
import json
import logging
import re
import tempfile
import threading
import unittest
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener

from pbp_monitoring.adminui import (
    AdminController,
    SETTING_LABELS,
    setting_label,
    syslog_commands,
)
from pbp_monitoring import __version__
from pbp_monitoring.config_store import ConfigStore, DEFAULT_SETTINGS
from pbp_monitoring.panos_keygen import SystemInfoError
from pbp_monitoring.webui import handler_factory
from tests.support import (
    SERVER_POLL_INTERVAL,
    start_fast_password_hashing,
    stop_fast_password_hashing,
)


def setUpModule():
    start_fast_password_hashing()


def tearDownModule():
    stop_fast_password_hashing()


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


class SetupCodeCatcher(logging.Handler):
    """Capture the one-time setup code the controller logs at startup."""

    def __init__(self):
        super().__init__()
        self.code = None

    def emit(self, record):
        match = re.search(r"setup code: (\S+)", record.getMessage())
        if match:
            self.code = match.group(1)


@contextlib.contextmanager
def capture_setup_code():
    catcher = SetupCodeCatcher()
    logger = logging.getLogger("pbp-adminui")
    logger.addHandler(catcher)
    try:
        yield catcher
    finally:
        logger.removeHandler(catcher)


@contextlib.contextmanager
def signed_in_admin(root: Path):
    """Start the admin server, complete setup, and sign in."""
    with capture_setup_code() as catcher:
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0), handler_factory(root / "data", 300, root / "config" / "config.db")
        )
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": SERVER_POLL_INTERVAL},
        daemon=True,
    )
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
                    {
                        "csrf": csrf,
                        "setup_code": catcher.code,
                        "password": "long-test-password",
                        "confirm": "long-test-password",
                    }
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
            with capture_setup_code() as catcher:
                server = ThreadingHTTPServer(
                    ("127.0.0.1", 0),
                    handler_factory(root / "data", 300, root / "config" / "config.db"),
                )
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": SERVER_POLL_INTERVAL},
                daemon=True,
            )
            thread.start()
            opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                setup = opener.open(base + "/admin").read().decode()
                setup_csrf = re.search(r'name="csrf" value="([^"]+)"', setup).group(1)
                setup_body = urlencode(
                    {
                        "csrf": setup_csrf,
                        "setup_code": catcher.code,
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
                self.assertIn("Incident idle TTL seconds", page)
                self.assertIn("Generate HTML report", page)
                self.assertNotIn("Ttl", page)
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

    def test_setup_rejects_a_wrong_code_and_accepts_the_logged_one(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with capture_setup_code() as catcher:
                server = ThreadingHTTPServer(
                    ("127.0.0.1", 0),
                    handler_factory(root / "data", 300, root / "config" / "config.db"),
                )
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": SERVER_POLL_INTERVAL},
                daemon=True,
            )
            thread.start()
            opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                setup = opener.open(base + "/admin").read().decode()
                self.assertIn("setup code", setup)
                csrf = re.search(r'name="csrf" value="([^"]+)"', setup).group(1)
                with self.assertRaises(HTTPError) as context:
                    opener.open(
                        Request(
                            base + "/admin/setup",
                            data=urlencode(
                                {
                                    "csrf": csrf,
                                    "setup_code": "wrong-code",
                                    "password": "long-test-password",
                                    "confirm": "long-test-password",
                                }
                            ).encode(),
                        )
                    )
                self.assertEqual(context.exception.code, 403)
                store = ConfigStore(root / "config" / "config.db")
                self.assertFalse(store.has_admin_password())
                accepted = opener.open(
                    Request(
                        base + "/admin/setup",
                        data=urlencode(
                            {
                                "csrf": csrf,
                                "setup_code": catcher.code,
                                "password": "long-test-password",
                                "confirm": "long-test-password",
                            }
                        ).encode(),
                    )
                ).read().decode()
                self.assertIn("Administrator sign in", accepted)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_repeated_login_failures_throttle_the_source(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with capture_setup_code() as catcher:
                server = ThreadingHTTPServer(
                    ("127.0.0.1", 0),
                    handler_factory(root / "data", 300, root / "config" / "config.db"),
                )
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": SERVER_POLL_INTERVAL},
                daemon=True,
            )
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
                            {
                                "csrf": csrf,
                                "setup_code": catcher.code,
                                "password": "long-test-password",
                                "confirm": "long-test-password",
                            }
                        ).encode(),
                    )
                ).read().decode()
                login_csrf = re.search(r'name="csrf" value="([^"]+)"', login).group(1)
                for _ in range(5):
                    with self.assertRaises(HTTPError) as context:
                        opener.open(
                            Request(
                                base + "/admin/login",
                                data=urlencode(
                                    {"csrf": login_csrf, "password": "wrong-password"}
                                ).encode(),
                            )
                        )
                    self.assertEqual(context.exception.code, 401)
                # The sixth attempt is refused before verification, even with
                # the correct password.
                with self.assertRaises(HTTPError) as context:
                    opener.open(
                        Request(
                            base + "/admin/login",
                            data=urlencode(
                                {"csrf": login_csrf, "password": "long-test-password"}
                            ).encode(),
                        )
                    )
                self.assertEqual(context.exception.code, 429)
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
                self.assertIn("can be intercepted on the management path", page)

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

    def test_the_syslog_commands_use_the_address_the_admin_page_was_reached_on(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            with signed_in_admin(Path(temporary_directory)) as (_opener, _base, _csrf, page):
                self.assertIn("PAN-OS Syslog forwarding", page)
                self.assertIn(
                    "set shared log-settings syslog PBP-Docker server PBP-Docker server 127.0.0.1",
                    page,
                )
                self.assertIn(
                    "set shared log-settings syslog PBP-Docker server PBP-Docker port 514", page
                )
                self.assertIn("set shared log-settings system match-list PBP-Docker", page)
                self.assertIn(
                    "set shared log-settings profiles default match-list PBP-Docker log-type threat",
                    page,
                )
                self.assertNotIn("&lt;COLLECTOR_IP&gt;", page)

    def test_the_syslog_commands_follow_the_submitted_profile_address_and_port(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            with signed_in_admin(Path(temporary_directory)) as (opener, base, _csrf, _page):
                page = opener.open(
                    base
                    + "/admin?"
                    + urlencode(
                        {
                            "collector_ip": "192.0.2.20",
                            "syslog_port": "1514",
                            "log_profile": "LFP-Corp",
                        }
                    )
                ).read().decode()
                self.assertIn(
                    "set shared log-settings syslog PBP-Docker server PBP-Docker server 192.0.2.20",
                    page,
                )
                self.assertIn(
                    "set shared log-settings syslog PBP-Docker server PBP-Docker port 1514", page
                )
                self.assertIn(
                    "set shared log-settings profiles LFP-Corp match-list PBP-Docker log-type threat",
                    page,
                )
                self.assertIn(
                    "set shared log-settings profiles LFP-Corp match-list PBP-Docker send-syslog"
                    " [ PBP-Docker ]",
                    page,
                )
                self.assertNotIn("profiles default match-list", page)

    def test_an_unusable_syslog_value_falls_back_to_its_default_and_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            with signed_in_admin(Path(temporary_directory)) as (opener, base, _csrf, _page):
                page = opener.open(
                    base
                    + "/admin?"
                    + urlencode(
                        {
                            "collector_ip": "192.0.2.20; reboot",
                            "syslog_port": "99999",
                            "log_profile": 'default" or "1',
                        }
                    )
                ).read().decode()
                self.assertIn("ignored collector address", page)
                self.assertIn("ignored Syslog port", page)
                self.assertIn("ignored log forwarding profile", page)
                self.assertIn("&lt;COLLECTOR_IP&gt;", page)
                block = re.search(r"<pre>(.*?)</pre>", page, re.S).group(1)
                self.assertNotIn("reboot", block)
                self.assertIn(
                    "set shared log-settings syslog PBP-Docker server PBP-Docker port 514", page
                )
                self.assertIn(
                    "set shared log-settings profiles default match-list PBP-Docker log-type threat",
                    page,
                )

    def test_the_syslog_commands_download_as_plain_text(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            with signed_in_admin(Path(temporary_directory)) as (opener, base, _csrf, _page):
                response = opener.open(
                    base
                    + "/admin/syslog-commands.txt?"
                    + urlencode({"collector_ip": "192.0.2.20", "log_profile": "LFP-Corp"})
                )
                body = response.read().decode()
                self.assertEqual(response.headers["Content-Type"], "text/plain; charset=utf-8")
                self.assertIn("pbp-monitoring-syslog-forwarding.txt", response.headers["Content-Disposition"])
                self.assertEqual(
                    body, syslog_commands("192.0.2.20", "514", "LFP-Corp") + "\n"
                )

    def test_the_threat_match_list_extends_a_profile_without_replacing_it(self):
        commands = syslog_commands("192.0.2.20", "514", "LFP-Corp")
        self.assertIn(
            'set shared log-settings profiles LFP-Corp match-list PBP-Docker filter'
            ' "((threatid eq 8507) or (threatid eq 8508) or (threatid eq 8509))"',
            commands,
        )
        self.assertIn('set shared log-settings system match-list PBP-Docker filter "All Logs"', commands)
        self.assertNotIn("delete ", commands)
        self.assertNotIn("clear ", commands)
        for line in commands.splitlines():
            self.assertRegex(
                line,
                r"^(#.*|configure|set .*|show .*|commit description \".*\"|)$",
            )

    def test_the_syslog_commands_require_an_authenticated_session(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with signed_in_admin(root) as (opener, base, csrf, _page):
                opener.open(
                    Request(base + "/admin/logout", data=urlencode({"csrf": csrf}).encode())
                ).read()
                page = opener.open(base + "/admin/syslog-commands.txt").read().decode()
                self.assertNotIn("set shared log-settings", page)
                self.assertIn("Administrator sign in", page)


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


class SettingLabelTests(unittest.TestCase):
    def test_every_stored_setting_has_a_spelled_out_label(self):
        self.assertEqual(set(DEFAULT_SETTINGS), set(SETTING_LABELS))

    def test_acronyms_keep_their_capitalization(self):
        self.assertEqual(
            setting_label("incident_idle_ttl_seconds"), "Incident idle TTL seconds"
        )
        self.assertEqual(setting_label("generate_html_report"), "Generate HTML report")
        self.assertEqual(setting_label("webhook_url"), "Webhook URL")

    def test_unknown_setting_falls_back_to_sentence_case(self):
        self.assertEqual(setting_label("future_knob_seconds"), "Future knob seconds")


if __name__ == "__main__":
    unittest.main()


class SupportBundleUITests(unittest.TestCase):
    """The bundle is evidence about the deployment: it needs a session."""

    def test_support_bundle_is_refused_without_an_administrator_session(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            with capture_setup_code():
                server = ThreadingHTTPServer(
                    ("127.0.0.1", 0),
                    handler_factory(root / "data", 300, root / "config" / "config.db"),
                )
            thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": SERVER_POLL_INTERVAL},
                daemon=True,
            )
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                response = build_opener().open(base + "/admin/support-bundle.zip")
                body = response.read()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
            # Setup has never been completed, so the request is answered with
            # the setup page rather than any deployment evidence.
            self.assertNotEqual(body[:2], b"PK")
            self.assertIn(b"setup", body.lower())

    def test_signed_in_administrator_downloads_the_deployment_bundle(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "data").mkdir()
            (root / "config").mkdir()
            store = ConfigStore(root / "config" / "config.db")
            store.initialize()
            store.save_target(
                name="fw-a",
                panos_url="https://192.0.2.10",
                api_key="super-secret-api-key",
                target_serial=None,
                serials=["001122334455"],
                syslog_sources=["192.0.2.10"],
            )
            with signed_in_admin(root) as (opener, base, _csrf, page):
                self.assertIn("Download support bundle", page)
                response = opener.open(base + "/admin/support-bundle.zip")
                payload = response.read()
            self.assertEqual(response.headers["Content-Type"], "application/zip")
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                names = archive.namelist()
                environment = json.loads(
                    archive.read(
                        next(n for n in names if n.endswith("environment.json"))
                    )
                )
                blob = b"".join(archive.read(name) for name in names)
            self.assertEqual(environment["application_version"], __version__)
            self.assertNotIn(b"super-secret-api-key", blob)
            self.assertTrue(any(name.endswith("README.txt") for name in names))


if __name__ == "__main__":
    unittest.main()
