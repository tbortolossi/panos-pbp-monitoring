import http.cookiejar
import re
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener

from pbp_monitoring.adminui import AdminController
from pbp_monitoring.config_store import ConfigStore
from pbp_monitoring.webui import handler_factory


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
                    "pbp-monitoring-recovery-key-v0.4.1.csv",
                    csv_response.headers["Content-Disposition"],
                )
                csv_payload = csv_response.read().decode("utf-8-sig")
                self.assertIn("product,version,recovery_key", csv_payload)
                self.assertIn("PBP Monitoring,0.4.1", csv_payload)
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

    def test_remote_admin_is_enabled_by_web_handler(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = ConfigStore(Path(temporary_directory) / "config.db")
            remote = type("Remote", (), {"client_address": ("192.0.2.20", 12345)})()
            remote_enabled = AdminController(store)
            self.assertTrue(remote_enabled._is_loopback(remote))


if __name__ == "__main__":
    unittest.main()
