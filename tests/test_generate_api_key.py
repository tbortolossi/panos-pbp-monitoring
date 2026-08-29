import ssl
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from pbp_monitoring.panos_keygen import SystemInfoError, fetch_system_info
from tools.generate_api_key import (
    KeyGenerationError,
    generate_api_key,
    normalize_firewall_url,
)


SYSTEM_INFO_XML = (
    '<response status="success"><result><system>'
    "<hostname>lab-fw-01</hostname><serial>001122334455</serial>"
    "<model>PA-440</model><sw-version>11.1.4-h7</sw-version>"
    "</system></result></response>"
)


class FakeResponse:
    def __init__(self, body: str):
        self.body = body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self, limit: int = -1):
        return self.body if limit is None or limit < 0 else self.body[:limit]


class GenerateAPIKeyTests(unittest.TestCase):
    """Tests for the standalone PAN-OS API key generator."""
    def test_normalizes_ipv4_and_hostname(self):
        self.assertEqual(normalize_firewall_url("192.0.2.10"), "https://192.0.2.10")
        self.assertEqual(
            normalize_firewall_url("fw.example.net/"), "https://fw.example.net"
        )

    def test_rejects_plain_http(self):
        with self.assertRaises(ValueError):
            normalize_firewall_url("http://192.0.2.10")

    @patch("tools.generate_api_key.urlopen")
    def test_credentials_are_posted_and_not_put_in_url(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse(
            '<response status="success"><result><key>secret-key</key></result></response>'
        )
        context = ssl.create_default_context()

        key = generate_api_key(
            "https://192.0.2.10",
            "api-user",
            "p@ss&word",
            ssl_context=context,
        )

        self.assertEqual(key, "secret-key")
        request = mock_urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://192.0.2.10/api/")
        self.assertEqual(
            parse_qs(request.data.decode("utf-8")),
            {"type": ["keygen"], "user": ["api-user"], "password": ["p@ss&word"]},
        )

    @patch("tools.generate_api_key.urlopen")
    def test_rejected_keygen_uses_a_generic_error(self, mock_urlopen):
        mock_urlopen.return_value = FakeResponse(
            '<response status="error"><msg>bad password: do-not-print</msg></response>'
        )

        with self.assertRaisesRegex(KeyGenerationError, "rejected") as raised:
            generate_api_key(
                "https://192.0.2.10",
                "api-user",
                "do-not-print",
                ssl_context=ssl.create_default_context(),
            )
        self.assertNotIn("do-not-print", str(raised.exception))


class FetchSystemInfoTests(unittest.TestCase):
    """`show system info` validates the key and identifies the device."""

    def _call(self, body: str):
        captured = {}

        def opener(request, *, timeout, context):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse(body)

        identity = fetch_system_info(
            "https://192.0.2.10",
            "secret-key",
            ssl_context=ssl.create_default_context(),
            timeout=7.0,
            opener=opener,
        )
        return identity, captured

    def test_key_is_sent_as_an_unredirected_header_and_serial_is_returned(self):
        identity, captured = self._call(SYSTEM_INFO_XML)

        self.assertEqual(identity["serial"], "001122334455")
        self.assertEqual(identity["hostname"], "lab-fw-01")
        self.assertEqual(identity["model"], "PA-440")
        self.assertEqual(identity["software_version"], "11.1.4-h7")
        request = captured["request"]
        self.assertEqual(request.full_url, "https://192.0.2.10/api/")
        self.assertEqual(captured["timeout"], 7.0)
        self.assertNotIn("secret-key", request.full_url)
        self.assertEqual(request.unredirected_hdrs.get("X-pan-key"), "secret-key")
        self.assertEqual(
            parse_qs(request.data.decode("utf-8")),
            {"type": ["op"], "cmd": ["<show><system><info/></system></show>"]},
        )

    def test_rejected_key_raises(self):
        with self.assertRaises(SystemInfoError):
            self._call('<response status="error"><msg>Invalid credentials</msg></response>')

    def test_missing_serial_raises(self):
        with self.assertRaises(SystemInfoError):
            self._call('<response status="success"><result><system/></result></response>')


if __name__ == "__main__":
    unittest.main()
