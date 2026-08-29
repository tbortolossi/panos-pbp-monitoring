import ssl
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from tools.generate_api_key import (
    KeyGenerationError,
    generate_api_key,
    normalize_firewall_url,
)


class FakeResponse:
    def __init__(self, body: str):
        self.body = body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self):
        return self.body


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


if __name__ == "__main__":
    unittest.main()
