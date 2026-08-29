import os
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import urlopen

from cryptography import x509

from pbp_monitoring.web_tls import ensure_self_signed_certificate
from pbp_monitoring.webui import ThreadingTLSHTTPServer, handler_factory


class WebTLSTests(unittest.TestCase):
    def test_stalled_tls_handshake_does_not_block_other_clients(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            certificate_path = root / "web-tls.crt"
            key_path = root / "web-tls.key"
            ensure_self_signed_certificate(
                certificate_path, key_path, ["localhost", "127.0.0.1"]
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certificate_path, key_path)
            server = ThreadingTLSHTTPServer(
                ("127.0.0.1", 0),
                handler_factory(root / "data", 300, tls_enabled=True),
                context,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            stalled = socket.create_connection(("127.0.0.1", server.server_port))
            try:
                response = urlopen(
                    f"https://127.0.0.1:{server.server_port}/healthz",
                    timeout=3,
                    context=ssl._create_unverified_context(),
                )
                self.assertEqual(response.read(), b"ok\n")
            finally:
                stalled.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_self_signed_certificate_is_persistent_and_has_requested_sans(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            certificate_path = root / "web-tls.crt"
            key_path = root / "web-tls.key"

            ensure_self_signed_certificate(
                certificate_path,
                key_path,
                ["pbp.example.test", "192.0.2.20", "localhost"],
            )
            original_certificate = certificate_path.read_bytes()
            ensure_self_signed_certificate(
                certificate_path,
                key_path,
                ["ignored-after-creation.example"],
            )

            self.assertEqual(certificate_path.read_bytes(), original_certificate)
            certificate = x509.load_pem_x509_certificate(original_certificate)
            alternatives = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            self.assertIn("pbp.example.test", alternatives.get_values_for_type(x509.DNSName))
            self.assertIn("192.0.2.20", [str(value) for value in alternatives.get_values_for_type(x509.IPAddress)])
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate_path, key_path)
            if os.name == "posix":
                self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)

    def test_incomplete_or_invalid_certificate_configuration_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            certificate_path = root / "web-tls.crt"
            key_path = root / "web-tls.key"
            certificate_path.write_text("certificate only", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "both exist"):
                ensure_self_signed_certificate(
                    certificate_path,
                    key_path,
                    ["localhost"],
                )


if __name__ == "__main__":
    unittest.main()
