"""Persistent TLS certificate support for the built-in Web service."""

from __future__ import annotations

import ipaddress
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


DNS_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")


def _atomic_private_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _subject_alt_names(hostnames: list[str]) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = []
    for value in dict.fromkeys(item.strip() for item in hostnames if item.strip()):
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(value)))
        except ValueError:
            if not DNS_NAME.fullmatch(value):
                raise ValueError(f"invalid Web TLS hostname: {value}")
            names.append(x509.DNSName(value))
    if not names:
        raise ValueError("at least one Web TLS hostname or IP address is required")
    return names


def ensure_self_signed_certificate(
    certificate_path: Path,
    private_key_path: Path,
    hostnames: list[str],
    *,
    valid_days: int = 825,
) -> tuple[Path, Path]:
    """Create a persistent private certificate, or validate the existing pair."""
    certificate_path = Path(certificate_path)
    private_key_path = Path(private_key_path)
    if certificate_path.exists() != private_key_path.exists():
        raise ValueError("Web TLS certificate and private key must both exist or both be absent")
    if certificate_path.exists():
        try:
            certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
            private_key = serialization.load_pem_private_key(
                private_key_path.read_bytes(), password=None
            )
        except (OSError, ValueError) as exc:
            raise ValueError("existing Web TLS certificate or private key is invalid") from exc
        if (
            certificate.public_key().public_numbers()
            != private_key.public_key().public_numbers()
        ):
            raise ValueError("Web TLS certificate does not match its private key")
        return certificate_path, private_key_path

    alternative_names = _subject_alt_names(hostnames)
    common_name = str(hostnames[0]).strip()
    now = datetime.now(timezone.utc)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.SubjectAlternativeName(alternative_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    _atomic_private_write(
        private_key_path,
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    _atomic_private_write(
        certificate_path,
        certificate.public_bytes(serialization.Encoding.PEM),
    )
    return certificate_path, private_key_path
