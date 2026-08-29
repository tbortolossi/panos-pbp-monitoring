"""PAN-OS API key generation shared by the CLI tool and admin UI."""

from __future__ import annotations

import ipaddress
import ssl
import xml.etree.ElementTree as ET
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen


class KeyGenerationError(RuntimeError):
    pass


def normalize_firewall_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("the firewall address is empty")
    if "://" not in value:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            value = f"[{address}]" if address.version == 6 else str(address)
        value = f"https://{value}"
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https":
        raise ValueError("only HTTPS is allowed to protect the password")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("invalid firewall address")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("enter only the firewall IP address or DNS name")
    return urlunsplit(("https", parsed.netloc, "", "", ""))


def make_ssl_context(*, insecure: bool, ca_bundle: str | None) -> ssl.SSLContext:
    if insecure:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=ca_bundle)


def generate_api_key(
    firewall_url: str,
    username: str,
    password: str,
    *,
    ssl_context: ssl.SSLContext,
    timeout: float = 15.0,
    opener: object = urlopen,
) -> str:
    body = urlencode({"type": "keygen", "user": username, "password": password}).encode()
    request = Request(
        f"{firewall_url}/api/",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with opener(request, timeout=timeout, context=ssl_context) as response:  # type: ignore[operator]
            response_text = response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        raise KeyGenerationError(f"the firewall returned HTTP error {exc.code}") from exc
    except URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            raise KeyGenerationError(
                "the TLS certificate is not trusted; configure a CA, or disable verification in a lab only"
            ) from exc
        raise KeyGenerationError("unable to reach the firewall") from exc
    try:
        root = ET.fromstring(response_text)
    except ET.ParseError as exc:
        raise KeyGenerationError("the firewall returned invalid XML") from exc
    key = root.findtext("./result/key")
    if root.attrib.get("status") != "success" or not key or not key.strip():
        raise KeyGenerationError(
            "PAN-OS rejected key generation (check credentials and API permissions)"
        )
    return key.strip()
