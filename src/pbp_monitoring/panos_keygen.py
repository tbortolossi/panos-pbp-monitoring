"""PAN-OS API key generation shared by the CLI tool and admin UI."""

from __future__ import annotations

import ipaddress
import ssl
import xml.etree.ElementTree as ET
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener, urlopen


SYSTEM_INFO_COMMAND = "<show><system><info/></system></show>"


class PanOSAdminError(RuntimeError):
    """Base error for the administrative PAN-OS calls made from the UI."""


class KeyGenerationError(PanOSAdminError):
    pass


class SystemInfoError(PanOSAdminError):
    pass


class _RejectRedirectHandler(HTTPRedirectHandler):
    """An authenticated PAN-OS API call must never follow a redirect."""

    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        raise SystemInfoError("the firewall API redirected an authenticated request")


def _open_without_redirects(request: Request, *, timeout: float, context: ssl.SSLContext):
    opener = build_opener(HTTPSHandler(context=context), _RejectRedirectHandler())
    return opener.open(request, timeout=timeout)


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


def _read_api_response(
    request: Request,
    *,
    ssl_context: ssl.SSLContext,
    timeout: float,
    opener: object,
    error: type[PanOSAdminError],
) -> ET.Element:
    try:
        with opener(request, timeout=timeout, context=ssl_context) as response:  # type: ignore[operator]
            response_text = response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        raise error(f"the firewall returned HTTP error {exc.code}") from exc
    except URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            raise error(
                "the TLS certificate is not trusted; configure a CA, or disable verification in a lab only"
            ) from exc
        raise error("unable to reach the firewall") from exc
    try:
        return ET.fromstring(response_text)
    except ET.ParseError as exc:
        raise error("the firewall returned invalid XML") from exc


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
    root = _read_api_response(
        request,
        ssl_context=ssl_context,
        timeout=timeout,
        opener=opener,
        error=KeyGenerationError,
    )
    key = root.findtext("./result/key")
    if root.attrib.get("status") != "success" or not key or not key.strip():
        raise KeyGenerationError(
            "PAN-OS rejected key generation (check credentials and API permissions)"
        )
    return key.strip()


def fetch_system_info(
    firewall_url: str,
    api_key: str,
    *,
    ssl_context: ssl.SSLContext,
    timeout: float = 15.0,
    opener: object = _open_without_redirects,
) -> dict[str, str]:
    """Validate an API key and return the device identity from `show system info`.

    The key is sent as an unredirected `X-PAN-KEY` header so it is never placed
    in a URL and never replayed to a redirect target.
    """
    body = urlencode({"type": "op", "cmd": SYSTEM_INFO_COMMAND}).encode()
    request = Request(
        f"{firewall_url}/api/",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    request.add_unredirected_header("X-PAN-KEY", api_key)
    root = _read_api_response(
        request,
        ssl_context=ssl_context,
        timeout=timeout,
        opener=opener,
        error=SystemInfoError,
    )
    if root.attrib.get("status") != "success":
        raise SystemInfoError(
            "PAN-OS rejected 'show system info' (check the API key and its permissions)"
        )
    from .orchestrator import extract_system_info

    identity = extract_system_info(ET.tostring(root, encoding="unicode"))
    if not identity.get("serial"):
        raise SystemInfoError("PAN-OS did not return a device serial number")
    return identity
