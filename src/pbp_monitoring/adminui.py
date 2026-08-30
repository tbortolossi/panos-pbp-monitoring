"""Authenticated administration pages with configurable network exposure."""

from __future__ import annotations

import csv
import html
import ipaddress
import io
import logging
import re
import secrets
import sqlite3
import ssl
import threading
import time
from collections import deque
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import parse_qs, urlencode, urlsplit

from . import __version__, diagnostics
from .config_store import ConfigStore, DEFAULT_SETTINGS, TARGET_NAME
from .panos_keygen import (
    PanOSAdminError,
    fetch_dp_core_functions,
    fetch_system_info,
    generate_api_key,
    make_ssl_context,
    normalize_firewall_url,
)


LOG = logging.getLogger("pbp-adminui")

SESSION_SECONDS = 8 * 60 * 60
AUTH_ATTEMPT_LIMIT = 5
AUTH_ATTEMPT_WINDOW_SECONDS = 15 * 60
AUTH_SOURCE_LIMIT = 1024
VERIFY_CONCURRENCY = 4
PENDING_CHECK_REFRESH_SECONDS = 5

# PAN-OS Syslog forwarding helper. The collector never writes to the firewall:
# these commands are rendered for the operator to review and run themselves.
SYSLOG_OBJECT_NAME = "PBP-Docker"
DEFAULT_SYSLOG_PORT = "514"
DEFAULT_LOG_FORWARDING_PROFILE = "default"
COLLECTOR_HOST_PLACEHOLDER = "<COLLECTOR_IP>"
PBP_THREAT_IDS = ("8507", "8508", "8509")
PANOS_OBJECT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,30}\Z")
COLLECTOR_HOST = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,61}[A-Za-z0-9])?\Z")

# Labels of the collector settings form. Deriving them from the stored key
# turns acronyms into words ("Ttl", "Html", "Url"), so the wording is spelled
# out here and kept identical to the settings table in docs/operations.md.
SETTING_LABELS: dict[str, str] = {
    "poll_seconds": "Poll seconds",
    "max_monitor_seconds": "Maximum monitor seconds",
    "incident_idle_ttl_seconds": "Incident idle TTL seconds",
    "recovery_threshold": "Recovery threshold",
    "low_samples_to_stop": "Low samples to stop",
    "request_timeout": "Request timeout",
    "max_session_lookups": "Maximum session lookups",
    "session_retry_seconds": "Session retry seconds",
    "large_session_min_kb": "Large session min KB",
    "large_session_min_age_seconds": "Large session min age seconds",
    "generate_html_report": "Generate HTML report",
    "generate_text_export": "Generate text export",
    "syslog_fresh_seconds": "Syslog fresh seconds",
    "target_check_hours": "Target check hours",
    "webhook_url": "Webhook URL",
}


def setting_label(key: str) -> str:
    """Return the form label of a collector setting.

    A setting added without an entry above still renders readably, in the
    sentence case the rest of the form uses.
    """
    return SETTING_LABELS.get(key) or key.replace("_", " ").capitalize()


def syslog_commands(
    collector_host: str,
    syslog_port: str = DEFAULT_SYSLOG_PORT,
    log_profile: str = DEFAULT_LOG_FORWARDING_PROFILE,
) -> str:
    """Render the PAN-OS CLI block that forwards PBP logs to this collector.

    The Threat match list is added to an existing log forwarding profile rather
    than replacing it, so a profile already referenced by every security rule
    keeps its current destinations and built-in actions.
    """
    server = f"set shared log-settings syslog {SYSLOG_OBJECT_NAME} server {SYSLOG_OBJECT_NAME}"
    system = f"set shared log-settings system match-list {SYSLOG_OBJECT_NAME}"
    profile = f"set shared log-settings profiles {log_profile} match-list {SYSLOG_OBJECT_NAME}"
    threat_filter = " or ".join(f"(threatid eq {identifier})" for identifier in PBP_THREAT_IDS)
    return "\n".join(
        (
            "configure",
            "",
            "# Syslog server profile dedicated to the collector",
            f"{server} server {collector_host}",
            f"{server} transport UDP",
            f"{server} port {syslog_port}",
            f"{server} format BSD",
            f"{server} facility LOG_USER",
            "",
            "# System logs: packet-buffer congestion alerts and transport freshness",
            f'{system} filter "All Logs"',
            f"{system} send-syslog [ {SYSLOG_OBJECT_NAME} ]",
            "",
            f"# PBP Threat logs added to the existing log forwarding profile {log_profile}",
            f"{profile} log-type threat",
            f'{profile} filter "({threat_filter})"',
            f"{profile} send-syslog [ {SYSLOG_OBJECT_NAME} ]",
            "",
            "# Review the candidate configuration before committing",
            f"show shared log-settings syslog {SYSLOG_OBJECT_NAME}",
            "show shared log-settings system",
            f"show shared log-settings profiles {log_profile}",
            "show rulebase security rules | match log-setting",
            "",
            'commit description "Forward PBP System and Threat logs to the diagnostic collector"',
        )
    )


def _e(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def _layout(title: str, body: str, refresh_seconds: int | None = None) -> str:
    refresh = (
        f'<meta http-equiv="refresh" content="{max(2, int(refresh_seconds))}">'
        if refresh_seconds
        else ""
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">{refresh}
<title>{_e(title)} · PBP Monitoring</title><style>
:root{{--ink:#172033;--muted:#64748b;--line:#dbe3ee;--soft:#f4f7fb;--accent:#155e75;--bad:#b42318;--ok:#15803d}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--soft);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}}
header{{padding:22px max(20px,calc((100vw - 1080px)/2));color:white;background:linear-gradient(125deg,#0f172a,#155e75)}}
header a{{color:white}}main{{width:min(1080px,calc(100% - 28px));margin:22px auto 48px}}.card{{padding:20px;margin:0 0 18px;border:1px solid var(--line);border-radius:14px;background:white;box-shadow:0 4px 18px #0f172a0a}}
h1,h2{{margin-top:0}}label{{display:block;margin:11px 0 4px;font-weight:650}}input,select{{width:100%;padding:9px 10px;border:1px solid #bdc9d8;border-radius:8px;background:white}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0 14px}}button,.button{{display:inline-block;margin-top:14px;padding:9px 14px;border:0;border-radius:8px;background:var(--accent);color:white;font-weight:700;text-decoration:none;cursor:pointer}}
button.danger{{background:var(--bad)}}.muted{{color:var(--muted)}}.notice{{padding:10px 12px;border-radius:8px;background:#e0f2fe;color:#075985}}.error{{background:#fee2e2;color:#991b1b}}table{{width:100%;border-collapse:collapse}}th,td{{padding:9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}code{{overflow-wrap:anywhere}}pre{{margin:0;padding:14px;overflow-x:auto;border-radius:10px;background:#0f172a;color:#e2e8f0;font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}}form.inline{{display:inline}}form.inline button{{margin:0}}nav{{display:flex;gap:16px;align-items:center}}nav .version{{margin-left:auto;color:#d9f4f2}}.action-row{{display:flex;align-items:center;gap:7px}}.action-row .button,.action-row button{{display:inline-flex;align-items:center;justify-content:center;width:72px;height:34px;margin:0;padding:6px 9px}}
.form-actions{{display:flex;align-items:center;gap:10px;margin-top:18px}}.form-actions button,.form-actions .button{{display:inline-flex;align-items:center;height:38px;margin:0}}
.button.secondary{{background:white;color:var(--ink);border:1px solid #bdc9d8}}
fieldset.auth{{margin:16px 0 0;padding:4px 14px 14px;border:1px solid var(--line);border-radius:10px}}
fieldset.auth>legend{{padding:0 6px;font-weight:650}}
fieldset.auth>input[type=radio]{{width:auto;margin:0 6px 0 0;vertical-align:middle;accent-color:var(--accent)}}
fieldset.auth>label{{display:inline-block;margin:6px 20px 6px 0;font-weight:500}}
fieldset.auth>.panel{{display:none;margin-top:2px}}fieldset.auth>.panel .muted{{margin:8px 0 0}}
#auth-stored:checked~#panel-stored,#auth-credentials:checked~#panel-credentials,#auth-key:checked~#panel-key{{display:block}}
</style></head><body><header><nav><strong>PBP Monitoring Admin</strong><a href="/">Dashboard</a><a href="/admin">Configuration</a><span class="version">v{_e(__version__)}</span></nav></header><main>{body}</main></body></html>"""


class AdminController:
    def __init__(
        self,
        store: ConfigStore,
        *,
        trust_loopback_proxy: bool = False,
        allow_remote: bool = True,
        secure_cookie: bool = False,
        data_dir: Path | None = None,
        log_dirs: Sequence[Path] = (),
    ):
        self.store = store
        self.trust_loopback_proxy = trust_loopback_proxy
        self.allow_remote = allow_remote
        self.secure_cookie = secure_cookie
        self.data_dir = Path(data_dir) if data_dir is not None else None
        self.log_dirs = tuple(Path(directory) for directory in log_dirs)
        self.store.initialize()
        self.sessions: dict[str, tuple[float, str]] = {}
        self.setup_token = secrets.token_urlsafe(32)
        self.login_token = secrets.token_urlsafe(32)
        self.auth_failures: dict[str, deque[float]] = {}
        self.verify_slots = threading.BoundedSemaphore(VERIFY_CONCURRENCY)
        self.setup_code: str | None = None
        if not self.store.has_admin_password():
            # A freshly deployed collector must not be claimable by whoever
            # reaches the port first. The code is only visible to someone who
            # can already read the container logs on the host.
            self.setup_code = secrets.token_urlsafe(12)
            LOG.warning(
                "Initial administrator setup requires the one-time setup code: %s",
                self.setup_code,
                # Shown once in the container log an operator must already be
                # able to read. A persistent file that later travels inside a
                # support bundle is not that place.
                extra={diagnostics.SENSITIVE_ATTRIBUTE: True},
            )

    def _throttled(self, source: str) -> bool:
        """Report whether this source exhausted its authentication attempts."""
        now = time.monotonic()
        failures = self.auth_failures.get(source)
        if failures is None:
            return False
        while failures and now - failures[0] > AUTH_ATTEMPT_WINDOW_SECONDS:
            failures.popleft()
        if not failures:
            del self.auth_failures[source]
            return False
        return len(failures) >= AUTH_ATTEMPT_LIMIT

    def _record_auth_failure(self, source: str) -> None:
        now = time.monotonic()
        for known in list(self.auth_failures):
            entries = self.auth_failures[known]
            while entries and now - entries[0] > AUTH_ATTEMPT_WINDOW_SECONDS:
                entries.popleft()
            if not entries:
                del self.auth_failures[known]
        if len(self.auth_failures) >= AUTH_SOURCE_LIMIT and source not in self.auth_failures:
            # Bounded memory: beyond this many concurrently throttled sources
            # the service is under attack anyway; drop the oldest entry.
            self.auth_failures.pop(next(iter(self.auth_failures)))
        self.auth_failures.setdefault(source, deque()).append(now)

    def _throttle_page(self, handler: Any) -> None:
        self._send(
            handler,
            _layout(
                "Too many attempts",
                '<section class="card"><h1>Too many failed attempts</h1>'
                "<p>Authentication from your address is paused. Try again in a few minutes.</p></section>",
            ),
            429,
        )

    def _is_loopback(self, handler: Any) -> bool:
        if self.allow_remote or self.trust_loopback_proxy:
            return True
        try:
            return ipaddress.ip_address(handler.client_address[0]).is_loopback
        except ValueError:
            return False

    def _send(self, handler: Any, payload: str, status: int = 200, cookie: str | None = None) -> None:
        encoded = payload.encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "text/html; charset=utf-8")
        handler.send_header("Content-Length", str(len(encoded)))
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.send_header("Referrer-Policy", "no-referrer")
        handler.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        if self.secure_cookie:
            handler.send_header("Strict-Transport-Security", "max-age=31536000")
        if cookie:
            handler.send_header("Set-Cookie", cookie)
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(encoded)

    def _send_download(
        self,
        handler: Any,
        payload: bytes,
        content_type: str,
        filename: str,
    ) -> None:
        handler.send_response(200)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        handler.send_header("Content-Length", str(len(payload)))
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.send_header("Referrer-Policy", "no-referrer")
        if self.secure_cookie:
            handler.send_header("Strict-Transport-Security", "max-age=31536000")
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(payload)

    def _redirect(self, handler: Any, location: str, cookie: str | None = None) -> None:
        handler.send_response(303)
        handler.send_header("Location", location)
        handler.send_header("Cache-Control", "no-store")
        if self.secure_cookie:
            handler.send_header("Strict-Transport-Security", "max-age=31536000")
        if cookie:
            handler.send_header("Set-Cookie", cookie)
        handler.end_headers()

    @staticmethod
    def read_form(handler: Any) -> dict[str, str]:
        try:
            length = int(handler.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid request length") from exc
        if length <= 0 or length > 64 * 1024:
            raise ValueError("invalid form size")
        values = parse_qs(handler.rfile.read(length).decode("utf-8"), keep_blank_values=True)
        return {key: items[-1] for key, items in values.items() if items}

    def is_authenticated(self, handler: Any) -> bool:
        """Report whether this request carries a live administrator session.

        Used by the dashboard to gate incident evidence behind the same
        session as the configuration. Fails closed: no password configured or
        no valid cookie both deny.
        """
        try:
            return self.store.has_admin_password() and self._session(handler) is not None
        except Exception:
            LOG.exception("Unable to evaluate the administrator session")
            return False

    def session_csrf(self, handler: Any) -> str | None:
        """Return the CSRF token of the live session, or ``None`` without one.

        The dashboard carries destructive controls of its own, so it needs the
        same per-session token the administration forms use.
        """
        session = self._session(handler)
        return session[1] if session else None

    def _session(self, handler: Any) -> tuple[str, str] | None:
        cookie = SimpleCookie(handler.headers.get("Cookie", ""))
        token = cookie.get("PBPADMIN")
        if not token:
            return None
        value = self.sessions.get(token.value)
        if not value or value[0] < time.monotonic():
            self.sessions.pop(token.value, None)
            return None
        return token.value, value[1]

    def _login_page(self, message: str = "") -> str:
        notice = f'<p class="notice error">{_e(message)}</p>' if message else ""
        return _layout("Sign in", f"""<section class="card"><h1>Administrator sign in</h1>{notice}
<p class="muted">Use a trusted management network. Remote access must be protected by HTTPS, a VPN, or an authenticated TLS reverse proxy.</p>
<form method="post" action="/admin/login"><input type="hidden" name="csrf" value="{self.login_token}">
<label>Password</label><input type="password" name="password" autocomplete="current-password" required autofocus>
<button type="submit">Sign in</button></form></section>""")

    def _setup_page(self, message: str = "") -> str:
        notice = f'<p class="notice error">{_e(message)}</p>' if message else ""
        return _layout("Initial setup", f"""<section class="card"><h1>Secure initial setup</h1>{notice}
<p>Create the local administrator password. It is stored as a salted PBKDF2 hash and cannot be recovered.</p>
<p class="muted">The one-time setup code is printed in the webui container log at startup:
<code>docker compose logs webui | grep "setup code"</code>. It proves you operate the host, so the
collector cannot be claimed by whoever reaches this port first.</p>
<form method="post" action="/admin/setup"><input type="hidden" name="csrf" value="{self.setup_token}">
<label>Setup code (from the container log)</label><input type="text" name="setup_code" autocomplete="off" required>
<label>Password (8 characters minimum)</label><input type="password" name="password" autocomplete="new-password" minlength="8" required>
<label>Confirm password</label><input type="password" name="confirm" autocomplete="new-password" minlength="8" required>
<button type="submit">Create administrator</button></form></section>""")

    def _dashboard(
        self,
        csrf: str,
        message: str = "",
        edit_id: int | None = None,
        syslog: dict[str, str] | None = None,
    ) -> str:
        settings = self.store.get_settings()
        targets = self.store.list_targets()
        notice = f'<p class="notice">{_e(message)}</p>' if message else ""
        rows = []
        for target in targets:
            rows.append(
                "<tr>"
                f"<td><strong>{_e(target['name'])}</strong></td>"
                f"<td>{_e(target['hostname'] or '-')}<div class=\"muted\">{_e(self._device_summary(target))}</div></td>"
                f"<td><code>{_e(self._firewall_ip(target))}</code></td>"
                f"<td><code>{_e(', '.join(target['serials']) or '-')}</code></td>"
                f"<td>{'Enabled' if target['enabled'] else 'Disabled'}</td>"
                f"<td>{self._check_summary(target)}</td>"
                f"<td><div class=\"action-row\"><a class=\"button\" href=\"/admin?edit={target['target_id']}\">Edit</a>"
                f"<form class=\"inline\" method=\"post\" action=\"/admin/target/check\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"target_id\" value=\"{target['target_id']}\"><button class=\"secondary\" type=\"submit\">Test</button></form>"
                f"<form class=\"inline\" method=\"post\" action=\"/admin/target/delete\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"target_id\" value=\"{target['target_id']}\"><button class=\"danger\" type=\"submit\">Delete</button></form></div></td></tr>"
            )
        target_rows = "".join(rows) or '<tr><td colspan="7" class="muted">No firewall configured yet.</td></tr>'
        edit_target = next((target for target in targets if target["target_id"] == edit_id), None)
        # A queued validation is cleared by the collector within seconds, so the
        # page reloads itself until the outcome is known. Editing a firewall
        # suspends the reload: it must never discard what is being typed.
        refresh_seconds = (
            PENDING_CHECK_REFRESH_SECONDS
            if edit_target is None
            and any(target.get("check_requested_at") for target in targets)
            else None
        )
        recovery = ""
        if not self.store.recovery_key_acknowledged():
            recovery_key = self.store.recovery_key()
            recovery = f"""<section class="card"><h2>Save the installation recovery key</h2>
<p class="notice error"><strong>This key is shown until you confirm its backup.</strong> Store it in a password manager or offline vault. Anyone who obtains both this key and the configuration database can decrypt the PAN-OS API keys.</p>
<label>Recovery key</label><code style="display:block;padding:12px;border-radius:8px;background:#0f172a;color:#e2e8f0;word-break:break-all">{_e(recovery_key)}</code>
<a class="button" href="/admin/recovery-key.csv">Download CSV</a>
<form method="post" action="/admin/recovery-key/ack"><input type="hidden" name="csrf" value="{csrf}"><button type="submit">I have securely saved this key</button></form></section>"""
        return _layout("Configuration", f"""{notice}
<section class="card"><h1>Configuration</h1><p class="muted">Revision {self.store.revision()}. Changes are loaded by the collector between active incidents.</p>
<form class="inline" method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{csrf}"><button type="submit">Sign out</button></form></section>
{recovery}
<section class="card"><h2>Change administrator password</h2>
<p class="muted">Changing the password signs out every administrator session.</p>
<form method="post" action="/admin/password"><input type="hidden" name="csrf" value="{csrf}"><div class="grid">
<div><label>Current password</label><input type="password" name="current_password" autocomplete="current-password" required></div>
<div><label>New password (8 characters minimum)</label><input type="password" name="new_password" autocomplete="new-password" minlength="8" required></div>
<div><label>Confirm new password</label><input type="password" name="confirm_password" autocomplete="new-password" minlength="8" required></div>
</div><button type="submit">Change password</button></form></section>
<section class="card"><h2>Firewalls</h2><table><thead><tr><th>Name</th><th>Device</th><th>Firewall IP</th><th>Serial</th><th>State</th><th>Last check</th><th>Actions</th></tr></thead><tbody>{target_rows}</tbody></table></section>
{self._target_form(csrf, edit_target)}
{self._syslog_card(syslog or self._syslog_options(None), targets)}
<section class="card"><h2>Support bundle</h2>
<p class="muted">One archive describing this deployment, for remote diagnosis. It carries the collector and dashboard logs, the running versions, every setting, the run inventory and the recent Syslog journals including refused messages. It never carries PAN-OS API keys, the administrator password or the recovery key. Producing it makes no call to any firewall.</p>
<p class="muted">The complete bundle names your firewalls: management addresses, hostnames, serial numbers and the source addresses recorded during an incident. The anonymized bundle replaces each of those with a token such as <code>ip-3f2c1a9b4d</code>, the same token every time so an offender stays recognizable across incidents, and irreversible for whoever receives it. Download the token mapping to translate a token back, and keep that file: it is the one thing that must never be sent.</p>
<div class="action-row"><a class="button" href="/admin/support-bundle.zip">Download support bundle</a>
<a class="button" href="/admin/support-bundle-anonymized.zip">Download anonymized bundle</a>
<a class="secondary button" href="/admin/support-token-mapping.csv">Download token mapping</a></div></section>
<section class="card"><h2>Collector settings</h2><form method="post" action="/admin/settings"><input type="hidden" name="csrf" value="{csrf}"><div class="grid">
{''.join(f'<div><label>{_e(setting_label(key))}</label><input name="{_e(key)}" value="{_e(value)}"{"" if DEFAULT_SETTINGS.get(key) == "" else " required"}></div>' for key, value in settings.items())}
</div><button type="submit">Save settings</button></form></section>""", refresh_seconds)

    def _support_bundle(self, anonymized: bool = False) -> tuple[bytes, bytes]:
        """Build the deployment diagnostic archive, and its token mapping.

        The archive is bounded by construction: only tails of the journals and
        logs, the most recent read-only API validation per firewall, and small
        generated summaries. Building it makes no call to any firewall.
        """
        anonymizer = (
            diagnostics.build_anonymizer(self.store) if anonymized else None
        )
        buffer = io.BytesIO()
        diagnostics.write_support_bundle(
            buffer,
            data_dir=self.data_dir if self.data_dir is not None else Path("/data"),
            config_store=self.store,
            log_dirs=self.log_dirs,
            anonymizer=anonymizer,
        )
        mapping = anonymizer.mapping_csv() if anonymizer is not None else b""
        return buffer.getvalue(), mapping

    def _syslog_options(self, handler: Any, query: dict[str, list[str]] | None = None) -> dict[str, str]:
        """Resolve the values the PAN-OS Syslog commands are rendered with.

        The collector address defaults to the address the administrator reached
        this page on, which is the host the firewall must send Syslog to. Every
        value is validated: an unusable one falls back to its default and is
        reported instead of reaching the rendered commands.
        """
        query = query or {}
        warnings: list[str] = []

        def submitted(field: str) -> str:
            return str(query.get(field, [""])[-1]).strip()

        host = submitted("collector_ip") or self._request_host(handler)
        if host and not COLLECTOR_HOST.fullmatch(host):
            warnings.append(f"ignored collector address {host!r}")
            host = ""
        port = submitted("syslog_port") or DEFAULT_SYSLOG_PORT
        if not (port.isdigit() and 1 <= int(port) <= 65535):
            warnings.append(f"ignored Syslog port {port!r}")
            port = DEFAULT_SYSLOG_PORT
        profile = submitted("log_profile") or DEFAULT_LOG_FORWARDING_PROFILE
        if not PANOS_OBJECT_NAME.fullmatch(profile):
            warnings.append(f"ignored log forwarding profile {profile!r}")
            profile = DEFAULT_LOG_FORWARDING_PROFILE
        return {
            "collector_host": host or COLLECTOR_HOST_PLACEHOLDER,
            "syslog_port": port,
            "log_profile": profile,
            "warning": "; ".join(warnings),
        }

    @staticmethod
    def _request_host(handler: Any) -> str:
        """Return the host part of the address this page was reached on."""
        if handler is None:
            return ""
        header = str(getattr(handler, "headers", {}).get("Host") or "")
        host = urlsplit(f"//{header}").hostname or ""
        return host if COLLECTOR_HOST.fullmatch(host) else ""

    def _syslog_card(self, options: dict[str, str], targets: list[dict[str, Any]]) -> str:
        """Render the ready-to-paste PAN-OS Syslog forwarding commands."""
        commands = syslog_commands(
            options["collector_host"], options["syslog_port"], options["log_profile"]
        )
        download = "/admin/syslog-commands.txt?" + urlencode(
            {
                "collector_ip": options["collector_host"],
                "syslog_port": options["syslog_port"],
                "log_profile": options["log_profile"],
            }
        )
        warning = (
            f'<p class="notice error">{_e(options["warning"])}.</p>'
            if options.get("warning")
            else ""
        )
        unresolved = (
            '<p class="notice error">Replace <code>&lt;COLLECTOR_IP&gt;</code> with the address '
            "of this collector as the firewall reaches it, then submit the form again.</p>"
            if options["collector_host"] == COLLECTOR_HOST_PLACEHOLDER
            else ""
        )
        names = ", ".join(str(target["name"]) for target in targets)
        applies = (
            f'<p class="muted">Run this block on each configured firewall: <code>{_e(names)}</code>. '
            "A firewall must send Syslog from the address registered as its <strong>Firewall IP</strong>; "
            "a service route sending from another address is rejected as <code>source not allowlisted</code>.</p>"
            if targets
            else '<p class="muted">Add a firewall above, then run this block on it.</p>'
        )
        return f"""<section class="card" id="syslog"><h2>PAN-OS Syslog forwarding</h2>
<p class="muted">These commands are for you to review and run on the firewall. The collector never writes to PAN-OS.
They create a Syslog server profile dedicated to this collector, forward System logs so packet-buffer congestion alerts
and transport freshness both arrive, and add the PBP Threat IDs {_e(", ".join(PBP_THREAT_IDS))} to a log forwarding profile
you already apply to your security rules, without replacing its existing destinations.</p>
{warning}{unresolved}{applies}
<form method="get" action="/admin"><div class="grid">
<div><label>Collector IP</label><input name="collector_ip" value="{_e(options["collector_host"])}" placeholder="192.0.2.20"><span class="muted">Address of this host as the firewall reaches it.</span></div>
<div><label>Syslog port</label><input name="syslog_port" value="{_e(options["syslog_port"])}"><span class="muted">Host port published for the Syslog gateway.</span></div>
<div><label>Log forwarding profile</label><input name="log_profile" value="{_e(options["log_profile"])}" placeholder="default"><span class="muted">Replace with the profile your security rules already reference.</span></div>
</div><div class="form-actions"><button type="submit">Update commands</button><a class="button secondary" href="{_e(download)}">Download</a></div></form>
<pre>{_e(commands)}</pre></section>"""

    @staticmethod
    def _check_summary(target: dict[str, Any]) -> str:
        """Render the outcome of the last automatic or requested firewall check."""
        if target.get("check_requested_at"):
            return (
                '<span class="muted">Validation queued</span>'
                '<div class="muted">Waiting for the collector</div>'
            )
        checked_at = target.get("last_check_at")
        if not checked_at:
            return '<span class="muted">Never checked</span>'
        status = str(target.get("last_check_status") or "")
        kind = str(target.get("last_check_kind") or "check")
        label = "Passed" if status == "ok" else "Failed"
        colour = "#047857" if status == "ok" else "var(--bad)"
        detail = str(target.get("last_check_detail") or "")
        return (
            f'<strong style="color:{colour}">{_e(label)}</strong>'
            f'<div class="muted">{_e(kind)} &middot; {_e(str(checked_at)[:19])}Z</div>'
            + (f'<div class="muted">{_e(detail)}</div>' if detail else "")
        )

    @staticmethod
    def _device_summary(target: dict[str, Any]) -> str:
        model, version = target.get("model"), target.get("sw_version")
        return " · ".join(
            part for part in (model, f"PAN-OS {version}" if version else "") if part
        )

    @staticmethod
    def _firewall_ip(target: dict[str, Any]) -> str:
        return urlsplit(str(target.get("panos_url") or "")).hostname or ""

    def _target_form(self, csrf: str, target: dict[str, Any] | None = None) -> str:
        target = target or {}
        editing = bool(target)
        address = self._firewall_ip(target)
        tls = str(target.get("tls_verify") or "false")
        custom_tls = (
            f'<option value="{_e(tls)}" selected>CA bundle: {_e(tls)}</option>'
            if tls not in {"true", "false"}
            else ""
        )
        stored_choice = (
            '<input type="radio" id="auth-stored" name="auth_method" value="stored" checked>'
            '<label for="auth-stored">Keep the stored API key</label>'
            if editing
            else ""
        )
        stored_panel = (
            '<div class="panel" id="panel-stored"><p class="muted">The encrypted API key already '
            "stored for this firewall is reused and revalidated.</p></div>"
            if editing
            else ""
        )
        extra_sources = [
            source for source in target.get("syslog_sources", ()) if source != address
        ]
        notes = []
        if target.get("serials") or target.get("hostname"):
            identity = " · ".join(
                part
                for part in (
                    target.get("hostname"),
                    self._device_summary(target),
                    ", ".join(target.get("serials", ())),
                )
                if part
            )
            notes.append(f"Read from the firewall: <code>{_e(identity)}</code>.")
        if extra_sources:
            notes.append(
                "Additional allowed Syslog sources configured outside this form are preserved: "
                f"<code>{_e(', '.join(extra_sources))}</code>."
            )
        note_html = f'<p class="muted">{" ".join(notes)}</p>' if notes else ""
        return f"""<section class="card"><h2>{'Edit firewall' if editing else 'Add a firewall'}</h2>
<p class="muted">The firewall IP is both the API management address and the allowed Syslog source. Saving contacts the firewall
with <code>show system info</code>: it validates the credentials and reads the device serial, so the firewall must be reachable.</p>
<form method="post" action="/admin/target/save"><input type="hidden" name="csrf" value="{csrf}">
<input type="hidden" name="target_id" value="{_e(target.get('target_id'))}"><div class="grid">
<div><label>Name</label><input name="name" value="{_e(target.get('name'))}" placeholder="firewall hostname"><span class="muted">Optional. Left blank, the PAN-OS hostname is used.</span></div>
<div><label>Firewall IP</label><input name="firewall_ip" value="{_e(address)}" placeholder="192.0.2.10" required></div>
<div><label>TLS verify</label><select name="tls_verify">{custom_tls}<option value="true" {'selected' if tls == 'true' else ''}>Yes</option><option value="false" {'selected' if tls != 'true' and not custom_tls else ''}>No</option></select><span class="muted">Per-firewall setting. New firewalls default to No.</span></div>
<div><label>Enabled</label><select name="enabled"><option value="true" {'selected' if target.get('enabled', True) else ''}>Yes</option><option value="false" {'selected' if target and not target.get('enabled') else ''}>No</option></select></div>
</div>
<fieldset class="auth"><legend>Authentication method</legend>{stored_choice}
<input type="radio" id="auth-credentials" name="auth_method" value="credentials" {'' if editing else 'checked'}><label for="auth-credentials">Username and password</label>
<input type="radio" id="auth-key" name="auth_method" value="api_key"><label for="auth-key">API key</label>
{stored_panel}<div class="panel" id="panel-credentials"><div class="grid">
<div><label>API username</label><input name="username" autocomplete="off"></div>
<div><label>API password (never stored)</label><input type="password" name="password" autocomplete="new-password"></div>
</div><p class="muted">The credentials generate an API key by HTTPS POST; only the key is stored.</p>
<p class="notice error">With <strong>TLS verify: No</strong>, this password travels over an unverified
connection and can be intercepted on the management path. Prefer the API key method with a key
generated on the firewall CLI, or enable TLS verification first.</p></div>
<div class="panel" id="panel-key"><div class="grid">
<div><label>API key</label><input type="password" name="api_key" autocomplete="off"></div>
</div></div></fieldset>
{note_html}<div class="form-actions"><button type="submit">Save firewall</button>{'<a class="button secondary" href="/admin">Cancel</a>' if editing else ''}</div></form></section>"""

    @staticmethod
    def _resolved_name(value: str, identity: dict[str, str], existing: Any) -> str:
        name = str(value).strip()
        if name:
            return name
        hostname = str(identity.get("hostname") or "").strip()
        if TARGET_NAME.fullmatch(hostname):
            return hostname
        if existing is not None:
            return existing.name
        raise ValueError(
            "enter a name: the PAN-OS hostname is empty or contains unsupported characters"
        )

    @staticmethod
    def _validated_firewall_ip(value: str) -> str:
        try:
            return str(ipaddress.ip_address(str(value).strip()))
        except ValueError as exc:
            raise ValueError(
                "the firewall IP must be an IPv4 or IPv6 address; it is also the allowed Syslog source"
            ) from exc

    @staticmethod
    def _validated_tls_verify(value: str, existing: Any) -> str:
        value = str(value).strip() or "false"
        if value in {"true", "false"}:
            return value
        if existing is not None and value == existing.tls_verify:
            return value
        raise ValueError("TLS verify must be Yes or No")

    def _resolved_api_key(
        self,
        form: dict[str, str],
        *,
        panos_url: str,
        ssl_context: Any,
        timeout: float,
        existing: Any,
    ) -> str:
        method = form.get("auth_method", "credentials")
        if method == "stored":
            if existing is None:
                raise ValueError("a new firewall has no stored API key to reuse")
            return existing.api_key
        if method == "api_key":
            api_key = form.get("api_key", "").strip()
            if not api_key:
                raise ValueError("an API key is required for this authentication method")
            return api_key
        if method != "credentials":
            raise ValueError("invalid authentication method")
        username, password = form.get("username", "").strip(), form.get("password", "")
        if not username or not password:
            raise ValueError("both API username and password are required to generate a key")
        return generate_api_key(
            panos_url, username, password, ssl_context=ssl_context, timeout=timeout
        )

    def handle(self, handler: Any, path: str) -> bool:
        if not path.startswith("/admin"):
            return False
        if not self._is_loopback(handler):
            self._send(handler, _layout("Forbidden", '<section class="card"><h1>Forbidden</h1><p>Remote administration is disabled.</p></section>'), 403)
            return True
        try:
            if not self.store.has_admin_password():
                if handler.command == "POST" and path == "/admin/setup":
                    source = handler.client_address[0]
                    if self._throttled(source):
                        self._throttle_page(handler)
                        return True
                    form = self.read_form(handler)
                    if not secrets.compare_digest(form.get("csrf", ""), self.setup_token):
                        raise ValueError("invalid setup token")
                    if not secrets.compare_digest(
                        form.get("setup_code", ""), self.setup_code or ""
                    ):
                        self._record_auth_failure(source)
                        self._send(
                            handler,
                            self._setup_page(
                                "Invalid setup code. Read it in the webui container log."
                            ),
                            403,
                        )
                        return True
                    if form.get("password") != form.get("confirm"):
                        raise ValueError("password confirmation does not match")
                    self.store.set_admin_password(form.get("password", ""))
                    self.setup_token = secrets.token_urlsafe(32)
                    self.setup_code = None
                    self._redirect(handler, "/admin")
                else:
                    self._send(handler, self._setup_page())
                return True
            session = self._session(handler)
            if session is None:
                if handler.command == "POST" and path == "/admin/login":
                    source = handler.client_address[0]
                    if self._throttled(source):
                        self._throttle_page(handler)
                        return True
                    form = self.read_form(handler)
                    if not self.verify_slots.acquire(blocking=False):
                        # Password hashing is deliberately expensive; refuse to
                        # stack unlimited concurrent derivations.
                        self._send(
                            handler,
                            self._login_page("The server is busy. Try again."),
                            503,
                        )
                        return True
                    try:
                        accepted = secrets.compare_digest(
                            form.get("csrf", ""), self.login_token
                        ) and self.store.verify_admin_password(form.get("password", ""))
                    finally:
                        self.verify_slots.release()
                    if not accepted:
                        self._record_auth_failure(source)
                        self._send(handler, self._login_page("Invalid password."), 401)
                    else:
                        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                        self.sessions[token] = (time.monotonic() + SESSION_SECONDS, csrf)
                        secure = "; Secure" if self.secure_cookie else ""
                        self._redirect(handler, "/admin", f"PBPADMIN={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}{secure}")
                else:
                    self._send(handler, self._login_page())
                return True
            token, csrf = session
            query = parse_qs(urlsplit(handler.path).query)
            syslog = self._syslog_options(handler, query)
            if handler.command == "GET":
                if path == "/admin/recovery-key.csv":
                    if self.store.recovery_key_acknowledged():
                        handler.send_error(404)
                        return True
                    output = io.StringIO(newline="")
                    writer = csv.writer(output)
                    writer.writerow(("product", "version", "recovery_key"))
                    writer.writerow(("PBP Monitoring", __version__, self.store.recovery_key()))
                    self._send_download(
                        handler,
                        output.getvalue().encode("utf-8-sig"),
                        "text/csv; charset=utf-8",
                        f"pbp-monitoring-recovery-key-v{__version__}.csv",
                    )
                    return True
                if path in (
                    "/admin/support-bundle.zip",
                    "/admin/support-bundle-anonymized.zip",
                ):
                    anonymized = path.endswith("anonymized.zip")
                    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
                    payload, _mapping = self._support_bundle(anonymized)
                    self._send_download(
                        handler,
                        payload,
                        "application/zip",
                        f"pbp-support-{'anonymized-' if anonymized else ''}{stamp}.zip",
                    )
                    return True
                if path == "/admin/support-token-mapping.csv":
                    # Regenerating the bundle is what guarantees the mapping
                    # covers exactly what an anonymized export contains; the
                    # tokens are derived from the stored salt, so it matches any
                    # bundle this installation has produced.
                    _payload, mapping = self._support_bundle(True)
                    self._send_download(
                        handler,
                        mapping,
                        "text/csv; charset=utf-8",
                        "pbp-support-token-mapping.csv",
                    )
                    return True
                if path == "/admin/syslog-commands.txt":
                    self._send_download(
                        handler,
                        (
                            syslog_commands(
                                syslog["collector_host"],
                                syslog["syslog_port"],
                                syslog["log_profile"],
                            )
                            + "\n"
                        ).encode("utf-8"),
                        "text/plain; charset=utf-8",
                        "pbp-monitoring-syslog-forwarding.txt",
                    )
                    return True
                edit_id = int(query["edit"][-1]) if query.get("edit") else None
                self._send(handler, self._dashboard(csrf, edit_id=edit_id, syslog=syslog))
                return True
            form = self.read_form(handler)
            if not secrets.compare_digest(form.get("csrf", ""), csrf):
                raise ValueError("invalid CSRF token")
            if path == "/admin/logout":
                self.sessions.pop(token, None)
                secure = "; Secure" if self.secure_cookie else ""
                self._redirect(handler, "/admin", f"PBPADMIN=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict{secure}")
            elif path == "/admin/recovery-key/ack":
                self.store.acknowledge_recovery_key()
                self._send(handler, self._dashboard(csrf, "Recovery key delivery acknowledged.", syslog=syslog))
            elif path == "/admin/settings":
                self.store.update_settings({key: form.get(key, "") for key in DEFAULT_SETTINGS})
                self._send(handler, self._dashboard(csrf, "Settings saved.", syslog=syslog))
            elif path == "/admin/password":
                if not self.store.verify_admin_password(form.get("current_password", "")):
                    raise ValueError("current administrator password is incorrect")
                if form.get("new_password") != form.get("confirm_password"):
                    raise ValueError("new password confirmation does not match")
                self.store.set_admin_password(form.get("new_password", ""))
                self.sessions.clear()
                secure = "; Secure" if self.secure_cookie else ""
                self._redirect(
                    handler,
                    "/admin",
                    f"PBPADMIN=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict{secure}",
                )
            elif path == "/admin/target/check":
                self.store.request_target_check(int(form["target_id"]))
                self._send(
                    handler,
                    self._dashboard(
                        csrf,
                        "Full read-only validation requested. The collector runs it "
                        "within a few seconds, and the result appears in this list.",
                        syslog=syslog,
                    ),
                )
            elif path == "/admin/target/delete":
                self.store.delete_target(int(form["target_id"]))
                self._send(handler, self._dashboard(csrf, "Firewall deleted.", syslog=syslog))
            elif path == "/admin/target/save":
                target_id = int(form["target_id"]) if form.get("target_id", "").strip() else None
                existing = None
                if target_id is not None:
                    existing = next(
                        (
                            item
                            for item in self.store.list_targets(include_secrets=True)
                            if item.target_id == target_id
                        ),
                        None,
                    )
                    if existing is None:
                        raise ValueError("firewall no longer exists")
                firewall_ip = self._validated_firewall_ip(form.get("firewall_ip", ""))
                panos_url = normalize_firewall_url(firewall_ip)
                tls = self._validated_tls_verify(form.get("tls_verify", "false"), existing)
                timeout = float(self.store.get_settings()["request_timeout"])
                context = make_ssl_context(
                    insecure=tls == "false", ca_bundle=None if tls == "true" else tls
                )
                api_key = self._resolved_api_key(
                    form,
                    panos_url=panos_url,
                    ssl_context=context,
                    timeout=timeout,
                    existing=existing,
                )
                identity = fetch_system_info(
                    panos_url, api_key, ssl_context=context, timeout=timeout
                )
                core_functions = fetch_dp_core_functions(
                    panos_url, api_key, ssl_context=context, timeout=timeout
                )
                replaced = {firewall_ip}
                if existing is not None:
                    replaced.add(urlsplit(existing.panos_url).hostname or "")
                preserved_sources = [
                    source
                    for source in (existing.syslog_sources if existing else ())
                    if source not in replaced
                ]
                self.store.save_target(
                    target_id=target_id,
                    name=self._resolved_name(form.get("name", ""), identity, existing),
                    panos_url=panos_url, api_key=api_key,
                    target_serial=existing.target_serial if existing else None,
                    serials=[identity["serial"]],
                    syslog_sources=[firewall_ip, *preserved_sources],
                    tls_verify=tls,
                    enabled=form.get("enabled") == "true",
                    device_identity=identity,
                    dp_core_functions=core_functions,
                )
                summary = " ".join(
                    part
                    for part in (
                        identity.get("hostname"),
                        identity.get("model"),
                        f"serial {identity['serial']}",
                        f"PAN-OS {identity['software_version']}"
                        if identity.get("software_version")
                        else "",
                        f"{len(core_functions)} dataplane cores mapped"
                        if core_functions
                        else "dataplane core map unavailable",
                    )
                    if part
                )
                self._send(
                    handler,
                    self._dashboard(
                        csrf,
                        f"Firewall saved and API key validated: {summary}. The API password"
                        " was not stored. Forward its logs with the PAN-OS Syslog commands below.",
                        syslog=syslog,
                    ),
                )
            else:
                handler.send_error(404)
            return True
        except (KeyError, ValueError, OSError, ssl.SSLError, sqlite3.Error, PanOSAdminError) as exc:
            self._send(handler, _layout("Configuration error", f'<section class="card"><h1>Configuration not saved</h1><p class="notice error">{_e(exc)}</p><p><a href="/admin">Return to configuration</a></p></section>'), 400)
            return True
