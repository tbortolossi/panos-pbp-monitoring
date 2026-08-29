"""Authenticated administration pages with configurable network exposure."""

from __future__ import annotations

import csv
import html
import ipaddress
import io
import secrets
import sqlite3
import ssl
import time
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .config_store import ConfigStore, DEFAULT_SETTINGS
from .panos_keygen import generate_api_key, make_ssl_context, normalize_firewall_url


SESSION_SECONDS = 8 * 60 * 60


def _e(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def _layout(title: str, body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">
<title>{_e(title)} · PBP Monitoring</title><style>
:root{{--ink:#172033;--muted:#64748b;--line:#dbe3ee;--soft:#f4f7fb;--accent:#155e75;--bad:#b42318;--ok:#15803d}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--soft);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}}
header{{padding:22px max(20px,calc((100vw - 1080px)/2));color:white;background:linear-gradient(125deg,#0f172a,#155e75)}}
header a{{color:white}}main{{width:min(1080px,calc(100% - 28px));margin:22px auto 48px}}.card{{padding:20px;margin:0 0 18px;border:1px solid var(--line);border-radius:14px;background:white;box-shadow:0 4px 18px #0f172a0a}}
h1,h2{{margin-top:0}}label{{display:block;margin:11px 0 4px;font-weight:650}}input,select{{width:100%;padding:9px 10px;border:1px solid #bdc9d8;border-radius:8px;background:white}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0 14px}}button,.button{{display:inline-block;margin-top:14px;padding:9px 14px;border:0;border-radius:8px;background:var(--accent);color:white;font-weight:700;text-decoration:none;cursor:pointer}}
button.danger{{background:var(--bad)}}.muted{{color:var(--muted)}}.notice{{padding:10px 12px;border-radius:8px;background:#e0f2fe;color:#075985}}.error{{background:#fee2e2;color:#991b1b}}table{{width:100%;border-collapse:collapse}}th,td{{padding:9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}code{{overflow-wrap:anywhere}}form.inline{{display:inline}}form.inline button{{margin:0}}nav{{display:flex;gap:16px;align-items:center}}nav .version{{margin-left:auto;color:#d9f4f2}}.action-row{{display:flex;align-items:center;gap:7px}}.action-row .button,.action-row button{{display:inline-flex;align-items:center;justify-content:center;width:72px;height:34px;margin:0;padding:6px 9px}}
</style></head><body><header><nav><strong>PBP Monitoring Admin</strong><a href="/">Dashboard</a><a href="/admin">Configuration</a><span class="version">v{_e(__version__)}</span></nav></header><main>{body}</main></body></html>"""


class AdminController:
    def __init__(
        self,
        store: ConfigStore,
        *,
        trust_loopback_proxy: bool = False,
        allow_remote: bool = True,
        secure_cookie: bool = False,
    ):
        self.store = store
        self.trust_loopback_proxy = trust_loopback_proxy
        self.allow_remote = allow_remote
        self.secure_cookie = secure_cookie
        self.store.initialize()
        self.sessions: dict[str, tuple[float, str]] = {}
        self.setup_token = secrets.token_urlsafe(32)
        self.login_token = secrets.token_urlsafe(32)

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
    def _form(handler: Any) -> dict[str, str]:
        try:
            length = int(handler.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid request length") from exc
        if length <= 0 or length > 64 * 1024:
            raise ValueError("invalid form size")
        values = parse_qs(handler.rfile.read(length).decode("utf-8"), keep_blank_values=True)
        return {key: items[-1] for key, items in values.items() if items}

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
<form method="post" action="/admin/setup"><input type="hidden" name="csrf" value="{self.setup_token}">
<label>Password (8 characters minimum)</label><input type="password" name="password" autocomplete="new-password" minlength="8" required>
<label>Confirm password</label><input type="password" name="confirm" autocomplete="new-password" minlength="8" required>
<button type="submit">Create administrator</button></form></section>""")

    def _dashboard(self, csrf: str, message: str = "", edit_id: int | None = None) -> str:
        settings = self.store.get_settings()
        targets = self.store.list_targets()
        notice = f'<p class="notice">{_e(message)}</p>' if message else ""
        rows = []
        for target in targets:
            rows.append(
                "<tr>"
                f"<td><strong>{_e(target['name'])}</strong></td><td><code>{_e(target['panos_url'])}</code></td>"
                f"<td>{_e(', '.join(target['syslog_sources']))}</td><td>{'Enabled' if target['enabled'] else 'Disabled'}</td>"
                f"<td><div class=\"action-row\"><a class=\"button\" href=\"/admin?edit={target['target_id']}\">Edit</a>"
                f"<form class=\"inline\" method=\"post\" action=\"/admin/target/delete\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"target_id\" value=\"{target['target_id']}\"><button class=\"danger\" type=\"submit\">Delete</button></form></div></td></tr>"
            )
        target_rows = "".join(rows) or '<tr><td colspan="5" class="muted">No firewall configured yet.</td></tr>'
        edit_target = next((target for target in targets if target["target_id"] == edit_id), None)
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
<section class="card"><h2>Firewalls</h2><table><thead><tr><th>Name</th><th>Management URL</th><th>Allowed Syslog sources</th><th>State</th><th>Actions</th></tr></thead><tbody>{target_rows}</tbody></table></section>
{self._target_form(csrf, edit_target)}
<section class="card"><h2>Collector settings</h2><form method="post" action="/admin/settings"><input type="hidden" name="csrf" value="{csrf}"><div class="grid">
{''.join(f'<div><label>{_e(key.replace("_", " ").title())}</label><input name="{_e(key)}" value="{_e(value)}" required></div>' for key, value in settings.items())}
</div><button type="submit">Save settings</button></form></section>""")

    def _target_form(self, csrf: str, target: dict[str, Any] | None = None) -> str:
        target = target or {}
        editing = bool(target)
        return f"""<section class="card"><h2>{'Edit firewall' if editing else 'Add a firewall'}</h2>
<p class="muted">Leave API key blank to retain the existing key. Alternatively provide temporary credentials to generate a key; the password is never stored.</p>
<form method="post" action="/admin/target/save"><input type="hidden" name="csrf" value="{csrf}"><div class="grid">
<input type="hidden" name="target_id" value="{_e(target.get('target_id'))}">
<div><label>Name</label><input name="name" value="{_e(target.get('name'))}" required></div><div><label>Management URL</label><input name="panos_url" value="{_e(target.get('panos_url'))}" placeholder="https://192.0.2.10" required></div>
<div><label>API key</label><input type="password" name="api_key" autocomplete="off"></div><div><label>API username (optional key generation)</label><input name="username" autocomplete="off"></div>
<div><label>API password (never stored)</label><input type="password" name="password" autocomplete="new-password"></div>
<div><label>Device serial(s), comma separated</label><input name="serials" value="{_e(', '.join(target.get('serials', ())))}"></div><div><label>Panorama target serial</label><input name="target_serial" value="{_e(target.get('target_serial'))}"></div>
<div><label>TLS verify</label><input name="tls_verify" value="{_e(target.get('tls_verify', 'false'))}" placeholder="false, true, or /certs/ca.pem" required><span class="muted">Per-firewall setting. New firewalls default to disabled.</span></div>
<div><label>Allowed Syslog source IP(s), comma separated</label><input name="syslog_sources" value="{_e(', '.join(target.get('syslog_sources', ())))}" required></div><div><label>Enabled</label><select name="enabled"><option value="true" {'selected' if target.get('enabled', True) else ''}>Yes</option><option value="false" {'selected' if target and not target.get('enabled') else ''}>No</option></select></div>
</div><button type="submit">Save firewall</button>{'<a class="button" href="/admin">Cancel</a>' if editing else ''}</form></section>"""

    def handle(self, handler: Any, path: str) -> bool:
        if not path.startswith("/admin"):
            return False
        if not self._is_loopback(handler):
            self._send(handler, _layout("Forbidden", '<section class="card"><h1>Forbidden</h1><p>Remote administration is disabled.</p></section>'), 403)
            return True
        try:
            if not self.store.has_admin_password():
                if handler.command == "POST" and path == "/admin/setup":
                    form = self._form(handler)
                    if not secrets.compare_digest(form.get("csrf", ""), self.setup_token):
                        raise ValueError("invalid setup token")
                    if form.get("password") != form.get("confirm"):
                        raise ValueError("password confirmation does not match")
                    self.store.set_admin_password(form.get("password", ""))
                    self.setup_token = secrets.token_urlsafe(32)
                    self._redirect(handler, "/admin")
                else:
                    self._send(handler, self._setup_page())
                return True
            session = self._session(handler)
            if session is None:
                if handler.command == "POST" and path == "/admin/login":
                    form = self._form(handler)
                    if not secrets.compare_digest(form.get("csrf", ""), self.login_token) or not self.store.verify_admin_password(form.get("password", "")):
                        self._send(handler, self._login_page("Invalid password."), 401)
                    else:
                        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                        self.sessions[token] = (time.monotonic() + SESSION_SECONDS, csrf)
                        secure = "; Secure" if self.secure_cookie else ""
                        self._redirect(handler, "/admin", f"PBPADMIN={token}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}{secure}")
                else:
                    self._send(handler, self._login_page())
                return True
            token, csrf = session
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
                query = parse_qs(urlsplit(handler.path).query)
                edit_id = int(query["edit"][-1]) if query.get("edit") else None
                self._send(handler, self._dashboard(csrf, edit_id=edit_id))
                return True
            form = self._form(handler)
            if not secrets.compare_digest(form.get("csrf", ""), csrf):
                raise ValueError("invalid CSRF token")
            if path == "/admin/logout":
                self.sessions.pop(token, None)
                secure = "; Secure" if self.secure_cookie else ""
                self._redirect(handler, "/admin", f"PBPADMIN=; Path=/admin; Max-Age=0; HttpOnly; SameSite=Strict{secure}")
            elif path == "/admin/recovery-key/ack":
                self.store.acknowledge_recovery_key()
                self._send(handler, self._dashboard(csrf, "Recovery key delivery acknowledged."))
            elif path == "/admin/settings":
                self.store.update_settings({key: form.get(key, "") for key in DEFAULT_SETTINGS})
                self._send(handler, self._dashboard(csrf, "Settings saved."))
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
                    f"PBPADMIN=; Path=/admin; Max-Age=0; HttpOnly; SameSite=Strict{secure}",
                )
            elif path == "/admin/target/delete":
                self.store.delete_target(int(form["target_id"]))
                self._send(handler, self._dashboard(csrf, "Firewall deleted."))
            elif path == "/admin/target/save":
                api_key = form.get("api_key", "").strip() or None
                username, password = form.get("username", "").strip(), form.get("password", "")
                if username or password:
                    if not username or not password:
                        raise ValueError("both API username and password are required for key generation")
                    settings = self.store.get_settings()
                    tls = form.get("tls_verify", "false").strip() or "false"
                    context = make_ssl_context(
                        insecure=tls.lower() in {"false", "0", "no", "off"},
                        ca_bundle=None if tls.lower() in {"true", "1", "yes", "on", "false", "0", "no", "off"} else tls,
                    )
                    api_key = generate_api_key(
                        normalize_firewall_url(form["panos_url"]), username, password,
                        ssl_context=context, timeout=float(settings["request_timeout"]),
                    )
                target_id = int(form["target_id"]) if form.get("target_id", "").strip() else None
                self.store.save_target(
                    target_id=target_id, name=form["name"], panos_url=form["panos_url"], api_key=api_key,
                    target_serial=form.get("target_serial"),
                    serials=[value.strip() for value in form.get("serials", "").split(",")],
                    syslog_sources=[value.strip() for value in form.get("syslog_sources", "").split(",")],
                    tls_verify=form.get("tls_verify", "false"),
                    enabled=form.get("enabled") == "true",
                )
                self._send(handler, self._dashboard(csrf, "Firewall saved. The API password was not stored."))
            else:
                handler.send_error(404)
            return True
        except (KeyError, ValueError, OSError, ssl.SSLError, sqlite3.Error) as exc:
            self._send(handler, _layout("Configuration error", f'<section class="card"><h1>Configuration not saved</h1><p class="notice error">{_e(exc)}</p><p><a href="/admin">Return to configuration</a></p></section>'), 400)
            return True
