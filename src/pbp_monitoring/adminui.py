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
from .config_store import ConfigStore, DEFAULT_SETTINGS, TARGET_NAME
from .panos_keygen import (
    PanOSAdminError,
    fetch_dp_core_functions,
    fetch_system_info,
    generate_api_key,
    make_ssl_context,
    normalize_firewall_url,
)


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
                f"<td><strong>{_e(target['name'])}</strong></td>"
                f"<td>{_e(target['hostname'] or '-')}<div class=\"muted\">{_e(self._device_summary(target))}</div></td>"
                f"<td><code>{_e(self._firewall_ip(target))}</code></td>"
                f"<td><code>{_e(', '.join(target['serials']) or '-')}</code></td>"
                f"<td>{'Enabled' if target['enabled'] else 'Disabled'}</td>"
                f"<td><div class=\"action-row\"><a class=\"button\" href=\"/admin?edit={target['target_id']}\">Edit</a>"
                f"<form class=\"inline\" method=\"post\" action=\"/admin/target/delete\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"target_id\" value=\"{target['target_id']}\"><button class=\"danger\" type=\"submit\">Delete</button></form></div></td></tr>"
            )
        target_rows = "".join(rows) or '<tr><td colspan="6" class="muted">No firewall configured yet.</td></tr>'
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
<section class="card"><h2>Firewalls</h2><table><thead><tr><th>Name</th><th>Device</th><th>Firewall IP</th><th>Serial</th><th>State</th><th>Actions</th></tr></thead><tbody>{target_rows}</tbody></table></section>
{self._target_form(csrf, edit_target)}
<section class="card"><h2>Collector settings</h2><form method="post" action="/admin/settings"><input type="hidden" name="csrf" value="{csrf}"><div class="grid">
{''.join(f'<div><label>{_e(key.replace("_", " ").title())}</label><input name="{_e(key)}" value="{_e(value)}" required></div>' for key, value in settings.items())}
</div><button type="submit">Save settings</button></form></section>""")

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
</div><p class="muted">The credentials generate an API key by HTTPS POST; only the key is stored.</p></div>
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
                        f"Firewall saved and API key validated: {summary}. The API password was not stored.",
                    ),
                )
            else:
                handler.send_error(404)
            return True
        except (KeyError, ValueError, OSError, ssl.SSLError, sqlite3.Error, PanOSAdminError) as exc:
            self._send(handler, _layout("Configuration error", f'<section class="card"><h1>Configuration not saved</h1><p class="notice error">{_e(exc)}</p><p><a href="/admin">Return to configuration</a></p></section>'), 400)
            return True
