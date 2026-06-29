"""Admin account, role, and AI-client management for Cortex HTTP servers.

The admin UI is deliberately small and dependency-light. It persists its state in
one local JSON file next to the public-safe config by default. That file contains
password/token hashes and should never be committed.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .config import Principal

ADMIN_PATH = "/admin"
_PASSWORD_ITERS = 200_000


def _now() -> int:
    return int(time.time())


def _hash_secret(secret: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", secret.encode("utf-8"), bytes.fromhex(salt), _PASSWORD_ITERS
    ).hex()
    return salt, digest


def _check_secret(secret: str, *, salt: str, digest: str) -> bool:
    _, candidate = _hash_secret(secret, salt)
    return hmac.compare_digest(candidate, digest)


@dataclass
class CreatedClient:
    name: str
    role: str
    token: str


class AdminStore:
    """Persistent admin state: one admin login, named roles, and AI clients."""

    def __init__(self, path: Path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # -- persistence -----------------------------------------------------
    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> dict[str, Any]:
        if not self.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def save(self, data: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.path.chmod(0o600)

    def ensure_initialized(self) -> str | None:
        """Create admin state if absent. Returns the one-time password if new."""
        if self.exists():
            return None
        password = secrets.token_urlsafe(18)
        salt, digest = _hash_secret(password)
        self.save(
            {
                "admin": {"username": "admin", "salt": salt, "password_hash": digest},
                "roles": {
                    "admin": ["**"],
                    "public": ["Public/**"],
                },
                "clients": {},
                "created_at": _now(),
            }
        )
        return password

    # -- admin auth ------------------------------------------------------
    def authenticate_admin(self, username: str, password: str) -> bool:
        data = self.load()
        admin = data.get("admin", {})
        if username != admin.get("username", "admin"):
            return False
        salt = admin.get("salt")
        digest = admin.get("password_hash")
        if not salt or not digest:
            return False
        return _check_secret(password, salt=salt, digest=digest)

    def cookie_secret(self) -> str:
        admin = self.load().get("admin", {})
        return str(admin.get("password_hash") or "uninitialized")

    # -- roles -----------------------------------------------------------
    def roles(self) -> dict[str, list[str]]:
        return dict(self.load().get("roles", {}))

    def add_role(self, name: str, scopes: list[str]) -> None:
        name = _clean_name(name)
        scopes = [s.strip() for s in scopes if s.strip()]
        if not name:
            raise ValueError("role name is required")
        if not scopes:
            raise ValueError("at least one scope is required")
        data = self.load()
        data.setdefault("roles", {})[name] = scopes
        self.save(data)

    # -- clients ---------------------------------------------------------
    def clients(self) -> dict[str, dict[str, Any]]:
        return dict(self.load().get("clients", {}))

    def create_client(self, name: str, role: str) -> CreatedClient:
        name = _clean_name(name)
        if not name:
            raise ValueError("client name is required")
        data = self.load()
        roles = data.setdefault("roles", {})
        if role not in roles:
            raise ValueError(f"unknown role: {role}")
        token = "ctx_" + secrets.token_urlsafe(32)
        salt, digest = _hash_secret(token)
        data.setdefault("clients", {})[name] = {
            "role": role,
            "salt": salt,
            "token_hash": digest,
            "token_prefix": token[:12],
            "created_at": _now(),
        }
        self.save(data)
        return CreatedClient(name=name, role=role, token=token)

    def principal_for_token(self, token: str | None) -> Principal | None:
        if not token:
            return None
        data = self.load()
        roles = data.get("roles", {})
        for name, info in data.get("clients", {}).items():
            salt = info.get("salt")
            digest = info.get("token_hash")
            role = info.get("role")
            if salt and digest and _check_secret(token, salt=salt, digest=digest):
                return Principal(name=name, scopes=list(roles.get(role, [])))
        return None

    def principal_by_name(self, name: str) -> Principal | None:
        data = self.load()
        info = data.get("clients", {}).get(name)
        if not info:
            return None
        scopes = data.get("roles", {}).get(info.get("role"), [])
        return Principal(name=name, scopes=list(scopes))


class AdminUI:
    """Starlette-compatible route handlers for the small admin UI."""

    def __init__(self, store: AdminStore, base_url: str):
        self.store = store
        self.base = base_url.rstrip("/")

    async def handle(self, request: Request) -> Response:
        subpath = request.url.path[len(ADMIN_PATH):] or "/"
        if request.method == "POST" and subpath == "/login":
            return await self._login(request)
        if request.method == "POST" and subpath == "/logout":
            resp = RedirectResponse(f"{self.base}{ADMIN_PATH}", status_code=303)
            resp.delete_cookie("cortex_admin")
            return resp
        if not self._is_logged_in(request):
            return self._login_page()
        if request.method == "POST" and subpath == "/roles":
            return await self._create_role(request)
        if request.method == "POST" and subpath == "/clients":
            return await self._create_client(request)
        return self._dashboard()

    async def _login(self, request: Request) -> Response:
        form = await request.form()
        username = str(form.get("username", ""))
        password = str(form.get("password", ""))
        if not self.store.authenticate_admin(username, password):
            return self._login_page("Invalid username or password", status=401)
        resp = RedirectResponse(f"{self.base}{ADMIN_PATH}", status_code=303)
        resp.set_cookie("cortex_admin", self._sign("admin"), httponly=True, samesite="lax")
        return resp

    async def _create_role(self, request: Request) -> Response:
        form = await request.form()
        try:
            scopes = str(form.get("scopes", "")).replace("\r", "").split("\n")
            self.store.add_role(str(form.get("name", "")), scopes)
            return self._dashboard(message="Role saved.")
        except ValueError as exc:
            return self._dashboard(error=str(exc), status=400)

    async def _create_client(self, request: Request) -> Response:
        form = await request.form()
        try:
            created = self.store.create_client(str(form.get("name", "")), str(form.get("role", "")))
            msg = f"Client created. Copy this token now; Cortex will not show it again: {created.token}"
            return self._dashboard(message=msg)
        except ValueError as exc:
            return self._dashboard(error=str(exc), status=400)

    def _is_logged_in(self, request: Request) -> bool:
        cookie = request.cookies.get("cortex_admin", "")
        return hmac.compare_digest(cookie, self._sign("admin"))

    def _sign(self, value: str) -> str:
        sig = hmac.new(self.store.cookie_secret().encode(), value.encode(), hashlib.sha256).hexdigest()
        return f"{value}.{sig}"

    def _login_page(self, error: str = "", status: int = 200) -> HTMLResponse:
        err = f'<p class="err">{html.escape(error)}</p>' if error else ""
        return HTMLResponse(_PAGE.format(title="Cortex Admin Login", body=f"""
<h1>Cortex Admin</h1>
<p class="muted">Sign in with the admin password generated by <code>cortex init</code>.</p>
{err}
<form method="post" action="{self.base}{ADMIN_PATH}/login">
<label>Username <input name="username" value="admin" required></label>
<label>Password <input name="password" type="password" required autofocus></label>
<button type="submit">Sign in</button>
</form>
"""), status_code=status)

    def _dashboard(self, message: str = "", error: str = "", status: int = 200) -> HTMLResponse:
        roles = self.store.roles()
        clients = self.store.clients()
        role_options = "".join(
            f'<option value="{html.escape(r)}">{html.escape(r)}</option>' for r in sorted(roles)
        )
        roles_rows = "".join(
            f"<tr><td>{html.escape(name)}</td><td><code>{html.escape(', '.join(scopes))}</code></td></tr>"
            for name, scopes in sorted(roles.items())
        ) or '<tr><td colspan="2">No roles yet.</td></tr>'
        clients_rows = "".join(
            f"<tr><td>{html.escape(name)}</td><td>{html.escape(info.get('role', ''))}</td>"
            f"<td><code>{html.escape(info.get('token_prefix', ''))}…</code></td></tr>"
            for name, info in sorted(clients.items())
        ) or '<tr><td colspan="3">No AI clients yet.</td></tr>'
        msg = f'<p class="ok">{html.escape(message)}</p>' if message else ""
        err = f'<p class="err">{html.escape(error)}</p>' if error else ""
        body = f"""
<h1>Cortex Admin</h1>
<form class="logout" method="post" action="{self.base}{ADMIN_PATH}/logout"><button>Sign out</button></form>
{msg}{err}
<section><h2>Roles</h2>
<table><tr><th>Name</th><th>Scopes</th></tr>{roles_rows}</table>
<form method="post" action="{self.base}{ADMIN_PATH}/roles">
<h3>Create / update role</h3>
<label>Role name <input name="name" placeholder="project-alpha" required></label>
<label>Scopes, one per line <textarea name="scopes" rows="4" placeholder="Projects/Alpha/**" required></textarea></label>
<button type="submit">Save role</button>
</form></section>
<section><h2>AI clients</h2>
<table><tr><th>Name</th><th>Role</th><th>Token prefix</th></tr>{clients_rows}</table>
<form method="post" action="{self.base}{ADMIN_PATH}/clients">
<h3>Create AI client</h3>
<label>Client name <input name="name" placeholder="claude-desktop" required></label>
<label>Role <select name="role">{role_options}</select></label>
<button type="submit">Create client token</button>
</form></section>
"""
        return HTMLResponse(_PAGE.format(title="Cortex Admin", body=body), status_code=status)


def _clean_name(name: str) -> str:
    return "".join(ch for ch in name.strip() if ch.isalnum() or ch in "-_ .")[:80].strip()


_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{{font-family:system-ui,sans-serif;max-width:58rem;margin:3rem auto;padding:0 1rem;color:#202124}}
 h1{{font-size:1.6rem}} h2{{margin-top:2rem}} label{{display:block;margin:.8rem 0}}
 input,textarea,select{{width:100%;padding:.55rem;box-sizing:border-box;font:inherit}}
 button{{padding:.55rem .9rem;font:inherit;cursor:pointer}} table{{width:100%;border-collapse:collapse;margin:.6rem 0 1rem}}
 th,td{{border-bottom:1px solid #ddd;text-align:left;padding:.45rem;vertical-align:top}}
 code{{background:#f3f3f3;padding:.1rem .25rem;border-radius:.2rem}} .muted{{color:#666}} .err{{color:#b00020}}
 .ok{{background:#e9f7ef;border:1px solid #b7e4c7;padding:.75rem;border-radius:.35rem;white-space:pre-wrap}}
 .logout{{float:right}}
</style></head><body>{body}</body></html>"""
