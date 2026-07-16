"""JSON REST API foundation — the ``/api/v1`` surface (A6, #40).

This is the API the React SPA (C1+) consumes, mounted as a route group on the
same Starlette app that serves MCP and the legacy admin UI. This phase is
**auth + user/group/token management only** — vault-content endpoints are B3,
MCP-gateway endpoints are D. The conventions established here are reused by
every later API issue:

**Auth.** Two credential kinds, resolved per request (design §8.1):

* **Session cookie** (browser/SPA) — resolved via :class:`~cortex.sessions.
  SessionAuth`. Every state-changing method (POST/PUT/PATCH/DELETE) must also
  present the session-bound double-submit CSRF token in ``X-Cortex-CSRF``
  (the A4 scheme), plus pass a same-origin check when the browser sent an
  ``Origin`` header.
* **Bearer token** (scripting) — a per-user API token from ``api_tokens``,
  resolved through the same identity layer as MCP bearer auth. Bearer
  requests are CSRF-exempt by construction: a cross-site page cannot attach
  an ``Authorization`` header without a CORS preflight, and this server never
  answers CORS preflights (no CORS middleware — the SPA is same-origin).

Only **user** identities exist on ``/api/v1``: config principals and legacy
admin-store clients are MCP identities and do not authenticate here (their
tokens get the same uniform 401 as an invalid one).

**Authorization.** Routes are user-level or admin-level. Admin routes return
403 for an authenticated non-admin and 401 for anonymous — the admin check
runs *before* any resource lookup, so a non-admin learns nothing about what
exists. Where a user-level route addresses a resource by id (``DELETE
/tokens/{id}``), a foreign resource is reported with the same 404 as a
missing one (the #21 non-distinguishing rule). **Token rule:** a user manages
only their own API tokens; an admin may revoke anyone's.

**Error envelope.** Every non-2xx response is
``{"error": {"code": "...", "message": "..."}}`` — 400 validation, 401
unauthenticated, 403 unauthorized/CSRF, 404 not found, 429 rate-limited,
503 directory outage.

**Logging.** With ``server.request_log: true``, each request emits one record
on the ``cortex.api.access`` logger: method, path, principal, status,
latency. Never bodies, tokens, or note content (#30 direction). Disabled it
costs one boolean check; the stdio path never touches this module.
"""

from __future__ import annotations

import json
import hashlib
import logging
import mimetypes
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .config import CortexConfig, Principal
from .access import VaultAccessError, VaultAccessResolver
from .gateway import (
    GatewayError,
    GatewayRuntime,
    PermissionResolver,
    validate_env_name,
    validate_header_name,
    validate_outbound_url,
    validate_server_name,
)
from .ldap import DirectoryService, LdapError
from .scopes import filter_paths, path_allowed
from .sessions import CSRF_HEADER, SAFE_METHODS, SessionAuth
from .users import AuthzError, IdentityError, IdentityService
from .vault import VaultError, canonical_asset_path, canonical_note_path
from .vaults import MAIN_VAULT_ID, VaultManagerError, attach_vault_manager

API_PREFIX = "/api/v1"

log = logging.getLogger("cortex.api")
access_log = logging.getLogger("cortex.api.access")

#: Uniform 401 wording — never distinguishes missing vs invalid vs foreign-
#: source credentials (no oracle).
_UNAUTHENTICATED = "authentication required"

#: Uniform login-failure wording — unknown user, wrong password, disabled
#: account, and LDAP-vs-local are indistinguishable (design §7.1).
_BAD_LOGIN = "invalid username or password"

#: Uniform not-found wording — also used for resources the caller is not
#: allowed to know exist (#21: out-of-authz is indistinguishable from absent).
_NOT_FOUND = "not found"


def error_response(status: int, code: str, message: str) -> JSONResponse:
    """The one error envelope every ``/api/v1`` error uses."""
    return JSONResponse(
        {"error": {"code": code, "message": message}}, status_code=status
    )


class ApiError(Exception):
    """Control-flow error rendered as the uniform envelope by the wrapper."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message

    def response(self) -> JSONResponse:
        return error_response(self.status, self.code, self.message)


def _unauthenticated() -> ApiError:
    return ApiError(401, "unauthenticated", _UNAUTHENTICATED)


@dataclass
class ApiIdentity:
    """The resolved caller of one request: a user row plus how it
    authenticated (``session`` or ``bearer``)."""

    user: dict
    via: str  # "session" | "bearer"
    principal: Principal | None = None

    @property
    def username(self) -> str:
        return self.user["username"]

    @property
    def is_admin(self) -> bool:
        return bool(self.user["is_admin"]) and not self.user["disabled"]

    @property
    def subject(self) -> str:
        return f"user:{self.username}"


class LoginRateLimiter:
    """Minimal fixed-window failure throttle for the login route (§7.1).

    Keyed by lowercased username so an attacker can't hammer one account;
    applied *before* any credential check so the throttle itself leaks
    nothing about whether the account exists. In-memory — a restart clears
    it, which is fine for the brute-force class it addresses.
    """

    def __init__(self, max_failures: int = 5, window_seconds: int = 300):
        self.max_failures = int(max_failures)
        self.window_seconds = int(window_seconds)
        self._failures: dict[str, list[float]] = {}

    def _prune(self, key: str, now: float) -> list[float]:
        stamps = [t for t in self._failures.get(key, []) if now - t < self.window_seconds]
        if stamps:
            self._failures[key] = stamps
        else:
            self._failures.pop(key, None)
        return stamps

    def blocked(self, key: str) -> bool:
        return len(self._prune(key.lower(), time.monotonic())) >= self.max_failures

    def record_failure(self, key: str) -> None:
        self._failures.setdefault(key.lower(), []).append(time.monotonic())

    def reset(self, key: str) -> None:
        self._failures.pop(key.lower(), None)


class ApiV1:
    """The ``/api/v1`` route group.

    Constructed only when the SQLite identity DB exists (``build_http_server``
    gates it exactly like the rest of the identity layer), so v1 single-file
    setups never grow this surface. ``directory`` is injectable for tests;
    by default it is built lazily from ``config.ldap`` on first use.
    """

    def __init__(
        self,
        config: CortexConfig,
        identity: IdentityService,
        session_auth: SessionAuth,
        *,
        directory: DirectoryService | None = None,
        rate_limiter: LoginRateLimiter | None = None,
        gateway_runtime: GatewayRuntime | None = None,
    ):
        self.config = config
        self.identity = identity
        self.session_auth = session_auth
        self._directory = directory
        self._throttle = rate_limiter or LoginRateLimiter()
        self._log_requests = bool(config.server.request_log)
        self.vault_manager = identity.vault_manager or attach_vault_manager(identity, config)
        self.vault_access = VaultAccessResolver(config, self.vault_manager, identity)
        self.gateway = gateway_runtime or GatewayRuntime(config, identity)
        self.permissions = PermissionResolver(config, identity)

    # -- wiring ---------------------------------------------------------------

    def _specs(self) -> list[tuple[str, list[str], object]]:
        p = API_PREFIX
        return [
            (f"{p}/auth/login", ["POST"], self.login),
            (f"{p}/auth/logout", ["POST"], self.logout),
            (f"{p}/auth/me", ["GET"], self.me),
            (f"{p}/users", ["GET", "POST"], self.users_collection),
            (f"{p}/users/{{username}}", ["GET", "PATCH", "DELETE"], self.user_item),
            (f"{p}/groups", ["GET", "POST"], self.groups_collection),
            (f"{p}/groups/{{name}}", ["PATCH", "DELETE"], self.group_item),
            (f"{p}/groups/{{name}}/members", ["POST"], self.group_members),
            (
                f"{p}/groups/{{name}}/members/{{username}}",
                ["DELETE"],
                self.group_member_item,
            ),
            (f"{p}/tokens", ["GET", "POST"], self.tokens_collection),
            (f"{p}/tokens/{{token_id}}", ["DELETE"], self.token_item),
            (f"{p}/ldap/sync", ["POST"], self.ldap_sync),
            (f"{p}/ldap/status", ["GET", "PATCH"], self.ldap_status),
            (f"{p}/admin/tokens", ["GET"], self.admin_tokens),
            (f"{p}/vaults", ["GET"], self.vaults_collection),
            (f"{p}/vaults/{{vault}}/tree", ["GET"], self.vault_tree),
            (f"{p}/vaults/{{vault}}/search", ["GET"], self.vault_search),
            (f"{p}/vaults/{{vault}}/tags", ["GET"], self.vault_tags),
            (f"{p}/vaults/{{vault}}/links/{{path:path}}", ["GET"], self.vault_links),
            (f"{p}/vaults/{{vault}}/notes/{{path:path}}", ["GET"], self.vault_note),
            (f"{p}/vaults/{{vault}}/assets/{{path:path}}", ["GET"], self.vault_asset),
            (f"{p}/admin/vaults/{{vault}}/{{action}}", ["POST"], self.admin_vault_action),
            (f"{p}/audit/commits", ["GET"], self.commit_audit),
            (f"{p}/audit/tools", ["GET"], self.tool_audit),
            (f"{p}/mcp/tools", ["GET"], self.mcp_tools),
            (f"{p}/mcp/servers", ["GET", "POST"], self.mcp_servers),
            (f"{p}/mcp/servers/{{server_id}}", ["GET", "PATCH", "DELETE"], self.mcp_server_item),
            (f"{p}/mcp/servers/{{server_id}}/{{action}}", ["POST"], self.mcp_server_action),
            (f"{p}/admin/permissions", ["GET", "POST"], self.tool_permissions),
            (f"{p}/admin/permissions/{{permission_id}}", ["DELETE"], self.tool_permission_item),
            (f"{p}/admin/janitor", ["GET"], self.janitor_status),
        ]

    def routes(self) -> list[Route]:
        """Starlette routes (used directly by tests / any plain mount)."""
        return [
            Route(path, endpoint=self._wrap(handler), methods=methods)
            for path, methods, handler in self._specs()
        ]

    def register(self, mcp) -> None:
        """Attach the route group to a FastMCP server's Starlette app,
        alongside the MCP endpoint and the legacy admin UI."""
        for path, methods, handler in self._specs():
            mcp.custom_route(path, methods=methods)(self._wrap(handler))

    def _wrap(self, handler):
        """Per-endpoint wrapper: exception → envelope mapping + access log."""

        async def endpoint(request: Request) -> Response:
            start = time.monotonic()
            request.state.subject = "-"
            try:
                response = await handler(request)
            except ApiError as exc:
                response = exc.response()
            except AuthzError as exc:
                response = error_response(403, "forbidden", str(exc))
            except IdentityError as exc:
                response = error_response(400, "invalid_request", str(exc))
            except VaultAccessError:
                response = error_response(404, "not_found", _NOT_FOUND)
            except VaultManagerError as exc:
                response = error_response(400, "invalid_request", str(exc))
            except GatewayError as exc:
                response = error_response(400, "gateway_error", str(exc))
            except LdapError:
                # Covers LdapUnavailableError (outage) and configuration/
                # protocol failures alike: callers get one non-revealing 503
                # and the details stay in the server log. Local logins never
                # reach the directory path, so they are unaffected (§7.4).
                log.warning(
                    "directory failure on %s %s", request.method, request.url.path
                )
                response = error_response(
                    503,
                    "directory_unavailable",
                    "directory unreachable; try again later",
                )
            except Exception:
                log.exception(
                    "unhandled error on %s %s", request.method, request.url.path
                )
                response = error_response(500, "internal_error", "internal server error")
            if self._log_requests:
                access_log.info(
                    "method=%s path=%s principal=%s status=%d duration_ms=%.1f",
                    request.method,
                    request.url.path,
                    getattr(request.state, "subject", "-"),
                    response.status_code,
                    (time.monotonic() - start) * 1000,
                )
            return response

        return endpoint

    # -- authentication ---------------------------------------------------------

    def _resolve_bearer(self, token: str) -> ApiIdentity:
        """Resolve a bearer token to a *user* identity. Config-principal and
        admin-client tokens are MCP credentials, not users — they get the
        same uniform 401 as an invalid token (no source oracle)."""
        resolved = self.identity.resolve_api_token(token)
        if resolved is None:
            raise _unauthenticated()
        principal, username = resolved
        user = self.identity.users.get_by_username(username)
        if user is None or user["disabled"]:  # pragma: no cover - resolve checks
            raise _unauthenticated()
        return ApiIdentity(user=user, via="bearer", principal=principal)

    def _origin_ok(self, request: Request) -> bool:
        """Same-origin backstop for cookie-authenticated mutations. A browser
        that attaches an ``Origin`` header must match this server (its own
        Host, the configured public_url, or an entry in allowed_origins).
        No header (curl, same-origin GET-initiated fetch in older browsers)
        passes — CSRF still holds via the double-submit token."""
        origin = request.headers.get("origin")
        if not origin:
            return True
        origin = origin.rstrip("/")
        if origin == "null":
            return False
        allowed = {o.rstrip("/") for o in self.config.server.allowed_origins}
        if self.config.server.public_url:
            allowed.add(self.config.server.public_url.rstrip("/"))
        host = request.headers.get("host", "")
        if host:
            allowed.add(f"http://{host}")
            allowed.add(f"https://{host}")
        return origin in allowed

    def _require_identity(self, request: Request, *, admin: bool = False) -> ApiIdentity:
        """The auth pipeline every route (except login) runs first.

        Bearer wins when presented; otherwise the session cookie. Cookie-
        authenticated state-changing methods additionally require the
        ``X-Cortex-CSRF`` header and a passing Origin check. ``admin=True``
        gates the route on ``is_admin`` — checked before anything else the
        handler does, so non-admins can't probe resource existence."""
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            ident = self._resolve_bearer(header[7:].strip())
        else:
            user = self.session_auth.user_for_request(request)
            if user is None:
                raise _unauthenticated()
            if request.method.upper() not in SAFE_METHODS:
                if not self._origin_ok(request):
                    raise ApiError(
                        403, "origin_forbidden", "cross-origin request refused"
                    )
                if not self.session_auth.csrf_ok(request):
                    raise ApiError(
                        403,
                        "csrf_failed",
                        f"missing or invalid {CSRF_HEADER} header",
                    )
            ident = ApiIdentity(user=user, via="session")
        request.state.subject = ident.subject
        if admin and not ident.is_admin:
            raise ApiError(403, "forbidden", "this operation requires an admin")
        return ident

    # -- request parsing helpers -----------------------------------------------

    @staticmethod
    async def _json_body(request: Request) -> dict:
        try:
            body = await request.json()
        except Exception:
            raise ApiError(400, "invalid_request", "request body must be a JSON object")
        if not isinstance(body, dict):
            raise ApiError(400, "invalid_request", "request body must be a JSON object")
        return body

    @staticmethod
    def _str_field(body: dict, name: str, *, required: bool = False) -> str | None:
        value = body.get(name)
        if value is None:
            if required:
                raise ApiError(400, "invalid_request", f"'{name}' is required")
            return None
        if not isinstance(value, str) or not value.strip():
            raise ApiError(400, "invalid_request", f"'{name}' must be a non-empty string")
        return value

    @staticmethod
    def _bool_field(body: dict, name: str) -> bool | None:
        value = body.get(name)
        if value is None:
            return None
        if not isinstance(value, bool):
            raise ApiError(400, "invalid_request", f"'{name}' must be a boolean")
        return value

    @staticmethod
    def _scopes_field(body: dict, name: str = "scopes") -> list[str] | None:
        value = body.get(name)
        if value is None:
            return None
        if not isinstance(value, list) or not all(
            isinstance(s, str) and s for s in value
        ):
            raise ApiError(
                400, "invalid_request", f"'{name}' must be a list of non-empty strings"
            )
        return value

    @staticmethod
    def _query_int(
        request: Request, name: str, default: int, *, minimum: int, maximum: int
    ) -> int:
        raw = request.query_params.get(name, str(default))
        try:
            value = int(raw)
        except (TypeError, ValueError):
            raise ApiError(400, "invalid_request", f"'{name}' must be an integer")
        return max(minimum, min(value, maximum))

    @staticmethod
    def _query_time(request: Request, name: str) -> int | None:
        raw = request.query_params.get(name)
        if not raw:
            return None
        try:
            if raw.isdigit():
                return int(raw)
            return int(datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp())
        except (ValueError, OverflowError):
            raise ApiError(
                400, "invalid_request", f"'{name}' must be ISO-8601 or Unix seconds"
            )

    # -- serializers -------------------------------------------------------------
    #
    # Summaries are the only shapes that leave the API: no password material,
    # no token hashes/salts, no session tokens ever appear in a response.

    def _user_summary(self, user: dict) -> dict:
        return {
            "username": user["username"],
            "display_name": user["display_name"],
            "email": user["email"],
            "auth_source": user["auth_source"],
            "is_admin": bool(user["is_admin"]),
            "disabled": bool(user["disabled"]),
            "created_at": user["created_at"],
            "last_login_at": user["last_login_at"],
            "groups": [
                g["name"] for g in self.identity.groups.groups_for_user(user["id"])
            ],
        }

    def _group_summary(self, group: dict) -> dict:
        read_scopes = list(json.loads(group["scopes_json"])) if group["scopes_json"] else []
        raw_write = group.get("write_scopes_json")
        return {
            "name": group["name"],
            "source": group["source"],
            "scopes": read_scopes,
            "write_scopes": (
                list(json.loads(raw_write)) if raw_write is not None else read_scopes
            ),
            "members": [
                u["username"] for u in self.identity.groups.members(group["id"])
            ],
            "created_at": group["created_at"],
        }

    @staticmethod
    def _token_summary(row: dict) -> dict:
        return {
            "id": row["id"],
            "name": row["name"],
            "token_prefix": row["token_prefix"],
            "scopes": list(json.loads(row["scopes_json"])) if row["scopes_json"] else None,
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "last_used_at": row["last_used_at"],
            "revoked_at": row["revoked_at"],
        }

    # -- resource lookups with non-leaking 404s ----------------------------------

    def _get_user_or_404(self, username: str) -> dict:
        try:
            return self.identity.get_user(username)
        except IdentityError:
            raise ApiError(404, "not_found", _NOT_FOUND)

    def _get_group_or_404(self, name: str) -> dict:
        try:
            return self.identity.get_group(name)
        except IdentityError:
            raise ApiError(404, "not_found", _NOT_FOUND)

    # -- auth endpoints -----------------------------------------------------------

    def _get_directory(self) -> DirectoryService:
        if self._directory is None:
            self._directory = DirectoryService(self.identity, self.config.ldap)
        return self._directory

    async def login(self, request: Request) -> Response:
        """``POST /api/v1/auth/login`` — body ``{username, password}``.

        Routes through :meth:`DirectoryService.login` whenever LDAP is
        configured, so local and LDAP users take one code path (design §9.1/
        §9.2); local-only deployments go straight to the local verify. On
        success: sets the HttpOnly session cookie and returns the CSRF token
        plus the current-user summary. Failure is one uniform 401."""
        body = await self._json_body(request)
        username = self._str_field(body, "username", required=True)
        password = body.get("password")
        if not isinstance(password, str) or not password:
            raise ApiError(400, "invalid_request", "'password' is required")
        if self._throttle.blocked(username):
            raise ApiError(
                429, "rate_limited", "too many failed logins; try again later"
            )
        if self.config.ldap is not None:
            result = self._get_directory().login(username, password)
        else:
            result = self.identity.login(username, password)
        if result is None:
            self._throttle.record_failure(username)
            raise ApiError(401, "invalid_credentials", _BAD_LOGIN)
        self._throttle.reset(username)
        request.state.subject = f"user:{result.user['username']}"
        response = JSONResponse(
            {
                "user": self._user_summary(result.user),
                "csrf_token": result.csrf_token,
            }
        )
        self.session_auth.set_session_cookie(response, result.session_token)
        return response

    async def logout(self, request: Request) -> Response:
        """``POST /api/v1/auth/logout`` — destroys the session server-side
        and clears the cookie. Session-cookie auth only (a bearer token has
        no session to destroy); CSRF applies like any other mutation."""
        ident = self._require_identity(request)
        if ident.via != "session":
            raise ApiError(
                400, "invalid_request", "logout applies to session authentication"
            )
        response = Response(status_code=204)
        self.session_auth.logout(request, response)
        return response

    async def me(self, request: Request) -> Response:
        """``GET /api/v1/auth/me`` — the authenticated caller, or 401."""
        ident = self._require_identity(request)
        payload = {"user": self._user_summary(ident.user), "auth": ident.via}
        if ident.via == "session":
            session_token = self.session_auth.session_token(request)
            payload["csrf_token"] = self.identity.csrf_token_for(session_token)
        return JSONResponse(payload)

    # -- admin: users ---------------------------------------------------------------

    async def users_collection(self, request: Request) -> Response:
        ident = self._require_identity(request, admin=True)
        if request.method == "GET":
            return JSONResponse(
                {"users": [self._user_summary(u) for u in self.identity.list_users()]}
            )
        body = await self._json_body(request)
        username = self._str_field(body, "username", required=True)
        user = self.identity.create_user(
            username,
            password=self._str_field(body, "password"),
            display_name=self._str_field(body, "display_name"),
            email=self._str_field(body, "email"),
            is_admin=bool(self._bool_field(body, "is_admin")),
            actor=ident.user,
        )
        return JSONResponse({"user": self._user_summary(user)}, status_code=201)

    _USER_PATCH_FIELDS = {"display_name", "email", "is_admin", "disabled", "password"}

    async def user_item(self, request: Request) -> Response:
        ident = self._require_identity(request, admin=True)
        username = request.path_params["username"]
        user = self._get_user_or_404(username)
        if request.method == "GET":
            return JSONResponse({"user": self._user_summary(user)})
        if request.method == "DELETE":
            self.identity.delete_user(user["username"], actor=ident.user)
            return Response(status_code=204)
        # PATCH: enable/disable, admin flag, profile fields, password reset.
        body = await self._json_body(request)
        unknown = set(body) - self._USER_PATCH_FIELDS
        if unknown:
            raise ApiError(
                400,
                "invalid_request",
                f"unknown field(s): {', '.join(sorted(unknown))}",
            )
        profile = {}
        for field_name in ("display_name", "email"):
            if field_name in body:
                profile[field_name] = self._str_field(body, field_name)
        if profile:
            self.identity.users.update(user["id"], **profile)
        is_admin = self._bool_field(body, "is_admin")
        if is_admin is not None:
            self.identity.set_admin(user["username"], is_admin, actor=ident.user)
        disabled = self._bool_field(body, "disabled")
        if disabled is True:
            self.identity.disable_user(user["username"], actor=ident.user)
        elif disabled is False:
            self.identity.enable_user(user["username"], actor=ident.user)
        password = self._str_field(body, "password")
        if password is not None:
            try:
                self.identity.set_password(
                    user["username"], password, actor=ident.user
                )
            except ValueError as exc:  # e.g. an LDAP user carries no password
                raise ApiError(400, "invalid_request", str(exc))
        return JSONResponse({"user": self._user_summary(self.identity.get_user(username))})

    # -- admin: groups ----------------------------------------------------------------

    async def groups_collection(self, request: Request) -> Response:
        ident = self._require_identity(request, admin=True)
        if request.method == "GET":
            return JSONResponse(
                {
                    "groups": [
                        self._group_summary(g) for g in self.identity.list_groups()
                    ]
                }
            )
        body = await self._json_body(request)
        name = self._str_field(body, "name", required=True)
        group = self.identity.create_group(
            name,
            scopes=self._scopes_field(body),
            write_scopes=self._scopes_field(body, "write_scopes"),
            actor=ident.user,
        )
        return JSONResponse({"group": self._group_summary(group)}, status_code=201)

    async def group_item(self, request: Request) -> Response:
        ident = self._require_identity(request, admin=True)
        name = request.path_params["name"]
        group = self._get_group_or_404(name)
        if request.method == "DELETE":
            self.identity.delete_group(group["name"], actor=ident.user)
            return Response(status_code=204)
        # PATCH: replace scope grants.
        body = await self._json_body(request)
        scopes = self._scopes_field(body)
        if scopes is None:
            raise ApiError(400, "invalid_request", "'scopes' is required")
        group = self.identity.set_group_scopes(
            group["name"],
            scopes,
            write_scopes=self._scopes_field(body, "write_scopes"),
            actor=ident.user,
        )
        return JSONResponse({"group": self._group_summary(group)})

    async def group_members(self, request: Request) -> Response:
        ident = self._require_identity(request, admin=True)
        group = self._get_group_or_404(request.path_params["name"])
        body = await self._json_body(request)
        username = self._str_field(body, "username", required=True)
        user = self._get_user_or_404(username)
        added = self.identity.add_to_group(
            user["username"], group["name"], actor=ident.user
        )
        return JSONResponse(
            {"group": self._group_summary(self._get_group_or_404(group["name"])), "added": added}
        )

    async def group_member_item(self, request: Request) -> Response:
        ident = self._require_identity(request, admin=True)
        group = self._get_group_or_404(request.path_params["name"])
        user = self._get_user_or_404(request.path_params["username"])
        self.identity.remove_from_group(
            user["username"], group["name"], actor=ident.user
        )
        return Response(status_code=204)

    # -- self-service tokens -----------------------------------------------------------

    async def tokens_collection(self, request: Request) -> Response:
        """``GET /api/v1/tokens`` lists the caller's own tokens; ``POST``
        mints one (the raw token appears in this response and never again)."""
        ident = self._require_identity(request)
        if request.method == "GET":
            rows = self.identity.list_tokens(ident.username)
            return JSONResponse({"tokens": [self._token_summary(r) for r in rows]})
        body = await self._json_body(request)
        name = self._str_field(body, "name", required=True)
        expires_in = body.get("expires_in")
        if expires_in is not None and (
            isinstance(expires_in, bool) or not isinstance(expires_in, int)
        ):
            raise ApiError(400, "invalid_request", "'expires_in' must be an integer")
        created = self.identity.mint_token(
            ident.username,
            name,
            scopes=self._scopes_field(body),
            expires_in=expires_in,
            actor=ident.user,
        )
        return JSONResponse(
            {
                "id": created.id,
                "name": created.name,
                "token": created.token,
                "token_prefix": created.token_prefix,
            },
            status_code=201,
        )

    async def token_item(self, request: Request) -> Response:
        """``DELETE /api/v1/tokens/{id}`` — revoke. Owner or admin only; a
        foreign token gets the same 404 as a missing one (no existence
        leak)."""
        ident = self._require_identity(request)
        raw_id = request.path_params["token_id"]
        try:
            token_id = int(raw_id)
        except (TypeError, ValueError):
            raise ApiError(404, "not_found", _NOT_FOUND)
        row = self.identity.tokens.get(token_id)
        if row is None or (row["user_id"] != ident.user["id"] and not ident.is_admin):
            raise ApiError(404, "not_found", _NOT_FOUND)
        self.identity.tokens.revoke(token_id)  # idempotent
        return Response(status_code=204)

    # -- admin: LDAP sync trigger (thin A5 delegate; C2 builds the UI) -------------------

    async def ldap_sync(self, request: Request) -> Response:
        """``POST /api/v1/ldap/sync?dry_run=`` — run (or preview) an A5
        directory sync. Admin-only; 400 when no ``ldap:`` block is
        configured; 503 on directory outage."""
        self._require_identity(request, admin=True)
        if self.config.ldap is None:
            raise ApiError(400, "ldap_not_configured", "LDAP is not configured")
        dry_run = request.query_params.get("dry_run", "").lower() in (
            "1",
            "true",
            "yes",
        )
        report = self._get_directory().sync(dry_run=dry_run)
        return JSONResponse(
            {
                "dry_run": report.dry_run,
                "changed": report.changed,
                "added": report.added,
                "updated": report.updated,
                "disabled": report.disabled,
                "group_changes": report.group_changes,
                "skipped": report.skipped,
            }
        )

    async def ldap_status(self, request: Request) -> Response:
        self._require_identity(request, admin=True)
        if request.method == "PATCH":
            if self.config.ldap is None:
                raise ApiError(400, "ldap_not_configured", "LDAP is not configured")
            body = await self._json_body(request)
            unknown = set(body) - {"jit_provisioning", "group_mappings"}
            if unknown:
                raise ApiError(
                    400,
                    "invalid_request",
                    f"unknown field(s): {', '.join(sorted(unknown))}",
                )
            jit = self._bool_field(body, "jit_provisioning")
            mappings = body.get("group_mappings")
            if mappings is not None and (
                not isinstance(mappings, dict)
                or not all(
                    isinstance(key, str)
                    and bool(key.strip())
                    and isinstance(value, str)
                    and bool(value.strip())
                    for key, value in mappings.items()
                )
            ):
                raise ApiError(
                    400,
                    "invalid_request",
                    "group_mappings must map non-empty LDAP group names to Cortex groups",
                )
            policy = {
                "jit_provisioning": (
                    jit if jit is not None else self.config.ldap.jit_provisioning
                ),
                "group_mappings": (
                    {key.strip(): value.strip() for key, value in mappings.items()}
                    if mappings is not None
                    else self.config.ldap.group_mappings
                ),
            }
            self.identity.settings.set("ldap_policy", policy)
            self.config.ldap.jit_provisioning = policy["jit_provisioning"]
            self.config.ldap.group_mappings = dict(policy["group_mappings"])
        return JSONResponse(
            {
                "configured": self.config.ldap is not None,
                "jit_provisioning": bool(
                    self.config.ldap and self.config.ldap.jit_provisioning
                ),
                "server_uri": self.config.ldap.server_uri if self.config.ldap else None,
                "group_mappings": self.config.ldap.group_mappings if self.config.ldap else {},
            }
        )

    # -- B2/B3: one authorization path for every vault-facing API -------------

    def _api_principal(self, ident: ApiIdentity):
        principal = ident.principal or self.identity.principal_for_username(ident.username)
        if principal is None:
            raise _unauthenticated()
        return principal

    def _select_vault(self, ident: ApiIdentity, vault_id: str, *, write: bool = False):
        return self.vault_access.select(
            self._api_principal(ident), vault_id, write=write
        )

    async def vaults_collection(self, request: Request) -> Response:
        ident = self._require_identity(request)
        principal = self._api_principal(ident)
        items: list[dict] = []
        for grant in self.vault_access.grants(principal):
            try:
                bundle = self.vault_manager.get(grant.vault_id)
            except VaultManagerError:
                continue
            notes = filter_paths(bundle.store.list_notes(), list(grant.scopes))
            stats = bundle.index.stats()
            size = 0
            for path in notes:
                try:
                    size += bundle.store._resolve(path).stat().st_size
                except OSError:
                    pass
            items.append(
                {
                    "id": grant.vault_id,
                    "relation": grant.relation,
                    "scopes": list(grant.scopes),
                    "write_scopes": list(grant.write_scopes),
                    "note_count": len(notes),
                    "size_bytes": size,
                    "head_commit": bundle.git.head(),
                    "last_commit_iso": bundle.git.head_time(),
                    "last_indexed_iso": stats["last_indexed"],
                    "index_note_count": stats["note_count"],
                    "sync_adapter": self.vault_manager.sync_config_for(grant.vault_id).adapter,
                }
            )
        return JSONResponse({"vaults": items})

    async def vault_tree(self, request: Request) -> Response:
        ident = self._require_identity(request)
        bundle, scoped, _ = self._select_vault(ident, request.path_params["vault"])
        paths = filter_paths(bundle.store.list_notes(), scoped.scopes)
        root: dict = {"name": "", "type": "folder", "children": {}}
        for path in paths:
            node = root
            parts = path.split("/")
            for part in parts[:-1]:
                node = node["children"].setdefault(
                    part, {"name": part, "type": "folder", "children": {}}
                )
            node["children"][parts[-1]] = {
                "name": parts[-1],
                "type": "note",
                "path": path,
            }

        def freeze(node: dict) -> dict:
            if node["type"] == "note":
                return node
            children = [freeze(child) for child in node["children"].values()]
            children.sort(key=lambda item: (item["type"] != "folder", item["name"].lower()))
            return {"name": node["name"], "type": "folder", "children": children}

        return JSONResponse({"vault": bundle.vault_id, "tree": freeze(root)})

    async def vault_note(self, request: Request) -> Response:
        ident = self._require_identity(request)
        bundle, scoped, _ = self._select_vault(ident, request.path_params["vault"])
        raw_path = request.path_params["path"]
        path = canonical_note_path(raw_path)
        if path is None or not path_allowed(path, scoped.scopes):
            raise ApiError(404, "not_found", _NOT_FOUND)
        try:
            note = bundle.store.read_note(path)
            file_path = bundle.store._resolve(path)
            content = file_path.read_bytes()
        except (VaultError, OSError):
            raise ApiError(404, "not_found", _NOT_FOUND)
        etag = '"' + hashlib.sha256(content).hexdigest() + '"'
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers={"ETag": etag})
        return JSONResponse(
            {
                "vault": bundle.vault_id,
                "path": path,
                "markdown": note.body,
                "raw": note.raw,
                "frontmatter": note.frontmatter,
                "etag": etag,
                "modified_at": int(file_path.stat().st_mtime),
            },
            headers={"ETag": etag, "Cache-Control": "private, no-cache"},
        )

    async def vault_search(self, request: Request) -> Response:
        ident = self._require_identity(request)
        bundle, scoped, _ = self._select_vault(ident, request.path_params["vault"])
        query = request.query_params.get("q", "").strip()
        if not query:
            return JSONResponse({"results": []})
        limit = self._query_int(request, "limit", 50, minimum=1, maximum=200)
        bundle.index.ensure_fresh()
        hits = bundle.index.search(query, limit=max(limit * 5, 500))
        folder = request.query_params.get("folder")
        tag = request.query_params.get("tag")
        results: list[dict] = []
        for hit in hits:
            if not path_allowed(hit.path, scoped.scopes):
                continue
            if folder and not hit.path.startswith(folder.rstrip("/") + "/"):
                continue
            if tag:
                try:
                    note = bundle.store.read_note(hit.path)
                except VaultError:
                    continue
                tags = note.frontmatter.get("tags", [])
                if isinstance(tags, str):
                    tags = [tags]
                if tag.lstrip("#") not in [str(value).lstrip("#") for value in tags]:
                    continue
            results.append(
                {
                    "path": hit.path,
                    "line": hit.line,
                    "snippet": hit.snippet,
                    "score": hit.score,
                    "headings": hit.headings,
                }
            )
            if len(results) >= limit:
                break
        return JSONResponse({"results": results})

    async def vault_asset(self, request: Request) -> Response:
        ident = self._require_identity(request)
        bundle, scoped, _ = self._select_vault(ident, request.path_params["vault"])
        path = canonical_asset_path(request.path_params["path"])
        if path is None or not path_allowed(path, scoped.scopes):
            raise ApiError(404, "not_found", _NOT_FOUND)
        try:
            resolved = bundle.store._resolve(path)
            if not resolved.is_file():
                raise OSError
            data = resolved.read_bytes()
        except (VaultError, OSError):
            raise ApiError(404, "not_found", _NOT_FOUND)
        media_type = mimetypes.guess_type(path)[0] or "application/octet-stream"
        safe_inline = media_type.startswith("image/") and media_type != "image/svg+xml"
        disposition = "inline" if safe_inline else "attachment"
        return Response(
            data,
            media_type=media_type,
            headers={
                "Content-Disposition": f'{disposition}; filename="{Path(path).name}"',
                "Content-Security-Policy": "default-src 'none'; sandbox",
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "private, max-age=300",
            },
        )

    async def vault_tags(self, request: Request) -> Response:
        ident = self._require_identity(request)
        bundle, scoped, _ = self._select_vault(ident, request.path_params["vault"])
        tags: dict[str, list[str]] = {}
        inline = re.compile(r"(?<![\w/])#([A-Za-z0-9_/-]+)")
        for path in filter_paths(bundle.store.list_notes(), scoped.scopes):
            try:
                note = bundle.store.read_note(path)
            except VaultError:
                continue
            values = note.frontmatter.get("tags", [])
            if isinstance(values, str):
                values = [values]
            found = {str(value).lstrip("#") for value in values}
            found.update(inline.findall(note.body))
            for tag in found:
                if tag:
                    tags.setdefault(tag, []).append(path)
        return JSONResponse(
            {
                "tags": [
                    {"name": tag, "count": len(paths), "paths": sorted(paths)}
                    for tag, paths in sorted(tags.items())
                ]
            }
        )

    async def vault_links(self, request: Request) -> Response:
        ident = self._require_identity(request)
        bundle, scoped, _ = self._select_vault(ident, request.path_params["vault"])
        path = canonical_note_path(request.path_params["path"])
        if path is None or not path_allowed(path, scoped.scopes):
            raise ApiError(404, "not_found", _NOT_FOUND)
        visible = filter_paths(bundle.store.list_notes(), scoped.scopes)
        by_key: dict[str, str] = {}
        for candidate in visible:
            by_key[candidate.lower()] = candidate
            by_key[Path(candidate).stem.lower()] = candidate
        link_re = re.compile(r"!?(?:\[\[)([^\]|#]+)(?:#[^\]|]+)?(?:\|[^\]]+)?\]\]")
        try:
            note = bundle.store.read_note(path)
        except VaultError:
            raise ApiError(404, "not_found", _NOT_FOUND)
        outbound = []
        for raw in link_re.findall(note.body):
            target = raw.strip()
            resolved = by_key.get(target.lower()) or by_key.get((target + ".md").lower())
            outbound.append({"target": target, "path": resolved, "broken": resolved is None})
        inbound = []
        aliases = {path.lower(), Path(path).stem.lower()}
        for candidate in visible:
            if candidate == path:
                continue
            try:
                body = bundle.store.read_note(candidate).body
            except VaultError:
                continue
            if any(raw.strip().lower() in aliases for raw in link_re.findall(body)):
                inbound.append(candidate)
        return JSONResponse({"path": path, "outbound": outbound, "inbound": inbound})

    # -- B4: lifecycle and aggregated git audit -------------------------------

    async def admin_vault_action(self, request: Request) -> Response:
        self._require_identity(request, admin=True)
        vault = request.path_params["vault"]
        action = request.path_params["action"]
        if action == "provision":
            result = self.vault_manager.provision(vault)
            return JSONResponse(
                {
                    "vault": result.vault_id,
                    "created": result.created_dir,
                    "initialized_git": result.initialized_git,
                    "seeded": result.seeded,
                    "commit": result.commit,
                }
            )
        if action == "repair":
            result = self.vault_manager.repair(vault)
            return JSONResponse(
                {
                    "vault": result.vault_id,
                    "initialized_git": result.initialized_git,
                    "baseline_commit": result.baseline_commit,
                    "indexed_notes": result.indexed_notes,
                }
            )
        if action == "archive":
            path = self.vault_manager.archive(vault)
            return JSONResponse({"vault": vault, "archived": True, "archive": str(path)})
        raise ApiError(404, "not_found", _NOT_FOUND)

    async def commit_audit(self, request: Request) -> Response:
        ident = self._require_identity(request)
        principal = self._api_principal(ident)
        vault_filter = request.query_params.get("vault")
        actor_filter = (
            request.query_params.get("user")
            or request.query_params.get("actor", "")
        ).lower()
        path_filter = request.query_params.get("path")
        since = self._query_time(request, "from")
        until = self._query_time(request, "to")
        limit = self._query_int(request, "limit", 100, minimum=1, maximum=500)
        events: list[dict] = []
        for grant in self.vault_access.grants(principal):
            # The user endpoint is their private-vault history, even when a
            # group grants a slice of main. A git commit can touch several
            # paths, so exposing main's commit metadata would leak activity
            # outside that slice. Admins retain the macro timeline.
            if not ident.is_admin and grant.relation != "owner":
                continue
            if vault_filter and grant.vault_id != vault_filter:
                continue
            bundle = self.vault_manager.get(grant.vault_id)
            for commit in bundle.git.log(limit=limit, path=path_filter):
                if actor_filter and actor_filter not in commit.actor.lower() and actor_filter not in commit.subject.lower():
                    continue
                try:
                    commit_ts = int(
                        datetime.fromisoformat(
                            commit.iso_date.replace("Z", "+00:00")
                        ).timestamp()
                    )
                except ValueError:
                    commit_ts = 0
                if since is not None and commit_ts < since:
                    continue
                if until is not None and commit_ts > until:
                    continue
                events.append(
                    {
                        "vault": grant.vault_id,
                        "sha": commit.sha,
                        "actor": commit.actor,
                        "subject": commit.subject,
                        "date": commit.iso_date,
                        "diff": bundle.git.diff_summary(commit.sha),
                    }
                )
        events.sort(key=lambda item: item["date"], reverse=True)
        return JSONResponse({"commits": events[:limit]})

    # -- D1-D4: MCP registry, permissions, and call audit ---------------------

    @staticmethod
    def _server_summary(row: dict, *, include_env_refs: bool = False) -> dict:
        tools = json.loads(row.get("tools_json") or "[]")
        result = {
            "id": row["id"],
            "name": row["name"],
            "description": row.get("description"),
            "url": row.get("url"),
            "transport": row["transport"],
            "owner_user_id": row["owner_user_id"],
            "visibility": row["visibility"],
            "enabled": bool(row["enabled"]),
            "tools": tools,
            "tool_count": len(tools),
            "last_error": row.get("last_error"),
            "last_checked_at": row.get("last_checked_at"),
            "created_at": row["created_at"],
            "updated_at": row.get("updated_at"),
        }
        if include_env_refs:
            result["auth_env"] = row.get("auth_env")
            result["headers_env"] = json.loads(row.get("headers_env_json") or "{}")
        return result

    def _server_for_identity(self, ident: ApiIdentity, raw_id: str) -> dict:
        try:
            server_id = int(raw_id)
        except ValueError:
            raise ApiError(404, "not_found", _NOT_FOUND)
        row = self.identity.mcp_servers.get(server_id)
        if row is None or (
            not ident.is_admin and row["owner_user_id"] != ident.user["id"]
        ):
            raise ApiError(404, "not_found", _NOT_FOUND)
        return row

    async def mcp_servers(self, request: Request) -> Response:
        ident = self._require_identity(request)
        if request.method == "GET":
            rows = self.identity.mcp_servers.visible_to(
                ident.user["id"], is_admin=ident.is_admin
            )
            return JSONResponse(
                {
                    "servers": [
                        self._server_summary(row, include_env_refs=ident.is_admin)
                        for row in rows
                    ],
                    "allow_user_servers": self.config.gateway.allow_user_servers,
                }
            )
        if not ident.is_admin and not self.config.gateway.allow_user_servers:
            raise ApiError(403, "forbidden", "personal MCP servers are disabled")
        body = await self._json_body(request)
        name = validate_server_name(self._str_field(body, "name", required=True))
        url = validate_outbound_url(self._str_field(body, "url", required=True), self.config)
        owner = None if ident.is_admin and body.get("global", True) else ident.user["id"]
        headers_env = body.get("headers_env", {})
        if not isinstance(headers_env, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in headers_env.items()
        ):
            raise ApiError(400, "invalid_request", "headers_env must map header names to env names")
        headers_env = {
            validate_header_name(key): validate_env_name(value)
            for key, value in headers_env.items()
        }
        row = self.identity.mcp_servers.create(
            name,
            url=url,
            owner_user_id=owner,
            description=self._str_field(body, "description"),
            auth_env=validate_env_name(self._str_field(body, "auth_env")),
            headers_env=headers_env,
            visibility="group" if owner is None else "personal",
            enabled=False,
        )
        error = None
        try:
            await self.gateway.discover(row)
        except GatewayError as exc:
            error = str(exc)
        row = self.identity.mcp_servers.get(row["id"])
        return JSONResponse(
            {"server": self._server_summary(row, include_env_refs=ident.is_admin), "validation_error": error},
            status_code=201,
        )

    async def mcp_server_item(self, request: Request) -> Response:
        ident = self._require_identity(request)
        row = self._server_for_identity(ident, request.path_params["server_id"])
        if request.method == "GET":
            return JSONResponse({"server": self._server_summary(row, include_env_refs=ident.is_admin)})
        if request.method == "DELETE":
            self.gateway.unregister(row)
            self.identity.mcp_servers.delete(row["id"])
            return Response(status_code=204)
        body = await self._json_body(request)
        fields = {}
        for key in ("description", "auth_env"):
            if key in body:
                fields[key] = self._str_field(body, key)
        if "auth_env" in fields:
            fields["auth_env"] = validate_env_name(fields["auth_env"])
        if "enabled" in body:
            fields["enabled"] = bool(self._bool_field(body, "enabled"))
        if "url" in body:
            fields["url"] = validate_outbound_url(self._str_field(body, "url", required=True), self.config)
        if "headers_env" in body:
            headers = body["headers_env"]
            if not isinstance(headers, dict):
                raise ApiError(400, "invalid_request", "headers_env must be an object")
            fields["headers_env_json"] = json.dumps(
                {
                    validate_header_name(key): validate_env_name(value)
                    for key, value in headers.items()
                }
            )
        row = self.identity.mcp_servers.update(row["id"], **fields)
        self.gateway.sync_registration(row)
        return JSONResponse({"server": self._server_summary(row, include_env_refs=ident.is_admin)})

    async def mcp_server_action(self, request: Request) -> Response:
        ident = self._require_identity(request)
        row = self._server_for_identity(ident, request.path_params["server_id"])
        if request.path_params["action"] not in ("test", "refresh"):
            raise ApiError(404, "not_found", _NOT_FOUND)
        tools = await self.gateway.discover(row)
        refreshed = self.identity.mcp_servers.get(row["id"])
        return JSONResponse({"server": self._server_summary(refreshed, include_env_refs=ident.is_admin), "tools": tools})

    def _tool_catalog(self, user_id: int, *, is_admin: bool) -> list[dict]:
        """Return the real tool inventory visible to one identity."""
        builtin = [
            "discover_scopes", "status", "list_notes", "search", "read_note",
            "read_frontmatter", "read_section", "context_pack", "semantic_search",
        ]
        if self.config.writes.enabled:
            builtin += [
                "write_note", "patch_note", "append_note",
                "update_frontmatter", "delete_note", "move_note",
            ]
        items = [
            {"id": f"cortex.{name}", "server": "cortex", "name": name}
            for name in builtin
        ]
        for row in self.identity.mcp_servers.visible_to(user_id, is_admin=is_admin):
            if not row["enabled"]:
                continue
            for tool in json.loads(row.get("tools_json") or "[]"):
                items.append(
                    {
                        "id": f"{row['name']}.{tool['name']}",
                        "server": row["name"],
                        "name": tool["name"],
                        "description": tool.get("description"),
                        "inputSchema": tool.get("inputSchema"),
                    }
                )
        return items

    async def mcp_tools(self, request: Request) -> Response:
        ident = self._require_identity(request)
        principal = self._api_principal(ident)
        items = []
        for item in self._tool_catalog(ident.user["id"], is_admin=ident.is_admin):
            tool_id = item["id"]
            if self.permissions.allowed(principal, tool_id):
                items.append(item)
        return JSONResponse({"tools": items})

    async def tool_permissions(self, request: Request) -> Response:
        ident = self._require_identity(request, admin=True)
        if request.method == "GET":
            preview_user = request.query_params.get("user")
            preview = []
            if preview_user:
                user = self._get_user_or_404(preview_user)
                catalog = self._tool_catalog(
                    user["id"], is_admin=bool(user["is_admin"])
                )
                preview = [
                    self.permissions.explain(user, item["id"])
                    for item in catalog
                ]
            return JSONResponse({"permissions": self.identity.tool_permissions.list(), "preview": preview})
        body = await self._json_body(request)
        subject_type = self._str_field(body, "subject_type", required=True)
        subject_name = self._str_field(body, "subject", required=True)
        if subject_type == "user":
            subject = self._get_user_or_404(subject_name)
        elif subject_type == "group":
            subject = self._get_group_or_404(subject_name)
        else:
            raise ApiError(400, "invalid_request", "subject_type must be user or group")
        server_id = body.get("server_id")
        if server_id is not None and not isinstance(server_id, int):
            raise ApiError(400, "invalid_request", "server_id must be an integer")
        if server_id is not None and self.identity.mcp_servers.get(server_id) is None:
            raise ApiError(404, "not_found", _NOT_FOUND)
        rule = self.identity.tool_permissions.set(
            subject_type=subject_type,
            subject_id=subject["id"],
            tool_pattern=self._str_field(body, "tool_pattern", required=True),
            effect=self._str_field(body, "effect", required=True),
            server_id=server_id,
            created_by=ident.user["id"],
        )
        return JSONResponse({"permission": rule}, status_code=201)

    async def tool_permission_item(self, request: Request) -> Response:
        self._require_identity(request, admin=True)
        try:
            permission_id = int(request.path_params["permission_id"])
        except ValueError:
            raise ApiError(404, "not_found", _NOT_FOUND)
        if not self.identity.tool_permissions.delete(permission_id):
            raise ApiError(404, "not_found", _NOT_FOUND)
        return Response(status_code=204)

    async def tool_audit(self, request: Request) -> Response:
        ident = self._require_identity(request)
        user_id = None if ident.is_admin else ident.user["id"]
        if ident.is_admin and request.query_params.get("user"):
            user_id = self._get_user_or_404(request.query_params["user"])["id"]
        rows = self.identity.tool_audit.list(
            user_id=user_id,
            server=request.query_params.get("server"),
            tool=request.query_params.get("tool"),
            decision=request.query_params.get("outcome"),
            since=self._query_time(request, "from"),
            until=self._query_time(request, "to"),
            limit=self._query_int(request, "limit", 200, minimum=1, maximum=1000),
        )
        return JSONResponse({"calls": rows})

    async def admin_tokens(self, request: Request) -> Response:
        self._require_identity(request, admin=True)
        items = []
        for user in self.identity.list_users():
            for row in self.identity.tokens.list_for_user(user["id"]):
                item = self._token_summary(row)
                item["owner"] = user["username"]
                items.append(item)
        items.sort(key=lambda item: (item["created_at"], item["id"]), reverse=True)
        return JSONResponse({"tokens": items})

    async def janitor_status(self, request: Request) -> Response:
        self._require_identity(request, admin=True)
        reports = []
        with self.identity.db.connection() as conn:
            reports = [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM janitor_reports ORDER BY created_at DESC LIMIT 100"
                ).fetchall()
            ]
        return JSONResponse(
            {
                "enabled": self.config.janitor.enabled,
                "dry_run": self.config.janitor.dry_run,
                "interval_seconds": self.config.janitor.interval_seconds,
                "allowed_paths": self.config.janitor.allowed_paths,
                "forbidden_paths": self.config.janitor.forbidden_paths,
                "reports": reports,
            }
        )


def build_api(config: CortexConfig, identity: IdentityService) -> ApiV1:
    """Standard construction used by ``build_http_server``: cookie Secure
    flag follows the public base URL's scheme (the #19 rule)."""
    base = config.server.public_url or f"http://{config.server.host}:{config.server.port}"
    session_auth = SessionAuth(identity, secure_cookies=base.startswith("https://"))
    return ApiV1(config, identity, session_auth)
