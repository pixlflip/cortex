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
import logging
import time
from dataclasses import dataclass

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .config import CortexConfig
from .ldap import DirectoryService, LdapUnavailableError
from .sessions import CSRF_HEADER, SAFE_METHODS, SessionAuth
from .users import AuthzError, IdentityError, IdentityService

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
    ):
        self.config = config
        self.identity = identity
        self.session_auth = session_auth
        self._directory = directory
        self._throttle = rate_limiter or LoginRateLimiter()
        self._log_requests = bool(config.server.request_log)

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
            except LdapUnavailableError:
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
        _, username = resolved
        user = self.identity.users.get_by_username(username)
        if user is None or user["disabled"]:  # pragma: no cover - resolve checks
            raise _unauthenticated()
        return ApiIdentity(user=user, via="bearer")

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
        return {
            "name": group["name"],
            "source": group["source"],
            "scopes": list(json.loads(group["scopes_json"]))
            if group["scopes_json"]
            else [],
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
        return JSONResponse(
            {"user": self._user_summary(ident.user), "auth": ident.via}
        )

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
            name, scopes=self._scopes_field(body), actor=ident.user
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
        group = self.identity.set_group_scopes(group["name"], scopes, actor=ident.user)
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


def build_api(config: CortexConfig, identity: IdentityService) -> ApiV1:
    """Standard construction used by ``build_http_server``: cookie Secure
    flag follows the public base URL's scheme (the #19 rule)."""
    base = config.server.public_url or f"http://{config.server.host}:{config.server.port}"
    session_auth = SessionAuth(identity, secure_cookies=base.startswith("https://"))
    return ApiV1(config, identity, session_auth)
