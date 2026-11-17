"""JSON REST API foundation — the ``/api/v1`` surface (A6, #40).

This headless account and memory API is mounted on the same Starlette app
that serves the dedicated memory MCP. No upstream MCP registry or proxy
endpoints are exposed.

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
import time
from datetime import datetime

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from .config import CortexConfig
from .access import VaultAccessError, VaultAccessResolver
from .memory_policy import PermissionResolver
from .ldap import DirectoryService, LdapError
from .sessions import CSRF_HEADER, SAFE_METHODS, SessionAuth
from .users import AuthzError, IdentityError, IdentityService
from .vaults import VaultManagerError, attach_vault_manager
from .api_routes import IdentityRoutesMixin, PolicyRoutesMixin, VaultRoutesMixin
from .api_routes._common import (  # noqa: F401 - public API re-exports
    API_PREFIX,
    ApiError,
    ApiIdentity,
    _BAD_LOGIN,
    _NOT_FOUND,
    _UNAUTHENTICATED,
    _unauthenticated,
    access_log,
    error_response,
    log,
    LoginRateLimiter,
)


class ApiV1(IdentityRoutesMixin, VaultRoutesMixin, PolicyRoutesMixin):
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
        self.vault_manager = identity.vault_manager or attach_vault_manager(
            identity, config
        )
        self.vault_access = VaultAccessResolver(config, self.vault_manager, identity)
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
            (f"{p}/admin/vault-grants", ["GET"], self.vault_grants_collection),
            (f"{p}/admin/vault-grants/{{username}}/{{vault}}", ["PUT", "DELETE"], self.vault_grant_item),
            (f"{p}/vaults", ["GET"], self.vaults_collection),
            (f"{p}/vaults/{{vault}}/tree", ["GET"], self.vault_tree),
            (f"{p}/vaults/{{vault}}/search", ["GET"], self.vault_search),
            (f"{p}/vaults/{{vault}}/tags", ["GET"], self.vault_tags),
            (f"{p}/vaults/{{vault}}/links/{{path:path}}", ["GET"], self.vault_links),
            (f"{p}/vaults/{{vault}}/notes/{{path:path}}", ["GET"], self.vault_note),
            (f"{p}/vaults/{{vault}}/assets/{{path:path}}", ["GET"], self.vault_asset),
            (
                f"{p}/admin/vaults/{{vault}}/{{action}}",
                ["POST"],
                self.admin_vault_action,
            ),
            (f"{p}/audit/commits", ["GET"], self.commit_audit),
            (f"{p}/audit/tools", ["GET"], self.tool_audit),
            (f"{p}/admin/permissions", ["GET", "POST"], self.tool_permissions),
            (
                f"{p}/admin/permissions/{{permission_id}}",
                ["DELETE"],
                self.tool_permission_item,
            ),
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
                response = error_response(
                    500, "internal_error", "internal server error"
                )
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

    def _require_identity(
        self, request: Request, *, admin: bool = False
    ) -> ApiIdentity:
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
            raise ApiError(
                400, "invalid_request", f"'{name}' must be a non-empty string"
            )
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
        read_scopes = (
            list(json.loads(group["scopes_json"])) if group["scopes_json"] else []
        )
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
            "scopes": list(json.loads(row["scopes_json"]))
            if row["scopes_json"]
            else None,
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


def build_api(
    config: CortexConfig,
    identity: IdentityService,
) -> ApiV1:
    """Standard construction used by ``build_http_server``: cookie Secure
    flag follows the public base URL's scheme (the #19 rule).
    """
    base = (
        config.server.public_url or f"http://{config.server.host}:{config.server.port}"
    )
    session_auth = SessionAuth(identity, secure_cookies=base.startswith("https://"))
    return ApiV1(config, identity, session_auth)
