"""Shared state and helpers for every ``/api/v1`` handler group.

:class:`ApiBase` owns construction, request authentication, body/query
parsing, serializers and non-leaking lookups. The handler mixins in this
package subclass it, and :class:`cortex.api.ApiV1` combines them with route
wiring.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Literal, overload

from starlette.requests import Request

from ..config import CortexConfig
from ..access import VaultAccessResolver
from ..memory_policy import PermissionResolver
from ..recall import SemanticRetrieval
from ..ldap import DirectoryService
from ..sessions import CSRF_HEADER, SAFE_METHODS, SessionAuth
from ..users import IdentityError, IdentityService
from ..vaults import attach_vault_manager
from ._common import (
    ApiError,
    ApiIdentity,
    _NOT_FOUND,
    _unauthenticated,
    LoginRateLimiter,
)


class ApiBase:
    """Construction plus the helpers shared by all handler mixins."""

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
        self.semantic = SemanticRetrieval.from_config(config.search)

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

    @overload
    @staticmethod
    def _str_field(body: dict, name: str, *, required: Literal[True]) -> str: ...

    @overload
    @staticmethod
    def _str_field(body: dict, name: str, *, required: bool = False) -> str | None: ...

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
