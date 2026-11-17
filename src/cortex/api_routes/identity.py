"""Identity endpoints: login/session, users, groups, tokens and LDAP."""

from __future__ import annotations

from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..ldap import DirectoryService

from ._base import ApiBase
from ._common import (
    ApiError,
    _BAD_LOGIN,
    _NOT_FOUND,
)


class IdentityRoutesMixin(ApiBase):
    """Handler mixin for :class:`cortex.api.ApiV1`."""

    # -- auth endpoints -----------------------------------------------------------

    def _get_directory(self) -> DirectoryService:
        if self._directory is None:
            if self.config.ldap is None:
                raise ApiError(400, "ldap_not_configured", "LDAP is not configured")
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
            assert session_token is not None  # a session identity implies a cookie
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
                self.identity.set_password(user["username"], password, actor=ident.user)
            except ValueError as exc:  # e.g. an LDAP user carries no password
                raise ApiError(400, "invalid_request", str(exc))
        return JSONResponse(
            {"user": self._user_summary(self.identity.get_user(username))}
        )

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
            {
                "group": self._group_summary(self._get_group_or_404(group["name"])),
                "added": added,
            }
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
            policy: dict[str, Any] = {
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
                "group_mappings": self.config.ldap.group_mappings
                if self.config.ldap
                else {},
            }
        )
