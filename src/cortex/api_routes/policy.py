"""Memory tool permissions, retained tool audit, admin token list and janitor status."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..memory_policy import memory_tool_ids

from ._common import (
    ApiError,
    _NOT_FOUND,
)


class PolicyRoutesMixin:
    """Handler mixin for :class:`cortex.api.ApiV1`."""

    # -- Memory tool permissions and retained call audit --------------------

    def _tool_catalog(self, user_id: int, *, is_admin: bool) -> list[dict]:
        """Only classified Cortex memory tools; historical registries are inert."""
        return [
            {"id": tool_id, "server": "cortex", "name": tool_id.split(".", 1)[1]}
            for tool_id in memory_tool_ids(self.config)
        ]

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
                    self.permissions.explain(user, item["id"]) for item in catalog
                ]
            return JSONResponse(
                {
                    "permissions": self.identity.tool_permissions.list(),
                    "preview": preview,
                }
            )
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
        if server_id is not None:
            raise ApiError(400, "invalid_request", "upstream tool permissions are retired")
        tool_pattern = self._str_field(body, "tool_pattern", required=True)
        assert tool_pattern is not None
        if not (tool_pattern == "*" or tool_pattern.startswith("cortex.")):
            raise ApiError(400, "invalid_request", "only Cortex memory tool patterns are supported")
        rule = self.identity.tool_permissions.set(
            subject_type=subject_type,
            subject_id=subject["id"],
            tool_pattern=tool_pattern,
            effect=self._str_field(body, "effect", required=True),
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
                # The shipped janitor is intentionally report-only.  Do not
                # imply write mode merely because an old/future-facing config
                # sets dry_run false.
                "dry_run": True,
                "configured_dry_run": self.config.janitor.dry_run,
                "interval_seconds": self.config.janitor.interval_seconds,
                "allowed_paths": self.config.janitor.allowed_paths,
                "forbidden_paths": self.config.janitor.forbidden_paths,
                "reports": reports,
            }
        )
