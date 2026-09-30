"""Headless HTTP readiness; no static files or browser application routes."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from . import __version__


def register_health(mcp, config, vault_manager) -> None:
    async def health(_: Request) -> Response:
        checks = {
            "account_storage": vault_manager.root.is_dir(),
            "database": config.database.path.exists(),
        }
        ready = all(checks.values())
        return JSONResponse(
            {"status": "ok" if ready else "degraded", "version": __version__, "checks": checks},
            status_code=200 if ready else 503,
            headers={"Cache-Control": "no-store"},
        )

    mcp.custom_route("/healthz", methods=["GET"])(health)
