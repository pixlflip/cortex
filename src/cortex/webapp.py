"""SPA/static integration and the unauthenticated liveness endpoint."""

from __future__ import annotations

import mimetypes
import os
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from . import __version__


_CSP = (
    "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; "
    "base-uri 'self'; frame-ancestors 'none'"
)


def _dist_path() -> Path | None:
    candidates = [
        Path(os.environ["CORTEX_WEB_DIST"]) if os.environ.get("CORTEX_WEB_DIST") else None,
        Path.cwd() / "web" / "dist",
        Path(__file__).resolve().parents[2] / "web" / "dist",
        Path(__file__).resolve().parent / "web_dist",
    ]
    for candidate in candidates:
        if candidate is not None and (candidate / "index.html").is_file():
            return candidate.resolve()
    return None


def register_web_app(mcp, config, vault_manager) -> None:
    async def health(_: Request) -> Response:
        checks = {
            "main_vault": vault_manager.exists("main"),
            "database": config.database.path.exists(),
            "spa": _dist_path() is not None,
        }
        ready = checks["main_vault"] and checks["database"]
        return JSONResponse(
            {"status": "ok" if ready else "degraded", "version": __version__, "checks": checks},
            status_code=200 if ready else 503,
            headers={"Cache-Control": "no-store"},
        )

    async def spa(request: Request) -> Response:
        dist = _dist_path()
        if dist is None:
            return JSONResponse(
                {"error": {"code": "spa_not_built", "message": "web assets are not installed"}},
                status_code=503,
            )
        rel = request.path_params.get("path", "").lstrip("/")
        # API/MCP/auth paths must never fall through to HTML on a miss.
        if rel.split("/", 1)[0] in {"api", "mcp", ".well-known", "authorize", "token", "register"}:
            return Response(status_code=404)
        target = (dist / rel).resolve() if rel else dist / "index.html"
        try:
            target.relative_to(dist)
        except ValueError:
            return Response(status_code=404)
        if not target.is_file():
            target = dist / "index.html"
        data = target.read_bytes()
        media_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        cache = "public, max-age=31536000, immutable" if target.parent.name == "assets" else "no-cache"
        return Response(
            data,
            media_type=media_type,
            headers={
                "Content-Security-Policy": _CSP,
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "same-origin",
                "Cache-Control": cache,
            },
        )

    mcp.custom_route("/healthz", methods=["GET"])(health)
    mcp.custom_route("/", methods=["GET"])(spa)
    mcp.custom_route("/{path:path}", methods=["GET"])(spa)
