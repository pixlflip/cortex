"""The service has no product UI, but keeps API, MCP and OAuth endpoints."""
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from cortex.config import (
    AdminConfig, AuthConfig, CortexConfig, DatabaseConfig, IndexConfig,
    Principal, ServerConfig, VaultConfig, VaultsConfig,
)
from cortex.db import Database
from cortex.server import build_http_server


def build(tmp_path: Path, *, identity: bool = True, oauth: bool = False):
    vault = tmp_path / "legacy"
    vault.mkdir()
    cfg = CortexConfig(
        vault=VaultConfig(path=vault),
        vaults=VaultsConfig(root=tmp_path / "accounts", index_dir=tmp_path / "indexes"),
        database=DatabaseConfig(path=tmp_path / "identity.sqlite"),
        index=IndexConfig(path=tmp_path / "index.sqlite"),
        admin=AdminConfig(enabled=True, path=tmp_path / "admin.json"),
        auth=AuthConfig(oauth_enabled=oauth),
        principals=[Principal(name="alice", scopes=["**"], token="test-token")],
        server=ServerConfig(transport="http", host="127.0.0.1", port=8765),
    )
    if identity:
        with Database(cfg.database.path).connection():
            pass
        cfg.vaults.root.mkdir(parents=True, exist_ok=True)
    return build_http_server(cfg), cfg


@pytest.mark.parametrize("identity", [True, False])
def test_ui_and_static_routes_are_absent(tmp_path: Path, identity: bool):
    srv, _ = build(tmp_path, identity=identity)
    client = TestClient(srv.mcp.streamable_http_app())
    for path in ["/", "/admin", "/login", "/vault", "/assets/index.js", "/.env", "/unknown"]:
        response = client.get(path)
        assert response.status_code == 404, (path, response.status_code)
        assert "text/html" not in response.headers.get("content-type", "")
    for path in ["/admin/login", "/admin/logout", "/admin/roles", "/admin/clients"]:
        assert client.post(path).status_code == 404


def test_health_and_authenticated_api_survive(tmp_path: Path):
    srv, cfg = build(tmp_path)
    client = TestClient(srv.mcp.streamable_http_app())
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["checks"] == {"account_storage": True, "database": True}
    assert response.headers["cache-control"] == "no-store"
    assert client.get("/api/v1/auth/me").status_code == 401
    assert srv.identity is not None
    srv.identity.create_user("bob", password="fixture-password")
    token = srv.identity.mint_token("bob", "headless-test").token
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    cfg.database.path.unlink()
    assert client.get("/healthz").status_code == 503


def test_oauth_protocol_routes_remain(tmp_path: Path):
    srv, _ = build(tmp_path, oauth=True)
    paths = {route.path for route in srv.mcp.streamable_http_app().routes}
    assert {"/mcp", "/authorize", "/token", "/register", "/cortex/authorize"} <= paths
    assert "/" not in paths
    assert "/{path:path}" not in paths
