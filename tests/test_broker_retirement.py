"""Source-only retirement acceptance: in-process MCP methods and ASGI, no network."""
import json
import socket
import subprocess
import time
from dataclasses import asdict
from importlib.util import find_spec

import httpx
import pytest
import yaml
from mcp.server.fastmcp.exceptions import ToolError
from starlette.testclient import TestClient

from cortex.config import ConfigError, load_config
from cortex.db import Database, MIGRATIONS, latest_version
from cortex.memory_policy import PermissionResolver, ToolGovernor, memory_tool_ids
from cortex.server import build_http_server
from cortex.users import IdentityService


@pytest.fixture
def anyio_backend():
    return "asyncio"


def deployed_config(tmp_path, enabled, **defaults):
    path = tmp_path / "cortex.yaml"
    path.write_text(yaml.safe_dump({
        "vaults": {"root": "accounts", "index_dir": "indexes"},
        "database": {"path": "identity.sqlite"},
        "admin": {"path": "admin.json"},
        "server": {"transport": "http"},
        "writes": {"enabled": True},
        "llm": {"provider": "none"},
        "gateway": {
            "enabled": enabled, "allow_user_servers": True,
            "allow_stdio_servers": True, "timeout_seconds": -1,
            "stdio_allowed_executables": ["${RETIRED_MCP_EXECUTABLE}"],
            **defaults,
        },
    }))
    return load_config(path)


def seed_historical(db, user_id):
    with db.transaction() as conn:
        server_id = conn.execute(
            "INSERT INTO mcp_servers "
            "(name, url, transport, owner_user_id, enabled, created_at, tools_json) "
            "VALUES ('retired', 'https://retired.invalid/mcp', 'streamable-http', ?, 1, 0, ?)",
            (user_id, '[{"name":"read","inputSchema":{"type":"object"}}]'),
        ).lastrowid
        conn.execute(
            "INSERT INTO tool_permissions "
            "(subject_type, subject_id, server_id, tool_pattern, effect, created_at) "
            "VALUES ('user', ?, ?, '*', 'allow', 0)", (user_id, server_id),
        )
        conn.execute(
            "INSERT INTO tool_call_audit (ts, subject, user_id, server, tool, decision) "
            "VALUES (0, 'user:alice', ?, 'retired', 'read', 'allowed')", (user_id,),
        )
    return server_id


def deny_outbound(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("retired broker attempted network or child process activity")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(httpx.AsyncClient, "send", forbidden)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)


@pytest.mark.anyio
@pytest.mark.parametrize("enabled", [True, False])
async def test_deployed_config_memory_inventory_and_old_calls_fail(tmp_path, monkeypatch, enabled):
    cfg = deployed_config(tmp_path, enabled)
    identity = IdentityService(Database(cfg.database.path), cfg)
    user = identity.create_user("alice", password="pw", is_admin=True)
    seed_historical(identity.db, user["id"])
    deny_outbound(monkeypatch)
    srv = build_http_server(cfg)
    srv.principal = srv.identity.principal_for_username("alice")
    assert not hasattr(srv, "gateway_runtime")
    assert not hasattr(srv.identity, "mcp_servers")
    assert not hasattr(srv.api, "gateway")
    assert not hasattr(srv.mcp, "lazy_catalog")
    assert find_spec("cortex.gateway") is None
    assert not srv.mcp._mcp_server.create_initialization_options().capabilities.tools.listChanged
    names = {tool.name for tool in await srv.mcp.list_tools()}
    assert {f"cortex.{name}" for name in names} == set(memory_tool_ids(cfg))
    assert names == {
        "discover_scopes", "status", "list_notes", "list_files", "get_file",
        "search", "read_note", "read_frontmatter", "read_section", "context_pack",
        "semantic_search", "put_file", "write_note", "patch_note", "append_note",
        "update_frontmatter", "set_memory_state", "supersede_note", "delete_note", "move_note",
    }
    for name in ("search_mcps", "peek_mcp", "load_mcp", "retired.read", "cortex.new_write"):
        assert srv.mcp._tool_manager.get_tool(name) is None
        with pytest.raises(ToolError, match="not available"):
            await srv.mcp.call_tool(name, {})


@pytest.mark.anyio
async def test_write_registration_gate_still_removes_all_mutations(tmp_path):
    cfg = deployed_config(tmp_path, False, default_write_allow=True)
    cfg.writes.enabled = False
    identity = IdentityService(Database(cfg.database.path), cfg)
    identity.create_user("alice", password="pw", is_admin=True)
    srv = build_http_server(cfg)
    srv.principal = srv.identity.principal_for_username("alice")
    names = {tool.name for tool in await srv.mcp.list_tools()}
    assert {f"cortex.{name}" for name in names} == set(memory_tool_ids(cfg))
    assert not {"write_note", "put_file", "set_memory_state", "supersede_note"} & names
    with pytest.raises(ToolError, match="Unknown tool"):
        await srv.mcp.call_tool("write_note", {})


@pytest.mark.anyio
@pytest.mark.parametrize("identity_backed", [True, False])
async def test_config_principal_does_not_gain_account_or_path_access(tmp_path, identity_backed):
    from cortex.config import Principal
    from cortex.server import CortexServer

    cfg = deployed_config(tmp_path, False)
    principal = Principal(name="automation", scopes=["Public/**"])
    cfg.principals = [principal]
    for account in ("automation", "other"):
        root = cfg.vaults.root / account
        (root / "Public").mkdir(parents=True)
        (root / "Public" / "visible.md").write_text("scoped memory")
        (root / "private.md").write_text("private memory")
    identity = IdentityService(Database(cfg.database.path), cfg) if identity_backed else None
    srv = CortexServer(cfg, principal, identity=identity)
    try:
        if identity_backed:
            with pytest.raises(ToolError, match="not in scope"):
                await srv.mcp.call_tool("read_note", {"path": "Public/visible.md"})
        else:
            assert "scoped memory" in str(await srv.mcp.call_tool("read_note", {"path": "Public/visible.md"}))
        for args in ({"path": "private.md"}, {"path": "Public/visible.md", "vault": "other"},
                     {"path": "Public/visible.md", "vault": "main"}):
            with pytest.raises(ToolError, match="not in scope"):
                await srv.mcp.call_tool("read_note", args)
    finally:
        srv.vault_manager.close()


@pytest.mark.parametrize("enabled", [True, False])
@pytest.mark.parametrize("authenticated", [True, False])
def test_old_api_routes_404_without_outbound_activity(tmp_path, monkeypatch, enabled, authenticated):
    cfg = deployed_config(tmp_path, enabled)
    identity = IdentityService(Database(cfg.database.path), cfg)
    user = identity.create_user("alice", password="pw", is_admin=True)
    seed_historical(identity.db, user["id"])
    token = identity.mint_token("alice", "retirement").token
    deny_outbound(monkeypatch)
    srv = build_http_server(cfg)
    with TestClient(srv.mcp.streamable_http_app()) as client:
        if authenticated:
            client.headers["Authorization"] = f"Bearer {token}"
        for method, path in (
            ("GET", "/mcp/tools"), ("GET", "/mcp/servers"), ("POST", "/mcp/servers"),
            ("GET", "/mcp/servers/1"), ("PATCH", "/mcp/servers/1"), ("DELETE", "/mcp/servers/1"),
            ("POST", "/mcp/servers/1/test"), ("POST", "/mcp/servers/1/refresh"),
        ):
            assert client.request(method, "/api/v1" + path, json={
                "name": "new", "url": "https://outbound.invalid/mcp",
            }).status_code == 404
        if authenticated:
            for extra in ({"server_id": 1}, {"tool_pattern": "retired.*"}):
                response = client.post("/api/v1/admin/permissions", json={
                    "subject_type": "user", "subject": "alice",
                    "tool_pattern": "cortex.*", "effect": "allow", **extra,
                })
                assert response.status_code == 400


@pytest.mark.anyio
@pytest.mark.parametrize("enabled", [True, False])
@pytest.mark.parametrize("read_allow,write_allow", [(True, False), (False, False), (False, True), (True, True)])
async def test_legacy_defaults_retained_without_authorization_switch(tmp_path, enabled, read_allow, write_allow):
    cfg = deployed_config(tmp_path, enabled, default_read_allow=read_allow,
                          default_write_allow=write_allow, audit_retention_days=17)
    assert asdict(cfg.memory_policy) == {
        "default_read_allow": read_allow, "default_write_allow": write_allow, "audit_retention_days": 17,
    }
    assert not hasattr(cfg, "gateway")
    identity = IdentityService(Database(cfg.database.path), cfg)
    user = identity.create_user("alice", password="pw")
    srv = build_http_server(cfg)
    srv.principal = srv.identity.principal_for_username("alice")
    names = {tool.name for tool in await srv.mcp.list_tools()}
    assert ("read_note" in names) == read_allow
    assert ("write_note" in names) == write_allow
    resolver = srv.mcp.governor.permissions
    assert resolver.allowed(srv.principal, "cortex.read_note") == read_allow
    assert resolver.allowed(srv.principal, "cortex.write_note") == write_allow
    identity.tool_permissions.set(subject_type="user", subject_id=user["id"],
                                  tool_pattern="cortex.*", effect="deny")
    assert await srv.mcp.list_tools() == []
    with pytest.raises(ToolError, match="not available"):
        await srv.mcp.call_tool("write_note", {})
    assert identity.tool_audit.list()[0]["decision"] == "denied"


def test_new_policy_wins_per_field_and_unsafe_boolean_rejected(tmp_path):
    deployed_config(tmp_path, False, default_read_allow=False, default_write_allow=True)
    path = tmp_path / "cortex.yaml"
    raw = yaml.safe_load(path.read_text())
    raw["memory_policy"] = {"default_write_allow": False}
    path.write_text(yaml.safe_dump(raw))
    cfg = load_config(path)
    assert cfg.memory_policy.default_read_allow is False
    assert cfg.memory_policy.default_write_allow is False
    raw["memory_policy"]["default_write_allow"] = "false"
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ConfigError, match="must be a boolean"):
        load_config(path)


@pytest.mark.anyio
async def test_real_memory_call_account_boundary_and_safe_audit(tmp_path):
    cfg = deployed_config(tmp_path, False)
    identity = IdentityService(Database(cfg.database.path), cfg)
    srv = build_http_server(cfg)
    for name in ("alice", "bob"):
        srv.identity.create_user(name, password="pw")
    srv.principal = srv.identity.principal_for_username("alice")
    secret = "private-note-body-not-for-audit"
    (srv.vault_manager.root_for("alice") / "owned.md").write_text(secret)
    try:
        result = await srv.mcp.call_tool("read_note", {"path": "owned.md"})
        assert secret in str(result)
        assert srv.identity.tool_audit.list()[0]["decision"] == "allowed"
        with pytest.raises(ToolError, match="not in scope"):
            await srv.mcp.call_tool("read_note", {"path": "owned.md", "vault": "bob"})
        rows = srv.identity.tool_audit.list()
        assert rows[0]["decision"] == "error"
        assert secret not in json.dumps(rows)
        assert "owned.md" not in json.dumps(rows)
        assert rows[0]["args_digest"]
        assert rows[0]["error_kind"] == "ToolError"
    finally:
        srv.vault_manager.close()


@pytest.mark.parametrize("old_version", [2, 4, latest_version()])
def test_existing_database_upgrade_preserves_identity_audit_and_history(tmp_path, monkeypatch, old_version):
    cfg = deployed_config(tmp_path, False)
    monkeypatch.setattr("cortex.db.core.MIGRATIONS", MIGRATIONS[:old_version])
    db = Database(cfg.database.path)
    identity = IdentityService(db, cfg)
    user = identity.create_user("alice", password="pw")
    token = identity.mint_token("alice", "existing").token
    seed_historical(db, user["id"])
    identity.tool_audit.record(subject="user:alice", user_id=user["id"],
                               server="cortex", tool="read_note", decision="allowed")
    tables = ("users", "api_tokens", "tool_call_audit", "mcp_servers", "tool_permissions", "schema_version")
    def snapshot(database):
        with database.connection() as conn:
            return {table: [dict(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY 1")]
                    for table in tables}
    before = snapshot(db)
    monkeypatch.setattr("cortex.db.core.MIGRATIONS", MIGRATIONS)
    upgraded = Database(cfg.database.path)
    assert upgraded.schema_version() == latest_version()
    after = snapshot(upgraded)
    for table in tables:
        for row in before[table]:
            assert any(all(new[key] == value for key, value in row.items()) for new in after[table])
    reopened = IdentityService(upgraded, cfg)
    assert reopened.resolve_api_token(token)[0].name == "alice"
    principal = reopened.principal_for_username("alice")
    ToolGovernor(cfg, reopened, lambda: principal)
    # Ancient upstream audit survives memory retention; the old server-scoped
    # wildcard allow never gives Alice new memory writes or external calls.
    assert any(row["server"] == "retired" for row in reopened.tool_audit.list())
    resolver = PermissionResolver(cfg, reopened)
    assert not resolver.allowed(principal, "cortex.write_note")
    assert not resolver.allowed(principal, "retired.read")
    assert not hasattr(reopened, "mcp_servers")


def test_memory_audit_retention_does_not_prune_upstream_history(tmp_path):
    cfg = deployed_config(tmp_path, True, audit_retention_days=17)
    identity = IdentityService(Database(cfg.database.path), cfg)
    identity.create_user("alice", password="pw")
    for server, days in (("cortex", 18), ("cortex", 16), ("retired", 100)):
        row_id = identity.tool_audit.record(subject="user:alice", server=server,
                                            tool="read", decision="allowed")
        with identity.db.transaction() as conn:
            conn.execute("UPDATE tool_call_audit SET ts = ? WHERE id = ?",
                         (int(time.time()) - days * 86400, row_id))
    ToolGovernor(cfg, identity, lambda: identity.principal_for_username("alice"))
    rows = identity.tool_audit.list()
    assert len(rows) == 2
    assert {row["server"] for row in rows} == {"cortex", "retired"}
