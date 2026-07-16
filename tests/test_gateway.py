"""D1-D3 permission, SSRF, registry-secret, and audit-boundary tests."""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.fastmcp import FastMCP
import uvicorn

from cortex.config import CortexConfig, GatewayConfig
from cortex.db import Database
from cortex.gateway import (
    GatewayError,
    GatewayRuntime,
    PermissionResolver,
    ToolGovernor,
    validate_outbound_url,
)
from cortex.users import IdentityService


@pytest.fixture
def identity(tmp_path: Path) -> IdentityService:
    service = IdentityService(Database(tmp_path / "cortex.sqlite"))
    service.create_user("admin", password="pw", is_admin=True)
    service.create_user("alice", password="pw")
    service.create_group("staff")
    service.add_to_group("alice", "staff")
    return service


def test_permission_defaults_explicit_allow_and_deny_wins(identity):
    cfg = CortexConfig()
    resolver = PermissionResolver(cfg, identity)
    principal = identity.principal_for_username("alice")
    user = identity.get_user("alice")
    group = identity.get_group("staff")

    assert resolver.allowed(principal, "cortex.search") is True
    assert resolver.allowed(principal, "cortex.write_note") is False
    assert resolver.allowed(principal, "calendar.list") is False

    identity.tool_permissions.set(
        subject_type="group",
        subject_id=group["id"],
        tool_pattern="calendar.*",
        effect="allow",
    )
    assert resolver.allowed(principal, "calendar.list") is True

    identity.tool_permissions.set(
        subject_type="user",
        subject_id=user["id"],
        tool_pattern="calendar.delete*",
        effect="deny",
    )
    assert resolver.allowed(principal, "calendar.list") is True
    assert resolver.allowed(principal, "calendar.delete_event") is False


def test_server_scoped_permission_does_not_bleed_to_another_namespace(identity):
    calendar = identity.mcp_servers.create(
        "calendar", url="https://calendar.example.com/mcp"
    )
    identity.mcp_servers.create("mail", url="https://mail.example.com/mcp")
    group = identity.get_group("staff")
    identity.tool_permissions.set(
        subject_type="group",
        subject_id=group["id"],
        server_id=calendar["id"],
        tool_pattern="*.list",
        effect="allow",
    )
    resolver = PermissionResolver(CortexConfig(), identity)
    principal = identity.principal_for_username("alice")
    assert resolver.allowed(principal, "calendar.list") is True
    assert resolver.allowed(principal, "mail.list") is False


def test_ssrf_guard_blocks_local_and_credentials(monkeypatch):
    cfg = CortexConfig()
    with pytest.raises(GatewayError):
        validate_outbound_url("file:///etc/passwd", cfg)
    with pytest.raises(GatewayError):
        validate_outbound_url("https://user:secret@example.com/mcp", cfg)
    with pytest.raises(GatewayError):
        validate_outbound_url("http://127.0.0.1:8080/mcp", cfg)

    cfg.gateway = GatewayConfig(block_private_networks=False)
    assert validate_outbound_url("http://127.0.0.1:8080/mcp", cfg).endswith("/mcp")

    cfg.gateway = GatewayConfig(outbound_allowlist=["*.example.com"])
    monkeypatch.setattr(
        "cortex.gateway.socket.getaddrinfo",
        lambda *args: [(2, 1, 6, "", ("203.0.113.10", 443))],
    )
    with pytest.raises(GatewayError):
        validate_outbound_url("https://evil.test/mcp", cfg)


def test_registry_stores_env_references_not_secret_values(identity, monkeypatch):
    row = identity.mcp_servers.create(
        "calendar",
        url="https://calendar.example.com/mcp",
        auth_env="CALENDAR_TOKEN",
        headers_env={"X-Account": "CALENDAR_ACCOUNT"},
    )
    monkeypatch.setenv("CALENDAR_TOKEN", "secret-bearer-value")
    monkeypatch.setenv("CALENDAR_ACCOUNT", "secret-account-value")
    runtime = GatewayRuntime(CortexConfig(), identity)
    assert runtime._headers(row) == {
        "Authorization": "Bearer secret-bearer-value",
        "X-Account": "secret-account-value",
    }
    encoded = json.dumps(row)
    assert "secret-bearer-value" not in encoded
    assert "secret-account-value" not in encoded
    assert row["auth_env"] == "CALENDAR_TOKEN"


def test_cached_tools_are_hot_replaced_and_removed(identity):
    row = identity.mcp_servers.create(
        "calendar", url="https://calendar.example.com/mcp"
    )
    row = identity.mcp_servers.set_inventory(
        row["id"],
        [{"name": "list", "description": "List events", "inputSchema": {"type": "object"}}],
    )
    runtime = GatewayRuntime(CortexConfig(), identity)
    mcp = FastMCP("test")
    runtime.register_cached_tools(mcp)
    assert mcp._tool_manager.get_tool("calendar.list") is not None

    row = identity.mcp_servers.set_inventory(
        row["id"],
        [{"name": "create", "description": "Create", "inputSchema": {"type": "object"}}],
    )
    runtime.sync_registration(row)
    assert mcp._tool_manager.get_tool("calendar.list") is None
    assert mcp._tool_manager.get_tool("calendar.create") is not None

    row = identity.mcp_servers.update(row["id"], enabled=False)
    runtime.sync_registration(row)
    assert mcp._tool_manager.get_tool("calendar.create") is None


@pytest.mark.asyncio
async def test_governor_rechecks_calls_and_audits_shape_without_values(identity):
    cfg = CortexConfig()
    principal = identity.principal_for_username("alice")
    governor = ToolGovernor(cfg, identity, lambda: principal)

    async def invoke(name, arguments):
        return {"ok": True}

    secret = "this-note-content-must-never-enter-the-audit-row"
    result = await governor.call(
        invoke, "search", {"query": secret, "vault": "alice"}
    )
    assert result == {"ok": True}
    allowed = identity.tool_audit.list()[0]
    assert allowed["decision"] == "allowed"
    assert allowed["vault"] == "alice"
    assert secret not in json.dumps(allowed)
    assert json.loads(allowed["args_summary"])["keys"] == ["query", "vault"]

    with pytest.raises(ToolError):
        await governor.call(invoke, "calendar.delete_event", {"token": secret})
    denied = identity.tool_audit.list()[0]
    assert denied["decision"] == "denied"
    assert denied["error_kind"] == "permission_denied"
    assert secret not in json.dumps(denied)


@pytest.mark.asyncio
async def test_upstream_http_pool_is_lazy_reused_and_rotates_secrets(
    identity, monkeypatch
):
    row = identity.mcp_servers.create(
        "calendar",
        url="https://calendar.example.com/mcp",
        auth_env="CALENDAR_TOKEN",
    )
    monkeypatch.setenv("CALENDAR_TOKEN", "first")
    runtime = GatewayRuntime(CortexConfig(), identity)

    first = await runtime._pooled_client(row)
    assert await runtime._pooled_client(row) is first
    assert first.is_closed is False

    monkeypatch.setenv("CALENDAR_TOKEN", "rotated")
    rotated = await runtime._pooled_client(row)
    assert rotated is not first
    assert first.is_closed is True
    assert rotated.headers["Authorization"] == "Bearer rotated"

    await runtime.aclose()
    assert rotated.is_closed is True


@pytest.mark.asyncio
async def test_fake_streamable_http_upstream_discovery_and_call(identity):
    upstream = FastMCP("fake-upstream")

    @upstream.tool()
    def echo(message: str) -> str:
        """Echo a test message."""
        return f"upstream:{message}"

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    server = uvicorn.Server(
        uvicorn.Config(
            upstream.streamable_http_app(),
            host="127.0.0.1",
            port=port,
            log_level="error",
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.01)
    assert server.started

    row = identity.mcp_servers.create(
        "fake", url=f"http://127.0.0.1:{port}/mcp"
    )
    config = CortexConfig()
    config.gateway.block_private_networks = False
    runtime = GatewayRuntime(config, identity)
    try:
        inventory = await runtime.discover(row)
        assert [tool["name"] for tool in inventory] == ["echo"]
        result = await runtime.call(row, "echo", {"message": "hello"})
        assert result["content"][0]["text"] == "upstream:hello"
    finally:
        await runtime.aclose()
        server.should_exit = True
        thread.join(timeout=5)
    assert not thread.is_alive()
