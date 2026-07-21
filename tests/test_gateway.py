"""D1-D3 permission, SSRF, registry-secret, and audit-boundary tests."""

from __future__ import annotations

import json
import os
import socket
import sys
import sysconfig
import threading
import time
import venv
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from mcp import ClientSession, types as mcp_types
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.lowlevel.server import request_ctx
import uvicorn

from cortex.config import CortexConfig, GatewayConfig, Principal
from cortex.db import Database
from cortex.gateway import (
    GatewayError,
    GatewayRuntime,
    GovernedFastMCP,
    LazyMcpCatalog,
    PermissionResolver,
    ToolGovernor,
    validate_outbound_url,
)
from cortex.users import IdentityService


class _ClientKey:
    pass


@pytest.fixture
def stdio_executable(tmp_path: Path) -> Path:
    """Make the MCP fixture use the interpreter that installed the test deps."""
    source = Path(__file__).parent / "fixtures" / "stdio_mcp_server.py"
    executable = tmp_path / "stdio-mcp-fixture"
    lines = source.read_text().splitlines(keepends=True)
    executable.write_text(f"#!{sys.executable}\n" + "".join(lines[1:]))
    executable.chmod(0o755)
    return executable


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


def test_personal_server_is_callable_only_by_its_owner(identity):
    alice = identity.get_user("alice")
    identity.create_user("bob", password="pw", is_admin=True)
    identity.mcp_servers.create(
        "personal",
        url="https://personal.example.com/mcp",
        owner_user_id=alice["id"],
        visibility="personal",
    )
    resolver = PermissionResolver(CortexConfig(), identity)

    assert (
        resolver.allowed(identity.principal_for_username("alice"), "personal.list")
        is True
    )
    # Even an administrator cannot invoke another user's personal upstream.
    assert (
        resolver.allowed(identity.principal_for_username("bob"), "personal.list")
        is False
    )
    # Static/config principals retain broad v1 access only to Cortex and
    # globally registered upstreams, never to a user's personal credentials.
    assert resolver.allowed(Principal(name="automation"), "personal.list") is False
    identity.tool_permissions.set(
        subject_type="user",
        subject_id=alice["id"],
        tool_pattern="personal.*",
        effect="deny",
    )
    assert (
        resolver.allowed(identity.principal_for_username("alice"), "personal.list")
        is False
    )


def test_explicit_deny_applies_to_admin(identity):
    admin = identity.get_user("admin")
    identity.tool_permissions.set(
        subject_type="user",
        subject_id=admin["id"],
        tool_pattern="cortex.search",
        effect="deny",
    )
    resolver = PermissionResolver(CortexConfig(), identity)

    assert (
        resolver.allowed(identity.principal_for_username("admin"), "cortex.search")
        is False
    )


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
        [
            {
                "name": "list",
                "description": "List events",
                "inputSchema": {"type": "object"},
            }
        ],
    )
    runtime = GatewayRuntime(CortexConfig(), identity)
    mcp = FastMCP("test")
    runtime.register_cached_tools(mcp)
    assert mcp._tool_manager.get_tool("calendar.list") is not None

    row = identity.mcp_servers.set_inventory(
        row["id"],
        [
            {
                "name": "create",
                "description": "Create",
                "inputSchema": {"type": "object"},
            }
        ],
    )
    runtime.sync_registration(row)
    assert mcp._tool_manager.get_tool("calendar.list") is None
    assert mcp._tool_manager.get_tool("calendar.create") is not None

    row = identity.mcp_servers.update(row["id"], enabled=False)
    runtime.sync_registration(row)
    assert mcp._tool_manager.get_tool("calendar.create") is None


def test_lazy_catalog_search_peek_and_policy_filtering(identity):
    calendar = identity.mcp_servers.create(
        "calendar",
        url="https://calendar.example.com/mcp",
        description="Team calendar",
    )
    identity.mcp_servers.set_inventory(
        calendar["id"],
        [
            {"name": "list", "inputSchema": {"type": "object"}},
            {"name": "delete", "inputSchema": {"type": "object"}},
        ],
    )
    mail = identity.mcp_servers.create(
        "mail", url="https://mail.example.com/mcp", description="Private mail"
    )
    identity.mcp_servers.set_inventory(
        mail["id"], [{"name": "send", "inputSchema": {"type": "object"}}]
    )
    group = identity.get_group("staff")
    identity.tool_permissions.set(
        subject_type="group",
        subject_id=group["id"],
        server_id=calendar["id"],
        tool_pattern="calendar.*",
        effect="allow",
    )
    user = identity.get_user("alice")
    identity.tool_permissions.set(
        subject_type="user",
        subject_id=user["id"],
        server_id=calendar["id"],
        tool_pattern="calendar.delete",
        effect="deny",
    )
    principal = identity.principal_for_username("alice")
    client_key = _ClientKey()
    catalog = LazyMcpCatalog(
        CortexConfig(), identity, lambda: principal, lambda: client_key
    )

    assert catalog.search() == [
        {
            "name": "calendar",
            "description": "Team calendar",
            "tool_count": 1,
        }
    ]
    assert catalog.search("team") == catalog.search()
    assert catalog.search("mail") == []
    assert catalog.peek("calendar") == ["calendar.list"]
    with pytest.raises(ToolError, match="not available"):
        catalog.peek("mail")


@pytest.mark.anyio
async def test_lazy_catalog_hides_calls_until_loaded_and_load_tool_notifies(identity):
    row = identity.mcp_servers.create(
        "calendar", url="https://calendar.example.com/mcp"
    )
    identity.mcp_servers.set_inventory(
        row["id"], [{"name": "list", "inputSchema": {"type": "object"}}]
    )
    group = identity.get_group("staff")
    identity.tool_permissions.set(
        subject_type="group",
        subject_id=group["id"],
        server_id=row["id"],
        tool_pattern="calendar.*",
        effect="allow",
    )
    principal = identity.principal_for_username("alice")
    client_key = _ClientKey()
    catalog = LazyMcpCatalog(
        CortexConfig(), identity, lambda: principal, lambda: client_key
    )
    mcp = GovernedFastMCP("test")
    mcp.governor = ToolGovernor(CortexConfig(), identity, lambda: principal)
    mcp.lazy_catalog = catalog

    @mcp.tool(name="calendar.list")
    def calendar_list() -> str:
        return "events"

    runtime = GatewayRuntime(CortexConfig(), identity)
    runtime.register_discovery_tools(mcp, catalog)

    initial = {tool.name for tool in await mcp.list_tools()}
    assert initial == {"search_mcps", "peek_mcp", "load_mcp"}
    assert "calendar.list" not in initial
    with pytest.raises(ToolError, match="not loaded"):
        await mcp.call_tool("calendar.list", {})

    notification = AsyncMock()
    ctx = Context(
        request_context=SimpleNamespace(
            session=SimpleNamespace(send_tool_list_changed=notification)
        ),
        fastmcp=mcp,
    )
    loaded = await mcp._tool_manager.call_tool(
        "load_mcp", {"name": "calendar"}, context=ctx
    )
    assert loaded == {"name": "calendar", "tool_count": 1, "loaded": True}
    notification.assert_awaited_once_with()
    assert "calendar.list" in {tool.name for tool in await mcp.list_tools()}
    result = await mcp.call_tool("calendar.list", {})
    assert result[0][0].text == "events"

    # Loading never becomes an authorization grant. A later deny removes the
    # stale schema and blocks a client that retained it.
    user = identity.get_user("alice")
    identity.tool_permissions.set(
        subject_type="user",
        subject_id=user["id"],
        server_id=row["id"],
        tool_pattern="calendar.list",
        effect="deny",
    )
    assert "calendar.list" not in {tool.name for tool in await mcp.list_tools()}
    with pytest.raises(ToolError, match="not available"):
        await mcp.call_tool("calendar.list", {})


def test_lazy_catalog_loadouts_are_isolated_by_client_key(identity):
    row = identity.mcp_servers.create(
        "calendar", url="https://calendar.example.com/mcp"
    )
    identity.mcp_servers.set_inventory(
        row["id"], [{"name": "list", "inputSchema": {"type": "object"}}]
    )
    group = identity.get_group("staff")
    identity.tool_permissions.set(
        subject_type="group",
        subject_id=group["id"],
        server_id=row["id"],
        tool_pattern="calendar.*",
        effect="allow",
    )
    principal = identity.principal_for_username("alice")
    first = _ClientKey()
    second = _ClientKey()
    client = {"key": first}
    catalog = LazyMcpCatalog(
        CortexConfig(), identity, lambda: principal, lambda: client["key"]
    )

    catalog.load("calendar")
    assert catalog.is_loaded("calendar") is True
    client["key"] = second
    assert catalog.is_loaded("calendar") is False


@pytest.mark.anyio
async def test_streamable_http_load_refresh_is_standard_and_session_scoped(identity):
    row = identity.mcp_servers.create(
        "calendar", url="https://calendar.example.com/mcp"
    )
    identity.mcp_servers.set_inventory(
        row["id"],
        [
            {
                "name": "list",
                "description": "List events",
                "inputSchema": {
                    "type": "object",
                    "properties": {"limit": {"type": "integer"}},
                },
            }
        ],
    )
    group = identity.get_group("staff")
    identity.tool_permissions.set(
        subject_type="group",
        subject_id=group["id"],
        server_id=row["id"],
        tool_pattern="calendar.*",
        effect="allow",
    )
    principal = identity.principal_for_username("alice")
    catalog = LazyMcpCatalog(
        CortexConfig(),
        identity,
        lambda: principal,
        lambda: request_ctx.get().session,
    )
    mcp = GovernedFastMCP("lazy-test", stateless_http=False)
    mcp.governor = ToolGovernor(CortexConfig(), identity, lambda: principal)
    mcp.lazy_catalog = catalog

    @mcp.tool(name="calendar.list")
    def calendar_list(limit: int | None = None) -> dict:
        return {"limit": limit}

    runtime = GatewayRuntime(CortexConfig(), identity)
    runtime.register_discovery_tools(mcp, catalog)

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    server = uvicorn.Server(
        uvicorn.Config(
            mcp.streamable_http_app(),
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

    async def names(session: ClientSession) -> dict[str, mcp_types.Tool]:
        result = await session.list_tools()
        return {tool.name: tool for tool in result.tools}

    notifications: list[object] = []

    async def capture(message) -> None:
        notifications.append(message)

    try:
        async with streamable_http_client(f"http://127.0.0.1:{port}/mcp") as streams:
            async with ClientSession(
                streams[0], streams[1], message_handler=capture
            ) as session:
                initialized = await session.initialize()
                assert initialized.capabilities.tools is not None
                assert initialized.capabilities.tools.listChanged is True
                initial = await names(session)
                assert "calendar.list" not in initial
                assert {"search_mcps", "peek_mcp", "load_mcp"} <= initial.keys()

                loaded = await session.call_tool("load_mcp", {"name": "calendar"})
                assert loaded.isError is False
                assert any(
                    isinstance(message, mcp_types.ServerNotification)
                    and isinstance(
                        message.root, mcp_types.ToolListChangedNotification
                    )
                    for message in notifications
                )
                refreshed = await names(session)
                limit_schema = refreshed["calendar.list"].inputSchema["properties"][
                    "limit"
                ]
                assert {option.get("type") for option in limit_schema["anyOf"]} == {
                    "integer",
                    "null",
                }
                called = await session.call_tool("calendar.list", {"limit": 3})
                assert called.isError is False

        # A separate MCP transport session starts from the compact baseline.
        async with streamable_http_client(f"http://127.0.0.1:{port}/mcp") as streams:
            async with ClientSession(streams[0], streams[1]) as second:
                await second.initialize()
                assert "calendar.list" not in await names(second)
    finally:
        server.should_exit = True
        thread.join(timeout=5)
    assert not thread.is_alive()


@pytest.mark.anyio
async def test_governor_rechecks_calls_and_audits_shape_without_values(identity):
    cfg = CortexConfig()
    principal = identity.principal_for_username("alice")
    governor = ToolGovernor(cfg, identity, lambda: principal)

    async def invoke(name, arguments):
        return {"ok": True}

    secret = "this-note-content-must-never-enter-the-audit-row"
    result = await governor.call(invoke, "search", {"query": secret, "vault": "alice"})
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


@pytest.mark.anyio
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


@pytest.mark.anyio
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

    row = identity.mcp_servers.create("fake", url=f"http://127.0.0.1:{port}/mcp")
    config = CortexConfig()
    config.gateway.block_private_networks = False
    runtime = GatewayRuntime(config, identity)
    try:
        inventory = await runtime.discover(row)
        assert [tool["name"] for tool in inventory] == ["echo"]
        group = identity.get_group("staff")
        identity.tool_permissions.set(
            subject_type="group",
            subject_id=group["id"],
            server_id=row["id"],
            tool_pattern="fake.echo",
            effect="allow",
        )
        alice = identity.principal_for_username("alice")
        governor = ToolGovernor(config, identity, lambda: alice)

        async def proxy(_name, arguments):
            return await runtime.call(row, "echo", arguments)

        result = await governor.call(proxy, "fake.echo", {"message": "hello"})
        assert result["content"][0]["text"] == "upstream:hello"
        audit = identity.tool_audit.list()[0]
        assert audit["decision"] == "allowed"
        assert audit["server"] == "fake"
        assert "hello" not in json.dumps(audit)

        identity.create_user("bob", password="pw")
        denied = ToolGovernor(
            config, identity, lambda: identity.principal_for_username("bob")
        )
        with pytest.raises(ToolError):
            await denied.call(proxy, "fake.echo", {"message": "not-forwarded"})
        assert identity.tool_audit.list()[0]["decision"] == "denied"
    finally:
        await runtime.aclose()
        server.should_exit = True
        thread.join(timeout=5)
    assert not thread.is_alive()


@pytest.mark.anyio
async def test_persistent_stdio_discovery_call_environment_and_close(
    tmp_path, monkeypatch, stdio_executable
):
    fixture = stdio_executable
    marker = tmp_path / "starts"
    monkeypatch.setenv("STDIO_MARKER_PARENT", str(marker))
    monkeypatch.setenv("UNRELATED_CORTEX_SECRET", "must-not-reach-child")
    config = CortexConfig()
    config.gateway = GatewayConfig(
        allow_stdio_servers=True,
        stdio_allowed_executables=[str(fixture)],
        stdio_allowed_workdirs=[str(tmp_path)],
        timeout_seconds=5,
    )
    identity = IdentityService(Database(tmp_path / "stdio.sqlite"))
    row = identity.mcp_servers.create(
        "fixture",
        transport="stdio-cmd",
        command=str(fixture),
        args=["space value", "; touch nope", "|", "$(false)", "`false`", ">nope"],
        cwd=str(tmp_path),
        env_refs={"FIXTURE_MARKER": "STDIO_MARKER_PARENT"},
        enabled=False,
    )
    runtime = GatewayRuntime(config, identity)
    tools = await runtime.discover(row)
    assert {tool["name"] for tool in tools} >= {"echo", "add", "fail", "sleep"}
    refreshed = identity.mcp_servers.get(row["id"])
    assert (await runtime.call(refreshed, "add", {"a": 2, "b": 3}))["content"][0][
        "text"
    ] == "5"
    hidden = await runtime.call(
        refreshed, "environment", {"name": "UNRELATED_CORTEX_SECRET"}
    )
    assert hidden["content"][0]["text"] == "<unset>"
    literal = await runtime.call(refreshed, "startup_args", {})
    assert [item["text"] for item in literal["content"]] == [
        "space value",
        "; touch nope",
        "|",
        "$(false)",
        "`false`",
        ">nope",
    ]
    assert not (tmp_path / "nope").exists()
    assert marker.read_text().count("start:") == 1
    await runtime.aclose()
    assert marker.read_text().count("stop:") == 1


@pytest.mark.anyio
async def test_stdio_executes_allowlisted_venv_launcher_without_resolving_it(
    tmp_path, monkeypatch
):
    environment = tmp_path / "dedicated"
    venv.EnvBuilder(with_pip=False, system_site_packages=True).create(environment)
    python = environment / "bin" / "python"
    child_purelib = (
        environment
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    (child_purelib / "parent-venv.pth").write_text(
        f"{sysconfig.get_path('purelib')}\n"
    )
    fixture = Path(__file__).parent / "fixtures" / "stdio_mcp_server.py"
    marker = tmp_path / "venv-markers"
    monkeypatch.setenv("STDIO_MARKER_PARENT", str(marker))
    config = CortexConfig()
    config.gateway = GatewayConfig(
        allow_stdio_servers=True,
        stdio_allowed_executables=[str(python)],
        stdio_allowed_workdirs=[str(tmp_path)],
        timeout_seconds=5,
    )
    identity = IdentityService(Database(tmp_path / "venv.sqlite"))
    row = identity.mcp_servers.create(
        "venvfixture",
        transport="stdio-cmd",
        command=str(python),
        args=[str(fixture)],
        cwd=str(tmp_path),
        env_refs={"FIXTURE_MARKER": "STDIO_MARKER_PARENT"},
        enabled=False,
    )
    runtime = GatewayRuntime(config, identity)
    try:
        await runtime.discover(row)
        refreshed = identity.mcp_servers.get(row["id"])
        result = await runtime.call(refreshed, "python_prefix", {})
        assert result["content"][0]["text"] == str(environment)
    finally:
        await runtime.aclose()
    pid = int(marker.read_text().split("start:", 1)[1].splitlines()[0])
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_stdio_repository_transport_invariants(tmp_path):
    identity = IdentityService(Database(tmp_path / "repo.sqlite"))
    with pytest.raises(ValueError, match="requires command"):
        identity.mcp_servers.create("bad", transport="stdio-cmd")
    with pytest.raises(ValueError, match="rejects stdio"):
        identity.mcp_servers.create("badhttp", url="https://example.com/mcp", args=[])
    http = identity.mcp_servers.create("httpok", url="https://example.com/mcp")
    assert http["url"] == "https://example.com/mcp"
