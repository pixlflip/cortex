"""Memory governance regressions extracted from the retired gateway suite."""
import json
from pathlib import Path

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from cortex.config import CortexConfig, Principal
from cortex.db import Database
from cortex.memory_policy import PermissionResolver, ToolGovernor
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
        tool_pattern="cortex.*",
        effect="allow",
    )
    assert resolver.allowed(principal, "cortex.write_note") is True

    identity.tool_permissions.set(
        subject_type="user",
        subject_id=user["id"],
        tool_pattern="cortex.delete*",
        effect="deny",
    )
    assert resolver.allowed(principal, "cortex.write_note") is True
    assert resolver.allowed(principal, "cortex.delete_note") is False


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

    async def fails(name, arguments):
        raise ValueError(secret)

    with pytest.raises(ValueError):
        await governor.call(fails, "read_note", {"path": secret, secret: secret})
    error = identity.tool_audit.list()[0]
    assert error["decision"] == "error"
    assert error["error_kind"] == "ValueError"
    assert secret not in json.dumps(error)


@pytest.mark.parametrize("username", ["alice", "admin"])
@pytest.mark.parametrize("deny_subject", ["user", "group"])
def test_user_and_group_deny_win_including_admin(identity, username, deny_subject):
    identity.add_to_group(username, "staff")
    user = identity.get_user(username)
    group = identity.get_group("staff")
    for kind, subject_id in (("user", user["id"]), ("group", group["id"])):
        identity.tool_permissions.set(
            subject_type=kind, subject_id=subject_id, tool_pattern="cortex.*",
            effect="deny" if kind == deny_subject else "allow",
        )
    resolver = PermissionResolver(CortexConfig(), identity)
    assert not resolver.allowed(identity.principal_for_username(username), "cortex.search")


@pytest.mark.parametrize("username", ["alice", "admin"])
def test_disabled_principal_denied_even_if_cached_and_granted(identity, username):
    principal = identity.principal_for_username(username)
    user = identity.get_user(username)
    identity.tool_permissions.set(subject_type="user", subject_id=user["id"],
                                  tool_pattern="*", effect="allow")
    identity.users.update(user["id"], disabled=True)
    assert not PermissionResolver(CortexConfig(), identity).allowed(principal, "cortex.search")


@pytest.mark.parametrize("with_identity", [False, True])
def test_config_principal_keeps_known_memory_semantics_only(identity, with_identity):
    resolver = PermissionResolver(CortexConfig(), identity if with_identity else None)
    principal = Principal(name="automation", scopes=["Public/**"])
    assert resolver.allowed(principal, "cortex.read_note")
    assert resolver.allowed(principal, "cortex.write_note")
    for tool_id in ("calendar.list", "cortex.new_write", "cortex.search_mcps"):
        assert not resolver.allowed(principal, tool_id)


@pytest.mark.parametrize("username", ["alice", "admin"])
def test_wildcard_grant_never_enables_unknown_or_upstream_tools(identity, username):
    user = identity.get_user(username)
    identity.tool_permissions.set(subject_type="user", subject_id=user["id"],
                                  tool_pattern="*", effect="allow")
    resolver = PermissionResolver(CortexConfig(), identity)
    for tool_id in ("calendar.list", "cortex.new_write", "cortex.load_mcp"):
        assert not resolver.allowed(identity.principal_for_username(username), tool_id)


@pytest.mark.anyio
async def test_governor_is_required_and_permissions_are_rechecked(identity):
    from cortex.memory_policy import GovernedFastMCP
    mcp = GovernedFastMCP("test")

    @mcp.tool()
    def search(query: str) -> str:
        return query

    with pytest.raises(ToolError, match="unavailable"):
        await mcp.list_tools()
    with pytest.raises(ToolError, match="unavailable"):
        await mcp.call_tool("search", {"query": "test"})
    p = identity.principal_for_username("alice")
    mcp.governor = ToolGovernor(CortexConfig(), identity, lambda: p)
    assert [tool.name for tool in await mcp.list_tools()] == ["search"]
    await mcp.call_tool("search", {"query": "test"})
    identity.tool_permissions.set(subject_type="group", subject_id=identity.get_group("staff")["id"],
                                  tool_pattern="cortex.search", effect="deny")
    assert await mcp.list_tools() == []
    with pytest.raises(ToolError, match="not available"):
        await mcp.call_tool("search", {"query": "test"})
