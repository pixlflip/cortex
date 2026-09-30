"""Always-on memory tool authorization and safe audit; no upstream transports."""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from .config import CortexConfig, Principal

# Explicit classification is intentional: a newly registered tool must not
# silently inherit read access, even if it has a Cortex-looking name.
_READ_TOOLS = frozenset(f"cortex.{name}" for name in (
    "discover_scopes", "status", "list_notes", "list_files", "get_file",
    "search", "read_note", "read_frontmatter", "read_section", "context_pack",
    "semantic_search",
))
_WRITE_TOOLS = frozenset(f"cortex.{name}" for name in (
    "put_file", "write_note", "patch_note", "append_note", "update_frontmatter",
    "set_memory_state", "supersede_note", "delete_note", "move_note",
))


def memory_tool_ids(config: CortexConfig) -> list[str]:
    """The registered memory inventory, also used by permission previews."""
    return sorted(_READ_TOOLS | (_WRITE_TOOLS if config.writes.enabled else set()))


def _tool_id(name: str) -> str:
    return name if "." in name else f"cortex.{name}"


class PermissionResolver:
    """Memory-only deny-wins rules shared by listing, calls and API preview."""

    def __init__(self, config: CortexConfig, identity):
        self.config = config
        self.identity = identity

    def allowed(self, principal: Principal, tool_id: str) -> bool:
        if tool_id not in _READ_TOOLS | _WRITE_TOOLS:
            return False  # even administrators cannot resurrect upstream tools
        user = (
            self.identity.users.get_by_username(principal.name)
            if self.identity is not None else None
        )
        if user is None:
            # Retain static/legacy memory semantics. Vault ownership, scopes
            # and writes.enabled remain separate guards, never an account grant.
            return True
        if user["disabled"]:
            return False
        assert self.identity is not None
        groups = self.identity.groups.groups_for_user(user["id"])
        rules = self.identity.tool_permissions.matching(
            user["id"], [g["id"] for g in groups], tool_id
        )
        if any(rule["effect"] == "deny" for rule in rules):
            return False
        if user["is_admin"] or any(rule["effect"] == "allow" for rule in rules):
            return True
        if tool_id in _WRITE_TOOLS:
            return self.config.memory_policy.default_write_allow
        return self.config.memory_policy.default_read_allow

    def explain(self, user: dict, tool_id: str) -> dict:
        principal = self.identity.principal_for_username(user["username"])
        allowed = bool(principal and self.allowed(principal, tool_id))
        groups = self.identity.groups.groups_for_user(user["id"])
        rules = self.identity.tool_permissions.matching(
            user["id"], [g["id"] for g in groups], tool_id
        )
        return {"tool_id": tool_id, "allowed": allowed, "rules": rules}


def _audit_argument_shape(arguments: dict[str, Any]) -> tuple[str, str, str | None]:
    """Digest and bounded shape only; never bodies, credentials or error text."""
    encoded = json.dumps(arguments, sort_keys=True, default=str, separators=(",", ":"))
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    # Do not persist arbitrary client-supplied keys (which could contain data).
    known_keys = {
        "vault", "path", "query", "question", "reason", "content", "body",
        "content_base64", "offset", "length", "limit", "regex", "heading",
        "include_frontmatter", "include_historical", "include_sha256",
        "max_notes", "budget_chars", "patch", "frontmatter", "state",
        "new_path", "old_path", "superseded_by",
    }
    keys = sorted(key for key in arguments if key in known_keys)
    summary = json.dumps({"keys": keys, "bytes": len(encoded),
                          "other_keys": len(arguments) - len(keys)}, separators=(",", ":"))
    vault = arguments.get("vault")
    return digest, summary, str(vault)[:64] if isinstance(vault, str) else None


class ToolGovernor:
    def __init__(self, config: CortexConfig, identity, principal_getter):
        self.identity = identity
        self.principal_getter = principal_getter
        self.permissions = PermissionResolver(config, identity)
        if identity is not None:
            identity.tool_audit.prune(
                before=int(time.time()) - config.memory_policy.audit_retention_days * 86400
            )

    def filter_names(self, names: list[str]) -> set[str]:
        principal = self.principal_getter()
        return {name for name in names if self.permissions.allowed(principal, _tool_id(name))}

    async def call(self, invoke, name: str, arguments: dict[str, Any]):
        principal = self.principal_getter()
        tool_id = _tool_id(name)
        user = (
            self.identity.users.get_by_username(principal.name)
            if self.identity is not None else None
        )
        server, tool = tool_id.split(".", 1)
        digest, summary, vault = _audit_argument_shape(arguments)
        started = time.monotonic()

        def audit(decision: str, error_kind: str | None = None):
            if self.identity is not None:
                self.identity.tool_audit.record(
                    subject=f"user:{principal.name}" if user else principal.name,
                    user_id=user["id"] if user else None,
                    server=server, tool=tool, decision=decision, vault=vault,
                    args_digest=digest, args_summary=summary,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    error_kind=error_kind,
                )

        if not self.permissions.allowed(principal, tool_id):
            audit("denied", "permission_denied")
            raise ToolError("tool not available for this identity")
        try:
            result = await invoke(name, arguments)
        except Exception as exc:
            audit("error", type(exc).__name__[:80])
            raise
        audit("allowed")
        return result


class GovernedFastMCP(FastMCP):
    """The advertised and callable memory surfaces share an unconditional guard."""

    governor: ToolGovernor | None = None

    async def list_tools(self):
        if self.governor is None:
            raise ToolError("memory authorization is unavailable")
        tools = await super().list_tools()
        allowed = self.governor.filter_names([tool.name for tool in tools])
        return [tool for tool in tools if tool.name in allowed]

    async def call_tool(self, name: str, arguments: dict[str, Any]):
        if self.governor is None:
            raise ToolError("memory authorization is unavailable")

        async def invoke(tool_name: str, tool_args: dict[str, Any]):
            return await super(GovernedFastMCP, self).call_tool(tool_name, tool_args)

        return await self.governor.call(invoke, name, arguments)
