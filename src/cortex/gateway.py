"""Governed MCP registry, permission resolver, proxy runtime, and audit.

External credentials are environment references in SQLite, never values.  A
caller sees one namespaced tool surface (``cortex.*`` and ``server.tool``);
the same permission decision filters discovery and is re-evaluated for every
call.  Every allowed, denied, and failed invocation is recorded centrally.
"""

from __future__ import annotations

import hashlib
import inspect
import ipaddress
import json
import os
import re
import socket
import time
from dataclasses import dataclass
from datetime import timedelta
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import urlparse

import anyio
import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from .config import CortexConfig, Principal


_SERVER_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,47}$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_WRITE_TOOLS = {
    "cortex.write_note",
    "cortex.patch_note",
    "cortex.append_note",
    "cortex.update_frontmatter",
    "cortex.delete_note",
    "cortex.move_note",
}


class GatewayError(Exception):
    pass


def validate_server_name(name: str) -> str:
    value = (name or "").strip()
    if not _SERVER_NAME.fullmatch(value) or value.lower() == "cortex":
        raise GatewayError(
            "server name must start with a letter, use only letters/numbers/_/-, "
            "and may not be 'cortex'"
        )
    return value


def validate_env_name(name: str | None) -> str | None:
    if name is None:
        return None
    value = name.strip()
    if not _ENV_NAME.fullmatch(value):
        raise GatewayError("credential references must be environment-variable names")
    return value


def validate_header_name(name: str) -> str:
    value = name.strip()
    if not _HEADER_NAME.fullmatch(value):
        raise GatewayError("invalid upstream HTTP header name")
    return value


def _safe_upstream_text(value: str, limit: int = 4000) -> str:
    """Length-cap and strip control characters from untrusted metadata."""
    return "".join(ch for ch in value if ch in "\n\t" or ord(ch) >= 32)[:limit]


def validate_outbound_url(url: str, config: CortexConfig) -> str:
    """Reject credentials-in-URL, non-HTTP schemes, and SSRF destinations."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise GatewayError("upstream URL must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise GatewayError("upstream credentials must use env references, not the URL")
    host = parsed.hostname.rstrip(".").lower()
    allowlist = config.gateway.outbound_allowlist
    if allowlist and not any(fnmatchcase(host, pattern.lower()) for pattern in allowlist):
        raise GatewayError("upstream host is not in gateway.outbound_allowlist")
    if config.gateway.block_private_networks:
        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
        except OSError as exc:
            raise GatewayError("upstream host could not be resolved") from exc
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                raise GatewayError("upstream resolves to a blocked private/link-local address")
    return url


def _tool_id(name: str) -> str:
    return name if "." in name else f"cortex.{name}"


class PermissionResolver:
    """Deny-wins resolver shared by discovery, invocation, and UI preview."""

    def __init__(self, config: CortexConfig, identity):
        self.config = config
        self.identity = identity

    def allowed(self, principal: Principal, tool_id: str) -> bool:
        server = self._server(tool_id)
        user = self.identity.users.get_by_username(principal.name)
        # Personal registrations are an ownership boundary for *every*
        # identity kind.  In particular, config/legacy principals must not
        # inherit their v1 allow-all behaviour for somebody's upstream.
        if server is not None and server["owner_user_id"] is not None:
            if user is None or server["owner_user_id"] != user["id"]:
                return False
            personal_owner = True
        else:
            personal_owner = False
        if user is None:
            return True  # static/config and legacy identities keep v1 behavior
        if user["disabled"]:
            return False
        # Personal upstreams are an ownership boundary, not merely another
        # permission default.  They must never become callable by an admin or
        # another user just because that identity otherwise has broad tool
        # access.  The owner still passes through the ordinary deny-wins rule
        # evaluation below; ownership is an implicit fallback allow, not a way
        # to bypass an explicit user/group denial.
        groups = self.identity.groups.groups_for_user(user["id"])
        server_id = self._server_id(tool_id)
        rules = self.identity.tool_permissions.matching(
            user["id"], [g["id"] for g in groups], tool_id, server_id=server_id
        )
        # Deny wins across user and group rules.  This deliberately prevents a
        # user override from escaping a group-level security boundary.
        if any(rule["effect"] == "deny" for rule in rules):
            return False
        # Administrators have an implicit allow, but an explicit deny remains
        # authoritative just as it is for every other identity.
        if user["is_admin"]:
            return True
        if any(rule["effect"] == "allow" for rule in rules):
            return True
        if tool_id.startswith("cortex."):
            if tool_id in _WRITE_TOOLS:
                return self.config.gateway.default_write_allow
            return self.config.gateway.default_read_allow
        return personal_owner

    def explain(self, user: dict, tool_id: str) -> dict:
        principal = self.identity.principal_for_username(user["username"])
        allowed = bool(principal and self.allowed(principal, tool_id))
        groups = self.identity.groups.groups_for_user(user["id"])
        rules = self.identity.tool_permissions.matching(
            user["id"],
            [g["id"] for g in groups],
            tool_id,
            server_id=self._server_id(tool_id),
        )
        return {"tool_id": tool_id, "allowed": allowed, "rules": rules}

    def _server_id(self, tool_id: str) -> int | None:
        server = self._server(tool_id)
        return server["id"] if server is not None else None

    def _server(self, tool_id: str) -> dict | None:
        server_name = tool_id.split(".", 1)[0]
        if server_name == "cortex":
            return None
        return self.identity.mcp_servers.get_by_name(server_name)


def _audit_argument_shape(arguments: dict[str, Any]) -> tuple[str, str, str | None]:
    """Return digest + safe shape + optional vault, never argument values."""
    encoded = json.dumps(arguments, sort_keys=True, default=str, separators=(",", ":"))
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    keys = sorted(str(key)[:64] for key in arguments)[:32]
    summary = json.dumps({"keys": keys, "bytes": len(encoded)}, separators=(",", ":"))
    vault = arguments.get("vault")
    return digest, summary, str(vault)[:64] if isinstance(vault, str) else None


class ToolGovernor:
    def __init__(self, config: CortexConfig, identity, principal_getter):
        self.config = config
        self.identity = identity
        self.principal_getter = principal_getter
        self.permissions = PermissionResolver(config, identity)
        identity.tool_audit.prune(
            before=int(time.time()) - config.gateway.audit_retention_days * 86400
        )

    def principal(self) -> Principal:
        return self.principal_getter()

    def filter_names(self, names: list[str]) -> set[str]:
        principal = self.principal()
        return {name for name in names if self.permissions.allowed(principal, _tool_id(name))}

    async def call(self, invoke, name: str, arguments: dict[str, Any]):
        principal = self.principal()
        tool_id = _tool_id(name)
        user = self.identity.users.get_by_username(principal.name)
        user_id = user["id"] if user is not None else None
        server, tool = tool_id.split(".", 1)
        digest, summary, vault = _audit_argument_shape(arguments)
        started = time.monotonic()
        if not self.permissions.allowed(principal, tool_id):
            self.identity.tool_audit.record(
                subject=(f"user:{principal.name}" if user else principal.name),
                user_id=user_id,
                server=server,
                tool=tool,
                decision="denied",
                vault=vault,
                args_digest=digest,
                args_summary=summary,
                duration_ms=0,
                error_kind="permission_denied",
            )
            raise ToolError("tool not available for this identity")
        try:
            result = await invoke(name, arguments)
        except Exception as exc:
            self.identity.tool_audit.record(
                subject=(f"user:{principal.name}" if user else principal.name),
                user_id=user_id,
                server=server,
                tool=tool,
                decision="error",
                vault=vault,
                args_digest=digest,
                args_summary=summary,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_kind=type(exc).__name__[:80],
            )
            raise
        self.identity.tool_audit.record(
            subject=(f"user:{principal.name}" if user else principal.name),
            user_id=user_id,
            server=server,
            tool=tool,
            decision="allowed",
            vault=vault,
            args_digest=digest,
            args_summary=summary,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return result


class GovernedFastMCP(FastMCP):
    """FastMCP variant whose advertised and callable surfaces share a guard."""

    governor: ToolGovernor | None = None

    async def list_tools(self):
        tools = await super().list_tools()
        if self.governor is None:
            return tools
        allowed = self.governor.filter_names([tool.name for tool in tools])
        return [tool for tool in tools if tool.name in allowed]

    async def call_tool(self, name: str, arguments: dict[str, Any]):
        if self.governor is None:
            return await super().call_tool(name, arguments)

        async def invoke(tool_name: str, tool_args: dict[str, Any]):
            return await super(GovernedFastMCP, self).call_tool(tool_name, tool_args)

        return await self.governor.call(invoke, name, arguments)


@dataclass
class CircuitState:
    failures: int = 0
    opened_at: float | None = None


@dataclass
class ClientPoolEntry:
    fingerprint: str
    client: httpx.AsyncClient


class GatewayRuntime:
    """Connection validation and bounded proxying for streamable HTTP MCP."""

    def __init__(self, config: CortexConfig, identity):
        self.config = config
        self.identity = identity
        self._limit = anyio.Semaphore(config.gateway.max_concurrency)
        self._circuits: dict[int, CircuitState] = {}
        self._clients: dict[int, ClientPoolEntry] = {}
        self._client_lock = anyio.Lock()
        self._mcp: FastMCP | None = None

    def _headers(self, row: dict) -> dict[str, str]:
        headers: dict[str, str] = {}
        if row.get("auth_env"):
            secret = os.environ.get(row["auth_env"])
            if not secret:
                raise GatewayError(f"required auth env {row['auth_env']!r} is unset")
            headers["Authorization"] = f"Bearer {secret}"
        for header, env_name in json.loads(row.get("headers_env_json") or "{}").items():
            value = os.environ.get(env_name)
            if not value:
                raise GatewayError(f"required header env {env_name!r} is unset")
            headers[str(header)] = value
        return headers

    async def _pooled_client(self, row: dict) -> httpx.AsyncClient:
        """Lazily reuse one bounded HTTP connection pool per registry row.

        The fingerprint includes resolved headers so rotating an environment
        secret replaces (and closes) the old pool without persisting the
        credential or requiring a process restart.
        """
        headers = self._headers(row)
        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "url": row["url"],
                    "headers": sorted(headers.items()),
                    "timeout": self.config.gateway.timeout_seconds,
                },
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        async with self._client_lock:
            current = self._clients.get(row["id"])
            if current is not None and current.fingerprint == fingerprint:
                return current.client
            limits = httpx.Limits(
                max_connections=self.config.gateway.max_concurrency,
                max_keepalive_connections=max(
                    1, min(8, self.config.gateway.max_concurrency)
                ),
            )
            client = httpx.AsyncClient(
                headers=headers,
                timeout=httpx.Timeout(self.config.gateway.timeout_seconds),
                follow_redirects=False,
                limits=limits,
                # Keep SSRF validation and the eventual socket destination in
                # the same trust boundary; ambient proxy variables could
                # otherwise resolve or route the host somewhere else.
                trust_env=False,
            )
            self._clients[row["id"]] = ClientPoolEntry(fingerprint, client)
            if current is not None:
                await current.client.aclose()
            return client

    async def aclose(self) -> None:
        """Close all lazy upstream pools (primarily for graceful shutdown/tests)."""
        async with self._client_lock:
            entries = list(self._clients.values())
            self._clients.clear()
        for entry in entries:
            await entry.client.aclose()

    async def _session_call(self, row: dict, operation):
        validate_outbound_url(row["url"], self.config)
        client = await self._pooled_client(row)
        async with self._limit:
            async with streamable_http_client(row["url"], http_client=client) as streams:
                read, write, _ = streams
                async with ClientSession(
                    read,
                    write,
                    read_timeout_seconds=timedelta(
                        seconds=self.config.gateway.timeout_seconds
                    ),
                ) as session:
                    await session.initialize()
                    return await operation(session)

    async def discover(self, row: dict) -> list[dict]:
        async def operation(session):
            result = await session.list_tools()
            inventory: list[dict] = []
            for tool in result.tools:
                inventory.append(
                    {
                        "name": tool.name,
                        "description": _safe_upstream_text(tool.description or ""),
                        "inputSchema": tool.inputSchema,
                        "outputSchema": tool.outputSchema,
                    }
                )
            return inventory

        try:
            # Discovery is idempotent, so one bounded retry is safe. Tool
            # calls are deliberately never retried because they may mutate an
            # upstream system and transport errors cannot prove non-delivery.
            for attempt in range(2):
                try:
                    tools = await self._session_call(row, operation)
                    break
                except Exception:
                    if attempt:
                        raise
                    await anyio.sleep(0.1)
        except Exception as exc:
            message = str(exc)[:500] or type(exc).__name__
            failed = self.identity.mcp_servers.set_inventory(row["id"], [], error=message)
            if failed is not None:
                self.sync_registration(failed)
            raise GatewayError(f"upstream connection failed: {message}") from exc
        self.identity.mcp_servers.set_inventory(row["id"], tools, error=None)
        refreshed = self.identity.mcp_servers.get(row["id"])
        if refreshed is not None:
            self.sync_registration(refreshed)
        return tools

    async def call(self, row: dict, tool_name: str, arguments: dict[str, Any]):
        state = self._circuits.setdefault(row["id"], CircuitState())
        if state.opened_at is not None and time.monotonic() - state.opened_at < 30:
            raise GatewayError("upstream circuit is temporarily open")

        async def operation(session):
            return await session.call_tool(tool_name, arguments)

        try:
            result = await self._session_call(row, operation)
        except Exception as exc:
            state.failures += 1
            if state.failures >= 3:
                state.opened_at = time.monotonic()
            raise GatewayError("upstream tool call failed") from exc
        state.failures = 0
        state.opened_at = None
        return result.model_dump(mode="json", exclude_none=True)

    def register_cached_tools(self, mcp: FastMCP) -> None:
        """Register cached upstream schemas as namespaced FastMCP tools."""
        self._mcp = mcp
        for row in self.identity.mcp_servers.list():
            self.sync_registration(row)

    def sync_registration(self, row: dict) -> None:
        """Hot-replace one server namespace after create/refresh/toggle."""
        if self._mcp is None:
            return
        prefix = f"{row['name']}."
        for tool_name in list(self._mcp._tool_manager._tools):
            if tool_name.startswith(prefix):
                self._mcp._tool_manager.remove_tool(tool_name)
        if not row["enabled"]:
            return
        for inventory in json.loads(row.get("tools_json") or "[]"):
            self._register_one(self._mcp, row, inventory)

    def unregister(self, row: dict) -> None:
        if self._mcp is None:
            return
        prefix = f"{row['name']}."
        for tool_name in list(self._mcp._tool_manager._tools):
            if tool_name.startswith(prefix):
                self._mcp._tool_manager.remove_tool(tool_name)

    def _register_one(self, mcp: FastMCP, row: dict, inventory: dict) -> None:
        upstream_name = inventory.get("name")
        if not isinstance(upstream_name, str) or not upstream_name:
            return
        exposed = f"{row['name']}.{upstream_name}"
        schema = inventory.get("inputSchema") or {"type": "object", "properties": {}}
        properties = schema.get("properties") if isinstance(schema, dict) else {}
        required = set(schema.get("required") or []) if isinstance(schema, dict) else set()
        parameters: list[inspect.Parameter] = []
        for name in (properties or {}):
            if not isinstance(name, str) or not name.isidentifier():
                continue
            default = inspect.Parameter.empty if name in required else None
            parameters.append(
                inspect.Parameter(
                    name,
                    inspect.Parameter.KEYWORD_ONLY,
                    default=default,
                    annotation=Any,
                )
            )

        async def proxy(**kwargs):
            current = self.identity.mcp_servers.get(row["id"])
            if current is None or not current["enabled"]:
                raise GatewayError("upstream server is disabled")
            return await self.call(current, upstream_name, kwargs)

        proxy.__name__ = exposed.replace(".", "_")
        proxy.__doc__ = _safe_upstream_text(
            inventory.get("description") or f"Proxied tool from {row['name']}"
        )
        proxy.__signature__ = inspect.Signature(parameters=parameters, return_annotation=Any)
        tool = mcp._tool_manager.add_tool(proxy, name=exposed, description=proxy.__doc__)
        if isinstance(schema, dict):
            tool.parameters = schema
