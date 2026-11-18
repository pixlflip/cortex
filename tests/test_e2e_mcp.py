"""End-to-end MCP isolation tests against a real ``cortex serve`` process.

Unit tests elsewhere call tool functions or the in-process FastMCP object.
These drive the shipped CLI as a subprocess and talk to it with the official
MCP client over both transports, so the whole stack (config loading, token
resolution, transport auth, the memory policy governor, vault selection and
path scoping) is exercised together.

The property under test is Cortex's central promise: resources outside a
caller's grant are *invisible*. Another account's vault, a path outside a
narrowed token's scope, and a tool the policy denies must neither appear in
listings nor be readable or callable.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client

pytestmark = [pytest.mark.e2e, pytest.mark.anyio]


@pytest.fixture
def anyio_backend():
    return "asyncio"

SRC = Path(__file__).resolve().parents[1] / "src"
CANARY_ALICE = "alice-private-canary-6f1e"
CANARY_BOB = "bob-private-canary-91c3"
WRITE_TOOLS = {"write_note", "patch_note", "append_note", "delete_note", "move_note", "put_file"}


# -- helpers ----------------------------------------------------------------


def _env(config: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["CORTEX_CONFIG"] = str(config)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(SRC), env.get("PYTHONPATH")]))
    env.setdefault("GIT_AUTHOR_NAME", "e2e")
    env.setdefault("GIT_AUTHOR_EMAIL", "e2e@example.invalid")
    env.setdefault("GIT_COMMITTER_NAME", "e2e")
    env.setdefault("GIT_COMMITTER_EMAIL", "e2e@example.invalid")
    return env


def _cli(config: Path, *args: str) -> str:
    proc = subprocess.run(
        [sys.executable, "-m", "cortex.cli", *args],
        env=_env(config),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, f"cortex {' '.join(args)} failed:\n{proc.stdout}\n{proc.stderr}"
    return proc.stdout


def _mint(config: Path, username: str, name: str, *scopes: str) -> str:
    args = ["token", "mint", username, name]
    for scope in scopes:
        args += ["--scope", scope]
    return _cli(config, *args).strip().splitlines()[-1]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _text(result) -> str:
    return "\n".join(getattr(block, "text", "") for block in result.content)


def _payload(result):
    """Decode a tool result's structured value (lists/dicts arrive as JSON)."""
    if result.structuredContent is not None:
        value = result.structuredContent
        return value.get("result", value) if isinstance(value, dict) and set(value) == {"result"} else value
    return json.loads(_text(result))


async def _tool_names(session: ClientSession) -> set[str]:
    return {tool.name for tool in (await session.list_tools()).tools}


def _assert_hidden(result, *canaries: str) -> None:
    """A denied read is an error that leaks neither content nor existence."""
    assert result.isError
    text = _text(result)
    for canary in canaries:
        assert canary not in text
    assert "not found" in text or "not in scope" in text or "not available" in text


# -- HTTP transport -----------------------------------------------------------


@pytest.fixture(scope="module")
def http_server(tmp_path_factory):
    root = tmp_path_factory.mktemp("e2e-http")
    data = root / "data"
    port = _free_port()
    config = root / "cortex.yaml"
    config.write_text(
        f"""
vault:
  git: {{ enabled: true, actor_name: cortex, actor_email: cortex@localhost }}
vaults:
  root: {data / 'vaults'}
  index_dir: {data / 'indexes'}
  archive_dir: {data / 'archive'}
database: {{ path: {data / 'cortex.sqlite'} }}
index: {{ enabled: true }}
principals: []
auth: {{ enabled: true, oauth_enabled: false }}
admin: {{ enabled: true, path: {data / 'cortex.admin.json'} }}
server: {{ transport: http, host: 127.0.0.1, port: {port}, path: /mcp }}
writes: {{ enabled: true }}
memory_policy: {{ default_read_allow: true, default_write_allow: false }}
llm: {{ provider: none }}
"""
    )
    _cli(config, "init")
    _cli(config, "user", "add", "alice", "--password", "alice-password-e2e")
    _cli(config, "user", "add", "bob", "--password", "bob-password-e2e")
    vaults = data / "vaults"
    _write(vaults / "alice" / "Private" / "plans.md", f"# Plans\n\n{CANARY_ALICE}\n")
    _write(vaults / "bob" / "Public" / "hello.md", "# Hello\n\nbob public note\n")
    _write(vaults / "bob" / "Private" / "diary.md", f"# Diary\n\n{CANARY_BOB}\n")
    _cli(config, "sync")
    tokens = {
        "admin": _mint(config, "admin", "e2e-admin"),
        "alice": _mint(config, "alice", "e2e-alice"),
        "bob": _mint(config, "bob", "e2e-bob"),
        "bob_public": _mint(config, "bob", "e2e-bob-public", "Public/**"),
    }
    log = (root / "server.log").open("w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "cortex.cli", "serve"],
        env=_env(config),
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                if httpx.get(f"{base}/healthz", timeout=1, trust_env=False).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if proc.poll() is not None or time.monotonic() > deadline:
                log.flush()
                pytest.fail("cortex serve did not become ready:\n" + (root / "server.log").read_text())
            time.sleep(0.2)
        yield {"base": base, "tokens": tokens}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


@asynccontextmanager
async def _http_session(server, token: str):
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"}, trust_env=False, timeout=30
    ) as client:
        async with streamable_http_client(f"{server['base']}/mcp", http_client=client) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


def _api(server, token: str, method: str, path: str, **kwargs) -> httpx.Response:
    return httpx.request(
        method,
        f"{server['base']}/api/v1{path}",
        headers={"Authorization": f"Bearer {token}"},
        trust_env=False,
        timeout=10,
        **kwargs,
    )


def test_http_rejects_missing_and_invalid_tokens(http_server):
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}},
    }
    headers = {"Accept": "application/json, text/event-stream"}
    url = f"{http_server['base']}/mcp"
    assert httpx.post(url, json=body, headers=headers, trust_env=False).status_code == 401
    bad = {**headers, "Authorization": "Bearer ctx_not-a-real-token"}
    assert httpx.post(url, json=body, headers=bad, trust_env=False).status_code == 401


async def test_http_other_accounts_vault_is_invisible(http_server):
    async with _http_session(http_server, http_server["tokens"]["alice"]) as alice:
        scopes = _payload(await alice.call_tool("discover_scopes", {}))
        assert [v["vault"] for v in scopes["vaults"]] == ["alice"]

        notes = _payload(await alice.call_tool("list_notes", {}))
        assert "Private/plans.md" in notes
        assert not any("diary" in path or "hello" in path for path in notes)

        own = await alice.call_tool("read_note", {"path": "Private/plans.md"})
        assert not own.isError and CANARY_ALICE in _text(own)

        # Naming bob's vault explicitly is indistinguishable from a missing one.
        for tool, args in (
            ("read_note", {"path": "Private/diary.md", "vault": "bob"}),
            ("list_notes", {"vault": "bob"}),
            ("status", {"vault": "bob"}),
            ("read_note", {"path": "Private/diary.md", "vault": "does-not-exist"}),
        ):
            _assert_hidden(await alice.call_tool(tool, args), CANARY_BOB)

        hits = _payload(await alice.call_tool("search", {"query": CANARY_BOB}))
        assert hits == []
        pack = _text(await alice.call_tool("context_pack", {"query": CANARY_BOB}))
        assert "No visible notes matched" in pack  # the query itself is echoed
        assert "Private/diary.md" not in pack


async def test_http_narrowed_token_hides_out_of_scope_paths(http_server):
    async with _http_session(http_server, http_server["tokens"]["bob_public"]) as bob:
        notes = _payload(await bob.call_tool("list_notes", {}))
        assert notes and all(path.startswith("Public/") for path in notes)

        assert not (await bob.call_tool("read_note", {"path": "Public/hello.md"})).isError
        _assert_hidden(await bob.call_tool("read_note", {"path": "Private/diary.md"}), CANARY_BOB)
        # Traversal does not escape the scope check.
        _assert_hidden(await bob.call_tool("read_note", {"path": "Public/../Private/diary.md"}), CANARY_BOB)
        assert _payload(await bob.call_tool("search", {"query": CANARY_BOB})) == []

    # The same user with an unnarrowed token still sees the private note.
    async with _http_session(http_server, http_server["tokens"]["bob"]) as bob_full:
        result = await bob_full.call_tool("read_note", {"path": "Private/diary.md"})
        assert not result.isError and CANARY_BOB in _text(result)


async def test_http_tool_policy_controls_listing_and_calls(http_server):
    tokens = http_server["tokens"]

    # Writes are enabled server-wide but denied by default for DB users:
    # the tools are absent from the listing and refused if called anyway.
    async with _http_session(http_server, tokens["alice"]) as alice:
        names = await _tool_names(alice)
        assert "read_note" in names
        assert not names & WRITE_TOOLS
        refused = await alice.call_tool(
            "write_note", {"path": "Notes/new.md", "content": "x", "reason": "e2e"}
        )
        assert refused.isError

    created = []
    try:
        # An explicit allow surfaces the tool for that user only.
        response = _api(
            http_server, tokens["admin"], "POST", "/admin/permissions",
            json={"subject_type": "user", "subject": "alice", "tool_pattern": "cortex.write_note", "effect": "allow"},
        )
        assert response.status_code == 201, response.text
        created.append(response.json()["permission"]["id"])

        # Deny wins: hiding a read tool from bob removes it from his listing.
        response = _api(
            http_server, tokens["admin"], "POST", "/admin/permissions",
            json={"subject_type": "user", "subject": "bob", "tool_pattern": "cortex.search", "effect": "deny"},
        )
        assert response.status_code == 201, response.text
        created.append(response.json()["permission"]["id"])

        async with _http_session(http_server, tokens["alice"]) as alice:
            names = await _tool_names(alice)
            assert "write_note" in names
            assert not (names & WRITE_TOOLS) - {"write_note"}
            wrote = await alice.call_tool(
                "write_note", {"path": "Notes/e2e.md", "content": "# e2e\n", "reason": "e2e write"}
            )
            assert not wrote.isError, _text(wrote)

        async with _http_session(http_server, tokens["bob"]) as bob:
            names = await _tool_names(bob)
            assert "search" not in names and "write_note" not in names
            assert (await bob.call_tool("search", {"query": "hello"})).isError
            # alice's write landed in her vault only.
            _assert_hidden(await bob.call_tool("read_note", {"path": "Notes/e2e.md", "vault": "alice"}))
            assert "Notes/e2e.md" not in _payload(await bob.call_tool("list_notes", {}))
    finally:
        for permission_id in created:
            _api(http_server, tokens["admin"], "DELETE", f"/admin/permissions/{permission_id}")


# -- stdio transport ----------------------------------------------------------


@pytest.fixture(scope="module")
def stdio_config(tmp_path_factory):
    root = tmp_path_factory.mktemp("e2e-stdio")
    data = root / "data"
    config = root / "cortex.yaml"
    config.write_text(
        f"""
vault:
  git: {{ enabled: true, actor_name: cortex, actor_email: cortex@localhost }}
vaults:
  root: {data / 'vaults'}
  index_dir: {data / 'indexes'}
  archive_dir: {data / 'archive'}
database: {{ path: {data / 'cortex.sqlite'} }}
index: {{ enabled: true }}
principals:
  - name: carol
    scopes: ["Public/**"]
auth: {{ enabled: true, local_principal: carol }}
server: {{ transport: stdio }}
writes: {{ enabled: false }}
llm: {{ provider: none }}
"""
    )
    vaults = data / "vaults"
    _write(vaults / "carol" / "Public" / "readme.md", "# Readme\n\ncarol public\n")
    _write(vaults / "carol" / "Private" / "keys.md", f"# Keys\n\n{CANARY_ALICE}\n")
    _write(vaults / "dave" / "Public" / "other.md", f"# Other\n\n{CANARY_BOB}\n")
    return config


async def test_stdio_scopes_and_write_switch(stdio_config):
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "cortex.cli", "serve"],
        env=_env(stdio_config),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # writes.enabled: false means write tools are never registered.
            names = await _tool_names(session)
            assert "read_note" in names
            assert not names & WRITE_TOOLS

            assert _payload(await session.call_tool("list_notes", {})) == ["Public/readme.md"]
            _assert_hidden(await session.call_tool("read_note", {"path": "Private/keys.md"}), CANARY_ALICE)
            _assert_hidden(
                await session.call_tool("read_note", {"path": "Public/other.md", "vault": "dave"}),
                CANARY_BOB,
            )
            for canary in (CANARY_ALICE, CANARY_BOB):
                assert _payload(await session.call_tool("search", {"query": canary})) == []


def test_canaries_are_distinct():
    # Guard against a copy/paste making the leak assertions vacuous.
    assert CANARY_ALICE != CANARY_BOB
    assert not re.search(CANARY_ALICE, CANARY_BOB)
