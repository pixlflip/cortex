"""Binary-safe, scoped vault file tooling tests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from pathlib import Path

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from cortex.config import CortexConfig, IndexConfig, Principal, VaultConfig, VaultsConfig, WritesConfig
from cortex.server import CortexServer


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    root = tmp_path / "vaults" / "p"
    (root / "Public" / "attachments").mkdir(parents=True)
    (root / "Private").mkdir()
    (root / "Public" / "note.md").write_text("# Public\n", encoding="utf-8")
    (root / "Public" / "attachments" / "image.bin").write_bytes(b"\x00\x01binary\xffpayload")
    (root / "Private" / "secret.pdf").write_bytes(b"private")
    (root / ".obsidian").mkdir()
    (root / ".obsidian" / "workspace.json").write_text("secret", encoding="utf-8")
    return root


def server(
    vault: Path,
    *,
    scopes: list[str] | None = None,
    write_scopes: list[str] | None = None,
    writes: bool = False,
) -> CortexServer:
    cfg = CortexConfig(
        vault=VaultConfig(),
        vaults=VaultsConfig(root=vault.parent, index_dir=vault.parent.parent / "indexes"),
        index=IndexConfig(enabled=False),
        principals=[
            Principal(
                name="p",
                scopes=scopes or ["Public/**"],
                write_scopes=write_scopes or [],
            )
        ],
        writes=WritesConfig(enabled=writes),
    )
    srv = CortexServer(cfg, principal=cfg.principal("p"))
    if writes:
        srv.git.ensure_repo()
        srv.git.commit("cortex-bootstrap", "initial vault snapshot")
    return srv


def call(srv: CortexServer, tool: str, **args):
    async def run():
        return await srv.mcp.call_tool(tool, args)

    result = asyncio.run(run())
    if isinstance(result, tuple) and result[1] is not None:
        payload = result[1]
    else:
        blocks = result[0] if isinstance(result, tuple) else result
        payload = json.loads(blocks[0].text)
    return payload["result"] if set(payload) == {"result"} else payload


def tool_names(srv: CortexServer) -> set[str]:
    return {tool.name for tool in srv.mcp._tool_manager.list_tools()}


def test_file_tools_registration_obeys_write_gate(vault: Path):
    read_only = server(vault)
    assert {"list_files", "get_file"} <= tool_names(read_only)
    assert "put_file" not in tool_names(read_only)

    writable = server(vault, writes=True)
    assert {"list_files", "get_file", "put_file"} <= tool_names(writable)


def test_list_files_is_scoped_and_excludes_hidden_files_and_symlinks(vault: Path):
    (vault / "Public" / "secret-link.pdf").symlink_to(vault / "Private" / "secret.pdf")
    result = call(server(vault), "list_files")
    assert [row["path"] for row in result] == [
        "Public/attachments/image.bin",
        "Public/note.md",
    ]
    assert result[0]["size"] == len(b"\x00\x01binary\xffpayload")
    assert result[0]["media_type"] == "application/octet-stream"


def test_get_file_returns_binary_safe_chunks_and_complete_digest(vault: Path):
    payload = (vault / "Public" / "attachments" / "image.bin").read_bytes()
    first = call(
        server(vault),
        "get_file",
        path="Public/attachments/image.bin",
        offset=0,
        length=5,
    )
    assert base64.b64decode(first["content_base64"]) == payload[:5]
    assert first["size"] == len(payload)
    assert first["length"] == 5
    assert first["next_offset"] == 5
    assert first["eof"] is False
    assert first["sha256"] == hashlib.sha256(payload).hexdigest()

    second = call(
        server(vault),
        "get_file",
        path="Public/attachments/image.bin",
        offset=first["next_offset"],
        length=999,
        include_sha256=False,
    )
    assert base64.b64decode(second["content_base64"]) == payload[5:]
    assert second["eof"] is True
    assert second["sha256"] is None


def test_get_file_rejects_out_of_scope_hidden_traversal_and_symlink(vault: Path):
    (vault / "Public" / "secret-link.pdf").symlink_to(vault / "Private" / "secret.pdf")
    srv = server(vault)
    for path in (
        "Private/secret.pdf",
        ".obsidian/workspace.json",
        "Public/../Private/secret.pdf",
        "Public/secret-link.pdf",
    ):
        with pytest.raises(ToolError, match="not found or not in scope|symlink"):
            call(srv, "get_file", path=path)


def test_get_file_bounds_are_validated_and_chunk_length_is_capped(vault: Path, monkeypatch):
    import cortex.server as server_module

    monkeypatch.setattr(server_module, "MAX_FILE_CHUNK_BYTES", 4)
    srv = server(vault)
    result = call(srv, "get_file", path="Public/attachments/image.bin", length=99)
    assert result["length"] == 4
    with pytest.raises(ToolError, match="offset must be non-negative"):
        call(srv, "get_file", path="Public/attachments/image.bin", offset=-1)
    with pytest.raises(ToolError, match="length must be at least 1"):
        call(srv, "get_file", path="Public/attachments/image.bin", length=0)


def test_put_file_round_trip_is_hashed_and_git_audited(vault: Path):
    srv = server(vault, writes=True)
    payload = b"%PDF-1.7\n\x00new attachment\n"
    digest = hashlib.sha256(payload).hexdigest()
    result = call(
        srv,
        "put_file",
        path="Public/attachments/report.pdf",
        content_base64=base64.b64encode(payload).decode("ascii"),
        expected_sha256=digest,
        reason="attach report",
    )
    assert result["created"] is True
    assert result["size"] == len(payload)
    assert result["sha256"] == digest
    assert result["commit"]
    assert (vault / "Public" / "attachments" / "report.pdf").read_bytes() == payload
    assert call(srv, "get_file", path="Public/attachments/report.pdf")["sha256"] == digest


def test_put_file_refuses_overwrite_invalid_base64_hash_mismatch_and_markdown(vault: Path):
    srv = server(vault, writes=True)
    encoded = base64.b64encode(b"replacement").decode("ascii")
    with pytest.raises(ToolError, match="already exists"):
        call(
            srv,
            "put_file",
            path="Public/attachments/image.bin",
            content_base64=encoded,
            reason="refuse overwrite",
        )
    with pytest.raises(ToolError, match="valid RFC 4648 base64"):
        call(srv, "put_file", path="Public/bad.bin", content_base64="%%%", reason="bad")
    with pytest.raises(ToolError, match="sha256 mismatch"):
        call(
            srv,
            "put_file",
            path="Public/bad-hash.bin",
            content_base64=encoded,
            expected_sha256="0" * 64,
            reason="bad hash",
        )
    with pytest.raises(ToolError, match="write_note"):
        call(srv, "put_file", path="Public/bypass.md", content_base64=encoded, reason="bad")
    assert not (vault / "Public" / "bad.bin").exists()
    assert not (vault / "Public" / "bad-hash.bin").exists()
    assert not (vault / "Public" / "bypass.md").exists()


def test_put_file_enforces_write_scope_and_size_limit(vault: Path, monkeypatch):
    import cortex.server as server_module

    srv = server(vault, scopes=["**"], write_scopes=["Public/uploads/**"], writes=True)
    encoded = base64.b64encode(b"12345").decode("ascii")
    with pytest.raises(ToolError, match="not in scope"):
        call(srv, "put_file", path="Private/no.bin", content_base64=encoded, reason="no")
    monkeypatch.setattr(server_module, "MAX_FILE_WRITE_BYTES", 4)
    with pytest.raises(ToolError, match="put_file limit"):
        call(srv, "put_file", path="Public/uploads/large.bin", content_base64=encoded, reason="large")


def test_note_read_rejects_in_vault_symlink_scope_bypass(vault: Path):
    (vault / "Public" / "linked.md").symlink_to(vault / "Private" / "secret.md")
    (vault / "Private" / "secret.md").write_text("secret", encoding="utf-8")
    with pytest.raises(ToolError, match="not found or not in scope|symlink"):
        call(server(vault), "read_note", path="Public/linked.md")
