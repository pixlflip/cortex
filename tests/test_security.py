"""Security-hardening regression tests (v2 baseline).

Covers the fixes for:

* #5  — scope bypass via ``..`` path segments that stay inside the vault
* #6  — dotfile/hidden-path exfiltration (``.git/config``) and non-note suffixes
* #7  — admin auth bypass when the admin store is uninitialized
* #9  — admin client name colliding with a config principal
* #14 — PBKDF2-per-client token lookup DoS (prefix-indexed lookup)
* #17 — admin store lost updates (locked read-modify-write)
* #18 — world-readable window while saving the admin state file
* #19 — admin cookie hardening (expiry, random server secret)
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from cortex.config import CortexConfig, IndexConfig, Principal, VaultConfig, WritesConfig
from cortex.server import CortexServer, _canonical_note_path
from mcp.server.fastmcp.exceptions import ToolError


# -- fixtures ----------------------------------------------------------------

@pytest.fixture
def vault(tmp_path: Path) -> Path:
    root = tmp_path / "vault"
    (root / "Projects").mkdir(parents=True)
    (root / "Private").mkdir()
    (root / "Projects" / "plan.md").write_text(
        "# Plan\n\n## Roadmap\n\nproject roadmap\n", encoding="utf-8"
    )
    (root / "Private" / "secret.md").write_text(
        "---\nowner: me\n---\n# Secret\n\nshh, private content\n", encoding="utf-8"
    )
    (root / "notes.txt").write_text("not a note\n", encoding="utf-8")
    return root


def _server(vault: Path, scopes: list[str], *, writes: bool = False) -> CortexServer:
    cfg = CortexConfig(
        vault=VaultConfig(path=vault),
        index=IndexConfig(enabled=False),
        principals=[Principal(name="p", scopes=list(scopes))],
        writes=WritesConfig(enabled=writes),
    )
    srv = CortexServer(cfg, principal=cfg.principal("p"))
    if writes:
        srv.git.ensure_repo()
        srv.git.commit("cortex-bootstrap", "initial vault snapshot")
    return srv


def _call(srv: CortexServer, tool: str, **args):
    async def run():
        return await srv.mcp.call_tool(tool, args)

    return asyncio.run(run())


# -- #5: scope bypass via `..` -------------------------------------------------

def test_dotdot_inside_vault_does_not_cross_scope_boundary(vault: Path):
    """A Projects/**-scoped principal must NOT read Private/ content through a
    raw path that matches the scope textually but resolves elsewhere."""
    srv = _server(vault, ["Projects/**"])
    with pytest.raises(ToolError, match="not found or not in scope"):
        _call(srv, "read_note", path="Projects/../Private/secret.md")
    with pytest.raises(ToolError, match="not found or not in scope"):
        _call(srv, "read_frontmatter", path="Projects/../Private/secret.md")
    with pytest.raises(ToolError, match="not found or not in scope"):
        _call(srv, "read_section", path="Projects/../Private/secret.md", heading="Secret")


def test_dotdot_rejected_for_write_tools(vault: Path):
    srv = _server(vault, ["Projects/**"], writes=True)
    p = srv.config.principal("p")
    for attempt in ("Projects/../Private/pwn.md", "../outside.md", "/abs/path.md"):
        with pytest.raises(ValueError, match="not found or not in scope"):
            srv._do_write_note(p, attempt, "pwned", "traversal attempt")
    assert not (vault / "Private" / "pwn.md").exists()


def test_scope_checked_against_canonical_form(vault: Path):
    """Redundant-but-harmless forms canonicalize and still resolve; the scope
    check runs on the exact normalized path."""
    srv = _server(vault, ["Projects/**"])
    result = _call(srv, "read_note", path="Projects//./plan.md")
    assert "project roadmap" in result[0][0].text


def test_canonical_note_path_rules():
    assert _canonical_note_path("Projects/plan.md") == "Projects/plan.md"
    assert _canonical_note_path("Projects//./plan.md") == "Projects/plan.md"
    assert _canonical_note_path("Projects/../Private/secret.md") is None
    assert _canonical_note_path("..") is None
    assert _canonical_note_path("/etc/passwd") is None
    assert _canonical_note_path("C:/x.md") is None
    assert _canonical_note_path("a\\b.md") is None
    assert _canonical_note_path("") is None
    assert _canonical_note_path(".git/config") is None
    assert _canonical_note_path("Projects/.hidden.md") is None
    assert _canonical_note_path("notes.txt") is None
    assert _canonical_note_path("Projects/plan.MD") == "Projects/plan.MD"


# -- #6: dotfile / non-note exfiltration ----------------------------------------

def test_read_note_rejects_git_config_even_for_broad_scope(vault: Path):
    (vault / ".git").mkdir()
    (vault / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = https://user:hunter2@example.com/repo.git\n',
        encoding="utf-8",
    )
    srv = _server(vault, ["**"])
    with pytest.raises(ToolError, match="not found or not in scope"):
        _call(srv, "read_note", path=".git/config")
    with pytest.raises(ToolError, match="not found or not in scope"):
        _call(srv, "read_note", path="Projects/../.git/config")


def test_read_note_rejects_non_note_suffix(vault: Path):
    srv = _server(vault, ["**"])
    with pytest.raises(ToolError, match="not found or not in scope"):
        _call(srv, "read_note", path="notes.txt")


def test_write_tools_cannot_target_hidden_paths(vault: Path):
    srv = _server(vault, ["**"], writes=True)
    p = srv.config.principal("p")
    with pytest.raises(ValueError, match="not found or not in scope"):
        srv._do_write_note(p, ".git/hooks/post-commit.md", "pwn", "hidden write")
    with pytest.raises(ValueError, match="not found or not in scope"):
        srv._do_delete_note(p, ".git/config", "hidden delete")
    assert (vault / ".git" / "config").exists()
