"""Write + delete layer tests: the global enable switch, the write-scope
boundary (and its fallback to read scopes), commit-per-mutation with the
`principal:<name> via mcp` actor convention, delete recoverability via git
history, frontmatter validation, and path-traversal safety.

Mirrors the fixture/server-construction style of test_search_index.py:
IndexConfig(enabled=False) so no stray cortex.index.sqlite gets written
outside tmp_path."""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path

import pytest

from cortex.config import CortexConfig, IndexConfig, Principal, VaultConfig, WritesConfig
from cortex.server import CortexServer
from cortex.vault import VaultError
from mcp.server.fastmcp.exceptions import ToolError


# -- fixtures ----------------------------------------------------------------

@pytest.fixture
def vault(tmp_path: Path) -> Path:
    root = tmp_path / "vault"
    (root / "Public").mkdir(parents=True)
    (root / "Private").mkdir()
    (root / "Public" / "open.md").write_text(
        "---\ntitle: Open\ntags: [a]\n---\n# Open\n\nbody about the open note\n",
        encoding="utf-8",
    )
    (root / "Private" / "secret.md").write_text(
        "# Secret\n\nshh, private content\n", encoding="utf-8"
    )
    return root


def _server(
    vault: Path,
    *,
    scopes: list[str] = ("**",),
    write_scopes: list[str] | None = None,
    writes_enabled: bool = True,
) -> CortexServer:
    cfg = CortexConfig(
        vault=VaultConfig(path=vault),
        index=IndexConfig(enabled=False),
        principals=[
            Principal(
                name="p",
                scopes=list(scopes),
                write_scopes=list(write_scopes) if write_scopes is not None else [],
            )
        ],
        writes=WritesConfig(enabled=writes_enabled),
    )
    srv = CortexServer(cfg, principal=cfg.principal("p"))
    srv.git.ensure_repo()
    srv.git.commit("cortex-bootstrap", "initial vault snapshot")
    return srv


def _tool_names(srv: CortexServer) -> set[str]:
    return {t.name for t in srv.mcp._tool_manager.list_tools()}


MUTATING_TOOLS = {
    "write_note", "patch_note", "append_note", "update_frontmatter", "delete_note", "move_note",
}


# -- global enable switch -----------------------------------------------------

def test_writes_disabled_by_default(vault: Path):
    """writes.enabled defaults to False, and a server built from defaults
    registers no mutating tools."""
    cfg = CortexConfig(
        vault=VaultConfig(path=vault),
        index=IndexConfig(enabled=False),
        principals=[Principal(name="p", scopes=["**"])],
    )
    assert cfg.writes.enabled is False
    srv = CortexServer(cfg, principal=cfg.principal("p"))
    assert not (MUTATING_TOOLS & _tool_names(srv))


def test_writes_disabled_hides_mutating_tools_explicitly(vault: Path):
    srv = _server(vault, writes_enabled=False)
    names = _tool_names(srv)
    assert not (MUTATING_TOOLS & names)
    # Read tools are unaffected.
    assert {"search", "read_note", "list_notes", "discover_scopes"} <= names


def test_writes_enabled_registers_mutating_tools(vault: Path):
    srv = _server(vault, writes_enabled=True)
    assert MUTATING_TOOLS <= _tool_names(srv)


def test_writes_disabled_calling_mutating_tool_raises_unknown_tool(vault: Path):
    """Belt-and-suspenders on the gate: not only is the tool absent from the
    registry, calling it by name through the real MCP dispatch path fails
    with "unknown tool" — there is no code path left that can mutate."""
    srv = _server(vault, writes_enabled=False)

    async def run():
        return await srv.mcp.call_tool(
            "write_note", {"path": "Public/x.md", "content": "y", "reason": "z"}
        )

    with pytest.raises(ToolError, match="Unknown tool"):
        asyncio.run(run())
    assert not srv.vault.exists("Public/x.md")


def test_write_note_via_real_mcp_tool_call(vault: Path):
    """End-to-end through the actual @mcp.tool() wrapper (not the _do_*
    method directly), proving the thin closure is wired correctly."""
    srv = _server(vault, writes_enabled=True)

    async def run():
        return await srv.mcp.call_tool(
            "write_note",
            {"path": "Public/via_tool.md", "content": "# Via tool\n\nhi\n", "reason": "via mcp"},
        )

    result = asyncio.run(run())
    payload = json.loads(result[0].text)
    assert payload["created"] is True
    assert payload["commit"]
    assert srv.vault.read_text("Public/via_tool.md") == "# Via tool\n\nhi\n"


# -- create / overwrite -------------------------------------------------------

def test_create_note(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    res = srv._do_write_note(p, "Public/new.md", "# New\n\nhello\n", "create new note")
    assert res["created"] is True
    assert srv.vault.read_text("Public/new.md") == "# New\n\nhello\n"


def test_write_note_refuses_overwrite_by_default(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises(ValueError, match="already exists"):
        srv._do_write_note(p, "Public/open.md", "clobbered", "should refuse")
    # Original content untouched.
    assert "body about the open note" in srv.vault.read_text("Public/open.md")


def test_write_note_overwrite_true_succeeds(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    res = srv._do_write_note(
        p, "Public/open.md", "# Open\n\nreplaced\n", "overwrite note", overwrite=True
    )
    assert res["created"] is False
    assert srv.vault.read_text("Public/open.md") == "# Open\n\nreplaced\n"


# -- patch ---------------------------------------------------------------------

def test_patch_note_unique_match(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    srv._do_patch_note(p, "Public/open.md", "body about the open note", "new body text", "patch")
    assert "new body text" in srv.vault.read_text("Public/open.md")
    assert "body about the open note" not in srv.vault.read_text("Public/open.md")


def test_patch_note_not_found(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises(ValueError, match="not found in"):
        srv._do_patch_note(p, "Public/open.md", "this string is absent", "x", "patch")


def test_patch_note_ambiguous(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    srv._do_write_note(p, "Public/amb.md", "dup dup dup\n", "setup", overwrite=True)
    with pytest.raises(ValueError, match="ambiguous: 3 matches"):
        srv._do_patch_note(p, "Public/amb.md", "dup", "x", "patch")
    # Refused: content unchanged.
    assert srv.vault.read_text("Public/amb.md") == "dup dup dup\n"


def test_patch_note_requires_existing_note(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises(ValueError):
        srv._do_patch_note(p, "Public/missing.md", "a", "b", "patch")


# -- append ---------------------------------------------------------------------

def test_append_note(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    srv._do_append_note(p, "Public/open.md", "appended text", "append")
    text = srv.vault.read_text("Public/open.md")
    assert text.endswith("appended text")
    assert "body about the open note" in text  # original content preserved


def test_append_note_requires_existing_note(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises(ValueError):
        srv._do_append_note(p, "Public/missing.md", "text", "append")


# -- update_frontmatter ----------------------------------------------------------

def test_update_frontmatter_merges_and_preserves_body(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    res = srv._do_update_frontmatter(p, "Public/open.md", {"status": "reviewed"}, "update fm")
    assert res["frontmatter"]["status"] == "reviewed"
    assert res["frontmatter"]["title"] == "Open"  # existing key preserved

    note = srv.vault.read_note("Public/open.md")
    assert note.frontmatter == {"title": "Open", "tags": ["a"], "status": "reviewed"}
    assert "body about the open note" in note.body


def test_update_frontmatter_rejects_non_dict_patch(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises(ValueError, match="mapping"):
        srv._do_update_frontmatter(p, "Public/open.md", ["not", "a", "dict"], "update fm")  # type: ignore[arg-type]


# -- delete + recoverability ------------------------------------------------------

def test_delete_note(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    srv._do_delete_note(p, "Public/open.md", "delete note")
    assert not srv.vault.exists("Public/open.md")


def test_delete_note_requires_existing_file(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises(ValueError):
        srv._do_delete_note(p, "Public/missing.md", "delete")


def test_delete_note_recoverable_from_git_history(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    original = srv.vault.read_text("Public/open.md")

    res = srv._do_delete_note(p, "Public/open.md", "delete note")
    assert res["deleted"] is True
    assert not srv.vault.exists("Public/open.md")

    # The content is recoverable straight from git history (the delete is its
    # own commit on top of the bootstrap commit) ...
    out = subprocess.run(
        ["git", "show", "HEAD~1:Public/open.md"],
        cwd=str(vault), capture_output=True, text=True,
    )
    assert out.returncode == 0
    assert out.stdout == original

    # ... and a `git revert` actually restores the file on disk.
    subprocess.run(
        ["git", "revert", "--no-edit", "HEAD"],
        cwd=str(vault), capture_output=True, text=True, check=True,
    )
    assert srv.vault.exists("Public/open.md")
    assert srv.vault.read_text("Public/open.md") == original


def test_delete_note_does_not_accept_directories(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises(ValueError):
        srv._do_delete_note(p, "Public", "delete directory should fail")
    assert (vault / "Public").is_dir()


# -- move / rename ---------------------------------------------------------------

def test_move_note_renames_within_folder(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    original = srv.vault.read_text("Public/open.md")

    res = srv._do_move_note(p, "Public/open.md", "Public/renamed.md", "rename note")
    assert res["moved"] is True
    assert res["src"] == "Public/open.md"
    assert res["dest"] == "Public/renamed.md"
    assert res["commit"]
    # Source gone, destination has the identical bytes.
    assert not srv.vault.exists("Public/open.md")
    assert srv.vault.read_text("Public/renamed.md") == original


def test_move_note_across_folders_creates_parent_dirs(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    srv._do_move_note(p, "Public/open.md", "Public/Archive/2026/open.md", "archive note")
    assert not srv.vault.exists("Public/open.md")
    assert srv.vault.exists("Public/Archive/2026/open.md")


def test_move_note_requires_existing_source(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises(ValueError, match="not found or not in scope"):
        srv._do_move_note(p, "Public/missing.md", "Public/dest.md", "move missing")
    assert not srv.vault.exists("Public/dest.md")


def test_move_note_refuses_to_clobber_by_default(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    srv._do_write_note(p, "Public/target.md", "existing target\n", "setup target")
    with pytest.raises(ValueError, match="already exists"):
        srv._do_move_note(p, "Public/open.md", "Public/target.md", "should refuse")
    # Both files untouched.
    assert srv.vault.exists("Public/open.md")
    assert srv.vault.read_text("Public/target.md") == "existing target\n"


def test_move_note_overwrite_true_replaces_destination(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    srv._do_write_note(p, "Public/target.md", "existing target\n", "setup target")
    source = srv.vault.read_text("Public/open.md")

    res = srv._do_move_note(
        p, "Public/open.md", "Public/target.md", "overwrite target", overwrite=True
    )
    assert res["moved"] is True
    assert not srv.vault.exists("Public/open.md")
    assert srv.vault.read_text("Public/target.md") == source


def test_move_note_rejects_same_src_and_dest(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises(ValueError, match="same"):
        srv._do_move_note(p, "Public/open.md", "Public/open.md", "no-op move")
    assert srv.vault.exists("Public/open.md")


def test_move_note_does_not_accept_directory_source(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises(ValueError):
        srv._do_move_note(p, "Public", "Public2", "move directory should fail")
    assert (vault / "Public").is_dir()


def test_move_note_rejects_directory_destination(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises(ValueError, match="directory"):
        srv._do_move_note(p, "Public/open.md", "Private", "dest is a directory")
    assert srv.vault.exists("Public/open.md")


def test_move_note_is_a_single_revertible_commit(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    original = srv.vault.read_text("Public/open.md")
    before = len(srv.git.log(limit=50))

    srv._do_move_note(p, "Public/open.md", "Public/moved.md", "move note")
    after = srv.git.log(limit=50)
    # Exactly one commit for the whole rename, with the actor convention.
    assert len(after) == before + 1
    assert after[0].subject == "principal:p via mcp: move note"
    assert after[0].actor == "principal:p via mcp"

    # Reverting that one commit restores the original layout on disk.
    subprocess.run(
        ["git", "revert", "--no-edit", "HEAD"],
        cwd=str(vault), capture_output=True, text=True, check=True,
    )
    assert srv.vault.exists("Public/open.md")
    assert srv.vault.read_text("Public/open.md") == original
    assert not srv.vault.exists("Public/moved.md")


def test_move_note_via_real_mcp_tool_call(vault: Path):
    srv = _server(vault, writes_enabled=True)

    async def run():
        return await srv.mcp.call_tool(
            "move_note",
            {"src": "Public/open.md", "dest": "Public/via_tool.md", "reason": "via mcp"},
        )

    result = asyncio.run(run())
    payload = json.loads(result[0].text)
    assert payload["moved"] is True
    assert payload["commit"]
    assert not srv.vault.exists("Public/open.md")
    assert srv.vault.exists("Public/via_tool.md")


def test_move_note_denied_when_source_outside_writable_scope(vault: Path):
    srv = _server(vault, scopes=["**"], write_scopes=["Public/**"])
    p = srv.config.principal("p")
    with pytest.raises(ValueError, match="not found or not in scope"):
        srv._do_move_note(p, "Private/secret.md", "Public/leaked.md", "exfiltrate")
    assert srv.vault.exists("Private/secret.md")
    assert not srv.vault.exists("Public/leaked.md")


def test_move_note_denied_when_destination_outside_writable_scope(vault: Path):
    srv = _server(vault, scopes=["**"], write_scopes=["Public/**"])
    p = srv.config.principal("p")
    with pytest.raises(ValueError, match="not found or not in scope"):
        srv._do_move_note(p, "Public/open.md", "Private/hidden.md", "hide it")
    # Source is left in place: the destination check fires before any move.
    assert srv.vault.exists("Public/open.md")
    assert not srv.vault.exists("Private/hidden.md")


def test_move_note_rejects_path_traversal(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises((ValueError, VaultError)):
        srv._do_move_note(p, "Public/open.md", "../../etc/passwd", "traversal attempt")
    assert srv.vault.exists("Public/open.md")


# -- scope boundary: write_scopes defaults open, narrows when set ----------------

def test_write_scopes_unset_falls_back_to_read_scopes(vault: Path):
    """No write_scopes configured => writable area == readable area."""
    srv = _server(vault, scopes=["**"], write_scopes=None)
    p = srv.config.principal("p")
    # Private/ is readable (scopes=['**']) and write_scopes is unset, so it
    # must also be writable.
    res = srv._do_write_note(p, "Private/new.md", "content", "fallback to read scopes")
    assert res["created"] is True


def test_write_scopes_narrows_writable_area(vault: Path):
    """A path that's readable but outside write_scopes is denied for mutation."""
    srv = _server(vault, scopes=["**"], write_scopes=["Public/**"])
    p = srv.config.principal("p")

    # Public/ is in write_scopes: allowed.
    res = srv._do_write_note(p, "Public/new.md", "content", "narrow scope allows Public")
    assert res["created"] is True

    # Private/ is readable (scopes=['**']) but NOT in write_scopes: denied,
    # even though read access would succeed.
    assert srv.vault.exists("Private/secret.md")  # sanity: it does exist
    with pytest.raises(ValueError, match="not found or not in scope"):
        srv._do_write_note(p, "Private/blocked.md", "content", "should be denied")


def test_write_outside_writable_scope_denied_for_all_mutations(vault: Path):
    srv = _server(vault, scopes=["**"], write_scopes=["Public/**"])
    p = srv.config.principal("p")

    with pytest.raises(ValueError, match="not found or not in scope"):
        srv._do_write_note(p, "Private/x.md", "content", "denied write")
    with pytest.raises(ValueError, match="not found or not in scope"):
        srv._do_patch_note(p, "Private/secret.md", "shh", "loud", "denied patch")
    with pytest.raises(ValueError, match="not found or not in scope"):
        srv._do_append_note(p, "Private/secret.md", "more", "denied append")
    with pytest.raises(ValueError, match="not found or not in scope"):
        srv._do_update_frontmatter(p, "Private/secret.md", {"x": 1}, "denied fm update")
    with pytest.raises(ValueError, match="not found or not in scope"):
        srv._do_delete_note(p, "Private/secret.md", "denied delete")

    # Untouched throughout.
    assert srv.vault.read_text("Private/secret.md") == "# Secret\n\nshh, private content\n"


def test_delete_outside_writable_scope_denied(vault: Path):
    srv = _server(vault, scopes=["Public/**", "Private/**"], write_scopes=["Public/**"])
    p = srv.config.principal("p")
    with pytest.raises(ValueError):
        srv._do_delete_note(p, "Private/secret.md", "should be denied")
    assert srv.vault.exists("Private/secret.md")


# -- commit-per-mutation: actor/subject convention -------------------------------

def test_each_mutation_produces_one_commit_with_actor_convention(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    before = len(srv.git.log(limit=50))

    srv._do_write_note(p, "Public/new.md", "content", "create it")
    after_create = srv.git.log(limit=50)
    assert len(after_create) == before + 1
    assert after_create[0].subject == "principal:p via mcp: create it"
    assert after_create[0].actor == "principal:p via mcp"

    srv._do_append_note(p, "Public/new.md", "more", "append it")
    after_append = srv.git.log(limit=50)
    assert len(after_append) == before + 2
    assert after_append[0].subject == "principal:p via mcp: append it"

    srv._do_delete_note(p, "Public/new.md", "delete it")
    after_delete = srv.git.log(limit=50)
    assert len(after_delete) == before + 3
    assert after_delete[0].subject == "principal:p via mcp: delete it"
    assert after_delete[0].actor == "principal:p via mcp"


def test_commit_paths_are_scoped_to_the_mutated_file(vault: Path):
    """Each commit stages only the path that was mutated, not the whole tree —
    GitAudit.commit(paths=[path]) keeps unrelated dirty state out of the
    audit commit."""
    srv = _server(vault)
    p = srv.config.principal("p")
    # Dirty an unrelated file in the working tree without going through a
    # mutating tool (simulating e.g. the user hand-editing in Obsidian).
    (vault / "Private" / "secret.md").write_text("hand-edited\n", encoding="utf-8")

    srv._do_write_note(p, "Public/new.md", "content", "create it")

    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=str(vault), capture_output=True, text=True
    ).stdout
    # The hand-edited file is still dirty (not swept into the commit); the new
    # note is no longer dirty (it was committed).
    assert "Private/secret.md" in status
    assert "Public/new.md" not in status


# -- frontmatter validation -------------------------------------------------------

def test_write_note_rejects_malformed_frontmatter(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises(ValueError, match="frontmatter"):
        srv._do_write_note(p, "Public/bad.md", "---\n: : bad\n---\nbody", "malformed fm")
    assert not srv.vault.exists("Public/bad.md")


def test_write_note_rejects_non_mapping_frontmatter(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises(ValueError, match="frontmatter"):
        srv._do_write_note(p, "Public/bad.md", "---\n- a\n- b\n---\nbody", "list frontmatter")


def test_write_note_validate_frontmatter_false_skips_check(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    # Would fail validation, but validate_frontmatter=False opts out.
    res = srv._do_write_note(
        p, "Public/bad.md", "---\n: : bad\n---\nbody", "skip validation",
        validate_frontmatter=False,
    )
    assert res["created"] is True


def test_write_note_valid_frontmatter_accepted(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    res = srv._do_write_note(
        p, "Public/good.md", "---\ntitle: Good\n---\n# Good\n\nbody\n", "valid fm"
    )
    assert res["created"] is True
    assert srv.vault.read_note("Public/good.md").frontmatter == {"title": "Good"}


# -- path-traversal safety --------------------------------------------------------

def test_write_note_rejects_path_traversal(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises((ValueError, VaultError)):
        srv._do_write_note(p, "../../etc/passwd", "pwned", "traversal attempt")
    assert not (vault.parent.parent / "etc" / "passwd").exists()


def test_delete_note_rejects_path_traversal(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises((ValueError, VaultError)):
        srv._do_delete_note(p, "../../etc/passwd", "traversal attempt")


def test_patch_note_rejects_path_traversal(vault: Path):
    srv = _server(vault)
    p = srv.config.principal("p")
    with pytest.raises((ValueError, VaultError)):
        srv._do_patch_note(p, "../../etc/passwd", "a", "b", "traversal attempt")
