"""Sync-freshness tests: ``cortex sync`` (the ``run_sync`` core), the new
``GitAudit.head_time()`` freshness primitive, and the ``status()`` MCP tool's
``_status_payload``.

Mirrors the fixture/server-construction style of test_write.py /
test_search_index.py: IndexConfig(enabled=False) or an index path rooted in
tmp_path so no stray cortex.index.sqlite gets written outside tmp_path."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from cortex.cli import run_sync
from cortex.config import (
    CortexConfig,
    GitConfig,
    IndexConfig,
    Principal,
    SyncConfig,
    VaultConfig,
)
from cortex.gitlog import GitAudit
from cortex.server import CortexServer


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


def _cfg(vault: Path, tmp_path: Path, *, adapter: str = "none") -> CortexConfig:
    return CortexConfig(
        vault=VaultConfig(path=vault, git=GitConfig()),
        sync=SyncConfig(adapter=adapter),
        index=IndexConfig(enabled=True, path=tmp_path / "index.sqlite"),
        principals=[Principal(name="p", scopes=["**"])],
    )


# -- run_sync: adapter "none" --------------------------------------------------

def test_run_sync_commits_pending_change(vault: Path, tmp_path: Path):
    """A pending human edit (made directly in the vault, not through any MCP
    write tool) gets snapshotted into the git audit trail by run_sync, under
    the cortex-sync actor."""
    cfg = _cfg(vault, tmp_path)
    git = GitAudit(cfg.vault.path, cfg.vault.git)
    git.ensure_repo()
    git.commit("cortex-bootstrap", "initial vault snapshot")

    (vault / "Public" / "open.md").write_text(
        "---\ntitle: Open\ntags: [a]\n---\n# Open\n\nedited directly in Obsidian\n",
        encoding="utf-8",
    )

    summary = run_sync(cfg)
    assert summary["commit"] is not None
    log = git.log(limit=1)
    assert log[0].actor == "cortex-sync"
    assert log[0].subject == "cortex-sync: periodic snapshot"


def test_run_sync_clean_is_a_noop(vault: Path, tmp_path: Path):
    """Running sync again with nothing changed produces no commit and raises
    nothing — the clean no-op case."""
    cfg = _cfg(vault, tmp_path)
    git = GitAudit(cfg.vault.path, cfg.vault.git)
    git.ensure_repo()
    git.commit("cortex-bootstrap", "initial vault snapshot")

    first = run_sync(cfg)
    assert first["commit"] is None  # nothing pending beyond the bootstrap commit above

    second = run_sync(cfg)
    assert second["commit"] is None
    assert second["remote"] == "skipped"


def test_run_sync_refreshes_index(vault: Path, tmp_path: Path):
    cfg = _cfg(vault, tmp_path)
    git = GitAudit(cfg.vault.path, cfg.vault.git)
    git.ensure_repo()
    git.commit("cortex-bootstrap", "initial vault snapshot")

    summary = run_sync(cfg)
    assert summary["index"] is not None
    assert summary["index"]["note_count"] == 2
    assert summary["index"]["last_indexed"] is not None


def test_run_sync_index_disabled_reports_none(vault: Path, tmp_path: Path):
    cfg = _cfg(vault, tmp_path)
    cfg.index = IndexConfig(enabled=False)
    git = GitAudit(cfg.vault.path, cfg.vault.git)
    git.ensure_repo()

    summary = run_sync(cfg)
    assert summary["index"] is None


def test_run_sync_adapter_none_skips_remote(vault: Path, tmp_path: Path):
    cfg = _cfg(vault, tmp_path, adapter="none")
    git = GitAudit(cfg.vault.path, cfg.vault.git)
    git.ensure_repo()

    summary = run_sync(cfg)
    assert summary["remote"] == "skipped"
    assert summary["remote_detail"] is None


# -- run_sync: adapter "git" ---------------------------------------------------

def test_run_sync_adapter_git_no_remote_records_error_not_fatal(vault: Path, tmp_path: Path):
    """With sync.adapter: git but no remote configured, pull/push fail — this
    must be recorded, not raised, and the local snapshot + reindex must still
    have happened (the durable half of the job)."""
    cfg = _cfg(vault, tmp_path, adapter="git")
    git = GitAudit(cfg.vault.path, cfg.vault.git)
    git.ensure_repo()
    git.commit("cortex-bootstrap", "initial vault snapshot")

    (vault / "Public" / "open.md").write_text("# Open\n\nchanged again\n", encoding="utf-8")

    summary = run_sync(cfg)  # must not raise
    assert summary["commit"] is not None  # local snapshot still happened
    assert summary["index"] is not None  # reindex still happened
    assert summary["remote"] == "error"
    assert summary["remote_detail"]  # some message explaining the git failure


def test_run_sync_adapter_git_pulls_and_pushes_real_remote(vault: Path, tmp_path: Path):
    """Exercise the git adapter against a real local bare remote: push a
    commit via run_sync, and confirm the bare remote receives it. Discovers
    the actual local branch name (git's default-branch name varies by
    environment/config) rather than assuming "main"."""
    bare = tmp_path / "remote.git"
    import subprocess

    subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True)

    cfg = _cfg(vault, tmp_path, adapter="git")
    git = GitAudit(cfg.vault.path, cfg.vault.git)
    git.ensure_repo()
    git.commit("cortex-bootstrap", "initial vault snapshot")
    branch = subprocess.run(
        ["git", "branch", "--show-current"], cwd=str(vault),
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    subprocess.run(["git", "remote", "add", "origin", str(bare)], cwd=str(vault), check=True)
    subprocess.run(["git", "push", "-q", "-u", "origin", branch], cwd=str(vault), check=True)

    (vault / "Public" / "open.md").write_text("# Open\n\nyet another edit\n", encoding="utf-8")
    cfg.sync.options = {"remote": "origin", "branch": branch}

    summary = run_sync(cfg)
    assert summary["remote"] == "ok"
    assert summary["remote_detail"] is None

    # The bare remote now has the pushed commit.
    out = subprocess.run(
        ["git", "log", "-n1", "--format=%s", branch], cwd=str(bare),
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert out == "cortex-sync: periodic snapshot"


# -- run_sync: adapters not yet implemented ------------------------------------

@pytest.mark.parametrize("adapter", ["nextcloud", "s3"])
def test_run_sync_unimplemented_adapters_are_local_only(vault: Path, tmp_path: Path, adapter: str):
    cfg = _cfg(vault, tmp_path, adapter=adapter)
    git = GitAudit(cfg.vault.path, cfg.vault.git)
    git.ensure_repo()

    summary = run_sync(cfg)  # must not raise
    assert summary["remote"] == "unsupported"
    assert "not implemented" in summary["remote_detail"]


# -- GitAudit.head_time() ------------------------------------------------------

def test_head_time_none_before_any_commit(vault: Path):
    git = GitAudit(vault, GitConfig())
    git.ensure_repo()
    assert git.head_time() is None


def test_head_time_returns_iso_after_commit(vault: Path):
    git = GitAudit(vault, GitConfig())
    git.ensure_repo()
    git.commit("cortex-bootstrap", "initial vault snapshot")
    iso = git.head_time()
    assert iso is not None
    # ISO 8601 date prefix, e.g. "2026-06-29T..."
    assert iso[4] == "-" and iso[7] == "-"


def test_head_time_none_when_not_a_repo(tmp_path: Path):
    git = GitAudit(tmp_path / "not-a-repo", GitConfig())
    assert git.head_time() is None


# -- status() / _status_payload ------------------------------------------------

def _status_server(vault: Path, tmp_path: Path, *, scopes: list[str] = ("**",)) -> CortexServer:
    cfg = CortexConfig(
        vault=VaultConfig(path=vault, git=GitConfig()),
        index=IndexConfig(enabled=True, path=tmp_path / "index.sqlite"),
        principals=[Principal(name="p", scopes=list(scopes))],
    )
    srv = CortexServer(cfg, principal=cfg.principal("p"))
    return srv


def test_status_payload_keys_and_types_before_any_commit(vault: Path, tmp_path: Path):
    srv = _status_server(vault, tmp_path)
    payload = srv._status_payload(srv.principal)

    assert set(payload) == {
        "principal",
        "visible_note_count",
        "head_commit",
        "last_commit_iso",
        "last_indexed_iso",
        "index_note_count",
    }
    assert payload["principal"] == "p"
    assert isinstance(payload["visible_note_count"], int)
    assert payload["visible_note_count"] == 2  # open.md + secret.md, full scope
    # No git repo yet => both git-derived fields are None.
    assert payload["head_commit"] is None
    assert payload["last_commit_iso"] is None
    assert isinstance(payload["index_note_count"], int)


def test_status_payload_after_commit_and_index(vault: Path, tmp_path: Path):
    srv = _status_server(vault, tmp_path)
    srv.git.ensure_repo()
    sha = srv.git.commit("cortex-bootstrap", "initial vault snapshot")
    srv.index.sync()

    payload = srv._status_payload(srv.principal)
    assert payload["head_commit"] == sha
    assert isinstance(payload["last_commit_iso"], str)
    assert payload["last_indexed_iso"] is not None
    assert isinstance(payload["last_indexed_iso"], str)
    assert payload["index_note_count"] == 2


def test_status_payload_visible_note_count_respects_scopes(vault: Path, tmp_path: Path):
    srv = _status_server(vault, tmp_path, scopes=["Public/**"])
    payload = srv._status_payload(srv.principal)
    assert payload["visible_note_count"] == 1  # only Public/open.md


def test_status_tool_via_real_mcp_call(vault: Path, tmp_path: Path):
    """End-to-end through the actual @mcp.tool() wrapper (not _status_payload
    directly), proving the thin closure is wired correctly and resolves the
    bound stdio principal."""
    srv = _status_server(vault, tmp_path)
    srv.git.ensure_repo()
    srv.git.commit("cortex-bootstrap", "initial vault snapshot")

    async def run():
        return await srv.mcp.call_tool("status", {})

    result = asyncio.run(run())
    payload = json.loads(result[0].text)
    assert payload["principal"] == "p"
    assert payload["head_commit"]
    assert payload["visible_note_count"] == 2
