"""Core deterministic-layer tests: vault, scopes, git audit, config."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cortex.config import ConfigError, load_config
from cortex.gitlog import GitAudit
from cortex.scopes import filter_paths, path_allowed
from cortex.vault import VaultStore, split_frontmatter


# -- fixtures --------------------------------------------------------------

@pytest.fixture
def vault(tmp_path: Path) -> Path:
    root = tmp_path / "vault"
    (root / "Welcome").mkdir(parents=True)
    (root / "Public").mkdir()
    (root / "Welcome" / "hello.md").write_text(
        "---\ntitle: Hello\ntags: [a, b]\n---\n# Hello\n\nbody about vaults\n\n## Sub\nsub text\n",
        encoding="utf-8",
    )
    (root / "Public" / "open.md").write_text("# Open\n\npublic content\n", encoding="utf-8")
    (root / "Public" / "scratch.txt").write_text("not an Obsidian note\n", encoding="utf-8")
    (root / ".obsidian").mkdir()
    (root / ".obsidian" / "workspace.json").write_text("{}", encoding="utf-8")
    return root


# -- frontmatter -----------------------------------------------------------

def test_split_frontmatter():
    fm, body = split_frontmatter("---\ntitle: X\n---\nhello\n")
    assert fm == {"title": "X"}
    assert body.strip() == "hello"


def test_split_frontmatter_none():
    fm, body = split_frontmatter("no frontmatter here")
    assert fm == {}
    assert body == "no frontmatter here"


def test_malformed_frontmatter_does_not_crash():
    fm, body = split_frontmatter("---\n: : bad\n---\nx")
    assert fm == {}  # falls back to treating as body, no exception


# -- vault store -----------------------------------------------------------

def test_list_notes_skips_hidden_dirs(vault: Path):
    store = VaultStore(vault)
    notes = store.list_notes()
    assert "Welcome/hello.md" in notes
    assert "Public/open.md" in notes
    assert "Public/scratch.txt" not in notes
    assert not any(".obsidian" in n for n in notes)


def test_read_note_and_frontmatter(vault: Path):
    store = VaultStore(vault)
    note = store.read_note("Welcome/hello.md")
    assert note.frontmatter["title"] == "Hello"
    assert "body about vaults" in note.body


def test_read_section(vault: Path):
    store = VaultStore(vault)
    section = store.read_section("Welcome/hello.md", "Sub")
    assert "sub text" in section
    assert "body about vaults" not in section


def test_search(vault: Path):
    store = VaultStore(vault)
    hits = store.search("vault")
    assert any(h.path == "Welcome/hello.md" for h in hits)


def test_path_traversal_rejected(vault: Path):
    store = VaultStore(vault)
    with pytest.raises(Exception):
        store.read_text("../../etc/passwd")


# -- scopes ----------------------------------------------------------------

def test_scope_globs():
    assert path_allowed("Public/open.md", ["Public/**"])
    assert not path_allowed("Welcome/hello.md", ["Public/**"])
    assert path_allowed("anything/x.md", ["**"])
    assert path_allowed("Notes/a.md", ["Notes/*.md"])
    assert not path_allowed("Notes/sub/a.md", ["Notes/*.md"])


def test_filter_paths():
    paths = ["Public/a.md", "Private/b.md", "Public/sub/c.md"]
    assert filter_paths(paths, ["Public/**"]) == ["Public/a.md", "Public/sub/c.md"]


# -- git audit -------------------------------------------------------------

def test_git_audit_commit_and_log(vault: Path):
    from cortex.config import GitConfig

    git = GitAudit(vault, GitConfig())
    assert git.ensure_repo() is True
    sha = git.commit("cortex-bootstrap", "initial vault snapshot")
    assert sha
    log = git.log()
    assert log[0].subject == "cortex-bootstrap: initial vault snapshot"
    assert log[0].actor == "cortex-bootstrap"
    # nothing to commit the second time
    assert git.commit("cortex-bootstrap", "noop") is None


def test_commit_message_convention():
    from cortex.config import GitConfig

    git = GitAudit(Path("."), GitConfig())
    assert git.message("cortex-janitor", "normalize frontmatter") == \
        "cortex-janitor: normalize frontmatter"


# -- config ----------------------------------------------------------------

def test_config_env_interpolation_and_secrets(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CORTEX_TOKEN_LOCAL", "s3cret")
    (tmp_path / "vault").mkdir()
    cfg_file = tmp_path / "cortex.yaml"
    cfg_file.write_text(
        "vault:\n  path: ./vault\n"
        "principals:\n  - name: local\n    scopes: ['**']\n    token_env: CORTEX_TOKEN_LOCAL\n"
        "auth:\n  local_principal: local\n",
        encoding="utf-8",
    )
    cfg = load_config(cfg_file)
    assert cfg.principal("local").token == "s3cret"
    assert cfg.auth.local_principal == "local"


def test_config_missing_token_env_raises(tmp_path: Path):
    (tmp_path / "vault").mkdir()
    cfg_file = tmp_path / "cortex.yaml"
    cfg_file.write_text(
        "vault:\n  path: ./vault\n"
        "principals:\n  - name: x\n    token_env: CORTEX_NOPE_UNSET\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(cfg_file)


def test_http_requires_auth(tmp_path: Path):
    (tmp_path / "vault").mkdir()
    cfg_file = tmp_path / "cortex.yaml"
    cfg_file.write_text(
        "vault:\n  path: ./vault\n"
        "server:\n  transport: http\n"
        "auth:\n  enabled: false\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(cfg_file)
