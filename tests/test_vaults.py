"""B1 tests: vault registry & provisioning (cortex.vaults.VaultManager).

Covers the storage-layer contract B2 will build on:

* provisioning creates a working git-initialized, indexable vault, idempotently;
* username → vault id sanitization rejects traversal / separators / reserved;
* archive MOVES a vault (git history intact) rather than destroying it, and
  delete is guarded (needs force);
* the main/shared vault resolves under the manager and keeps its v1 index path;
* auto-provision wires into IdentityService.create_user;
* `cortex sync` / `cortex index` iterate ALL vaults and one failing vault does
  not abort the rest;
* pure-v1 (no vaults:/database: block) config is unchanged.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cortex.config import (
    CortexConfig,
    DatabaseConfig,
    GitConfig,
    IndexConfig,
    SyncConfig,
    VaultConfig,
    VaultsConfig,
    load_config,
)
from cortex.db import Database
from cortex.gitlog import GitAudit
from cortex.users import IdentityService
from cortex.vaults import (
    MAIN_VAULT_ID,
    VaultManager,
    VaultManagerError,
    attach_vault_manager,
    sanitize_vault_id,
    user_actor,
)


# -- fixtures ----------------------------------------------------------------

@pytest.fixture
def main_vault(tmp_path: Path) -> Path:
    root = tmp_path / "vault"
    root.mkdir()
    (root / "Main.md").write_text("# main\n\nshared content\n", encoding="utf-8")
    return root


def _cfg(main_vault: Path, tmp_path: Path, **vaults_kw) -> CortexConfig:
    data = tmp_path / "data"
    vaults = VaultsConfig(
        root=vaults_kw.pop("root", data / "vaults"),
        index_dir=vaults_kw.pop("index_dir", data / "indexes"),
        archive_dir=vaults_kw.pop("archive_dir", data / "archive"),
        **vaults_kw,
    )
    return CortexConfig(
        vault=VaultConfig(path=main_vault, git=GitConfig()),
        vaults=vaults,
        index=IndexConfig(enabled=True, path=tmp_path / "cortex.index.sqlite"),
        database=DatabaseConfig(path=data / "cortex.sqlite"),
    )


@pytest.fixture
def manager(main_vault: Path, tmp_path: Path) -> VaultManager:
    mgr = VaultManager(_cfg(main_vault, tmp_path))
    yield mgr
    mgr.close()


# -- sanitization ------------------------------------------------------------

@pytest.mark.parametrize(
    "bad",
    ["../evil", "a/b", "a\\b", "/abs", "..", ".hidden", "user:x", "", "  ", "main"],
)
def test_sanitize_rejects_unsafe_ids(bad):
    with pytest.raises(VaultManagerError):
        sanitize_vault_id(bad)


@pytest.mark.parametrize("ok", ["alice", "bob-1", "a.b_c", "A9", "x" * 64])
def test_sanitize_accepts_safe_ids(ok):
    assert sanitize_vault_id(ok) == ok


def test_sanitize_charset_matches_a4_username_charset():
    """The vault-id charset must stay identical to the A4 username charset so
    every valid username is a valid vault id and neither drifts."""
    import cortex.users as users_mod
    import cortex.vaults as vaults_mod

    assert vaults_mod._VAULT_ID_RE.pattern == users_mod._USERNAME_RE.pattern


def test_root_for_cannot_escape_root(manager: VaultManager):
    with pytest.raises(VaultManagerError):
        manager.root_for("../../etc")


def test_user_actor_convention():
    assert user_actor("alice") == "user:alice via mcp"
    assert user_actor("alice", via="web") == "user:alice via web"


# -- provisioning ------------------------------------------------------------

def test_provision_creates_git_indexable_vault(manager: VaultManager):
    result = manager.provision("alice")
    assert result.created_dir and result.initialized_git and result.seeded
    assert result.commit is not None

    root = manager.root_for("alice")
    assert (root / ".git").is_dir()
    assert (root / "Welcome.md").is_file()

    # A real repo with the baseline commit.
    git = GitAudit(root, GitConfig())
    assert git.is_repo()
    log = git.log(limit=5)
    assert any("provision vault for alice" in c.subject for c in log)

    # Indexable: the bundle's SearchIndex syncs and sees the welcome note.
    bundle = manager.get("alice")
    bundle.index.sync()
    assert bundle.index.stats()["note_count"] == 1
    assert bundle.store.list_notes() == ["Welcome.md"]


def test_reprovision_is_idempotent_noop(manager: VaultManager):
    manager.provision("alice")
    # An immediate re-provision changes nothing: no new dir, no re-init, no
    # re-seed, and nothing new to commit.
    again = manager.provision("alice")
    assert not again.created_dir
    assert not again.initialized_git
    assert not again.seeded
    assert again.commit is None


def test_reprovision_does_not_clobber_user_notes(manager: VaultManager):
    manager.provision("alice")
    # A note the user has since written must survive a repair re-provision
    # (re-seeding only happens into an empty vault).
    (manager.root_for("alice") / "Kept.md").write_text("mine\n", encoding="utf-8")
    again = manager.provision("alice")
    assert not again.seeded
    kept = manager.root_for("alice") / "Kept.md"
    assert kept.is_file() and kept.read_text(encoding="utf-8") == "mine\n"


def test_provision_template_dir_seeds_skeleton(main_vault: Path, tmp_path: Path):
    template = tmp_path / "template"
    (template / "Projects").mkdir(parents=True)
    (template / "Start Here.md").write_text("# start\n", encoding="utf-8")
    (template / ".git").mkdir()  # must be excluded from the copy
    (template / ".git" / "HEAD").write_text("ref\n", encoding="utf-8")

    mgr = VaultManager(_cfg(main_vault, tmp_path, template_dir=template))
    try:
        mgr.provision("bob")
        root = mgr.root_for("bob")
        assert (root / "Start Here.md").is_file()
        assert (root / "Projects").is_dir()
        # The template's own .git was not copied in (the vault got its own).
        assert not (root / ".git" / "HEAD").exists() or (root / ".git" / "config").exists()
        assert not (root / "Welcome.md").exists()
    finally:
        mgr.close()


def test_provision_rejects_traversal(manager: VaultManager):
    for bad in ["../evil", "a/b", ".."]:
        with pytest.raises(VaultManagerError):
            manager.provision(bad)


# -- registry / lookup -------------------------------------------------------

def test_main_vault_resolves_under_manager(manager: VaultManager, main_vault: Path):
    assert manager.exists(MAIN_VAULT_ID)
    bundle = manager.get(MAIN_VAULT_ID)
    assert bundle.is_main
    assert bundle.root == main_vault.resolve()
    assert "Main.md" in bundle.store.list_notes()


def test_main_vault_keeps_v1_index_path(manager: VaultManager, tmp_path: Path):
    # Backward compatibility: the main vault's index stays at index.path,
    # while user vaults get data/indexes/<user>.index.sqlite.
    assert manager.index_path_for(MAIN_VAULT_ID) == tmp_path / "cortex.index.sqlite"
    assert manager.index_path_for("alice").name == "alice.index.sqlite"


def test_vault_ids_lists_main_then_users(manager: VaultManager):
    manager.provision("alice")
    manager.provision("bob")
    assert manager.vault_ids() == [MAIN_VAULT_ID, "alice", "bob"]


def test_get_unprovisioned_user_vault_raises(manager: VaultManager):
    with pytest.raises(VaultManagerError):
        manager.get("ghost")


def test_get_caches_bundle(manager: VaultManager):
    manager.provision("alice")
    assert manager.get("alice") is manager.get("alice")


# -- lifecycle: archive / delete ---------------------------------------------

def test_archive_moves_not_destroys(manager: VaultManager):
    manager.provision("alice")
    root = manager.root_for("alice")
    dest = manager.archive("alice", timestamp="20260101T000000Z")

    assert not root.exists()  # moved out of the live registry
    assert dest.is_dir()
    assert (dest / "Welcome.md").is_file()
    assert (dest / ".git").is_dir()  # git history preserved
    assert "alice" not in manager.vault_ids()


def test_delete_is_guarded(manager: VaultManager):
    manager.provision("alice")
    with pytest.raises(VaultManagerError):
        manager.delete("alice")  # no force
    assert manager.exists("alice")  # still there


def test_delete_force_destroys(manager: VaultManager):
    manager.provision("alice")
    idx_path = manager.index_path_for("alice")
    manager.get("alice").index.sync()  # create the index file
    assert idx_path.exists()

    manager.delete("alice", force=True)
    assert not manager.root_for("alice").exists()
    assert not idx_path.exists()  # rebuildable cache removed too


def test_archive_unknown_vault_raises(manager: VaultManager):
    with pytest.raises(VaultManagerError):
        manager.archive("ghost")


# -- auto-provision hook on user creation ------------------------------------

def test_create_user_auto_provisions_vault(main_vault: Path, tmp_path: Path):
    cfg = _cfg(main_vault, tmp_path)
    db = Database(cfg.database.path)
    identity = IdentityService(db, cfg)
    manager = attach_vault_manager(identity, cfg)
    try:
        identity.create_user("carol", password="pw")
        assert manager.exists("carol")
        assert (manager.root_for("carol") / ".git").is_dir()
    finally:
        manager.close()


def test_auto_provision_disabled_skips(main_vault: Path, tmp_path: Path):
    cfg = _cfg(main_vault, tmp_path, auto_provision=False)
    db = Database(cfg.database.path)
    identity = IdentityService(db, cfg)
    manager = attach_vault_manager(identity, cfg)
    try:
        identity.create_user("dan", password="pw")
        assert not manager.exists("dan")
    finally:
        manager.close()


def test_no_manager_no_provisioning(main_vault: Path, tmp_path: Path):
    """A DB-only IdentityService (no manager attached) touches no filesystem."""
    cfg = _cfg(main_vault, tmp_path)
    identity = IdentityService(Database(cfg.database.path), cfg)
    identity.create_user("erin", password="pw")
    assert not (tmp_path / "data" / "vaults" / "erin").exists()


# -- sync / index iterate all vaults -----------------------------------------

def test_run_sync_all_covers_every_vault(main_vault: Path, tmp_path: Path):
    from cortex.cli import run_sync_all

    cfg = _cfg(main_vault, tmp_path)
    mgr = VaultManager(cfg)
    mgr.provision("alice")
    mgr.provision("bob")
    mgr.close()

    results = run_sync_all(cfg)
    ids = [vid for vid, _ in results]
    assert ids == [MAIN_VAULT_ID, "alice", "bob"]
    for _vid, summary in results:
        assert not isinstance(summary, Exception)
        assert summary["remote"] == "skipped"


def test_run_sync_all_isolates_a_failing_vault(main_vault: Path, tmp_path: Path):
    from cortex.cli import run_sync_all

    cfg = _cfg(main_vault, tmp_path)
    mgr = VaultManager(cfg)
    mgr.provision("good")
    mgr.provision("broken")
    mgr.close()

    # Corrupt one vault's git repo (still a listed directory, so it IS
    # iterated) by replacing its .git with garbage — the snapshot commit for
    # it raises, and the others must still complete.
    import shutil

    broken_git = tmp_path / "data" / "vaults" / "broken" / ".git"
    shutil.rmtree(broken_git)
    broken_git.write_text("gitdir: nowhere-corrupt\n", encoding="utf-8")

    results = dict(run_sync_all(cfg))
    assert isinstance(results["broken"], Exception)
    assert not isinstance(results[MAIN_VAULT_ID], Exception)
    assert not isinstance(results["good"], Exception)


def test_cmd_index_iterates_all_vaults(main_vault: Path, tmp_path: Path, capsys):
    from cortex.cli import main as cli_main

    cfg_path = tmp_path / "cortex.yaml"
    cfg_path.write_text(
        "vault:\n"
        f"  path: {main_vault}\n"
        "vaults:\n"
        f"  root: {tmp_path / 'data' / 'vaults'}\n"
        f"  index_dir: {tmp_path / 'data' / 'indexes'}\n"
        "database:\n"
        f"  path: {tmp_path / 'data' / 'cortex.sqlite'}\n"
        "index:\n"
        f"  path: {tmp_path / 'cortex.index.sqlite'}\n",
        encoding="utf-8",
    )
    VaultManager(load_config(cfg_path)).provision("alice")

    rc = cli_main(["-c", str(cfg_path), "index"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "vault 'main'" in out
    assert "vault 'alice'" in out


# -- pure-v1 backward compatibility ------------------------------------------

def test_v1_config_has_default_vaults_section(tmp_path: Path):
    """A config with no vaults:/database: block loads with defaults and the
    single-vault behavior is untouched."""
    cfg_path = tmp_path / "cortex.yaml"
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()
    cfg_path.write_text(
        "vault:\n" f"  path: {vault_dir}\n", encoding="utf-8"
    )
    cfg = load_config(cfg_path)
    # Defaults resolve next to the config file.
    assert cfg.vaults.root == (tmp_path / "data" / "vaults").resolve()
    assert cfg.vaults.auto_provision is True
    assert cfg.vaults.sync.adapter == "none"


def test_per_vault_sync_override_and_default(tmp_path: Path):
    cfg_path = tmp_path / "cortex.yaml"
    (tmp_path / "main").mkdir()
    cfg_path.write_text(
        "vault:\n"
        "  path: main\n"
        "vaults:\n"
        "  sync:\n"
        "    adapter: git\n"
        "    options: {remote: origin}\n"
        "  sync_overrides:\n"
        "    alice:\n"
        "      adapter: s3\n"
        "      options: {bucket: alice-notes}\n",
        encoding="utf-8",
    )
    manager = VaultManager(load_config(cfg_path))
    assert manager.sync_config_for("alice").adapter == "s3"
    assert manager.sync_config_for("alice").options == {"bucket": "alice-notes"}
    assert manager.sync_config_for("bob").adapter == "git"
    assert manager.sync_config_for("bob").options == {"remote": "origin"}


def test_manager_construction_creates_nothing(main_vault: Path, tmp_path: Path):
    """Constructing a manager must not scaffold the vaults root — a pure-v1
    deployment that never provisions never grows a data/vaults tree."""
    cfg = _cfg(main_vault, tmp_path)
    VaultManager(cfg)
    assert not (tmp_path / "data" / "vaults").exists()
    assert manager_user_vaults_empty(cfg)


def manager_user_vaults_empty(cfg: CortexConfig) -> bool:
    mgr = VaultManager(cfg)
    try:
        return mgr.user_vault_ids() == []
    finally:
        mgr.close()
