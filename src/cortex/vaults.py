"""Account-owned vault storage, Git audit and search indexes.

Every live vault is a named account directory under vaults.root. Legacy
vault.path is migration input only, never an implicit shared store. Old
clients requesting the retired global id fail closed instead of seeing
another account's notes. Storage lookup does not itself authorize a caller;
VaultAccessResolver enforces ownership and explicit administrator selection.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .config import CortexConfig, GitConfig, SyncConfig
from .gitlog import GitAudit
from .search_index import SearchIndex
from .vault import VaultStore

# Retired identifier: kept only to reject old clients and migrations safely.
MAIN_VAULT_ID = "main"

# Mirrors cortex.users._USERNAME_RE (the A4 charset): leading alphanumeric,
# then alphanumerics plus ``. _ -``; 1–64 chars; notably no ``:`` (subject
# namespacing), no ``/`` or ``\`` (path separators), no ``..`` possible. A
# test asserts this stays identical to the users module so the two never drift.
_VAULT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class VaultManagerError(Exception):
    """A registry/provisioning error (bad vault id, unknown vault, guarded
    delete without ``force``, path-escape attempt, ...)."""


def sanitize_vault_id(username: str) -> str:
    """Validate a username as a filesystem- and scope-safe vault id.

    Rejects anything that could escape the vaults root: traversal (``..``),
    path separators, absolute paths, and any character outside the strict A4
    charset. Returns the (stripped) id on success; raises
    :class:`VaultManagerError` otherwise. This is defense in depth on top of
    A4's own username validation — provisioning re-checks rather than trusting
    that the caller already did."""
    candidate = (username or "").strip()
    if candidate == MAIN_VAULT_ID:
        raise VaultManagerError(
            f"{MAIN_VAULT_ID!r} is a retired global vault id; select an account"
        )
    if not _VAULT_ID_RE.match(candidate):
        raise VaultManagerError(
            f"invalid vault id {username!r}: use 1-64 characters [A-Za-z0-9._-] "
            "starting with a letter or digit (no separators, no '..')"
        )
    return candidate


def user_actor(username: str, via: str = "mcp") -> str:
    """The per-vault commit actor for a user mutation (design §5): e.g.
    ``user:alice via mcp`` / ``user:alice via web``. Keeps GitAudit's
    actor+reason contract; B2 uses this when it commits user writes."""
    return f"user:{username} via {via}"


@dataclass
class VaultBundle:
    """The per-vault operating triple B2 asks the manager for. ``index`` holds
    an open SQLite connection; the manager caches and owns closing it."""

    vault_id: str
    root: Path
    store: VaultStore
    git: GitAudit
    index: SearchIndex


@dataclass
class ProvisionResult:
    """Outcome of :meth:`VaultManager.provision` (idempotent: re-provisioning
    an existing vault yields all-False flags and a None commit)."""

    vault_id: str
    root: Path
    created_dir: bool
    initialized_git: bool
    seeded: bool
    commit: str | None


@dataclass
class RepairResult:
    vault_id: str
    root: Path
    initialized_git: bool
    baseline_commit: str | None
    indexed_notes: int


class VaultManager:
    """Registry of account directories; no global vault is registered."""

    def __init__(self, config: CortexConfig):
        self.config = config
        self.vaults_cfg = config.vaults
        self.root = Path(config.vaults.root)
        self.index_dir = Path(config.vaults.index_dir)
        self._bundles: dict[str, VaultBundle] = {}

    # -- git config per vault -------------------------------------------------

    @property
    def _git_config(self) -> GitConfig:
        """Per-user vaults reuse the main vault's git identity/enable flag —
        the commit *actor* (not this default committer name) carries per-user
        attribution via :func:`user_actor`."""
        return self.config.vault.git

    # -- path resolution ------------------------------------------------------

    def root_for(self, vault_id: str) -> Path:
        """Validated account directory, contained in vaults.root."""
        safe = sanitize_vault_id(vault_id)
        candidate = self.root / safe
        if candidate.is_symlink():
            raise VaultManagerError("account vault cannot be a symlink")
        root = candidate.resolve()
        # Belt-and-suspenders: even a charset-valid id must resolve inside the
        # vaults root (guards against symlink/edge shenanigans in `self.root`).
        try:
            root.relative_to(self.root.resolve())
        except ValueError as exc:  # pragma: no cover - unreachable given the regex
            raise VaultManagerError(
                f"vault id {vault_id!r} escapes the vaults root"
            ) from exc
        return root

    def index_path_for(self, vault_id: str) -> Path:
        """Per-account rebuildable index, outside note storage."""
        safe = sanitize_vault_id(vault_id)
        return self.index_dir / f"{safe}.index.sqlite"

    # -- registry -------------------------------------------------------------

    def exists(self, vault_id: str) -> bool:
        """Whether a vault directory is present on disk."""
        try:
            return self.root_for(vault_id).is_dir()
        except VaultManagerError:
            return False

    def user_vault_ids(self) -> list[str]:
        """Provisioned per-user vault ids (directories under ``vaults.root``),
        sorted. Skips dotfiles and any non-charset-valid name."""
        root = self.root
        if not root.is_dir():
            return []
        ids: list[str] = []
        for child in sorted(root.iterdir()):
            if child.is_symlink() or not child.is_dir() or child.name.startswith(".") or child.name == MAIN_VAULT_ID:
                continue
            if _VAULT_ID_RE.match(child.name):
                ids.append(child.name)
        return ids

    def vault_ids(self) -> list[str]:
        """All provisioned account directories; never a global store."""
        return self.user_vault_ids()

    # -- the B2 lookup surface ------------------------------------------------

    def get(self, vault_id: str) -> VaultBundle:
        """The ``(VaultStore, GitAudit, SearchIndex)`` triple for a vault,
        cached per id. This is the single question B2 asks of the manager.

        Raises :class:`VaultManagerError` if the vault directory does not
        exist (a user vault must be provisioned first)."""
        key = sanitize_vault_id(vault_id)
        cached = self._bundles.get(key)
        if cached is not None:
            return cached
        root = self.root_for(key)
        if not root.is_dir():
            raise VaultManagerError(
                f"vault {key!r} is not provisioned (no directory at {root})"
            )
        store = VaultStore(root)
        git = GitAudit(root, self._git_config)
        index = SearchIndex(
            store,
            self.index_path_for(key),
            chunk_chars=self.config.index.chunk_chars,
            overlap=self.config.index.overlap,
            enabled=self.config.index.enabled,
        )
        bundle = VaultBundle(
            vault_id=key,
            root=root,
            store=store,
            git=git,
            index=index,
        )
        self._bundles[key] = bundle
        return bundle

    def store_for(self, vault_id: str) -> VaultStore:
        return self.get(vault_id).store

    def git_for(self, vault_id: str) -> GitAudit:
        return self.get(vault_id).git

    def index_for(self, vault_id: str) -> SearchIndex:
        return self.get(vault_id).index

    def sync_config_for(self, vault_id: str) -> SyncConfig:
        """Account-specific sync override, otherwise the per-account default."""
        safe = sanitize_vault_id(vault_id)
        if safe in self.vaults_cfg.sync_overrides:
            return self.vaults_cfg.sync_overrides[safe]
        return self.vaults_cfg.sync

    # -- provisioning ---------------------------------------------------------

    def provision(
        self, username: str, *, seed: bool = True, via: str = "provision"
    ) -> ProvisionResult:
        """Provision a user's vault: mkdir, ``git init`` + baseline commit, and
        (optionally) a template/welcome skeleton. **Idempotent** — a second
        call on an already-provisioned vault makes no changes and returns
        all-False flags with a None commit.

        Seeding only happens when the vault holds no notes yet, so a
        re-provision of a vault a user has since written to never clobbers it.
        """
        vault_id = sanitize_vault_id(username)
        root = self.root_for(vault_id)

        created_dir = not root.exists()
        root.mkdir(parents=True, exist_ok=True)

        store = VaultStore(root)
        seeded = False
        if seed and not store.list_notes():
            self._seed(root)
            seeded = True

        git = GitAudit(root, self._git_config)
        initialized_git = False
        commit: str | None = None
        if self._git_config.enabled:
            initialized_git = git.ensure_repo()
            commit = git.commit(
                actor="cortex-bootstrap",
                reason=f"provision vault for {vault_id}",
            )

        # A cached bundle (e.g. from a prior `get`) predates the seed/commit;
        # drop it so the next lookup rebuilds against the now-populated vault.
        self._invalidate(vault_id)
        return ProvisionResult(
            vault_id=vault_id,
            root=root,
            created_dir=created_dir,
            initialized_git=initialized_git,
            seeded=seeded,
            commit=commit,
        )

    def repair(self, vault_id: str) -> RepairResult:
        """Repair the rebuildable/derived parts of any live vault.

        A missing git repository is initialized and baselined; an existing
        repository's pending human edits are deliberately left untouched.
        The search index is rebuilt from the current Markdown source of truth.
        """
        bundle = self.get(vault_id)
        initialized = False
        commit = None
        if self._git_config.enabled:
            initialized = bundle.git.ensure_repo()
            if initialized:
                commit = bundle.git.commit(
                    actor="cortex-repair",
                    reason=f"restore audit baseline for {bundle.vault_id}",
                )
        bundle.index.rebuild()
        return RepairResult(
            vault_id=bundle.vault_id,
            root=bundle.root,
            initialized_git=initialized,
            baseline_commit=commit,
            indexed_notes=bundle.index.stats()["note_count"],
        )

    def _seed(self, root: Path) -> None:
        """Lay down the initial skeleton: copy the configured template dir if
        set (excluding any ``.git``/dotfiles), else a single welcome note."""
        template = self.vaults_cfg.template_dir
        if template is not None and Path(template).is_dir():
            shutil.copytree(
                template,
                root,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(".git", ".*"),
            )
            return
        welcome = root / "Welcome.md"
        if not welcome.exists():
            welcome.write_text(
                "---\ntitle: Welcome\n---\n"
                "# Welcome to your Cortex vault\n\n"
                "This is your personal, private vault. Notes you keep here are "
                "yours alone; every change is committed to this vault's own git "
                "history.\n",
                encoding="utf-8",
            )

    # -- lifecycle: archive / delete ------------------------------------------

    def archive(self, username: str, *, timestamp: str | None = None) -> Path:
        """Archive-not-delete: MOVE a user's vault (git history and all) to
        ``vaults.archive_dir/<username>-<timestamp>/`` and drop its search
        index. The vault leaves the live registry but nothing is destroyed —
        the deletes-off-by-default ethos. Returns the archive path."""
        vault_id = sanitize_vault_id(username)
        root = self.root_for(vault_id)
        if not root.is_dir():
            raise VaultManagerError(f"vault {vault_id!r} is not provisioned")
        self._teardown_index(vault_id)
        self._invalidate(vault_id)
        stamp = timestamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        archive_root = Path(self.vaults_cfg.archive_dir)
        archive_root.mkdir(parents=True, exist_ok=True)
        dest = archive_root / f"{vault_id}-{stamp}"
        shutil.move(str(root), str(dest))
        return dest

    def delete(self, username: str, *, force: bool = False) -> Path | None:
        """Guarded destroy. Without ``force`` this **refuses** and points at
        :meth:`archive` (deletes are off by default). With ``force=True`` it
        permanently removes the vault directory and its index — an explicit,
        irreversible admin action."""
        vault_id = sanitize_vault_id(username)
        root = self.root_for(vault_id)
        if not root.is_dir():
            raise VaultManagerError(f"vault {vault_id!r} is not provisioned")
        if not force:
            raise VaultManagerError(
                f"refusing to permanently delete vault {vault_id!r}: archive it "
                "instead (moves it aside, preserving git history), or pass "
                "force=True to destroy it irreversibly"
            )
        self._teardown_index(vault_id)
        self._invalidate(vault_id)
        shutil.rmtree(root)
        return root

    # -- cache management -----------------------------------------------------

    def _teardown_index(self, vault_id: str) -> None:
        """Close and delete a vault's rebuildable index cache (main vault's
        index is left alone — it is never archived/deleted here)."""
        cached = self._bundles.get(vault_id)
        if cached is not None:
            cached.index.close()
        idx_path = self.index_path_for(vault_id)
        for suffix in ("", "-wal", "-shm", "-journal"):
            p = Path(str(idx_path) + suffix)
            if p.exists():
                p.unlink()

    def _invalidate(self, vault_id: str) -> None:
        bundle = self._bundles.pop(vault_id, None)
        if bundle is not None:
            bundle.index.close()

    def close(self) -> None:
        """Close every cached vault's search index. Long-lived servers keep the
        manager open; CLI iterations call this when done."""
        for bundle in self._bundles.values():
            bundle.index.close()
        self._bundles.clear()


def attach_vault_manager(identity, config: CortexConfig | None = None) -> VaultManager:
    """Build a :class:`VaultManager` and wire it into an
    :class:`~cortex.users.IdentityService` so user creation provisions the
    user's vault (B1). Kept here (not in ``users``) to avoid an import cycle:
    ``vaults`` imports ``config``; ``users`` never needs to import ``vaults``.
    Returns the manager for callers that also want to iterate/look up vaults."""
    cfg = config if config is not None else identity.config
    if cfg is None:
        raise VaultManagerError("a CortexConfig is required to build a VaultManager")
    manager = VaultManager(cfg)
    identity.vault_manager = manager
    return manager
