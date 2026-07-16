"""Cortex command-line interface.

The same CLI is the entry point both on bare metal (a Debian/Proxmox container,
a laptop) and inside the Docker image — there is no separate launcher to
maintain. Config path resolves from ``--config``, then ``$CORTEX_CONFIG``, then
``./cortex.yaml``.

Commands:
    cortex serve     Run the MCP server (transport from config; default stdio).
    cortex init      Initialize the vault git repo + bootstrap snapshot commit.
    cortex log       Show recent audit commits.
    cortex check     Validate config and report the resolved setup.
    cortex index     Build/refresh the FTS5 search index and report stats.
    cortex sync      Snapshot pending vault changes, reindex, and (adapter:
                     git) pull/push across ALL vaults. Run on a timer.
    cortex vault     Manage per-user vaults (registry & provisioning):
                     list | provision | archive | delete.
    cortex db        Manage the SQLite identity/gateway database:
                     init | migrate | status | import-admin.
    cortex user      Manage local user accounts:
                     add | list | disable | enable | passwd | delete.
    cortex token     Manage per-user API bearer tokens:
                     mint | list | revoke.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .admin import AdminStore
from .config import ConfigError, CortexConfig, load_config
from .gitlog import GitAudit, GitError
from .search_index import SearchIndex
from .vault import VaultStore


def _resolve_config_path(arg: str | None) -> str:
    return arg or os.environ.get("CORTEX_CONFIG") or "cortex.yaml"


def _load(args: argparse.Namespace):
    path = _resolve_config_path(args.config)
    try:
        return load_config(path)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        raise SystemExit(2)


def cmd_check(args: argparse.Namespace) -> int:
    cfg = _load(args)
    store = VaultStore(cfg.vault.path)
    print(f"cortex {__version__}")
    print(f"  vault:        {cfg.vault.path} ({len(store.list_notes())} notes)")
    print(f"  git audit:    {'on' if cfg.vault.git.enabled else 'off'}")
    print(f"  sync adapter: {cfg.sync.adapter}")
    print(f"  transport:    {cfg.server.transport}")
    print(f"  admin UI:     {'enabled' if cfg.admin.enabled else 'off'}"
          f" ({cfg.admin.path})" if cfg.admin.enabled else "")
    if cfg.index.enabled:
        idx = SearchIndex(
            store, cfg.index.path, chunk_chars=cfg.index.chunk_chars, overlap=cfg.index.overlap
        )
        idx.ensure_fresh()
        stats = idx.stats()
        backend = "fts5+bm25" if idx.fts_available else "substring-fallback (FTS5 unavailable)"
        print(
            f"  search index: enabled ({cfg.index.path}) [{backend}] "
            f"— {stats['note_count']} notes, {stats['chunk_count']} chunks, "
            f"last indexed {stats['last_indexed'] or 'never'}"
        )
        idx.close()
    else:
        print("  search index: disabled (falling back to substring search)")
    print(f"  llm provider: {cfg.llm.provider or 'none'} ({cfg.llm.model or '-'})")
    print(f"  janitor:      {'enabled' if cfg.janitor.enabled else 'dark'}"
          f"{' (dry-run)' if cfg.janitor.enabled and cfg.janitor.dry_run else ''}")
    print(f"  principals:   {', '.join(p.name for p in cfg.principals) or '(none)'}")
    print(f"  local principal: {cfg.auth.local_principal or '(none — stdio denied)'}")
    return 0


def cmd_index(args: argparse.Namespace) -> int:
    """Build/refresh the FTS5 search index for EVERY registered vault (main +
    per-user). One vault failing is reported but never aborts the others."""
    cfg = _load(args)
    if not cfg.index.enabled:
        print("search index is disabled in config (index.enabled: false); nothing to build.")
        return 0
    from .vaults import VaultManager

    manager = VaultManager(cfg)
    warned_fts = False
    failed = False
    try:
        for vault_id in manager.vault_ids():
            try:
                idx = manager.index_for(vault_id)
            except Exception as exc:  # noqa: BLE001 - isolate per-vault failure
                failed = True
                print(f"vault '{vault_id}': ERROR: {exc}", file=sys.stderr)
                continue
            if not idx.fts_available and not warned_fts:
                print(
                    "warning: SQLite FTS5 is not available in this environment; "
                    "ranked search will fall back to substring search.",
                    file=sys.stderr,
                )
                warned_fts = True
            if args.rebuild:
                idx.rebuild()
                verb = "rebuilt"
            else:
                idx.sync()
                verb = "refreshed"
            stats = idx.stats()
            print(
                f"vault '{vault_id}': {verb} index at {manager.index_path_for(vault_id)}"
            )
            print(f"  notes:        {stats['note_count']}")
            print(f"  chunks:       {stats['chunk_count']}")
            print(f"  last indexed: {stats['last_indexed'] or 'never'}")
    finally:
        manager.close()
    return 1 if failed else 0


def run_sync(cfg: CortexConfig) -> dict:
    """Snapshot any pending vault changes into the git audit trail, refresh
    the search index, and (adapter: git) best-effort pull/push. This is the
    core of ``cortex sync``, factored out so it's directly unit-testable
    without going through argparse/stdout — the timer-driven systemd path and
    the test suite both call this.

    Returns a summary dict:
        {
          "commit": str | None,        # sha of the snapshot commit, or None
                                        # if nothing had changed
          "index": dict | None,        # SearchIndex.stats(), or None if
                                        # index.enabled is false
          "remote": str,                # "skipped" | "ok" | "error" | "unsupported"
          "remote_detail": str | None,  # human-readable detail for the above
        }

    A remote failure (adapter: git, pull/push raises) is recorded but never
    raised — the local snapshot + reindex already succeeded and that's the
    durable, important half of the job.
    """
    git = GitAudit(cfg.vault.path, cfg.vault.git)
    index = None
    if cfg.index.enabled:
        index = SearchIndex(
            VaultStore(cfg.vault.path),
            cfg.index.path,
            chunk_chars=cfg.index.chunk_chars,
            overlap=cfg.index.overlap,
        )
    try:
        return _sync_core(
            git,
            index,
            git_enabled=cfg.vault.git.enabled,
            index_enabled=cfg.index.enabled,
            adapter=cfg.sync.adapter,
            options=cfg.sync.options or {},
        )
    finally:
        if index is not None:
            index.close()


def _sync_core(
    git: GitAudit,
    index,
    *,
    git_enabled: bool,
    index_enabled: bool,
    adapter: str,
    options: dict,
    actor: str = "cortex-sync",
    reason: str = "periodic snapshot",
) -> dict:
    """Snapshot + reindex + (adapter: git) pull/push for ONE vault's
    git/index pair. Factored out of :func:`run_sync` so both the single-vault
    path and the all-vaults iteration (:func:`run_sync_all`) share identical
    semantics. The caller owns the index's lifetime (open/close)."""
    commit_sha: str | None = None
    if git_enabled:
        git.ensure_repo()
        commit_sha = git.commit(actor=actor, reason=reason)

    index_stats: dict | None = None
    if index_enabled and index is not None:
        index.sync()
        index_stats = index.stats()

    remote = "skipped"
    remote_detail: str | None = None
    if adapter == "none":
        remote = "skipped"
    elif adapter == "git":
        remote_name = options.get("remote", "origin")
        branch = options.get("branch")
        try:
            git.pull_rebase(remote_name, branch)
            git.push(remote_name, branch)
            remote = "ok"
        except GitError as exc:
            remote = "error"
            remote_detail = str(exc)
    elif adapter in ("nextcloud", "s3"):
        remote = "unsupported"
        remote_detail = f"adapter '{adapter}' not implemented; local snapshot only"
    else:
        remote = "unsupported"
        remote_detail = f"unknown sync adapter '{adapter}'; local snapshot only"

    return {
        "commit": commit_sha,
        "index": index_stats,
        "remote": remote,
        "remote_detail": remote_detail,
    }


def run_sync_all(cfg: CortexConfig) -> list[tuple[str, dict | Exception]]:
    """Run :func:`_sync_core` over EVERY registered vault (main + per-user),
    returning ``(vault_id, summary_or_exception)`` pairs in registry order.

    A failure in one vault is captured and reported, never raised — so one
    broken user vault can't abort the sync of the rest (B4 leans on this).
    The per-vault sync adapter is the main vault's ``sync:`` block for the
    main vault and ``vaults.sync`` for each user vault."""
    from .vaults import VaultManager

    manager = VaultManager(cfg)
    results: list[tuple[str, dict | Exception]] = []
    try:
        for vault_id in manager.vault_ids():
            try:
                bundle = manager.get(vault_id)
                sc = manager.sync_config_for(vault_id)
                summary = _sync_core(
                    bundle.git,
                    bundle.index,
                    git_enabled=cfg.vault.git.enabled,
                    index_enabled=cfg.index.enabled,
                    adapter=sc.adapter,
                    options=sc.options or {},
                )
                results.append((vault_id, summary))
            except Exception as exc:  # noqa: BLE001 - isolate per-vault failure
                results.append((vault_id, exc))
    finally:
        manager.close()
    return results


def _print_sync_summary(vault_id: str, summary: dict) -> bool:
    """Print one vault's sync summary. Returns True if its remote errored."""
    print(f"vault '{vault_id}':")
    if summary["commit"]:
        print(f"  snapshot committed: {summary['commit'][:10]}")
    else:
        print("  nothing to commit (vault unchanged since last sync)")
    if summary["index"] is not None:
        idx = summary["index"]
        print(
            f"  index: {idx['note_count']} notes, {idx['chunk_count']} chunks, "
            f"last indexed {idx['last_indexed'] or 'never'}"
        )
    else:
        print("  index: disabled")
    if summary["remote"] == "ok":
        print("  remote: pulled/pushed")
    elif summary["remote"] == "skipped":
        print("  remote: skipped (adapter: none)")
    elif summary["remote"] == "error":
        print(f"  remote: FAILED — {summary['remote_detail']}", file=sys.stderr)
        return True
    elif summary["remote"] == "unsupported":
        print(f"  remote: {summary['remote_detail']}")
    return False


def cmd_sync(args: argparse.Namespace) -> int:
    """Snapshot + reindex + (adapter: git) pull/push across ALL registered
    vaults (main + per-user). One vault failing is reported but never aborts
    the others."""
    cfg = _load(args)
    results = run_sync_all(cfg)
    failed = False
    for vault_id, outcome in results:
        if isinstance(outcome, Exception):
            failed = True
            print(f"vault '{vault_id}':")
            print(f"  ERROR: {outcome}", file=sys.stderr)
            continue
        if _print_sync_summary(vault_id, outcome):
            failed = True
    return 1 if failed else 0


def _bootstrap_identity(cfg: CortexConfig) -> int:
    """Shared first-run identity bootstrap for ``cortex init`` and
    ``cortex db init``: create/migrate the database, import any legacy
    cortex.admin.json state, then ensure an admin user exists — printing the
    generated password exactly once. The DB is the source of truth for users
    (A4); the legacy admin.json is import-only from here on."""
    from .db import Database, import_admin_state
    from .users import IdentityService, bootstrap_admin
    from .vaults import attach_vault_manager

    db = Database(cfg.database.path)
    if cfg.admin.enabled and AdminStore(cfg.admin.path).exists():
        report = import_admin_state(db, cfg.admin.path)
        if report.changed:
            print(f"imported legacy admin state from {cfg.admin.path}")
    identity = IdentityService(db, cfg)
    manager = attach_vault_manager(identity, cfg)
    try:
        password = bootstrap_admin(identity)
        # Imported/existing users predate the attached manager; repair their
        # private vaults as part of the same idempotent first-run command.
        for user in identity.list_users():
            manager.provision(user["username"])
    finally:
        manager.close()
    if password:
        print(f"admin user created in {cfg.database.path}")
        print("admin username: admin")
        print(f"admin password: {password}")
        print("save this password now; Cortex stores only its hash.")
        print("(change it anytime with: cortex user passwd admin)")
    else:
        print("admin user already present in database.")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    cfg = _load(args)
    git = GitAudit(cfg.vault.path, cfg.vault.git)
    if cfg.vault.git.enabled:
        created = git.ensure_repo()
        sha = git.commit("cortex-bootstrap", "initial vault snapshot")
        if created:
            print(f"initialized git repo at {cfg.vault.path}")
        if sha:
            print(f"bootstrap snapshot committed: {sha[:10]}")
        else:
            print("nothing to commit (vault already snapshotted / empty)")
    else:
        print("git audit is disabled in config; skipping vault repo init.")
    return _bootstrap_identity(cfg)


def cmd_migrate(args: argparse.Namespace) -> int:
    """Idempotent v1 -> v2 adoption command (E1).

    Applies SQLite migrations, imports the legacy admin store exactly once,
    keeps ``vault.path`` as the main/shared vault, and repairs a private vault
    for every existing user.  It is safe to rerun after an interrupted
    upgrade.
    """
    cfg = _load(args)
    from .db import Database, import_admin_state
    from .users import IdentityService, bootstrap_admin
    from .vaults import attach_vault_manager

    db = Database(cfg.database.path)
    report = import_admin_state(db, cfg.admin.path)
    identity = IdentityService(db, cfg)
    bootstrap_password = bootstrap_admin(identity)
    manager = attach_vault_manager(identity, cfg)
    provisioned: list[str] = []
    repaired: list[str] = []
    try:
        for user in identity.list_users():
            outcome = manager.provision(user["username"])
            if outcome.created_dir:
                provisioned.append(user["username"])
            else:
                repaired.append(user["username"])
    finally:
        manager.close()
    print(f"database: {cfg.database.path} (schema {db.schema_version()})")
    print(f"main vault adopted: {cfg.vault.path}")
    print(
        "legacy admin import: "
        + ("applied" if report.changed else "already complete / nothing to import")
    )
    print(f"user vaults provisioned: {len(provisioned)}; checked: {len(repaired)}")
    if bootstrap_password:
        print("initial admin created: admin")
        print(f"admin password: {bootstrap_password}")
        print("save this password now; Cortex stores only its hash.")
    return 0


def cmd_db(args: argparse.Namespace) -> int:
    cfg = _load(args)
    # Imported here (like serve) to keep unrelated commands lean.
    from .db import Database, MigrationsPendingError, import_admin_state, latest_version
    from .db.core import schema_version_of

    path = cfg.database.path
    action = args.db_command

    if action == "status":
        if not path.exists():
            print(f"database: {path} (absent — run 'cortex db init')")
            return 0
        try:
            db = Database(path, auto_migrate=False)
        except MigrationsPendingError as exc:
            print(f"database: {path}")
            print(f"  schema:  BEHIND — {exc}")
            return 1
        print(f"database: {path}")
        print(f"  schema:  version {db.schema_version()} (latest {latest_version()})")
        for table, count in db.table_counts().items():
            print(f"  {table}: {count} row(s)")
        return 0

    if action in ("init", "migrate"):
        existed = path.exists()
        version_before = schema_version_of(path)
        db = Database(path)  # opens, checks version, applies pending forward
        version_after = db.schema_version()
        if not existed:
            print(f"created database at {path}")
        if version_after > version_before:
            print(f"applied migrations: {version_before} -> {version_after}")
        else:
            print(f"schema up to date (version {version_after})")
        if action == "init":
            report = import_admin_state(db, cfg.admin.path)
            if report.changed:
                created = (
                    len(report.users_created)
                    + len(report.groups_created)
                    + len(report.tokens_created)
                )
                print(
                    f"imported legacy admin state from {cfg.admin.path}: "
                    f"{created} row(s) created"
                )
            elif not report.warnings:
                print("legacy admin state already imported (or empty).")
            # First-run admin bootstrap (A4): the DB is the source of truth
            # for users, so `db init` guarantees an admin exists.
            from .users import IdentityService, bootstrap_admin
            from .vaults import attach_vault_manager

            identity = IdentityService(db, cfg)
            manager = attach_vault_manager(identity, cfg)
            try:
                password = bootstrap_admin(identity)
                for user in identity.list_users():
                    manager.provision(user["username"])
            finally:
                manager.close()
            if password:
                print("admin username: admin")
                print(f"admin password: {password}")
                print("save this password now; Cortex stores only its hash.")
        return 0

    if action == "import-admin":
        db = Database(path)
        report = import_admin_state(db, cfg.admin.path)
        for name in report.users_created:
            print(f"  user created:  {name}")
        for name in report.groups_created:
            print(f"  group created: {name} (from role)")
        for name in report.tokens_created:
            print(f"  token imported: {name}")
        for name in report.memberships_added:
            print(f"  membership:    {name}")
        skipped = (
            len(report.users_skipped)
            + len(report.groups_skipped)
            + len(report.tokens_skipped)
        )
        if skipped:
            print(f"  skipped (already present): {skipped}")
        for warning in report.warnings:
            print(f"  warning: {warning}", file=sys.stderr)
        if not report.changed and not report.warnings:
            print("nothing to import (already up to date).")
        return 0

    print(f"unknown db command: {action}", file=sys.stderr)
    return 2


def _identity(cfg: CortexConfig):
    """Open the identity service over the configured database. The CLI acts
    as the trusted local operator (cortex.users.OPERATOR) — running it on
    the server box is the same trust level as editing cortex.yaml."""
    from .db import Database
    from .users import IdentityService

    if not cfg.database.path.exists():
        print(
            f"database not found: {cfg.database.path} (run 'cortex db init' first)",
            file=sys.stderr,
        )
        raise SystemExit(2)
    identity = IdentityService(Database(cfg.database.path), cfg)
    # Attach the vault registry so `cortex user add` provisions the new user's
    # per-user vault (B1). Cheap: constructs no directories until a user is
    # actually created.
    from .vaults import attach_vault_manager

    attach_vault_manager(identity, cfg)
    return identity


def _read_password(args: argparse.Namespace, *, confirm: bool) -> str:
    """Password from --password, else an interactive prompt."""
    if getattr(args, "password", None):
        return args.password
    import getpass

    first = getpass.getpass("Password: ")
    if confirm and getpass.getpass("Repeat password: ") != first:
        print("passwords do not match", file=sys.stderr)
        raise SystemExit(2)
    return first


def cmd_user(args: argparse.Namespace) -> int:
    from .users import AuthzError, IdentityError

    cfg = _load(args)
    identity = _identity(cfg)
    action = args.user_command
    try:
        if action == "add":
            password = _read_password(args, confirm=True)
            user = identity.create_user(
                args.username,
                password=password,
                display_name=args.display_name,
                email=args.email,
                is_admin=args.admin,
            )
            kind = "admin user" if user["is_admin"] else "user"
            print(f"created {kind} '{user['username']}' (id {user['id']})")
            return 0
        if action == "list":
            users = identity.list_users()
            if not users:
                print("no users.")
                return 0
            for u in users:
                flags = []
                if u["is_admin"]:
                    flags.append("admin")
                if u["disabled"]:
                    flags.append("disabled")
                suffix = f" [{', '.join(flags)}]" if flags else ""
                print(f"{u['username']}  ({u['auth_source']}){suffix}")
            return 0
        if action == "disable":
            identity.disable_user(args.username)
            print(f"disabled user '{args.username}' (sessions revoked)")
            return 0
        if action == "enable":
            identity.enable_user(args.username)
            print(f"enabled user '{args.username}'")
            return 0
        if action == "passwd":
            identity.set_password(args.username, _read_password(args, confirm=True))
            print(f"password updated for '{args.username}'")
            return 0
        if action == "delete":
            identity.delete_user(args.username)
            print(f"deleted user '{args.username}' (sessions and tokens removed)")
            return 0
    except (IdentityError, AuthzError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"unknown user command: {action}", file=sys.stderr)
    return 2


def cmd_token(args: argparse.Namespace) -> int:
    from .users import AuthzError, IdentityError

    cfg = _load(args)
    identity = _identity(cfg)
    action = args.token_command
    try:
        if action == "mint":
            created = identity.mint_token(
                args.username,
                args.name,
                scopes=args.scope or None,
                expires_in=args.expires_in,
            )
            print(f"token '{created.name}' minted for '{args.username}'.")
            print("copy it now; Cortex stores only its hash and will not show it again:")
            print(created.token)
            return 0
        if action == "list":
            rows = identity.list_tokens(args.username)
            if not rows:
                print(f"no tokens for '{args.username}'.")
                return 0
            for t in rows:
                state = "revoked" if t["revoked_at"] else "active"
                if state == "active" and t["expires_at"]:
                    state = f"expires at {t['expires_at']}"
                print(f"{t['name']}  {t['token_prefix']}…  [{state}]")
            return 0
        if action == "revoke":
            revoked = identity.revoke_token(args.username, args.name)
            if revoked:
                print(f"revoked {revoked} token(s) named '{args.name}' for '{args.username}'")
                return 0
            print(f"no active token named '{args.name}' for '{args.username}'", file=sys.stderr)
            return 1
    except (IdentityError, AuthzError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"unknown token command: {action}", file=sys.stderr)
    return 2


def cmd_vault(args: argparse.Namespace) -> int:
    """Manage per-user vaults: provision (create/repair), list, archive (move
    aside, keeping git history), delete (guarded — needs --force)."""
    cfg = _load(args)
    from .vaults import VaultManager, VaultManagerError

    manager = VaultManager(cfg)
    action = args.vault_command
    try:
        if action == "list":
            ids = manager.vault_ids()
            for vault_id in ids:
                root = manager.root_for(vault_id)
                present = "provisioned" if manager.exists(vault_id) else "MISSING"
                tag = " (main/shared)" if vault_id == "main" else ""
                print(f"{vault_id}{tag}  {root}  [{present}]")
            return 0
        if action == "provision":
            result = manager.provision(args.username)
            if result.created_dir or result.seeded or result.commit:
                print(f"provisioned vault '{result.vault_id}' at {result.root}")
                if result.initialized_git:
                    print("  git repo initialized")
                if result.seeded:
                    print("  seeded initial skeleton")
                if result.commit:
                    print(f"  baseline commit: {result.commit[:10]}")
            else:
                print(
                    f"vault '{result.vault_id}' already provisioned at "
                    f"{result.root} (no changes)"
                )
            return 0
        if action == "repair":
            result = manager.repair(args.vault)
            print(f"repaired vault '{result.vault_id}' at {result.root}")
            if result.initialized_git:
                print("  restored git audit repository")
            if result.baseline_commit:
                print(f"  baseline commit: {result.baseline_commit[:10]}")
            print(f"  rebuilt index: {result.indexed_notes} note(s)")
            return 0
        if action == "archive":
            dest = manager.archive(args.username)
            print(f"archived vault '{args.username}' to {dest}")
            print("(git history preserved; the vault is out of the live registry)")
            return 0
        if action == "delete":
            if not args.force:
                print(
                    f"refusing to delete vault '{args.username}' without --force. "
                    "Prefer 'cortex vault archive' (moves it aside, keeps git "
                    "history); pass --force to destroy it irreversibly.",
                    file=sys.stderr,
                )
                return 2
            manager.delete(args.username, force=True)
            print(f"permanently deleted vault '{args.username}' and its index")
            return 0
    except VaultManagerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        manager.close()
    print(f"unknown vault command: {action}", file=sys.stderr)
    return 2


def cmd_ldap(args: argparse.Namespace) -> int:
    cfg = _load(args)
    if cfg.ldap is None:
        print(
            "ldap is not configured — add an 'ldap:' block to cortex.yaml "
            "(see cortex.example.yaml)",
            file=sys.stderr,
        )
        return 2
    from .ldap import DirectoryService, LdapClient, LdapError, LdapUnavailableError

    action = args.ldap_command
    try:
        if action == "check":
            LdapClient(cfg.ldap).check()
            print(f"ok: service-account bind to {cfg.ldap.server_uri} succeeded")
            return 0
        if action == "sync":
            identity = _identity(cfg)
            report = DirectoryService(identity, cfg.ldap).sync(dry_run=args.dry_run)
            prefix = "would " if report.dry_run else ""
            sections = (
                (f"{prefix}add", "+", report.added),
                (f"{prefix}update", "~", report.updated),
                (f"{prefix}disable", "-", report.disabled),
                ("group changes", "", report.group_changes),
            )
            for label, marker, items in sections:
                print(f"{label}: {len(items)}")
                for item in items:
                    print(f"  {marker}{' ' if marker else ''}{item}")
            for reason in report.skipped:
                print(f"  skipped: {reason}", file=sys.stderr)
            if report.dry_run:
                print("dry run: nothing was written.")
            elif not report.changed:
                print("already in sync.")
            return 0
    except LdapUnavailableError as exc:
        print(
            f"error: {exc}\n(directory unreachable — nothing was changed; "
            "local logins are unaffected)",
            file=sys.stderr,
        )
        return 1
    except LdapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"unknown ldap command: {action}", file=sys.stderr)
    return 2


def cmd_log(args: argparse.Namespace) -> int:
    cfg = _load(args)
    git = GitAudit(cfg.vault.path, cfg.vault.git)
    commits = git.log(limit=args.limit)
    if not commits:
        print("no audit history yet (run 'cortex init').")
        return 0
    for c in commits:
        print(f"{c.sha[:10]}  {c.iso_date[:10]}  {c.subject}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    cfg = _load(args)
    # Import here so 'cortex check/init/log' don't require the mcp package.
    if cfg.server.transport == "stdio":
        from .server import build_stdio_server

        server = build_stdio_server(cfg)
        print(
            f"cortex serving vault '{cfg.vault.path}' over stdio "
            f"as principal '{server.principal.name}'",
            file=sys.stderr,
        )
        server.run_stdio()
        return 0

    from .server import build_http_server

    sc = cfg.server
    base = sc.public_url or f"http://{sc.host}:{sc.port}"
    server = build_http_server(cfg)
    print(
        f"cortex serving vault '{cfg.vault.path}' over streamable-http at "
        f"{sc.host}:{sc.port}{sc.path} (public: {base}{sc.path}); "
        f"{len([p for p in cfg.principals if p.token])} bearer principal(s). "
        "Terminate TLS at a reverse proxy in front of this.",
        file=sys.stderr,
    )
    server.run_http()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cortex", description="Cortex dynamic memory layer")
    p.add_argument("--version", action="version", version=f"cortex {__version__}")
    p.add_argument("-c", "--config", help="path to cortex.yaml (or $CORTEX_CONFIG)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="validate config and report setup").set_defaults(func=cmd_check)
    sub.add_parser("init", help="init git repo + bootstrap snapshot").set_defaults(func=cmd_init)
    sub.add_parser("serve", help="run the MCP server").set_defaults(func=cmd_serve)
    sub.add_parser(
        "migrate",
        help="idempotently upgrade/adopt a v1 install into the v2 data layout",
    ).set_defaults(func=cmd_migrate)

    pl = sub.add_parser("log", help="show recent audit commits")
    pl.add_argument("-n", "--limit", type=int, default=20)
    pl.set_defaults(func=cmd_log)

    pi = sub.add_parser("index", help="build/refresh the FTS5 search index")
    pi.add_argument("--rebuild", action="store_true", help="drop and rebuild the index from scratch")
    pi.set_defaults(func=cmd_index)

    sub.add_parser(
        "sync", help="snapshot pending vault changes, reindex, and (adapter: git) pull/push"
    ).set_defaults(func=cmd_sync)

    pd = sub.add_parser("db", help="manage the SQLite identity/gateway database")
    pd_sub = pd.add_subparsers(dest="db_command", required=True)
    pd_sub.add_parser(
        "init",
        help="create the database, apply migrations, and import legacy admin state",
    ).set_defaults(func=cmd_db)
    pd_sub.add_parser("migrate", help="apply pending schema migrations").set_defaults(
        func=cmd_db
    )
    pd_sub.add_parser(
        "status", help="show schema version and table row counts"
    ).set_defaults(func=cmd_db)
    pd_sub.add_parser(
        "import-admin",
        help="import cortex.admin.json (admin login, roles, AI clients) into the database",
    ).set_defaults(func=cmd_db)

    pu = sub.add_parser("user", help="manage local user accounts")
    pu_sub = pu.add_subparsers(dest="user_command", required=True)
    pu_add = pu_sub.add_parser("add", help="create a local user")
    pu_add.add_argument("username")
    pu_add.add_argument("--admin", action="store_true", help="grant the admin flag")
    pu_add.add_argument("--display-name")
    pu_add.add_argument("--email")
    pu_add.add_argument("--password", help="password (omit to be prompted)")
    pu_add.set_defaults(func=cmd_user)
    pu_sub.add_parser("list", help="list users").set_defaults(func=cmd_user)
    for verb, help_text in (
        ("disable", "disable a user (revokes live sessions)"),
        ("enable", "re-enable a disabled user"),
        ("delete", "delete a user (sessions and tokens removed)"),
    ):
        sp = pu_sub.add_parser(verb, help=help_text)
        sp.add_argument("username")
        sp.set_defaults(func=cmd_user)
    pu_passwd = pu_sub.add_parser("passwd", help="set/reset a user's password")
    pu_passwd.add_argument("username")
    pu_passwd.add_argument("--password", help="new password (omit to be prompted)")
    pu_passwd.set_defaults(func=cmd_user)

    pld = sub.add_parser("ldap", help="LDAP / Active Directory integration")
    pld_sub = pld.add_subparsers(dest="ldap_command", required=True)
    pld_sub.add_parser(
        "check", help="verify directory connectivity (service-account bind)"
    ).set_defaults(func=cmd_ldap)
    pld_sync = pld_sub.add_parser(
        "sync",
        help="pull directory users into the DB and reconcile mapped groups "
        "(vanished users are disabled, never deleted; local users untouched)",
    )
    pld_sync.add_argument(
        "--dry-run",
        action="store_true",
        help="report adds/updates/disables/group changes without writing",
    )
    pld_sync.set_defaults(func=cmd_ldap)

    pv = sub.add_parser("vault", help="manage per-user vaults (registry & provisioning)")
    pv_sub = pv.add_subparsers(dest="vault_command", required=True)
    pv_sub.add_parser(
        "list", help="list registered vaults (main + per-user) and their paths"
    ).set_defaults(func=cmd_vault)
    pv_prov = pv_sub.add_parser(
        "provision", help="create/repair a user's vault (idempotent)"
    )
    pv_prov.add_argument("username")
    pv_prov.set_defaults(func=cmd_vault)
    pv_repair = pv_sub.add_parser(
        "repair", help="repair git/index state for main or a per-user vault"
    )
    pv_repair.add_argument("vault", help="vault id (main or username)")
    pv_repair.set_defaults(func=cmd_vault)
    pv_arch = pv_sub.add_parser(
        "archive",
        help="move a user's vault aside (archive_dir/<user>-<ts>), keeping git history",
    )
    pv_arch.add_argument("username")
    pv_arch.set_defaults(func=cmd_vault)
    pv_del = pv_sub.add_parser(
        "delete", help="permanently delete a user's vault (guarded — needs --force)"
    )
    pv_del.add_argument("username")
    pv_del.add_argument(
        "--force",
        action="store_true",
        help="required: without it, delete refuses and points you at archive",
    )
    pv_del.set_defaults(func=cmd_vault)

    pt = sub.add_parser("token", help="manage per-user API bearer tokens")
    pt_sub = pt.add_subparsers(dest="token_command", required=True)
    pt_mint = pt_sub.add_parser("mint", help="mint a named token (shown once)")
    pt_mint.add_argument("username")
    pt_mint.add_argument("name", help="token label, e.g. 'claude-desktop'")
    pt_mint.add_argument(
        "--expires-in", type=int, help="lifetime in seconds (default: no expiry)"
    )
    pt_mint.add_argument(
        "--scope",
        action="append",
        help="optional narrowing path glob (repeatable); must be within the "
        "user's granted scopes to have any effect",
    )
    pt_mint.set_defaults(func=cmd_token)
    pt_list = pt_sub.add_parser("list", help="list a user's tokens")
    pt_list.add_argument("username")
    pt_list.set_defaults(func=cmd_token)
    pt_revoke = pt_sub.add_parser("revoke", help="revoke a user's token by name")
    pt_revoke.add_argument("username")
    pt_revoke.add_argument("name")
    pt_revoke.set_defaults(func=cmd_token)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
