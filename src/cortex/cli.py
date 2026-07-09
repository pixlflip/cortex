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
                     git) pull/push. Intended to be run on a timer.
    cortex db        Manage the SQLite identity/gateway database:
                     init | migrate | status | import-admin.
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
    cfg = _load(args)
    store = VaultStore(cfg.vault.path)
    if not cfg.index.enabled:
        print("search index is disabled in config (index.enabled: false); nothing to build.")
        return 0
    idx = SearchIndex(
        store, cfg.index.path, chunk_chars=cfg.index.chunk_chars, overlap=cfg.index.overlap
    )
    if not idx.fts_available:
        print(
            "warning: SQLite FTS5 is not available in this environment; "
            "ranked search will fall back to substring search.",
            file=sys.stderr,
        )
    if args.rebuild:
        idx.rebuild()
        print(f"rebuilt search index at {cfg.index.path}")
    else:
        idx.sync()
        print(f"refreshed search index at {cfg.index.path}")
    stats = idx.stats()
    print(f"  notes:        {stats['note_count']}")
    print(f"  chunks:       {stats['chunk_count']}")
    print(f"  last indexed: {stats['last_indexed'] or 'never'}")
    idx.close()
    return 0


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
    commit_sha: str | None = None
    if cfg.vault.git.enabled:
        git.ensure_repo()
        commit_sha = git.commit(actor="cortex-sync", reason="periodic snapshot")

    index_stats: dict | None = None
    if cfg.index.enabled:
        idx = SearchIndex(
            VaultStore(cfg.vault.path),
            cfg.index.path,
            chunk_chars=cfg.index.chunk_chars,
            overlap=cfg.index.overlap,
        )
        idx.sync()
        index_stats = idx.stats()
        idx.close()

    remote = "skipped"
    remote_detail: str | None = None
    adapter = cfg.sync.adapter
    if adapter == "none":
        remote = "skipped"
    elif adapter == "git":
        options = cfg.sync.options or {}
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


def cmd_sync(args: argparse.Namespace) -> int:
    cfg = _load(args)
    summary = run_sync(cfg)
    if summary["commit"]:
        print(f"snapshot committed: {summary['commit'][:10]}")
    else:
        print("nothing to commit (vault unchanged since last sync)")
    if summary["index"] is not None:
        idx = summary["index"]
        print(
            f"  index: {idx['note_count']} notes, {idx['chunk_count']} chunks, "
            f"last indexed {idx['last_indexed'] or 'never'}"
        )
    else:
        print("  index: disabled")
    if summary["remote"] == "ok":
        print(f"  remote: pulled/pushed ({cfg.sync.adapter})")
    elif summary["remote"] == "skipped":
        print("  remote: skipped (sync.adapter: none)")
    elif summary["remote"] == "error":
        print(f"  remote: FAILED — {summary['remote_detail']}", file=sys.stderr)
    elif summary["remote"] == "unsupported":
        print(f"  remote: {summary['remote_detail']}")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    cfg = _load(args)
    git = GitAudit(cfg.vault.path, cfg.vault.git)
    if not cfg.vault.git.enabled:
        print("git audit is disabled in config; nothing to initialize.")
        return 0
    created = git.ensure_repo()
    sha = git.commit("cortex-bootstrap", "initial vault snapshot")
    if created:
        print(f"initialized git repo at {cfg.vault.path}")
    if sha:
        print(f"bootstrap snapshot committed: {sha[:10]}")
    else:
        print("nothing to commit (vault already snapshotted / empty)")
    if cfg.admin.enabled:
        password = AdminStore(cfg.admin.path).ensure_initialized()
        if password:
            print(f"admin UI initialized at {cfg.admin.path}")
            print(f"admin username: admin")
            print(f"admin password: {password}")
            print("save this password now; Cortex stores only its hash.")
        else:
            print(f"admin UI already initialized at {cfg.admin.path}")
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

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
