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
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .config import ConfigError, load_config
from .gitlog import GitAudit
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
    print(f"  llm provider: {cfg.llm.provider or 'none'} ({cfg.llm.model or '-'})")
    print(f"  janitor:      {'enabled' if cfg.janitor.enabled else 'dark'}"
          f"{' (dry-run)' if cfg.janitor.enabled and cfg.janitor.dry_run else ''}")
    print(f"  principals:   {', '.join(p.name for p in cfg.principals) or '(none)'}")
    print(f"  local principal: {cfg.auth.local_principal or '(none — stdio denied)'}")
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
    return 0


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

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
