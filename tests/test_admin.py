"""Admin UI/store tests: generated admin account, roles, clients, and auth."""

from __future__ import annotations

from pathlib import Path

from cortex.admin import AdminStore
from cortex.auth import Authenticator
from cortex.config import AdminConfig, CortexConfig, Principal, ServerConfig, VaultConfig, load_config
from cortex.server import build_http_server


def test_admin_store_initializes_once_and_authenticates(tmp_path: Path):
    store = AdminStore(tmp_path / "cortex.admin.json")
    password = store.ensure_initialized()

    assert password
    assert store.authenticate_admin("admin", password)
    assert not store.authenticate_admin("admin", "wrong")
    assert store.ensure_initialized() is None
    assert store.path.stat().st_mode & 0o777 == 0o600


def test_admin_created_client_becomes_scoped_principal(tmp_path: Path):
    store = AdminStore(tmp_path / "cortex.admin.json")
    store.ensure_initialized()
    store.add_role("alpha", ["Projects/Alpha/**"])
    created = store.create_client("claude-alpha", "alpha")

    principal = store.principal_for_token(created.token)
    assert principal is not None
    assert principal.name == "claude-alpha"
    assert principal.scopes == ["Projects/Alpha/**"]
    assert store.principal_for_token("bogus") is None
    assert created.token not in store.path.read_text(encoding="utf-8")


def test_authenticator_accepts_admin_client_tokens(tmp_path: Path):
    vault = tmp_path / "vault"
    vault.mkdir()
    store = AdminStore(tmp_path / "cortex.admin.json")
    store.ensure_initialized()
    token = store.create_client("bot", "public").token
    cfg = CortexConfig(
        vault=VaultConfig(path=vault),
        principals=[Principal(name="static", scopes=["**"], token="static-token")],
        admin=AdminConfig(enabled=True, path=store.path),
    )

    auth = Authenticator(cfg, admin_store=store)
    assert auth.for_token("static-token").name == "static"
    dynamic = auth.for_token(token)
    assert dynamic.name == "bot"
    assert dynamic.scopes == ["Public/**"]


def test_http_can_start_with_admin_enabled_and_no_static_principals(tmp_path: Path):
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "Public").mkdir()
    (vault / "Public" / "open.md").write_text("# Open\n", encoding="utf-8")
    cfg_file = tmp_path / "cortex.yaml"
    cfg_file.write_text(
        "vault:\n  path: ./vault\n"
        "server:\n  transport: http\n"
        "admin:\n  enabled: true\n  path: ./cortex.admin.json\n",
        encoding="utf-8",
    )

    cfg = load_config(cfg_file)
    assert cfg.admin.enabled
    server = build_http_server(cfg)
    assert server.admin_store is not None
