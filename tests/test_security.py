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


# -- #7 / #19: admin auth + cookie hardening -------------------------------------

def _fake_request(path: str = "/admin", cookie: str | None = None):
    from starlette.requests import Request

    headers = []
    if cookie is not None:
        headers.append((b"cookie", f"cortex_admin={cookie}".encode()))
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "headers": headers,
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
    }
    return Request(scope)


def test_uninitialized_store_has_no_cookie_secret(tmp_path: Path):
    from cortex.admin import AdminNotInitializedError, AdminStore

    store = AdminStore(tmp_path / "cortex.admin.json")
    with pytest.raises(AdminNotInitializedError):
        store.cookie_secret()


def test_admin_ui_refuses_until_initialized(tmp_path: Path):
    from cortex.admin import AdminStore, AdminUI

    store = AdminStore(tmp_path / "cortex.admin.json")
    ui = AdminUI(store, "http://127.0.0.1:8765")
    resp = asyncio.run(ui.handle(_fake_request()))
    assert resp.status_code == 503

    store.ensure_initialized()
    resp = asyncio.run(ui.handle(_fake_request()))
    assert resp.status_code == 200  # login page now served


def test_cookie_secret_is_random_not_password_hash(tmp_path: Path):
    from cortex.admin import AdminStore

    store = AdminStore(tmp_path / "cortex.admin.json")
    store.ensure_initialized()
    data = store.load()
    secret = store.cookie_secret()
    assert secret
    assert secret != data["admin"]["password_hash"]
    assert secret != "uninitialized"
    # Two installs never share a secret.
    other = AdminStore(tmp_path / "other.admin.json")
    other.ensure_initialized()
    assert other.cookie_secret() != secret


def test_cookie_secret_migrated_for_legacy_state(tmp_path: Path):
    """A pre-hardening state file (no cookie_secret) gets a random one minted
    on first use instead of falling back to the password hash."""
    from cortex.admin import AdminStore

    store = AdminStore(tmp_path / "cortex.admin.json")
    store.ensure_initialized()
    data = store.load()
    del data["admin"]["cookie_secret"]
    store.save(data)
    secret = store.cookie_secret()
    assert secret and secret != data["admin"]["password_hash"]
    assert store.load()["admin"]["cookie_secret"] == secret  # persisted


def test_admin_cookie_expires_and_rejects_tampering(tmp_path: Path, monkeypatch):
    import cortex.admin as admin_mod
    from cortex.admin import AdminStore, AdminUI, COOKIE_TTL

    store = AdminStore(tmp_path / "cortex.admin.json")
    store.ensure_initialized()
    ui = AdminUI(store, "http://127.0.0.1:8765")

    cookie = ui._sign("admin")
    assert ui._is_logged_in(_fake_request(cookie=cookie))

    # No cookie / garbage / legacy deterministic format: rejected.
    assert not ui._is_logged_in(_fake_request())
    assert not ui._is_logged_in(_fake_request(cookie="admin.deadbeef"))
    legacy_sig = __import__("hmac").new(
        store.load()["admin"]["password_hash"].encode(), b"admin", __import__("hashlib").sha256
    ).hexdigest()
    assert not ui._is_logged_in(_fake_request(cookie=f"admin.{legacy_sig}"))

    # Tampered payload (extended expiry) fails signature verification.
    payload, sig = cookie.rsplit(".", 1)
    value, issued, exp = payload.split(".")
    forged = f"{value}.{issued}.{int(exp) + 9999}.{sig}"
    assert not ui._is_logged_in(_fake_request(cookie=forged))

    # Past its expiry the same genuine cookie stops working.
    real_now = admin_mod._now
    monkeypatch.setattr(admin_mod, "_now", lambda: real_now() + COOKIE_TTL + 1)
    assert not ui._is_logged_in(_fake_request(cookie=cookie))


# -- #14: PBKDF2-per-client token lookup DoS --------------------------------------

def test_token_lookup_hashes_at_most_one_candidate(tmp_path: Path, monkeypatch):
    import cortex.admin as admin_mod
    from cortex.admin import AdminStore

    store = AdminStore(tmp_path / "cortex.admin.json")
    store.ensure_initialized()
    store.add_role("r", ["Public/**"])
    tokens = [store.create_client(f"c{i}", "r").token for i in range(5)]

    calls = []
    real_check = admin_mod._check_secret

    def counting_check(secret, *, salt, digest):
        calls.append(secret)
        return real_check(secret, salt=salt, digest=digest)

    monkeypatch.setattr(admin_mod, "_check_secret", counting_check)

    # A bogus token matching no stored prefix costs zero PBKDF2 runs.
    assert store.principal_for_token("ctx_totally-bogus-token") is None
    assert len(calls) == 0

    # A valid token verifies against exactly one candidate, not all five.
    p = store.principal_for_token(tokens[3])
    assert p is not None and p.name == "c3"
    assert len(calls) == 1


# -- #17: admin store lost updates -------------------------------------------------

def test_concurrent_role_and_client_creation_loses_nothing(tmp_path: Path):
    import threading

    from cortex.admin import AdminStore

    path = tmp_path / "cortex.admin.json"
    AdminStore(path).ensure_initialized()
    # Separate store instances (separate fds/caches) hammering the same file.
    errors: list[Exception] = []

    def add(i: int):
        try:
            AdminStore(path).add_role(f"role-{i}", [f"Area{i}/**"])
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=add, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    roles = AdminStore(path).roles()
    for i in range(12):
        assert roles[f"role-{i}"] == [f"Area{i}/**"]


# -- #18: state file is 0600 from the first byte -----------------------------------

def test_admin_state_written_owner_only_and_atomically(tmp_path: Path):
    from cortex.admin import AdminStore

    store = AdminStore(tmp_path / "cortex.admin.json")
    store.ensure_initialized()
    assert store.path.stat().st_mode & 0o777 == 0o600

    store.add_role("x", ["X/**"])
    assert store.path.stat().st_mode & 0o777 == 0o600
    # No stray temp files left behind.
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".cortex.admin")]
    assert leftovers == []


# -- #9: admin client colliding with a config principal ----------------------------

def _admin_http_server(tmp_path: Path, vault: Path):
    from cortex.admin import AdminStore
    from cortex.config import AdminConfig, ServerConfig

    store = AdminStore(tmp_path / "cortex.admin.json")
    store.ensure_initialized()
    store.add_role("public", ["Public/**"])
    cfg = CortexConfig(
        vault=VaultConfig(path=vault),
        index=IndexConfig(enabled=False),
        principals=[Principal(name="alice", scopes=["**"], token="tok-alice")],
        admin=AdminConfig(enabled=True, path=store.path),
        server=ServerConfig(transport="http"),
    )
    return store, cfg


def test_admin_client_subject_is_namespaced(tmp_path: Path, vault: Path):
    from cortex.auth import Authenticator
    from cortex.server import CortexTokenVerifier

    store, cfg = _admin_http_server(tmp_path, vault)
    token = store.create_client("bot", "public").token
    v = CortexTokenVerifier(Authenticator(cfg, admin_store=store))

    admin_at = asyncio.run(v.verify_token(token))
    assert admin_at is not None and admin_at.subject == "client:bot"
    config_at = asyncio.run(v.verify_token("tok-alice"))
    assert config_at is not None and config_at.subject == "alice"


def test_admin_client_named_like_config_principal_cannot_inherit_its_scopes(
    tmp_path: Path, vault: Path, monkeypatch
):
    """Even if a client named 'alice' exists in the admin store, a token
    authenticated by the admin store resolves through the admin store only —
    it never picks up the config principal alice's '**' scopes."""
    from cortex.server import build_http_server
    import cortex.server as server_mod
    from types import SimpleNamespace

    store, cfg = _admin_http_server(tmp_path, vault)
    srv = build_http_server(cfg)  # no collision yet: builds fine
    # Collision created at runtime through the admin UI path.
    store.create_client("alice", "public")

    monkeypatch.setattr(
        server_mod, "get_access_token", lambda: SimpleNamespace(subject="client:alice")
    )
    p = srv._get_principal()
    assert p.scopes == ["Public/**"]  # the admin role, NOT the config '**'

    # And the plain subject still resolves to the config principal only.
    monkeypatch.setattr(
        server_mod, "get_access_token", lambda: SimpleNamespace(subject="alice")
    )
    assert srv._get_principal().scopes == ["**"]


def test_authenticator_rejects_colliding_names_at_startup(tmp_path: Path, vault: Path):
    from cortex.auth import AuthError, Authenticator

    store, cfg = _admin_http_server(tmp_path, vault)
    store.create_client("alice", "public")  # collides with config principal
    with pytest.raises(AuthError, match="collide"):
        Authenticator(cfg, admin_store=store)


def test_config_rejects_reserved_client_prefix(tmp_path: Path):
    from cortex.config import ConfigError, load_config

    (tmp_path / "vault").mkdir()
    cfg_file = tmp_path / "cortex.yaml"
    cfg_file.write_text(
        "vault:\n  path: ./vault\n"
        "principals:\n  - name: 'client:evil'\n    scopes: ['**']\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="reserved"):
        load_config(cfg_file)
