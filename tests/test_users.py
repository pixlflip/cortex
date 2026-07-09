"""A4 tests: local user accounts, groups, sessions + CSRF, per-user API
tokens, source-separated token resolution, admin gating, and the CLI verbs.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

import cortex.db.repos as repos_mod
import cortex.users as users_mod
from cortex.auth import Authenticator, AuthError
from cortex.cli import main
from cortex.config import (
    AdminConfig,
    CortexConfig,
    DatabaseConfig,
    IndexConfig,
    Principal,
    ServerConfig,
    VaultConfig,
)
from cortex.db import Database
from cortex.sessions import CSRF_HEADER, SESSION_COOKIE, SessionAuth
from cortex.users import (
    OPERATOR,
    AuthzError,
    IdentityError,
    IdentityService,
    bootstrap_admin,
)


@pytest.fixture
def db(tmp_path: Path) -> Database:
    return Database(tmp_path / "cortex.sqlite")


@pytest.fixture
def identity(db: Database) -> IdentityService:
    return IdentityService(db)


@pytest.fixture
def clock(monkeypatch):
    """Deterministic, advanceable time shared by the repos and the service."""

    state = {"now": 1_000_000}

    def advance(seconds: int) -> None:
        state["now"] += seconds

    monkeypatch.setattr(repos_mod, "_now", lambda: state["now"])
    monkeypatch.setattr(users_mod, "_now", lambda: state["now"])
    return advance


# --------------------------------------------------------------------------
# user lifecycle + name hygiene
# --------------------------------------------------------------------------

def test_create_list_disable_enable_delete(identity: IdentityService):
    identity.create_user("alice", password="pw-alice")
    identity.create_user("bob")
    assert [u["username"] for u in identity.list_users()] == ["alice", "bob"]

    disabled = identity.disable_user("alice")
    assert disabled["disabled"] == 1
    enabled = identity.enable_user("alice")
    assert enabled["disabled"] == 0

    identity.delete_user("bob")
    with pytest.raises(IdentityError, match="no such user"):
        identity.get_user("bob")


def test_duplicate_username_rejected(identity: IdentityService):
    identity.create_user("alice")
    with pytest.raises(IdentityError, match="already exists"):
        identity.create_user("alice")


@pytest.mark.parametrize(
    "bad",
    ["", "  ", "a b", "a:b", "user:alice", "client:alice", "../etc", ".hidden", "a/b"],
)
def test_invalid_usernames_rejected(identity: IdentityService, bad: str):
    with pytest.raises(IdentityError):
        identity.create_user(bad)


def test_username_may_not_collide_with_config_principal(db: Database):
    cfg = CortexConfig(principals=[Principal(name="web", scopes=["Public/**"])])
    identity = IdentityService(db, cfg)
    with pytest.raises(IdentityError, match="config principal"):
        identity.create_user("web")
    # Non-colliding names still work with a config present.
    identity.create_user("alice")


def test_reserved_prefix_rejected_even_case_insensitively(identity: IdentityService):
    # ':' is outside the charset anyway; the reserved-prefix check is the
    # explicit second line of defense.
    with pytest.raises(IdentityError):
        identity.create_user("User:alice")


def test_authenticator_guards_db_user_vs_config_principal_collision(db: Database):
    # A user created before the principal existed (no config passed) must be
    # caught at Authenticator construction, not silently coexist.
    IdentityService(db).create_user("web")
    cfg = CortexConfig(principals=[Principal(name="web", scopes=["**"], token="t")])
    with pytest.raises(AuthError, match="collide with config principals"):
        Authenticator(cfg, user_service=IdentityService(db, cfg))


# --------------------------------------------------------------------------
# admin gating
# --------------------------------------------------------------------------

def test_admin_ops_require_admin_actor(identity: IdentityService):
    admin = identity.create_user("root", password="pw", is_admin=True)
    plain = identity.create_user("alice", password="pw")

    # Non-admin actor: every admin op refuses.
    for op in (
        lambda: identity.create_user("eve", actor=plain),
        lambda: identity.disable_user("root", actor=plain),
        lambda: identity.enable_user("root", actor=plain),
        lambda: identity.delete_user("root", actor=plain),
        lambda: identity.set_admin("alice", True, actor=plain),
        lambda: identity.create_group("g", actor=plain),
        lambda: identity.add_to_group("alice", "g", actor=plain),
        lambda: identity.set_password("root", "x", actor=plain),
        lambda: identity.mint_token("root", "t", actor=plain),
        lambda: identity.revoke_token("root", "t", actor=plain),
    ):
        with pytest.raises(AuthzError):
            op()

    # Admin actor and the trusted local operator both succeed.
    identity.create_user("eve", actor=admin)
    identity.create_user("mallory", actor=OPERATOR)


def test_disabled_admin_actor_is_refused(identity: IdentityService):
    identity.create_user("root", password="pw", is_admin=True)
    stale = identity.disable_user("root")
    with pytest.raises(AuthzError):
        identity.create_user("eve", actor=stale)


def test_self_service_password_and_tokens(identity: IdentityService):
    alice = identity.create_user("alice", password="old")
    identity.set_password("alice", "new", actor=alice)  # self: allowed
    assert identity.login("alice", "new") is not None
    created = identity.mint_token("alice", "laptop", actor=alice)
    assert identity.revoke_token("alice", "laptop", actor=alice) == 1
    assert identity.tokens.resolve(created.token) is None


# --------------------------------------------------------------------------
# password verify: no enumeration oracle
# --------------------------------------------------------------------------

def test_login_failures_are_uniform(identity: IdentityService):
    identity.create_user("alice", password="right")
    identity.create_user("dave", password="pw")
    identity.disable_user("dave")

    assert identity.login("alice", "wrong") is None       # wrong password
    assert identity.login("nobody", "whatever") is None   # unknown user
    assert identity.login("dave", "pw") is None           # disabled user
    assert identity.login("alice", "") is None
    assert identity.login("alice", "right") is not None


def test_empty_password_rejected(identity: IdentityService):
    identity.create_user("alice")
    with pytest.raises((IdentityError, ValueError)):
        identity.set_password("alice", "")


# --------------------------------------------------------------------------
# groups → effective scopes
# --------------------------------------------------------------------------

def test_group_membership_and_scope_union(identity: IdentityService):
    identity.create_user("alice", password="pw")
    identity.create_group("research", scopes=["Projects/Research/**"])
    identity.create_group("staff", scopes=["Public/**", "Projects/Research/**"])
    assert identity.add_to_group("alice", "research")
    assert identity.add_to_group("alice", "staff")
    assert not identity.add_to_group("alice", "staff")  # idempotent

    p = identity.principal_for_username("alice")
    assert p is not None
    assert p.name == "alice"
    assert p.scopes == ["Projects/Research/**", "Public/**"]  # deduped union

    assert identity.remove_from_group("alice", "staff")
    assert identity.principal_for_username("alice").scopes == ["Projects/Research/**"]


def test_principal_for_missing_or_disabled_user_is_none(identity: IdentityService):
    assert identity.principal_for_username("ghost") is None
    identity.create_user("alice")
    identity.disable_user("alice")
    assert identity.principal_for_username("alice") is None


# --------------------------------------------------------------------------
# sessions: issue / expiry / sliding renewal / logout / CSRF
# --------------------------------------------------------------------------

def _login(identity: IdentityService):
    identity.create_user("alice", password="pw")
    result = identity.login("alice", "pw")
    assert result is not None
    return result


def test_session_resolves_and_expires(identity: IdentityService, clock):
    result = _login(identity)
    assert identity.resolve_session(result.session_token)["username"] == "alice"
    assert identity.resolve_session("bogus") is None
    assert identity.resolve_session(None) is None

    clock(identity.session_ttl + 1)
    assert identity.resolve_session(result.session_token) is None


def test_session_sliding_renewal(identity: IdentityService, clock):
    result = _login(identity)
    ttl = identity.session_ttl

    # First half of life: expiry unchanged.
    clock(ttl // 4)
    identity.resolve_session(result.session_token)
    assert identity.sessions.get(result.session_id)["expires_at"] == result.expires_at

    # Second half: use extends the session by a full TTL.
    clock(ttl // 2)
    identity.resolve_session(result.session_token)
    extended = identity.sessions.get(result.session_id)["expires_at"]
    assert extended > result.expires_at

    # An untouched session still dies on (the extended) schedule.
    clock(ttl + 1)
    assert identity.resolve_session(result.session_token) is None


def test_logout_destroys_session_server_side(identity: IdentityService):
    result = _login(identity)
    assert identity.logout(result.session_token) is True
    assert identity.logout(result.session_token) is False  # idempotent
    assert identity.resolve_session(result.session_token) is None


def test_disabling_user_kills_live_sessions(identity: IdentityService):
    result = _login(identity)
    identity.disable_user("alice")
    assert identity.resolve_session(result.session_token) is None
    # Re-enabling does not resurrect the session.
    identity.enable_user("alice")
    assert identity.resolve_session(result.session_token) is None


def _request(method: str, cookie: str | None = None, csrf: str | None = None):
    from starlette.requests import Request

    headers = []
    if cookie is not None:
        headers.append((b"cookie", f"{SESSION_COOKIE}={cookie}".encode()))
    if csrf is not None:
        headers.append((CSRF_HEADER.encode(), csrf.encode()))
    return Request(
        {"type": "http", "method": method, "headers": headers, "path": "/",
         "query_string": b""}
    )


def test_csrf_enforcement(identity: IdentityService):
    result = _login(identity)
    auth = SessionAuth(identity, secure_cookies=True)
    token, csrf = result.session_token, result.csrf_token

    # Safe methods need no CSRF proof.
    assert auth.authenticate(_request("GET", cookie=token))["username"] == "alice"
    # State-changing without the header: rejected.
    assert auth.authenticate(_request("POST", cookie=token)) is None
    assert auth.csrf_ok(_request("POST", cookie=token)) is False
    # Wrong header value: rejected.
    assert auth.authenticate(_request("POST", cookie=token, csrf="forged")) is None
    # CSRF token of a *different* session: rejected.
    other = identity.login("alice", "pw")
    assert (
        auth.authenticate(_request("POST", cookie=token, csrf=other.csrf_token)) is None
    )
    # Correct session-bound header: accepted.
    ok = auth.authenticate(_request("POST", cookie=token, csrf=csrf))
    assert ok is not None and ok["username"] == "alice"
    # No cookie at all: unauthenticated regardless of header.
    assert auth.authenticate(_request("POST", csrf=csrf)) is None


def test_session_cookie_flags(identity: IdentityService):
    from starlette.responses import Response

    result = _login(identity)
    auth = SessionAuth(identity, secure_cookies=True)
    resp = Response()
    auth.set_session_cookie(resp, result.session_token)
    header = resp.headers["set-cookie"].lower()
    assert SESSION_COOKIE in header
    assert "httponly" in header
    assert "secure" in header
    assert "samesite=lax" in header
    assert f"max-age={identity.session_ttl}" in header

    # Plain-HTTP setups omit Secure (same rule as the admin cookie, #19).
    resp2 = Response()
    SessionAuth(identity, secure_cookies=False).set_session_cookie(
        resp2, result.session_token
    )
    assert "secure" not in resp2.headers["set-cookie"].lower()


# --------------------------------------------------------------------------
# API tokens: mint / resolve / revoke, source separation
# --------------------------------------------------------------------------

def _config(tmp_path: Path, db_path: Path) -> CortexConfig:
    vault = tmp_path / "vault"
    (vault / "Public").mkdir(parents=True, exist_ok=True)
    (vault / "Public" / "open.md").write_text("# Open\n", encoding="utf-8")
    return CortexConfig(
        vault=VaultConfig(path=vault),
        index=IndexConfig(path=tmp_path / "cortex.index.sqlite"),
        admin=AdminConfig(enabled=False, path=tmp_path / "cortex.admin.json"),
        database=DatabaseConfig(path=db_path),
        principals=[
            Principal(name="web", scopes=["Public/**"], token="tok-web"),
        ],
        server=ServerConfig(transport="http", host="127.0.0.1", port=8765),
    )


def test_token_mint_resolve_revoke(identity: IdentityService, clock):
    identity.create_user("bob", password="pw")
    identity.create_group("staff", scopes=["Public/**"])
    identity.add_to_group("bob", "staff")

    created = identity.mint_token("bob", "laptop", expires_in=3600)
    assert created.token.startswith("ctx_")

    resolved = identity.resolve_api_token(created.token)
    assert resolved is not None
    principal, username = resolved
    assert username == "bob" and principal.scopes == ["Public/**"]

    # Expiry.
    clock(3601)
    assert identity.resolve_api_token(created.token) is None

    # Revocation.
    fresh = identity.mint_token("bob", "phone")
    assert identity.revoke_token("bob", "phone") == 1
    assert identity.resolve_api_token(fresh.token) is None
    assert identity.revoke_token("bob", "phone") == 0  # idempotent

    # Disabled owner.
    live = identity.mint_token("bob", "tablet")
    identity.disable_user("bob")
    assert identity.resolve_api_token(live.token) is None


def test_token_scope_narrowing_never_widens(identity: IdentityService):
    identity.create_user("bob", password="pw")
    identity.create_group("staff", scopes=["Public/**", "Team/**"])
    identity.add_to_group("bob", "staff")

    narrowed = identity.mint_token("bob", "one-project", scopes=["Public/**"])
    principal, _ = identity.resolve_api_token(narrowed.token)
    assert principal.scopes == ["Public/**"]

    # Scopes the user does not hold are dropped, not granted.
    widened = identity.mint_token("bob", "greedy", scopes=["Secret/**", "Team/**"])
    principal, _ = identity.resolve_api_token(widened.token)
    assert principal.scopes == ["Team/**"]


def test_authenticator_resolves_user_tokens_source_tagged(tmp_path: Path):
    db = Database(tmp_path / "cortex.sqlite")
    cfg = _config(tmp_path, db.path)
    identity = IdentityService(db, cfg)
    identity.create_user("bob", password="pw")
    identity.create_group("staff", scopes=["Team/**"])
    identity.add_to_group("bob", "staff")
    created = identity.mint_token("bob", "laptop")

    authn = Authenticator(cfg, user_service=identity)
    principal, subject = authn.resolve_token(created.token)
    assert subject == "user:bob"
    assert principal.name == "bob" and principal.scopes == ["Team/**"]

    # Config principals still resolve first, with plain-name subjects.
    principal, subject = authn.resolve_token("tok-web")
    assert subject == "web" and principal.scopes == ["Public/**"]

    with pytest.raises(AuthError):
        authn.resolve_token("ctx_bogus")


def test_user_token_never_cross_resolves_to_admin_client(tmp_path: Path):
    """A DB user and an admin-store client sharing a name stay two distinct,
    source-tagged identities with their own scopes (the generalized #9)."""
    from cortex.admin import AdminStore

    store = AdminStore(tmp_path / "admin.json")
    store.ensure_initialized()
    store.add_role("wide", ["**"])
    client = store.create_client("shadow", "wide")

    db = Database(tmp_path / "cortex.sqlite")
    identity = IdentityService(db)
    identity.create_user("shadow", password="pw")  # no groups: no scopes
    user_token = identity.mint_token("shadow", "t")

    cfg = CortexConfig(admin=AdminConfig(path=store.path))
    authn = Authenticator(cfg, admin_store=store, user_service=identity)

    principal, subject = authn.resolve_token(user_token.token)
    assert subject == "user:shadow" and principal.scopes == []

    principal, subject = authn.resolve_token(client.token)
    assert subject == "client:shadow" and principal.scopes == ["**"]


# --------------------------------------------------------------------------
# per-request principal resolution on the HTTP path
# --------------------------------------------------------------------------

def test_get_principal_resolves_user_subject(tmp_path: Path, monkeypatch):
    import cortex.server as server_mod
    from cortex.server import CortexTokenVerifier, build_http_server

    db = Database(tmp_path / "cortex.sqlite")
    cfg = _config(tmp_path, db.path)
    identity = IdentityService(db, cfg)
    identity.create_user("bob", password="pw")
    identity.create_group("staff", scopes=["Public/**"])
    identity.add_to_group("bob", "staff")
    created = identity.mint_token("bob", "laptop")

    srv = build_http_server(cfg)

    # The verifier tags the subject with the user: namespace.
    verified = asyncio.run(
        CortexTokenVerifier(Authenticator(cfg, user_service=identity)).verify_token(
            created.token
        )
    )
    assert verified is not None and verified.subject == "user:bob"

    # _get_principal re-resolves the raw token against the user store.
    monkeypatch.setattr(
        server_mod,
        "get_access_token",
        lambda: SimpleNamespace(subject="user:bob", token=created.token),
    )
    p = srv._get_principal()
    assert p.name == "bob" and p.scopes == ["Public/**"]

    # A revoked token dies immediately, mid-connection.
    identity.revoke_token("bob", "laptop")
    with pytest.raises(ValueError, match="unknown principal"):
        srv._get_principal()


def test_user_subject_never_falls_through_to_config_store(
    tmp_path: Path, monkeypatch
):
    """A forged user:web subject must not inherit the config principal
    'web''s scopes — and the plain subject 'web' must not consult the user
    store."""
    import cortex.server as server_mod
    from cortex.server import build_http_server

    db = Database(tmp_path / "cortex.sqlite")
    cfg = _config(tmp_path, db.path)
    srv = build_http_server(cfg)

    monkeypatch.setattr(
        server_mod,
        "get_access_token",
        lambda: SimpleNamespace(subject="user:web", token="tok-web"),
    )
    with pytest.raises(ValueError, match="unknown principal"):
        srv._get_principal()

    monkeypatch.setattr(
        server_mod, "get_access_token", lambda: SimpleNamespace(subject="web")
    )
    assert srv._get_principal().scopes == ["Public/**"]


def test_narrowed_token_scopes_apply_per_call(tmp_path: Path, monkeypatch):
    import cortex.server as server_mod
    from cortex.server import build_http_server

    db = Database(tmp_path / "cortex.sqlite")
    cfg = _config(tmp_path, db.path)
    identity = IdentityService(db, cfg)
    identity.create_user("bob", password="pw")
    identity.create_group("staff", scopes=["Public/**", "Team/**"])
    identity.add_to_group("bob", "staff")
    narrowed = identity.mint_token("bob", "one-project", scopes=["Public/**"])

    srv = build_http_server(cfg)
    monkeypatch.setattr(
        server_mod,
        "get_access_token",
        lambda: SimpleNamespace(subject="user:bob", token=narrowed.token),
    )
    assert srv._get_principal().scopes == ["Public/**"]


# --------------------------------------------------------------------------
# admin bootstrap
# --------------------------------------------------------------------------

def test_bootstrap_admin_first_run_and_idempotence(identity: IdentityService):
    password = bootstrap_admin(identity)
    assert password
    assert identity.login("admin", password).user["is_admin"] == 1
    # Second run: no-op, no password churn.
    assert bootstrap_admin(identity) is None
    assert identity.login("admin", password) is not None


def test_bootstrap_admin_skips_after_admin_import(identity: IdentityService):
    identity.create_user("imported-admin", password="pw", is_admin=True)
    assert bootstrap_admin(identity) is None


def test_bootstrap_admin_promotes_flagless_admin_username(identity: IdentityService):
    identity.create_user("admin", password="old")
    password = bootstrap_admin(identity)
    assert password and password != "old"
    user = identity.get_user("admin")
    assert user["is_admin"] == 1
    assert identity.login("admin", password) is not None


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

@pytest.fixture
def cli_env(tmp_path: Path):
    (tmp_path / "vault").mkdir()
    cfg_path = tmp_path / "cortex.yaml"
    cfg_path.write_text(
        f"""
vault:
  path: {tmp_path / 'vault'}
  git:
    enabled: false
database:
  path: {tmp_path / 'cortex.sqlite'}
admin:
  enabled: false
""",
        encoding="utf-8",
    )
    return cfg_path


def test_cli_user_and_token_roundtrip(cli_env: Path, capsys):
    c = str(cli_env)
    assert main(["-c", c, "db", "init"]) == 0
    boot = capsys.readouterr().out
    assert "admin password:" in boot  # first-run bootstrap prints it once

    assert main(["-c", c, "user", "add", "alice", "--password", "pw-alice"]) == 0
    assert main(["-c", c, "user", "add", "alice", "--password", "x"]) == 1  # dup
    capsys.readouterr()

    assert main(["-c", c, "user", "list"]) == 0
    out = capsys.readouterr().out
    assert "alice" in out and "admin" in out and "[admin]" in out

    assert main(["-c", c, "token", "mint", "alice", "laptop"]) == 0
    out = capsys.readouterr().out
    raw = [line for line in out.splitlines() if line.startswith("ctx_")][0]

    # The minted token resolves to the user, source-tagged.
    from cortex.config import load_config

    cfg = load_config(c)
    identity = IdentityService(Database(cfg.database.path), cfg)
    principal, subject = Authenticator(cfg, user_service=identity).resolve_token(raw)
    assert subject == "user:alice"

    assert main(["-c", c, "token", "list", "alice"]) == 0
    assert "laptop" in capsys.readouterr().out
    assert main(["-c", c, "token", "revoke", "alice", "laptop"]) == 0
    assert identity.resolve_api_token(raw) is None
    assert main(["-c", c, "token", "revoke", "alice", "laptop"]) == 1

    assert main(["-c", c, "user", "passwd", "alice", "--password", "pw2"]) == 0
    assert identity.login("alice", "pw-alice") is None
    assert identity.login("alice", "pw2") is not None

    assert main(["-c", c, "user", "disable", "alice"]) == 0
    assert identity.login("alice", "pw2") is None
    assert main(["-c", c, "user", "enable", "alice"]) == 0
    assert identity.login("alice", "pw2") is not None

    assert main(["-c", c, "user", "delete", "alice"]) == 0
    assert identity.users.get_by_username("alice") is None


def test_cli_init_bootstraps_admin_against_db(cli_env: Path, capsys):
    c = str(cli_env)
    assert main(["-c", c, "init"]) == 0
    out = capsys.readouterr().out
    assert "admin password:" in out
    password = [
        line.split("admin password:", 1)[1].strip()
        for line in out.splitlines()
        if "admin password:" in line
    ][0]

    # Idempotent: a second init mints nothing new.
    assert main(["-c", c, "init"]) == 0
    assert "admin password:" not in capsys.readouterr().out

    from cortex.config import load_config

    cfg = load_config(c)
    identity = IdentityService(Database(cfg.database.path), cfg)
    assert identity.login("admin", password) is not None


def test_cli_user_add_admin_flag(cli_env: Path, capsys):
    c = str(cli_env)
    assert main(["-c", c, "db", "init"]) == 0
    assert main(["-c", c, "user", "add", "ops", "--admin", "--password", "pw"]) == 0
    capsys.readouterr()

    from cortex.config import load_config

    cfg = load_config(c)
    identity = IdentityService(Database(cfg.database.path), cfg)
    assert identity.get_user("ops")["is_admin"] == 1


def test_cli_refuses_username_colliding_with_config_principal(
    cli_env: Path, tmp_path: Path, capsys, monkeypatch
):
    monkeypatch.setenv("CORTEX_TOKEN_WEB", "tok-web")
    cli_env.write_text(
        cli_env.read_text(encoding="utf-8")
        + """
principals:
  - name: web
    scopes: ["Public/**"]
    token_env: CORTEX_TOKEN_WEB
""",
        encoding="utf-8",
    )
    c = str(cli_env)
    assert main(["-c", c, "db", "init"]) == 0
    assert main(["-c", c, "user", "add", "web", "--password", "pw"]) == 1
    assert "config principal" in capsys.readouterr().err
