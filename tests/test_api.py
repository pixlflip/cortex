"""A6 tests: the /api/v1 JSON REST surface.

Runs the real route group over a plain Starlette app with the Starlette
TestClient — no socket, no MCP machinery. Covers: login (local and LDAP via
the A5 mock directory) minting a working session; /auth/me; logout; CSRF
enforcement on cookie-authenticated mutations (and bearer's exemption);
401/403 on every admin route for anonymous/non-admin callers; the
own-tokens-only rule; the uniform error envelope; and no existence leaks.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from cortex.api import API_PREFIX, ApiV1, LoginRateLimiter
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
from cortex.users import IdentityService

# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def identity(tmp_path: Path) -> IdentityService:
    svc = IdentityService(Database(tmp_path / "cortex.sqlite"))
    svc.create_user("admin", password="admin-pw", is_admin=True)
    svc.create_user("alice", password="alice-pw")
    svc.create_user("bob", password="bob-pw")
    return svc


def make_api(identity: IdentityService, config: CortexConfig | None = None, **kwargs) -> ApiV1:
    config = config or CortexConfig()
    return ApiV1(
        config,
        identity,
        SessionAuth(identity, secure_cookies=False),
        **kwargs,
    )


@pytest.fixture
def api(identity: IdentityService) -> ApiV1:
    return make_api(identity)


def make_client(api: ApiV1) -> TestClient:
    return TestClient(Starlette(routes=api.routes()))


@pytest.fixture
def client(api: ApiV1) -> TestClient:
    return make_client(api)


def login(client: TestClient, username: str, password: str) -> str:
    """Log in and return the CSRF token; the TestClient keeps the cookie."""
    resp = client.post(
        f"{API_PREFIX}/auth/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["csrf_token"]


def assert_envelope(resp, status: int, code: str | None = None) -> dict:
    """Every error is exactly {"error": {"code", "message"}}."""
    assert resp.status_code == status, resp.text
    body = resp.json()
    assert set(body) == {"error"}
    assert set(body["error"]) == {"code", "message"}
    if code is not None:
        assert body["error"]["code"] == code
    return body


# ---------------------------------------------------------------------------
# auth: login / me / logout
# ---------------------------------------------------------------------------


def test_login_sets_working_session_and_me_reflects_it(client: TestClient):
    resp = client.post(
        f"{API_PREFIX}/auth/login", json={"username": "alice", "password": "alice-pw"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["user"]["username"] == "alice"
    assert body["user"]["is_admin"] is False
    assert body["csrf_token"]
    # No credential material in the summary.
    assert "password_hash" not in body["user"] and "password_salt" not in body["user"]
    assert SESSION_COOKIE in resp.cookies

    me = client.get(f"{API_PREFIX}/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["username"] == "alice"
    assert me.json()["auth"] == "session"


def test_login_failures_are_uniform(client: TestClient):
    wrong = client.post(
        f"{API_PREFIX}/auth/login", json={"username": "alice", "password": "nope"}
    )
    ghost = client.post(
        f"{API_PREFIX}/auth/login", json={"username": "ghost", "password": "nope"}
    )
    a = assert_envelope(wrong, 401, "invalid_credentials")
    b = assert_envelope(ghost, 401, "invalid_credentials")
    assert a == b  # unknown user vs wrong password: indistinguishable


def test_login_validation_and_envelope(client: TestClient):
    assert_envelope(
        client.post(f"{API_PREFIX}/auth/login", json={"username": "alice"}),
        400,
        "invalid_request",
    )
    assert_envelope(
        client.post(f"{API_PREFIX}/auth/login", content=b"not json"),
        400,
        "invalid_request",
    )


def test_login_rate_limited_after_repeated_failures(identity: IdentityService):
    api = make_api(identity, rate_limiter=LoginRateLimiter(max_failures=3))
    client = make_client(api)
    for _ in range(3):
        assert_envelope(
            client.post(
                f"{API_PREFIX}/auth/login",
                json={"username": "alice", "password": "nope"},
            ),
            401,
        )
    # Even the correct password is throttled now.
    assert_envelope(
        client.post(
            f"{API_PREFIX}/auth/login",
            json={"username": "alice", "password": "alice-pw"},
        ),
        429,
        "rate_limited",
    )


def test_logout_invalidates_session(client: TestClient):
    csrf = login(client, "alice", "alice-pw")
    # Logout is a mutation: CSRF applies.
    assert_envelope(client.post(f"{API_PREFIX}/auth/logout"), 403, "csrf_failed")
    resp = client.post(f"{API_PREFIX}/auth/logout", headers={CSRF_HEADER: csrf})
    assert resp.status_code == 204
    assert_envelope(client.get(f"{API_PREFIX}/auth/me"), 401, "unauthenticated")


def test_me_anonymous_is_401(client: TestClient):
    assert_envelope(client.get(f"{API_PREFIX}/auth/me"), 401, "unauthenticated")


# ---------------------------------------------------------------------------
# CSRF + Origin on cookie auth; bearer is exempt
# ---------------------------------------------------------------------------


def test_cookie_mutation_requires_csrf(client: TestClient):
    csrf = login(client, "alice", "alice-pw")
    no_header = client.post(f"{API_PREFIX}/tokens", json={"name": "t"})
    assert_envelope(no_header, 403, "csrf_failed")
    bad_header = client.post(
        f"{API_PREFIX}/tokens", json={"name": "t"}, headers={CSRF_HEADER: "wrong"}
    )
    assert_envelope(bad_header, 403, "csrf_failed")
    ok = client.post(
        f"{API_PREFIX}/tokens", json={"name": "t"}, headers={CSRF_HEADER: csrf}
    )
    assert ok.status_code == 201


def test_cookie_mutation_rejects_cross_origin(client: TestClient):
    csrf = login(client, "alice", "alice-pw")
    resp = client.post(
        f"{API_PREFIX}/tokens",
        json={"name": "t"},
        headers={CSRF_HEADER: csrf, "Origin": "https://evil.example"},
    )
    assert_envelope(resp, 403, "origin_forbidden")
    # Same-origin (the request's own host) passes.
    ok = client.post(
        f"{API_PREFIX}/tokens",
        json={"name": "t"},
        headers={CSRF_HEADER: csrf, "Origin": "http://testserver"},
    )
    assert ok.status_code == 201


def test_bearer_auth_works_and_is_csrf_exempt(identity: IdentityService, api: ApiV1):
    raw = identity.mint_token("alice", "cli").token
    client = make_client(api)  # no cookies at all
    headers = {"Authorization": f"Bearer {raw}"}

    me = client.get(f"{API_PREFIX}/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json() == {"user": me.json()["user"], "auth": "bearer"}
    assert me.json()["user"]["username"] == "alice"

    # Mutation with no CSRF header: fine under bearer.
    minted = client.post(f"{API_PREFIX}/tokens", json={"name": "t2"}, headers=headers)
    assert minted.status_code == 201
    assert minted.json()["token"].startswith("ctx_")

    assert_envelope(
        client.get(f"{API_PREFIX}/auth/me", headers={"Authorization": "Bearer nope"}),
        401,
        "unauthenticated",
    )


def test_bearer_logout_is_rejected(identity: IdentityService, api: ApiV1):
    raw = identity.mint_token("alice", "cli").token
    client = make_client(api)
    resp = client.post(
        f"{API_PREFIX}/auth/logout", headers={"Authorization": f"Bearer {raw}"}
    )
    assert_envelope(resp, 400, "invalid_request")


# ---------------------------------------------------------------------------
# admin gating: every admin route → 401 anonymous, 403 non-admin
# ---------------------------------------------------------------------------

ADMIN_ROUTES = [
    ("GET", "/users", None),
    ("POST", "/users", {"username": "x"}),
    ("GET", "/users/alice", None),
    ("PATCH", "/users/alice", {"disabled": True}),
    ("DELETE", "/users/alice", None),
    ("GET", "/groups", None),
    ("POST", "/groups", {"name": "g"}),
    ("PATCH", "/groups/g", {"scopes": []}),
    ("DELETE", "/groups/g", None),
    ("POST", "/groups/g/members", {"username": "alice"}),
    ("DELETE", "/groups/g/members/alice", None),
    ("POST", "/ldap/sync", None),
]


@pytest.mark.parametrize("method,path,body", ADMIN_ROUTES)
def test_admin_routes_401_for_anonymous(client: TestClient, method, path, body):
    resp = client.request(method, f"{API_PREFIX}{path}", json=body)
    assert_envelope(resp, 401, "unauthenticated")


@pytest.mark.parametrize("method,path,body", ADMIN_ROUTES)
def test_admin_routes_403_for_non_admin(client: TestClient, method, path, body):
    csrf = login(client, "alice", "alice-pw")
    resp = client.request(
        method, f"{API_PREFIX}{path}", json=body, headers={CSRF_HEADER: csrf}
    )
    assert_envelope(resp, 403, "forbidden")


def test_admin_check_runs_before_resource_lookup(client: TestClient):
    """A non-admin probing /users/{name} gets 403 whether or not the user
    exists — no existence oracle behind the authz wall."""
    csrf = login(client, "alice", "alice-pw")
    real = client.get(f"{API_PREFIX}/users/bob", headers={CSRF_HEADER: csrf})
    ghost = client.get(f"{API_PREFIX}/users/ghost", headers={CSRF_HEADER: csrf})
    assert real.status_code == ghost.status_code == 403
    assert real.json() == ghost.json()


# ---------------------------------------------------------------------------
# admin: user CRUD
# ---------------------------------------------------------------------------


def test_admin_user_lifecycle(client: TestClient):
    csrf = login(client, "admin", "admin-pw")
    h = {CSRF_HEADER: csrf}

    created = client.post(
        f"{API_PREFIX}/users",
        json={"username": "carol", "password": "carol-pw", "display_name": "Carol"},
        headers=h,
    )
    assert created.status_code == 201
    assert created.json()["user"]["username"] == "carol"

    listed = client.get(f"{API_PREFIX}/users")
    assert "carol" in [u["username"] for u in listed.json()["users"]]

    got = client.get(f"{API_PREFIX}/users/carol")
    assert got.status_code == 200 and got.json()["user"]["disabled"] is False

    # Disable stops login immediately; failure stays uniform.
    disabled = client.patch(
        f"{API_PREFIX}/users/carol", json={"disabled": True}, headers=h
    )
    assert disabled.status_code == 200 and disabled.json()["user"]["disabled"] is True
    other = make_client_from(client)
    assert_envelope(
        other.post(
            f"{API_PREFIX}/auth/login",
            json={"username": "carol", "password": "carol-pw"},
        ),
        401,
        "invalid_credentials",
    )

    # Enable + password reset via PATCH.
    client.patch(
        f"{API_PREFIX}/users/carol",
        json={"disabled": False, "password": "new-pw"},
        headers=h,
    )
    ok = other.post(
        f"{API_PREFIX}/auth/login", json={"username": "carol", "password": "new-pw"}
    )
    assert ok.status_code == 200

    # Admin flag flips.
    promoted = client.patch(
        f"{API_PREFIX}/users/carol", json={"is_admin": True}, headers=h
    )
    assert promoted.json()["user"]["is_admin"] is True

    # Delete; the user is gone.
    assert client.delete(f"{API_PREFIX}/users/carol", headers=h).status_code == 204
    assert_envelope(client.get(f"{API_PREFIX}/users/carol"), 404, "not_found")


def make_client_from(client: TestClient) -> TestClient:
    """A fresh, cookie-less client over the same app."""
    return TestClient(client.app)


def test_admin_user_validation_errors(client: TestClient):
    csrf = login(client, "admin", "admin-pw")
    h = {CSRF_HEADER: csrf}
    assert_envelope(
        client.post(f"{API_PREFIX}/users", json={"username": "bad name!"}, headers=h),
        400,
        "invalid_request",
    )
    assert_envelope(
        client.post(f"{API_PREFIX}/users", json={"username": "alice"}, headers=h),
        400,
        "invalid_request",
    )
    assert_envelope(
        client.patch(
            f"{API_PREFIX}/users/alice", json={"unknown_field": 1}, headers=h
        ),
        400,
        "invalid_request",
    )
    assert_envelope(
        client.patch(f"{API_PREFIX}/users/ghost", json={"disabled": True}, headers=h),
        404,
        "not_found",
    )


# ---------------------------------------------------------------------------
# admin: groups + membership
# ---------------------------------------------------------------------------


def test_admin_group_lifecycle_and_membership(client: TestClient):
    csrf = login(client, "admin", "admin-pw")
    h = {CSRF_HEADER: csrf}

    created = client.post(
        f"{API_PREFIX}/groups",
        json={"name": "research", "scopes": ["Projects/Research/**"]},
        headers=h,
    )
    assert created.status_code == 201
    assert created.json()["group"]["scopes"] == ["Projects/Research/**"]

    added = client.post(
        f"{API_PREFIX}/groups/research/members", json={"username": "alice"}, headers=h
    )
    assert added.status_code == 200
    assert added.json()["added"] is True
    assert "alice" in added.json()["group"]["members"]
    # Idempotent add reports added: false.
    again = client.post(
        f"{API_PREFIX}/groups/research/members", json={"username": "alice"}, headers=h
    )
    assert again.json()["added"] is False

    # Membership shows on the user summary too.
    user = client.get(f"{API_PREFIX}/users/alice").json()["user"]
    assert user["groups"] == ["research"]

    patched = client.patch(
        f"{API_PREFIX}/groups/research", json={"scopes": ["Public/**"]}, headers=h
    )
    assert patched.json()["group"]["scopes"] == ["Public/**"]

    removed = client.delete(
        f"{API_PREFIX}/groups/research/members/alice", headers=h
    )
    assert removed.status_code == 204
    listed = client.get(f"{API_PREFIX}/groups").json()["groups"]
    assert listed[0]["members"] == []

    assert client.delete(f"{API_PREFIX}/groups/research", headers=h).status_code == 204
    assert client.get(f"{API_PREFIX}/groups").json()["groups"] == []
    assert_envelope(
        client.patch(f"{API_PREFIX}/groups/research", json={"scopes": []}, headers=h),
        404,
        "not_found",
    )


# ---------------------------------------------------------------------------
# self-service tokens: own-only; admin may revoke any; no existence leaks
# ---------------------------------------------------------------------------


def test_tokens_are_listed_per_owner_without_secrets(client: TestClient):
    csrf = login(client, "alice", "alice-pw")
    minted = client.post(
        f"{API_PREFIX}/tokens", json={"name": "cli"}, headers={CSRF_HEADER: csrf}
    )
    assert minted.status_code == 201

    listed = client.get(f"{API_PREFIX}/tokens").json()["tokens"]
    assert [t["name"] for t in listed] == ["cli"]
    for row in listed:
        assert "token" not in row and "token_hash" not in row and "salt" not in row

    # Bob sees only his own (none).
    bob = make_client_from(client)
    login(bob, "bob", "bob-pw")
    assert bob.get(f"{API_PREFIX}/tokens").json()["tokens"] == []


def test_token_revocation_ownership_rules(identity: IdentityService, api: ApiV1):
    alice_token = identity.mint_token("alice", "cli")
    client = make_client(api)

    # Bob cannot revoke Alice's token — and cannot tell it exists: the
    # response is identical to a nonexistent id.
    bob = make_client(api)
    bob_csrf = login(bob, "bob", "bob-pw")
    h = {CSRF_HEADER: bob_csrf}
    foreign = bob.delete(f"{API_PREFIX}/tokens/{alice_token.id}", headers=h)
    missing = bob.delete(f"{API_PREFIX}/tokens/999999", headers=h)
    junk = bob.delete(f"{API_PREFIX}/tokens/not-a-number", headers=h)
    assert foreign.status_code == missing.status_code == junk.status_code == 404
    assert foreign.json() == missing.json() == junk.json()
    # The token still works.
    assert identity.resolve_api_token(alice_token.token) is not None

    # Alice revokes her own; the bearer credential dies immediately.
    alice_csrf = login(client, "alice", "alice-pw")
    resp = client.delete(
        f"{API_PREFIX}/tokens/{alice_token.id}", headers={CSRF_HEADER: alice_csrf}
    )
    assert resp.status_code == 204
    assert identity.resolve_api_token(alice_token.token) is None

    # Admin may revoke anyone's.
    bob_token = identity.mint_token("bob", "cli")
    admin = make_client(api)
    admin_csrf = login(admin, "admin", "admin-pw")
    resp = admin.delete(
        f"{API_PREFIX}/tokens/{bob_token.id}", headers={CSRF_HEADER: admin_csrf}
    )
    assert resp.status_code == 204
    assert identity.resolve_api_token(bob_token.token) is None


def test_token_mint_validation(client: TestClient):
    csrf = login(client, "alice", "alice-pw")
    h = {CSRF_HEADER: csrf}
    assert_envelope(
        client.post(f"{API_PREFIX}/tokens", json={}, headers=h), 400, "invalid_request"
    )
    assert_envelope(
        client.post(
            f"{API_PREFIX}/tokens", json={"name": "t", "expires_in": "soon"}, headers=h
        ),
        400,
        "invalid_request",
    )
    assert_envelope(
        client.post(
            f"{API_PREFIX}/tokens", json={"name": "t", "expires_in": -5}, headers=h
        ),
        400,
        "invalid_request",
    )


# ---------------------------------------------------------------------------
# LDAP: login through the same endpoint; admin sync trigger
# ---------------------------------------------------------------------------


def make_ldap_api(identity: IdentityService):
    """An ApiV1 wired to the A5 mock directory (ldap3 MOCK_SYNC)."""
    pytest.importorskip("ldap3")
    from test_ldap import base_entries, make_config, mock_factory

    from cortex.ldap import DirectoryService, LdapClient

    ldap_cfg = make_config()
    config = CortexConfig(ldap=ldap_cfg)
    directory = DirectoryService(
        identity,
        ldap_cfg,
        client=LdapClient(ldap_cfg, connection_factory=mock_factory(base_entries())),
    )
    return make_api(identity, config=config, directory=directory)


def test_ldap_login_via_api(identity: IdentityService):
    api = make_ldap_api(identity)
    client = make_client(api)
    # 'alice' exists as a local user (fixture) — local path wins for her; use
    # the directory-only user 'bob'? bob is local too. Use a fresh LDAP-only
    # identity set instead.
    resp = client.post(
        f"{API_PREFIX}/auth/login", json={"username": "alice", "password": "alice-pw"}
    )
    # Local alice logs in via the local path even with LDAP configured.
    assert resp.status_code == 200
    assert resp.json()["user"]["auth_source"] == "local"


def test_ldap_only_user_login_and_session(tmp_path: Path):
    identity = IdentityService(Database(tmp_path / "ldap-only.sqlite"))
    api = make_ldap_api(identity)
    client = make_client(api)
    resp = client.post(
        f"{API_PREFIX}/auth/login", json={"username": "alice", "password": "alice-pw"}
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user"]["auth_source"] == "ldap"
    assert "engineering" in body["user"]["groups"]  # mapped group refreshed

    me = client.get(f"{API_PREFIX}/auth/me")
    assert me.status_code == 200 and me.json()["user"]["username"] == "alice"

    bad = client.post(
        f"{API_PREFIX}/auth/login", json={"username": "alice", "password": "wrong"}
    )
    assert_envelope(bad, 401, "invalid_credentials")


def test_ldap_sync_endpoint(identity: IdentityService):
    api = make_ldap_api(identity)
    client = make_client(api)
    csrf = login(client, "admin", "admin-pw")
    resp = client.post(
        f"{API_PREFIX}/ldap/sync?dry_run=true", headers={CSRF_HEADER: csrf}
    )
    assert resp.status_code == 200
    report = resp.json()
    assert report["dry_run"] is True
    # local alice/bob collide with directory names → skipped, not touched.
    assert any("alice" in s for s in report["skipped"])

    applied = client.post(f"{API_PREFIX}/ldap/sync", headers={CSRF_HEADER: csrf})
    assert applied.json()["dry_run"] is False


def test_ldap_sync_without_ldap_config(client: TestClient):
    csrf = login(client, "admin", "admin-pw")
    assert_envelope(
        client.post(f"{API_PREFIX}/ldap/sync", headers={CSRF_HEADER: csrf}),
        400,
        "ldap_not_configured",
    )


def test_ldap_outage_is_503(tmp_path: Path):
    ldap3 = pytest.importorskip("ldap3")
    from test_ldap import make_config

    from cortex.ldap import DirectoryService, LdapClient

    def outage_factory(user, password):
        raise ldap3.core.exceptions.LDAPSocketOpenError("connection refused")

    identity = IdentityService(Database(tmp_path / "outage.sqlite"))
    ldap_cfg = make_config()
    directory = DirectoryService(
        identity,
        ldap_cfg,
        client=LdapClient(ldap_cfg, connection_factory=outage_factory),
    )
    api = make_api(identity, config=CortexConfig(ldap=ldap_cfg), directory=directory)
    client = make_client(api)
    resp = client.post(
        f"{API_PREFIX}/auth/login", json={"username": "someone", "password": "pw"}
    )
    assert_envelope(resp, 503, "directory_unavailable")


# ---------------------------------------------------------------------------
# request logging
# ---------------------------------------------------------------------------


def test_request_log_records_shape_and_no_secrets(
    identity: IdentityService, caplog: pytest.LogCaptureFixture
):
    api = make_api(identity, config=CortexConfig(server=ServerConfig(request_log=True)))
    client = make_client(api)
    with caplog.at_level(logging.INFO, logger="cortex.api.access"):
        login(client, "alice", "alice-pw")
        client.get(f"{API_PREFIX}/auth/me")
    messages = [r.getMessage() for r in caplog.records if r.name == "cortex.api.access"]
    assert any(
        "method=POST path=/api/v1/auth/login" in m
        and "principal=user:alice" in m
        and "status=200" in m
        for m in messages
    )
    assert any("path=/api/v1/auth/me" in m for m in messages)
    assert all("alice-pw" not in m for m in messages)  # never the password


def test_request_log_off_by_default(
    client: TestClient, caplog: pytest.LogCaptureFixture
):
    with caplog.at_level(logging.INFO, logger="cortex.api.access"):
        login(client, "alice", "alice-pw")
    assert not [r for r in caplog.records if r.name == "cortex.api.access"]


# ---------------------------------------------------------------------------
# wiring: the route group exists iff the identity DB does
# ---------------------------------------------------------------------------


def _http_config(tmp_path: Path, *, with_db: bool) -> CortexConfig:
    vault = tmp_path / "vault"
    vault.mkdir(exist_ok=True)
    db_path = tmp_path / "data" / "cortex.sqlite"
    if with_db:
        Database(db_path)  # creates + migrates the identity DB
    return CortexConfig(
        vault=VaultConfig(path=vault),
        index=IndexConfig(path=tmp_path / "cortex.index.sqlite"),
        admin=AdminConfig(enabled=False, path=tmp_path / "cortex.admin.json"),
        database=DatabaseConfig(path=db_path),
        principals=[Principal(name="web", scopes=["**"], token="tok-web")],
        server=ServerConfig(transport="http", host="127.0.0.1", port=8765),
    )


def test_build_http_server_mounts_api_when_db_exists(tmp_path: Path):
    from cortex.server import build_http_server

    srv = build_http_server(_http_config(tmp_path, with_db=True))
    assert srv.api is not None
    paths = {r.path for r in srv.mcp._custom_starlette_routes}
    assert f"{API_PREFIX}/auth/login" in paths
    assert f"{API_PREFIX}/users/{{username}}" in paths
    assert f"{API_PREFIX}/tokens" in paths


def test_build_http_server_skips_api_without_db(tmp_path: Path):
    from cortex.server import build_http_server

    srv = build_http_server(_http_config(tmp_path, with_db=False))
    assert srv.api is None
    assert not any(
        r.path.startswith(API_PREFIX) for r in srv.mcp._custom_starlette_routes
    )
