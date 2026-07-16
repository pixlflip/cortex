"""Tests for the SQLite data layer (v2 A3, #37): migrations + versioning,
repositories, concurrency, admin.json import, and the ``cortex db`` CLI."""

from __future__ import annotations

import json
import sqlite3
import threading
import time

import pytest

from cortex.admin import AdminStore
from cortex.db import (
    ApiTokensRepo,
    Database,
    GroupsRepo,
    MIGRATIONS,
    Migration,
    MigrationsPendingError,
    SchemaVersionError,
    SessionsRepo,
    UsersRepo,
    import_admin_state,
    latest_version,
    schema_version_of,
)
from cortex.pwhash import TOKEN_PREFIX_LEN, hash_secret


@pytest.fixture
def db(tmp_path):
    return Database(tmp_path / "cortex.sqlite")


# ---------------------------------------------------------------------------
# migrations + schema versioning
# ---------------------------------------------------------------------------

EXPECTED_TABLES = {
    "users",
    "groups",
    "user_groups",
    "sessions",
    "api_tokens",
    "mcp_servers",
    "tool_permissions",
    "tool_call_audit",
    "janitor_reports",
}


def test_open_creates_schema_and_all_tables(db):
    assert db.schema_version() == latest_version()
    assert set(db.table_counts()) == EXPECTED_TABLES
    assert all(count == 0 for count in db.table_counts().values())


def test_open_is_idempotent(tmp_path):
    path = tmp_path / "cortex.sqlite"
    Database(path)
    db2 = Database(path)  # reopen: no error, no re-apply
    assert db2.migrate() == []  # explicit re-migrate is a no-op
    assert db2.schema_version() == latest_version()


def test_pragmas_wal_and_foreign_keys(db):
    with db.connection() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_foreign_keys_enforced(db):
    with pytest.raises(sqlite3.IntegrityError):
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO api_tokens (user_id, name, token_prefix, salt, "
                "token_hash, created_at) VALUES (999, 'x', 'p', 's', 'h', 0)"
            )


def test_token_prefix_index_exists(db):
    with db.connection() as conn:
        names = {
            r["name"]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
    assert "idx_api_tokens_prefix" in names


def test_newer_schema_refuses_to_open(tmp_path):
    path = tmp_path / "cortex.sqlite"
    Database(path)
    conn = sqlite3.connect(str(path))
    conn.execute(
        "INSERT INTO schema_version (version, name, applied_at) VALUES (999, 'future', 0)"
    )
    conn.commit()
    conn.close()
    with pytest.raises(SchemaVersionError):
        Database(path)


def test_pending_migrations_raise_when_auto_migrate_off(tmp_path):
    with pytest.raises(MigrationsPendingError):
        Database(tmp_path / "cortex.sqlite", auto_migrate=False)


def test_future_migration_applies_forward_on_open(tmp_path, monkeypatch):
    path = tmp_path / "cortex.sqlite"
    base_version = latest_version()
    Database(path)  # at the current latest version

    def add_nickname(conn):
        conn.execute("ALTER TABLE users ADD COLUMN nickname TEXT")

    monkeypatch.setattr(
        "cortex.db.core.MIGRATIONS",
        MIGRATIONS + [Migration(base_version + 1, "add_nickname", add_nickname)],
    )
    db = Database(path)  # open checks version and applies forward
    assert db.schema_version() == base_version + 1
    with db.connection() as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    assert "nickname" in cols
    # and it recorded exactly once — reopening applies nothing
    assert Database(path).migrate() == []


def test_failed_migration_rolls_back(tmp_path, monkeypatch):
    path = tmp_path / "cortex.sqlite"
    base_version = latest_version()
    Database(path)

    def broken(conn):
        conn.execute("ALTER TABLE users ADD COLUMN half_done TEXT")
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "cortex.db.core.MIGRATIONS",
        MIGRATIONS + [Migration(base_version + 1, "broken", broken)],
    )
    with pytest.raises(RuntimeError):
        Database(path)
    # transaction rolled back: version unchanged, column absent
    assert schema_version_of(path) == base_version
    conn = sqlite3.connect(str(path))
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    conn.close()
    assert "half_done" not in cols


def test_schema_version_of_absent_and_foreign(tmp_path):
    assert schema_version_of(tmp_path / "missing.sqlite") == 0
    foreign = tmp_path / "foreign.sqlite"
    conn = sqlite3.connect(str(foreign))
    conn.execute("CREATE TABLE t (x)")
    conn.commit()
    conn.close()
    assert schema_version_of(foreign) == 0


# ---------------------------------------------------------------------------
# users
# ---------------------------------------------------------------------------


def test_user_crud(db):
    users = UsersRepo(db)
    u = users.create("alice", password="pw1", display_name="Alice", email="a@x")
    assert u["username"] == "alice"
    assert u["auth_source"] == "local"
    assert not u["is_admin"] and not u["disabled"]
    assert users.get(u["id"])["username"] == "alice"
    assert users.get_by_username("alice")["id"] == u["id"]
    users.create("bob", password="pw2")
    assert [x["username"] for x in users.list()] == ["alice", "bob"]
    updated = users.update(u["id"], display_name="Alice B", is_admin=True)
    assert updated["display_name"] == "Alice B" and updated["is_admin"] == 1
    assert users.delete(u["id"]) is True
    assert users.get(u["id"]) is None
    assert users.delete(u["id"]) is False


def test_user_username_unique(db):
    users = UsersRepo(db)
    users.create("alice", password="pw")
    with pytest.raises(sqlite3.IntegrityError):
        users.create("alice", password="other")


def test_user_validation(db):
    users = UsersRepo(db)
    with pytest.raises(ValueError):
        users.create("", password="pw")
    with pytest.raises(ValueError):
        users.create("x", auth_source="magic")
    with pytest.raises(ValueError):
        users.create("x", auth_source="ldap", password="pw")  # ldap: no password
    with pytest.raises(ValueError):
        users.create("x", password="pw", password_salt="ab", password_hash="cd")
    u = users.create("alice", password="pw")
    with pytest.raises(ValueError):
        users.update(u["id"], password_hash="sneaky")  # not whitelisted


def test_password_verify_and_change(db):
    users = UsersRepo(db)
    u = users.create("alice", password="pw1")
    assert users.verify_password("alice", "pw1")["id"] == u["id"]
    assert users.verify_password("alice", "wrong") is None
    assert users.verify_password("nobody", "pw1") is None
    users.set_password(u["id"], "pw2")
    assert users.verify_password("alice", "pw1") is None
    assert users.verify_password("alice", "pw2") is not None
    users.update(u["id"], disabled=True)
    assert users.verify_password("alice", "pw2") is None  # disabled: no login


def test_ldap_user_never_verifies_password(db):
    users = UsersRepo(db)
    u = users.create("carol", auth_source="ldap", ldap_dn="cn=carol,dc=x")
    assert u["password_salt"] is None and u["password_hash"] is None
    assert users.verify_password("carol", "anything") is None
    with pytest.raises(ValueError):
        users.set_password(u["id"], "pw")


def test_touch_last_login(db):
    users = UsersRepo(db)
    u = users.create("alice", password="pw")
    assert u["last_login_at"] is None
    users.touch_last_login(u["id"], when=12345)
    assert users.get(u["id"])["last_login_at"] == 12345


# ---------------------------------------------------------------------------
# groups + membership
# ---------------------------------------------------------------------------


def test_group_crud_and_scopes(db):
    groups = GroupsRepo(db)
    g = groups.create("research", scopes=["Projects/Research/**"])
    assert g["source"] == "local"
    assert groups.get_by_name("research")["id"] == g["id"]
    assert groups.scopes(g["id"]) == ["Projects/Research/**"]
    groups.set_scopes(g["id"], ["Public/**"])
    assert groups.scopes(g["id"]) == ["Public/**"]
    with pytest.raises(sqlite3.IntegrityError):
        groups.create("research")
    with pytest.raises(ValueError):
        groups.create("x", source="magic")
    assert groups.delete(g["id"]) is True
    assert groups.get(g["id"]) is None


def test_membership(db):
    users, groups = UsersRepo(db), GroupsRepo(db)
    u1 = users.create("alice", password="pw")
    u2 = users.create("bob", password="pw")
    g = groups.create("research")
    assert groups.add_member(g["id"], u1["id"]) is True
    assert groups.add_member(g["id"], u1["id"]) is False  # idempotent
    groups.add_member(g["id"], u2["id"])
    assert [m["username"] for m in groups.members(g["id"])] == ["alice", "bob"]
    assert [x["name"] for x in groups.groups_for_user(u1["id"])] == ["research"]
    assert groups.remove_member(g["id"], u2["id"]) is True
    assert groups.remove_member(g["id"], u2["id"]) is False
    assert [m["username"] for m in groups.members(g["id"])] == ["alice"]


def test_cascades_on_user_delete(db):
    users, groups, tokens, sessions = (
        UsersRepo(db),
        GroupsRepo(db),
        ApiTokensRepo(db),
        SessionsRepo(db),
    )
    u = users.create("alice", password="pw")
    g = groups.create("research")
    groups.add_member(g["id"], u["id"])
    tokens.create(u["id"], "t1")
    sessions.create(u["id"], ttl_seconds=60)
    users.delete(u["id"])
    counts = db.table_counts()
    assert counts["user_groups"] == 0
    assert counts["api_tokens"] == 0
    assert counts["sessions"] == 0
    assert groups.get(g["id"]) is not None  # the group itself survives


# ---------------------------------------------------------------------------
# api tokens
# ---------------------------------------------------------------------------


def test_token_mint_and_resolve(db):
    users, tokens = UsersRepo(db), ApiTokensRepo(db)
    u = users.create("alice", password="pw")
    created = tokens.create(u["id"], "claude-desktop", scopes=["Projects/**"])
    assert created.token.startswith("ctx_")
    assert created.token_prefix == created.token[:TOKEN_PREFIX_LEN]
    row = tokens.resolve(created.token)
    assert row["id"] == created.id and row["user_id"] == u["id"]
    assert json.loads(row["scopes_json"]) == ["Projects/**"]
    assert row["last_used_at"] is not None  # touched on use
    assert tokens.resolve("ctx_definitely-not-a-token") is None
    assert tokens.resolve(None) is None
    assert tokens.resolve("") is None


def test_token_revoke_and_expiry(db):
    users, tokens = UsersRepo(db), ApiTokensRepo(db)
    u = users.create("alice", password="pw")
    t1 = tokens.create(u["id"], "t1")
    assert tokens.revoke(t1.id) is True
    assert tokens.revoke(t1.id) is False  # idempotent
    assert tokens.resolve(t1.token) is None
    t2 = tokens.create(u["id"], "t2", expires_at=int(time.time()) - 1)
    assert tokens.resolve(t2.token) is None
    t3 = tokens.create(u["id"], "t3", expires_at=int(time.time()) + 3600)
    assert tokens.resolve(t3.token) is not None


def test_token_prefix_collision_still_resolves_correctly(db):
    """Two stored tokens sharing a prefix: verification picks the right one."""
    users, tokens = UsersRepo(db), ApiTokensRepo(db)
    u = users.create("alice", password="pw")
    token_a = "ctx_SAMEPREF-aaaaaaaaaaaaaaaa"
    token_b = "ctx_SAMEPREF-bbbbbbbbbbbbbbbb"
    assert token_a[:TOKEN_PREFIX_LEN] == token_b[:TOKEN_PREFIX_LEN]
    for name, tok in (("a", token_a), ("b", token_b)):
        salt, digest = hash_secret(tok)
        tokens.import_hashed(
            u["id"], name, token_prefix=tok[:TOKEN_PREFIX_LEN], salt=salt, token_hash=digest
        )
    assert tokens.resolve(token_a)["name"] == "a"
    assert tokens.resolve(token_b)["name"] == "b"
    assert tokens.resolve(token_a[:TOKEN_PREFIX_LEN] + "-cccccc") is None


def test_token_list_and_delete(db):
    users, tokens = UsersRepo(db), ApiTokensRepo(db)
    u = users.create("alice", password="pw")
    t1 = tokens.create(u["id"], "t1")
    tokens.create(u["id"], "t2")
    assert [t["name"] for t in tokens.list_for_user(u["id"])] == ["t1", "t2"]
    assert tokens.delete(t1.id) is True
    assert tokens.get(t1.id) is None


# ---------------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------------


def test_session_lifecycle(db):
    users, sessions = UsersRepo(db), SessionsRepo(db)
    u = users.create("alice", password="pw")
    s = sessions.create(u["id"], ttl_seconds=3600)
    row = sessions.resolve(s.token)
    assert row["user_id"] == u["id"]
    assert sessions.resolve("bogus") is None
    assert sessions.resolve(None) is None
    assert sessions.delete(s.id) is True
    assert sessions.resolve(s.token) is None


def test_session_expiry_and_purge(db):
    users, sessions = UsersRepo(db), SessionsRepo(db)
    u = users.create("alice", password="pw")
    live = sessions.create(u["id"], ttl_seconds=3600)
    stale = sessions.create(u["id"], ttl_seconds=1)
    # Force the second session into the past.
    with db.transaction() as conn:
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE id = ?",
            (int(time.time()) - 10, stale.id),
        )
    assert sessions.resolve(stale.token) is None  # expired: does not resolve
    assert sessions.purge_expired() == 1
    assert sessions.get(stale.id) is None
    assert sessions.resolve(live.token) is not None
    assert sessions.delete_for_user(u["id"]) == 1


def test_session_ttl_must_be_positive(db):
    users, sessions = UsersRepo(db), SessionsRepo(db)
    u = users.create("alice", password="pw")
    with pytest.raises(ValueError):
        sessions.create(u["id"], ttl_seconds=0)


# ---------------------------------------------------------------------------
# concurrency
# ---------------------------------------------------------------------------


def test_concurrent_writes_lose_nothing(db):
    users = UsersRepo(db)
    errors: list[Exception] = []

    def worker(i: int) -> None:
        try:
            for j in range(10):
                users.create(f"user-{i}-{j}", password="pw")
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(users.list()) == 80


def test_concurrent_mixed_reads_and_writes(db):
    users, tokens = UsersRepo(db), ApiTokensRepo(db)
    u = users.create("alice", password="pw")
    created = tokens.create(u["id"], "shared")
    errors: list[Exception] = []

    def resolver() -> None:
        try:
            for _ in range(20):
                assert tokens.resolve(created.token) is not None
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    def writer(i: int) -> None:
        try:
            for j in range(10):
                tokens.create(u["id"], f"t-{i}-{j}")
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=resolver) for _ in range(3)] + [
        threading.Thread(target=writer, args=(i,)) for i in range(3)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(tokens.list_for_user(u["id"])) == 31


# ---------------------------------------------------------------------------
# admin.json import
# ---------------------------------------------------------------------------


@pytest.fixture
def admin_state(tmp_path):
    store = AdminStore(tmp_path / "cortex.admin.json")
    password = store.ensure_initialized()
    store.add_role("research", ["Projects/Research/**"])
    created = store.create_client("claude-desktop", "research")
    return store, password, created


def test_admin_import_full(db, admin_state):
    store, password, client = admin_state
    report = import_admin_state(db, store.path)
    assert "admin" in report.users_created
    assert "claude-desktop" in report.users_created
    # default roles (admin/public) + research all become groups
    assert set(report.groups_created) == {"admin", "public", "research"}
    assert report.warnings == []

    users, groups, tokens = UsersRepo(db), GroupsRepo(db), ApiTokensRepo(db)
    # admin password keeps working (hash copied verbatim)
    admin = users.verify_password("admin", password)
    assert admin is not None and admin["is_admin"] == 1
    # role scopes preserved on the group
    g = groups.get_by_name("research")
    assert json.loads(g["scopes_json"]) == ["Projects/Research/**"]
    # existing client token stays valid, tied to the client's user
    row = tokens.resolve(client.token)
    assert row is not None
    client_user = users.get_by_username("claude-desktop")
    assert row["user_id"] == client_user["id"]
    assert client_user["password_hash"] is None  # token-only identity
    # client's role became a group membership
    assert [x["name"] for x in groups.groups_for_user(client_user["id"])] == ["research"]


def test_admin_import_idempotent(db, admin_state):
    store, _, client = admin_state
    first = import_admin_state(db, store.path)
    assert first.changed
    second = import_admin_state(db, store.path)
    assert not second.changed
    assert "admin" in second.users_skipped
    assert "claude-desktop" in second.users_skipped
    counts = db.table_counts()
    assert counts["users"] == 2 and counts["api_tokens"] == 1 and counts["groups"] == 3
    # token still resolves exactly once-imported
    assert ApiTokensRepo(db).resolve(client.token) is not None


def test_admin_import_does_not_clobber_existing_user(db, admin_state):
    store, password, _ = admin_state
    users = UsersRepo(db)
    users.create("admin", password="already-here", is_admin=False)
    report = import_admin_state(db, store.path)
    assert "admin" in report.users_skipped
    # pre-existing account untouched: old password still valid, flag unchanged
    assert users.verify_password("admin", "already-here") is not None
    assert users.verify_password("admin", password) is None


def test_admin_import_missing_file(db, tmp_path):
    report = import_admin_state(db, tmp_path / "nope.json")
    assert not report.changed
    assert report.warnings


def test_admin_import_unknown_role_warns(db, tmp_path):
    path = tmp_path / "cortex.admin.json"
    path.write_text(
        json.dumps(
            {
                "admin": {"username": "admin", "salt": "00", "password_hash": "00"},
                "roles": {},
                "clients": {
                    "ghost": {
                        "role": "missing-role",
                        "salt": "00",
                        "token_hash": "00",
                        "token_prefix": "ctx_xxxxxxxx",
                    }
                },
            }
        )
    )
    report = import_admin_state(db, path)
    assert any("missing-role" in w for w in report.warnings)
    assert "ghost/imported" in report.tokens_created


# ---------------------------------------------------------------------------
# config + CLI
# ---------------------------------------------------------------------------


@pytest.fixture
def project(tmp_path):
    (tmp_path / "vault").mkdir()
    cfg = tmp_path / "cortex.yaml"
    cfg.write_text("vault:\n  path: ./vault\n")
    return tmp_path, cfg


def test_config_database_default_and_override(project, tmp_path):
    from cortex.config import load_config

    base, cfg_path = project
    cfg = load_config(cfg_path)
    assert cfg.database.path == (base / "data" / "cortex.sqlite").resolve()
    cfg_path.write_text("vault:\n  path: ./vault\ndatabase:\n  path: ./elsewhere.sqlite\n")
    assert load_config(cfg_path).database.path == (base / "elsewhere.sqlite").resolve()


def test_cli_db_init_status_migrate_import(project, capsys):
    from cortex.cli import main

    base, cfg_path = project
    # seed legacy admin state so init has something to import
    store = AdminStore(base / "cortex.admin.json")
    store.ensure_initialized()
    store.add_role("research", ["Projects/**"])
    client = store.create_client("bot", "research")

    assert main(["-c", str(cfg_path), "db", "status"]) == 0
    assert "absent" in capsys.readouterr().out

    assert main(["-c", str(cfg_path), "db", "init"]) == 0
    out = capsys.readouterr().out
    assert (
        "created database" in out
        and f"0 -> {latest_version()}" in out
        and "imported legacy" in out
    )
    assert (base / "data" / "cortex.sqlite").exists()

    assert main(["-c", str(cfg_path), "db", "init"]) == 0  # idempotent
    out = capsys.readouterr().out
    assert "up to date" in out and "already imported" in out

    assert main(["-c", str(cfg_path), "db", "migrate"]) == 0
    assert "up to date" in capsys.readouterr().out

    assert main(["-c", str(cfg_path), "db", "status"]) == 0
    out = capsys.readouterr().out
    assert f"version {latest_version()}" in out
    assert "users: 2 row(s)" in out and "api_tokens: 1 row(s)" in out

    assert main(["-c", str(cfg_path), "db", "import-admin"]) == 0
    assert "nothing to import" in capsys.readouterr().out

    # the imported client token resolves against the CLI-created DB
    db = Database(base / "data" / "cortex.sqlite")
    assert ApiTokensRepo(db).resolve(client.token) is not None
