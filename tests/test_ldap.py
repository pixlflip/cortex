"""A5 tests: LDAP / Active Directory integration.

Everything runs offline: directory behavior is ldap3's MOCK_SYNC strategy
(an in-memory fake server), outages are a factory that raises, and the
import-safety test blocks ldap3 from a fresh module load. No network.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

import cortex.ldap as ldap_mod
from cortex.cli import main
from cortex.config import ConfigError, LdapAttributeMap, LdapConfig, load_config
from cortex.db import Database
from cortex.ldap import (
    DirectoryService,
    LdapClient,
    LdapError,
    LdapUnavailableError,
    escape_filter_value,
)
from cortex.users import IdentityService

ldap3 = pytest.importorskip("ldap3")

SVC_DN = "cn=cortex-svc,ou=svc,dc=example,dc=com"
SVC_PW = "svc-pw"
PEOPLE = "ou=people,dc=example,dc=com"
GROUPS = "ou=groups,dc=example,dc=com"
ALICE_DN = f"cn=Alice Adams,{PEOPLE}"
BOB_DN = f"cn=Bob Brown,{PEOPLE}"
ENG_DN = f"cn=Engineering,{GROUPS}"
OPS_DN = f"cn=Ops,{GROUPS}"


def base_entries() -> dict[str, dict]:
    """A small AD-flavored directory; tests mutate their own copy."""
    return {
        SVC_DN: {"objectClass": ["person"], "cn": "cortex-svc", "userPassword": SVC_PW},
        ALICE_DN: {
            "objectClass": ["person"],
            "userPassword": "alice-pw",
            "sAMAccountName": "alice",
            "displayName": "Alice Adams",
            "mail": "alice@example.com",
        },
        BOB_DN: {
            "objectClass": ["person"],
            "userPassword": "bob-pw",
            "sAMAccountName": "bob",
            "displayName": "Bob Brown",
            "mail": "bob@example.com",
        },
        ENG_DN: {"objectClass": ["group"], "cn": "Engineering", "member": [ALICE_DN]},
        OPS_DN: {"objectClass": ["group"], "cn": "Ops", "member": [BOB_DN]},
    }


def make_config(**overrides) -> LdapConfig:
    kwargs = dict(
        server_uri="ldap://directory.example.com",
        starttls=True,
        bind_dn=SVC_DN,
        bind_password_env="CORTEX_LDAP_BIND_PASSWORD",
        bind_password=SVC_PW,
        user_base_dn=PEOPLE,
        user_filter="(sAMAccountName={username})",
        attributes=LdapAttributeMap(
            username="sAMAccountName", display_name="displayName", email="mail"
        ),
        group_base_dn=GROUPS,
        group_filter="(objectClass=group)",
        group_member_attr="member",
        # one mapping by DN, one by group name — both forms must work
        group_mappings={ENG_DN: "engineering", "Ops": "ops"},
        jit_provisioning=True,
    )
    kwargs.update(overrides)
    return LdapConfig(**kwargs)


def mock_factory(entries: dict[str, dict]):
    """A ConnectionFactory over ldap3 MOCK_SYNC sharing one entry set.
    Each call sees the *current* contents of ``entries``, so tests can
    mutate the fake directory between operations. (The mock DIT lives on
    the Server object, so every connection gets a fresh Server.)"""

    def factory(user, password):
        conn = ldap3.Connection(
            ldap3.Server("fake-directory"),
            user=user,
            password=password,
            client_strategy=ldap3.MOCK_SYNC,
            raise_exceptions=False,
        )
        for dn, attrs in entries.items():
            conn.strategy.add_entry(dn, dict(attrs))
        return conn

    return factory


def outage_factory(user, password):
    raise ldap3.core.exceptions.LDAPSocketOpenError("connection refused")


@pytest.fixture
def entries() -> dict[str, dict]:
    return base_entries()


@pytest.fixture
def identity(tmp_path: Path) -> IdentityService:
    return IdentityService(Database(tmp_path / "cortex.sqlite"))


@pytest.fixture
def directory(identity: IdentityService, entries) -> DirectoryService:
    cfg = make_config()
    client = LdapClient(cfg, connection_factory=mock_factory(entries))
    return DirectoryService(identity, cfg, client)


# --------------------------------------------------------------------------
# bind authentication + JIT provisioning
# --------------------------------------------------------------------------

def test_bind_login_jit_provisions_user_with_mapped_groups(
    directory: DirectoryService, identity: IdentityService
):
    result = directory.login("alice", "alice-pw")
    assert result is not None

    user = identity.get_user("alice")
    assert user["auth_source"] == "ldap"
    assert user["ldap_dn"] == ALICE_DN
    assert user["display_name"] == "Alice Adams"
    assert user["email"] == "alice@example.com"
    # no local password material, ever (design §3.2)
    assert user["password_salt"] is None and user["password_hash"] is None

    # group mapped by DN, created on demand with source=ldap
    group = identity.get_group("engineering")
    assert group["source"] == "ldap"
    assert [m["username"] for m in identity.groups.members(group["id"])] == ["alice"]
    # unmapped directory groups produce nothing
    assert identity.groups.get_by_name("Ops") is None

    # the minted session is a real session (§9.2 step 4)
    assert identity.resolve_session(result.session_token)["username"] == "alice"


def test_wrong_password_and_unknown_user_rejected_uniformly(
    directory: DirectoryService, identity: IdentityService
):
    assert directory.login("alice", "wrong") is None
    assert directory.login("nobody", "whatever") is None
    assert directory.login("alice", "") is None  # unauthenticated-bind trap
    assert identity.users.get_by_username("alice") is None  # no row on failure


def test_login_refreshes_attributes_and_groups(
    directory: DirectoryService, identity: IdentityService, entries
):
    assert directory.login("alice", "alice-pw") is not None
    # directory drift: new mail, moved from Engineering to Ops
    entries[ALICE_DN]["mail"] = "a.adams@example.com"
    entries[ENG_DN]["member"] = []
    entries[OPS_DN]["member"] = [ALICE_DN, BOB_DN]

    assert directory.login("alice", "alice-pw") is not None
    user = identity.get_user("alice")
    assert user["email"] == "a.adams@example.com"
    names = {g["name"] for g in identity.groups.groups_for_user(user["id"])}
    assert names == {"ops"}


def test_jit_provisioning_toggle(identity: IdentityService, entries):
    cfg = make_config(jit_provisioning=False)
    client = LdapClient(cfg, connection_factory=mock_factory(entries))
    directory = DirectoryService(identity, cfg, client)

    # unknown username: refused before any directory traffic
    assert directory.login("alice", "alice-pw") is None
    assert identity.users.get_by_username("alice") is None

    # a pre-synced ldap row may still log in
    identity.users.create("alice", auth_source="ldap", ldap_dn=ALICE_DN)
    assert directory.login("alice", "alice-pw") is not None


def test_disabled_ldap_user_cannot_login(
    directory: DirectoryService, identity: IdentityService
):
    assert directory.login("alice", "alice-pw") is not None
    identity.disable_user("alice")
    assert directory.login("alice", "alice-pw") is None


# --------------------------------------------------------------------------
# local users are never bound to LDAP
# --------------------------------------------------------------------------

class ExplodingClient:
    """A client that fails the test if the local path ever consults LDAP."""

    def authenticate(self, username, password):  # pragma: no cover
        raise AssertionError("local users must never reach the directory")

    def search_users(self):  # pragma: no cover
        raise AssertionError("unexpected directory search")


def test_local_user_always_takes_local_path(identity: IdentityService, entries):
    # 'carol' exists both locally and (hypothetically) in the directory;
    # the exploding client proves the directory is never consulted.
    identity.create_user("carol", password="local-pw")
    directory = DirectoryService(identity, make_config(), ExplodingClient())
    assert directory.login("carol", "local-pw") is not None
    assert directory.login("carol", "wrong") is None


def test_ldap_user_cannot_set_local_password(
    directory: DirectoryService, identity: IdentityService
):
    directory.login("alice", "alice-pw")
    with pytest.raises(ValueError, match="only local users carry a password"):
        identity.set_password("alice", "sneaky")
    # and the local login path refuses the row outright (A4 seam)
    assert identity.login("alice", "alice-pw") is None


# --------------------------------------------------------------------------
# directory sync
# --------------------------------------------------------------------------

def seed_for_sync(identity: IdentityService) -> None:
    identity.create_user("local-admin", password="pw", is_admin=True)
    identity.users.create("ghost", auth_source="ldap", ldap_dn="cn=ghost")


def test_sync_dry_run_reports_and_writes_nothing(
    directory: DirectoryService, identity: IdentityService
):
    seed_for_sync(identity)
    before = identity.list_users()

    report = directory.sync(dry_run=True)
    assert report.dry_run is True
    assert sorted(report.added) == ["alice", "bob"]
    assert report.updated == []
    assert report.disabled == ["ghost"]  # gone from the directory
    assert sorted(report.group_changes) == [
        "alice: +engineering",
        "bob: +ops",
    ]

    # zero writes: same rows, same enabled/disabled state, no groups created
    assert identity.list_users() == before
    assert identity.groups.list() == []


def test_sync_adds_updates_disables_and_reconciles(
    directory: DirectoryService, identity: IdentityService, entries
):
    seed_for_sync(identity)
    report = directory.sync()
    assert sorted(report.added) == ["alice", "bob"]
    assert report.disabled == ["ghost"]

    alice = identity.get_user("alice")
    assert alice["auth_source"] == "ldap"
    assert alice["password_hash"] is None
    assert {g["name"] for g in identity.groups.groups_for_user(alice["id"])} == {
        "engineering"
    }
    ghost = identity.get_user("ghost")
    assert ghost["disabled"] == 1  # disabled, not deleted
    assert identity.get_user("local-admin")["disabled"] == 0  # untouched

    # a second sync is a no-op
    report = directory.sync()
    assert not report.changed

    # drift: alice's mail changes and she moves engineering -> ops
    entries[ALICE_DN]["mail"] = "new@example.com"
    entries[ENG_DN]["member"] = []
    entries[OPS_DN]["member"] = [ALICE_DN, BOB_DN]
    report = directory.sync()
    assert report.updated == ["alice"]
    assert "alice: +ops -engineering" in report.group_changes
    alice = identity.get_user("alice")
    assert alice["email"] == "new@example.com"
    assert {g["name"] for g in identity.groups.groups_for_user(alice["id"])} == {"ops"}


def test_sync_never_touches_local_users(
    identity: IdentityService, entries
):
    # a directory entry whose username collides with a local account
    identity.create_user("alice", password="pw")
    cfg = make_config()
    directory = DirectoryService(
        identity, cfg, LdapClient(cfg, connection_factory=mock_factory(entries))
    )
    report = directory.sync()
    assert "alice" not in report.added + report.updated + report.disabled
    assert any("alice" in reason for reason in report.skipped)
    user = identity.get_user("alice")
    assert user["auth_source"] == "local"
    assert user["password_hash"] is not None
    # bind login for that name also refuses to convert/overwrite
    assert directory.login("alice", "alice-pw") is None


def test_sync_preserves_purely_local_group_membership(
    directory: DirectoryService, identity: IdentityService
):
    directory.sync()
    identity.create_group("vip", scopes=["Secret/**"])
    identity.add_to_group("alice", "vip")
    directory.sync()
    alice = identity.get_user("alice")
    names = {g["name"] for g in identity.groups.groups_for_user(alice["id"])}
    assert names == {"engineering", "vip"}  # unmapped local group survives


# --------------------------------------------------------------------------
# outage degradation
# --------------------------------------------------------------------------

def test_outage_degrades_gracefully(identity: IdentityService):
    identity.create_user("local-admin", password="pw", is_admin=True)
    identity.users.create("alice", auth_source="ldap", ldap_dn=ALICE_DN)
    cfg = make_config()
    directory = DirectoryService(
        identity, cfg, LdapClient(cfg, connection_factory=outage_factory)
    )
    with pytest.raises(LdapUnavailableError):
        directory.login("alice", "alice-pw")
    with pytest.raises(LdapUnavailableError):
        directory.sync()
    assert identity.get_user("alice")["disabled"] == 0  # no writes on outage
    # local logins never touch the directory and keep working (§7.4)
    assert directory.login("local-admin", "pw") is not None


# --------------------------------------------------------------------------
# filter injection (RFC 4515 escaping)
# --------------------------------------------------------------------------

def test_escape_filter_value():
    assert escape_filter_value("alice") == "alice"
    assert escape_filter_value("a*b(c)d\\e") == "a\\2ab\\28c\\29d\\5ce"
    assert escape_filter_value("nul\x00ctl\n") == "nul\\00ctl\\0a"


def test_injection_attempt_is_escaped(
    directory: DirectoryService, identity: IdentityService
):
    # would match every user (and bind as the first hit) if unescaped
    assert directory.login("*", "alice-pw") is None
    assert directory.login("ali*)(sAMAccountName=*", "alice-pw") is None
    assert directory.login("alice)(objectClass=*", "alice-pw") is None
    assert identity.list_users() == []


# --------------------------------------------------------------------------
# inert without config / importable without ldap3
# --------------------------------------------------------------------------

def test_config_absent_means_ldap_off(tmp_path: Path):
    cfg_path = tmp_path / "cortex.yaml"
    cfg_path.write_text("vault:\n  path: ./vault\n", encoding="utf-8")
    assert load_config(cfg_path).ldap is None


def test_config_validation(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CORTEX_LDAP_PW", "secret")

    def load(block: str):
        cfg_path = tmp_path / "cortex.yaml"
        cfg_path.write_text(f"vault:\n  path: ./vault\nldap:\n{block}", encoding="utf-8")
        return load_config(cfg_path)

    good = load(
        "  server_uri: ldaps://ad.example.com\n"
        "  bind_dn: cn=svc\n"
        "  bind_password_env: CORTEX_LDAP_PW\n"
        "  user_base_dn: ou=people\n"
        '  user_filter: "(uid={username})"\n'
        "  group_base_dn: ou=groups\n"
        "  group_mappings:\n    cn=Eng,ou=groups: engineering\n"
    )
    assert good.ldap is not None
    assert good.ldap.bind_password == "secret"  # resolved from env, not the file
    assert good.ldap.group_mappings == {"cn=Eng,ou=groups": "engineering"}

    with pytest.raises(ConfigError, match="bind_password_env is required"):
        load("  server_uri: ldaps://x\n  bind_dn: cn=svc\n  user_base_dn: ou=p\n")
    with pytest.raises(ConfigError, match="env var is unset"):
        load(
            "  server_uri: ldaps://x\n  bind_dn: cn=svc\n  user_base_dn: ou=p\n"
            "  bind_password_env: CORTEX_LDAP_MISSING\n"
        )
    with pytest.raises(ConfigError, match="ldaps:// or starttls"):
        load(
            "  server_uri: ldap://x\n  bind_dn: cn=svc\n  user_base_dn: ou=p\n"
            "  bind_password_env: CORTEX_LDAP_PW\n"
        )
    with pytest.raises(ConfigError, match="username.*placeholder"):
        load(
            "  server_uri: ldaps://x\n  bind_dn: cn=svc\n  user_base_dn: ou=p\n"
            "  bind_password_env: CORTEX_LDAP_PW\n"
            '  user_filter: "(uid=alice)"\n'
        )
    with pytest.raises(ConfigError, match="group_base_dn"):
        load(
            "  server_uri: ldaps://x\n  bind_dn: cn=svc\n  user_base_dn: ou=p\n"
            "  bind_password_env: CORTEX_LDAP_PW\n"
            "  group_mappings:\n    cn=Eng: engineering\n"
        )


def test_module_imports_without_ldap3(monkeypatch):
    """cortex.ldap must import with ldap3 absent and fail clearly on use."""
    monkeypatch.setitem(sys.modules, "ldap3", None)  # None => ImportError
    try:
        mod = importlib.reload(ldap_mod)
        assert mod.ldap3 is None
        with pytest.raises(mod.LdapError, match=r"cortex-memory\[ldap\]"):
            mod.LdapClient(make_config())
        # a factory-injected client is constructible; only real use needs ldap3
        assert mod.escape_filter_value("(x)") == "\\28x\\29"
    finally:
        monkeypatch.undo()
        importlib.reload(ldap_mod)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CORTEX_LDAP_BIND_PASSWORD", SVC_PW)
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
ldap:
  server_uri: ldap://127.0.0.1:1
  allow_insecure: true
  bind_dn: {SVC_DN}
  bind_password_env: CORTEX_LDAP_BIND_PASSWORD
  user_base_dn: {PEOPLE}
  user_filter: "(sAMAccountName={{username}})"
  attributes:
    username: sAMAccountName
    display_name: displayName
    email: mail
  group_base_dn: {GROUPS}
  group_filter: "(objectClass=group)"
  group_mappings:
    {ENG_DN}: engineering
    Ops: ops
""",
        encoding="utf-8",
    )
    return cfg_path


def test_cli_ldap_requires_config(tmp_path: Path, capsys):
    cfg_path = tmp_path / "cortex.yaml"
    (tmp_path / "vault").mkdir()
    cfg_path.write_text(
        f"vault:\n  path: {tmp_path / 'vault'}\n  git:\n    enabled: false\n",
        encoding="utf-8",
    )
    assert main(["-c", str(cfg_path), "ldap", "sync"]) == 2
    assert "not configured" in capsys.readouterr().err


def test_cli_ldap_sync_and_check(cli_env: Path, entries, monkeypatch, capsys):
    c = str(cli_env)
    assert main(["-c", c, "db", "init"]) == 0
    capsys.readouterr()

    # route the CLI's client construction onto the mock directory
    factory = mock_factory(entries)
    monkeypatch.setattr(
        ldap_mod.LdapClient,
        "_default_connection_factory",
        lambda self, user, password: factory(user, password),
    )

    assert main(["-c", c, "ldap", "check"]) == 0
    assert "ok" in capsys.readouterr().out

    assert main(["-c", c, "ldap", "sync", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "would add: 2" in out and "alice" in out and "dry run" in out

    assert main(["-c", c, "ldap", "sync"]) == 0
    out = capsys.readouterr().out
    assert "add: 2" in out
    assert main(["-c", c, "user", "list"]) == 0
    out = capsys.readouterr().out
    assert "alice  (ldap)" in out and "bob  (ldap)" in out


def test_cli_ldap_outage_is_a_clear_error(cli_env: Path, capsys):
    c = str(cli_env)
    assert main(["-c", c, "db", "init"]) == 0
    capsys.readouterr()
    # ldap://127.0.0.1:1 — nothing listens; must fail fast and clearly
    assert main(["-c", c, "ldap", "sync"]) == 1
    err = capsys.readouterr().err
    assert "local logins are unaffected" in err
