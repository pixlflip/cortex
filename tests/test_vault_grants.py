"""Explicit account-vault grants: synthetic stores, no operational credentials."""
from __future__ import annotations

import asyncio
import itertools
import json
import shutil
import sqlite3

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from starlette.applications import Starlette
from starlette.testclient import TestClient

from cortex.access import VaultAccessError, VaultAccessResolver
from cortex.api import ApiV1
from cortex.cli import main
from cortex.config import (
    CortexConfig, DatabaseConfig, Principal, VaultConfig, VaultsConfig, WritesConfig,
    load_config,
)
from cortex.db import Database, MIGRATIONS, UsersRepo, latest_version
from cortex.scopes import filter_paths, intersect_scopes, path_allowed
from cortex.server import CortexServer
from cortex.sessions import SessionAuth
from cortex.users import AuthzError, IdentityError, IdentityService
from cortex.vaults import attach_vault_manager

READ = ["Work/Studio Space/**"]
WRITE = ["Work/Studio Space/Inbox/**"]
ALLOWED = "Work/Studio Space/Inbox/a.md"
READ_ONLY = "Work/Studio Space/reference.md"
HIDDEN = "Private/secret.md"
GRANTS_URL = "/api/v1/admin/vault-grants"


@pytest.fixture
def accounts(tmp_path):
    cfg = CortexConfig(
        vault=VaultConfig(path=tmp_path / "unused-legacy"),
        vaults=VaultsConfig(root=tmp_path / "vaults", index_dir=tmp_path / "indexes"),
        database=DatabaseConfig(path=tmp_path / "identity.sqlite"),
        writes=WritesConfig(enabled=True),
    )
    identity = IdentityService(Database(cfg.database.path), cfg)
    manager = attach_vault_manager(identity, cfg)
    for name in ("admin", "alice", "bob", "carol"):
        identity.create_user(name, password="test-password", is_admin=name == "admin")
        for path in (ALLOWED, READ_ONLY, HIDDEN, "Work/Other/a.md",
                     "Work/Studio Space-extra/a.md", "Work/Studio Space/Inbox/nested/a.md"):
            target = manager.root_for(name) / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f"---\ntags: [{name}]\n---\n# Example\nneedle {name} {path}\n")
        asset = manager.root_for(name) / "Work/Studio Space/Inbox/image.bin"
        asset.write_bytes(b"synthetic attachment")
        hidden_asset = manager.root_for(name) / "Private/image.bin"
        hidden_asset.write_bytes(b"private attachment")
    yield cfg, identity, manager
    manager.close()


def grant(identity, *, read=READ, write=WRITE, vault="bob", username="alice"):
    return identity.set_vault_grant(username, vault, read_scopes=read, write_scopes=write)


def api_client(cfg, identity):
    api = ApiV1(cfg, identity, SessionAuth(identity, secure_cookies=False))
    return TestClient(Starlette(routes=api.routes()))


def login(client, username):
    response = client.post("/api/v1/auth/login", json={"username": username, "password": "test-password"})
    assert response.status_code == 200
    client.headers["X-Cortex-CSRF"] = response.json()["csrf_token"]


def call(server, tool, **kwargs):
    result = asyncio.run(server.mcp.call_tool(tool, kwargs))
    if isinstance(result, tuple):
        result = result[0]
    return "\n".join(part.text for part in result if hasattr(part, "text"))


def allow_memory_tools(identity):
    # Tool authorization is deliberately independent of vault/path grants.
    identity.tool_permissions.set(
        subject_type="user", subject_id=identity.get_user("alice")["id"],
        tool_pattern="cortex.*", effect="allow",
    )


def test_fail_closed_and_only_exact_account_gets_grant(accounts):
    cfg, identity, manager = accounts
    access = VaultAccessResolver(cfg, manager, identity)
    alice = identity.principal_for_username("alice")
    with pytest.raises(VaultAccessError):
        access.select(alice, "bob")
    row = grant(identity)
    assert row["principal"] == "alice" and row["vault"] == "bob"
    assert access.visible_vaults(alice) == ["alice", "bob"]
    bundle, scoped, resolved = access.select(alice, "bob")
    assert bundle.vault_id == "bob" and resolved.relation == "explicit"
    assert path_allowed(ALLOWED, scoped.scopes)
    assert path_allowed(ALLOWED, scoped.write_scopes)
    assert path_allowed(READ_ONLY, scoped.scopes)
    assert not path_allowed(READ_ONLY, scoped.write_scopes)
    for path in (HIDDEN, "Work/Other/a.md", "Work/Studio Space-extra/a.md", "Work/a.md"):
        assert not path_allowed(path, scoped.scopes)
        assert not path_allowed(path, scoped.write_scopes)
    for principal, vault in ((alice, "carol"), (alice, "main"),
                             (identity.principal_for_username("carol"), "bob"),
                             (Principal(name="unmapped", scopes=["**"]), "bob")):
        with pytest.raises(VaultAccessError):
            access.select(principal, vault)
    assert access.select(alice)[0].vault_id == "alice"
    assert path_allowed(HIDDEN, access.select(alice)[1].write_scopes)


@pytest.mark.parametrize("limits", [None, [], ["**"], READ, WRITE, ["Work/**"],
    ["**/a.md"], ["Work/*/Inbox/*.md"], ["Work/?tudio Space/**"],
    ["Private/**"], ["Work/*/Inbox/*.md", "Private/**"]])
def test_token_is_exact_read_and_write_intersection(accounts, limits):
    cfg, identity, manager = accounts
    grant(identity)
    access = VaultAccessResolver(cfg, manager, identity)
    principal = identity.principal_for_username("alice", token_scopes=limits)
    if limits == []:
        assert access.grants(principal) == []
        with pytest.raises(VaultAccessError):
            access.select(principal, "bob", write=True)
        return
    _, scoped, _ = access.select(principal, "bob")
    paths = [ALLOWED, READ_ONLY, HIDDEN, "Work/Other/a.md",
             "Work/Studio Space/Inbox/nested/a.md", "Work/Studio Space/Inbox/new.md",
             "Work/Studio Space/Inbox/image.bin"]
    for path in paths:
        token_allows = limits is None or path_allowed(path, limits)
        assert path_allowed(path, scoped.scopes) == (path_allowed(path, READ) and token_allows)
        assert path_allowed(path, scoped.write_scopes) == (path_allowed(path, WRITE) and token_allows)


def test_glob_intersection_algebra_and_non_subset_overlap():
    # Includes pairs for which neither glob contains the other, crossing and
    # directory-bounded stars, literal brackets, unicode and space-containing paths.
    patterns = ["**", "*", "*.md", "A/**", "A/*.md", "A/?.md", "*/x.md",
                "**/x.md", "A/*/x.*", "A/[x].md", "A/space here/*", "A/雪.*", "B/**", "A/new\nline.md"]
    paths = ["x.md", "A/x.md", "A/y.md", "A/xy.md", "A/deep/x.md", "A/[x].md",
             "A/space here/x.md", "A/雪.md", "B/x.md", "A/x.txt", "A/deep/x.txt", "A/new\nline.md"]
    for left, right in itertools.product(patterns, repeat=2):
        for path in paths:
            expected = path_allowed(path, [left]) and path_allowed(path, [right])
            assert path_allowed(path, intersect_scopes([left], [right])) == expected
    assert intersect_scopes(["A/**"], []) == ()
    assert intersect_scopes([], ["**"]) == ()
    assert filter_paths(paths, intersect_scopes(["A/**", "B/**"], ["*/x.md", "*.txt"])) == ["A/x.md", "B/x.md"]
    assert not path_allowed("A/x.md", [()])


def test_per_vault_read_only_and_write_only_do_not_fallback(accounts):
    cfg, identity, manager = accounts
    grant(identity, write=[])
    grant(identity, vault="carol", read=[], write=["Drops/**"])
    access = VaultAccessResolver(cfg, manager, identity)
    principal = identity.principal_for_username("alice")
    _, read_only, _ = access.select(principal, "bob")
    assert read_only.write_scopes == []
    with pytest.raises(VaultAccessError):
        access.select(principal, "bob", write=True)
    # Even an internal helper cannot accidentally treat [] as read-scope fallback.
    for checker in (CortexServer._require_writable, CortexServer._require_writable_file):
        with pytest.raises(ValueError):
            checker(read_only, ALLOWED)
    with pytest.raises(VaultAccessError):
        access.select(principal, "carol")
    _, write_only, _ = access.select(principal, "carol", write=True)
    assert write_only.scopes == []
    assert CortexServer._require_writable(write_only, "Drops/new.md") == "Drops/new.md"
    with pytest.raises(ValueError):
        CortexServer._require_visible(write_only, "Drops/new.md")
    with pytest.raises(ValueError):
        CortexServer._require_writable(write_only, ALLOWED)


def test_owner_admin_and_empty_token_semantics_preserved(accounts):
    cfg, identity, manager = accounts
    access = VaultAccessResolver(cfg, manager, identity)
    grant(identity, read=[], write=[])
    for username in ("alice", "admin"):
        principal = identity.principal_for_username(username)
        assert access.select(principal)[0].vault_id == username
        assert path_allowed(HIDDEN, access.select(principal)[1].write_scopes)
    assert "bob" not in access.visible_vaults(identity.principal_for_username("alice"))
    admin = identity.principal_for_username("admin")
    assert access.select(admin, "bob")[2].relation == "admin"
    assert path_allowed(HIDDEN, access.select(admin, "bob")[1].write_scopes)
    for username, vault in (("alice", "alice"), ("admin", "bob")):
        narrowed = identity.principal_for_username(username, token_scopes=WRITE)
        _, scoped, _ = access.select(narrowed, vault)
        assert scoped.scopes == scoped.write_scopes == WRITE
        assert not path_allowed(HIDDEN, scoped.scopes)
        assert access.grants(identity.principal_for_username(username, token_scopes=[])) == []


def test_mcp_reads_writes_scope_intersection_and_immediate_revocation(accounts):
    cfg, identity, manager = accounts
    grant(identity)
    allow_memory_tools(identity)
    principal = identity.principal_for_username("alice", token_scopes=["Work/*/Inbox/*.md"])
    server = CortexServer(cfg, principal, identity=identity)
    assert "needle bob" in call(server, "read_note", path=ALLOWED, vault="bob")
    assert "needle alice" in call(server, "read_note", path=ALLOWED)
    for path in (READ_ONLY, HIDDEN, "Work/Studio Space/Inbox/nested/a.md"):
        with pytest.raises(ToolError, match="not found or not in scope"):
            call(server, "read_note", path=path, vault="bob")
    for tool in ("search", "context_pack"):
        text = call(server, tool, query="needle", vault="bob")
        assert ALLOWED in text
        assert HIDDEN not in text and READ_ONLY not in text and "nested" not in text
    new_path = "Work/Studio Space/Inbox/future.md"
    result = json.loads(call(server, "write_note", path=new_path, content="new body", reason="test", vault="bob"))
    assert result["vault"] == "bob"
    assert (manager.root_for("bob") / new_path).is_file()
    assert not (manager.root_for("alice") / new_path).exists()
    for path in (READ_ONLY, HIDDEN, "Work/Studio Space/Inbox/nested/future.md"):
        with pytest.raises(ToolError, match="not found or not in scope"):
            call(server, "write_note", path=path, content="denied", reason="test", overwrite=True, vault="bob")
    with pytest.raises(ToolError, match="not found or not in scope"):
        call(server, "move_note", src=ALLOWED, dest=HIDDEN, reason="test", vault="bob")
    assert "needle bob" in (manager.root_for("bob") / ALLOWED).read_text()
    discovery = json.loads(call(server, "discover_scopes"))
    bob = next(item for item in discovery["vaults"] if item["vault"] == "bob")
    assert bob["scopes"] == [[READ[0], "Work/*/Inbox/*.md"]]
    status = json.loads(call(server, "status", vault="bob"))
    assert status["head_commit"] is None and status["index_note_count"] is None
    assert identity.revoke_vault_grant("alice", "bob")
    # Same server and principal: no permission snapshot survives revocation.
    with pytest.raises(ToolError, match="not found or not in scope"):
        call(server, "read_note", path=ALLOWED, vault="bob")
    with pytest.raises(ToolError, match="not found or not in scope"):
        call(server, "write_note", path=new_path, content="denied", overwrite=True, reason="test", vault="bob")


def test_mcp_read_only_and_attachments(accounts):
    cfg, identity, manager = accounts
    grant(identity, write=[])
    allow_memory_tools(identity)
    server = CortexServer(cfg, identity.principal_for_username("alice"), identity=identity)
    assert "content_base64" in call(server, "get_file", path="Work/Studio Space/Inbox/image.bin", vault="bob")
    assert "Private/image.bin" not in call(server, "list_files", vault="bob")
    with pytest.raises(ToolError, match="not found or not in scope"):
        call(server, "get_file", path="Private/image.bin", vault="bob")
    with pytest.raises(ToolError, match="not found or not in scope"):
        call(server, "put_file", path="Work/Studio Space/Inbox/new.bin", content_base64="eA==", reason="test", vault="bob")
    with pytest.raises(ToolError, match="not found or not in scope"):
        call(server, "append_note", path=ALLOWED, text="denied", reason="test", vault="bob")
    grant(identity)
    call(server, "put_file", path="Work/Studio Space/Inbox/new.bin", content_base64="eA==", reason="test", vault="bob")
    assert (manager.root_for("bob") / "Work/Studio Space/Inbox/new.bin").read_bytes() == b"x"
    with pytest.raises(ToolError, match="not found or not in scope"):
        call(server, "put_file", path="Private/new.bin", content_base64="eA==", reason="test", vault="bob")


def test_write_only_cannot_extract_existing_content_through_mutations(accounts):
    cfg, identity, manager = accounts
    grant(identity, read=["Readable/**"], write=["**"])
    allow_memory_tools(identity)
    server = CortexServer(cfg, identity.principal_for_username("alice"), identity=identity)
    original = (manager.root_for("bob") / HIDDEN).read_bytes()
    mutations = [
        ("write_note", {"path": HIDDEN, "content": "overwrite", "overwrite": True}),
        ("patch_note", {"path": HIDDEN, "old_string": "needle", "new_string": "probe"}),
        ("append_note", {"path": HIDDEN, "text": "append"}),
        ("update_frontmatter", {"path": HIDDEN, "patch": {}}),
        ("set_memory_state", {"path": HIDDEN, "memory_state": "current", "expected_sha256": "0" * 64}),
        ("move_note", {"src": HIDDEN, "dest": "Readable/leak.md"}),
    ]
    for tool, kwargs in mutations:
        with pytest.raises(ToolError, match="not found or not in scope"):
            call(server, tool, **kwargs, reason="test", vault="bob")
        assert (manager.root_for("bob") / HIDDEN).read_bytes() == original
    assert not (manager.root_for("bob") / "Readable/leak.md").exists()
    # Write permission alone still permits a new note without a read grant.
    call(server, "write_note", path="Drops/new.md", content="drop", reason="test", vault="bob")
    with pytest.raises(ToolError, match="not found or not in scope"):
        call(server, "read_note", path="Drops/new.md", vault="bob")
    call(server, "delete_note", path="Drops/new.md", reason="test", vault="bob")
    assert not (manager.root_for("bob") / "Drops/new.md").exists()


def test_grants_do_not_override_tool_policy_or_register_admin_tools(accounts):
    cfg, identity, _ = accounts
    grant(identity)
    server = CortexServer(cfg, identity.principal_for_username("alice"), identity=identity)
    with pytest.raises(ToolError, match="tool not available"):
        call(server, "write_note", path="Work/Studio Space/Inbox/new.md", content="x", reason="test", vault="bob")
    allow_memory_tools(identity)
    identity.tool_permissions.set(subject_type="user", subject_id=identity.get_user("alice")["id"],
                                  tool_pattern="cortex.write_note", effect="deny")
    with pytest.raises(ToolError, match="tool not available"):
        call(server, "write_note", path="Work/Studio Space/Inbox/new.md", content="x", reason="test", vault="bob")
    assert all("grant" not in tool.name for tool in asyncio.run(server.mcp.list_tools()))
    cfg.writes.enabled = False
    read_only = CortexServer(cfg, identity.principal_for_username("alice"), identity=identity)
    assert "write_note" not in {tool.name for tool in asyncio.run(read_only.mcp.list_tools())}


def test_cross_account_canonical_paths_and_symlinks_fail_closed(accounts):
    cfg, identity, manager = accounts
    grant(identity)
    allow_memory_tools(identity)
    server = CortexServer(cfg, identity.principal_for_username("alice"), identity=identity)
    link = manager.root_for("bob") / "Work/Studio Space/Inbox/link.md"
    link.symlink_to(manager.root_for("bob") / HIDDEN)
    for path in ("Work/Studio Space/Inbox/../../../Private/secret.md", str(manager.root_for("bob") / HIDDEN),
                 "Work/Studio Space/Inbox/.private.md", "Work/Studio Space/Inbox/link.md"):
        with pytest.raises(ToolError, match="not found or not in scope"):
            call(server, "read_note", path=path, vault="bob")
    manager.close()
    shutil.rmtree(manager.root_for("bob"))
    (manager.root / "bob").symlink_to(manager.root_for("carol"), target_is_directory=True)
    with pytest.raises(ToolError, match="not found or not in scope"):
        call(server, "read_note", path=ALLOWED, vault="bob")


def test_api_grant_surface_privilege_csrf_validation_and_revocation(accounts):
    cfg, identity, _ = accounts
    url = f"{GRANTS_URL}/alice/bob"
    body = {"read_scopes": READ, "write_scopes": []}
    with api_client(cfg, identity) as client:
        assert client.get(GRANTS_URL).status_code == 401
        assert client.put(url, json=body).status_code == 401
        assert client.delete(url).status_code == 401
        for username in ("alice", "bob"):
            login(client, username)
            assert client.get(GRANTS_URL).status_code == 403
            # Owner cannot delegate; grantee cannot self-escalate. Auth precedes lookup.
            for target in (url, f"{GRANTS_URL}/unknown/missing"):
                assert client.put(target, json=body).status_code == 403
                assert client.delete(target).status_code == 403
        login(client, "admin")
        csrf = client.headers.pop("X-Cortex-CSRF")
        assert client.put(url, json=body).status_code == 403
        client.headers["X-Cortex-CSRF"] = csrf
        assert client.put(url, json=body, headers={"Origin": "https://foreign.invalid"}).status_code == 403
        assert client.put(url, json=body).status_code == 200
        assert client.get(GRANTS_URL).json()["grants"][0]["write_scopes"] == []
        for bad in ({"read_scopes": READ}, {**body, "is_admin": True},
                    {"read_scopes": READ, "write_scopes": None},
                    {"read_scopes": "**", "write_scopes": []},
                    {"read_scopes": [["**"]], "write_scopes": []},
                    {"read_scopes": ["../Private/**"], "write_scopes": []}):
            assert client.put(url, json=bad).status_code == 400
        assert client.get(GRANTS_URL).json()["grants"][0]["write_scopes"] == []
        assert client.put(f"{GRANTS_URL}/alice/missing", json=body).status_code == 404
        assert client.delete(url).status_code == 204
        assert client.delete(url).status_code == 204
        assert client.get(GRANTS_URL).json() == {"grants": []}


def test_api_reads_tree_search_assets_and_metadata_are_scoped(accounts):
    cfg, identity, _ = accounts
    grant(identity)
    with api_client(cfg, identity) as client:
        login(client, "alice")
        prefix = "/api/v1/vaults/bob"
        assert client.get(f"{prefix}/notes/{ALLOWED}").status_code == 200
        denied = client.get(f"{prefix}/notes/{HIDDEN}")
        absent = client.get(f"{prefix}/notes/missing.md")
        assert denied.status_code == absent.status_code == 404
        assert denied.json() == absent.json()
        for endpoint in ("tree", "search?q=needle", "tags"):
            response = client.get(f"{prefix}/{endpoint}")
            assert response.status_code == 200
            assert "Private" not in response.text and "secret" not in response.text
        assert client.get(f"{prefix}/assets/Work/Studio Space/Inbox/image.bin").content == b"synthetic attachment"
        assert client.get(f"{prefix}/assets/Private/image.bin").status_code == 404
        assert client.get(f"{prefix}/links/{HIDDEN}").status_code == 404
        for vault in ("carol", "main", "missing"):
            assert client.get(f"/api/v1/vaults/{vault}/notes/{ALLOWED}").status_code == 404
        payload = client.get("/api/v1/vaults").json()
        assert payload["default_vault"] == "alice"
        bob = next(v for v in payload["vaults"] if v["id"] == "bob")
        assert bob["relation"] == "explicit"
        assert bob["note_count"] == 3
        assert all(bob[key] is None for key in ("head_commit", "last_commit_iso", "last_indexed_iso", "index_note_count", "sync_adapter"))
        assert client.get("/api/v1/audit/commits?vault=bob").json() == {"commits": []}
        for action in ("archive", "repair", "provision"):
            assert client.post(f"/api/v1/admin/vaults/bob/{action}").status_code == 403
        identity.revoke_vault_grant("alice", "bob")
        assert client.get(f"{prefix}/notes/{ALLOWED}").status_code == 404


def test_api_bearer_boundary_uses_token_constraints_without_minting(accounts, monkeypatch):
    # Inject at the existing identity resolution seam; no tokens are created.
    # Actual token authentication/expiry/revocation has its own regression suite.
    cfg, identity, _ = accounts
    grant(identity)
    principal = identity.principal_for_username("alice", token_scopes=["Work/*/Inbox/*.md"])
    monkeypatch.setattr(identity, "resolve_api_token", lambda token: (principal, principal.name))
    with api_client(cfg, identity) as client:
        client.headers["Authorization"] = "Bearer synthetic-test-input"
        prefix = "/api/v1/vaults/bob"
        assert client.get(f"{prefix}/notes/{ALLOWED}").status_code == 200
        assert client.get(f"{prefix}/notes/{READ_ONLY}").status_code == 404
        assert client.get(f"{prefix}/assets/Work/Studio Space/Inbox/image.bin").status_code == 404
        assert "reference.md" not in client.get(f"{prefix}/tree").text
        assert "reference.md" not in client.get(f"{prefix}/search?q=needle").text
        assert client.put(f"{GRANTS_URL}/alice/bob", json={"read_scopes": ["**"], "write_scopes": ["**"]}).status_code == 403
        principal = identity.principal_for_username("admin", token_scopes=["**"])
        assert client.get(GRANTS_URL).status_code == 403
        principal = identity.principal_for_username("admin")
        assert client.get(GRANTS_URL).status_code == 200


def test_persistence_update_revoke_and_missing_storage_no_fallback(accounts):
    cfg, identity, manager = accounts
    grant(identity)
    reopened = IdentityService(Database(cfg.database.path), cfg)
    access = VaultAccessResolver(cfg, manager, reopened)
    principal = reopened.principal_for_username("alice")
    assert access.select(principal, "bob")[2].write_scopes == tuple(WRITE)
    assert reopened.list_vault_grants()[0]["read_scopes"] == READ
    grant(identity, read=["Public/**"], write=[])
    _, scoped, _ = access.select(principal, "bob")
    assert not path_allowed(ALLOWED, scoped.scopes)
    with pytest.raises(VaultAccessError):
        access.select(principal, "bob", write=True)
    # Granting a foreign vault never changes the missing-owner default.
    manager.close()
    shutil.rmtree(manager.root_for("alice"))
    with pytest.raises(VaultAccessError):
        access.select(principal)
    assert access.select(principal, "bob")[0].vault_id == "bob"
    manager.close()
    shutil.rmtree(manager.root_for("bob"))
    with pytest.raises(VaultAccessError):
        access.select(principal, "bob")
    assert identity.revoke_vault_grant("alice", "bob")
    assert IdentityService(Database(cfg.database.path), cfg).list_vault_grants() == []


@pytest.mark.parametrize("username", ["alice", "bob"])
def test_disable_delete_and_recreate_does_not_inherit_grants(accounts, username):
    cfg, identity, manager = accounts
    grant(identity)
    access = VaultAccessResolver(cfg, manager, identity)
    principal = identity.principal_for_username("alice")
    identity.disable_user(username)
    with pytest.raises(VaultAccessError):
        access.select(principal, "bob")
    identity.enable_user(username)
    assert access.select(principal, "bob")[2].relation == "explicit"
    identity.delete_user(username)
    identity.create_user(username)
    assert identity.list_vault_grants() == []
    with pytest.raises(VaultAccessError):
        access.select(identity.principal_for_username("alice"), "bob")


def test_domain_admin_gate_checks_current_privileges(accounts):
    _, identity, _ = accounts
    admin = identity.get_user("admin")
    for actor in (identity.get_user("alice"), identity.get_user("bob"), {}):
        with pytest.raises(AuthzError):
            identity.set_vault_grant("alice", "bob", read_scopes=READ, write_scopes=[], actor=actor)
        with pytest.raises(AuthzError):
            identity.list_vault_grants(actor=actor)
        with pytest.raises(AuthzError):
            identity.revoke_vault_grant("alice", "bob", actor=actor)
    identity.disable_user("admin")
    with pytest.raises(AuthzError):
        identity.set_vault_grant("alice", "bob", read_scopes=READ, write_scopes=[], actor=admin)
    identity.enable_user("admin")
    identity.set_admin("admin", False)
    with pytest.raises(AuthzError):
        identity.set_vault_grant("alice", "bob", read_scopes=READ, write_scopes=[], actor=admin)


@pytest.mark.parametrize("value", [None, "**", [None], [""], ["/Work/**"], [" Work/**"],
    ["Work//**"], ["Work/../**"], ["Work/./**"], ["Work\\**"], ["Work/\x00*"],
    ["Work/.git/**"], [["**"]], ["x" * 1025]])
def test_invalid_scopes_never_replace_valid_grant(accounts, value):
    _, identity, _ = accounts
    grant(identity)
    with pytest.raises(IdentityError):
        grant(identity, read=value)
    assert identity.list_vault_grants()[0]["read_scopes"] == READ
    assert identity.list_vault_grants()[0]["write_scopes"] == WRITE


@pytest.mark.parametrize("vault", ["alice", "missing", "main", " bob", "bob ", "../bob", "*"])
def test_invalid_target_is_not_normalized_or_created(accounts, vault):
    _, identity, _ = accounts
    with pytest.raises(IdentityError):
        grant(identity, vault=vault)
    assert identity.list_vault_grants() == []


@pytest.mark.parametrize("bad_json", ["null", "{}", '"**"', '[null]', '[["**"]]', 'not json'])
def test_corrupt_grant_fails_closed(accounts, bad_json):
    cfg, identity, manager = accounts
    grant(identity)
    with identity.db.transaction() as conn:
        conn.execute("UPDATE vault_grants SET write_scopes_json = ?", (bad_json,))
    with pytest.raises(VaultAccessError):
        VaultAccessResolver(cfg, manager, identity).select(identity.principal_for_username("alice"), "bob")


def test_forward_migration_preserves_users_and_creates_no_grants(tmp_path, monkeypatch):
    path = tmp_path / "old.sqlite"
    with monkeypatch.context() as old:
        old.setattr("cortex.db.core.MIGRATIONS", MIGRATIONS[:4])
        db = Database(path)
        alice = UsersRepo(db).create("alice")
        bob = UsersRepo(db).create("bob")
    db = Database(path)
    assert db.schema_version() == latest_version()
    assert db.table_counts()["vault_grants"] == 0
    assert UsersRepo(db).get(alice["id"])["username"] == "alice"
    assert db.migrate() == []
    identity = IdentityService(db)
    grant(identity)
    assert identity.list_vault_grants()[0]["owner_user_id"] == bob["id"]
    for principal_id, owner_id in ((alice["id"], alice["id"]), (alice["id"], 9999)):
        with pytest.raises(sqlite3.IntegrityError):
            identity.vault_grants.set(principal_id, owner_id, read_scopes=READ, write_scopes=[], updated_by=None)


def test_local_operator_cli_persists_replaces_and_revokes(accounts, tmp_path, capsys):
    cfg, identity, _ = accounts
    config = tmp_path / "test.yaml"
    config.write_text(f"database:\n  path: {cfg.database.path}\nvaults:\n  root: {cfg.vaults.root}\n  index_dir: {cfg.vaults.index_dir}\n")
    base = ["--config", str(config), "vault", "grant"]
    assert main(base + ["set", "alice", "bob", "--read-scope", READ[0], "--write-scope", WRITE[0]]) == 0
    assert json.loads(capsys.readouterr().out)["grant"]["write_scopes"] == WRITE
    assert main(base + ["list"]) == 0
    assert json.loads(capsys.readouterr().out)["grants"][0]["read_scopes"] == READ
    assert main(base + ["set", "alice", "bob", "--read-scope", READ[0]]) == 0
    capsys.readouterr()
    assert identity.list_vault_grants()[0]["write_scopes"] == []
    assert main(base + ["set", "alice", "unknown", "--read-scope", "**"]) == 1
    capsys.readouterr()
    assert main(base + ["revoke", "alice", "bob"]) == 0
    assert identity.list_vault_grants() == []


def test_standalone_empty_writes_deny_but_unset_keeps_legacy_default(tmp_path):
    config = tmp_path / "local.yaml"
    config.write_text("principals:\n  - name: reader\n    scopes: ['**']\n    write_scopes: []\n  - name: writer\n    scopes: ['**']\n")
    cfg = load_config(config)
    reader, writer = cfg.principal("reader"), cfg.principal("writer")
    assert reader.write_scopes == [] and writer.write_scopes is None
    assert CortexServer._require_writable(writer, "new.md") == "new.md"
    with pytest.raises(ValueError):
        CortexServer._require_writable(reader, "new.md")
