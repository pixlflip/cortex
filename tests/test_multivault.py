"""B2/B3 isolation tests for the shared API/MCP vault resolver."""

from __future__ import annotations

from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from cortex.access import VaultAccessError, VaultAccessResolver
from cortex.api import API_PREFIX, ApiV1
from cortex.config import (
    CortexConfig,
    DatabaseConfig,
    IndexConfig,
    VaultConfig,
    VaultsConfig,
)
from cortex.db import Database
from cortex.sessions import SessionAuth
from cortex.server import CortexServer
from cortex.users import IdentityService
from cortex.vaults import MAIN_VAULT_ID, attach_vault_manager


@pytest.fixture
def multivault(tmp_path: Path):
    main = tmp_path / "main"
    main.mkdir()
    (main / "Shared").mkdir()
    (main / "Shared" / "visible.md").write_text("# Shared\n", encoding="utf-8")
    (main / "Private").mkdir()
    (main / "Private" / "hidden.md").write_text("# Hidden\n", encoding="utf-8")
    cfg = CortexConfig(
        vault=VaultConfig(path=main),
        vaults=VaultsConfig(
            root=tmp_path / "vaults",
            index_dir=tmp_path / "indexes",
            archive_dir=tmp_path / "archive",
        ),
        database=DatabaseConfig(path=tmp_path / "cortex.sqlite"),
        index=IndexConfig(path=tmp_path / "main.index.sqlite"),
    )
    identity = IdentityService(Database(cfg.database.path), cfg)
    manager = attach_vault_manager(identity, cfg)
    identity.create_user("admin", password="admin-pw", is_admin=True)
    identity.create_user("alice", password="alice-pw")
    identity.create_user("bob", password="bob-pw")
    identity.create_group(
        "shared", scopes=["Shared/**"], write_scopes=["Shared/Inbox/**"]
    )
    identity.add_to_group("alice", "shared")
    (manager.root_for("alice") / "Projects").mkdir()
    (manager.root_for("alice") / "Projects" / "alpha.md").write_text(
        "# Alpha\n", encoding="utf-8"
    )
    (manager.root_for("bob") / "secret.md").write_text("# Bob only\n", encoding="utf-8")
    yield cfg, identity, manager
    manager.close()


def test_container_group_and_macro_grants(multivault):
    cfg, identity, manager = multivault
    access = VaultAccessResolver(cfg, manager, identity)

    alice = identity.principal_for_username("alice")
    grants = {grant.vault_id: grant for grant in access.grants(alice)}
    assert set(grants) == {"alice", MAIN_VAULT_ID}
    assert grants["alice"].scopes == ("**",)
    assert grants[MAIN_VAULT_ID].scopes == ("Shared/**",)
    assert grants[MAIN_VAULT_ID].write_scopes == ("Shared/Inbox/**",)
    with pytest.raises(VaultAccessError):
        access.select(alice, "bob")

    admin = identity.principal_for_username("admin")
    assert set(access.visible_vaults(admin)) == {MAIN_VAULT_ID, "admin", "alice", "bob"}


def test_token_scope_narrows_own_and_shared_vaults(multivault):
    cfg, identity, manager = multivault
    access = VaultAccessResolver(cfg, manager, identity)
    created = identity.mint_token("alice", "project", scopes=["Projects/**"])
    principal, _ = identity.resolve_api_token(created.token)
    grants = {grant.vault_id: grant for grant in access.grants(principal)}
    assert grants["alice"].scopes == ("Projects/**",)
    assert MAIN_VAULT_ID not in grants

    shared = identity.mint_token("alice", "shared", scopes=["Shared/**"])
    principal, _ = identity.resolve_api_token(shared.token)
    grants = {grant.vault_id: grant for grant in access.grants(principal)}
    assert grants["alice"].scopes == ("Shared/**",)
    assert grants[MAIN_VAULT_ID].scopes == ("Shared/**",)
    assert grants[MAIN_VAULT_ID].write_scopes == ()


def test_vault_api_never_leaks_another_users_vault(multivault):
    cfg, identity, _ = multivault
    api = ApiV1(cfg, identity, SessionAuth(identity, secure_cookies=False))
    client = TestClient(Starlette(routes=api.routes()))
    login = client.post(
        f"{API_PREFIX}/auth/login",
        json={"username": "alice", "password": "alice-pw"},
    )
    assert login.status_code == 200

    own = client.get(f"{API_PREFIX}/vaults/alice/notes/Projects/alpha.md")
    assert own.status_code == 200
    assert own.json()["markdown"] == "# Alpha\n"

    foreign = client.get(f"{API_PREFIX}/vaults/bob/notes/secret.md")
    absent = client.get(f"{API_PREFIX}/vaults/does-not-exist/notes/secret.md")
    assert foreign.status_code == absent.status_code == 404
    assert foreign.json() == absent.json()

    visible = client.get(f"{API_PREFIX}/vaults/main/notes/Shared/visible.md")
    hidden = client.get(f"{API_PREFIX}/vaults/main/notes/Private/hidden.md")
    assert visible.status_code == 200
    assert hidden.status_code == 404


def test_vault_note_normalizes_date_frontmatter_without_changing_content(multivault):
    cfg, identity, manager = multivault
    raw = (
        "---\n"
        "date: 2026-04-07\n"
        "nested:\n"
        "  dates: [2026-04-08, 2026-04-09]\n"
        "title: Dated note\n"
        "published: true\n"
        "rating: 5\n"
        "optional: null\n"
        "---\n"
        "# Original body\n\nBody text stays exactly as written.\n"
    )
    note_path = manager.root_for("alice") / "Projects" / "dated.md"
    note_path.write_text(raw, encoding="utf-8")
    expected_raw = manager.get("alice").store.read_note("Projects/dated.md").raw
    api = ApiV1(cfg, identity, SessionAuth(identity, secure_cookies=False))
    client = TestClient(Starlette(routes=api.routes()))
    assert client.post(
        f"{API_PREFIX}/auth/login",
        json={"username": "alice", "password": "alice-pw"},
    ).status_code == 200

    response = client.get(f"{API_PREFIX}/vaults/alice/notes/Projects/dated.md")

    assert response.status_code == 200
    payload = response.json()
    assert payload["frontmatter"] == {
        "date": "2026-04-07",
        "nested": {"dates": ["2026-04-08", "2026-04-09"]},
        "title": "Dated note",
        "published": True,
        "rating": 5,
        "optional": None,
    }
    assert payload["markdown"] == "# Original body\n\nBody text stays exactly as written.\n"
    assert payload["raw"] == expected_raw


def test_move_note_stays_in_selected_vault_and_uses_user_actor(multivault):
    cfg, identity, manager = multivault
    principal = identity.principal_for_username("alice")
    bundle, scoped, _ = VaultAccessResolver(cfg, manager, identity).select(
        principal, "alice", write=True
    )
    server = CortexServer(cfg, principal, identity=identity)
    result = server._do_move_note(
        scoped,
        "Projects/alpha.md",
        "Projects/renamed.md",
        "rename project note",
        bundle=bundle,
    )
    assert result["vault"] == "alice"
    assert not (bundle.root / "Projects" / "alpha.md").exists()
    assert (bundle.root / "Projects" / "renamed.md").is_file()
    assert bundle.git.log(limit=1)[0].actor == "user:alice via mcp"
