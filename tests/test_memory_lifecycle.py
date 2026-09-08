from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from cortex.memory_lifecycle import STATES, inspect_memory, update_metadata_bytes
from cortex.config import CortexConfig, IndexConfig, Principal, VaultConfig, VaultsConfig, WritesConfig
from cortex.server import CortexServer


def test_interfaces_and_byte_preservation():
    raw = "---\r\ntitle: \u2603\r\n---\r\nBODY\r\n\u2603".encode()
    out = update_metadata_bytes(raw, {"memory_state": "current"})
    assert out.endswith("BODY\r\n\u2603".encode())
    assert inspect_memory({}) == {"state": "unreviewed", "warnings": []}
    assert inspect_memory({"memory_state": "wat"})["state"] == "unreviewed"
    assert inspect_memory({"memory_state": "wat"})["warnings"]
    plain = b"body\r\n\xe2\x98\x83"
    assert update_metadata_bytes(plain, {"memory_state": "draft"}).endswith(plain)
    assert STATES == ("unreviewed", "draft", "current", "superseded", "disputed")


def test_server_lifecycle_hash_and_supersede(tmp_path: Path):
    root = tmp_path / "vaults" / "p"; root.mkdir(parents=True)
    (root / "old.md").write_bytes(b"# old\r\nold body")
    (root / "new.md").write_bytes(b"# new\r\nnew body")
    cfg = CortexConfig(vault=VaultConfig(), vaults=VaultsConfig(root=root.parent, index_dir=tmp_path/'indexes'), index=IndexConfig(enabled=False),
                       principals=[Principal(name="p", scopes=["**"])],
                       writes=WritesConfig(enabled=True))
    srv = CortexServer(cfg, principal=cfg.principal("p")); srv.git.ensure_repo(); srv.git.commit("boot", "boot")
    p = cfg.principal("p")
    old = (root / "old.md").read_bytes(); new = (root / "new.md").read_bytes()
    with pytest.raises(ValueError): srv._do_set_memory_state(p, "old.md", "bogus", "x", hashlib.sha256(old).hexdigest())
    srv._do_set_memory_state(p, "old.md", "current", "review", hashlib.sha256(old).hexdigest())
    old2 = (root / "old.md").read_bytes()
    srv._do_supersede_note(p, "old.md", "new.md", "replace", hashlib.sha256(old2).hexdigest(), hashlib.sha256(new).hexdigest())
    assert (root / "old.md").read_bytes().endswith(b"# old\r\nold body")
    assert srv.vault.read_frontmatter("old.md")["memory_state"] == "superseded"
    assert srv.vault.read_frontmatter("new.md")["memory_state"] == "current"
    with pytest.raises(ValueError): srv._do_set_memory_state(p, "old.md", "draft", "stale", hashlib.sha256(old).hexdigest())
