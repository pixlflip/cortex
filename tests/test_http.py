"""HTTP/bearer transport tests: token→principal mapping and per-request scoping.

No socket is opened; we exercise the token verifier and the per-request
principal resolution directly (the same code paths the bearer middleware drives).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from cortex.auth import Authenticator
from cortex.config import (
    ConfigError,
    CortexConfig,
    IndexConfig,
    Principal,
    ServerConfig,
    VaultConfig,
    load_config,
)
from cortex.server import CortexTokenVerifier, build_http_server


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    root = tmp_path / "vault"
    (root / "Public").mkdir(parents=True)
    (root / "Public" / "open.md").write_text("# Open\n\npublic\n", encoding="utf-8")
    return root


def _http_config(vault: Path) -> CortexConfig:
    return CortexConfig(
        vault=VaultConfig(path=vault),
        # Keep the search index's SQLite file inside the tmp_path sandbox too —
        # otherwise its dataclass default ("./cortex.index.sqlite") resolves
        # against the test runner's CWD instead of a throwaway directory.
        index=IndexConfig(path=vault.parent / "cortex.index.sqlite"),
        principals=[
            Principal(name="web", scopes=["Public/**"], token="tok-web"),
            Principal(name="admin", scopes=["**"], token="tok-admin"),
        ],
        server=ServerConfig(transport="http", host="127.0.0.1", port=8765),
    )


# -- token verifier --------------------------------------------------------

def test_token_verifier_maps_principal(vault: Path):
    cfg = _http_config(vault)
    v = CortexTokenVerifier(Authenticator(cfg))
    good = asyncio.run(v.verify_token("tok-web"))
    assert good is not None and good.subject == "web"
    assert asyncio.run(v.verify_token("bogus")) is None
    assert asyncio.run(v.verify_token("")) is None


# -- per-request principal resolution -------------------------------------

def test_http_server_builds_and_registers_tools(vault: Path):
    srv = build_http_server(_http_config(vault))
    tools = asyncio.run(srv.mcp.list_tools())
    assert {t.name for t in tools} >= {"discover_scopes", "read_note", "semantic_search"}


def test_get_principal_unauthenticated_raises(vault: Path):
    srv = build_http_server(_http_config(vault))
    with pytest.raises(ValueError, match="unauthenticated"):
        srv._get_principal()


def test_get_principal_resolves_from_token(monkeypatch, vault: Path):
    cfg = _http_config(vault)
    srv = build_http_server(cfg)
    import cortex.server as server_mod

    # Simulate the bearer middleware having stashed the verified token.
    monkeypatch.setattr(server_mod, "get_access_token", lambda: SimpleNamespace(subject="web"))
    p = srv._get_principal()
    assert p.name == "web" and p.scopes == ["Public/**"]


def test_get_principal_unknown_subject_raises(monkeypatch, vault: Path):
    srv = build_http_server(_http_config(vault))
    import cortex.server as server_mod

    monkeypatch.setattr(server_mod, "get_access_token", lambda: SimpleNamespace(subject="ghost"))
    with pytest.raises(ValueError, match="unknown principal"):
        srv._get_principal()


# -- config validation -----------------------------------------------------

def test_http_requires_token_bearing_principal(tmp_path: Path, monkeypatch):
    (tmp_path / "vault").mkdir()
    cfg_file = tmp_path / "cortex.yaml"
    cfg_file.write_text(
        "vault:\n  path: ./vault\n"
        "server:\n  transport: http\n"
        "admin:\n  enabled: false\n"
        "principals:\n  - name: web\n    scopes: ['**']\n",  # no token_env
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="token_env"):
        load_config(cfg_file)


def test_http_config_parses_url_and_origins(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CORTEX_TOKEN_WEB", "secret")
    (tmp_path / "vault").mkdir()
    cfg_file = tmp_path / "cortex.yaml"
    cfg_file.write_text(
        "vault:\n  path: ./vault\n"
        "server:\n  transport: http\n  public_url: https://cortex.example.com\n"
        "  path: /mcp\n  allowed_origins: ['https://claude.ai']\n"
        "principals:\n  - name: web\n    scopes: ['**']\n    token_env: CORTEX_TOKEN_WEB\n",
        encoding="utf-8",
    )
    cfg = load_config(cfg_file)
    assert str(cfg.server.public_url) == "https://cortex.example.com"
    assert cfg.server.allowed_origins == ["https://claude.ai"]
    assert cfg.principal("web").token == "secret"
