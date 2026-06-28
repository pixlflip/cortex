"""OAuth 2.1 authorization-server provider tests.

Drives the provider methods directly (the full HTTP flow is smoke-tested
separately). Confirms: authorize → consent → code → token, PKCE challenge is
carried into the code, the issued access token resolves to the right principal,
static config bearer tokens still resolve, refresh rotates, and a bad principal
token is rejected at consent.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from pydantic import AnyUrl

from cortex.auth import AuthError, Authenticator
from cortex.config import CortexConfig, Principal, VaultConfig
from cortex.oauth import CortexOAuthProvider
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull


@pytest.fixture
def provider(tmp_path: Path) -> CortexOAuthProvider:
    (tmp_path / "vault").mkdir()
    cfg = CortexConfig(
        vault=VaultConfig(path=tmp_path / "vault"),
        principals=[Principal(name="web", scopes=["Public/**"], token="tok-web")],
    )
    return CortexOAuthProvider(Authenticator(cfg), "https://cortex.example.com")


def _client() -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id="client-1",
        redirect_uris=[AnyUrl("https://app.example/callback")],
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name="Test App",
    )


def _params() -> AuthorizationParams:
    return AuthorizationParams(
        state="st-123",
        scopes=[],
        code_challenge="challenge-abc",
        redirect_uri=AnyUrl("https://app.example/callback"),
        redirect_uri_provided_explicitly=True,
        resource="https://cortex.example.com/mcp",
    )


def test_register_and_get_client(provider: CortexOAuthProvider):
    client = _client()
    asyncio.run(provider.register_client(client))
    assert asyncio.run(provider.get_client("client-1")).client_name == "Test App"
    assert asyncio.run(provider.get_client("nope")) is None


def test_full_authorize_consent_token_flow(provider: CortexOAuthProvider):
    client = _client()
    asyncio.run(provider.register_client(client))

    # authorize -> consent URL carrying a transaction id
    url = asyncio.run(provider.authorize(client, _params()))
    assert url.startswith("https://cortex.example.com/cortex/authorize?txn=")
    txn = url.split("txn=")[1]

    # consent with the principal token -> redirect carrying code + state
    redirect = provider.complete_consent(txn, "tok-web")
    assert "code=" in redirect and "state=st-123" in redirect
    code = redirect.split("code=")[1].split("&")[0]

    # the code carries the PKCE challenge and the bound principal
    loaded = asyncio.run(provider.load_authorization_code(client, code))
    assert loaded is not None
    assert loaded.code_challenge == "challenge-abc"
    assert loaded.subject == "web"

    # exchange the code for tokens
    tok = asyncio.run(provider.exchange_authorization_code(client, loaded))
    assert tok.token_type == "Bearer" and tok.refresh_token

    # the issued access token resolves to the principal
    at = asyncio.run(provider.load_access_token(tok.access_token))
    assert at is not None and at.subject == "web"

    # code is single-use
    assert asyncio.run(provider.load_authorization_code(client, code)) is None

    # refresh rotates and stays bound to the principal
    rt = asyncio.run(provider.load_refresh_token(client, tok.refresh_token))
    assert rt is not None
    tok2 = asyncio.run(provider.exchange_refresh_token(client, rt, []))
    at2 = asyncio.run(provider.load_access_token(tok2.access_token))
    assert at2.subject == "web"
    # old refresh token is invalidated
    assert asyncio.run(provider.load_refresh_token(client, tok.refresh_token)) is None


def test_static_principal_token_still_resolves(provider: CortexOAuthProvider):
    # A configured bearer token (9a / programmatic clients) resolves via the
    # same access-token path, so enabling OAuth doesn't break them.
    at = asyncio.run(provider.load_access_token("tok-web"))
    assert at is not None and at.subject == "web"
    assert asyncio.run(provider.load_access_token("bogus")) is None


def test_consent_rejects_bad_token(provider: CortexOAuthProvider):
    client = _client()
    asyncio.run(provider.register_client(client))
    url = asyncio.run(provider.authorize(client, _params()))
    txn = url.split("txn=")[1]
    with pytest.raises(AuthError):
        provider.complete_consent(txn, "wrong-token")
