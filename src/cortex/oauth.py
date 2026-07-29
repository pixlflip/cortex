"""OAuth 2.1 authorization server for one-click MCP connector UIs.

Claude.ai / ChatGPT / Grok "add a custom connector" flows are built around
OAuth 2.1 — protected-resource metadata, dynamic client registration, and an
authorization-code + PKCE flow — not a pasted bearer token. This module makes
Cortex its own minimal authorization server so those one-click flows work.

How a resource owner authenticates: the authorize step redirects the user's
browser to a Cortex **consent page** where they paste their Cortex *principal
token* (the same high-entropy token configured under `principals[].token_env`).
That proves which principal they are; the issued OAuth access token is bound to
that principal in a server-side delegation record, and every tool call enforces
the principal's scopes exactly as on the stdio/bearer paths.

Static config bearer tokens keep working: ``load_access_token`` resolves both
OAuth-issued tokens and the configured principal tokens, so programmatic clients
and the Anthropic API ``mcp_servers`` connector are unaffected.

Issued tokens are in-memory. Dynamically registered client metadata can be
persisted so reconnecting clients survive a service restart.
"""

from __future__ import annotations

import html
import json
import os
import secrets
import time
from pathlib import Path

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from .auth import AuthError, Authenticator

LOGIN_PATH = "/cortex/authorize"
_CODE_TTL = 600  # seconds
_ACCESS_TTL = 3600  # seconds


def _now() -> int:
    return int(time.time())


_CONSENT_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Authorize Cortex</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{{font-family:system-ui,sans-serif;max-width:30rem;margin:4rem auto;padding:0 1rem;color:#222}}
 h1{{font-size:1.3rem}} input{{width:100%;padding:.6rem;font-size:1rem;box-sizing:border-box}}
 button{{margin-top:1rem;padding:.6rem 1rem;font-size:1rem;cursor:pointer}}
 .err{{color:#b00;margin:.5rem 0}} .muted{{color:#666;font-size:.9rem}}
</style></head><body>
<h1>Authorize {client}</h1>
<p class="muted">{client} wants to access your Cortex memory vault. Paste your
Cortex access token to authorize it. It will only see the notes your token's
principal is scoped to.</p>
{error}
<form method="post" action="{action}">
 <input type="hidden" name="txn" value="{txn}">
 <input type="password" name="token" placeholder="Cortex access token" autofocus required>
 <button type="submit">Authorize</button>
</form>
</body></html>"""


class CortexOAuthProvider:
    """Minimal OAuth 2.1 authorization server backed by Cortex principals."""

    def __init__(
        self,
        authenticator: Authenticator,
        base_url: str,
        client_store_path: Path | None = None,
    ):
        self._auth = authenticator
        self.base = base_url.rstrip("/")
        self._client_store_path = client_store_path
        self._clients = self._load_clients()
        self._codes: dict[str, AuthorizationCode] = {}
        self._access: dict[str, AccessToken] = {}
        self._refresh: dict[str, RefreshToken] = {}
        # OAuth tokens are delegated from the Cortex credential entered at
        # consent. Keep that source credential server-side so user-token scope
        # narrowing, revocation, expiry, and disablement can be re-evaluated on
        # every MCP call. The raw credential is never sent to the OAuth client.
        self._source_by_code: dict[str, str] = {}
        self._source_by_access: dict[str, str] = {}
        self._source_by_refresh: dict[str, str] = {}
        # Pending authorize transactions awaiting consent: txn -> (client, params)
        self._pending: dict[str, tuple[OAuthClientInformationFull, AuthorizationParams]] = {}

    # -- dynamic client registration --------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info
        self._persist_clients()

    def _load_clients(self) -> dict[str, OAuthClientInformationFull]:
        """Load DCR clients so reconnecting clients survive service restarts.

        OAuth codes and tokens deliberately remain ephemeral, but remote MCP
        clients such as ChatGPT retain their dynamically registered client ID
        and will not repeat DCR after a server restart.
        """
        if self._client_store_path is None or not self._client_store_path.exists():
            return {}
        try:
            raw = json.loads(self._client_store_path.read_text())
            clients = {
                item["client_id"]: OAuthClientInformationFull.model_validate(item)
                for item in raw
            }
        except (OSError, ValueError, TypeError, KeyError):
            # A corrupt cache must not prevent Cortex from starting. Existing
            # clients can register again; operators retain the file for repair.
            return {}
        return clients

    def _persist_clients(self) -> None:
        if self._client_store_path is None:
            return
        self._client_store_path.parent.mkdir(parents=True, exist_ok=True)
        encoded = [client.model_dump(mode="json") for client in self._clients.values()]
        temp_path = self._client_store_path.with_suffix(
            self._client_store_path.suffix + ".tmp"
        )
        try:
            temp_path.write_text(json.dumps(encoded, separators=(",", ":")))
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, self._client_store_path)
        finally:
            temp_path.unlink(missing_ok=True)

    # -- authorization code flow ------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Begin the flow: stash the request and send the browser to the Cortex
        consent page, which collects the principal token."""
        txn = secrets.token_urlsafe(24)
        self._pending[txn] = (client, params)
        return f"{self.base}{LOGIN_PATH}?txn={txn}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self._codes.get(authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        if code.expires_at and code.expires_at < _now():
            self._codes.pop(authorization_code, None)
            self._source_by_code.pop(authorization_code, None)
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        # One-time use.
        self._codes.pop(authorization_code.code, None)
        source_token = self._source_by_code.pop(authorization_code.code, None)
        return self._issue(
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            subject=authorization_code.subject,
            resource=authorization_code.resource,
            source_token=source_token,
        )

    # -- refresh ----------------------------------------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        rt = self._refresh.get(refresh_token)
        if rt is None or rt.client_id != client.client_id:
            return None
        return rt

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Rotate: invalidate the presented refresh token.
        self._refresh.pop(refresh_token.token, None)
        source_token = self._source_by_refresh.pop(refresh_token.token, None)
        return self._issue(
            client_id=client.client_id,
            scopes=scopes or refresh_token.scopes,
            subject=refresh_token.subject,
            resource=None,
            source_token=source_token,
        )

    # -- token verification (OAuth tokens AND static principal tokens) ----

    async def load_access_token(self, token: str) -> AccessToken | None:
        at = self._access.get(token)
        if at is not None:
            if at.expires_at and at.expires_at < _now():
                self._access.pop(token, None)
                self._source_by_access.pop(token, None)
                return None
            return at
        # Fall back to a static principal token (9a / programmatic clients).
        try:
            principal, subject = self._auth.resolve_token(token)
        except AuthError:
            return None
        return AccessToken(token=token, client_id=subject, scopes=[])

    async def revoke_token(self, token) -> None:
        raw = getattr(token, "token", "")
        self._access.pop(raw, None)
        self._refresh.pop(raw, None)
        self._source_by_access.pop(raw, None)
        self._source_by_refresh.pop(raw, None)

    def resolve_delegated_principal(self, access_token: str):
        """Re-resolve the credential that authorized ``access_token``.

        This preserves the source credential's live security semantics for
        OAuth clients: scope narrowing is retained, and revoking/expiring the
        source token or disabling its user immediately invalidates delegation.
        """
        source_token = self._source_by_access.get(access_token)
        if source_token is None:
            return None
        try:
            return self._auth.resolve_token(source_token)
        except AuthError:
            return None

    # -- consent page (custom routes) -------------------------------------

    async def handle_consent(self, request: Request) -> Response:
        if request.method == "GET":
            return self._render(request.query_params.get("txn", ""))
        form = await request.form()
        txn = str(form.get("txn", ""))
        token = str(form.get("token", ""))
        if txn not in self._pending:
            return HTMLResponse("Authorization request expired. Start again.", status_code=400)
        try:
            redirect = self.complete_consent(txn, token)
        except AuthError:
            return self._render(txn, error="Invalid token — check it and try again.", status=401)
        return RedirectResponse(url=redirect, status_code=302)

    def complete_consent(self, txn: str, token: str) -> str:
        """Validate the principal token and mint an authorization code bound to
        that principal. Returns the client redirect URL (with code + state).
        Raises AuthError on a bad token, KeyError on an unknown transaction."""
        client, params = self._pending[txn]
        # raises AuthError if invalid; subject is namespaced (client:<name>)
        # for admin-store clients so later resolution uses the right store (#9)
        principal, subject = self._auth.resolve_token(token)
        self._pending.pop(txn, None)
        code = secrets.token_urlsafe(32)
        self._codes[code] = AuthorizationCode(
            code=code,
            scopes=params.scopes or [],
            expires_at=_now() + _CODE_TTL,
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject=subject,
        )
        self._source_by_code[code] = token
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    # -- internals --------------------------------------------------------

    def _issue(
        self,
        *,
        client_id: str,
        scopes: list[str],
        subject: str | None,
        resource,
        source_token: str | None = None,
    ) -> OAuthToken:
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        self._access[access] = AccessToken(
            token=access,
            client_id=client_id,
            scopes=scopes,
            expires_at=_now() + _ACCESS_TTL,
            resource=resource,
        )
        self._refresh[refresh] = RefreshToken(
            token=refresh, client_id=client_id, scopes=scopes, subject=subject
        )
        if source_token is not None:
            self._source_by_access[access] = source_token
            self._source_by_refresh[refresh] = source_token
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=_ACCESS_TTL,
            scope=" ".join(scopes) if scopes else None,
            refresh_token=refresh,
        )

    def _render(self, txn: str, *, error: str = "", status: int = 200) -> HTMLResponse:
        client_name = "An application"
        pending = self._pending.get(txn)
        if pending and pending[0].client_name:
            client_name = pending[0].client_name
        err_html = f'<p class="err">{html.escape(error)}</p>' if error else ""
        page = _CONSENT_PAGE.format(
            client=html.escape(client_name),
            action=f"{self.base}{LOGIN_PATH}",
            txn=html.escape(txn),
            error=err_html,
        )
        return HTMLResponse(page, status_code=status)
