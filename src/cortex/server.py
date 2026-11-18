"""Cortex MCP server — the synchronous front door (v1, read-only).

Exposes scoped, deterministic vault tools over MCP. Safety is enforced here, at
the tool layer, never trusting the caller: every path-addressed tool checks the
calling principal's scopes, and a non-matching path is reported as "not found or
not in scope" so existence isn't leaked across scope boundaries.

Two transports share the same tool layer:

* **stdio** — local, single trusted principal bound for the connection.
* **streamable-http** — remote; the principal is resolved *per request* from a
  bearer token (token → principal mapping). This is what web/desktop MCP clients
  connect to. OAuth 2.1 for one-click consumer connectors layers on top later.

All tools are deterministic and cheap except ``semantic_search``, the single
tool permitted to spend model tokens.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
import logging

import anyio
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl

from .admin import AdminStore
from .access import VaultAccessError, VaultAccessResolver
from .auth import (
    ADMIN_SUBJECT_PREFIX,
    USER_SUBJECT_PREFIX,
    Authenticator,
    AuthError,
)
from .config import CortexConfig, Principal
from .memory_policy import GovernedFastMCP, ToolGovernor
from .llm import build_provider
from .scopes import filter_paths, path_allowed
from .recall import RecallHit, SemanticRetrieval, recall_hits, resolve_mode
from .vault import (
    VaultStore,
    VaultError,
    canonical_asset_path,
    canonical_note_path,
)
from .vaults import VaultBundle, VaultManager

if TYPE_CHECKING:
    from .api import ApiV1
    from .oauth import CortexOAuthProvider
from .note_writes import (  # noqa: F401 - re-exported for compatibility
    MAX_FILE_WRITE_BYTES,
    NoteWriteMixin,
    _validate_frontmatter_block,
)
from .mcp_tools.read_tools import MAX_FILE_CHUNK_BYTES  # noqa: F401


_LOG = logging.getLogger("cortex.janitor")



def _canonical_note_path(path: str) -> str | None:
    """Canonicalize a caller-supplied path to its vault-relative POSIX form.

    Returns the normalized path, or None if the path must be rejected. This
    runs BEFORE any scope check so scopes are always evaluated against the
    exact path the filesystem layer will resolve — a raw string like
    ``Projects/../Private/secret.md`` matches a ``Projects/**`` scope
    textually while resolving inside ``Private/``, which is a scope bypass,
    not a cosmetic mismatch (#5).

    Rejected outright (never notes, or ambiguous under scoping):

    * empty paths, NUL bytes;
    * absolute paths (``/etc/...``, ``C:...``) and backslash separators;
    * any ``..`` segment — even one that stays inside the vault crosses
      scope boundaries;
    * any hidden component (``.git``, ``.obsidian``, ``.trash`` ...), the
      same exclusion ``iter_notes`` applies when listing (#6);
    * non-note suffixes — path-addressed tools only ever serve notes, so
      ``.git/config``-style exfiltration targets are out of the address
      space entirely (#6).

    ``.``/empty segments are dropped, so ``Public//./open.md`` canonicalizes
    to ``Public/open.md`` and is scope-checked as such.
    """
    return canonical_note_path(path)


class CortexTokenVerifier(TokenVerifier):
    """Maps an incoming bearer token to a Cortex principal.

    The verified token's ``subject`` carries the principal name; the tool layer
    resolves the full principal (and its scopes) from config on each call. An
    unrecognized token returns None, which the bearer middleware turns into 401.
    """

    def __init__(self, authenticator: Authenticator):
        self._auth = authenticator

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            _principal, subject = self._auth.resolve_token(token)
        except AuthError:
            return None
        return AccessToken(
            token=token,
            # The SDK's AccessToken model has no separate subject field. Keep
            # the namespaced Cortex identity in client_id so request-time
            # resolution can distinguish config, admin-client, and DB-user
            # identities without relying on ignored Pydantic extras.
            client_id=subject,
            scopes=[],
            expires_at=None,
        )


@dataclass
class HttpServe:
    """Resolved HTTP-transport settings. Exactly one of ``token_verifier``
    (bearer-only, 9a) or ``oauth_provider`` (full OAuth 2.1 AS, 9b) is set."""

    auth_settings: AuthSettings
    transport_security: TransportSecuritySettings
    host: str
    port: int
    path: str
    token_verifier: TokenVerifier | None = None
    oauth_provider: CortexOAuthProvider | None = None


class CortexServer(NoteWriteMixin):
    """Holds vault/git/LLM state and registers the MCP tools.

    ``principal`` is set for stdio (one trusted local identity) and left None for
    HTTP, where each request resolves its own principal from the bearer token.
    """

    def __init__(
        self,
        config: CortexConfig,
        principal: Principal | None = None,
        *,
        http: HttpServe | None = None,
        admin_store: AdminStore | None = None,
        identity=None,
    ):
        self.config = config
        self.principal = principal  # None => resolve per-request (HTTP)
        self.admin_store = admin_store or (AdminStore(config.admin.path) if config.admin.enabled else None)
        # IdentityService (cortex.users) over the SQLite identity DB, when it
        # exists — the store behind `user:` subjects. None for pure-v1 setups.
        self.identity = identity
        self.oauth_provider = http.oauth_provider if http is not None else None
        self.vault_manager = (
            identity.vault_manager
            if identity is not None and identity.vault_manager is not None
            else VaultManager(config)
        )
        if identity is not None:
            identity.vault_manager = self.vault_manager
        self.vault_access = VaultAccessResolver(config, self.vault_manager, identity)

        # The /api/v1 route group (cortex.api.ApiV1); attached by
        # build_http_server when the identity DB exists, else None.
        self.api: ApiV1 | None = None
        # None when llm.provider is "none"; raises at startup on misconfig.
        self.provider = build_provider(config.llm)
        # None unless search.semantic.enabled; used for hybrid retrieval only.
        self.semantic = SemanticRetrieval.from_config(config.search)
        self.mcp = self._build_mcp(http)
        self._register()
        # Memory authorization is unconditional, never tied to a broker switch.
        self.mcp.governor = ToolGovernor(config, identity, self._get_principal)

    @property
    def _local_bundle(self) -> VaultBundle:
        # Helpers without an explicit bundle are for authenticated stdio only.
        # HTTP requests must always carry their request-selected account bundle.
        if self.principal is None:
            raise VaultAccessError("an explicit account vault is required")
        return self.vault_access.select(self.principal)[0]

    @property
    def vault(self) -> VaultStore:
        return self._local_bundle.store

    @property
    def index(self):
        return self._local_bundle.index

    @property
    def git(self):
        return self._local_bundle.git

    def _build_mcp(self, http: HttpServe | None) -> GovernedFastMCP:
        @asynccontextmanager
        async def lifespan(_server):
            async def janitor_heartbeat() -> None:
                from .janitor import run_janitor_all

                assert self.identity is not None
                while True:
                    try:
                        await anyio.to_thread.run_sync(
                            run_janitor_all, self.config, self.identity.db
                        )
                    except Exception:  # keep maintenance outside the request path
                        _LOG.exception("janitor heartbeat failed")
                    await anyio.sleep(max(1, self.config.janitor.interval_seconds))

            async with anyio.create_task_group() as tasks:
                if self.config.janitor.enabled and self.identity is not None:
                    tasks.start_soon(janitor_heartbeat)
                try:
                    yield {}
                finally:
                    tasks.cancel_scope.cancel()

        if http is None:
            return GovernedFastMCP("cortex", lifespan=lifespan)
        kwargs: dict[str, Any] = dict(
            auth=http.auth_settings,
            transport_security=http.transport_security,
            host=http.host,
            port=http.port,
            streamable_http_path=http.path,
            stateless_http=False,
            lifespan=lifespan,
        )
        if http.oauth_provider is not None:
            kwargs["auth_server_provider"] = http.oauth_provider
        else:
            kwargs["token_verifier"] = http.token_verifier
        mcp = GovernedFastMCP("cortex", **kwargs)
        if http.oauth_provider is not None:
            # Public consent page where the resource owner pastes their token.
            from .oauth import LOGIN_PATH

            mcp.custom_route(LOGIN_PATH, methods=["GET", "POST"])(
                http.oauth_provider.handle_consent
            )
        return mcp

    # -- principal resolution ---------------------------------------------

    def _get_principal(self) -> Principal:
        """The principal for the current call: the bound one (stdio) or the one
        mapped from the request's bearer token (HTTP)."""
        if self.principal is not None:
            return self.principal
        token = get_access_token()
        if token is None:
            raise ValueError("unauthenticated")
        # OAuth access tokens carry the registered OAuth application's ID in
        # AccessToken.client_id. Resolve their Cortex principal from the
        # server-side source credential binding before handling direct Cortex
        # bearer tokens, whose client_id stores the namespaced Cortex subject.
        if self.oauth_provider is not None:
            delegated = self.oauth_provider.resolve_delegated_principal(
                getattr(token, "token", "")
            )
            if delegated is not None:
                principal, _resolved_subject = delegated
                return principal
        subject = token.client_id or ""
        # Cortex stores the namespaced authenticated identity in AccessToken's
        # client_id because the supported MCP 1.x SDK model has no subject
        # field. Resolve against exactly the store that authenticated the token —
        # never fall through from one to the other. An admin client or DB
        # user named like a config principal must not inherit that
        # principal's scopes, and vice versa (#9, generalized).
        if subject.startswith(USER_SUBJECT_PREFIX):
            # Re-resolve the *raw bearer token* against the user store on
            # every call, not just the username: this re-applies the token's
            # mint-time scope narrowing and makes revocation, expiry, and
            # user-disable take effect immediately, mid-connection.
            resolved = (
                self.identity.resolve_api_token(getattr(token, "token", None))
                if self.identity is not None
                else None
            )
            principal = None
            if resolved is not None:
                candidate, resolved_subject = resolved
                # Defense in depth: the token must still belong to the
                # subject it originally authenticated as.
                if (
                    resolved_subject == subject
                    or f"{USER_SUBJECT_PREFIX}{resolved_subject}" == subject
                ):
                    principal = candidate
        elif subject.startswith(ADMIN_SUBJECT_PREFIX):
            principal = (
                self.admin_store.principal_by_name(subject[len(ADMIN_SUBJECT_PREFIX):])
                if self.admin_store is not None
                else None
            )
        else:
            principal = self.config.principal(subject)
        if principal is None:
            raise ValueError("unknown principal")
        return principal

    def _select_vault(
        self,
        principal: Principal,
        vault: str | None = None,
        *,
        write: bool = False,
    ) -> tuple[VaultBundle, Principal]:
        """Resolve a request to one authorized vault before path scoping."""
        try:
            bundle, scoped, _ = self.vault_access.select(
                principal, vault, write=write
            )
        except VaultAccessError as exc:
            raise ValueError("vault not found or not in scope") from exc
        return bundle, scoped

    # -- scope helpers -----------------------------------------------------

    @staticmethod
    def _require_visible(principal: Principal, path: str) -> str:
        """Canonicalize ``path`` and check it against the read scopes.

        Returns the canonical vault-relative path, which the caller MUST use
        for the actual vault operation — checking the raw string and then
        resolving it independently is exactly the check/use gap that allowed
        the ``..`` scope bypass (#5). A malformed path (traversal, hidden
        component, non-note suffix) gets the same non-leaking wording as an
        out-of-scope one, so nothing is distinguishable from "absent"."""
        norm = _canonical_note_path(path)
        if norm is None or not path_allowed(norm, principal.scopes):
            # Do not distinguish "absent" from "out of scope".
            raise ValueError(f"note not found or not in scope: {path}")
        return norm

    @staticmethod
    def _require_writable(principal: Principal, path: str) -> str:
        """A principal may mutate ``path`` iff it's in ``write_scopes`` —
        falling back to its read ``scopes`` when ``write_scopes`` is unset, so
        writes work immediately with no extra config. Setting ``write_scopes``
        narrows the writable area independent of what's readable; this is the
        hook for per-principal write permissioning, deferred for now.

        Like ``_require_visible``, canonicalizes first and returns the
        canonical path the caller must operate on."""
        norm = _canonical_note_path(path)
        scopes = principal.scopes if principal.write_scopes is None else principal.write_scopes
        if norm is None or not path_allowed(norm, scopes):
            # Same non-leaking wording as _require_visible: don't distinguish
            # "absent" from "not in scope".
            raise ValueError(f"not found or not in scope: {path}")
        return norm

    @staticmethod
    def _require_visible_file(principal: Principal, path: str) -> str:
        """Canonicalize an arbitrary vault file and enforce read scope."""
        norm = canonical_asset_path(path)
        if norm is None or not path_allowed(norm, principal.scopes):
            raise ValueError(f"file not found or not in scope: {path}")
        return norm

    @staticmethod
    def _require_writable_file(principal: Principal, path: str) -> str:
        """Canonicalize an arbitrary vault file and enforce write scope."""
        norm = canonical_asset_path(path)
        scopes = principal.scopes if principal.write_scopes is None else principal.write_scopes
        if norm is None or not path_allowed(norm, scopes):
            raise ValueError(f"file not found or not in scope: {path}")
        return norm

    def _status_payload(
        self, principal: Principal, bundle: VaultBundle | None = None,
        *, expose_activity: bool = True,
    ) -> dict:
        """Deterministic freshness/visibility snapshot for ``principal``, the
        payload behind the ``status`` MCP tool. Lets a caller judge whether
        what it's about to read is current — e.g. before trusting a
        ``search``/``context_pack`` result — without spending a model call.
        ``head_commit``/``last_commit_iso`` are None when the vault isn't (or
        isn't yet) a git repo; ``index_note_count``/``last_indexed_iso`` are 0
        / None when the search index is disabled."""
        store = bundle.store if bundle is not None else self.vault
        index = bundle.index if bundle is not None else self.index
        git = bundle.git if bundle is not None else self.git
        visible = filter_paths(store.list_notes(), principal.scopes)
        stats = index.stats()
        payload = {
            "principal": principal.name,
            "visible_note_count": len(visible),
            "head_commit": git.head() if expose_activity else None,
            "last_commit_iso": git.head_time() if expose_activity else None,
            "last_indexed_iso": stats["last_indexed"] if expose_activity else None,
            "index_note_count": stats["note_count"] if expose_activity else None,
        }
        if self.semantic is not None:
            model_id = self.semantic.provider.identity
            emb = index.embedding_stats(model_id)
            payload["semantic"] = {
                "default_mode": self.config.search.default_mode,
                "model": model_id,
                "ready": index.semantic_ready(model_id),
                "remote_endpoint": self.config.search.semantic.allow_remote,
                "dimensions": emb["dimensions"],
                "pending_chunks": emb["pending_chunks"] if expose_activity else None,
                "last_embedded_iso": emb["last_embedded"] if expose_activity else None,
                "last_error": emb["last_error"] if expose_activity else None,
            }
        if bundle is not None:
            payload["vault"] = bundle.vault_id
        return payload

    def _commit_and_reindex(
        self,
        principal: Principal,
        reason: str,
        *paths: str,
        bundle: VaultBundle | None = None,
    ) -> str | None:
        """Commit one or more mutated paths under the per-vault actor
        convention, then refresh that vault's search index.

        Most mutations touch one path; a move stages the source removal and
        destination creation together as one revertible commit.
        Returns the commit sha, or None if nothing actually changed on disk
        (e.g. a write that reproduced the existing content byte-for-byte)."""
        actor = (
            f"user:{principal.name} via mcp"
            if bundle is not None and bundle.vault_id == principal.name
            else f"principal:{principal.name} via mcp"
        )
        git = bundle.git if bundle is not None else self.git
        index = bundle.index if bundle is not None else self.index
        sha = git.commit(actor=actor, reason=reason, paths=list(paths))
        index.ensure_fresh()
        return sha

    def _gather_context(
        self,
        principal: Principal,
        query: str,
        max_notes: int,
        budget_chars: int,
        bundle: VaultBundle | None = None,
        include_historical: bool = False,
        mode: str | None = None,
    ) -> tuple[list[str], str]:
        """Deterministically gather the top *visible* chunks for a query into a
        compact, budgeted context string. Shared by context_pack and
        semantic_search so retrieval stays scoped and model-free — the model (if
        any) only ever sees notes this principal is allowed to read.

        Ranking comes from the SQLite FTS5/BM25 search index (falling back to
        VaultStore substring search transparently if FTS5 is unavailable), so
        natural-language phrasing — not just literal substrings — finds the
        right note. Candidates are over-fetched at a generous, non-scaling-down
        floor and only then scope-filtered, so a narrowly-scoped principal in a
        large vault — who may have dozens of higher-ranked out-of-scope hits
        ahead of their first visible one — never has an out-of-scope note
        counted toward max_notes nor surfaced."""
        index = bundle.index if bundle is not None else self.index
        store = bundle.store if bundle is not None else self.vault
        scoped = recall_hits(
            store, index, query, principal.scopes, include_historical=include_historical,
            mode=resolve_mode(mode, self.config.search.default_mode), semantic=self.semantic,
        )

        # Dedup to the single best (top-ranked) chunk per note, preserving rank
        # order, then cap to max_notes distinct notes.
        best_per_note: dict[str, RecallHit] = {}
        order: list[str] = []
        for h in scoped:
            if h.path not in best_per_note:
                best_per_note[h.path] = h
                order.append(h.path)
            if len(order) >= max(1, max_notes):
                break

        chunks: list[str] = []
        used_paths: list[str] = []
        used = 0
        for rel in order:
            hit: RecallHit = best_per_note[rel]
            breadcrumb = f" — {hit.headings}" if hit.headings else ""
            header = f"\n## {rel}{breadcrumb} [memory_state={hit.memory_state}]"
            if hit.warnings:
                header += " [warnings=" + ",".join(hit.warnings) + "]"
            header += f" [vault={bundle.vault_id if bundle else self._local_bundle.vault_id}; line={hit.line}]\n"
            remaining = budget_chars - used - len(header)
            if remaining <= 0:
                break
            body = (hit.body or hit.snippet or "").strip()
            if not body:
                # Defensive fallback: pull the note body directly if neither
                # the chunk text nor the snippet came back populated.
                try:
                    body = store.read_note(rel).body.strip()
                except VaultError:
                    continue
            if len(body) > remaining:
                body = body[:remaining].rstrip() + "\n…(truncated)"
            chunks.append(header + body + "\n")
            used += len(header) + len(body)
            used_paths.append(rel)
        return used_paths, "".join(chunks)

    # -- tools -------------------------------------------------------------

    def _register(self) -> None:
        from .mcp_tools import register_tools

        register_tools(self)

    # -- run ---------------------------------------------------------------

    def run_stdio(self) -> None:
        self.mcp.run(transport="stdio")

    def run_http(self) -> None:
        self.mcp.run(transport="streamable-http")


def build_stdio_server(config: CortexConfig) -> CortexServer:
    """Construct a server for a local stdio connection (single local principal)."""
    principal = Authenticator(config).for_stdio()
    return CortexServer(config, principal)


def build_http_server(config: CortexConfig) -> CortexServer:
    """Construct a server for remote Streamable HTTP access.

    With ``auth.oauth_enabled`` (9b) Cortex runs a full OAuth 2.1 authorization
    server — dynamic client registration + authorization-code/PKCE — so the
    one-click Claude.ai / ChatGPT / Grok connector UIs work. Otherwise (9a) it's
    a bearer-only resource server. Either way, requests authenticate to a
    principal and per-request scoping is enforced; static config bearer tokens
    keep working in both modes.
    """
    sc = config.server
    base = sc.public_url or f"http://{sc.host}:{sc.port}"
    # The SQLite identity store (users, groups, api_tokens, sessions) joins
    # token resolution when its database exists — created via `cortex init` /
    # `cortex db init`. Its absence means a pure-v1 setup; nothing is created
    # implicitly here.
    identity = None
    if config.database.path.exists():
        from .db import Database
        from .users import IdentityService
        from .vaults import attach_vault_manager

        identity = IdentityService(Database(config.database.path), config)
        # Attach the vault registry (B1) so a user created through the running
        # server (admin API) is provisioned a per-user vault. This is the
        # storage layer only — request-time vault routing/scoping is B2.
        attach_vault_manager(identity, config)
    authn = Authenticator(
        config,
        admin_store=AdminStore(config.admin.path) if config.admin.enabled else None,
        user_service=identity,
    )
    restrict = bool(sc.allowed_hosts or sc.allowed_origins)
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=restrict,
        allowed_hosts=sc.allowed_hosts or ["*"],
        allowed_origins=sc.allowed_origins or ["*"],
    )

    if config.auth.oauth_enabled:
        from .oauth import CortexOAuthProvider

        provider = CortexOAuthProvider(
            authn, base, config.database.path.parent / "oauth-clients.json"
        )
        resource_url = base.rstrip(chr(47)) + sc.path
        auth_settings = AuthSettings(
            issuer_url=AnyHttpUrl(base),
            resource_server_url=AnyHttpUrl(resource_url),
            required_scopes=[],
            client_registration_options=ClientRegistrationOptions(enabled=True),
            revocation_options=RevocationOptions(enabled=True),
        )
        http = HttpServe(
            auth_settings, transport_security, sc.host, sc.port, sc.path,
            oauth_provider=provider,
        )
    else:
        auth_settings = AuthSettings(
            issuer_url=AnyHttpUrl(base), resource_server_url=AnyHttpUrl(base), required_scopes=[]
        )
        http = HttpServe(
            auth_settings, transport_security, sc.host, sc.port, sc.path,
            token_verifier=CortexTokenVerifier(authn),
        )
    server = CortexServer(config, principal=None, http=http, identity=identity)
    # The /api/v1 JSON surface (A6) rides the same Starlette app, but only
    # when the identity DB exists — a pure-v1 setup grows no new routes.
    if identity is not None:
        from .api import build_api
        from .health import register_health

        api = build_api(config, identity)
        api.register(server.mcp)
        server.api = api
        register_health(server.mcp, config, server.vault_manager)
    return server
