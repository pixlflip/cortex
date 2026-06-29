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

from dataclasses import asdict, dataclass

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .admin import ADMIN_PATH, AdminStore, AdminUI
from .auth import Authenticator, AuthError
from .config import CortexConfig, Principal
from .gitlog import GitAudit
from .llm import LLMError, build_provider
from .scopes import filter_paths, path_allowed
from .search_index import IndexHit, SearchIndex
from .vault import VaultError, VaultStore


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
            principal = self._auth.for_token(token)
        except AuthError:
            return None
        return AccessToken(
            token=token,
            client_id=principal.name,
            scopes=[],
            subject=principal.name,
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
    oauth_provider: object | None = None


class CortexServer:
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
    ):
        self.config = config
        self.principal = principal  # None => resolve per-request (HTTP)
        self.admin_store = admin_store or (AdminStore(config.admin.path) if config.admin.enabled else None)
        self.vault = VaultStore(config.vault.path)
        self.index = SearchIndex(
            self.vault,
            config.index.path,
            chunk_chars=config.index.chunk_chars,
            overlap=config.index.overlap,
            enabled=config.index.enabled,
        )
        self.git = GitAudit(config.vault.path, config.vault.git)
        # None when llm.provider is "none"; raises at startup on misconfig.
        self.provider = build_provider(config.llm)
        self.mcp = self._build_mcp(http)
        self._register()

    def _build_mcp(self, http: HttpServe | None) -> FastMCP:
        if http is None:
            return FastMCP("cortex")
        kwargs = dict(
            auth=http.auth_settings,
            transport_security=http.transport_security,
            host=http.host,
            port=http.port,
            streamable_http_path=http.path,
            stateless_http=True,
        )
        if http.oauth_provider is not None:
            kwargs["auth_server_provider"] = http.oauth_provider
        else:
            kwargs["token_verifier"] = http.token_verifier
        mcp = FastMCP("cortex", **kwargs)
        if http.oauth_provider is not None:
            # Public consent page where the resource owner pastes their token.
            from .oauth import LOGIN_PATH

            mcp.custom_route(LOGIN_PATH, methods=["GET", "POST"])(
                http.oauth_provider.handle_consent
            )
        if http is not None and self.admin_store is not None:
            admin_ui = AdminUI(self.admin_store, self.config.server.public_url or f"http://{http.host}:{http.port}")
            mcp.custom_route(ADMIN_PATH, methods=["GET", "POST"])(admin_ui.handle)
            mcp.custom_route(f"{ADMIN_PATH}/login", methods=["POST"])(admin_ui.handle)
            mcp.custom_route(f"{ADMIN_PATH}/logout", methods=["POST"])(admin_ui.handle)
            mcp.custom_route(f"{ADMIN_PATH}/roles", methods=["POST"])(admin_ui.handle)
            mcp.custom_route(f"{ADMIN_PATH}/clients", methods=["POST"])(admin_ui.handle)
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
        principal = self.config.principal(token.subject or "")
        if principal is None and self.admin_store is not None:
            principal = self.admin_store.principal_by_name(token.subject or "")
        if principal is None:
            raise ValueError("unknown principal")
        return principal

    # -- scope helpers -----------------------------------------------------

    @staticmethod
    def _require_visible(principal: Principal, path: str) -> None:
        if not path_allowed(path, principal.scopes):
            # Do not distinguish "absent" from "out of scope".
            raise ValueError(f"note not found or not in scope: {path}")

    def _gather_context(
        self, principal: Principal, query: str, max_notes: int, budget_chars: int
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
        self.index.ensure_fresh()
        over_fetch = max(max(1, max_notes) * 20, 500)
        hits = self.index.search(query, limit=over_fetch)
        scoped = [h for h in hits if path_allowed(h.path, principal.scopes)]

        # Dedup to the single best (top-ranked) chunk per note, preserving rank
        # order, then cap to max_notes distinct notes.
        best_per_note: dict[str, IndexHit] = {}
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
            hit: IndexHit = best_per_note[rel]
            breadcrumb = f" — {hit.headings}" if hit.headings else ""
            header = f"\n## {rel}{breadcrumb}\n"
            remaining = budget_chars - used - len(header)
            if remaining <= 0:
                break
            body = (hit.body or hit.snippet or "").strip()
            if not body:
                # Defensive fallback: pull the note body directly if neither
                # the chunk text nor the snippet came back populated.
                try:
                    body = self.vault.read_note(rel).body.strip()
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
        mcp = self.mcp

        @mcp.tool()
        def discover_scopes() -> dict:
            """What can I (the calling principal) see? Returns this principal's
            name, its scopes, and the count of notes currently visible to it."""
            p = self._get_principal()
            visible = filter_paths(self.vault.list_notes(), p.scopes)
            return {
                "principal": p.name,
                "scopes": p.scopes,
                "visible_note_count": len(visible),
            }

        @mcp.tool()
        def list_notes() -> list[str]:
            """List the relative paths of all notes visible to this principal."""
            p = self._get_principal()
            return filter_paths(self.vault.list_notes(), p.scopes)

        @mcp.tool()
        def search(query: str, regex: bool = False, limit: int = 50) -> list[dict]:
            """Search visible notes. By default, ranked keyword/natural-language
            search over an FTS5/BM25 index (porter-stemmed, heading-aware) —
            returns matching chunks with line numbers, trimmed snippets, and a
            relevance score (lower is better). Pass regex=True for a literal
            substring/regex scan instead (no ranking; score omitted).
            Deterministic; no model spend."""
            p = self._get_principal()
            capped = max(1, min(limit, 200))
            if regex:
                hits = self.vault.search(query, regex=True, limit=capped)
                scoped = [h for h in hits if path_allowed(h.path, p.scopes)]
                return [asdict(h) for h in scoped[:capped]]
            # Over-fetch ranked candidates *before* scope-filtering so an
            # out-of-scope note is never counted toward the requested limit —
            # only truncate to `limit` after filtering. The over-fetch floor is
            # intentionally NOT scaled down for small `limit`: a principal with
            # a narrow scope inside a large vault can have dozens of
            # higher-ranked out-of-scope hits ahead of their first visible one,
            # so a small limit must not shrink the candidate pool.
            self.index.ensure_fresh()
            over_fetch = max(capped * 5, 500)
            hits = self.index.search(query, limit=over_fetch)
            scoped = [h for h in hits if path_allowed(h.path, p.scopes)][:capped]
            return [
                {"path": h.path, "line": h.line, "snippet": h.snippet, "score": h.score}
                for h in scoped
            ]

        @mcp.tool()
        def read_note(path: str, include_frontmatter: bool = True) -> str:
            """Read a full note by its vault-relative path. Scope-checked."""
            p = self._get_principal()
            self._require_visible(p, path)
            try:
                note = self.vault.read_note(path)
            except VaultError as exc:
                raise ValueError(f"note not found or not in scope: {path}") from exc
            return note.raw if include_frontmatter else note.body

        @mcp.tool()
        def read_frontmatter(path: str) -> dict:
            """Read just the YAML frontmatter of a note. Scope-checked."""
            p = self._get_principal()
            self._require_visible(p, path)
            try:
                return self.vault.read_frontmatter(path)
            except VaultError as exc:
                raise ValueError(f"note not found or not in scope: {path}") from exc

        @mcp.tool()
        def read_section(path: str, heading: str) -> str:
            """Read a single section of a note, identified by its heading text.
            Scope-checked."""
            p = self._get_principal()
            self._require_visible(p, path)
            try:
                return self.vault.read_section(path, heading)
            except VaultError as exc:
                raise ValueError(str(exc)) from exc

        @mcp.tool()
        def context_pack(query: str, max_notes: int = 5, budget_chars: int = 6000) -> str:
            """Assemble a compact, token-budgeted context bundle for a query from
            the highest-matching visible notes. Deterministic; no model spend."""
            p = self._get_principal()
            used, ctx = self._gather_context(p, query, max_notes, budget_chars)
            if not used:
                return f"# Context pack for: {query}\n\n_No visible notes matched this query._\n"
            return f"# Context pack for: {query}\n{ctx}"

        @mcp.tool()
        def semantic_search(question: str, max_notes: int = 8) -> str:
            """Fuzzy 'comb the vault and synthesize' search. This is the only tool
            that spends model tokens: it retrieves the most relevant *visible*
            notes (deterministic, scope-checked) and asks the configured LLM to
            answer the question grounded in them. Returns a clear notice if no
            provider is configured."""
            p = self._get_principal()
            if self.provider is None:
                return (
                    "semantic_search is disabled: no LLM provider configured "
                    "(llm.provider = none). Use search / context_pack for "
                    "deterministic retrieval, or configure a provider."
                )
            used, ctx = self._gather_context(p, question, max_notes=max_notes, budget_chars=12000)
            if not used:
                return (
                    "No notes in your scope matched that question, so there is "
                    "nothing to synthesize. Try different terms or a broader scope."
                )
            system = (
                "You are Cortex, a memory assistant. Answer the user's question "
                "using ONLY the provided vault notes. If the notes do not contain "
                "the answer, say so plainly — do not invent facts. Cite the note "
                "path(s) you drew from in parentheses. Be concise."
            )
            prompt = f"Question: {question}\n\nVault notes:\n{ctx}"
            max_tokens = int(self.config.llm.options.get("max_tokens", 1500))
            try:
                result = self.provider.complete(
                    system=system, prompt=prompt, max_tokens=max_tokens
                )
            except LLMError as exc:
                raise ValueError(f"semantic_search failed: {exc}") from exc
            footer = f"\n\n— synthesized by {result.model} from: {', '.join(used)}"
            return result.text.rstrip() + footer

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
    authn = Authenticator(config, admin_store=AdminStore(config.admin.path) if config.admin.enabled else None)
    restrict = bool(sc.allowed_hosts or sc.allowed_origins)
    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=restrict,
        allowed_hosts=sc.allowed_hosts or ["*"],
        allowed_origins=sc.allowed_origins or ["*"],
    )

    if config.auth.oauth_enabled:
        from .oauth import CortexOAuthProvider

        provider = CortexOAuthProvider(authn, base)
        auth_settings = AuthSettings(
            issuer_url=base,
            resource_server_url=base,
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
            issuer_url=base, resource_server_url=base, required_scopes=[]
        )
        http = HttpServe(
            auth_settings, transport_security, sc.host, sc.port, sc.path,
            token_verifier=CortexTokenVerifier(authn),
        )
    return CortexServer(config, principal=None, http=http)
