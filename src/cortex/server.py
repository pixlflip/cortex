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
from dataclasses import asdict, dataclass
import logging

import anyio
import yaml
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.server.lowlevel.server import request_ctx
from mcp.server.transport_security import TransportSecuritySettings

from .admin import ADMIN_PATH, AdminStore, AdminUI
from .access import VaultAccessError, VaultAccessResolver
from .auth import (
    ADMIN_SUBJECT_PREFIX,
    USER_SUBJECT_PREFIX,
    Authenticator,
    AuthError,
)
from .config import CortexConfig, Principal
from .gitlog import GitAudit
from .gateway import (
    GatewayRuntime,
    GovernedFastMCP,
    LazyMcpCatalog,
    ToolGovernor,
)

_LOG = logging.getLogger("cortex.janitor")
from .llm import LLMError, build_provider
from .scopes import filter_paths, path_allowed
from .search_index import IndexHit, SearchIndex
from .serialization import normalize_json
from .vault import VaultError, VaultStore, _FRONTMATTER_RE, canonical_note_path
from .vaults import MAIN_VAULT_ID, VaultBundle, VaultManager


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


def _validate_frontmatter_block(content: str, path: str) -> None:
    """Reject content whose leading ``---`` frontmatter block fails to parse as
    YAML, or parses to something other than a mapping.

    ``vault.split_frontmatter`` is deliberately lenient (malformed frontmatter
    falls back to treating the whole document as body, rather than raising) —
    that's the right behavior for *reading* an existing note someone else may
    have hand-edited. But ``write_note`` is creating/replacing content fresh,
    so it can afford to be strict and catch a mistake before it lands. Reuses
    the exact frontmatter-block regex from vault.py so "is this a frontmatter
    block" is decided identically in both places.
    """
    match = _FRONTMATTER_RE.match(content)
    if not match:
        return  # no leading --- block at all; nothing to validate
    raw_fm = match.group(1)
    try:
        data = yaml.safe_load(raw_fm)
    except yaml.YAMLError as exc:
        raise ValueError(f"malformed frontmatter in {path}: {exc}") from exc
    if data is not None and not isinstance(data, dict):
        raise ValueError(f"malformed frontmatter in {path}: must be a mapping")


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
            principal, subject = self._auth.resolve_token(token)
        except AuthError:
            return None
        return AccessToken(
            token=token,
            client_id=principal.name,
            scopes=[],
            # Namespaced for admin-store clients (client:<name>) so the
            # per-call principal resolution consults the same store that
            # authenticated the token (#9).
            subject=subject,
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
        identity=None,
    ):
        self.config = config
        self.principal = principal  # None => resolve per-request (HTTP)
        self.admin_store = admin_store or (AdminStore(config.admin.path) if config.admin.enabled else None)
        # IdentityService (cortex.users) over the SQLite identity DB, when it
        # exists — the store behind `user:` subjects. None for pure-v1 setups.
        self.identity = identity
        self.vault_manager = (
            identity.vault_manager
            if identity is not None and identity.vault_manager is not None
            else VaultManager(config)
        )
        if identity is not None:
            identity.vault_manager = self.vault_manager
        main = self.vault_manager.get(MAIN_VAULT_ID)
        self.vault = main.store
        self.index = main.index
        self.git = main.git
        self.vault_access = VaultAccessResolver(config, self.vault_manager, identity)
        self.gateway_runtime = GatewayRuntime(config, identity) if identity is not None else None
        # The /api/v1 route group (cortex.api.ApiV1); attached by
        # build_http_server when the identity DB exists, else None.
        self.api = None
        # None when llm.provider is "none"; raises at startup on misconfig.
        self.provider = build_provider(config.llm)
        self.mcp = self._build_mcp(http)
        self._register()
        if self.gateway_runtime is not None and config.gateway.enabled:
            catalog = LazyMcpCatalog(
                config,
                identity,
                self._get_principal,
                self._get_mcp_client_key,
            )
            self.mcp.lazy_catalog = catalog
            self.gateway_runtime.register_discovery_tools(self.mcp, catalog)
            self.gateway_runtime.register_cached_tools(self.mcp)
            self.mcp.governor = ToolGovernor(config, identity, self._get_principal)

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
                    if self.gateway_runtime is not None:
                        await self.gateway_runtime.aclose()

        if http is None:
            return GovernedFastMCP("cortex", lifespan=lifespan)
        kwargs = dict(
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
        if http is not None and self.admin_store is not None and self.identity is None:
            admin_ui = AdminUI(self.admin_store, self.config.server.public_url or f"http://{http.host}:{http.port}")
            mcp.custom_route(ADMIN_PATH, methods=["GET", "POST"])(admin_ui.handle)
            mcp.custom_route(f"{ADMIN_PATH}/login", methods=["POST"])(admin_ui.handle)
            mcp.custom_route(f"{ADMIN_PATH}/logout", methods=["POST"])(admin_ui.handle)
            mcp.custom_route(f"{ADMIN_PATH}/roles", methods=["POST"])(admin_ui.handle)
            mcp.custom_route(f"{ADMIN_PATH}/clients", methods=["POST"])(admin_ui.handle)
        return mcp

    # -- principal resolution ---------------------------------------------

    def _get_mcp_client_key(self) -> object:
        """Return the current MCP transport session as the load-state key."""
        try:
            return request_ctx.get().session
        except LookupError as exc:
            raise ValueError("MCP client session is unavailable") from exc

    def _get_principal(self) -> Principal:
        """The principal for the current call: the bound one (stdio) or the one
        mapped from the request's bearer token (HTTP)."""
        if self.principal is not None:
            return self.principal
        token = get_access_token()
        if token is None:
            raise ValueError("unauthenticated")
        subject = token.subject or ""
        # Resolve against exactly the store that authenticated the token —
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
                candidate, username = resolved
                # Defense in depth: the token must still belong to the
                # subject it originally authenticated as.
                if f"{USER_SUBJECT_PREFIX}{username}" == subject:
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
        scopes = principal.write_scopes or principal.scopes
        if norm is None or not path_allowed(norm, scopes):
            # Same non-leaking wording as _require_visible: don't distinguish
            # "absent" from "not in scope".
            raise ValueError(f"not found or not in scope: {path}")
        return norm

    def _status_payload(
        self, principal: Principal, bundle: VaultBundle | None = None
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
            "head_commit": git.head(),
            "last_commit_iso": git.head_time(),
            "last_indexed_iso": stats["last_indexed"],
            "index_note_count": stats["note_count"],
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
        index.ensure_fresh()
        over_fetch = max(max(1, max_notes) * 20, 500)
        hits = index.search(query, limit=over_fetch)
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
                    body = store.read_note(rel).body.strip()
                except VaultError:
                    continue
            if len(body) > remaining:
                body = body[:remaining].rstrip() + "\n…(truncated)"
            chunks.append(header + body + "\n")
            used += len(header) + len(body)
            used_paths.append(rel)
        return used_paths, "".join(chunks)

    # -- write orchestration -------------------------------------------------
    #
    # These private methods hold the actual mutation logic so it's directly
    # unit-testable without going through the MCP tool-call machinery; the
    # `@mcp.tool()` closures registered below are thin wrappers that resolve
    # the principal and delegate here. Every one of them: checks write scope,
    # performs exactly one VaultStore mutation, commits it (actor + reason)
    # via GitAudit, and refreshes the search index.

    def _do_write_note(
        self,
        principal: Principal,
        path: str,
        content: str,
        reason: str,
        *,
        overwrite: bool = False,
        validate_frontmatter: bool = True,
        bundle: VaultBundle | None = None,
    ) -> dict:
        path = self._require_writable(principal, path)
        store = bundle.store if bundle is not None else self.vault
        if validate_frontmatter:
            _validate_frontmatter_block(content, path)
        exists = store.exists(path)
        if exists and not overwrite:
            raise ValueError(f"note already exists (pass overwrite=True to replace): {path}")
        store.write_text(path, content)
        sha = self._commit_and_reindex(principal, reason, path, bundle=bundle)
        return {"vault": bundle.vault_id if bundle else MAIN_VAULT_ID, "path": path, "created": not exists, "commit": sha}

    def _do_patch_note(
        self, principal: Principal, path: str, old_string: str, new_string: str, reason: str,
        bundle: VaultBundle | None = None,
    ) -> dict:
        path = self._require_writable(principal, path)
        store = bundle.store if bundle is not None else self.vault
        try:
            text = store.read_text(path)
        except VaultError as exc:
            raise ValueError(f"not found or not in scope: {path}") from exc
        count = text.count(old_string)
        if count == 0:
            raise ValueError(f"not found in {path}: {old_string!r}")
        if count > 1:
            raise ValueError(f"ambiguous: {count} matches in {path}")
        new_text = text.replace(old_string, new_string, 1)
        store.write_text(path, new_text)
        sha = self._commit_and_reindex(principal, reason, path, bundle=bundle)
        return {"vault": bundle.vault_id if bundle else MAIN_VAULT_ID, "path": path, "commit": sha}

    def _do_append_note(
        self, principal: Principal, path: str, text: str, reason: str, *, separator: str = "\n\n",
        bundle: VaultBundle | None = None,
    ) -> dict:
        path = self._require_writable(principal, path)
        try:
            (bundle.store if bundle is not None else self.vault).append(path, text, separator=separator)
        except VaultError as exc:
            raise ValueError(f"not found or not in scope: {path}") from exc
        sha = self._commit_and_reindex(principal, reason, path, bundle=bundle)
        return {"vault": bundle.vault_id if bundle else MAIN_VAULT_ID, "path": path, "commit": sha}

    def _do_update_frontmatter(
        self, principal: Principal, path: str, patch: dict, reason: str,
        bundle: VaultBundle | None = None,
    ) -> dict:
        path = self._require_writable(principal, path)
        store = bundle.store if bundle is not None else self.vault
        if not isinstance(patch, dict):
            raise ValueError("patch must be a mapping")
        try:
            note = store.read_note(path)
        except VaultError as exc:
            raise ValueError(f"not found or not in scope: {path}") from exc
        note.frontmatter.update(patch)
        store.write_text(path, note.raw)
        sha = self._commit_and_reindex(principal, reason, path, bundle=bundle)
        return {
            "vault": bundle.vault_id if bundle else MAIN_VAULT_ID,
            "path": path,
            "frontmatter": normalize_json(note.frontmatter),
            "commit": sha,
        }

    def _do_delete_note(
        self, principal: Principal, path: str, reason: str,
        bundle: VaultBundle | None = None,
    ) -> dict:
        path = self._require_writable(principal, path)
        try:
            (bundle.store if bundle is not None else self.vault).delete_note(path)
        except VaultError as exc:
            raise ValueError(f"not found or not in scope: {path}") from exc
        sha = self._commit_and_reindex(principal, reason, path, bundle=bundle)
        return {"vault": bundle.vault_id if bundle else MAIN_VAULT_ID, "path": path, "deleted": True, "commit": sha}

    def _do_move_note(
        self,
        principal: Principal,
        src: str,
        dest: str,
        reason: str,
        *,
        overwrite: bool = False,
        bundle: VaultBundle | None = None,
    ) -> dict:
        # A move is both a removal at `src` and a creation at `dest`, so both
        # ends must be within the writable area — the check mirrors delete for
        # the source and write for the destination.
        src = self._require_writable(principal, src)
        dest = self._require_writable(principal, dest)
        store = bundle.store if bundle is not None else self.vault
        try:
            store.move_note(src, dest, overwrite=overwrite)
        except VaultError as exc:
            # "note already exists"/"destination is a directory" describe dest,
            # which the caller can already write, so surfacing them leaks
            # nothing; a missing/absent source is reported the same non-leaking
            # way the other mutating tools report an out-of-scope source.
            msg = str(exc)
            if "not found" in msg or "not a file" in msg:
                raise ValueError(f"not found or not in scope: {src}") from exc
            raise ValueError(msg) from exc
        # Stage both paths in one commit so the rename is a single revertible
        # unit in the audit trail.
        sha = self._commit_and_reindex(
            principal, reason, src, dest, bundle=bundle
        )
        return {
            "vault": bundle.vault_id if bundle else MAIN_VAULT_ID,
            "src": src,
            "dest": dest,
            "moved": True,
            "commit": sha,
        }

    # -- tools -------------------------------------------------------------

    def _register(self) -> None:
        mcp = self.mcp

        @mcp.tool()
        def discover_scopes() -> dict:
            """What can I (the calling principal) see? Returns this principal's
            name, its scopes, and the count of notes currently visible to it."""
            p = self._get_principal()
            grants = self.vault_access.grants(p)
            vaults = []
            visible_total = 0
            for grant in grants:
                try:
                    bundle = self.vault_manager.get(grant.vault_id)
                except Exception:
                    continue
                count = len(filter_paths(bundle.store.list_notes(), list(grant.scopes)))
                visible_total += count
                vaults.append(
                    {
                        "vault": grant.vault_id,
                        "relation": grant.relation,
                        "scopes": list(grant.scopes),
                        "write_scopes": list(grant.write_scopes),
                        "visible_note_count": count,
                    }
                )
            return {
                "principal": p.name,
                "scopes": p.scopes,  # retained for v1 clients
                "vaults": vaults,
                "visible_note_count": visible_total,
            }

        @mcp.tool()
        def status(vault: str | None = None) -> dict:
            """Deterministic freshness/visibility signal — no model spend.
            Lets a caller judge whether what it's about to read is current:
            ``head_commit``/``last_commit_iso`` are the git audit trail's HEAD
            and its committer date (None if the vault isn't a git repo yet);
            ``last_indexed_iso``/``index_note_count`` describe the search
            index's last refresh; ``visible_note_count`` is this principal's
            current visible note count. Call this before trusting a stale-
            looking ``search``/``context_pack`` result, or to confirm a
            periodic ``cortex sync`` actually ran recently."""
            p = self._get_principal()
            bundle, scoped = self._select_vault(p, vault)
            return self._status_payload(scoped, bundle)

        @mcp.tool()
        def list_notes(vault: str | None = None) -> list[str]:
            """List the relative paths of all notes visible to this principal."""
            p = self._get_principal()
            bundle, scoped = self._select_vault(p, vault)
            return filter_paths(bundle.store.list_notes(), scoped.scopes)

        @mcp.tool()
        def search(
            query: str,
            regex: bool = False,
            limit: int = 50,
            vault: str | None = None,
        ) -> list[dict]:
            """Search visible notes. By default, ranked keyword/natural-language
            search over an FTS5/BM25 index (porter-stemmed, heading-aware) —
            returns matching chunks with line numbers, trimmed snippets, and a
            relevance score (lower is better). Pass regex=True for a literal
            substring/regex scan instead (no ranking; score omitted).
            Deterministic; no model spend."""
            p = self._get_principal()
            bundle, p = self._select_vault(p, vault)
            capped = max(1, min(limit, 200))
            if regex:
                hits = bundle.store.search(query, regex=True, limit=capped)
                scoped = [h for h in hits if path_allowed(h.path, p.scopes)]
                return [asdict(h) for h in scoped[:capped]]
            # Over-fetch ranked candidates *before* scope-filtering so an
            # out-of-scope note is never counted toward the requested limit —
            # only truncate to `limit` after filtering. The over-fetch floor is
            # intentionally NOT scaled down for small `limit`: a principal with
            # a narrow scope inside a large vault can have dozens of
            # higher-ranked out-of-scope hits ahead of their first visible one,
            # so a small limit must not shrink the candidate pool.
            bundle.index.ensure_fresh()
            over_fetch = max(capped * 5, 500)
            hits = bundle.index.search(query, limit=over_fetch)
            scoped = [h for h in hits if path_allowed(h.path, p.scopes)][:capped]
            return [
                {"path": h.path, "line": h.line, "snippet": h.snippet, "score": h.score}
                for h in scoped
            ]

        @mcp.tool()
        def read_note(
            path: str,
            include_frontmatter: bool = True,
            vault: str | None = None,
        ) -> str:
            """Read a full note by its vault-relative path. Scope-checked."""
            p = self._get_principal()
            bundle, p = self._select_vault(p, vault)
            path = self._require_visible(p, path)
            try:
                note = bundle.store.read_note(path)
            except VaultError as exc:
                raise ValueError(f"note not found or not in scope: {path}") from exc
            return note.raw if include_frontmatter else note.body

        @mcp.tool()
        def read_frontmatter(path: str, vault: str | None = None) -> dict:
            """Read just the YAML frontmatter of a note. Scope-checked."""
            p = self._get_principal()
            bundle, p = self._select_vault(p, vault)
            path = self._require_visible(p, path)
            try:
                return normalize_json(bundle.store.read_frontmatter(path))
            except VaultError as exc:
                raise ValueError(f"note not found or not in scope: {path}") from exc

        @mcp.tool()
        def read_section(
            path: str, heading: str, vault: str | None = None
        ) -> str:
            """Read a single section of a note, identified by its heading text.
            Scope-checked."""
            p = self._get_principal()
            bundle, p = self._select_vault(p, vault)
            path = self._require_visible(p, path)
            try:
                return bundle.store.read_section(path, heading)
            except VaultError as exc:
                raise ValueError(str(exc)) from exc

        @mcp.tool()
        def context_pack(
            query: str,
            max_notes: int = 5,
            budget_chars: int = 6000,
            vault: str | None = None,
        ) -> str:
            """Assemble a compact, token-budgeted context bundle for a query from
            the highest-matching visible notes. Deterministic; no model spend."""
            p = self._get_principal()
            bundle, p = self._select_vault(p, vault)
            used, ctx = self._gather_context(p, query, max_notes, budget_chars, bundle)
            if not used:
                return f"# Context pack for: {query}\n\n_No visible notes matched this query._\n"
            return f"# Context pack for: {query}\n{ctx}"

        @mcp.tool()
        def semantic_search(
            question: str, max_notes: int = 8, vault: str | None = None
        ) -> str:
            """Fuzzy 'comb the vault and synthesize' search. This is the only tool
            that spends model tokens: it retrieves the most relevant *visible*
            notes (deterministic, scope-checked) and asks the configured LLM to
            answer the question grounded in them. Returns a clear notice if no
            provider is configured."""
            p = self._get_principal()
            bundle, p = self._select_vault(p, vault)
            if self.provider is None:
                return (
                    "semantic_search is disabled: no LLM provider configured "
                    "(llm.provider = none). Use search / context_pack for "
                    "deterministic retrieval, or configure a provider."
                )
            used, ctx = self._gather_context(
                p, question, max_notes=max_notes, budget_chars=12000, bundle=bundle
            )
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

        # -- mutating tools --------------------------------------------------
        #
        # Registered ONLY when config.writes.enabled is true (default false).
        # This is the single global switch: an operator who never sets
        # `writes.enabled: true` in their cortex.yaml gets a server with no
        # mutating tools in its MCP registry at all — not just tools that
        # refuse at call time. Every tool here requires `reason: str` (no
        # default), is scope-checked via `_require_writable`, and on success
        # produces exactly one git commit (so it's always `git revert`-able)
        # before the search index is refreshed. All real logic lives in the
        # `_do_*` methods above so it's unit-testable without MCP plumbing.
        if self.config.writes.enabled:

            @mcp.tool()
            def write_note(
                path: str,
                content: str,
                reason: str,
                overwrite: bool = False,
                validate_frontmatter: bool = True,
                vault: str | None = None,
            ) -> dict:
                """Create a new note, or replace an existing one if
                overwrite=True. Refuses to clobber an existing note unless
                overwrite is set. By default validates that any leading YAML
                frontmatter block parses to a mapping (rejects malformed
                frontmatter) — pass validate_frontmatter=False to skip.
                Write-scope-checked. Commits to git (revertible) and refreshes
                the search index. `reason` is required for the audit trail."""
                p = self._get_principal()
                bundle, p = self._select_vault(p, vault, write=True)
                return self._do_write_note(
                    p, path, content, reason,
                    overwrite=overwrite, validate_frontmatter=validate_frontmatter,
                    bundle=bundle,
                )

            @mcp.tool()
            def patch_note(
                path: str,
                old_string: str,
                new_string: str,
                reason: str,
                vault: str | None = None,
            ) -> dict:
                """Replace a single unique occurrence of old_string with
                new_string in an existing note. Refuses if old_string isn't
                found, or if it matches more than once (ambiguous — narrow the
                string first). Write-scope-checked. Commits to git and
                refreshes the search index."""
                p = self._get_principal()
                bundle, p = self._select_vault(p, vault, write=True)
                return self._do_patch_note(p, path, old_string, new_string, reason, bundle)

            @mcp.tool()
            def append_note(
                path: str,
                text: str,
                reason: str,
                separator: str = "\n\n",
                vault: str | None = None,
            ) -> dict:
                """Append text to the end of an existing note, joined by
                separator (default a blank line). Requires the note to
                already exist (use write_note to create one). Write-scope-
                checked. Commits to git and refreshes the search index."""
                p = self._get_principal()
                bundle, p = self._select_vault(p, vault, write=True)
                return self._do_append_note(
                    p, path, text, reason, separator=separator, bundle=bundle
                )

            @mcp.tool()
            def update_frontmatter(
                path: str,
                patch: dict,
                reason: str,
                vault: str | None = None,
            ) -> dict:
                """Merge patch into an existing note's YAML frontmatter,
                leaving the body untouched. patch must be a mapping; keys in
                patch overwrite existing frontmatter keys, other existing keys
                are preserved. Write-scope-checked. Commits to git and
                refreshes the search index."""
                p = self._get_principal()
                bundle, p = self._select_vault(p, vault, write=True)
                return self._do_update_frontmatter(p, path, patch, reason, bundle)

            @mcp.tool()
            def delete_note(
                path: str, reason: str, vault: str | None = None
            ) -> dict:
                """Delete a single existing note file. Only ever operates on
                exactly one existing file — no directory deletes, no globs.
                Write-scope-checked. The delete itself is committed to git, so
                the note's last content is always recoverable (e.g. `git show
                HEAD~1:<path>`, or `git revert` the commit) even after
                deletion. Refreshes the search index."""
                p = self._get_principal()
                bundle, p = self._select_vault(p, vault, write=True)
                return self._do_delete_note(p, path, reason, bundle)

            @mcp.tool()
            def move_note(
                src: str,
                dest: str,
                reason: str,
                overwrite: bool = False,
                vault: str | None = None,
            ) -> dict:
                """Move or rename a single existing note from src to dest (both
                vault-relative paths). Refuses to clobber an existing note at
                dest unless overwrite=True, and never moves directories. BOTH
                src and dest must be within write scope, so a note can't be
                moved out of (or into) an area this principal can't write.
                Records the rename as a single git commit staging both paths —
                revertible as one unit — then refreshes the search index.
                `reason` is required for the audit trail."""
                p = self._get_principal()
                bundle, p = self._select_vault(p, vault, write=True)
                return self._do_move_note(
                    p, src, dest, reason, overwrite=overwrite, bundle=bundle
                )

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
    server = CortexServer(config, principal=None, http=http, identity=identity)
    # The /api/v1 JSON surface (A6) rides the same Starlette app, but only
    # when the identity DB exists — a pure-v1 setup grows no new routes.
    if identity is not None:
        from .api import build_api
        from .webapp import register_web_app

        server.api = build_api(
            config,
            identity,
            gateway_runtime=server.gateway_runtime,
        )
        server.api.register(server.mcp)
        register_web_app(server.mcp, config, server.vault_manager)
    return server
