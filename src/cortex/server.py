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
import base64
import binascii
import hashlib
import logging
import mimetypes
import re
from pathlib import Path

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
from .llm import LLMError, build_provider
from .memory_lifecycle import (
    STATES, MANAGED, MemoryState, serialized_write, inspect_memory, inspect_memory_bytes, memory_patch, parse_memory_bytes,
    update_metadata_bytes, validate_memory_state,
)
from .scopes import filter_paths, path_allowed
from .recall import recall_hits
from .search_index import IndexHit, SearchIndex
from .serialization import normalize_json
from .vault import (
    NOTE_SUFFIXES,
    VaultError,
    VaultStore,
    _FRONTMATTER_RE,
    canonical_asset_path,
    canonical_note_path,
)
from .vaults import MAIN_VAULT_ID, VaultBundle, VaultManager


_LOG = logging.getLogger("cortex.janitor")

MAX_FILE_CHUNK_BYTES = 1024 * 1024
MAX_FILE_WRITE_BYTES = 8 * 1024 * 1024


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
        self.oauth_provider = http.oauth_provider if http is not None else None
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
        scopes = principal.write_scopes or principal.scopes
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
        scopes = principal.write_scopes or principal.scopes
        if norm is None or not path_allowed(norm, scopes):
            raise ValueError(f"file not found or not in scope: {path}")
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
        include_historical: bool = False,
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
        scoped = recall_hits(store, index, query, principal.scopes, include_historical=include_historical)

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
            header = f"\n## {rel}{breadcrumb} [memory_state={hit.memory_state}]"
            if hit.warnings:
                header += " [warnings=" + ",".join(hit.warnings) + "]"
            header += f" [vault={bundle.vault_id if bundle else MAIN_VAULT_ID}; line={hit.line}]\n"
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

    def _note_bytes(self, store, path):
        try:
            return store._resolve(path).read_bytes()
        except (VaultError, OSError) as exc:
            raise ValueError(f"not found or not in scope: {path}") from exc

    def _save_note_updates(self, principal, updates, originals, reason, bundle=None):
        """Roll back recoverable write/commit failures; index outcome is explicit.

        Reject a pre-existing staged change rather than include another actor's
        work. A process/power loss still requires ordinary Git/operator recovery.
        """
        import subprocess
        store = bundle.store if bundle is not None else self.vault
        git = bundle.git if bundle is not None else self.git
        index = bundle.index if bundle is not None else self.index
        if not git.config.enabled or not git.is_repo():
            raise ValueError("an initialized Git audit repository is required")
        staged = subprocess.run(['git', 'diff', '--cached', '--name-only'], cwd=store.root,
                                capture_output=True, check=True).stdout
        if staged.strip():
            raise ValueError("vault has staged changes; finish or unstage them before writing")
        head = git.head()
        try:
            for path, content in updates.items():
                store.write_bytes(path, content)
            actor = (f"user:{principal.name} via mcp" if bundle is not None and bundle.vault_id == principal.name
                     else f"principal:{principal.name} via mcp")
            commit = git.commit(actor=actor, reason=reason,
                                paths=list(updates))
        except Exception:
            # Do not undo an already-committed operation if a post-commit reader failed.
            if git.head() != head:
                raise ValueError("audit HEAD changed; inspect operation before retrying")
            for path, raw in originals.items():
                if raw is None:
                    target = store._resolve(path)
                    if target.exists():
                        target.unlink()
                else:
                    store.write_bytes(path, raw)
            command = (['git', '--literal-pathspecs', 'reset', '-q', 'HEAD', '--', *updates] if head else
                       ['git', '--literal-pathspecs', 'rm', '--cached', '--ignore-unmatch', '--', *updates])
            subprocess.run(command, cwd=store.root, capture_output=True, check=True)
            raise
        indexed = True
        try:
            index.ensure_fresh()
        except Exception:
            indexed = False
            _LOG.warning("memory index refresh pending after audited write")
        return {"vault": bundle.vault_id if bundle else MAIN_VAULT_ID,
                "commit": commit, "saved": True, "audited": True,
                "index_status": "ready" if indexed else "pending"}

    @staticmethod
    def _check_hash(raw, expected):
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("expected SHA-256 must be 64 lowercase hexadecimal characters")
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("expected_sha256 mismatch; note was not changed")

    @staticmethod
    def _ordinary_metadata(raw, original, principal, reason, state=None):
        """Validate every write route and reserve relationship fields for lifecycle tools."""
        fm, _ = parse_memory_bytes(raw)
        old = parse_memory_bytes(original)[0] if original is not None else {}
        if 'memory_state' in fm:
            validate_memory_state(fm['memory_state'])
        for key in MANAGED - {'memory_state'}:
            if key in fm and fm[key] != old.get(key):
                raise ValueError("managed lifecycle metadata requires a lifecycle operation")
        if state is not None:
            validate_memory_state(state)
            if 'memory_state' in fm and fm['memory_state'] != state and original is None:
                raise ValueError("memory_state argument conflicts with YAML")
        requested = state if state is not None else fm.get('memory_state', old.get('memory_state', 'unreviewed'))
        validate_memory_state(requested)
        previous = old.get('memory_state', 'unreviewed')
        if requested == 'superseded' and previous != 'superseded':
            raise ValueError("superseded may only be set by supersede_note")
        if old.get('memory_superseded_by') and requested != previous:
            raise ValueError("superseded records cannot be reactivated without resolving their replacement")
        patch = {k: v for k, v in old.items() if k in MANAGED}
        if original is None or requested != previous or state is not None:
            patch.update(memory_patch(requested, actor=principal.name, reason=reason))
        # Legacy existing content retains absent metadata until explicitly classified.
        return update_metadata_bytes(raw, patch) if patch else raw

    @serialized_write
    def _do_write_note(self, principal: Principal, path: str, content: str, reason: str,
                       *, overwrite: bool = False, validate_frontmatter: bool = True,
                       memory_state: MemoryState | None = None, bundle: VaultBundle | None = None) -> dict:
        path = self._require_writable(principal, path)
        store = bundle.store if bundle is not None else self.vault
        if validate_frontmatter:
            _validate_frontmatter_block(content, path)
        exists = store.exists(path)
        if exists and not overwrite:
            raise ValueError(f"note already exists (pass overwrite=True to replace): {path}")
        original = self._note_bytes(store, path) if exists else None
        updated = self._ordinary_metadata(content.encode('utf-8'), original, principal, reason, memory_state)
        receipt = self._save_note_updates(principal, {path: updated}, {path: original}, reason, bundle)
        return {**receipt, 'path': path, 'created': not exists,
                'sha256': hashlib.sha256(updated).hexdigest()}

    @serialized_write
    def _do_patch_note(self, principal: Principal, path: str, old_string: str,
                       new_string: str, reason: str, bundle: VaultBundle | None = None) -> dict:
        path = self._require_writable(principal, path)
        store = bundle.store if bundle is not None else self.vault
        original = self._note_bytes(store, path)
        text = original.decode('utf-8')
        count = text.count(old_string)
        if count == 0:
            raise ValueError(f"not found in {path}: {old_string!r}")
        if count != 1:
            raise ValueError(f"ambiguous: {count} matches in {path}")
        raw = text.replace(old_string, new_string, 1).encode('utf-8')
        old_fm, _ = parse_memory_bytes(original)
        new_fm, _ = parse_memory_bytes(raw)
        if any(old_fm.get(k) != new_fm.get(k) for k in MANAGED):
            raise ValueError('lifecycle metadata changes require set_memory_state or supersede_note')
        updated = self._ordinary_metadata(raw, original, principal, reason)
        return {**self._save_note_updates(principal, {path:updated}, {path:original}, reason, bundle), 'path':path}

    @serialized_write
    def _do_append_note(self, principal: Principal, path: str, text: str, reason: str,
                        *, separator: str = '\n\n', bundle: VaultBundle | None = None) -> dict:
        path = self._require_writable(principal, path)
        store = bundle.store if bundle is not None else self.vault
        original = self._note_bytes(store, path)
        raw = original + separator.encode('utf-8') + text.encode('utf-8')
        updated = self._ordinary_metadata(raw, original, principal, reason)
        return {**self._save_note_updates(principal, {path:updated}, {path:original}, reason, bundle), 'path':path}

    @serialized_write
    def _do_update_frontmatter(self, principal: Principal, path: str, patch: dict,
                               reason: str, bundle: VaultBundle | None = None) -> dict:
        path = self._require_writable(principal, path)
        store = bundle.store if bundle is not None else self.vault
        if not isinstance(patch, dict):
            raise ValueError('patch must be a mapping')
        original = self._note_bytes(store, path)
        if set(patch) & (MANAGED - {'memory_state'}):
            raise ValueError('managed lifecycle metadata requires a lifecycle operation')
        raw = update_metadata_bytes(original, patch)
        updated = self._ordinary_metadata(raw, original, principal, reason, patch.get('memory_state'))
        receipt = self._save_note_updates(principal, {path:updated}, {path:original}, reason, bundle)
        return {**receipt, 'path':path, 'frontmatter':normalize_json(parse_memory_bytes(updated)[0])}

    @serialized_write
    def _do_set_memory_state(self, principal: Principal, path: str, state: MemoryState,
                             reason: str, expected_sha256: str, bundle: VaultBundle | None = None) -> dict:
        path = self._require_writable(principal, path)
        store = bundle.store if bundle is not None else self.vault
        patch = memory_patch(state, actor=principal.name, reason=reason)
        if state == 'superseded':
            raise ValueError('superseded may only be set by supersede_note')
        original = self._note_bytes(store, path)
        self._check_hash(original, expected_sha256)
        fm, _ = parse_memory_bytes(original)
        if fm.get('memory_superseded_by'):
            raise ValueError('superseded record has a replacement; cannot reactivate independently')
        updated = update_metadata_bytes(original, patch)
        receipt = self._save_note_updates(principal, {path:updated}, {path:original}, reason, bundle)
        return {**receipt, 'path':path, 'state':state, 'sha256':hashlib.sha256(updated).hexdigest()}

    @serialized_write
    def _do_supersede_note(self, principal: Principal, old_path: str, replacement_path: str,
                           reason: str, old_sha256: str, replacement_sha256: str,
                           bundle: VaultBundle | None = None) -> dict:
        old_path = self._require_writable(principal, old_path)
        replacement_path = self._require_writable(principal, replacement_path)
        # Lifecycle relationships must not reveal a note the caller cannot read.
        self._require_visible(principal, old_path)
        self._require_visible(principal, replacement_path)
        if old_path == replacement_path:
            raise ValueError('a note cannot supersede itself')
        store = bundle.store if bundle is not None else self.vault
        old_raw = self._note_bytes(store, old_path)
        replacement_raw = self._note_bytes(store, replacement_path)
        self._check_hash(old_raw, old_sha256)
        self._check_hash(replacement_raw, replacement_sha256)
        old_fm, _ = parse_memory_bytes(old_raw)
        replacement_fm, _ = parse_memory_bytes(replacement_raw)
        if old_fm.get('memory_superseded_by'):
            raise ValueError('old note already has a replacement')
        # A replacement with its own successor would create inconsistent current
        # guidance; reject rather than silently reactivating historical records.
        if replacement_fm.get('memory_superseded_by') or replacement_fm.get('memory_state') == 'superseded':
            raise ValueError('replacement is itself superseded; possible cycle')
        # Validate the old record's ancestry with DFS colors. Shared ancestors
        # are legal; a back-edge or replacement-as-ancestor is not.
        pending, visiting, complete = [(old_path, False)], set(), set()
        while pending:
            current, exiting = pending.pop()
            if exiting:
                visiting.remove(current)
                complete.add(current)
                continue
            if current in complete:
                continue
            if current in visiting:
                raise ValueError('supersession cycle detected')
            self._require_visible(principal, current)
            data, _ = parse_memory_bytes(self._note_bytes(store, current))
            parents = data.get('memory_supersedes', [])
            if not isinstance(parents, list) or any(not isinstance(x, str) for x in parents):
                raise ValueError('invalid supersession metadata')
            visiting.add(current)
            pending.append((current, True))
            for parent in reversed(parents):
                parent = self._require_visible(principal, parent)
                if parent == replacement_path or parent in visiting:
                    raise ValueError('supersession cycle detected')
                pending.append((parent, False))
            if len(complete) + len(visiting) + len(pending) > 1000:
                raise ValueError('supersession graph exceeds bounded validation')
        links = replacement_fm.get('memory_supersedes', [])
        if not isinstance(links, list) or any(not isinstance(x,str) for x in links):
            raise ValueError('invalid replacement backlinks')
        if old_path in links:
            raise ValueError('replacement already links to old note')
        updates = {
            old_path: update_metadata_bytes(old_raw, {**memory_patch('superseded', actor=principal.name, reason=reason), 'memory_superseded_by':replacement_path}),
            replacement_path: update_metadata_bytes(replacement_raw, {**memory_patch('current', actor=principal.name, reason=reason), 'memory_supersedes':[*links, old_path]}),
        }
        receipt = self._save_note_updates(principal, updates, {old_path:old_raw,replacement_path:replacement_raw}, reason, bundle)
        return {**receipt, 'old_path':old_path, 'replacement_path':replacement_path,
                'sha256':{p:hashlib.sha256(raw).hexdigest() for p,raw in updates.items()}}

    @serialized_write
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

    @serialized_write
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
        except (VaultError, OSError) as exc:
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

    @staticmethod
    def _file_metadata(store: VaultStore, path: str, *, include_sha256: bool) -> dict:
        try:
            resolved = store._resolve(path)
            if not resolved.is_file():
                raise VaultError(f"file not found: {path}")
            stat = resolved.stat()
            digest = None
            if include_sha256:
                hasher = hashlib.sha256()
                with resolved.open("rb") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        hasher.update(block)
                digest = hasher.hexdigest()
        except (OSError, VaultError) as exc:
            raise ValueError(f"file not found or not in scope: {path}") from exc
        return {
            "path": path,
            "size": stat.st_size,
            "media_type": mimetypes.guess_type(path)[0] or "application/octet-stream",
            "sha256": digest,
        }

    @serialized_write
    def _do_put_file(
        self,
        principal: Principal,
        path: str,
        content_base64: str,
        reason: str,
        *,
        overwrite: bool = False,
        expected_sha256: str | None = None,
        bundle: VaultBundle | None = None,
    ) -> dict:
        path = self._require_writable_file(principal, path)
        if Path(path).suffix.lower() in NOTE_SUFFIXES:
            raise ValueError("Markdown files must be written with write_note")
        if len(content_base64) > ((MAX_FILE_WRITE_BYTES + 2) // 3) * 4:
            raise ValueError(
                f"file exceeds the {MAX_FILE_WRITE_BYTES}-byte put_file limit"
            )
        try:
            content = base64.b64decode(content_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("content_base64 must be valid RFC 4648 base64") from exc
        if len(content) > MAX_FILE_WRITE_BYTES:
            raise ValueError(
                f"file exceeds the {MAX_FILE_WRITE_BYTES}-byte put_file limit"
            )
        digest = hashlib.sha256(content).hexdigest()
        if expected_sha256 is not None and digest != expected_sha256.strip().lower():
            raise ValueError("sha256 mismatch; file was not written")
        store = bundle.store if bundle is not None else self.vault
        try:
            target = store._resolve(path)
        except VaultError as exc:
            raise ValueError(f"file not found or not in scope: {path}") from exc
        if target.exists() and not target.is_file():
            raise ValueError(f"destination is not a file: {path}")
        existed = target.is_file()
        if existed and not overwrite:
            raise ValueError(f"file already exists (pass overwrite=True to replace): {path}")
        try:
            store.write_bytes(path, content)
        except (OSError, VaultError) as exc:
            raise ValueError(f"file could not be written: {path}") from exc
        sha = self._commit_and_reindex(principal, reason, path, bundle=bundle)
        return {
            "vault": bundle.vault_id if bundle else MAIN_VAULT_ID,
            "path": path,
            "created": not existed,
            "size": len(content),
            "media_type": mimetypes.guess_type(path)[0] or "application/octet-stream",
            "sha256": digest,
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
        def list_files(limit: int = 200, vault: str | None = None) -> list[dict]:
            """List visible vault files, including binary attachments.

            Hidden files, symlinks, and out-of-scope paths are never returned.
            Results contain path, byte size, and inferred media type but no file
            content or digest. Use get_file to download a bounded base64 chunk.
            """
            p = self._get_principal()
            bundle, scoped = self._select_vault(p, vault)
            capped = max(1, min(limit, 500))
            paths = filter_paths(bundle.store.list_files(), scoped.scopes)[:capped]
            return [
                {
                    key: value
                    for key, value in self._file_metadata(
                        bundle.store, path, include_sha256=False
                    ).items()
                    if key != "sha256"
                }
                for path in paths
            ]

        @mcp.tool()
        def get_file(
            path: str,
            offset: int = 0,
            length: int = 262144,
            include_sha256: bool = True,
            vault: str | None = None,
        ) -> dict:
            """Download one visible vault file as a bounded base64 chunk.

            ``offset`` is a zero-based byte offset and ``length`` is capped at
            1 MiB, allowing large attachments to be pulled over repeated calls.
            The response reports total size, returned range, EOF, media type,
            and (by default) the SHA-256 of the complete file. Paths are
            canonicalized, hidden/symlink paths are rejected, and read scopes
            are enforced before any bytes are opened.
            """
            p = self._get_principal()
            bundle, scoped = self._select_vault(p, vault)
            path = self._require_visible_file(scoped, path)
            if offset < 0:
                raise ValueError("offset must be non-negative")
            if length < 1:
                raise ValueError("length must be at least 1")
            capped = min(length, MAX_FILE_CHUNK_BYTES)
            metadata = self._file_metadata(
                bundle.store, path, include_sha256=include_sha256
            )
            try:
                content = bundle.store.read_bytes(path, offset=offset, length=capped)
            except VaultError as exc:
                raise ValueError(f"file not found or not in scope: {path}") from exc
            returned = len(content)
            return {
                "vault": bundle.vault_id,
                **metadata,
                "offset": offset,
                "length": returned,
                "next_offset": offset + returned,
                "eof": offset + returned >= metadata["size"],
                "content_base64": base64.b64encode(content).decode("ascii"),
            }

        @mcp.tool()
        def search(
            query: str,
            regex: bool = False,
            limit: int = 50,
            include_historical: bool = False,
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
            hits = recall_hits(bundle.store, bundle.index, query, p.scopes,
                               include_historical=include_historical, regex=regex)
            return [
                {"path": h.path, "line": h.line, "snippet": h.snippet, "score": h.score,
                 "memory_state": h.memory_state, "warnings": h.warnings or [],
                 "state_changed_at": h.state_changed_at}
                for h in hits[:capped]
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
            include_historical: bool = False,
            vault: str | None = None,
        ) -> str:
            """Assemble a compact, token-budgeted context bundle for a query from
            the highest-matching visible notes. Deterministic; no model spend."""
            p = self._get_principal()
            bundle, p = self._select_vault(p, vault)
            used, ctx = self._gather_context(p, query, max_notes, budget_chars, bundle, include_historical)
            if not used:
                return f"# Context pack for: {query}\n\n_No visible notes matched this query._\n"
            return f"# Context pack for: {query}\n{ctx}"

        @mcp.tool()
        def semantic_search(
            question: str, max_notes: int = 8, vault: str | None = None, include_historical: bool = False
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
                p, question, max_notes=max_notes, budget_chars=12000, bundle=bundle,
                include_historical=include_historical
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
            def put_file(
                path: str,
                content_base64: str,
                reason: str,
                overwrite: bool = False,
                expected_sha256: str | None = None,
                vault: str | None = None,
            ) -> dict:
                """Upload one binary vault attachment from RFC 4648 base64.

                The decoded file is limited to 8 MiB, written atomically, and
                refuses an existing destination unless overwrite=True. If
                expected_sha256 is supplied, a mismatch aborts before writing.
                Hidden paths and symlinks are rejected, write scopes are
                enforced, and success creates exactly one revertible git commit.
                Markdown remains governed by write_note and is rejected here.
                ``reason`` is required for the audit trail.
                """
                p = self._get_principal()
                bundle, p = self._select_vault(p, vault, write=True)
                return self._do_put_file(
                    p,
                    path,
                    content_base64,
                    reason,
                    overwrite=overwrite,
                    expected_sha256=expected_sha256,
                    bundle=bundle,
                )

            @mcp.tool()
            def write_note(
                path: str,
                content: str,
                reason: str,
                overwrite: bool = False,
                validate_frontmatter: bool = True,
                memory_state: MemoryState | None = None,
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
                    memory_state=memory_state,
                    bundle=bundle,
                )

            @mcp.tool()
            def set_memory_state(path: str, memory_state: MemoryState, reason: str,
                                 expected_sha256: str, vault: str | None = None) -> dict:
                """Change lifecycle YAML only; expected_sha256 is mandatory."""
                p = self._get_principal()
                bundle, p = self._select_vault(p, vault, write=True)
                return self._do_set_memory_state(p, path, memory_state, reason,
                                                 expected_sha256, bundle)

            @mcp.tool()
            def supersede_note(old_path: str, replacement_path: str, reason: str,
                               old_sha256: str, replacement_sha256: str,
                               vault: str | None = None) -> dict:
                """Atomically mark old note superseded and replacement current."""
                p = self._get_principal()
                bundle, p = self._select_vault(p, vault, write=True)
                return self._do_supersede_note(p, old_path, replacement_path, reason,
                                               old_sha256, replacement_sha256, bundle)

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

        provider = CortexOAuthProvider(
            authn, base, config.vault.path.parent.parent / "oauth-clients.json"
        )
        resource_url = base.rstrip(chr(47)) + sc.path
        auth_settings = AuthSettings(
            issuer_url=base,
            resource_server_url=resource_url,
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
