"""Read-only, deterministic MCP tools (plus the one model-spending
``semantic_search``). Registered unconditionally on every Cortex server."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from ..llm import LLMError
from ..recall import recall_hits
from ..scopes import filter_paths
from ..serialization import normalize_json
from ..access import VaultAccessError
from ..vault import VaultError

if TYPE_CHECKING:
    from ..server import CortexServer

MAX_FILE_CHUNK_BYTES = 1024 * 1024


def register_read_tools(server: CortexServer) -> None:
    mcp = server.mcp


    @mcp.tool()
    def discover_scopes() -> dict:
        """What can I (the calling principal) see? Returns this principal's
        name, its scopes, and the count of notes currently visible to it."""
        p = server._get_principal()
        grants = server.vault_access.grants(p)
        vaults = []
        visible_total = 0
        for grant in grants:
            try:
                bundle = server.vault_manager.get(grant.vault_id)
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
        p = server._get_principal()
        try:
            bundle, scoped, grant = server.vault_access.select(p, vault)
        except VaultAccessError as exc:
            raise ValueError("vault not found or not in scope") from exc
        return server._status_payload(scoped, bundle, expose_activity=grant.relation != "explicit")

    @mcp.tool()
    def list_notes(vault: str | None = None) -> list[str]:
        """List the relative paths of all notes visible to this principal."""
        p = server._get_principal()
        bundle, scoped = server._select_vault(p, vault)
        return filter_paths(bundle.store.list_notes(), scoped.scopes)

    @mcp.tool()
    def list_files(limit: int = 200, vault: str | None = None) -> list[dict]:
        """List visible vault files, including binary attachments.

        Hidden files, symlinks, and out-of-scope paths are never returned.
        Results contain path, byte size, and inferred media type but no file
        content or digest. Use get_file to download a bounded base64 chunk.
        """
        p = server._get_principal()
        bundle, scoped = server._select_vault(p, vault)
        capped = max(1, min(limit, 500))
        paths = filter_paths(bundle.store.list_files(), scoped.scopes)[:capped]
        return [
            {
                key: value
                for key, value in server._file_metadata(
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
        p = server._get_principal()
        bundle, scoped = server._select_vault(p, vault)
        path = server._require_visible_file(scoped, path)
        if offset < 0:
            raise ValueError("offset must be non-negative")
        if length < 1:
            raise ValueError("length must be at least 1")
        capped = min(length, MAX_FILE_CHUNK_BYTES)
        metadata = server._file_metadata(
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
        p = server._get_principal()
        bundle, p = server._select_vault(p, vault)
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
        p = server._get_principal()
        bundle, p = server._select_vault(p, vault)
        path = server._require_visible(p, path)
        try:
            note = bundle.store.read_note(path)
        except VaultError as exc:
            raise ValueError(f"note not found or not in scope: {path}") from exc
        return note.raw if include_frontmatter else note.body

    @mcp.tool()
    def read_frontmatter(path: str, vault: str | None = None) -> dict:
        """Read just the YAML frontmatter of a note. Scope-checked."""
        p = server._get_principal()
        bundle, p = server._select_vault(p, vault)
        path = server._require_visible(p, path)
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
        p = server._get_principal()
        bundle, p = server._select_vault(p, vault)
        path = server._require_visible(p, path)
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
        p = server._get_principal()
        bundle, p = server._select_vault(p, vault)
        used, ctx = server._gather_context(p, query, max_notes, budget_chars, bundle, include_historical)
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
        p = server._get_principal()
        bundle, p = server._select_vault(p, vault)
        if server.provider is None:
            return (
                "semantic_search is disabled: no LLM provider configured "
                "(llm.provider = none). Use search / context_pack for "
                "deterministic retrieval, or configure a provider."
            )
        used, ctx = server._gather_context(
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
        max_tokens = int(server.config.llm.options.get("max_tokens", 1500))
        try:
            result = server.provider.complete(
                system=system, prompt=prompt, max_tokens=max_tokens
            )
        except LLMError as exc:
            raise ValueError(f"semantic_search failed: {exc}") from exc
        footer = f"\n\n— synthesized by {result.model} from: {', '.join(used)}"
        return result.text.rstrip() + footer
