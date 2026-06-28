"""Cortex MCP server — the synchronous front door (v1, read-only).

Exposes scoped, deterministic vault tools over MCP. Safety is enforced here, at
the tool layer, never trusting the caller: every path-addressed tool checks the
calling principal's scopes, and a non-matching path is reported as "not found or
not in scope" so existence isn't leaked across scope boundaries.

All tools here are deterministic and cheap except ``semantic_search``, which is
the single tool permitted to spend model tokens (wired to the LLM provider in a
later build step).
"""

from __future__ import annotations

from dataclasses import asdict

from mcp.server.fastmcp import FastMCP

from .auth import Authenticator
from .config import CortexConfig, Principal
from .gitlog import GitAudit
from .llm import LLMError, build_provider
from .scopes import filter_paths, path_allowed
from .vault import VaultError, VaultStore


class CortexServer:
    """Holds vault/git/auth state and registers MCP tools for one principal.

    In v1/stdio there is a single resolved principal for the connection. HTTP
    per-request principal resolution is added with the secure-exposure step.
    """

    def __init__(self, config: CortexConfig, principal: Principal):
        self.config = config
        self.principal = principal
        self.vault = VaultStore(config.vault.path)
        self.git = GitAudit(config.vault.path, config.vault.git)
        # None when llm.provider is "none"; raises at startup on misconfig.
        self.provider = build_provider(config.llm)
        self.mcp = FastMCP("cortex")
        self._register()

    # -- scope helpers -----------------------------------------------------

    def _require_visible(self, path: str) -> None:
        if not path_allowed(path, self.principal.scopes):
            # Do not distinguish "absent" from "out of scope".
            raise ValueError(f"note not found or not in scope: {path}")

    def _gather_context(
        self, query: str, max_notes: int, budget_chars: int
    ) -> tuple[list[str], str]:
        """Deterministically gather the top *visible* notes for a query into a
        compact, budgeted context string. Shared by context_pack and
        semantic_search so retrieval stays scoped and model-free — the model (if
        any) only ever sees notes this principal is allowed to read."""
        hits = self.vault.search(query, limit=200)
        seen: list[str] = []
        for h in hits:
            if h.path in seen:
                continue
            if path_allowed(h.path, self.principal.scopes):
                seen.append(h.path)
            if len(seen) >= max(1, max_notes):
                break
        chunks: list[str] = []
        used_paths: list[str] = []
        used = 0
        for rel in seen:
            try:
                note = self.vault.read_note(rel)
            except VaultError:
                continue
            header = f"\n## {rel}\n"
            remaining = budget_chars - used - len(header)
            if remaining <= 0:
                break
            body = note.body.strip()
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
            visible = filter_paths(self.vault.list_notes(), self.principal.scopes)
            return {
                "principal": self.principal.name,
                "scopes": self.principal.scopes,
                "visible_note_count": len(visible),
            }

        @mcp.tool()
        def list_notes() -> list[str]:
            """List the relative paths of all notes visible to this principal."""
            return filter_paths(self.vault.list_notes(), self.principal.scopes)

        @mcp.tool()
        def search(query: str, regex: bool = False, limit: int = 50) -> list[dict]:
            """Search visible notes for a substring (or regex). Returns matching
            notes with line numbers and trimmed snippets. Deterministic; no model
            spend."""
            hits = self.vault.search(query, regex=regex, limit=max(1, min(limit, 200)))
            scoped = [h for h in hits if path_allowed(h.path, self.principal.scopes)]
            return [asdict(h) for h in scoped]

        @mcp.tool()
        def read_note(path: str, include_frontmatter: bool = True) -> str:
            """Read a full note by its vault-relative path. Scope-checked."""
            self._require_visible(path)
            try:
                note = self.vault.read_note(path)
            except VaultError as exc:
                raise ValueError(f"note not found or not in scope: {path}") from exc
            return note.raw if include_frontmatter else note.body

        @mcp.tool()
        def read_frontmatter(path: str) -> dict:
            """Read just the YAML frontmatter of a note. Scope-checked."""
            self._require_visible(path)
            try:
                return self.vault.read_frontmatter(path)
            except VaultError as exc:
                raise ValueError(f"note not found or not in scope: {path}") from exc

        @mcp.tool()
        def read_section(path: str, heading: str) -> str:
            """Read a single section of a note, identified by its heading text.
            Scope-checked."""
            self._require_visible(path)
            try:
                return self.vault.read_section(path, heading)
            except VaultError as exc:
                raise ValueError(str(exc)) from exc

        @mcp.tool()
        def context_pack(query: str, max_notes: int = 5, budget_chars: int = 6000) -> str:
            """Assemble a compact, token-budgeted context bundle for a query from
            the highest-matching visible notes. Deterministic; no model spend."""
            used, ctx = self._gather_context(query, max_notes, budget_chars)
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
            if self.provider is None:
                return (
                    "semantic_search is disabled: no LLM provider configured "
                    "(llm.provider = none). Use search / context_pack for "
                    "deterministic retrieval, or configure a provider."
                )
            used, ctx = self._gather_context(question, max_notes=max_notes, budget_chars=12000)
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


def build_stdio_server(config: CortexConfig) -> CortexServer:
    """Construct a server for a local stdio connection (single local principal)."""
    principal = Authenticator(config).for_stdio()
    return CortexServer(config, principal)
