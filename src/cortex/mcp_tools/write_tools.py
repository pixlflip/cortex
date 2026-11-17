"""Mutating MCP tools. Registered only when ``writes.enabled`` is true."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..memory_lifecycle import MemoryState

if TYPE_CHECKING:
    from ..server import CortexServer


def register_write_tools(server: CortexServer) -> None:
    mcp = server.mcp

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
    if server.config.writes.enabled:

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
            p = server._get_principal()
            bundle, p = server._select_vault(p, vault, write=True)
            return server._do_put_file(
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
            p = server._get_principal()
            bundle, p = server._select_vault(p, vault, write=True)
            return server._do_write_note(
                p, path, content, reason,
                overwrite=overwrite, validate_frontmatter=validate_frontmatter,
                memory_state=memory_state,
                bundle=bundle,
            )

        @mcp.tool()
        def set_memory_state(path: str, memory_state: MemoryState, reason: str,
                             expected_sha256: str, vault: str | None = None) -> dict:
            """Change lifecycle YAML only; expected_sha256 is mandatory."""
            p = server._get_principal()
            bundle, p = server._select_vault(p, vault, write=True)
            return server._do_set_memory_state(p, path, memory_state, reason,
                                             expected_sha256, bundle)

        @mcp.tool()
        def supersede_note(old_path: str, replacement_path: str, reason: str,
                           old_sha256: str, replacement_sha256: str,
                           vault: str | None = None) -> dict:
            """Supersede an old note with an already-current replacement.

            Requires both full-file hashes. Preserves body bytes and commits
            both metadata changes together; not a crash-atomic transaction.
            """
            p = server._get_principal()
            bundle, p = server._select_vault(p, vault, write=True)
            return server._do_supersede_note(p, old_path, replacement_path, reason,
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
            p = server._get_principal()
            bundle, p = server._select_vault(p, vault, write=True)
            return server._do_patch_note(p, path, old_string, new_string, reason, bundle)

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
            p = server._get_principal()
            bundle, p = server._select_vault(p, vault, write=True)
            return server._do_append_note(
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
            p = server._get_principal()
            bundle, p = server._select_vault(p, vault, write=True)
            return server._do_update_frontmatter(p, path, patch, reason, bundle)

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
            p = server._get_principal()
            bundle, p = server._select_vault(p, vault, write=True)
            return server._do_delete_note(p, path, reason, bundle)

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
            p = server._get_principal()
            bundle, p = server._select_vault(p, vault, write=True)
            return server._do_move_note(
                p, src, dest, reason, overwrite=overwrite, bundle=bundle
            )
