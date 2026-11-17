"""Write orchestration for the Cortex MCP server.

These methods hold the actual mutation logic so it is directly unit-testable
without going through the MCP tool-call machinery. ``CortexServer`` mixes them
in; the ``@mcp.tool()`` closures in :mod:`cortex.mcp_tools.write_tools` are thin
wrappers that resolve the principal and delegate here.
"""

from __future__ import annotations

import base64
import logging
import binascii
import hashlib
import mimetypes
import re
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from .config import Principal
from .memory_lifecycle import (
    MANAGED,
    MemoryState,
    memory_patch,
    parse_memory_bytes,
    serialized_write,
    update_metadata_bytes,
    validate_memory_state,
)
from .serialization import normalize_json
from .vault import (
    NOTE_SUFFIXES,
    VaultError,
    VaultStore,
    _FRONTMATTER_RE,
)
from .vaults import VaultBundle

_LOG = logging.getLogger("cortex.janitor")

MAX_FILE_WRITE_BYTES = 8 * 1024 * 1024


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


class NoteWriteMixin:
    """Mutation helpers shared by the MCP write tools (mixed into CortexServer)."""

    if TYPE_CHECKING:
        # Provided by CortexServer; declared here so the mixin type-checks.
        @property
        def _local_bundle(self) -> VaultBundle: ...

        @property
        def vault(self) -> VaultStore: ...

        @staticmethod
        def _require_visible(principal: Principal, path: str) -> str: ...

        @staticmethod
        def _require_writable(principal: Principal, path: str) -> str: ...

        @staticmethod
        def _require_writable_file(principal: Principal, path: str) -> str: ...

        def _commit_and_reindex(
            self,
            principal: Principal,
            reason: str,
            *paths: str,
            bundle: VaultBundle | None = None,
        ) -> str | None: ...

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
        return {"vault": bundle.vault_id if bundle else self._local_bundle.vault_id,
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
        if (original is not None and previous == 'current' and state is None
                and parse_memory_bytes(raw)[1] != parse_memory_bytes(original)[1]):
            requested = 'unreviewed'
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
        if exists:
            # Replacement preserves managed metadata from the original note.
            # A write-only grant may create, but must not inspect that metadata.
            self._require_visible(principal, path)
        original = self._note_bytes(store, path) if exists else None
        updated = self._ordinary_metadata(content.encode('utf-8'), original, principal, reason, memory_state)
        receipt = self._save_note_updates(principal, {path: updated}, {path: original}, reason, bundle)
        return {**receipt, 'path': path, 'created': not exists,
                'sha256': hashlib.sha256(updated).hexdigest()}

    @serialized_write
    def _do_patch_note(self, principal: Principal, path: str, old_string: str,
                       new_string: str, reason: str, bundle: VaultBundle | None = None) -> dict:
        path = self._require_writable(principal, path)
        self._require_visible(principal, path)  # match counts would be a read oracle
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
        self._require_visible(principal, path)
        store = bundle.store if bundle is not None else self.vault
        original = self._note_bytes(store, path)
        raw = original + separator.encode('utf-8') + text.encode('utf-8')
        updated = self._ordinary_metadata(raw, original, principal, reason)
        return {**self._save_note_updates(principal, {path:updated}, {path:original}, reason, bundle), 'path':path}

    @serialized_write
    def _do_update_frontmatter(self, principal: Principal, path: str, patch: dict,
                               reason: str, bundle: VaultBundle | None = None) -> dict:
        path = self._require_writable(principal, path)
        self._require_visible(principal, path)  # response includes existing metadata
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
        self._require_visible(principal, path)
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
        pending: list[tuple[str, bool]] = [(old_path, False)]
        visiting: set[str] = set()
        complete: set[str] = set()
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
        return {"vault": bundle.vault_id if bundle else self._local_bundle.vault_id, "path": path, "deleted": True, "commit": sha}

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
        # Otherwise a write-only source could be moved into a readable scope.
        self._require_visible(principal, src)
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
            "vault": bundle.vault_id if bundle else self._local_bundle.vault_id,
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
            "vault": bundle.vault_id if bundle else self._local_bundle.vault_id,
            "path": path,
            "created": not existed,
            "size": len(content),
            "media_type": mimetypes.guess_type(path)[0] or "application/octet-stream",
            "sha256": digest,
            "commit": sha,
        }
