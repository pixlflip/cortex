"""Vault Store — deterministic filesystem primitives over an Obsidian vault.

The vault is a local Obsidian vault: Markdown notes with optional YAML
frontmatter, folders, links, and human editability. Every operation here is
deterministic and cheap: no network, no model. Notes are addressed by their
**relative POSIX path** from the vault root (e.g. ``Projects/Cortex/README.md``)
which is also how scopes are expressed.

Frontmatter is the optional leading ``---`` YAML block, Obsidian-compatible.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import yaml

_FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n?(.*)\Z", re.DOTALL)
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")

# File extensions treated as readable Obsidian notes.
NOTE_SUFFIXES = {".md", ".markdown"}


class VaultError(Exception):
    """Raised for invalid paths or missing notes."""


@dataclass
class SearchHit:
    path: str
    line: int
    snippet: str


@dataclass
class Note:
    path: str
    frontmatter: dict
    body: str  # content with the frontmatter block stripped

    @property
    def raw(self) -> str:
        if not self.frontmatter:
            return self.body
        fm = yaml.safe_dump(self.frontmatter, sort_keys=False).strip()
        return f"---\n{fm}\n---\n{self.body}"


def split_frontmatter(text: str) -> tuple[dict, str]:
    """Split a document into (frontmatter dict, body). Empty dict if none."""
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}, text
    raw_fm, body = match.group(1), match.group(2)
    try:
        data = yaml.safe_load(raw_fm) or {}
    except yaml.YAMLError:
        # Malformed frontmatter: treat the whole thing as body, don't crash.
        return {}, text
    if not isinstance(data, dict):
        return {}, text
    return data, body


class VaultStore:
    """Read-only filesystem access to a vault, with path-traversal safety."""

    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        if not self.root.exists():
            raise VaultError(f"vault path does not exist: {self.root}")
        if not self.root.is_dir():
            raise VaultError(f"vault path is not a directory: {self.root}")

    # -- path handling -----------------------------------------------------

    def _resolve(self, rel_path: str) -> Path:
        """Resolve a vault-relative path, rejecting traversal outside the root."""
        candidate = (self.root / rel_path).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise VaultError(f"path escapes the vault: {rel_path!r}") from exc
        return candidate

    def relpath(self, p: Path) -> str:
        return p.resolve().relative_to(self.root).as_posix()

    def exists(self, rel_path: str) -> bool:
        try:
            return self._resolve(rel_path).is_file()
        except VaultError:
            return False

    # -- listing -----------------------------------------------------------

    def iter_notes(self) -> Iterator[str]:
        """Yield relative POSIX paths of all notes, skipping dotted dirs."""
        for p in sorted(self.root.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(self.root)
            # Skip anything under a hidden directory (.git, .obsidian, .trash...).
            if any(part.startswith(".") for part in rel.parts[:-1]):
                continue
            if p.suffix.lower() in NOTE_SUFFIXES:
                yield rel.as_posix()

    def list_notes(self) -> list[str]:
        return list(self.iter_notes())

    # -- reading -----------------------------------------------------------

    def read_text(self, rel_path: str) -> str:
        path = self._resolve(rel_path)
        if not path.is_file():
            raise VaultError(f"note not found: {rel_path}")
        return path.read_text(encoding="utf-8", errors="replace")

    def read_note(self, rel_path: str) -> Note:
        text = self.read_text(rel_path)
        fm, body = split_frontmatter(text)
        return Note(path=rel_path, frontmatter=fm, body=body)

    def read_frontmatter(self, rel_path: str) -> dict:
        return self.read_note(rel_path).frontmatter

    def read_section(self, rel_path: str, heading: str) -> str:
        """Return the body of a section identified by its heading text.

        The returned text spans from the matching heading up to the next heading
        of the same or shallower depth. Heading match is case-insensitive on the
        trimmed heading text.
        """
        note = self.read_note(rel_path)
        lines = note.body.splitlines()
        target = heading.strip().lower()
        start: int | None = None
        start_depth = 0
        out: list[str] = []
        for i, line in enumerate(lines):
            m = _HEADING_RE.match(line)
            if start is None:
                if m and m.group(2).strip().lower() == target:
                    start = i
                    start_depth = len(m.group(1))
                    out.append(line)
                continue
            # Inside the section: stop at a heading of equal/shallower depth.
            if m and len(m.group(1)) <= start_depth:
                break
            out.append(line)
        if start is None:
            raise VaultError(f"section {heading!r} not found in {rel_path}")
        return "\n".join(out).strip()

    # -- search ------------------------------------------------------------

    def search(
        self,
        query: str,
        *,
        regex: bool = False,
        case_sensitive: bool = False,
        limit: int = 50,
        snippet_chars: int = 160,
    ) -> list[SearchHit]:
        """Substring or regex search across note bodies.

        Returns at most ``limit`` hits, one per matching line, with a trimmed
        snippet. Deterministic, no model involved.
        """
        flags = 0 if case_sensitive else re.IGNORECASE
        pattern = re.compile(query if regex else re.escape(query), flags)
        hits: list[SearchHit] = []
        for rel in self.iter_notes():
            try:
                text = self.read_text(rel)
            except VaultError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    snippet = line.strip()
                    if len(snippet) > snippet_chars:
                        snippet = snippet[:snippet_chars].rstrip() + "…"
                    hits.append(SearchHit(path=rel, line=lineno, snippet=snippet))
                    if len(hits) >= limit:
                        return hits
        return hits

    # -- writing -------------------------------------------------------------
    #
    # These are the deterministic primitives the mutating MCP tools build on
    # (server.py). They carry no notion of scope or audit themselves — they're
    # purely "do this filesystem operation safely" (path-traversal safe, and
    # atomic where it matters). Scope checks and git-commit-per-mutation are
    # the caller's job (CortexServer), same separation read-only tools follow.

    def write_text(self, rel_path: str, text: str) -> Path:
        """Write ``text`` to ``rel_path``, creating parent dirs as needed.

        Atomic: written to a temp file in the same directory first, then
        ``os.replace`` swaps it into place, so a crash mid-write can never
        leave a partially-written note on disk.
        """
        path = self._resolve(rel_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.parent / f".{path.name}.{os.getpid()}.tmp"
        try:
            tmp.write_text(text, encoding="utf-8")
            os.replace(tmp, path)
        finally:
            if tmp.exists():
                tmp.unlink()
        return path

    def create_note(self, rel_path: str, content: str) -> Path:
        """Write a brand-new note. Raises if one already exists at this path."""
        path = self._resolve(rel_path)
        if path.exists():
            raise VaultError(f"note already exists: {rel_path}")
        return self.write_text(rel_path, content)

    def append(self, rel_path: str, text: str, separator: str = "\n\n") -> Path:
        """Append ``text`` to an existing note, joined by ``separator``."""
        existing = self.read_text(rel_path)  # raises VaultError if missing
        return self.write_text(rel_path, existing + separator + text)

    def delete_note(self, rel_path: str) -> None:
        """Delete an existing note file. Raises if missing or not a file (no
        directory deletes — that's a deliberate restriction, not an oversight).
        """
        path = self._resolve(rel_path)
        if not path.exists():
            raise VaultError(f"note not found: {rel_path}")
        if not path.is_file():
            raise VaultError(f"not a file: {rel_path}")
        path.unlink()

    def move_note(self, src: str, dest: str, *, overwrite: bool = False) -> Path:
        """Move (or rename) an existing note from ``src`` to ``dest``.

        Both paths are vault-relative and path-traversal safe. Raises if
        ``src`` is missing or not a file, if ``dest`` already exists (unless
        ``overwrite=True``), or if ``dest`` names an existing directory. Parent
        directories of ``dest`` are created as needed. The move itself is atomic
        within the vault's filesystem via ``os.replace``. Only ever operates on
        a single file — no directory moves.
        """
        src_path = self._resolve(src)
        if not src_path.exists():
            raise VaultError(f"note not found: {src}")
        if not src_path.is_file():
            raise VaultError(f"not a file: {src}")
        dest_path = self._resolve(dest)
        if dest_path == src_path:
            raise VaultError(f"source and destination are the same: {src}")
        if dest_path.is_dir():
            raise VaultError(f"destination is a directory: {dest}")
        if dest_path.exists() and not overwrite:
            raise VaultError(f"note already exists: {dest}")
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(src_path, dest_path)
        return dest_path
