"""Search Index — SQLite FTS5/BM25 ranked keyword search over the vault.

This is the second search primitive alongside :class:`cortex.vault.VaultStore`'s
deterministic substring/regex search. Where ``VaultStore.search`` answers "which
lines contain this literal text", :class:`SearchIndex` answers "which notes (and
which sections of them) best match this natural-language-ish query", using
SQLite's FTS5 extension with the Porter stemmer and BM25 ranking.

Design constraints (see Workstream A spec):

* **Zero new runtime dependencies.** Only the stdlib ``sqlite3`` module.
* **The index is global** (it indexes every note in the vault), but it never
  enforces scope itself — callers (the MCP tool layer in ``server.py``) are
  responsible for filtering hits through ``scopes.path_allowed`` before they
  reach a principal. This module purely answers "what matches", not "what may
  this caller see".
* **Never crash the server.** If FTS5 isn't compiled into the local SQLite
  build, or a query fails for any reason, this falls back to
  ``VaultStore.search`` instead of raising.

Chunking is heading-aware: a note's body is split at Markdown headings, and any
section still larger than ``chunk_chars`` is further split on paragraph (blank
line) boundaries with a small character overlap so a chunk boundary doesn't
sever a relevant phrase. Each chunk remembers the 1-based starting line in the
original note (for snippet attribution) and a "breadcrumb" of the heading path
it lives under (e.g. ``"Hello Cortex > What is this vault?"``).
"""

from __future__ import annotations

import logging
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .vault import SearchHit, VaultError, VaultStore, _HEADING_RE

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1"

# BM25 column weights: title and tags are short and highly diagnostic, headings
# give section-level context, body is the bulk text. Order matches the column
# order of the `chunks` FTS5 table: path(unindexed), title, headings, tags, body.
_W_TITLE = 5.0
_W_HEADINGS = 3.0
_W_TAGS = 4.0
_W_BODY = 1.0

# Column index of `body` within the FTS5 table (0-based, counting all columns
# including the UNINDEXED ones) — used for snippet()'s column-targeting arg.
_COL_BODY = 4

# Characters with special meaning in FTS5 MATCH syntax. We strip/avoid these
# when building a sanitized query so user input can never produce a syntax
# error or unintended column-filter/operator behavior.
_FTS_OPERATOR_CHARS = re.compile(r'["*^:(){}\[\]]')
_QUOTED_PHRASE_RE = re.compile(r'"([^"]+)"')


@dataclass
class IndexHit:
    path: str
    score: float
    snippet: str  # short, highlight-style excerpt (for the `search` tool)
    line: int
    headings: str
    body: str = ""  # full chunk text (for context_pack-style packing)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _split_tags(raw: Any) -> str:
    """Normalize frontmatter ``tags`` (list or comma-separated string) into a
    single space-joined string suitable for an FTS column."""
    if raw is None:
        return ""
    if isinstance(raw, (list, tuple)):
        items = [str(t).strip() for t in raw if str(t).strip()]
    elif isinstance(raw, str):
        items = [t.strip() for t in raw.split(",") if t.strip()]
    else:
        items = [str(raw)]
    return " ".join(items)


def _derive_title(rel_path: str, frontmatter: dict, body: str) -> str:
    fm_title = frontmatter.get("title") if frontmatter else None
    if fm_title:
        return str(fm_title)
    for line in body.splitlines():
        m = _HEADING_RE.match(line)
        if m and len(m.group(1)) == 1:
            return m.group(2).strip()
    return Path(rel_path).stem


@dataclass
class _Chunk:
    headings: str
    start_line: int
    text: str


def _split_paragraphs_with_overlap(
    lines: list[str], start_line: int, chunk_chars: int, overlap: int
) -> list[tuple[int, str]]:
    """Split a block of lines into ~chunk_chars pieces on blank-line (paragraph)
    boundaries, carrying ``overlap`` characters of trailing context forward into
    the next piece. Returns (start_line, text) pairs."""
    text = "\n".join(lines)
    if len(text) <= chunk_chars:
        return [(start_line, text)] if text.strip() else []

    # Paragraphs, with the 1-based line number each starts on.
    paragraphs: list[tuple[int, str]] = []
    buf: list[str] = []
    buf_start = start_line
    for i, line in enumerate(lines):
        lineno = start_line + i
        if line.strip() == "":
            if buf:
                paragraphs.append((buf_start, "\n".join(buf)))
                buf = []
            continue
        if not buf:
            buf_start = lineno
        buf.append(line)
    if buf:
        paragraphs.append((buf_start, "\n".join(buf)))

    # A lone short leading fragment (e.g. just a heading line, or a carried-over
    # overlap remnant) must never be ejected as its own near-empty chunk just
    # because the *next* paragraph alone would overflow — require the buffer to
    # already hold a reasonable fraction of chunk_chars before a flush is
    # allowed, so it always absorbs at least one substantial paragraph first.
    min_fill = max(1, int(chunk_chars * 0.4))

    out: list[tuple[int, str]] = []
    cur_start = paragraphs[0][0] if paragraphs else start_line
    cur_parts: list[str] = []
    cur_len = 0
    for p_start, p_text in paragraphs:
        if cur_parts and cur_len >= min_fill and cur_len + len(p_text) + 2 > chunk_chars:
            joined = ("\n\n".join(cur_parts)).strip()
            if joined:
                out.append((cur_start, joined))
            # Carry trailing overlap forward so a boundary doesn't sever context.
            carry = joined[-overlap:] if overlap > 0 else ""
            cur_parts = [carry] if carry else []
            cur_len = len(carry)
            cur_start = p_start
        cur_parts.append(p_text)
        cur_len += len(p_text) + 2
    if cur_parts:
        joined = ("\n\n".join(cur_parts)).strip()
        if joined:
            out.append((cur_start, joined))
    return out


def chunk_note(body: str, *, chunk_chars: int = 1500, overlap: int = 150) -> list[_Chunk]:
    """Split a note body into heading-aware chunks.

    Each heading starts a new section; the breadcrumb accumulates ancestor
    headings (e.g. ``"Top > Sub"``) following Markdown heading depth. A section
    larger than ``chunk_chars`` is further split on paragraph boundaries with
    character overlap carried forward.
    """
    lines = body.splitlines()
    # Sections: list of (breadcrumb, start_line, [body_lines]).
    sections: list[tuple[str, int, list[str]]] = []
    stack: list[tuple[int, str]] = []  # (depth, text) ancestor headings
    cur_breadcrumb = ""
    cur_start = 1
    cur_lines: list[str] = []

    def flush():
        if cur_lines and any(l.strip() for l in cur_lines):
            sections.append((cur_breadcrumb, cur_start, cur_lines))

    for i, line in enumerate(lines, start=1):
        m = _HEADING_RE.match(line)
        if m:
            flush()
            depth = len(m.group(1))
            text = m.group(2).strip()
            stack = [s for s in stack if s[0] < depth]
            stack.append((depth, text))
            cur_breadcrumb = " > ".join(t for _, t in stack)
            cur_start = i
            cur_lines = [line]
        else:
            cur_lines.append(line)
    flush()

    if not sections:
        sections = [("", 1, lines)]

    chunks: list[_Chunk] = []
    for breadcrumb, start_line, sec_lines in sections:
        for piece_start, piece_text in _split_paragraphs_with_overlap(
            sec_lines, start_line, chunk_chars, overlap
        ):
            if piece_text.strip():
                chunks.append(_Chunk(headings=breadcrumb, start_line=piece_start, text=piece_text))
    return chunks


def sanitize_fts_query(raw: str) -> str:
    """Turn arbitrary user input into a safe FTS5 MATCH expression.

    Tokenizes on whitespace, preserves explicit ``"quoted phrases"`` verbatim
    (re-quoted), strips FTS5 operator characters from bare tokens, wraps each
    surviving token in double quotes (so it's always treated as a literal
    string, never a column filter or operator), and OR-joins everything. This
    is recall-friendly by design — bm25 still floats documents matching more
    terms to the top — and it can never raise a MATCH syntax error since every
    token is a quoted string literal.

    Returns "" if nothing usable survives sanitization.
    """
    if not raw or not raw.strip():
        return ""

    parts: list[str] = []
    remainder = raw

    # Pull out explicit quoted phrases first so their contents (including FTS
    # operator chars like ':' or '(') survive as a literal phrase.
    def take_phrase(m: re.Match[str]) -> str:
        phrase = m.group(1).strip()
        if phrase:
            cleaned = phrase.replace('"', " ").strip()
            if cleaned:
                parts.append(f'"{cleaned}"')
        return " "

    remainder = _QUOTED_PHRASE_RE.sub(take_phrase, remainder)

    for tok in remainder.split():
        cleaned = _FTS_OPERATOR_CHARS.sub("", tok).strip()
        # A lone '-' prefix means "NOT" in FTS5; since we already stripped it
        # along with other operator chars there's nothing left to misinterpret.
        if cleaned:
            parts.append(f'"{cleaned}"')

    if not parts:
        return ""
    return " OR ".join(parts)


class SearchIndex:
    """SQLite FTS5-backed ranked search over a :class:`VaultStore`.

    Indexing is incremental (:meth:`sync`) and cheap enough to call before
    every query (:meth:`ensure_fresh`). If FTS5 isn't available in the local
    SQLite build, every query transparently falls back to
    ``VaultStore.search`` instead of raising.
    """

    def __init__(
        self,
        vault: VaultStore,
        path: Path,
        *,
        chunk_chars: int = 1500,
        overlap: int = 150,
        enabled: bool = True,
    ):
        self.vault = vault
        self.path = Path(path)
        self.chunk_chars = chunk_chars
        self.overlap = overlap
        self.enabled = enabled
        self.fts_available = False
        self._conn: sqlite3.Connection | None = None
        self._synced = False
        if self.enabled:
            self._conn = self._open()
            self.fts_available = self._init_schema()
            if not self.fts_available:
                logger.warning(
                    "SQLite FTS5 is not available; SearchIndex falls back to "
                    "VaultStore substring search for all queries."
                )
        else:
            logger.info("SearchIndex disabled by config; using VaultStore.search fallback.")

    # -- setup ---------------------------------------------------------------

    def _open(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> bool:
        assert self._conn is not None
        conn = self._conn
        conn.execute(
            "CREATE TABLE IF NOT EXISTS notes ("
            " path TEXT PRIMARY KEY,"
            " mtime REAL,"
            " size INTEGER,"
            " title TEXT"
            ")"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
        )
        try:
            conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS chunks USING fts5("
                " path UNINDEXED, title, headings, tags, body, start_line UNINDEXED,"
                " tokenize='porter unicode61'"
                ")"
            )
        except sqlite3.OperationalError as exc:
            logger.warning("FTS5 virtual table creation failed (%s); disabling ranked search.", exc)
            return False
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (SCHEMA_VERSION,),
        )
        conn.commit()
        return True

    # -- sync / indexing -------------------------------------------------------

    def ensure_fresh(self) -> None:
        """Lazily sync once per process lifetime is not enough for a long-lived
        server, so this re-checks vault mtimes every call but does no work for
        unchanged notes; cheap enough to call before each query."""
        if not self.enabled or not self.fts_available:
            return
        self.sync()

    def sync(self) -> None:
        """Incrementally bring the index up to date with the vault on disk.

        Compares each note's (mtime, size) against the `notes` bookkeeping
        table; only changed/new notes are (re)chunked, and notes removed from
        the vault are dropped from both tables.
        """
        if not self.enabled or not self.fts_available or self._conn is None:
            return
        conn = self._conn
        on_disk = set(self.vault.iter_notes())

        existing = {row["path"]: (row["mtime"], row["size"]) for row in conn.execute("SELECT path, mtime, size FROM notes")}

        seen: set[str] = set()
        changed = False
        for rel in on_disk:
            seen.add(rel)
            try:
                full = self.vault._resolve(rel)
                st = full.stat()
            except (VaultError, OSError):
                continue
            mtime, size = st.st_mtime, st.st_size
            prev = existing.get(rel)
            if prev is not None and prev == (mtime, size):
                continue  # unchanged
            self._index_note(rel, mtime, size)
            changed = True

        removed = set(existing) - seen
        for rel in removed:
            conn.execute("DELETE FROM chunks WHERE path = ?", (rel,))
            conn.execute("DELETE FROM notes WHERE path = ?", (rel,))
            changed = True

        if changed or "last_indexed" not in {r["key"] for r in conn.execute("SELECT key FROM meta")}:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('last_indexed', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (_utcnow_iso(),),
            )
        conn.commit()
        self._synced = True

    def _index_note(self, rel: str, mtime: float, size: int) -> None:
        assert self._conn is not None
        conn = self._conn
        try:
            note = self.vault.read_note(rel)
        except VaultError:
            return
        title = _derive_title(rel, note.frontmatter, note.body)
        tags = _split_tags(note.frontmatter.get("tags") if note.frontmatter else None)

        conn.execute("DELETE FROM chunks WHERE path = ?", (rel,))
        conn.execute(
            "INSERT INTO notes (path, mtime, size, title) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(path) DO UPDATE SET mtime=excluded.mtime, size=excluded.size, title=excluded.title",
            (rel, mtime, size, title),
        )
        for c in chunk_note(note.body, chunk_chars=self.chunk_chars, overlap=self.overlap):
            conn.execute(
                "INSERT INTO chunks (path, title, headings, tags, body, start_line) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (rel, title, c.headings, tags, c.text, c.start_line),
            )

    def rebuild(self) -> None:
        """Drop and recreate the index from scratch."""
        if not self.enabled:
            return
        if self._conn is not None:
            self._conn.close()
        if self.path.exists():
            self.path.unlink()
        for suffix in ("-wal", "-shm", "-journal"):
            p = Path(str(self.path) + suffix)
            if p.exists():
                p.unlink()
        self._conn = self._open()
        self.fts_available = self._init_schema()
        self._synced = False
        if self.fts_available:
            self.sync()

    # -- query -----------------------------------------------------------------

    def search(
        self,
        query: str,
        *,
        limit: int = 50,
        snippet_chars: int = 160,
    ) -> list[IndexHit]:
        """Ranked search across chunks. Falls back to ``VaultStore.search``
        (wrapped as IndexHit, score=0.0) if FTS5 is unavailable, the query
        sanitizes to nothing, or the MATCH query fails for any reason."""
        if self.enabled and self.fts_available and self._conn is not None:
            fts_query = sanitize_fts_query(query)
            if fts_query:
                try:
                    return self._fts_search(fts_query, limit=limit, snippet_chars=snippet_chars)
                except sqlite3.OperationalError as exc:
                    logger.warning("FTS5 MATCH query failed (%r); falling back to substring search.", exc)
        return self._fallback_search(query, limit=limit, snippet_chars=snippet_chars)

    def _fts_search(self, fts_query: str, *, limit: int, snippet_chars: int) -> list[IndexHit]:
        assert self._conn is not None
        sql = (
            "SELECT path, headings, start_line, body, "
            f" bm25(chunks, ?, ?, ?, ?) AS score, "
            f" snippet(chunks, {_COL_BODY}, '', '', '…', 12) AS snip "
            "FROM chunks WHERE chunks MATCH ? ORDER BY score ASC LIMIT ?"
        )
        # bm25() column-weight args follow declaration order of indexed columns:
        # title, headings, tags, body (path/start_line are UNINDEXED, no weight).
        rows = self._conn.execute(
            sql, (_W_TITLE, _W_HEADINGS, _W_TAGS, _W_BODY, fts_query, limit)
        ).fetchall()
        hits: list[IndexHit] = []
        for row in rows:
            snip = (row["snip"] or "").strip()
            if len(snip) > snippet_chars:
                snip = snip[:snippet_chars].rstrip() + "…"
            if not snip:
                # snippet() can come back empty for short/edge-case chunks;
                # fall back to a trimmed chunk prefix per the spec.
                raw_body = row["body"] or ""
                snip = raw_body[:snippet_chars].strip()
                if len(raw_body) > snippet_chars:
                    snip = snip.rstrip() + "…"
            hits.append(
                IndexHit(
                    path=row["path"],
                    score=float(row["score"]),
                    snippet=snip,
                    line=int(row["start_line"]),
                    headings=row["headings"] or "",
                    body=row["body"] or "",
                )
            )
        return hits

    def _fallback_search(self, query: str, *, limit: int, snippet_chars: int) -> list[IndexHit]:
        hits: list[SearchHit] = self.vault.search(query, limit=limit, snippet_chars=snippet_chars)
        return [
            IndexHit(path=h.path, score=0.0, snippet=h.snippet, line=h.line, headings="", body=h.snippet)
            for h in hits
        ]

    # -- stats -------------------------------------------------------------

    def stats(self) -> dict:
        if not self.enabled or not self.fts_available or self._conn is None:
            return {"note_count": 0, "chunk_count": 0, "last_indexed": None}
        conn = self._conn
        note_count = conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
        chunk_count = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        row = conn.execute("SELECT value FROM meta WHERE key = 'last_indexed'").fetchone()
        last_indexed = row["value"] if row else None
        return {
            "note_count": int(note_count),
            "chunk_count": int(chunk_count),
            "last_indexed": last_indexed,
        }

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
