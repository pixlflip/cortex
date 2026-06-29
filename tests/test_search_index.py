"""Search index tests: FTS5/BM25 ranking, chunking, incremental sync, the
FTS-unavailable fallback path, and — the #1 correctness requirement — that
scope filtering happens at the query layer so an out-of-scope note can never
appear in results, even when it would otherwise outrank the visible ones."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from cortex.config import CortexConfig, IndexConfig, Principal, VaultConfig
from cortex.search_index import SearchIndex, chunk_note, sanitize_fts_query
from cortex.server import CortexServer
from cortex.vault import VaultStore


# -- fixtures ----------------------------------------------------------------

@pytest.fixture
def vault(tmp_path: Path) -> Path:
    root = tmp_path / "vault"
    (root / "Welcome").mkdir(parents=True)
    (root / "Public").mkdir()
    (root / "Private").mkdir()
    (root / "Welcome" / "hello.md").write_text(
        "---\ntitle: Hello Cortex\ntags: [intro, vault]\n---\n"
        "# Hello Cortex\n\n"
        "## What is this vault?\n\n"
        "Cortex is a governed memory layer for AI agents running over MCP. "
        "It indexes notes and answers natural language questions about them "
        "using ranked search.\n",
        encoding="utf-8",
    )
    (root / "Public" / "runner.md").write_text(
        "# Runner\n\nA runner went running through the park every morning.\n",
        encoding="utf-8",
    )
    (root / "Private" / "secret.md").write_text(
        "# Secret\n\nCortex is a governed memory layer for AI agents running "
        "over MCP too — but this note must never be visible to a scoped principal.\n",
        encoding="utf-8",
    )
    return root


@pytest.fixture
def store(vault: Path) -> VaultStore:
    return VaultStore(vault)


@pytest.fixture
def index(store: VaultStore, tmp_path: Path) -> SearchIndex:
    idx = SearchIndex(store, tmp_path / "index.sqlite")
    idx.sync()
    return idx


# -- chunking ------------------------------------------------------------

def test_chunk_note_heading_aware_breadcrumbs():
    body = (
        "# Top\n\nintro text\n\n"
        "## Sub\n\nsub text here\n\n"
        "### Deep\n\ndeep text here\n"
    )
    chunks = chunk_note(body, chunk_chars=1500, overlap=150)
    breadcrumbs = [c.headings for c in chunks]
    assert breadcrumbs == ["Top", "Top > Sub", "Top > Sub > Deep"]
    # start_line should point at the heading line itself (1-based).
    assert chunks[0].start_line == 1
    assert chunks[1].start_line == 5
    assert chunks[2].start_line == 9


def test_chunk_note_splits_large_section_with_overlap():
    para = (
        "Paragraph {} with enough padding text to take up real space so the "
        "section exceeds the configured chunk_chars threshold and must split."
    )
    big = "# Big\n\n" + "\n\n".join(para.format(i) for i in range(8))
    chunks = chunk_note(big, chunk_chars=300, overlap=30)
    assert len(chunks) > 1
    # Every chunk stays close to the budget (some slack allowed for overlap).
    assert all(len(c.text) <= 300 + 60 for c in chunks)
    # All chunks belong to the same (only) heading.
    assert all(c.headings == "Big" for c in chunks)


def test_chunk_note_no_headings_falls_back_to_single_section():
    chunks = chunk_note("just a plain note with no headings at all\n")
    assert len(chunks) == 1
    assert chunks[0].headings == ""
    assert chunks[0].start_line == 1


# -- query sanitization ---------------------------------------------------

def test_sanitize_fts_query_basic_terms():
    assert sanitize_fts_query("hello world") == '"hello" OR "world"'


def test_sanitize_fts_query_preserves_quoted_phrase():
    result = sanitize_fts_query('"exact phrase" extra')
    assert '"exact phrase"' in result
    assert '"extra"' in result


def test_sanitize_fts_query_strips_operator_characters():
    # Should never raise, and should never leave a bare operator character
    # that could be interpreted as FTS5 syntax (column filter, NOT, etc).
    result = sanitize_fts_query('weird:(*"stuff) AND other')
    assert result  # something usable survives

    # The real proof: feeding it back through an actual MATCH never raises.
    import sqlite3

    con = sqlite3.connect(":memory:")
    con.execute("CREATE VIRTUAL TABLE t USING fts5(body)")
    con.execute("INSERT INTO t (body) VALUES ('weird stuff and other text')")
    con.execute(f"SELECT * FROM t WHERE t MATCH '{result}'")  # must not raise
    con.close()


def test_sanitize_fts_query_empty_input():
    assert sanitize_fts_query("") == ""
    assert sanitize_fts_query("   ") == ""
    # Pure operator soup with nothing left over also sanitizes to empty.
    assert sanitize_fts_query('***:::()') == ""


# -- ranked search: the core "substring would miss it" property -------------

def test_natural_language_query_ranks_right_note_first(index: SearchIndex):
    hits = index.search("what is a governed memory layer for agents")
    assert hits, "expected at least one hit"
    assert hits[0].path == "Welcome/hello.md"


def test_case_insensitive(index: SearchIndex):
    hits = index.search("HELLO CORTEX")
    assert any(h.path == "Welcome/hello.md" for h in hits)


def test_porter_stemming_run_matches_running(index: SearchIndex):
    hits = index.search("run")
    paths = {h.path for h in hits}
    assert "Public/runner.md" in paths


def test_heading_aware_snippet_and_line(index: SearchIndex):
    hits = index.search("ranked search natural language")
    top = next(h for h in hits if h.path == "Welcome/hello.md")
    assert "What is this vault?" in top.headings
    assert top.line > 1  # the matching chunk starts after the H1


def test_fts_search_score_is_better_when_lower(index: SearchIndex):
    # bm25() is negative-better; multiple hits should come back sorted
    # ascending (best first).
    hits = index.search("governed memory layer agents MCP")
    scores = [h.score for h in hits]
    assert scores == sorted(scores)


# -- incremental sync ---------------------------------------------------

def test_sync_reflects_added_note(store: VaultStore, tmp_path: Path):
    idx = SearchIndex(store, tmp_path / "inc.sqlite")
    idx.sync()
    before = idx.stats()["note_count"]

    (store.root / "Public" / "new.md").write_text("# New\n\nbananas everywhere\n", encoding="utf-8")
    idx.sync()
    after = idx.stats()
    assert after["note_count"] == before + 1
    assert any(h.path == "Public/new.md" for h in idx.search("bananas"))


def test_sync_reflects_modified_note(store: VaultStore, tmp_path: Path):
    idx = SearchIndex(store, tmp_path / "inc.sqlite")
    idx.sync()
    assert any(h.path == "Public/runner.md" for h in idx.search("running"))

    time.sleep(0.01)  # ensure mtime advances
    (store.root / "Public" / "runner.md").write_text(
        "# Runner\n\nnow only about kayaking, running is gone\n", encoding="utf-8"
    )
    idx.sync()
    hits = idx.search("kayaking")
    assert any(h.path == "Public/runner.md" for h in hits)


def test_sync_reflects_deleted_note(store: VaultStore, tmp_path: Path):
    idx = SearchIndex(store, tmp_path / "inc.sqlite")
    idx.sync()
    before = idx.stats()

    (store.root / "Private" / "secret.md").unlink()
    idx.sync()
    after = idx.stats()
    assert after["note_count"] == before["note_count"] - 1
    assert not any(h.path == "Private/secret.md" for h in idx.search("Cortex governed memory"))


def test_stats_shape(index: SearchIndex):
    s = index.stats()
    assert set(s) == {"note_count", "chunk_count", "last_indexed"}
    assert s["note_count"] == 3
    assert s["chunk_count"] >= 3
    assert s["last_indexed"]  # ISO8601 string, non-empty


def test_rebuild_drops_and_recreates(store: VaultStore, tmp_path: Path):
    idx = SearchIndex(store, tmp_path / "rb.sqlite")
    idx.sync()
    before = idx.stats()
    idx.rebuild()
    after = idx.stats()
    assert after["note_count"] == before["note_count"]
    assert any(h.path == "Welcome/hello.md" for h in idx.search("Cortex"))


# -- FTS-unavailable fallback ---------------------------------------------

def test_fallback_when_fts_unavailable(store: VaultStore, tmp_path: Path):
    idx = SearchIndex(store, tmp_path / "fb.sqlite")
    idx.sync()
    # Simulate FTS5 not being compiled in, as the constructor would set on a
    # sqlite3.OperationalError during CREATE VIRTUAL TABLE.
    idx.fts_available = False
    hits = idx.search("governed memory layer")
    assert any(h.path == "Welcome/hello.md" for h in hits)
    # Fallback hits carry a neutral score (no bm25 ranking available).
    assert all(h.score == 0.0 for h in hits)


def test_disabled_index_falls_back_to_vault_search(store: VaultStore, tmp_path: Path):
    idx = SearchIndex(store, tmp_path / "disabled.sqlite", enabled=False)
    assert idx.fts_available is False
    hits = idx.search("governed memory layer")
    assert any(h.path == "Welcome/hello.md" for h in hits)
    assert idx.stats() == {"note_count": 0, "chunk_count": 0, "last_indexed": None}


def test_search_never_raises_on_pathological_query(index: SearchIndex):
    for bad in ['"', "***", "((()))", ':::', "", "   ", 'a"b*c(d)e:f']:
        index.search(bad)  # must not raise


# -- scope filtering happens at the query layer ---------------------------

def _scoped_server(vault: Path, tmp_path: Path, scopes: list[str]) -> CortexServer:
    cfg = CortexConfig(
        vault=VaultConfig(path=vault),
        index=IndexConfig(path=tmp_path / "server.sqlite"),
        principals=[Principal(name="scoped", scopes=scopes)],
    )
    return CortexServer(cfg, principal=cfg.principal("scoped"))


def test_search_tool_never_returns_out_of_scope_note(vault: Path, tmp_path: Path):
    srv = _scoped_server(vault, tmp_path, ["Welcome/**", "Public/**"])

    async def run():
        return await srv.mcp.call_tool(
            "search", {"query": "governed memory layer for AI agents over MCP"}
        )

    result = asyncio.run(run())[1]["result"]
    paths = {r["path"] for r in result}
    assert "Private/secret.md" not in paths
    assert "Welcome/hello.md" in paths
    # Every returned hit also carries a score field (the spec's optional addition).
    assert all("score" in r for r in result)
    assert all({"path", "line", "snippet"} <= set(r) for r in result)


def test_search_tool_scope_safe_under_adversarial_ranking(vault: Path, tmp_path: Path):
    """Out-of-scope notes that *outrank* the only visible match must still
    never appear — even with a small `limit` that could otherwise truncate
    before scope filtering happens."""
    for i in range(30):
        (vault / "Private" / f"noise{i}.md").write_text(
            f"# Noise {i}\n\nwidget widget widget widget widget filler {i}\n",
            encoding="utf-8",
        )
    (vault / "Welcome" / "target.md").write_text(
        "# Target\n\nwidget mentioned once here only\n", encoding="utf-8"
    )
    srv = _scoped_server(vault, tmp_path, ["Welcome/**"])

    async def run():
        return await srv.mcp.call_tool("search", {"query": "widget", "limit": 1})

    result = asyncio.run(run())[1]["result"]
    for r in result:
        assert r["path"] == "Welcome/target.md", f"scope leak: {r['path']}"


def test_context_pack_excludes_out_of_scope_notes(vault: Path, tmp_path: Path):
    srv = _scoped_server(vault, tmp_path, ["Welcome/**", "Public/**"])

    async def run():
        return await srv.mcp.call_tool(
            "context_pack", {"query": "governed memory layer for AI agents"}
        )

    text = asyncio.run(run())[1]["result"]
    assert "Welcome/hello.md" in text
    assert "Private" not in text
    assert "secret.md" not in text


def test_context_pack_natural_language_returns_expected_note(vault: Path, tmp_path: Path):
    srv = _scoped_server(vault, tmp_path, ["**"])

    async def run():
        return await srv.mcp.call_tool(
            "context_pack",
            {"query": "what does Cortex do for AI agents and MCP", "max_notes": 3},
        )

    text = asyncio.run(run())[1]["result"]
    assert "Welcome/hello.md" in text
    assert "governed memory layer" in text


def test_regex_search_path_unaffected_by_index(vault: Path, tmp_path: Path):
    """regex=True must keep using VaultStore.search (backward compatibility)
    regardless of index state."""
    srv = _scoped_server(vault, tmp_path, ["**"])

    async def run():
        return await srv.mcp.call_tool(
            "search", {"query": "gov[er]+ned", "regex": True}
        )

    result = asyncio.run(run())[1]["result"]
    assert any(r["path"] == "Welcome/hello.md" for r in result)
    # Regex path doesn't promise ranking, but must still satisfy the
    # backward-compat shape (path, line, snippet at minimum).
    assert all({"path", "line", "snippet"} <= set(r) for r in result)
