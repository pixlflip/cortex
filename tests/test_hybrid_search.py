"""Hybrid (lexical + local embedding) retrieval.

A deterministic fake provider maps words to a few "concept" axes so a
paraphrase with no shared vocabulary still lands near the right note. The
network is never used, except for one loopback HTTP endpoint run in-process to
exercise the OpenAI-compatible wire format end to end.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from cortex.config import (
    ConfigError,
    CortexConfig,
    IndexConfig,
    Principal,
    SearchConfig,
    SemanticSearchConfig,
    VaultConfig,
    VaultsConfig,
    load_config,
)
from cortex.embeddings import (
    EmbeddingError,
    OpenAICompatibleEmbeddings,
    is_loopback_url,
    pack_normalized,
    unpack,
)
from cortex.recall import SemanticRetrieval, SemanticUnavailable, recall_hits
from cortex.search_index import SearchIndex
from cortex.server import CortexServer
from cortex.vault import VaultStore

CONCEPTS = {
    "privacy": {"private", "privacy", "isolation", "isolated", "confidential", "separate", "separates", "secret"},
    "cooking": {"recipe", "cooking", "bake", "bread", "kitchen", "oven", "dough"},
    "travel": {"flight", "travel", "trip", "airport", "passport", "itinerary"},
}


class FakeEmbeddings:
    """Bag-of-concepts vectors; counts calls and texts for incrementality."""

    def __init__(self, model: str = "fake-v1", *, fail: bool = False, width: int = 4):
        self.model = model
        self.fail = fail
        self.width = width
        self.calls: list[list[str]] = []

    @property
    def identity(self) -> str:
        return f"fake:{self.model}"

    def embed(self, texts: list[str]) -> list[list[float]]:
        self.calls.append(list(texts))
        if self.fail:
            raise EmbeddingError("endpoint down")
        out = []
        for text in texts:
            words = set(re.findall(r"[a-z]+", text.lower()))
            vector = [float(len(words & vocab)) for vocab in CONCEPTS.values()]
            vector += [0.05] * (self.width - len(vector))
            out.append(vector)
        return out

    @property
    def embedded_texts(self) -> list[str]:
        return [text for call in self.calls for text in call]


@pytest.fixture
def vault(tmp_path: Path) -> Path:
    root = tmp_path / "vaults" / "p"
    notes = {
        "Public/isolation.md": "# Accounts\n\nPrincipal-scoped isolation separates every account.\n",
        "Public/bread.md": "# Bread\n\nBake the dough in a hot oven.\n",
        "Public/trip.md": "# Trip\n\nFlight itinerary and passport checklist.\n",
        "Private/secret.md": "# Hidden\n\nConfidential privacy isolation secret separate private.\n",
    }
    for rel, text in notes.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return root


def make_index(vault: Path) -> SearchIndex:
    return SearchIndex(VaultStore(vault), vault.parent.parent / "idx.sqlite")


QUESTION = "how is family data kept confidential?"


# -- vectors and provider ----------------------------------------------------


def test_pack_normalizes_and_round_trips():
    values = unpack(pack_normalized([3.0, 4.0]))
    assert list(values) == pytest.approx([0.6, 0.8])
    with pytest.raises(EmbeddingError):
        pack_normalized([0.0, 0.0])


@pytest.mark.parametrize(
    "url,loopback",
    [
        ("http://127.0.0.1:11434/v1", True),
        ("http://localhost:11434/v1", True),
        ("http://[::1]:8080/v1", True),
        ("http://127.8.9.10/v1", True),
        ("https://api.example.com/v1", False),
        ("http://192.168.1.10:11434/v1", False),
        ("http://localhost.example.com/v1", False),
    ],
)
def test_loopback_detection(url, loopback):
    assert is_loopback_url(url) is loopback


def _mock_provider(handler, **kwargs) -> OpenAICompatibleEmbeddings:
    return OpenAICompatibleEmbeddings(
        base_url="http://127.0.0.1:9/v1", model="m", transport=httpx.MockTransport(handler), **kwargs
    )


def test_provider_sends_openai_shape_and_orders_by_index():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"data": [
            {"index": 1, "embedding": [0.0, 1.0]},
            {"index": 0, "embedding": [1.0, 0.0]},
        ]})

    provider = _mock_provider(handler, api_key="k")
    assert provider.embed(["a", "b"]) == [[1.0, 0.0], [0.0, 1.0]]
    assert seen == {"url": "http://127.0.0.1:9/v1/embeddings",
                    "body": {"model": "m", "input": ["a", "b"]}, "auth": "Bearer k"}


@pytest.mark.parametrize(
    "response,message",
    [
        (httpx.Response(500, json={}), "HTTP 500"),
        (httpx.Response(200, text="not json"), "malformed"),
        (httpx.Response(200, json={"data": [{"embedding": [1.0]}]}), "1 vectors for 2 inputs"),
        (httpx.Response(200, json={"data": [{"embedding": [1.0]}, {"embedding": [1.0, 2.0]}]}), "mixes"),
        (httpx.Response(200, json={"data": [{"embedding": []}, {"embedding": []}]}), "empty vector"),
        (httpx.Response(200, json={"data": [{"embedding": [1.0, "nan"]}, {"embedding": [1.0, 2.0]}]}),
         "non-finite"),
    ],
)
def test_provider_rejects_invalid_responses(response, message):
    provider = _mock_provider(lambda request: response)
    with pytest.raises(EmbeddingError, match=message):
        provider.embed(["a", "b"])


def test_provider_enforces_configured_dimensions():
    provider = _mock_provider(
        lambda request: httpx.Response(200, json={"data": [{"embedding": [1.0, 2.0]}]}), dimensions=3
    )
    with pytest.raises(EmbeddingError, match="does not match configured 3"):
        provider.embed(["a"])


def test_config_requires_acknowledgment_for_remote_endpoint(tmp_path: Path):
    path = tmp_path / "cortex.yaml"
    path.write_text(
        "search:\n  semantic:\n    enabled: true\n    model: m\n"
        "    base_url: https://embeddings.example.com/v1\n"
    )
    with pytest.raises(ConfigError, match="allow_remote"):
        load_config(path)
    path.write_text(path.read_text() + "    allow_remote: true\n")
    assert load_config(path).search.semantic.allow_remote is True


def test_config_defaults_keep_semantic_off(tmp_path: Path):
    path = tmp_path / "cortex.yaml"
    path.write_text("{}\n")
    cfg = load_config(path).search
    assert cfg.default_mode == "auto" and cfg.semantic.enabled is False
    path.write_text("search:\n  default_mode: hybrid\n")
    with pytest.raises(ConfigError, match="requires search.semantic.enabled"):
        load_config(path)


# -- embedding index ------------------------------------------------------------


def test_sync_embeds_only_new_or_changed_chunks(vault: Path):
    index = make_index(vault)
    provider = FakeEmbeddings()
    first = index.sync_embeddings(provider, batch_size=2)
    assert first["error"] is None and first["embedded"] == 4
    assert all(len(call) <= 2 for call in provider.calls)

    provider.calls.clear()
    assert index.sync_embeddings(provider)["embedded"] == 0
    assert provider.calls == []

    (vault / "Public" / "bread.md").write_text("# Bread\n\nKnead the dough twice.\n")
    (vault / "Public" / "trip.md").unlink()
    outcome = index.sync_embeddings(provider)
    assert outcome == {"embedded": 1, "removed": 1, "pending": 0, "error": None}
    assert len(provider.embedded_texts) == 1 and "Knead" in provider.embedded_texts[0]
    stats = index.embedding_stats(provider.identity)
    assert stats["vector_count"] == 3 and stats["pending_chunks"] == 0 and stats["dimensions"] == 4


def test_failed_refresh_keeps_previous_vectors_and_records_error(vault: Path):
    index = make_index(vault)
    good = FakeEmbeddings()
    index.sync_embeddings(good)
    (vault / "Public" / "bread.md").write_text("# Bread\n\nChanged body.\n")

    outcome = index.sync_embeddings(FakeEmbeddings(fail=True))
    assert outcome["error"] == "endpoint down" and outcome["pending"] == 1
    stats = index.embedding_stats(good.identity)
    assert stats["vector_count"] == 4 and stats["pending_chunks"] == 1
    assert stats["last_error"] == "endpoint down"
    assert index.semantic_ready(good.identity)
    # Lexical search is unaffected.
    assert [hit.path for hit in index.search("Changed")] == ["Public/bread.md"]

    assert index.sync_embeddings(good)["error"] is None
    assert index.embedding_stats(good.identity)["last_error"] is None


def test_model_change_replaces_vectors_without_touching_fts(vault: Path):
    index = make_index(vault)
    index.sync_embeddings(FakeEmbeddings("v1"))
    chunks_before = index.stats()["chunk_count"]
    v2 = FakeEmbeddings("v2", width=6)
    assert index.sync_embeddings(v2)["embedded"] == 4
    assert not index.semantic_ready("fake:v1")
    assert index.semantic_ready(v2.identity)
    assert index.embedding_stats(v2.identity)["dimensions"] == 6
    assert index.stats()["chunk_count"] == chunks_before


def test_dimension_change_under_same_model_is_rejected(vault: Path):
    index = make_index(vault)
    index.sync_embeddings(FakeEmbeddings("same", width=4))
    (vault / "Public" / "bread.md").write_text("# Bread\n\nAnother body.\n")
    outcome = index.sync_embeddings(FakeEmbeddings("same", width=5))
    assert "dimensions changed" in outcome["error"]


def test_semantic_scope_is_applied_before_top_k(vault: Path):
    """The out-of-scope Private note is the closest vector, but it must not
    consume the single candidate slot of a Public-only caller."""
    index = make_index(vault)
    provider = FakeEmbeddings()
    index.sync_embeddings(provider)
    query = [1.0, 0.0, 0.0, 0.0]  # pure "privacy": Private/secret.md is nearest
    unscoped = index.semantic_search(query, model_id=provider.identity, allowed=lambda p: True, limit=1)
    assert unscoped[0][0].path == "Private/secret.md"
    scoped = index.semantic_search(
        query, model_id=provider.identity, allowed=lambda p: p.startswith("Public/"), limit=1
    )
    assert [hit.path for hit, _ in scoped] == ["Public/isolation.md"]


# -- fused recall -------------------------------------------------------------------


def _retrieval(provider, **kwargs) -> SemanticRetrieval:
    return SemanticRetrieval(provider=provider, **kwargs)


def test_hybrid_finds_paraphrase_that_lexical_misses(vault: Path):
    index = make_index(vault)
    store = VaultStore(vault)
    provider = FakeEmbeddings()
    index.sync_embeddings(provider)
    scopes = ["Public/**"]

    lexical = recall_hits(store, index, QUESTION, scopes, mode="lexical")
    assert "Public/isolation.md" not in [hit.path for hit in lexical]

    hybrid = recall_hits(store, index, QUESTION, scopes, mode="hybrid", semantic=_retrieval(provider))
    assert hybrid[0].path == "Public/isolation.md"
    assert hybrid[0].retrieval_mode == "hybrid"
    assert hybrid[0].semantic_rank == 1 and hybrid[0].lexical_rank is None
    assert hybrid[0].similarity == pytest.approx(1.0, abs=0.05)
    assert all(hit.path.startswith("Public/") for hit in hybrid)
    assert [hit.score for hit in hybrid] == sorted(hit.score for hit in hybrid)


def test_hybrid_keeps_exact_term_matches_on_top(vault: Path):
    index = make_index(vault)
    provider = FakeEmbeddings()
    index.sync_embeddings(provider)
    hits = recall_hits(VaultStore(vault), index, "itinerary passport", ["**"],
                       mode="hybrid", semantic=_retrieval(provider))
    assert hits[0].path == "Public/trip.md"
    assert hits[0].lexical_rank == 1 and hits[0].semantic_rank == 1


def test_auto_falls_back_and_hybrid_reports_unavailable(vault: Path):
    index = make_index(vault)
    store = VaultStore(vault)
    provider = FakeEmbeddings()
    # Configured but not yet embedded: auto silently uses lexical.
    auto = recall_hits(store, index, "bread", ["**"], mode="auto", semantic=_retrieval(provider))
    assert auto and {hit.retrieval_mode for hit in auto} == {"lexical"}
    with pytest.raises(SemanticUnavailable, match="cortex index --embeddings"):
        recall_hits(store, index, "bread", ["**"], mode="hybrid", semantic=_retrieval(provider))
    with pytest.raises(SemanticUnavailable):
        recall_hits(store, index, "bread", ["**"], mode="hybrid", semantic=None)

    index.sync_embeddings(provider)
    provider.fail = True  # query embedding outage
    auto = recall_hits(store, index, "bread", ["**"], mode="auto", semantic=_retrieval(provider))
    assert {hit.retrieval_mode for hit in auto} == {"lexical"}
    with pytest.raises(SemanticUnavailable, match="endpoint down"):
        recall_hits(store, index, "bread", ["**"], mode="hybrid", semantic=_retrieval(provider))
    with pytest.raises(ValueError, match="mode must be one of"):
        recall_hits(store, index, "bread", ["**"], mode="vector")


# -- MCP tools -----------------------------------------------------------------------


def make_server(vault: Path, provider: FakeEmbeddings | None) -> CortexServer:
    cfg = CortexConfig(
        vault=VaultConfig(),
        vaults=VaultsConfig(root=vault.parent, index_dir=vault.parent.parent / "indexes"),
        index=IndexConfig(enabled=True),
        search=SearchConfig(default_mode="auto"),
        principals=[Principal(name="p", scopes=["Public/**"])],
    )
    srv = CortexServer(cfg, principal=cfg.principal("p"))
    if provider is not None:
        srv.semantic = _retrieval(provider)
        srv.index.sync_embeddings(provider)
    return srv


def call(srv: CortexServer, tool: str, **args):
    result = asyncio.run(srv.mcp.call_tool(tool, args))
    if isinstance(result, tuple) and result[1] is not None:
        payload = result[1]
        return payload["result"] if set(payload) == {"result"} else payload
    blocks = result[0] if isinstance(result, tuple) else result
    text = blocks[0].text
    try:
        payload = json.loads(text)
    except ValueError:
        return text
    return payload["result"] if isinstance(payload, dict) and set(payload) == {"result"} else payload


def test_search_tool_reports_mode_and_provenance(vault: Path):
    srv = make_server(vault, FakeEmbeddings())
    hits = call(srv, "search", query=QUESTION)
    assert hits[0]["path"] == "Public/isolation.md"
    assert hits[0]["retrieval_mode"] == "hybrid"
    assert {"lexical_rank", "semantic_rank", "similarity"} <= set(hits[0])
    assert all(hit["path"].startswith("Public/") for hit in hits)

    lexical = call(srv, "search", query="bread", mode="lexical")
    assert lexical[0]["retrieval_mode"] == "lexical" and "semantic_rank" not in lexical[0]

    pack = call(srv, "context_pack", query=QUESTION)
    assert "Public/isolation.md" in pack and "Private/secret.md" not in pack

    status = call(srv, "status")
    assert status["semantic"]["ready"] is True
    assert status["semantic"]["model"] == "fake:fake-v1"


def test_search_tool_without_semantic_is_unchanged(vault: Path):
    srv = make_server(vault, None)
    hits = call(srv, "search", query="bread")
    assert hits[0]["retrieval_mode"] == "lexical"
    assert "semantic" not in call(srv, "status")
    with pytest.raises(Exception, match="hybrid search is unavailable"):
        call(srv, "search", query="bread", mode="hybrid")


def test_semantic_search_synthesis_sees_only_scoped_hybrid_context(vault: Path):
    srv = make_server(vault, FakeEmbeddings())
    prompts = []

    class Recorder:
        def complete(self, *, system, prompt, max_tokens):
            prompts.append(prompt)
            from cortex.llm.base import LLMResult

            return LLMResult(text="answer", model="recorder")

    srv.provider = Recorder()
    out = call(srv, "semantic_search", question=QUESTION)
    assert "Public/isolation.md" in out
    assert "Principal-scoped isolation" in prompts[0]
    assert "Private/secret.md" not in prompts[0] and "Confidential privacy" not in prompts[0]


# -- loopback OpenAI-compatible endpoint + CLI ------------------------------------------


class _EmbeddingHandler(BaseHTTPRequestHandler):
    fake = FakeEmbeddings()

    def do_POST(self):  # noqa: N802 - http.server API
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        vectors = self.fake.embed(body["input"])
        payload = json.dumps({"data": [{"index": i, "embedding": v} for i, v in enumerate(vectors)]})
        self.send_response(200 if self.path == "/v1/embeddings" else 404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode())

    def log_message(self, *args):  # silence test output
        pass


@pytest.fixture
def embedding_endpoint():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EmbeddingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    server.shutdown()


def test_cli_check_index_and_sync_with_loopback_endpoint(vault: Path, embedding_endpoint, capsys):
    from cortex.cli import main

    root = vault.parent.parent
    config = root / "cortex.yaml"
    config.write_text(
        f"""
vault: {{ git: {{ enabled: false }} }}
vaults: {{ root: {vault.parent}, index_dir: {root / 'indexes'} }}
principals: [{{ name: p, scopes: ["Public/**"] }}]
auth: {{ local_principal: p }}
search:
  semantic: {{ enabled: true, model: fake-v1, base_url: "{embedding_endpoint}", batch_size: 3 }}
"""
    )
    assert main(["-c", str(config), "check"]) == 0
    assert "semantic search: openai-compatible:fake-v1 at loopback" in capsys.readouterr().out

    assert main(["-c", str(config), "index", "--embeddings"]) == 0
    assert "embeddings:   4 vectors (4 new/changed, 0 removed)" in capsys.readouterr().out

    (vault / "Public" / "bread.md").write_text("# Bread\n\nRye dough.\n")
    assert main(["-c", str(config), "sync"]) == 0
    assert "embeddings: 1 new/changed, 0 removed" in capsys.readouterr().out

    cfg = load_config(config)
    assert cfg.search.semantic == SemanticSearchConfig(
        enabled=True, model="fake-v1", base_url=embedding_endpoint, batch_size=3
    )


def test_cli_index_embeddings_requires_config(vault: Path, capsys):
    from cortex.cli import main

    config = vault.parent.parent / "cortex.yaml"
    config.write_text(f"vaults: {{ root: {vault.parent} }}\n")
    assert main(["-c", str(config), "index", "--embeddings"]) == 2
    assert "search.semantic.enabled: false" in capsys.readouterr().err
