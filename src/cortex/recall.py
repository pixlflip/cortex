"""Lifecycle-aware retrieval shared by MCP and REST.

Authorization is applied before reading lifecycle metadata or limiting results.
Ranking is lexical (FTS5/BM25) by default, or hybrid when a local embedding
index is configured and healthy: lexical and semantic ranks are fused with
weighted reciprocal-rank fusion (docs/local-semantic-search.md). No chat model
is ever called here. Per-request metadata reads are cached.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .embeddings import EmbeddingError, EmbeddingProvider, build_embedding_provider
from .memory_lifecycle import inspect_memory_bytes, parse_memory_bytes
from .scopes import path_allowed
from .vault import VaultError

if TYPE_CHECKING:
    from .config import SearchConfig

logger = logging.getLogger(__name__)

MODES = ("auto", "lexical", "hybrid")
_UNBOUNDED = 2**31 - 1


class SemanticUnavailable(ValueError):
    """``mode="hybrid"`` was requested but no healthy semantic index exists."""


@dataclass
class RecallHit:
    path: str
    line: int
    snippet: str
    score: float = 0.0
    headings: str = ''
    body: str = ''
    memory_state: str = 'unreviewed'
    warnings: list[str] | None = None
    state_changed_at: str | None = None
    # Retrieval provenance. ``score`` stays "lower is better" in every mode:
    # BM25 for lexical, the negated fused RRF score for hybrid.
    retrieval_mode: str = 'lexical'
    lexical_rank: int | None = None
    semantic_rank: int | None = None
    similarity: float | None = None


@dataclass
class SemanticRetrieval:
    """Everything hybrid ranking needs besides the index itself."""

    provider: EmbeddingProvider
    rrf_k: int = 60
    lexical_weight: float = 1.0
    semantic_weight: float = 1.0
    max_candidates: int = 200

    @classmethod
    def from_config(cls, cfg: SearchConfig) -> SemanticRetrieval | None:
        provider = build_embedding_provider(cfg.semantic)
        if provider is None:
            return None
        sem = cfg.semantic
        return cls(
            provider=provider,
            rrf_k=sem.rrf_k,
            lexical_weight=sem.lexical_weight,
            semantic_weight=sem.semantic_weight,
            max_candidates=sem.max_candidates,
        )


def resolve_mode(requested: str | None, default: str) -> str:
    mode = requested or default
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}")
    return mode


def _ranked(store: Any, index: Any, query: str, scopes: Any, *, mode: str,
            semantic: SemanticRetrieval | None) -> list[tuple[Any, dict[str, Any]]]:
    """Scope-filtered candidates with provenance, best first."""
    index.ensure_fresh()
    lexical = [hit for hit in index.search(query, limit=_UNBOUNDED) if path_allowed(hit.path, scopes)]
    lexical_only = [(hit, {"retrieval_mode": "lexical", "lexical_rank": rank})
                    for rank, hit in enumerate(lexical, start=1)]
    if mode == "lexical":
        return lexical_only

    model_id = semantic.provider.identity if semantic is not None else None
    ready = semantic is not None and model_id is not None and index.semantic_ready(model_id)
    if not ready:
        if mode == "hybrid":
            raise SemanticUnavailable(
                "hybrid search is unavailable: semantic search is not configured or the "
                "embedding index has not been built (run `cortex index --embeddings`)"
            )
        return lexical_only
    assert semantic is not None and model_id is not None
    try:
        query_vector = semantic.provider.embed([query])[0]
    except (EmbeddingError, IndexError) as exc:
        if mode == "hybrid":
            raise SemanticUnavailable(f"hybrid search is unavailable: {exc}") from exc
        logger.warning("query embedding failed; using lexical search: %s", exc)
        return lexical_only

    semantic_hits = index.semantic_search(
        query_vector,
        model_id=model_id,
        allowed=lambda path: path_allowed(path, scopes),
        limit=semantic.max_candidates,
    )
    fused: dict[tuple[str, int], dict[str, Any]] = {}
    for rank, hit in enumerate(lexical, start=1):
        entry = fused.setdefault((hit.path, hit.line), {"hit": hit, "score": 0.0})
        entry["lexical_rank"] = rank
        entry["score"] += semantic.lexical_weight / (semantic.rrf_k + rank)
    for rank, (hit, similarity) in enumerate(semantic_hits, start=1):
        entry = fused.setdefault((hit.path, hit.line), {"hit": hit, "score": 0.0})
        entry["semantic_rank"] = rank
        entry["similarity"] = similarity
        entry["score"] += semantic.semantic_weight / (semantic.rrf_k + rank)
    ordered = sorted(
        fused.values(),
        key=lambda e: (-e["score"], e.get("lexical_rank") or _UNBOUNDED, e["hit"].path, e["hit"].line),
    )
    out = []
    for entry in ordered:
        out.append((entry["hit"], {
            "retrieval_mode": "hybrid",
            "score": -entry["score"],
            "lexical_rank": entry.get("lexical_rank"),
            "semantic_rank": entry.get("semantic_rank"),
            "similarity": entry.get("similarity"),
        }))
    return out


def recall_hits(store, index, query, scopes, *, include_historical=False, regex=False,
                mode: str = "lexical", semantic: SemanticRetrieval | None = None):
    candidates: list[tuple[Any, dict[str, Any]]]
    if regex:
        candidates = [(hit, {"retrieval_mode": "regex"})
                      for hit in store.search(query, regex=True, limit=_UNBOUNDED)
                      if path_allowed(hit.path, scopes)]
    else:
        candidates = _ranked(store, index, query, scopes, mode=resolve_mode(mode, "lexical"),
                             semantic=semantic)
    metadata = {}
    output = []
    for hit, provenance in candidates:
        if not path_allowed(hit.path, scopes):
            continue
        if hit.path not in metadata:
            try:
                raw = store._resolve(hit.path).read_bytes()
                memory = inspect_memory_bytes(raw)
                try:
                    fm, _ = parse_memory_bytes(raw)
                except ValueError:
                    fm = {}
                changed = fm.get('memory_state_changed_at')
                memory['changed_at'] = str(changed)[:64] if changed else None
                metadata[hit.path] = memory
            except (VaultError, OSError):
                continue
        memory = metadata[hit.path]
        if memory['state'] == 'superseded' and not include_historical:
            continue
        output.append(RecallHit(path=hit.path, line=hit.line, snippet=hit.snippet,
            score=provenance.get('score', getattr(hit, 'score', 0.0)),
            headings=getattr(hit, 'headings', ''),
            body=getattr(hit, 'body', hit.snippet), memory_state=memory['state'],
            warnings=memory['warnings'], state_changed_at=memory['changed_at'],
            retrieval_mode=provenance['retrieval_mode'],
            lexical_rank=provenance.get('lexical_rank'),
            semantic_rank=provenance.get('semantic_rank'),
            similarity=provenance.get('similarity')))
    # Stable order keeps relevance ordering within lifecycle groups.
    output.sort(key=lambda hit: hit.memory_state != 'current')
    return output
