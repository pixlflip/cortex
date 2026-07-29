# Local semantic search design

## Decision

Cortex should add **hybrid retrieval**: keep SQLite FTS5/BM25 for exact terms and add an optional, on-machine embedding index for concept similarity. Fuse the two ranked lists with reciprocal-rank fusion (RRF), then preserve the current optional LLM synthesis step.

The initial backend should use an OpenAI-compatible embeddings endpoint on loopback, with Ollama as the documented local example. Embeddings stay in the existing per-vault SQLite index as `float32` blobs. Do not add a vector database in the first release: Cortex's normal vault size is small enough for a scoped linear cosine scan, and avoiding another daemon or native SQLite extension keeps deployment and rollback simple.

This separates three concerns that the current `semantic_search` name conflates:

1. **Lexical retrieval**: existing FTS5/BM25.
2. **Semantic retrieval**: local embeddings, deterministic and model-spend-free after indexing.
3. **Synthesis**: the existing optional chat model, which may also run through local Ollama.

## Current behavior and failure mode

`semantic_search` currently calls `_gather_context`, which retrieves only through FTS5/BM25, and then asks the configured chat provider to summarize the selected chunks. The synthesis can understand concepts, but the retriever must first find the relevant chunks lexically. A question such as "what keeps family data private?" can miss a note that only says "principal-scoped isolation" because the important vocabulary does not overlap.

Configuring `llm.provider: ollama` makes synthesis local, but does not make retrieval semantic.

## Goals

- Find relevant chunks when query and note vocabulary differ.
- Keep note content and embeddings on the Cortex host by default.
- Preserve principal and per-vault scoping as hard server-side boundaries.
- Keep FTS5 working when embeddings are disabled, stale, or unavailable.
- Avoid a large PyTorch dependency and avoid requiring a separate vector database.
- Incrementally embed only changed chunks.
- Make retrieval quality measurable before changing defaults.

## Non-goals for the first slice

- Approximate-nearest-neighbor indexing.
- GPU requirements.
- Replacing FTS5.
- Automatically downloading or selecting a model without operator consent.
- Sending vault content to a hosted embedding API by default.
- Using an LLM to decide authorization or scope.

## Proposed configuration

```yaml
search:
  enabled: true
  mode: hybrid                 # lexical | hybrid
  semantic:
    enabled: true
    provider: openai-compatible
    base_url: http://127.0.0.1:11434/v1
    model: nomic-embed-text     # example only; operator chooses the installed model
    api_key_env: null           # loopback Ollama does not need a real key
    dimensions: 768             # validate against the first response
    timeout_seconds: 30
    batch_size: 32
    rrf_k: 60
    lexical_weight: 1.0
    semantic_weight: 1.0
    max_candidates: 200
```

Rules:

- `semantic.enabled` defaults to `false`.
- Non-loopback `base_url` requires an explicit `allow_remote: true` acknowledgment because indexing sends note chunks to that endpoint.
- Store the actual model identifier and vector dimensions with every embedding. A model or dimension change invalidates only the embedding table, not FTS5.
- The configured dimensions are optional; if set, reject a mismatched provider response instead of silently storing corrupt rows.

## Provider contract

Add a small provider interface independent from `LLMProvider`:

```python
class EmbeddingProvider(Protocol):
    @property
    def identity(self) -> str: ...

    def embed(self, texts: list[str]) -> list[list[float]]: ...
```

The first implementation calls `POST {base_url}/embeddings` using the OpenAI-compatible shape. This covers a loopback Ollama deployment without importing PyTorch, ONNX Runtime, or a model framework into Cortex itself. A future in-process provider can be an optional extra if measurements justify the added package and model lifecycle.

Provider validation at startup or `cortex check` must verify:

- URL policy (loopback by default).
- Model is non-empty.
- Response count equals input count.
- Every vector has the same non-zero dimension.
- Every value is finite.
- Timeout and response body limits are enforced.

## Storage design

FTS5 virtual tables should remain unchanged. Add a normal table to the same per-vault index database:

```sql
CREATE TABLE chunk_embeddings (
    path          TEXT NOT NULL,
    start_line    INTEGER NOT NULL,
    content_hash  TEXT NOT NULL,
    model_id      TEXT NOT NULL,
    dimensions    INTEGER NOT NULL,
    vector        BLOB NOT NULL,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (path, start_line, model_id)
);
CREATE INDEX chunk_embeddings_model ON chunk_embeddings(model_id);
```

The blob contains normalized little-endian `float32` values. Normalizing once at index time makes cosine similarity a dot product at query time. `content_hash` should cover the exact text sent to the embedding provider, including title/headings if those are included.

Do not key embeddings to the FTS5 `rowid`; changed notes are deleted and reinserted, so row IDs are not stable.

### Embedding text

Embed the same chunk boundaries Cortex already uses, prefixed with concise structural context:

```text
Title: <title>
Headings: <heading chain>
Tags: <tags>

<chunk body>
```

Path may be useful for ranking but can add noisy folder vocabulary. Measure it before including it in the embedded text.

## Incremental indexing

Extend index synchronization in a bounded second phase:

1. FTS indexing determines changed and removed paths as it does now.
2. Remove embedding rows for removed paths.
3. For changed paths, chunk the note, compute content hashes, and reuse matching rows for the active model.
4. Batch only missing/changed chunks through the embedding provider.
5. Write a batch transaction after all vectors validate.
6. Record `embedding_model`, `embedding_dimensions`, `last_embedded`, pending count, and last error in `meta`.

Embedding refresh should run from `cortex index` / the sync timer, not block ordinary read queries. Queries may use the last complete embedding snapshot and should report staleness through `status`.

If embedding a batch fails, retain the prior complete rows for unchanged chunks, record the error, and continue serving lexical search. Never delete a healthy semantic index before replacement vectors validate.

## Retrieval pipeline

For a query and principal:

1. Canonicalize the selected vault and resolve the principal exactly as current tools do.
2. Obtain lexical candidates from FTS5.
3. If a healthy embedding index is available, embed the query locally and score only rows whose paths pass `path_allowed` for the effective principal.
4. Keep the top semantic candidates with a bounded min-heap.
5. Deduplicate by `(path, start_line)`.
6. Fuse lexical and semantic ranks with weighted RRF:

   `score = lexical_weight / (rrf_k + lexical_rank) + semantic_weight / (rrf_k + semantic_rank)`

7. Deduplicate to the best chunks/notes required by the caller and apply the existing context budget.
8. Return deterministic retrieval results. Only `semantic_search` proceeds to optional LLM synthesis.

Authorization is applied before a candidate can enter the semantic ranked list or response. Do not rely on filtering only after a global top-k: a narrowly scoped principal could otherwise receive poor results because out-of-scope chunks consumed the candidate window.

## Tool/API shape

Avoid a second confusing tool. Extend deterministic search while preserving compatibility:

```text
search(query, limit=20, regex=false, mode="auto", vault=null)
```

- `regex=true`: existing literal/regex path; `mode` ignored.
- `mode="lexical"`: current FTS5 behavior.
- `mode="hybrid"`: require semantic index; return a clear disabled/stale notice if unavailable.
- `mode="auto"`: use hybrid when healthy, otherwise lexical.

Each result should include:

- path, heading, start line, snippet;
- fused score;
- lexical rank/score when present;
- semantic rank/similarity when present;
- retrieval mode actually used.

`context_pack` should default to `auto`. `semantic_search` should use the same hybrid retrieval and then call the configured synthesis provider. This allows a fully local path when both embedding and LLM providers point to loopback Ollama.

## Privacy and governance

- Embedding vectors are derived vault data and inherit the vault's sensitivity. Keep the SQLite index in the existing protected per-vault data path and include it in backup/restore policy.
- Principal scoping remains path-based and server-enforced. Vectors do not create a cross-vault global index.
- Query text is sensitive. In local mode it goes only to loopback. Remote embedding mode must be explicit and documented in status output.
- Logs and audit rows record provider/model, mode, latency, and result count, not query text, note text, or vectors.
- A model change triggers re-embedding; it must not mutate vault files or git history.

## Resource envelope

The first implementation targets CPU-only Cortex hosts. A 384-dimensional normalized vector uses 1,536 bytes before SQLite overhead; a 768-dimensional vector uses 3,072 bytes. Even 10,000 chunks remain small enough for a linear scan and avoid the operational cost of an ANN service. Measure real vault chunk counts before choosing a hard crossover.

If p95 query latency exceeds the acceptance target at supported vault sizes, the next optimization is an optional `sqlite-vec` backend behind the same provider/index interface. Do not make a native extension the baseline until packaging is proven across Docker and bare metal.

## Rollout plan

### Phase 0: evaluation corpus

Create 30–50 query judgments from the real vault without committing private note text to the public repository. Include:

- exact-name and acronym queries where BM25 should win;
- paraphrases and conceptual queries where embeddings should win;
- mixed queries;
- no-answer queries;
- narrowly scoped principal cases.

Store only a reusable public synthetic corpus in tests. Keep Jack's private relevance judgments outside the repo.

### Phase 1: provider and index, disabled by default

- Add config validation and the embedding provider.
- Add the embedding table and `cortex index --embeddings`.
- Add status/health fields and failure fallback.
- Add unit tests with a deterministic fake provider; network is never used in tests.

### Phase 2: hybrid deterministic search

- Add scoped cosine ranking and weighted RRF.
- Extend `search` and `context_pack` with retrieval mode and provenance.
- Preserve regex and lexical response compatibility.

### Phase 3: local synthesis path

- Route `semantic_search` through hybrid retrieval.
- Document a loopback Ollama embedding model plus a small local chat model.
- Keep synthesis optional; hybrid retrieval remains useful without a chat model.

### Phase 4: optimize only from evidence

- Benchmark larger synthetic vaults and the real vault.
- Add sqlite-vec only if the linear scan misses latency targets.
- Tune RRF weights against the judgment set rather than intuition.

## Acceptance criteria

Correctness and safety:

- Out-of-scope chunks are never returned, included in synthesis prompts, or allowed to consume a scoped semantic top-k.
- Cross-vault embeddings are stored and queried separately.
- Editing one note re-embeds only its changed chunks.
- Model changes invalidate semantic rows without rebuilding or damaging FTS5.
- Embedding outages leave lexical search available and produce an observable status error.
- Remote endpoints are rejected unless explicitly acknowledged.

Quality:

- Hybrid recall@5 is no worse than lexical recall@5 on exact-term queries.
- Hybrid recall@5 improves by at least 20 percentage points on the paraphrase subset before becoming the default.
- No-answer queries do not become fabricated answers; synthesis still states when the retrieved notes are insufficient.

Performance on the 2-core / 4 GiB target Cortex host:

- Query embedding plus ranking p95 under 500 ms after model warm-up for the current vault.
- Incremental re-index of one typical note under 2 seconds after model warm-up.
- Peak Cortex process RSS increase under 150 MiB when the model runs out-of-process.
- The local model service and Cortex together remain within the host's memory budget with documented headroom.

Operations:

- `cortex check` verifies the embedding endpoint and reports model/dimensions without exposing note content.
- `status` reports lexical and semantic freshness separately.
- Docker and bare-metal docs include model setup, re-index, rollback, and disk usage.

## Rejected alternatives

### Replace FTS5 with vectors

Rejected. Exact identifiers, paths, names, and error strings are core Cortex queries. BM25 is cheaper and often better for them.

### Use the synthesis LLM to generate alternate search keywords

Rejected as the primary fix. It adds latency and model dependence to every query, still may miss vocabulary, and blurs deterministic retrieval with generation.

### Add sentence-transformers/PyTorch to the Cortex process

Rejected for the baseline. It substantially increases image size, memory pressure, and dependency risk on a 4 GiB host. It can remain an optional future provider.

### Require a standalone vector database

Rejected at Cortex's current scale. It adds another service, credentials, backup surface, and authorization integration without evidence that SQLite plus a linear scan is insufficient.

### Make sqlite-vec mandatory immediately

Deferred. It is a good optimization candidate, but native-extension packaging and platform coverage should not block the first local semantic implementation.
