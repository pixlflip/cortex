"""Lifecycle-aware retrieval shared by MCP and REST.

Authorization is applied before reading lifecycle metadata or limiting results.
This first implementation materializes matching index candidates; the index is
still keyword-ranked and no LLM is called. Per-request metadata reads are cached.
"""
from dataclasses import dataclass
from .memory_lifecycle import inspect_memory_bytes, parse_memory_bytes
from .scopes import path_allowed
from .vault import VaultError

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


def recall_hits(store, index, query, scopes, *, include_historical=False, regex=False):
    if regex:
        hits = store.search(query, regex=True, limit=2**31-1)
    else:
        index.ensure_fresh()
        hits = index.search(query, limit=2**31-1)
    metadata = {}
    output = []
    for hit in hits:
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
            score=getattr(hit,'score',0.0), headings=getattr(hit,'headings',''),
            body=getattr(hit,'body',hit.snippet), memory_state=memory['state'],
            warnings=memory['warnings'], state_changed_at=memory['changed_at']))
    # Stable order keeps BM25 ordering within lifecycle groups.
    output.sort(key=lambda hit: hit.memory_state != 'current')
    return output
