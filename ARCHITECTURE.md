# Cortex Architecture

> Every mind needs a memory that is dynamic, not stationary.

Cortex is a headless, governed memory service for AI agents. Each account owns
an ordinary Obsidian-compatible Markdown vault on disk; humans edit it with any
editor, and AI clients reach it only through Cortex's memory MCP server (plus
an authenticated JSON API and the CLI). Every change is a git commit, every
read is scoped, and nothing outside a caller's grant is visible.

This document describes Cortex as it is now (0.3.x). The original v1 design and
the retired v2 UI/gateway design are kept in [`docs/archive/`](docs/archive/).

---

## 1. Front doors

| Surface | Transport | Who uses it | Module |
| --- | --- | --- | --- |
| Memory MCP | stdio (local) or Streamable HTTP | AI clients | `server`, `mcp_tools/` |
| JSON API `/api/v1` | HTTP, same app as MCP | scripts, admins | `api`, `api_routes/` |
| OAuth 2.1 consent | HTTP (optional) | one-click MCP connectors | `oauth` |
| Readiness `/healthz` | HTTP | orchestrators | `health` |
| CLI `cortex …` | local process | operators | `cli` |

There is no web UI, vault viewer, or upstream MCP proxy. `/` and former UI
paths return 404. The MCP server exposes only Cortex's own memory tools.

## 2. Request path

```
 MCP client ──stdio──┐                 ┌── JSON API client (session cookie or bearer)
                     │                 │
 MCP client ─HTTP────┤                 │
  bearer / OAuth     ▼                 ▼
            ┌───────────────────────────────────────────┐
            │ Authentication                            │  auth, oauth, sessions, users
            │   token / session → principal             │
            ├───────────────────────────────────────────┤
            │ Tool policy (MCP only)                    │  memory_policy
            │   deny-wins rules per user/group;         │
            │   hides tools from tools/list, refuses    │
            │   calls, records value-free audit rows    │
            ├───────────────────────────────────────────┤
            │ Vault selection                           │  access, vaults, db.vault_grants
            │   own account by default; admin or        │
            │   explicit grant for another account      │
            ├───────────────────────────────────────────┤
            │ Path scope                                │  scopes
            │   canonical path ∈ read/write globs,      │
            │   intersected with token narrowing        │
            ├───────────────────────────────────────────┤
            │ Retrieval / mutation                      │  vault, search_index, recall,
            │   files · FTS5 · embeddings · git         │  embeddings, note_writes, gitlog
            └───────────────────────────────────────────┘
```

The four guards are independent and all must pass. A failure at vault selection
or path scope is reported exactly like a missing resource ("not found or not in
scope"), so callers cannot probe for what exists outside their grant.

## 3. Identity and authorization

- **Principals.** A request runs as one principal. Over stdio it is the
  configured `auth.local_principal`. Over HTTP it comes from a bearer token:
  config principals (`token_env`), database user API tokens (`user:` subjects),
  legacy admin-store clients, or an OAuth access token bound server-side to one
  of those.
- **Accounts and vaults.** Database users (local or LDAP) each own one vault at
  `vaults.root/<username>` with its own git repository and index. There is no
  global vault and no fallback: a missing account vault fails closed. See
  [account vaults](docs/account-vaults.md).
- **Cross-account access** happens only through an administrator acting
  explicitly, or an explicit `vault_grants` row with separate read and write
  globs. Grants are re-read on every call.
- **Token narrowing.** A user token may carry scopes; they intersect every
  grant and can only reduce access.
- **Tool policy.** `memory_policy.ToolGovernor` wraps the MCP server. Rules are
  globs over `cortex.<tool>` for users and groups; any matching deny wins, then
  any allow, then the configured read/write defaults. Unknown tool IDs fail
  closed. See [memory policy](docs/memory-policy.md).
- **Writes switch.** With `writes.enabled: false` (the default) mutating tools
  are never registered, whatever the policy says.

Authorization-critical modules (`access`, `scopes`, `memory_policy`,
`db.vault_grants`) are type-checked strictly and held to a 95% coverage floor
in CI.

## 4. Storage

```
data/
├── cortex.sqlite            identity, tokens, sessions, tool policy + audit,
│                            vault grants, janitor reports, settings
├── vaults/<account>/        Obsidian vault = git working tree (source of truth)
├── indexes/<account>.index.sqlite  rebuildable FTS5 index + embeddings
└── archive/                 archived account vaults (history preserved)
```

- **Vault files** are the only durable memory. Notes are Markdown with optional
  YAML frontmatter; binary attachments are supported through the file tools.
  Hidden paths and symlinks are rejected.
- **Git** is the single audit trail and rollback mechanism. Each MCP mutation is
  one commit whose message records actor and reason; `cortex sync` snapshots
  human edits the same way.
- **The SQLite identity database** holds no note content. Its schema is
  migrated forward by `cortex migrate` / `cortex init`; historical tables from
  the retired gateway are kept inert rather than dropped.
- **Indexes** are caches: delete them and `cortex index` rebuilds them.

## 5. Retrieval

All retrieval is scope-filtered before ranking limits apply, so a narrowly
scoped caller never loses results to out-of-scope matches.

- **Lexical:** SQLite FTS5 with BM25 over heading-aware chunks (`search_index`).
  Falls back to substring search if FTS5 is unavailable.
- **Semantic (optional, off by default):** an OpenAI-compatible embedding
  endpoint, loopback-only unless `allow_remote` is set, with normalized
  float32 vectors stored beside FTS5 and refreshed incrementally by
  `cortex index --embeddings` / `cortex sync` (`embeddings`).
- **Hybrid:** `recall` fuses lexical and semantic ranks with weighted
  reciprocal-rank fusion. `mode=auto` uses hybrid when the vector index is
  healthy and lexical otherwise; results report their provenance.
- **Lifecycle:** `memory_state` frontmatter (`current`, `superseded`, …) orders
  results and hides superseded notes unless history is requested. See
  [memory lifecycle](docs/memory-lifecycle.md).
- **Synthesis:** `semantic_search` is the only tool that calls a chat model
  (`llm`: OpenRouter, OpenAI-compatible, Anthropic, Ollama, or `none`). The
  model only sees chunks the caller could have read directly.

Details: [local semantic search](docs/local-semantic-search.md).

## 6. MCP tools

Read tools (always registered, governed by policy):
`discover_scopes`, `status`, `list_notes`, `list_files`, `get_file`, `search`,
`read_note`, `read_frontmatter`, `read_section`, `context_pack`,
`semantic_search`.

Write tools (registered only with `writes.enabled: true`; each needs a
`reason`, is write-scope checked and produces one git commit):
`write_note`, `patch_note`, `append_note`, `update_frontmatter`,
`set_memory_state`, `supersede_note`, `delete_note`, `move_note`, `put_file`.

Code layout: `mcp_tools/read_tools.py` and `mcp_tools/write_tools.py` register
thin wrappers; the mutation logic lives in `note_writes.NoteWriteMixin` so it
is unit-testable without MCP plumbing.

## 7. Background work

- **Sync** (`cortex sync`, typically a systemd timer): commit pending human
  edits, refresh the index (and embeddings when enabled), then optionally
  pull/push a git remote (`sync.adapter: git`). `nextcloud` and `s3` are
  reserved adapter names and currently only snapshot locally.
- **Janitor** (`janitor.enabled`, off by default): a bounded, report-only pass
  over eligible notes that writes findings to the database and never edits the
  vault. It cannot change scopes, principals, credentials or its own limits.
  See [memory janitor](docs/memory-janitor.md).

## 8. Safety invariants

1. Every guard is enforced server-side; clients are never trusted.
2. Out-of-scope resources are invisible, not merely unreadable.
3. Credentials map to exactly one principal; HTTP requires one.
4. Writes are opt-in globally and per user; every write is a revertible commit.
5. Only `semantic_search` spends chat-model tokens, and only on visible notes.
6. Embedding endpoints are loopback unless explicitly acknowledged.
7. Secrets come from the environment, never the repository or image.

These are exercised end to end by `tests/test_e2e_mcp.py`, which runs the real
`cortex serve` process over stdio and HTTP.

## 9. Source map

| Area | Modules |
| --- | --- |
| Entry points | `cli`, `server`, `api`, `health` |
| MCP tools | `mcp_tools/`, `note_writes` |
| JSON API handlers | `api_routes/` (`_base`, `identity`, `vaults`, `policy`) |
| Identity | `auth`, `oauth`, `sessions`, `users`, `ldap`, `pwhash`, `admin` |
| Authorization | `access`, `scopes`, `memory_policy`, `db/vault_grants` |
| Storage | `vault`, `vaults`, `gitlog`, `db/` |
| Retrieval | `search_index`, `embeddings`, `recall`, `memory_lifecycle` |
| Models | `llm/` |
| Maintenance | `janitor/`, `sync/` |
