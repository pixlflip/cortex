# Cortex

> Every mind needs a memory that is dynamic, not stationary.

Cortex is a **dynamic, governed memory layer for AI agents, assistants, and
chatbots**, backed by a real **Obsidian vault**. Humans keep using ordinary
Obsidian-compatible Markdown files; AI clients access that same memory only
through a secure [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) server:

- **Obsidian-native** — the source of truth is a normal Obsidian vault: Markdown
  notes, YAML frontmatter, folders, links, and your editor of choice.
- **Account-owned** — every vault belongs to a named account. There is no global
  vault. Requests default to the authenticated account, including administrators;
  cross-account administration requires explicit selection.
- **Scoped** — each token sees only its allowed vaults, note paths, and MCP
  tools. Out-of-scope resources are *invisible*, not just unreadable.
- **Audited** — every change is a git commit tagged with *actor* and *reason*.
  Git is the single audit trail and rollback mechanism.
- **Deterministic by default** — search, reads, and context packs spend zero
  model tokens. Only the one `semantic_search` tool calls an LLM.
- **Dedicated memory MCP** — only Cortex memory tools, filtered by the token
  owner's always-on deny-wins policy. No upstream registry or proxy.
- **Self-improving (bounded)** — an optional, report-first janitor tidies and
  watches the vault on a heartbeat, never able to edit its own limits.

Anyone can spin one up — locally, in Docker, or on a homelab — and keep their
memory *theirs*: a fully working Obsidian vault for humans, a governed memory
API for agents.

**Upgrading from 0.2.x?** 0.3.0 is a breaking release: legacy `vault.path` is
no longer served, and the web UI and upstream MCP broker are gone. Follow
[upgrading to 0.3.0](docs/upgrading.md). No automatic merging or deletion is
performed.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for how Cortex is put together.

---

## Quick start

### Docker (recommended)

```bash
git clone https://github.com/pixlflip/cortex.git && cd cortex
cp cortex.example.yaml cortex.yaml          # edit to taste
# import existing notes into the owning account under ./data/vaults/<username>
docker compose run --rm cortex check        # validate setup
docker compose run --rm cortex init         # DB + admin + git baselines
docker compose up -d                        # headless API + MCP on :8765
```

To skip the local build, use the published image:
`CORTEX_IMAGE=ghcr.io/pixlflip/cortex:latest docker compose up -d`. For a local
stdio MCP client, have it launch
`docker compose --profile stdio run --rm -T cortex-stdio`.

Run `cortex sync` any time (or on a schedule — see
[`docs/bare-metal.md`](docs/bare-metal.md)) to snapshot pending human edits
into the git audit trail and refresh the search index, so the `status` tool's
freshness numbers stay current.

### Bare metal (Debian / Proxmox / laptop)

```bash
git clone https://github.com/pixlflip/cortex.git && cd cortex
python3 -m venv .venv && . .venv/bin/activate
pip install .
cp cortex.example.yaml cortex.yaml          # edit to taste
cortex check
cortex init
cortex serve                                # stdio or HTTP, per cortex.yaml
```

Full host/service setup (service user, systemd) is in
[`docs/bare-metal.md`](docs/bare-metal.md).

Cortex is headless: there is no web app, vault viewer, or admin dashboard.
Manage accounts and tokens with the CLI or authenticated JSON API. Readiness is
available at `/healthz`; `/` and former UI paths return 404. OAuth consent is
retained only for MCP client authorization.

### Connect an AI once

Create a per-user token with `cortex token mint <username> <client-name>`,
then configure the AI client with Cortex as its memory MCP endpoint:

```json
{
  "mcpServers": {
    "cortex": {
      "url": "https://cortex.example.com/mcp",
      "headers": { "Authorization": "Bearer ctx_…" }
    }
  }
}
```

Tool discovery is identity-specific and memory-only. Authorization is checked
again at call time, including when an old config sets `gateway.enabled: false`.
Upstream tools, `search_mcps`/`peek_mcp`/`load_mcp`, and `/api/v1/mcp/*` broker
routes have been removed. This is an intentional breaking change, not a switch.
See [memory policy and broker retirement](docs/memory-policy.md) before cutover.

For local stdio clients, register Cortex as a server that runs `cortex serve`
with `CORTEX_CONFIG` pointing at your config. Built-in tools include:

| Tool | What it does |
|---|---|
| `discover_scopes` | What can I (this principal) see? |
| `status` | Freshness signal: git HEAD/commit time, last index refresh, visible note count |
| `list_notes` | List visible note paths |
| `list_files` | List visible vault files, including binary attachments |
| `search` | Ranked search over visible notes: BM25, or hybrid BM25 + local embeddings; `regex=True` for literal scans |
| `read_note` | Read a full note (scope-checked) |
| `get_file` | Pull a scoped file in bounded, binary-safe base64 chunks |
| `read_frontmatter` | Read a note's YAML frontmatter |
| `read_section` | Read one section by heading |
| `context_pack` | Compact, budgeted bundle for a query |
| `semantic_search` | Fuzzy "comb & synthesize" — the only tool that uses an LLM |

`search` and `context_pack` can also find notes by meaning rather than shared
words: enable `search.semantic` with a local embedding model (for example
Ollama) and run `cortex index --embeddings`. Lexical and semantic ranks are
fused, everything stays on the host by default, and lexical search keeps
working if the model is down. See
[`docs/local-semantic-search.md`](docs/local-semantic-search.md).

With `writes.enabled: true` in `cortex.yaml` (default **false** — otherwise
these tools are not registered at all), the mutating tools appear. Each one
requires a `reason`, is write-scope-checked, and lands as exactly one git
commit (always `git revert`-able):

| Tool (gated by `writes.enabled`) | What it does |
|---|---|
| `write_note` | Create a note (or replace one, only with `overwrite=True`) |
| `put_file` | Atomically upload a scoped binary attachment from base64 (8 MiB maximum) |
| `patch_note` | Replace a single unique string in an existing note |
| `append_note` | Append text to an existing note |
| `update_frontmatter` | Merge a patch into a note's YAML frontmatter |
| `set_memory_state` | Change lifecycle YAML with a reason and expected file hash |
| `supersede_note` | Link an old record to a current replacement, preserving both bodies |
| `delete_note` | Delete one note file (committed, so still recoverable) |
| `move_note` | Move/rename a note when both paths are writable |

---

## Memory lifecycle

Notes use a fixed `memory_state`: `unreviewed`, `draft`, `current`,
`superseded`, or `disputed`. Missing metadata means unreviewed, not verified.
Normal recall prefers current records and excludes superseded ones; historical
recall is an explicit option. State-only operations preserve note-body bytes.
The deterministic janitor reports metadata issues without modifying notes;
optional bounded LLM suggestions remain advisory.

See [`docs/memory-lifecycle.md`](docs/memory-lifecycle.md) for tool contracts,
authorization, preservation guarantees, and first-iteration limitations.

## Configuration

`cortex.yaml` is **public-safe**: structure only, no secrets. Tokens and API
keys are referenced by env-var name and read at startup. The shipped example
runs locally with no API key and the LLM disabled (deterministic tools only).

Key knobs (see [`cortex.example.yaml`](cortex.example.yaml)):

- `vaults.root` — account-owned directories (`<root>/<username>`).
- `vaults` — private-vault root, index directory, templates, archives, sync.
- `principals` — static identities, their `scopes` (path globs), and `token_env`.
- `database.path` — SQLite identity, sessions, memory permissions and telemetry;
  historical upstream records remain inert for rollback.
- `memory_policy` — existing read/write permission defaults and memory audit
  retention. No authorization-off switch. See the migration compatibility rules.
- `search` — default retrieval mode and the optional local embedding index
  (`search.semantic`, off by default; loopback endpoints only unless
  `allow_remote: true`).
- `vaults.sync.adapter` — `none` (default, local-only) · `git`. `nextcloud` and
  `s3` are reserved names that currently only snapshot locally.
- `llm.provider` — `none` (default) · `openrouter` · `openai` · `anthropic` ·
  `ollama`. OpenRouter (one key, many models; defaulting to the latest Claude
  Sonnet) is the recommended way to enable `semantic_search`.
- `janitor` — off by default; report-only before any write mode.

Run one bounded report pass across account vaults with
`cortex janitor --force` (or omit `--force` when `janitor.enabled` is true).
Reports are stored in SQLite and available through the authenticated API; the current worker
never modifies vault content.

---

## Documentation

| Topic | Document |
| --- | --- |
| Design and safety model | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Upgrading to 0.3.0 | [docs/upgrading.md](docs/upgrading.md) |
| Accounts, vault ownership and grants | [docs/account-vaults.md](docs/account-vaults.md) |
| Users, groups, LDAP, tokens | [docs/multi-user.md](docs/multi-user.md) |
| Tool policy and the broker retirement | [docs/memory-policy.md](docs/memory-policy.md) |
| Memory lifecycle | [docs/memory-lifecycle.md](docs/memory-lifecycle.md) |
| Janitor | [docs/memory-janitor.md](docs/memory-janitor.md) |
| Hybrid / semantic search | [docs/local-semantic-search.md](docs/local-semantic-search.md) |
| Remote HTTP exposure | [docs/http-exposure.md](docs/http-exposure.md) |
| Bare-metal install | [docs/bare-metal.md](docs/bare-metal.md) |
| JSON API reference | [docs/openapi.yaml](docs/openapi.yaml) |
| Releasing | [docs/release-checklist.md](docs/release-checklist.md) |
| Retired designs (history only) | [docs/archive/](docs/archive/) |

---

## Development

```bash
pip install -c requirements/dev.txt -e ".[dev]"   # the versions CI uses
ruff check src tests
mypy
pytest --cov                                      # includes end-to-end MCP tests
```

Dependencies are declared as ranges in `pyproject.toml` and locked in
`requirements/`; after changing them run `scripts/lock.sh` (see
[requirements/README.md](requirements/README.md)).

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
