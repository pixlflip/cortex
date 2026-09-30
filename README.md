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

**Breaking storage correction:** legacy `vault.path` is no longer served or
synced. Read [account-vault migration](docs/account-vaults.md) before upgrading
an existing installation. No automatic merging or deletion is performed.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the broader design; the account-vault
contract supersedes its historical shared-vault sections.

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
| `search` | Substring/regex search over visible notes |
| `read_note` | Read a full note (scope-checked) |
| `get_file` | Pull a scoped file in bounded, binary-safe base64 chunks |
| `read_frontmatter` | Read a note's YAML frontmatter |
| `read_section` | Read one section by heading |
| `context_pack` | Compact, budgeted bundle for a query |
| `semantic_search` | Fuzzy "comb & synthesize" — the only tool that uses an LLM |

The proposed path to genuinely local concept retrieval (hybrid FTS5 plus
on-machine embeddings, with optional local synthesis) is documented in
[`docs/local-semantic-search.md`](docs/local-semantic-search.md). It is a design,
not yet part of the shipped configuration surface.

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
- `sync.adapter` — `none` (default, local-only) · `git` · `nextcloud` · `s3`.
- `llm.provider` — `none` (default) · `openrouter` · `openai` · `anthropic` ·
  `ollama`. OpenRouter (one key, many models; defaulting to the latest Claude
  Sonnet) is the recommended way to enable `semantic_search`.
- `janitor` — off by default; report-only before any write mode.

Run one bounded report pass across account vaults with
`cortex janitor --force` (or omit `--force` when `janitor.enabled` is true).
Reports are stored in SQLite and available through the authenticated API; the current worker
never modifies vault content.

---

## What v2 includes

- Local accounts, LDAP/Active Directory login and sync, groups, sessions,
  CSRF-protected same-origin API, and individually revocable user tokens.
- One git-audited vault per account, explicit cross-account administration,
  lifecycle repair/archive operations, and token-level path narrowing.
  There is no general or shared default vault.
- Headless JSON API and MCP access, with scope-checked notes and attachments.
  The React UI, static assets, and legacy browser admin have been removed.
- Memory-only per-user/group tool permissions, deny-wins behavior (including
  admins), listing/call parity, and argument-shape-only call telemetry.
- Reproducible Docker/Compose and Python-wheel packaging, a v1→v2 migration
  command, health checks, CI, and documented backup/upgrade procedures.

Start with [`docs/multi-user.md`](docs/multi-user.md),
[`docs/memory-policy.md`](docs/memory-policy.md), and
[account-vault migration](docs/account-vaults.md). The original
[v2 upgrade](docs/upgrading-v2.md) and [security review](docs/security-review-v2.md)
are historical.

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
