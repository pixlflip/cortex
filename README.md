# Cortex

> Every mind needs a memory that is dynamic, not stationary.

Cortex is a **dynamic, governed memory layer for AI agents, assistants, and
chatbots**, backed by a real **Obsidian vault**. Humans keep using ordinary
Obsidian-compatible Markdown files; AI clients access that same memory only
through a secure [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) server:

- **Obsidian-native** — the source of truth is a normal Obsidian vault: Markdown
  notes, YAML frontmatter, folders, links, and your editor of choice.
- **Multi-user** — local or LDAP users get private vaults; groups grant
  independent read/write slices of a shared vault; admins get a macro view.
- **Scoped** — each token sees only its allowed vaults, note paths, and MCP
  tools. Out-of-scope resources are *invisible*, not just unreadable.
- **Audited** — every change is a git commit tagged with *actor* and *reason*.
  Git is the single audit trail and rollback mechanism.
- **Deterministic by default** — search, reads, and context packs spend zero
  model tokens. Only the one `semantic_search` tool calls an LLM.
- **One governed MCP** — connect an AI only to Cortex; it receives Cortex and
  upstream MCP tools filtered by the token owner's deny-wins policy.
- **Self-improving (bounded)** — an optional, report-first janitor tidies and
  watches the vault on a heartbeat, never able to edit its own limits.

Anyone can spin one up — locally, in Docker, or on a homelab — and keep their
memory *theirs*: a fully working Obsidian vault for humans, a governed memory
API for agents.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design.

---

## Quick start

### Docker (recommended)

```bash
git clone https://github.com/pixlflip/cortex.git && cd cortex
cp cortex.example.yaml cortex.yaml          # edit to taste
# put your Obsidian vault in ./vault (or point vault.path at one)
docker compose run --rm cortex check        # validate setup
docker compose run --rm cortex init         # DB + admin + git baselines
docker compose up -d                        # SPA + API + MCP on :8765
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

Open the same-origin web app at the server root (for example
`http://127.0.0.1:8765/`). The first-run admin password is printed by
`cortex init`. The panel manages people, groups, vault health, tokens, LDAP,
upstream MCP servers, tool permissions, and both audit streams.

### Connect an AI once

Create a per-user token in the web app, then give the AI Cortex as its only
MCP endpoint:

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

Tool discovery is identity-specific. Built-in tools and namespaced upstream
tools (`calendar.list_events`, for example) are omitted unless allowed, and
authorization is checked again at call time. See
[`docs/mcp-gateway.md`](docs/mcp-gateway.md).

For local stdio clients, register Cortex as a server that runs `cortex serve`
with `CORTEX_CONFIG` pointing at your config. Built-in tools include:

| Tool | What it does |
|---|---|
| `discover_scopes` | What can I (this principal) see? |
| `status` | Freshness signal: git HEAD/commit time, last index refresh, visible note count |
| `list_notes` | List visible note paths |
| `search` | Substring/regex search over visible notes |
| `read_note` | Read a full note (scope-checked) |
| `read_frontmatter` | Read a note's YAML frontmatter |
| `read_section` | Read one section by heading |
| `context_pack` | Compact, budgeted bundle for a query |
| `semantic_search` | Fuzzy "comb & synthesize" — the only tool that uses an LLM |

With `writes.enabled: true` in `cortex.yaml` (default **false** — otherwise
these tools are not registered at all), the mutating tools appear. Each one
requires a `reason`, is write-scope-checked, and lands as exactly one git
commit (always `git revert`-able):

| Tool (gated by `writes.enabled`) | What it does |
|---|---|
| `write_note` | Create a note (or replace one, only with `overwrite=True`) |
| `patch_note` | Replace a single unique string in an existing note |
| `append_note` | Append text to an existing note |
| `update_frontmatter` | Merge a patch into a note's YAML frontmatter |
| `delete_note` | Delete one note file (committed, so still recoverable) |
| `move_note` | Move/rename a note when both paths are writable |

---

## Configuration

`cortex.yaml` is **public-safe**: structure only, no secrets. Tokens and API
keys are referenced by env-var name and read at startup. The shipped example
runs locally with no API key and the LLM disabled (deterministic tools only).

Key knobs (see [`cortex.example.yaml`](cortex.example.yaml)):

- `vault.path` — your Obsidian vault folder.
- `vaults` — private-vault root, index directory, templates, archives, sync.
- `principals` — static identities, their `scopes` (path globs), and `token_env`.
- `database.path` — SQLite identity, session, gateway, and telemetry state.
- `gateway` — upstream registration policy, SSRF controls, timeouts, and audit
  retention. Secrets are environment references only.
- `sync.adapter` — `none` (default, local-only) · `git` · `nextcloud` · `s3`.
- `llm.provider` — `none` (default) · `openrouter` · `openai` · `anthropic` ·
  `ollama`. OpenRouter (one key, many models; defaulting to the latest Claude
  Sonnet) is the recommended way to enable `semantic_search`.
- `janitor` — off by default; report-only before any write mode.

Run one bounded report pass across the main and every user vault with
`cortex janitor --force` (or omit `--force` when `janitor.enabled` is true).
Reports are stored in SQLite for the admin vault panel; the current worker
never modifies vault content.

---

## What v2 includes

- Local accounts, LDAP/Active Directory login and sync, groups, sessions,
  CSRF-protected same-origin API, and individually revocable user tokens.
- One git-audited private vault per user, the existing main/shared vault,
  group scope grants, admin macro view, lifecycle repair/archive operations,
  and token-level path narrowing.
- A responsive React admin panel and read-oriented Obsidian-compatible vault
  viewer with full-text search, tags, backlinks, embeds, properties, ETags,
  and safe Markdown rendering.
- Governed upstream MCP aggregation with per-user/group glob permissions,
  deny-wins behavior, discovery/call parity, SSRF defenses, bounded calls,
  circuit breaking, hot tool refresh, and argument-shape-only telemetry.
- Reproducible Docker/Compose and Python-wheel packaging, a v1→v2 migration
  command, health checks, CI, and documented backup/upgrade procedures.

Start with [`docs/multi-user.md`](docs/multi-user.md),
[`docs/mcp-gateway.md`](docs/mcp-gateway.md), and
[`docs/upgrading-v2.md`](docs/upgrading-v2.md). The focused security review is
[`docs/security-review-v2.md`](docs/security-review-v2.md).

---

## Development

```bash
pip install -e ".[dev]"
pytest
cd web && npm ci && npm run lint && npm run build
```

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
