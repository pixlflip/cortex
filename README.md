# Cortex

> Every mind needs a memory that is dynamic, not stationary.

Cortex is a **dynamic, governed memory layer for AI agents, assistants, and
chatbots**, backed by a real **Obsidian vault**. Humans keep using ordinary
Obsidian-compatible Markdown files; AI clients access that same memory only
through a secure [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) server:

- **Obsidian-native** — the source of truth is a normal Obsidian vault: Markdown
  notes, YAML frontmatter, folders, links, and your editor of choice.
- **Scoped** — each caller (principal) sees only the slice you grant; a path
  out of scope is *invisible*, not just unreadable.
- **Audited** — every change is a git commit tagged with *actor* and *reason*.
  Git is the single audit trail and rollback mechanism.
- **Deterministic by default** — search, reads, and context packs spend zero
  model tokens. Only the one `semantic_search` tool calls an LLM.
- **Self-improving (later)** — an optional, bounded "janitor" AI tidies and
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
docker compose run --rm cortex init         # create the git audit baseline
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
cortex serve                                # MCP server over stdio
```

Full host/service setup (service user, systemd) is in
[`docs/bare-metal.md`](docs/bare-metal.md).

### Connect an MCP client

For a stdio client (e.g. Claude Desktop), register Cortex as a server that runs
`cortex serve` with `CORTEX_CONFIG` pointing at your `cortex.yaml`. It exposes:

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

---

## Configuration

`cortex.yaml` is **public-safe**: structure only, no secrets. Tokens and API
keys are referenced by env-var name and read at startup. The shipped example
runs locally with no API key and the LLM disabled (deterministic tools only).

Key knobs (see [`cortex.example.yaml`](cortex.example.yaml)):

- `vault.path` — your Obsidian vault folder.
- `principals` — static identities, their `scopes` (path globs), and `token_env`.
- `admin` — optional web UI state path. `cortex init` generates the admin
  password; the UI creates roles and per-client tokens for scoped AI clients.
- `sync.adapter` — `none` (default, local-only) · `git` · `nextcloud` · `s3`.
- `llm.provider` — `none` (default) · `openrouter` · `openai` · `anthropic` ·
  `ollama`. OpenRouter (one key, many models; defaulting to the latest Claude
  Sonnet) is the recommended way to enable `semantic_search`.
- `janitor` — off by default; report-only before any write mode.

---

## Status

This repo is built in dependency order (see the build sequence in
[`ARCHITECTURE.md`](ARCHITECTURE.md)). **Working today:**

- ✅ Config system (public-safe, env-injected secrets)
- ✅ Obsidian vault store (list / read / frontmatter / section / search) with
  path-traversal safety
- ✅ Git audit layer (commit-on-mutation with actor + reason)
- ✅ Scoping + auth (token → principal → scopes; directory-bounded globs)
- ✅ MCP server **v1, read-only** over stdio — all tools above
- ✅ LLM provider layer (OpenRouter default → latest Claude Sonnet; also
  OpenAI / Anthropic / Ollama / none)
- ✅ Live `semantic_search` — scoped retrieve-then-synthesize (the model only
  sees notes the principal may read)
- ✅ Remote **Streamable HTTP** transport with bearer-token → principal auth,
  per-request scoping, and Host/Origin protection (TLS via reverse proxy).
- ✅ Admin web UI for HTTP deployments — `cortex init` generates an admin
  password, then the UI can create roles and per-client tokens for scoped AI
  clients.
- ✅ **OAuth 2.1** authorization server (dynamic client registration + PKCE +
  consent) so the one-click **Claude.ai / ChatGPT / Grok** connector UIs can
  authorize. See [`docs/http-exposure.md`](docs/http-exposure.md).
- ✅ Docker image + Compose, and a bare-metal/systemd path

**Next on the roadmap:** sync adapters (opt-in) → the bounded janitor.

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
