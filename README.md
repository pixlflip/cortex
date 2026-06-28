# Cortex

> Every mind needs a memory that is dynamic, not stationary.

Cortex is a **dynamic, governed memory layer** for your notes. Point it at a
folder of Markdown (Obsidian, Logseq, plain text — anything) and it serves that
knowledge to AI clients and humans through a secure
[Model Context Protocol](https://modelcontextprotocol.io) (MCP) server:

- **Scoped** — each caller (principal) sees only the slice you grant; a path
  out of scope is *invisible*, not just unreadable.
- **Audited** — every change is a git commit tagged with *actor* and *reason*.
  Git is the single audit trail and rollback mechanism.
- **Deterministic by default** — search, reads, and context packs spend zero
  model tokens. Only the one `semantic_search` tool calls an LLM.
- **Self-improving (later)** — an optional, bounded "janitor" AI tidies and
  watches the vault on a heartbeat, never able to edit its own limits.

Anyone can spin one up — locally, in Docker, or on a homelab — and keep their
memory *theirs* while still letting AI tools retrieve from it safely.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design.

---

## Quick start

### Docker (recommended)

```bash
git clone https://github.com/pixlflip/cortex.git && cd cortex
cp cortex.example.yaml cortex.yaml          # edit to taste
# put your notes in ./vault (or point vault.path elsewhere)
docker compose run --rm cortex check        # validate setup
docker compose run --rm cortex init         # create the git audit baseline
```

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

- `vault.path` — your notes folder.
- `principals` — identities, their `scopes` (path globs), and `token_env`.
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
- ✅ Vault store (list / read / frontmatter / section / search) with
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
  Works today with programmatic clients and the Anthropic API `mcp_servers`
  connector. See [`docs/http-exposure.md`](docs/http-exposure.md).
- ✅ Docker image + Compose, and a bare-metal/systemd path

**Next on the roadmap:** OAuth 2.1 (the unlock for one-click Claude.ai / ChatGPT
/ Grok connector UIs) → sync adapters → the bounded janitor.

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
