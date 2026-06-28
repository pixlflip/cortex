# Cortex Architecture

> Every mind needs a memory that is dynamic, not stationary.

Cortex is a **dynamic memory layer** you can put in front of any knowledge
vault (a folder of Markdown/plain-text notes) and expose to AI clients and
humans through a secure [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) server. It is designed so that **anyone can spin one up** — locally with
Docker, on a server, or on a homelab — and point their AI tools at their own
memory without handing the whole vault to every caller.

This document is the canonical design. It is intentionally
infrastructure-agnostic: no IP addresses, no hostnames, no secrets. Everything
environment-specific is a config value with a sane default.

---

## 1. The problem

People accumulate knowledge in note vaults (Obsidian, Logseq, plain Markdown,
a wiki). That knowledge is *stationary*: it sits in files, and every tool that
wants it either gets raw filesystem access (no scoping, no audit, no safety) or
nothing at all. AI assistants in particular need **scoped, structured,
auditable** retrieval — not "here's my entire life, please don't mess it up."

Cortex turns a stationary vault into a **governed, self-improving memory**:

- **Fast, deterministic retrieval** for machines (search, read, context packs).
- **A single audit trail** so every change is attributable and reversible.
- **Enforced scoping** so different callers see different slices.
- **A background intelligence** that keeps the vault healthy and watches for
  drift — without being in the hot path and without the power to change its own
  limits.

---

## 2. Two faces

Cortex has exactly two faces, kept deliberately separate.

### Face A — Synchronous front door (MCP server)

A credentialed MCP server exposing **scoped, deterministic** vault tools. This
is what web and desktop AI clients connect to. It is the *only* sanctioned way
in. It enforces safety **at the tool layer**, never trusting the caller.

### Face B — Asynchronous maintenance mind (the Janitor)

A separate, low-power AI worker on a heartbeat. It tidies, validates, and
watches the vault for drift. It is **not** in the request path (except as the
backend for the one semantic-search tool). It runs under hard boundaries it
cannot edit.

The separation is the point: the front door stays fast and predictable; the
maintenance mind stays bounded and observable. They never blur.

---

## 3. Layers (bottom to top)

```
┌──────────────────────────────────────────────────────────────┐
│  Clients: Claude Desktop, web apps, IDEs, CLIs (MCP)           │
└───────────────────────────┬──────────────────────────────────┘
                            │  MCP (stdio for local, HTTP for remote)
┌───────────────────────────▼──────────────────────────────────┐
│  Auth & Scoping:  token → principal → scopes                  │
├──────────────────────────────────────────────────────────────┤
│  MCP Tools (v1 read-only):                                    │
│    discover_scopes · search · read_note · read_section        │
│    read_frontmatter · context_pack · semantic_search*         │
├──────────────────────────────────────────────────────────────┤
│  Vault Store (filesystem)   │   Git Audit (actor + reason)    │
├─────────────────────────────┴────────────────────────────────┤
│  Sync Adapter (git-native default · nextcloud · s3 · none)    │
├──────────────────────────────────────────────────────────────┤
│  Janitor (dark by default) ── LLM provider (claude/openai/    │
│                                ollama/none)  *also backs       │
│                                semantic_search                 │
└──────────────────────────────────────────────────────────────┘
```

### 3.1 Vault Store

- The vault is a **local folder** of notes. All reads/writes go through the
  filesystem — never a remote call in the request path.
- Notes are Markdown with optional YAML frontmatter (Obsidian-compatible, but
  not Obsidian-specific).
- The store exposes primitives: list notes, read a note, read its frontmatter,
  read a named section (by heading), and substring/regex search.

### 3.2 Git Audit

- The vault folder is a git repository. **Every mutation is immediately
  committed**, with the message encoding *actor* and *reason*:
  - `cortex-janitor: normalize frontmatter`
  - `principal:didact via mcp: append decision record`
- Git is the **single** audit + rollback mechanism. No separate version store.
- Rollback = `git revert` / `git checkout` of a path. Diffs are the change log.

### 3.3 Sync Adapter (pluggable)

The source-of-truth / propagation layer is an adapter so the same Cortex runs
for very different users. **The default is `none` (local-only):** the vault is
just a folder, git audit (3.2) still applies for rollback, and you bring your
own sync if you want one. Everything else is opt-in.

| Adapter | Source of truth | Use case |
|---|---|---|
| `none` *(default)* | the local folder | Single-box; bring-your-own-sync |
| `git` | a git remote | Portable; the remote *is* both sync and audit |
| `nextcloud` | Nextcloud/WebDAV | Obsidian-over-Nextcloud users (the original setup) |
| `s3` | object storage | Cloud-first, large vaults |

Hard rule for any adapter: **git internals (`.git/`) are never propagated to a
file-sync backend** (it corrupts the repo). The git remote is the only thing
that ever sees `.git`.

### 3.4 Auth & Scoping

- A **principal** is a named identity (a person or an agent).
- A **scope** is a set of vault paths (glob) a principal may read (and later,
  write).
- A **credential** (bearer token) maps to exactly one principal. The server
  treats "X called it" and "a holder of X's token called it" as identical —
  which is exactly why the mapping must be explicit and enforced.
- **No public exposure without credential→principal mapping.** Without it,
  scoping is decorative. Over local `stdio` a single trusted default principal
  is allowed; over HTTP a bearer token is required.
- Secrets live in **environment variables / a secrets file**, never in the
  committed config or the image.

### 3.5 MCP Tools — v1 (read-only)

Deterministic and cheap (no model spend) unless marked:

| Tool | Purpose |
|---|---|
| `discover_scopes` | What can *I* (this principal) see? |
| `search` | Scoped substring/regex search → matching notes + snippets |
| `read_note` | Full note body (+ optional frontmatter), scope-checked |
| `read_frontmatter` | Just the YAML frontmatter |
| `read_section` | A single heading's section from a note |
| `context_pack` | Compact, token-budgeted bundle assembled for a query |
| `semantic_search` * | Fuzzy "comb the vault and synthesize" — *delegates to the LLM/Janitor backend*. The **only** tool that spends model tokens. |

**v2** adds writes (append/patch/create) once v1 scoping and audit are proven —
path-restricted, never deletes-by-default, every write → a git commit.

### 3.6 LLM Provider (pluggable)

A thin provider interface backs both `semantic_search` and the Janitor:

- `openrouter` *(default)* — one API key, many models via an OpenAI-compatible
  endpoint. Default model: **latest Claude Sonnet**. Lets users swap models
  without code changes.
- `openai` — any OpenAI-compatible endpoint.
- `anthropic` — the Anthropic API directly.
- `ollama` — local models, zero API cost, full privacy.
- `none` — disables semantic search + Janitor entirely (pure deterministic
  retrieval). Cortex is fully useful in this mode, and this is what ships in the
  example config so it runs with no API key.

### 3.7 Janitor (dark by default)

A heartbeat-driven worker, separate harness, low-power model. **Disabled until
explicitly enabled**, and even then **dry-run/report-only before write mode**.

It **may**: normalize frontmatter, validate links/metadata shape/stale refs,
propose or perform safe reorganization inside allowed paths, generate reports.

It **must never** edit: scope/permission definitions, principal definitions,
auth/credential material, or **the ruleset defining its own limits**. This is a
hard category, not a logged event: git would faithfully commit a privilege
escalation, so the class of change must be *prevented*, not merely audited.

It can grow into a **drift-watcher** — noticing when an actor (human or AI) is
moving away from declared operating rules — because it is structurally outside
the actors it watches.

---

## 4. Safety model (summary)

1. Safety is enforced **server-side at the tool layer**, never at the client.
2. **Writes off in v1; deletes off by default forever.**
3. Reads are **principal-scoped**; no scope match → not visible, not just
   not-readable.
4. **Credential→principal mapping is mandatory** before any non-local exposure.
5. The Janitor **cannot touch the four protected categories** (scopes,
   principals, credentials, its own ruleset).
6. **Everything is a git commit** with actor + reason → full audit + rollback.
7. **No secrets in the repo or image.** Config is public-safe; secrets are env.

---

## 5. Build order

The repository is built in dependency order. Each step is runnable/verifiable
before the next begins.

1. **Design captured** (this document) + project scaffold.
2. **Config system** — vault path, principals, scopes, sync adapter, LLM,
   janitor toggles. Public-safe defaults; secrets via env.
3. **Vault Store** — filesystem primitives (list/read/frontmatter/section/search).
4. **Git Audit** — commit-on-mutation with actor+reason; history; rollback.
5. **Scoping + Auth** — token→principal→scopes; path authorization.
6. **MCP server v1 (read-only)** — deterministic tools, local `stdio` first.
7. **LLM provider layer** — pluggable; default Claude; `none` works.
8. **`semantic_search`** — the one non-deterministic tool, behind the provider.
9. **Secure HTTP exposure** — bearer auth, TLS via reverse proxy, tool filtering.
10. **Packaging** — Docker Compose for one-command spin-up *and* a first-class
    bare-metal path (`pip install` + `cortex` CLI + systemd unit) that runs from
    the repo unmodified on a Debian/Proxmox container.
11. **Sync adapters** (opt-in) — git-remote first, then Nextcloud/WebDAV, then S3.
12. **Janitor** — spec boundaries → dry-run/report → (opt-in) write mode.

v1 is "done" at step 9–10: a credentialed, scoped, audited, read-only memory
server anyone can run. The Janitor (12) is the self-improving face and lands
last, behind its boundaries.

---

## 6. Non-goals (v1)

- Not a sync tool itself — it *uses* a sync adapter; it doesn't reinvent one.
- Not an editor/UI — humans keep using Obsidian/their editor of choice.
- Not a general database — it's a memory layer over files, with git as truth.
- Not autonomous on day one — the Janitor stays dark until boundaries are spec'd
  and proven in dry-run.
