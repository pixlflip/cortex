# Changelog

## Unreleased

## 0.3.0 — Unreleased (date set when tagged)

**Breaking release.** Read [upgrading to 0.3.0](docs/upgrading.md) first: it
covers account-owned storage, the removed UI and broker, the `gateway` →
`memory_policy` rename, and how to roll back.

### Added

- Hybrid retrieval: an optional local embedding index fused with FTS5/BM25 by
  weighted reciprocal-rank fusion (`search.semantic`, off by default). Loopback
  endpoints only unless `allow_remote: true`; incremental, hash-keyed vector
  refresh via `cortex index --embeddings` and `cortex sync`; an endpoint probe
  in `cortex check`; a `semantic` block in `status`. `search`, `context_pack`
  and `GET /api/v1/vaults/{vault}/search` take `mode=auto|lexical|hybrid` and
  report `retrieval_mode` plus ranks. Lexical behaviour is unchanged by default.
  See [local semantic search](docs/local-semantic-search.md).
- End-to-end MCP tests that run the real `cortex serve` over stdio and HTTP and
  check cross-account, path-scope and tool-policy isolation.
- Container images published to GHCR on version tags, smoke-tested, with
  provenance and SBOM.
- `docs/upgrading.md`, a rewritten `ARCHITECTURE.md` and release checklist.

### Changed

- Docker image uses a digest-pinned Python 3.13 base and installs hash-locked
  runtime dependencies from `requirements/runtime.txt` (regenerate with
  `scripts/lock.sh`).
- Compose runs the HTTP server by default; stdio clients use the new
  `cortex-stdio` profile, which has no TTY.
- CI adds ruff, mypy (strict on authorization modules), a fail-closed
  `pip-audit` of the locked runtime set, a lock freshness check, locked test
  installs, and coverage floors (75% overall, 95% on authorization modules).
  Dependabot covers pip, Actions and the base image.
- `server.py` and `api.py` are split into `mcp_tools/`, `note_writes` and
  `api_routes/`. Public imports from `cortex.server` and `cortex.api` are kept.
- Historical documents moved to `docs/archive/`.

### Fixed

- Grant administration no longer raises a server error for an actor record
  without an id, and LDAP directory construction fails cleanly when LDAP is
  not configured (found by type checking).

### Earlier changes in this release

- **Breaking:** enforce account-owned vaults. Legacy `vault.path` is no longer
  served, indexed or synced; there is no global vault or first-available
  fallback, and a missing account vault fails closed. Administrators must
  select another account explicitly. See `docs/account-vaults.md`.
- Add explicit, scoped cross-account vault grants (schema migration 5;
  `cortex vault grant`, `/api/v1/admin/vault-grants`), re-read on every call.
- Add validated memory lifecycle metadata (`memory_state`), lifecycle-aware
  recall with explicit disputed/historical handling, `set_memory_state` and
  `supersede_note` tools, and a report-only lifecycle janitor with optional
  advisory LLM suggestions. See `docs/memory-lifecycle.md`.
- Reconcile OAuth delegation fixes and classify stdio MCP startup failures
  without leaking details.
- Remove the operational upstream MCP broker: registration, discovery/calls,
  HTTP/stdio connection workers, lazy session catalogs, and broker REST routes.
  Cortex is a dedicated memory MCP; old `/api/v1/mcp/*` endpoints return 404.
- Extract always-on memory deny-wins policy into `cortex.memory_policy`.
  `memory_policy` replaces `gateway` configuration; only existing read/write
  defaults and audit retention migrate. Old `gateway.enabled` cannot disable
  authorization or restore upstream execution. Unknown tools fail closed.
- Preserve identity/tokens, historical SQLite schema/migrations and inert
  upstream records. No destructive migration; historical upstream audit is
  retained. Account storage, JSON API, OAuth, LDAP and Nextcloud sync remain.
  See `docs/memory-policy.md` for compatibility and cutover requirements.

- Remove the React/Vite interface, packaged static assets, SPA fallback, and
  legacy HTML admin dashboard. Cortex is now headless; old UI paths return 404.
- Remove the Node frontend build from Docker and CI. Retain JSON API, MCP,
  CLI, OAuth consent, and readiness without a frontend requirement.

- Added scoped `list_files` and chunked `get_file` MCP tools for binary vault
  attachments, plus write-gated, atomic, git-audited `put_file` uploads with
  overwrite protection, size limits, and optional SHA-256 verification.
- Reject symlink components from vault operations so an in-vault symlink cannot
  cross a principal's path scope.
- Constrained Cortex to the compatible MCP 1.x SDK, declared its direct HTTPX
  dependency, and added fail-closed production dependency auditing (since
  replaced by `pip-audit` of the Python lock after the frontend removal).

## 0.2.0 — Cortex v2

- Added local/LDAP users, groups, sessions, revocable user tokens, and the
  CSRF-protected `/api/v1` surface.
- Added private per-user vaults, shared-vault grants, token narrowing, macro
  sync/audit, lifecycle repair/archive, and scoped vault content APIs.
- Added the packaged React SPA, admin panel, Obsidian-compatible vault viewer,
  search, tags, backlinks, MCP setup, permission, and audit pages.
- Added the governed upstream MCP registry/proxy with hot schema refresh,
  deny-wins rules, SSRF defenses, bounded calls, circuit breaking, and
  value-free tool-call telemetry.
- Added schema migrations through version 3, `cortex migrate`, multi-stage Docker packaging,
  persistent Compose data mounts, health checks, CI web/dependency/image smoke
  validation, v2 operations documentation, and a focused security review.

Existing v1 config principals, main-vault layout, stdio mode, bearer mode, and
legacy admin import remain supported.
