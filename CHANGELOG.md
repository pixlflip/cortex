# Changelog

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
- Added schema migration 2, `cortex migrate`, multi-stage Docker packaging,
  persistent Compose data mounts, health checks, CI web/dependency/image smoke
  validation, v2 operations documentation, and a focused security review.

Existing v1 config principals, main-vault layout, stdio mode, bearer mode, and
legacy admin import remain supported.

