# Changelog

## Unreleased

- Added scoped `list_files` and chunked `get_file` MCP tools for binary vault
  attachments, plus write-gated, atomic, git-audited `put_file` uploads with
  overwrite protection, size limits, and optional SHA-256 verification.
- Reject symlink components from vault operations so an in-vault symlink cannot
  cross a principal's path scope.
- Constrained Cortex to the compatible MCP 1.x SDK, declared its direct HTTPX
  dependency, and restored fail-closed production dependency auditing with one
  explicit exception for unused React Router server-component code.

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
