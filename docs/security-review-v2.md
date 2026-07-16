# Cortex v2 focused security review

Review scope: multi-user identity, per-user/shared vault routing, the same-origin
SPA/API, and governed upstream MCP passthrough. This is a design/code review,
not a third-party penetration test.

## Enforced invariants

| Boundary | Enforcement |
|---|---|
| Identity source confusion | Config, user, and legacy-client subjects are namespaced and re-resolved only against their authenticating store. |
| Cross-user vault access | One resolver maps identity to `(vault, read scopes, write scopes)` before any path operation; foreign and absent are indistinguishable. |
| Path traversal/hidden files | Canonicalize first; reject absolute paths, backslashes, `..`, hidden components, and invalid suffixes; then scope-check. |
| Token widening | Token path globs intersect existing grants and cannot create a new vault grant. |
| Browser session abuse | HttpOnly/SameSite cookies, Secure under HTTPS, session-bound CSRF, Origin checks, no CORS, uniform auth errors, login throttle. |
| Markdown/attachment XSS | Sanitized Markdown AST; no raw search-snippet HTML; attachment `nosniff`, safe inline types, sandbox CSP; same-origin SPA CSP. |
| Tool-policy bypass | Denied tools are filtered from discovery and the same deny-wins resolver runs again immediately before invocation. |
| SSRF | HTTP(S) only, no URL credentials, hostname allowlist, DNS/IP classification on each call, no redirect following, private ranges blocked by default. |
| Credential disclosure | DB stores environment names and salted credential hashes, never upstream secret values; serializers omit hash/salt material. |
| Audit exfiltration | Tool audit contains argument digest and shape only—no values, note content, results, or secrets. |
| Destructive vault lifecycle | UI/API archive by moving intact; permanent deletion is local CLI-only with `--force`; mutations are git commits. |

Automated coverage includes cross-user API non-disclosure, group read/write
separation, admin macro grants, token narrowing, SSRF rejection, environment
reference behavior, deny-wins precedence, hot namespace replacement, call-time
authorization, and audit-value exclusion.

## Residual risks and operator obligations

1. **Trusted upstream content.** An upstream controls its descriptions and tool
   results and may attempt prompt injection. Namespacing and metadata bounds do
   not make that content trustworthy. Register only reviewed servers and grant
   the smallest tool patterns.
2. **Host compromise.** The Cortex process resolves configured environment
   secrets and can read the vaults/DB by design. OS account isolation, file
   ownership, secret-file permissions, patching, and backups remain operator
   responsibilities.
3. **TLS termination.** Cortex commonly listens on plain loopback HTTP. A
   correctly configured reverse proxy must terminate TLS and preserve Host and
   authorization headers for remote use.
4. **LDAP availability and policy.** New directory sessions depend on LDAP.
   Local admin access remains the break-glass path. Mapping/JIT policy is config
   owned and requires service restart after change.
5. **Telemetry metadata.** Audit rows avoid content but still reveal identity,
   tool names, timing, and vault ids. Protect and retain the SQLite database as
   security telemetry.
6. **OAuth persistence.** The current OAuth provider's issued state is
   process-local; restarts require connector reauthorization. User API tokens
   are persistent and individually revocable.

## Deployment checklist

- Keep `writes.enabled: false` until mutation access is intentionally granted.
- Keep `gateway.allow_user_servers: false` unless personal upstreams are needed.
- Set `gateway.outbound_allowlist` when upstream hosts are known.
- Never disable private-network blocking merely to avoid configuring a local
  upstream; isolate and document that exception.
- Use HTTPS, `server.public_url`, proxy limits, and explicit allowed hosts.
- Store the DB, config, env file, and all vault roots outside the source tree
  with least-privilege ownership; back up vault `.git` directories.
- Review denied/error audit events and stale tokens regularly.

