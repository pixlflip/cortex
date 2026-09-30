# Dedicated memory MCP and broker retirement

Cortex is a headless, account-vault memory service. Its supported front doors
are the memory MCP, authenticated JSON memory/account API, CLI, `/healthz`, and
optional OAuth consent. There is no product UI or general-purpose tool broker.

## Intentional breaking changes

- Removed upstream registration, cached discovery/execution, HTTP/stdio
  connection workers, environment/URL/executable validators, and registry CRUD.
- Removed `search_mcps`, `peek_mcp`, `load_mcp`, namespaced upstream tools, and
  per-session dynamic catalogs. MCP tools/list contains only authorized Cortex
  memory tools. Old tool calls fail closed, including for administrators.
- Removed `/api/v1/mcp/tools`, `/api/v1/mcp/servers`, server item operations,
  and server `test`/`refresh` actions. All return 404; no upstream is contacted.
- Removed the `cortex.gateway` module and `GatewayConfig` Python API. No
  compatibility shim, enable flag, or database row can restore the broker.

Consumers must move operational tool use to a separate service before cutover.
For the authorized Gameverse SQL / Pterodactyl retirement, those capabilities
remain exclusively with Reve; the parent accesses them through A2A. This source
change does not verify that every consumer has moved. The parent/operator must
perform direct consumer-coverage verification before publishing/deploying.

## Always-on memory authorization

`cortex.memory_policy` governs tools/list and every tools/call. It does not
replace credential validation, token path narrowing, account ownership, or
write-scope checks. Known memory tools are explicitly classified as reads or
writes. Unknown tools, including a future `cortex.*` mutation, are denied until
classified; an admin or wildcard allow cannot make an upstream callable.

Database principals retain existing semantics:

1. Disabled accounts are denied, including a previously resolved principal.
2. Any matching user or group deny wins, including over admin and explicit allow.
3. Admin or explicit user/group allow grants the tool, not an extra vault grant.
4. Otherwise the existing read/write defaults apply. Writes default to denied.

Static/config and legacy principals retain access to known memory tools;
account/path authorization still applies. On an identity-backed server a
config principal without a database account has no account-vault grant. In a
config-only setup it can use only its existing, named account directory within
its configured scopes. Missing owner storage never falls back to `main`,
`vault.path`, another account, or an orphan directory. An administrator's omitted
vault also selects only their own account; cross-account administration is
explicit. Ordinary accounts cannot access each other's vaults.

`writes.enabled` remains an independent global registration gate. Setting it
true does not grant a DB user write permission. A memory policy grant does not
bypass account, token, path or git-audit constraints. No new writes are granted
by removing the broker.

## Configuration migration

```yaml
memory_policy:
  default_read_allow: true
  default_write_allow: false
  audit_retention_days: 90
```

There is no `memory_policy.enabled` or authorization-off mode. For migration,
ONLY `gateway.default_read_allow`, `gateway.default_write_allow`, and
`gateway.audit_retention_days` are accepted as fallback values. Precedence is
per field: explicit `memory_policy` value, then legacy `gateway` value, then
the defaults above. Booleans must be YAML booleans; retention must be a positive
integer. Quoted `"false"` is rejected rather than becoming a truthy write grant.

Both `gateway.enabled: true` and `gateway.enabled: false` now result in the same
always-on authorization. All old upstream/transport options are ignored,
including unresolved environment references inside retired connection settings.
No upstream configuration is loaded or validated. Operators who previously
used `gateway.enabled: false` to bypass DB tool permissions must provision
explicit memory grants, not set a new bypass flag.

`/api/v1/admin/permissions` and `/audit/tools` are retained for memory policy
and audit. New permission rules accept `cortex.*`-style patterns or `*` and
reject non-null `server_id` and other namespaces. Historical rules remain
readable/deletable, but server-scoped rules never influence memory permissions.

## Data and audit compatibility

No SQLite schema/migration code is changed and no destructive migration is
added. Accounts, passwords, existing tokens, sessions, historical upstream
registrations, permission rows and audit records are not rewritten for this
retirement. Upstream records stay inert for rollback; there is no registry
repository or transport capable of consuming them.

On identity-backed servers, memory calls record identity, tool, outcome,
vault identifier (when supplied), timing, argument digest and bounded shape.
Argument values, note bodies, results, arbitrary argument keys and exception
messages are not logged. Denied and failed calls are audited as well as
successful calls. Config-only operation without an identity DB has no SQLite
call telemetry, as before; tool policy and vault checks still run. Git remains
the separate mutation-content audit trail.

The retained audit-retention setting prunes expired `server='cortex'` call
telemetry at governor construction, as normal retention rather than a schema
migration. Historical upstream audit is not pruned by the memory policy.
Back up telemetry if a longer retention period is needed.

## Unchanged integrations and deployment responsibilities

Local/LDAP identity, existing token resolution/revocation/scopes, OAuth, JSON
memory API, account vaults, headless readiness and the no-global-fallback
contract remain. Ranking, semantic search, janitor, attachments, and sync are
not redesigned. Existing external Nextcloud account-vault sync remains intact;
it is not an upstream MCP and must not be removed from deployment scheduling.

Before cutover, the parent/operator owns:

- A consistent runtime DB/account-vault/git/OAuth backup and rollback image.
- Direct client inventory and consumer-coverage verification, including A2A
  routing for operational capabilities, before removing old Cortex tool use.
- Review of retained defaults and explicit memory grants, especially for old
  `gateway.enabled: false` installations; do not broaden writes by accident.
- Publish/deploy and real authenticated MCP list/call/denial tests, API broker
  404 checks, OAuth/token/LDAP checks, and external Nextcloud sync verification.

Source-only tests use synthetic databases, temporary account stores and
in-process calls. They are not evidence of live deployment or consumer coverage.
The older gateway, v2 design and v2 security documents are labelled historical.
