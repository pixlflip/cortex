# Account-owned vaults

Cortex has no global vault. Every live memory directory is keyed by an account
under `vaults.root/<username>`, with its own Git history and rebuildable index.
The retired `main` identifier is rejected, never redirected to an account.

## Authorization and defaults

- MCP calls without a vault select the authenticated account, including admins.
- Missing owner storage fails closed: no fallback to the first available vault.
- Administrators can explicitly select other registered accounts. Administration
  is not a shared memory namespace, and orphan directories confer no API grant.
- Ordinary users see only their own account unless an administrator explicitly
  grants paths in another account vault. Token scopes intersect every read and
  write grant independently; they never confer vault access on their own.
  Legacy group path grants confer no memory access; tool policy is independent.
- Config-only standalone identities address only their named account directory.
  An identity-backed server requires a matching actual account.
- The JSON API returns `default_vault`; no first-available-account fallback exists.
- Service startup and readiness do not read or depend on `vault.path`.

## Explicit cross-account grants

Schema migration 5 adds `vault_grants` to the identity database, initially empty.
Each row binds a grantee account ID to an owner account ID, with separate lists
of read and write globs. Deleting either account cascades the grant, so recreating
a username does not inherit it. Disabled grantees or owners suspend explicit
access. A missing, archived or symlinked vault fails closed. Grants are read on
every API/MCP call: replacing or revoking one needs no restart or new credential.
Already-running operations are not retroactively cancelled.

Only enabled administrators or the trusted local CLI operator may list, replace
or revoke grants. Neither the vault owner nor the grantee can delegate access.
There is no grant-management MCP tool. A grant does not confer administrator,
tool-policy, provisioning, archive, Git-history or whole-vault activity access.
The global write switch and deny-wins memory tool policy still apply to writes.

The local operator commands (example account names, not default grants):

```bash
cortex vault grant set assistant owner --read-scope 'Projects/Example/**' --write-scope 'Projects/Example/Inbox/**'
cortex vault grant list
cortex vault grant revoke assistant owner
```

`set` replaces BOTH lists atomically. Flags are repeatable; an omitted list is
empty and denies that operation. Read-only: omit `--write-scope`. Write-only:
omit `--read-scope`. Content-dependent note mutations (including overwrite,
patch, append, frontmatter/lifecycle edits and a move's source) also require read
access; write-only access can create notes, delete notes or upload attachments,
but cannot use these mutations to read existing content indirectly.
Quote globs so the shell does not expand them. No grant
changes ownership, owner/admin permissions or the default selected vault.

API administration uses `GET /api/v1/admin/vault-grants` and
`PUT`/`DELETE /api/v1/admin/vault-grants/{username}/{vault}`. PUT requires exactly
`{"read_scopes": ["Projects/Example/**"], "write_scopes": []}` (both lists required).
Session mutations require CSRF and same-origin validation. Bearer administration
requires an administrator credential with no token scope restriction; even an
explicit `scopes: ["**"]` token is rejected on these grant-management routes.
Account names are exact, not patterns. Grants accept only canonical vault-relative
globs (up to 128 per operation, 1024 characters each); no normalization, absolute
paths, hidden components, backslashes or traversal components are accepted.

Effective permission is `(any grant glob matches path) AND (any token glob
matches path)`, independently for reads and writes. Unrestricted credentials omit
the second condition; an empty token scope list denies everything. `*` and `?`
stay in one directory segment; `**` crosses directories. Partially overlapping
patterns work without approximation. Discovery's `scopes` and `write_scopes`
remain OR lists, but an element may be an array of globs requiring ALL of them
to match: e.g. `[["Projects/*/report.*", "Projects/Example/*.md"]]`. These
conjunctions are output only, not valid administrative grant/token input.
A grant's vault ID can remain discoverable even when token/glob intersections
match no paths; no content or whole-vault activity metadata is exposed.

For standalone config principals, omitted/null `write_scopes` retains the old
read-scope fallback. Explicit `write_scopes: []` now denies writes. Resolved DB
vault grants always carry an explicit write list; they never use that fallback.

## Upgrade existing installations

This is a breaking correction, not a silent data migration. `vault.path` remains
parseable for migration tooling but is not registered, indexed or served.

1. Stop application writes and all external sync writers. Take a consistent
   backup of both note stores, Git histories, identity database and configuration.
2. Identify the account owner and the actual sync endpoint. Do not choose by
   modification time alone and do not reinterpret group access as an owner grant.
3. Inventory hashes, bodies, attachments and hidden editor/sync configuration.
   Preserve unique files and divergent bodies; do not overwrite or concatenate
   competing text to manufacture a canonical version.
4. Reconcile into the named account path. Keep rollback copies OUTSIDE
   `vaults.root`; do not leave a global alias or symlink in the live registry.
5. Update external sync to that account path. Preserve its remote account mapping,
   exclude Git/private runtime files and verify the actual remote consumer.
6. OAuth client registrations now live beside `database.path`, in
   `oauth-clients.json`. Preserve existing registrations when moving this service
   metadata out of the old vault-derived path. Never put credentials in notes.
7. Rebuild account indexes, start the service, and test authenticated default
   reads, writes, explicit denied `main` requests and non-owner isolation.
8. Verify each pre-migration body and attachment hash at its retained destination,
   including preserved alternatives. Keep unresolved conflicts explicitly labeled.

`cortex init` bootstraps identity/accounts, not an ownerless repository.
`cortex index` and `cortex sync` iterate account directories only. Standalone
`run_sync`/`log` select the configured local principal's account. Sync configuration
belongs under `vaults.sync` or `vaults.sync_overrides.<username>`.

## Review invalidation

Cortex ordinary write, append and patch operations downgrade a `current` note to
`unreviewed` when its body bytes change. A full write may explicitly reaffirm a
state via its `memory_state` argument. Merely copying the old YAML state along
with a changed body is not reaffirmation. YAML-only edits preserve applicability.
This write-route rule does not yet detect external-editor changes automatically;
external sync and filesystem editors remain a separate review-detection boundary.
