# Account-owned vaults

Cortex has no global vault. Every live memory directory is keyed by an account
under `vaults.root/<username>`, with its own Git history and rebuildable index.
The retired `main` identifier is rejected, never redirected to an account.

## Authorization and defaults

- MCP calls without a vault select the authenticated account, including admins.
- Missing owner storage fails closed: no fallback to the first available vault.
- Administrators can explicitly select other registered accounts. Administration
  is not a shared memory namespace, and orphan directories confer no API grant.
- Ordinary users see only their own account. Token scopes narrow paths within
  that account. Legacy group read/write path grants confer no memory access;
  group tool policies are independent and remain available.
- Config-only standalone identities address only their named account directory.
  An identity-backed server requires a matching actual account.
- The web API returns `default_vault`; the viewer does not pick the first vault.
- Service startup and readiness do not read or depend on `vault.path`.

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
