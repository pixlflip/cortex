# Upgrading to Cortex 0.3.0

0.3.0 is the first release after 0.2.0 ("Cortex v2"). It contains **breaking
changes**: account-owned storage replaces the shared vault, the web UI and the
upstream MCP broker are gone, and the `gateway` config block is now
`memory_policy`. Nothing is deleted or merged automatically. Plan a short
maintenance window.

If you are still on v1 (single-file config, no identity database), first read
the historical [v1 → v2 procedure](archive/upgrading-v2.md) for how
`cortex migrate` imports legacy admin state, then continue here.

## What changed

| Area | 0.2.0 | 0.3.0 | Action |
| --- | --- | --- | --- |
| Storage | Shared `vault.path` plus per-user vaults | Only `vaults.root/<account>`; `vault.path` is never served | Move notes into an owning account ([account vaults](account-vaults.md)) |
| Cross-account access | Shared vault, group path grants | Admin selection or explicit `vault_grants` | Recreate any needed sharing with `cortex vault grant set` |
| UI | React app, vault viewer, admin dashboard | None; CLI and JSON API only | Remove any reverse-proxy routes for `/`, `/admin`, `/assets` |
| MCP | Memory tools plus proxied upstream tools | Memory tools only | Point clients at their upstream MCP servers directly ([memory policy](memory-policy.md)) |
| Config | `gateway:` | `memory_policy:` (read/write defaults and audit retention migrate) | Rename the block; `gateway.enabled` no longer disables anything |
| Search | Lexical FTS5 | Lexical by default; optional hybrid embeddings (`search:`) | None required ([local semantic search](local-semantic-search.md)) |
| Image | Python 3.11, unpinned dependencies | Python 3.13, digest-pinned base, hash-locked dependencies | Rebuild, or pull `ghcr.io/pixlflip/cortex:0.3.0` |
| Compose | One service with a TTY | `cortex` (HTTP) plus a `cortex-stdio` profile without a TTY | Use `docker compose --profile stdio run --rm -T cortex-stdio` for stdio clients |

Unchanged: user accounts, groups, LDAP, API tokens (existing tokens keep
working), sessions, OAuth client registrations (now kept beside the
database, see step 4), existing identity database contents, git audit
history, and the MCP tool names and arguments for memory tools. `search` and
`context_pack` gained an optional `mode` argument; results gained a
`retrieval_mode` field.

## Procedure

1. **Back up.** Stop Cortex and every external sync writer. Copy the identity
   database (`database.path`), `cortex.yaml`, every vault directory *including*
   its `.git`, and the legacy `vault.path` if you used one.

2. **Update the code.**
   - Docker: `git pull`, then `docker compose build` (or set
     `CORTEX_IMAGE=ghcr.io/pixlflip/cortex:0.3.0`).
   - Bare metal: `git pull && pip install .` in the service virtualenv.

3. **Update `cortex.yaml`.**
   - Rename `gateway:` to `memory_policy:`. Only `default_read_allow`,
     `default_write_allow` and `audit_retention_days` carry over; transport and
     upstream settings are ignored.
   - Move sync settings to `vaults.sync` or `vaults.sync_overrides.<username>`.
   - Optionally add a `search:` block (see `cortex.example.yaml`). Leaving it
     out keeps 0.2.0 search behaviour.

4. **Move shared notes into accounts.** Follow
   [account vaults → Upgrade existing installations](account-vaults.md#upgrade-existing-installations).
   That page covers choosing owners, preserving divergent copies and moving
   `oauth-clients.json` beside the database.

5. **Migrate and check.**

   ```bash
   cortex check
   cortex migrate
   cortex index
   ```

   `cortex migrate` is idempotent and never deletes data. Historical upstream
   broker rows stay in the database, inert.

6. **Start and verify.**
   - `curl -fsS http://127.0.0.1:8765/healthz` reports `"status":"ok"`.
   - An existing user token can `read_note` in its own account and gets "not
     found or not in scope" for another account.
   - `tools/list` shows only memory tools; write tools appear only where
     `writes.enabled` and policy allow them.
   - Old `/api/v1/mcp/*` routes and `/` return 404.

7. **Re-enable sync writers** against the new account paths.

## Rolling back

Stop 0.3.0, reinstall 0.2.0, and **restore the identity database from the
step 1 backup**. 0.3.0 migrates the schema to version 5 (adding
`stdio_mcp_servers` history and `vault_grants`), and 0.2.0 refuses to open a
database newer than the version 3 it knows. Restore the vault directories
too if you moved notes between them. Changes made while 0.3.0 was running
(new users, tokens, grants) are lost with the database rollback, but note
edits remain in each vault's git history.
