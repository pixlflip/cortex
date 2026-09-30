# Multi-user Cortex

Cortex is a headless memory service. Each named account has its own git-audited
vault; there is no global or shared default vault. Local and LDAP identities
share the same token, tool-policy, and audit infrastructure.

## First run and administration

```bash
cp cortex.example.yaml cortex.yaml
cortex check
cortex init
cortex user add alice
cortex user passwd alice
cortex token mint alice claude-desktop
cortex vault list
cortex vault provision alice
cortex vault repair alice
cortex vault archive alice
```

`cortex init` applies SQLite migrations, imports a legacy identity store when
present, creates the first local `admin` account and provisions its vault.
Passwords and minted tokens are shown once; store them outside the vault.
There is no web dashboard or vault viewer. Use the CLI or authenticated
`/api/v1` JSON API. Readiness is `/healthz`; `/` and former UI routes return 404.
Optional OAuth consent remains available for MCP client authorization.

Deleting a user removes identity, sessions, and tokens, not their note store.
Archive their vault explicitly; permanent vault deletion requires CLI `--force`.

## Isolation

- An omitted vault selects the authenticated account, including administrators.
- Ordinary accounts access their own vault only. A token can narrow paths,
  never broaden its owner's access.
- Administrators must explicitly select another account for cross-account work.
- Legacy group path grants do not confer account-vault access. Group tool
  permissions remain independent.
- Missing owner storage fails closed. The retired `main` identifier is rejected.

See [account-owned vaults](account-vaults.md) for the authoritative storage and
migration contract. Foreign vaults and absent/out-of-scope paths use the same
not-found response to avoid existence leaks.

## API

User bearer tokens can call `/api/v1`. Existing session-cookie authentication
is retained; its mutations require `X-Cortex-CSRF`. The API contract is
[openapi.yaml](openapi.yaml). Notes use ETags; attachments use bounded reads,
safe content types, `nosniff`, and sandboxed CSP where applicable.

## Backup

Back up these together while stopped or from a consistent filesystem snapshot:

- `vaults.root`, including each account's `.git` history
- `database.path` and the OAuth registration file beside it
- `vaults.archive_dir`
- public-safe configuration and separately protected secret files

Indexes are rebuildable caches. Preserve any legacy migration source separately;
it is not a live default vault. Use SQLite's online backup API rather than copying
a live WAL database piecemeal, and align that backup with the vault snapshot.
