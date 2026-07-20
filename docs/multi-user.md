# Multi-user Cortex

Cortex v2 keeps the original Obsidian vault as `main` and adds one private,
git-audited vault per user. Local and LDAP identities use the same groups,
vault grants, API tokens, tool permissions, and audit model.

## First run

```bash
cp cortex.example.yaml cortex.yaml
cortex check
cortex init
```

`cortex init` applies SQLite migrations, imports a legacy admin store when
present, creates the first local `admin` account, provisions its private vault,
and prints the initial password once. With HTTP transport, open `/` and sign in.

Useful operator commands:

```bash
cortex user add alice
cortex user passwd alice
cortex user disable alice
cortex vault list
cortex vault provision alice
cortex vault repair alice        # `main` is also accepted
cortex vault archive alice       # reversible move; preserves .git
cortex token mint alice claude-desktop
```

Deleting a user removes their identity, sessions, and tokens but does not erase
their vault. Archive the vault explicitly after the identity decision. Permanent
vault deletion is CLI-only and requires `--force`.

## Grants and isolation

| Identity | Visible vaults | Path scopes |
|---|---|---|
| Config principal | `main` only | configured read/write scopes |
| User | own vault | `**` read/write |
| User through groups | `main` | union of group read/write scopes |
| Admin | all live vaults | `**` read/write |

The vault id and note path are separate values. Cortex chooses an authorized
vault before canonicalizing and scope-checking the path. A foreign vault, an
out-of-scope note, and an absent resource use the same not-found response.

User API tokens may carry path globs. Those constraints narrow every vault the
owner already reaches and can never add a grant. Use one token per AI/client so
it can be revoked independently.

## Shared memory

Groups grant the main vault independently for reads and writes. Example:

```text
group: research
read:  Projects/Research/**
write: Projects/Research/Inbox/**
```

Manage local groups, membership, and scopes under **Administration → People →
Groups**. The panel can override public-safe LDAP JIT/mapping policy in SQLite
and supports dry-run/apply sync; connection and bind-secret settings remain
config/environment-only.

## Vault viewer and API

The same-origin SPA uses `/api/v1`. The viewer renders sanitized Markdown and
GFM, translates Obsidian wikilinks/embeds, shows properties and backlinks, and
searches only visible notes. Note responses include an ETag; attachments use
safe content types, `nosniff`, and a sandboxed CSP.

Session-cookie mutations require `X-Cortex-CSRF`. User bearer tokens can also
call the API and are CSRF-exempt. The hand-maintained contract is
[`openapi.yaml`](openapi.yaml).

## Backup

Back up these together while Cortex is stopped or from a filesystem snapshot:

- `vault.path` (main vault, including `.git`)
- `vaults.root` (private vaults, including each `.git`)
- `database.path` (SQLite identity/gateway/audit state)
- `vaults.archive_dir`
- `cortex.yaml` and the separately managed environment/secret file

Search indexes are rebuildable caches and may be omitted. Restore paths and
ownership, run `cortex migrate`, then `cortex vault repair <id>` as needed.

For a live SQLite-only copy, use its online backup API rather than copying a
WAL database piecemeal:

```bash
sqlite3 data/cortex.sqlite ".backup '/backup/cortex-$(date +%F).sqlite'"
```

Keep that database backup aligned with a snapshot of the vault roots.
