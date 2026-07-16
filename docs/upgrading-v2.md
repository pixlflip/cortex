# Upgrade from Cortex v1 to v2

The v2 migration is forward-only and idempotent. It leaves `vault.path` in
place as the main/shared vault, imports legacy admin identities into SQLite,
and provisions a private vault for every database user.

## Before upgrading

1. Stop Cortex.
2. Back up the main vault including `.git`, `cortex.admin.json`, config, and
   environment/secret file.
3. Create a filesystem snapshot if available.
4. Update the package/image and compare your config with
   `cortex.example.yaml`; add `vaults:` and `gateway:` deliberately.

## Migrate

```bash
cortex check
cortex migrate
cortex db status
cortex vault list
```

`cortex migrate` applies all pending SQLite migrations, imports legacy admin
state once, guarantees a local admin exists, adopts the existing main vault,
and creates/repairs each user's private vault. It is safe to rerun after an
interruption. Save a newly printed admin password immediately.

Then start Cortex and verify:

```bash
curl -f http://127.0.0.1:8765/healthz
cortex vault repair main
```

Sign in, review users/groups and shared-vault scopes, mint fresh per-user AI
tokens, and register upstream MCP servers. Legacy config principals continue to
target only `main`; legacy client tokens remain available during transition but
should be replaced with user tokens.

## Docker Compose

The v2 Compose file persists both `./vault` and `./data`. Do not recreate the
service until both mounts and `cortex.yaml` are present.

```bash
docker compose build
docker compose run --rm cortex migrate
docker compose up -d
docker compose ps
```

## Rollback

Application rollback is possible only while the older binary understands the
on-disk schema. v1 does not understand v2 schema 2, so the reliable rollback is
to stop Cortex, restore the pre-upgrade database/admin file and vault snapshot,
then run the earlier image. Do not edit `schema_version` manually.

