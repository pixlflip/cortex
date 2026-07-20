# Running Cortex on bare metal (Debian / Proxmox LXC)

Docker is the easy path, but Cortex also runs directly on a host with nothing
but Python and git — straight from the repo, no edits required. This is the path
for a Proxmox/Debian LXC, a VM, or a Raspberry Pi.

> This guide is a **template**. It uses placeholder values (paths, a service
> user, an IP). Substitute your own. Cortex stores no infrastructure facts in
> the repo by design.

## 1. Prerequisites

```bash
apt update
apt install -y python3 python3-venv git
```

## 2. Get the code and install

A dedicated service user keeps Cortex's files off root:

```bash
useradd --system --create-home --home-dir /srv/cortex --shell /bin/bash cortex
runuser -u cortex -- bash -lc '
  cd /srv/cortex
  git clone https://github.com/pixlflip/cortex.git app
  cd app
  python3 -m venv .venv
  . .venv/bin/activate
  pip install .
'
```

## 3. Configure

```bash
runuser -u cortex -- bash -lc '
  cd /srv/cortex/app
  cp cortex.example.yaml /srv/cortex/cortex.yaml
'
# Edit /srv/cortex/cortex.yaml: set vault.path to your Obsidian vault,
# define principals/scopes, choose an llm provider if you want semantic search.
```

Point `vault.path` at wherever your notes live (e.g. a Nextcloud-synced folder).
The default config runs locally with no API key and the LLM disabled.

## 4. Initialize and check

```bash
runuser -u cortex -- bash -lc '
  cd /srv/cortex/app && . .venv/bin/activate
  export CORTEX_CONFIG=/srv/cortex/cortex.yaml
  cortex check
  cortex init       # database, first admin, private vault, git baselines
'
```

## 5. Run as a service (systemd)

A unit template ships at [`deploy/cortex.service`](../deploy/cortex.service).
Install it:

```bash
cp /srv/cortex/app/deploy/cortex.service /etc/systemd/system/cortex.service
# edit the unit if your paths differ from the defaults
systemctl daemon-reload
systemctl enable --now cortex
systemctl status cortex
```

The unit runs `cortex serve`. Over **stdio** this is for local MCP clients that
spawn the process; for a long-running background service use **http** transport.
The same server exposes the SPA at `/`, JSON API at `/api/v1`, MCP at the
configured path, and readiness at `/healthz`.

## Periodic sync & audit

Humans editing notes directly in the Obsidian vault — outside any MCP tool
call — don't go through `GitAudit.commit()`, so those edits sit uncommitted
until something else triggers a commit. `cortex sync` closes that gap: it
snapshots any pending vault changes into the git audit trail (actor
`cortex-sync`, so it's distinguishable from MCP-driven commits in `cortex
log`), refreshes the search index so ranked search reflects the latest
content, and — only when `sync.adapter: git` is configured — best-effort
pulls then pushes so the vault stays in sync with a remote. With the default
`sync.adapter: none` the remote step is simply skipped; the local snapshot +
reindex still happens.

Run it on a timer with the shipped unit + timer pair:

```bash
cp /srv/cortex/app/deploy/cortex-sync.service /etc/systemd/system/cortex-sync.service
cp /srv/cortex/app/deploy/cortex-sync.timer /etc/systemd/system/cortex-sync.timer
# edit the unit if your paths differ from the defaults
systemctl daemon-reload
systemctl enable --now cortex-sync.timer
systemctl list-timers cortex-sync.timer
```

The timer fires 5 minutes after boot and every 10 minutes thereafter
(`Persistent=true`, so a missed run while the host was off still happens on
the next boot). Each run is a single `cortex sync` invocation (`Type=oneshot`)
— check `journalctl -u cortex-sync.service` for its output, or call the
`status` MCP tool from a client to see `last_commit_iso` / `last_indexed_iso`
move forward. A failed remote pull/push (adapter: git) is logged but never
fails the unit: the local snapshot and reindex are the durable, important
half of the job, and a transient remote failure self-heals on the next tick.

## 6. Secrets

Never put tokens or API keys in `cortex.yaml`. Supply them via the environment.
With systemd, use an `EnvironmentFile`:

```bash
install -m 600 -o cortex -g cortex /dev/null /srv/cortex/cortex.env
# add lines like:
#   CORTEX_TOKEN_LOCAL=...
#   CORTEX_LLM_API_KEY=...
```

The shipped unit already references `/srv/cortex/cortex.env` if present.

## Upgrading

```bash
runuser -u cortex -- bash -lc '
  cd /srv/cortex/app && git pull && . .venv/bin/activate && pip install .
  export CORTEX_CONFIG=/srv/cortex/cortex.yaml
  cortex migrate
'
systemctl restart cortex
```

See [`upgrading-v2.md`](upgrading-v2.md) for backup, migration, verification,
and rollback details.
