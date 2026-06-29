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
  cortex init       # creates the git audit baseline in your vault
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
spawn the process; for a long-running background service you'll typically use
the **http** transport (a later build step) so clients connect over the network.
Until HTTP lands, use the unit for `cortex check`/health and run stdio on demand.

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
'
systemctl restart cortex
```
