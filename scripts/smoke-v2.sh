#!/usr/bin/env bash
set -euo pipefail

image="${1:-cortex:ci}"
name="cortex-v2-smoke-${RANDOM}"
root="$(mktemp -d)"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$root"
}
trap cleanup EXIT

mkdir -p "$root/vault" "$root/data"
# mktemp creates a 0700 directory owned by the host runner.  The image runs as
# its unprivileged `cortex` user, so it must be able to traverse the bind mount.
chmod 0755 "$root"
# The host runner UID is unrelated to the image's unprivileged UID.  These are
# disposable smoke-test mounts and must be writable by that container user.
chmod 0777 "$root/vault" "$root/data"
printf '# Smoke vault\n' >"$root/vault/Welcome.md"
cat >"$root/cortex.yaml" <<'YAML'
vault:
  path: /data/vault
  git: { enabled: true, actor_name: cortex, actor_email: cortex@localhost }
vaults:
  root: /data/data/vaults
  index_dir: /data/data/indexes
  archive_dir: /data/data/archive
database: { path: /data/data/cortex.sqlite }
index: { path: /data/data/main.index.sqlite }
principals: []
auth: { enabled: true, oauth_enabled: false }
admin: { enabled: true, path: /data/cortex.admin.json }
server:
  transport: http
  host: 0.0.0.0
  port: 8765
  path: /mcp
writes: { enabled: false }
gateway: { enabled: true, block_private_networks: true }
llm: { provider: none }
YAML

run=(docker run --rm -v "$root:/data" "$image")
"${run[@]}" init >/dev/null
"${run[@]}" user add smoke --password smoke-password >/dev/null
token="$("${run[@]}" token mint smoke smoke-test | tail -n 1)"
test -d "$root/data/vaults/smoke/.git"

docker run -d --name "$name" -p 127.0.0.1:18765:8765 \
  -v "$root:/data" "$image" serve >/dev/null
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:18765/healthz >/dev/null; then break; fi
  sleep 1
done
curl -fsS http://127.0.0.1:18765/healthz | grep -q '"status":"ok"'
curl -fsS http://127.0.0.1:18765/api/v1/auth/me \
  -H "Authorization: Bearer $token" | grep -q '"username":"smoke"'
curl -fsS -X POST http://127.0.0.1:18765/mcp \
  -H "Authorization: Bearer $token" \
  -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cortex-smoke","version":"1"}}}' \
  | grep -q '"result"'
echo "Cortex v2 image smoke test passed"
