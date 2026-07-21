#!/usr/bin/env bash
set -euo pipefail

image="${1:-cortex:ci}"
name="cortex-v2-smoke-${RANDOM}"
volume="${name}-data"
root="$(mktemp -d)"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm -f "$volume" >/dev/null 2>&1 || true
  rm -rf "$root"
}
trap cleanup EXIT

docker volume create "$volume" >/dev/null
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
admin: { enabled: true, path: /data/data/cortex.admin.json }
server:
  transport: http
  host: 0.0.0.0
  port: 8765
  path: /mcp
writes: { enabled: false }
gateway: { enabled: true, block_private_networks: true }
llm: { provider: none }
YAML

# Use a named volume so Docker initializes /data with the image's real cortex
# ownership. A host bind mount is owned by the runner and modern Git correctly
# rejects it as a different owner's worktree inside the unprivileged container.
mounts=(-v "$volume:/data" -v "$root/cortex.yaml:/data/cortex.yaml:ro")
docker run --rm -v "$volume:/data" --entrypoint sh "$image" \
  -c "printf '# Smoke vault\\n' > /data/vault/Welcome.md"
run=(docker run --rm "${mounts[@]}" "$image")
"${run[@]}" init >/dev/null
"${run[@]}" user add smoke --password smoke-password >/dev/null
token="$("${run[@]}" token mint smoke smoke-test | tail -n 1)"
docker run --rm -v "$volume:/data" --entrypoint test "$image" \
  -d /data/data/vaults/smoke/.git

docker run -d --name "$name" -p 127.0.0.1:18765:8765 \
  "${mounts[@]}" "$image" serve >/dev/null
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
