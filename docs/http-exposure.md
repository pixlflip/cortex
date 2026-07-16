# Exposing Cortex over HTTP (remote MCP)

Local clients use **stdio**. To let remote/web clients connect, run Cortex over
**Streamable HTTP** with bearer-token authentication, behind a TLS-terminating
reverse proxy.

## 1. Configure

```yaml
server:
  transport: http
  host: 127.0.0.1            # bind locally; the proxy faces the internet
  port: 8765
  path: /mcp
  public_url: https://cortex.example.com   # your external HTTPS URL
  allowed_origins: ["https://claude.ai", "https://chatgpt.com"]  # optional

principals:
  - name: web-assistant
    scopes: ["Public/**"]
    token_env: CORTEX_TOKEN_WEB_ASSISTANT   # the bearer token, from the env

auth:
  enabled: true
```

Set the token in the environment (never in the config):

```bash
export CORTEX_TOKEN_WEB_ASSISTANT="$(openssl rand -hex 32)"
cortex serve     # serves Streamable HTTP at 127.0.0.1:8765/mcp
```

Each request must send `Authorization: Bearer <token>`. The token maps to its
principal; the principal's scopes are enforced on every tool call. An unknown or
missing token gets `401`.

## 2. Web app and admin panel

Run `cortex init` once before exposing HTTP. It initializes the git audit
baseline and creates the admin UI state file with a generated password:

```bash
cortex init
# admin username: admin
# admin password: <shown once>
```

HTTP deployments with an initialized SQLite database expose the same-origin SPA
at `/`. Sign in with the generated local admin to manage users, groups and
shared scopes, private vaults, LDAP sync, user tokens, upstream MCP servers,
deny-wins tool rules, and audit telemetry. Each person creates a separate token
per AI client; token path scopes may narrow that client's vault access.

## 3. Put TLS in front (reverse proxy)

Cortex speaks plain HTTP and expects a proxy to terminate TLS. Example (Caddy):

```
cortex.example.com {
    reverse_proxy 127.0.0.1:8765
}
```

nginx is equivalent — proxy `https://cortex.example.com/mcp` →
`http://127.0.0.1:8765/mcp`, and pass through the `Authorization`,
`Accept`, and `Mcp-Session-Id` headers. Behind a trusted proxy you can leave
`allowed_origins`/`allowed_hosts` empty; for direct exposure, set them so
DNS-rebinding protection is enabled.

## 4. Two auth modes

Cortex supports both, on the same Streamable HTTP transport. Pick by who needs
to connect.

### Bearer only (default — `auth.oauth_enabled: false`)

Each request sends `Authorization: Bearer <principal token>`. Simple, great for
programmatic and API-driven clients.

### OAuth 2.1 (`auth.oauth_enabled: true`) — for one-click connector UIs

Cortex runs a full authorization server: protected-resource + AS metadata,
**dynamic client registration**, and an **authorization-code + PKCE** flow. The
browser is redirected to a Cortex **consent page** where the user pastes their
principal token; the issued OAuth access token is bound to that principal, and
scoping is enforced exactly as everywhere else. Static bearer tokens keep
working in this mode too, so nothing below regresses.

```yaml
server:
  transport: http
  public_url: https://cortex.example.com   # REQUIRED and correct — it's the OAuth issuer
auth:
  enabled: true
  oauth_enabled: true
```

### Client compatibility

| Client | Bearer mode | OAuth mode |
|---|---|---|
| Anthropic API `mcp_servers` connector (`authorization_token`) | ✅ | ✅ |
| Custom code / MCP Inspector / n8n / scripts | ✅ | ✅ |
| **Claude.ai** one-click connector UI | ❌ (no bearer field) | ✅ |
| **ChatGPT** connector UI / developer mode | ⚠️ partial | ✅ |
| **Grok** custom connector UI | ❌ | ✅ |

To add Cortex in Claude.ai / ChatGPT / Grok: enable OAuth, point the connector
at `https://cortex.example.com/mcp`, let it auto-discover and register, and when
it sends you to the Cortex consent page, paste the principal token for the scope
you want that connector to have.

> OAuth authorization state is in-memory: a server restart invalidates issued OAuth tokens
> and registered clients, so connectors re-authorize. Persisting them is a
> planned enhancement. Principal tokens should be high-entropy
> (`openssl rand -hex 32`) — at the consent step they are the login credential.

## 5. Verify

```bash
# 401 without a token:
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://cortex.example.com/mcp \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# 200 + capabilities with a valid token (initialize handshake):
curl -s -X POST https://cortex.example.com/mcp \
  -H 'Authorization: Bearer '"$CORTEX_TOKEN_WEB_ASSISTANT" \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
```

Read [`mcp-gateway.md`](mcp-gateway.md) before registering upstream servers,
especially the SSRF and untrusted-result boundaries.
