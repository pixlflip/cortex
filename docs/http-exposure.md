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

## 2. Put TLS in front (reverse proxy)

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

## 3. Client compatibility — read this before connecting

The transport (Streamable HTTP over HTTPS) is what every current MCP client
expects. **Authentication is where clients differ:**

| Client | Works with bearer today? | Notes |
|---|---|---|
| Anthropic API `mcp_servers` connector | ✅ | Pass the token as `authorization_token` |
| Custom code / your own MCP client | ✅ | Send `Authorization: Bearer …` |
| MCP Inspector, n8n, scripts | ✅ | Bearer header |
| ChatGPT (developer mode) | ⚠️ partial | Header auth works in some paths; OAuth preferred |
| **Claude.ai one-click connector UI** | ❌ not yet | The UI only offers OAuth fields — no bearer field |
| **ChatGPT / Grok one-click connector UI** | ❌ not yet | Expect OAuth 2.1 + dynamic client registration |

So bearer auth covers programmatic and API-driven use **today**. The one-click
"add a custom connector" buttons in Claude.ai, ChatGPT, and Grok are built
around **OAuth 2.1** (protected-resource metadata + dynamic client registration
+ PKCE), which Cortex will add as the next step. Cortex already serves the
`/.well-known/oauth-protected-resource` discovery document, so the OAuth layer
slots in on top of this without changing the tool or scoping model.

## 4. Verify

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
