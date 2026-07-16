# Governed MCP gateway

Give an AI Cortex as its only MCP server. Cortex exposes its built-in memory
tools plus explicitly registered upstream tools under stable namespaces such as
`calendar.list_events`. The connecting user token determines what appears.

## Policy model

Permissions are glob rules over `<server>.<tool>` attached to users or groups.
`cortex.*` names built-ins; every other prefix names an upstream server.

- Any matching `deny` wins across user and group rules.
- Otherwise any matching `allow` permits the tool.
- With no rule, deterministic Cortex reads are allowed by default.
- Cortex writes and all external tools are denied by default.
- Discovery filtering and invocation use the same resolver; each call is
  rechecked, so a stale client cannot invoke a newly denied tool.

The global `writes.enabled` switch still removes Cortex mutation tools entirely.
Configure rules under **Administration → Gateway → Permission matrix**.

## Register an upstream

The admin panel accepts a namespace, Streamable HTTP URL, optional bearer-token
environment variable name, and optional header→environment mappings. It tests
the connection and caches tool schemas. Refreshes hot-replace the live namespace
without restarting Cortex. Removing/disabling a server removes its tools.

Credential values never enter SQLite or API responses. For example:

```yaml
gateway:
  enabled: true
  allow_user_servers: false
  block_private_networks: true
  outbound_allowlist: ["mcp.example.com", "*.trusted.example"]
```

```bash
export CALENDAR_MCP_TOKEN='…'
```

Enter `CALENDAR_MCP_TOKEN`—not its value—as the server's auth environment
reference. Personal server registration is off unless
`gateway.allow_user_servers` is enabled.

## Runtime boundaries

- Only absolute HTTP(S) URLs are accepted; URL credentials are rejected.
- DNS is checked on every connection. Loopback, private, link-local,
  unspecified, multicast, and reserved addresses are blocked by default.
- An optional hostname allowlist narrows egress further. HTTP redirects are not
  followed to another host.
- Calls have configurable timeouts, a global concurrency bound, and lazy
  per-server keep-alive pools. Rotating a referenced environment secret
  replaces its pool without persisting the credential. Safe discovery gets
  one bounded retry; tool calls are never replayed because they may mutate an
  upstream system. Three consecutive upstream failures open a short circuit
  so one dead server does not stall every client.
- Ambient HTTP proxy variables are ignored so DNS/SSRF validation and the
  eventual socket destination remain in the same trust boundary.
- Upstream descriptions are control-character stripped, length capped, and
  always namespaced. Results remain untrusted upstream content; registering a
  server is a trust decision.

Only Streamable HTTP upstreams are active today. `stdio-cmd` remains disabled by
default and is not executed by the gateway runtime.

## Audit

Every allowed, denied, and failed MCP call records identity, server/tool,
decision, vault, latency, error class, a SHA-256 argument digest, and a bounded
list of argument keys/encoded size. Argument values, note content, credentials,
and tool results are never copied into the audit table. Retention is controlled
by `gateway.audit_retention_days`.

View/export telemetry under **Administration → Audit**. Vault mutations retain
their separate per-vault git history, which answers what changed and how to
revert it; tool telemetry answers who called what and whether it was allowed.
