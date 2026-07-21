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

## Lazy discovery

Cortex keeps upstream tool schemas out of the initial catalog. Built-in Cortex
tools remain available, alongside three compact gateway tools:

- `search_mcps(query="")` lists or searches only upstream namespaces with at
  least one tool authorized for the current identity. Results contain namespace,
  bounded description, and authorized tool count, but no tool schemas.
- `peek_mcp(name)` returns authorized names such as `calendar.list_events` for
  one visible namespace. It returns names only, without descriptions or
  parameter schemas.
- `load_mcp(name)` activates that namespace's currently authorized tools for
  the current MCP transport session. Loads are cumulative within the session.

After a successful load, Cortex sends the standard
`notifications/tools/list_changed` notification. A subsequent standard
`tools/list` returns the loaded tools as first-class MCP tools with their full
schemas. Cortex advertises `tools.listChanged: true`, so no Cortex-specific
client extension or generic invocation proxy is required.

Load state belongs to the transport session, not the bearer token or identity.
A second connection using the same credentials has an independent catalog, and
a reconnect starts again from the compact baseline. Loading is not an
authorization grant: policy is rechecked both when listing and on every call.

Clients that ignore `notifications/tools/list_changed` must refresh their tool
list manually or reconnect. Cortex can change future discovery responses, but
it cannot remove schemas already copied into a client's model context or
reclaim tokens that client already consumed.

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

## Local stdio upstreams

Local processes are a privileged execution boundary and are disabled by
default. Only administrators can register them; `allow_user_servers` never
widens this rule. Enable the feature with exact, operator-controlled paths:

```yaml
gateway:
  allow_stdio_servers: true
  stdio_allowed_executables:
    - /opt/cortex-mcp/harmless/.venv/bin/harmless-mcp-server
  stdio_allowed_workdirs:
    - /opt/cortex-mcp
```

```json
{
  "name": "harmless",
  "transport": "stdio-cmd",
  "command": "/opt/cortex-mcp/harmless/.venv/bin/harmless-mcp-server",
  "args": ["run", "--transport", "stdio"],
  "cwd": "/opt/cortex-mcp/harmless",
  "env_refs": {"SERVICE_TOKEN": "HARMLESS_MCP_TOKEN"},
  "global": true
}
```

Install each MCP in a dedicated root/operator-managed virtual environment and
allowlist its dedicated entry point. **Never allowlist a shell, generic Python
or Node interpreter, package manager, `env`, or `uvx`**: doing so would turn a
structured registration API into arbitrary command execution. Paths are
resolved before exact executable comparison; working directories must resolve
beneath an allowed root, so traversal and symlink escapes are rejected. The
child runs as the same unprivileged service identity as Cortex—there is no
sudo, setuid helper, or privilege escalation.

Put credentials in the service manager's protected `EnvironmentFile` and map
only child-variable names to parent-variable names. Values are resolved at
launch, included only in a one-way connection fingerprint, and never stored or
returned. Arguments are visible administrative configuration, **not secret
storage**. Restrict the service user's filesystem permissions to only the MCP
installation and data it needs.

Cortex starts one child lazily, initializes and reuses its MCP session, and
serializes session operations under the gateway's global concurrency bound.
Changing a path, arguments, working directory, or referenced value replaces
the child. Disable, delete, failed discovery, timeout, and Cortex shutdown close
stdin, terminate after a bounded grace period, kill if necessary, and reap the
process. Tool calls are never retried; idempotent discovery retains one retry.
Stderr is not stored or returned, and local failures use generic diagnostics.
For troubleshooting, verify the executable bit, exact resolved allowlist path,
working-directory root, referenced variable presence, and service-user access.

## Audit

Every allowed, denied, and failed MCP call records identity, server/tool,
decision, vault, latency, error class, a SHA-256 argument digest, and a bounded
list of argument keys/encoded size. Argument values, note content, credentials,
and tool results are never copied into the audit table. Retention is controlled
by `gateway.audit_retention_days`.

View/export telemetry under **Administration → Audit**. Vault mutations retain
their separate per-vault git history, which answers what changed and how to
revert it; tool telemetry answers who called what and whether it was allowed.
