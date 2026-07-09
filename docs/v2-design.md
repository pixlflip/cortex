# Cortex v2 Design — Multi-user, Multi-vault, Web App, MCP Gateway

> Status: **canonical v2 design.** This document extends
> [`ARCHITECTURE.md`](../ARCHITECTURE.md) (the v1 canonical design, which
> remains authoritative for everything it covers). Where the two disagree,
> this document wins for v2 work. It is written so that an agent picking up
> any issue in the v2 tree (#35–#55) can build from it cold.

Like the v1 document, this is intentionally infrastructure-agnostic: no IP
addresses, no hostnames, no secrets. Everything environment-specific is a
config value with a sane default.

---

## 1. What v2 is

v1 Cortex is a single-vault, credentialed, scoped, audited memory server: one
Obsidian vault, config-file `principals`, an MCP front door, git as the audit
trail. v2 grows it into a **small multi-user memory host** without changing
that core:

| | v1 (today) | v2 |
|---|---|---|
| Identities | config `principals` + admin-store AI clients | + real **user accounts** in SQLite (local password or LDAP/AD), groups, sessions, per-user tokens |
| Vaults | one vault (`vault.path`) | + **one vault directory + one git repo per user**, under a configurable root; the main vault remains as the shared vault |
| Human UI | minimal server-rendered admin page | **React/Vite SPA**: admin panel + Obsidian vault viewer, served same-origin, over a JSON `/api/v1` API |
| MCP surface | Cortex's own vault tools | + a **gateway** proxying registered external MCP servers, permission-gated per user/group |
| Audit | git commit per vault mutation | git per-vault (unchanged) + **SQLite `tool_call_audit`** for tool-call access telemetry |

Everything in v1's safety model still holds; §7 below extends it.

### Non-goals (v2)

- Not a general LDAP admin tool — Cortex *consumes* LDAP identity, it never
  writes to the directory.
- Not a hosted multi-tenant SaaS — one install serves one household / team /
  lab. There is no tenant isolation beyond users and vaults.
- Not an Obsidian replacement — the vault viewer is read-oriented; humans
  keep editing with Obsidian or any Markdown editor.
- Not an MCP marketplace — the gateway proxies servers an admin (or a user,
  behind a toggle) explicitly registered; it discovers nothing on its own.

---

## 2. Starting point: the post-A1 auth model

A1 (#35) landed the security baseline v2 builds on. The parts that matter for
everything below:

- **Source-tagged subjects.** Token resolution returns `(principal, subject)`
  where the subject encodes *which store* authenticated the token: config
  principals use their plain name; admin-store AI clients are namespaced
  `client:<name>`. Per-call principal resolution consults **only** the store
  named by the subject — an identity in one store can never inherit the
  scopes of a same-named identity in another. Config load and the
  authenticator both refuse names that squat on a reserved prefix.
- **Canonicalize-then-check.** Every path-addressed tool canonicalizes the
  caller-supplied path (rejecting traversal, absolute paths, hidden
  components, non-note suffixes) *before* the scope check, and then operates
  on the canonical path. Out-of-scope and absent are indistinguishable to the
  caller.
- **Random per-install secrets.** Admin session cookies are HMAC-signed with
  a random secret minted at `cortex init`, carry issued-at/expiry, and the
  store refuses to serve a login flow before initialization.

v2 **generalizes** the subject model rather than replacing it: user-account
tokens get their own namespace (`user:<name>`), resolved only against the
SQLite user store. The three sources never cross-resolve.

---

## 3. Identity model

### 3.1 Three identity sources, one resolution order

A bearer token presented to the MCP endpoint (or `/api/v1`) resolves in this
fixed order, stopping at the first match:

1. **Config principals** (`principals:` in `cortex.yaml`) — static identities
   for agents and fixed integrations against the **main/shared vault**.
   Subject = plain name. Unchanged from v1.
2. **User API tokens** (SQLite `api_tokens`) — per-user tokens minted in the
   web app. Subject = `user:<username>`. New in v2.
3. **Legacy admin-store AI clients** (`cortex.admin.json`) — subject =
   `client:<name>`. Kept working through the v2 transition; A3 migrates this
   store into SQLite and the admin UI into the SPA, after which this source
   is import-only.

Each source owns a disjoint subject namespace; config validation and the
authenticator enforce that no name can squat on another source's prefix
(the A1 model, extended with `user:`). SPA **session cookies** are a fourth
credential kind but resolve only to users (source 2) — a cookie can never
authenticate as a config principal or AI client.

### 3.2 Users

A user is a row in SQLite with an `auth_source` of `local` or `ldap`:

- **Local users** carry a PBKDF2 salt+hash (same primitives the admin store
  uses today). Created by an admin in the web app; password change/reset in
  the SPA.
- **LDAP users** carry a DN and *no password material* — authentication is a
  bind against the directory at login time. Users are pulled (or created on
  first successful login, config choice) and their group memberships mapped
  to Cortex groups. Cortex never stores LDAP passwords; the service-account
  bind credential comes from an env var only (§7).

**Groups** are named sets of users, either local or mapped from LDAP groups.
Groups are the unit of shared-vault scope grants (§6.4) and of gateway tool
permissions (§8.4). A user's effective identity = their user row + the union
of their groups.

**Admins** are users with an `is_admin` flag (or membership in a designated
admin group). Admin implies the macro view (§6.3) and access to the admin
panel. The v1 single `admin` login migrates to a local user with this flag.

### 3.3 Credentials per identity

| Credential | Who | Used by | Lifetime |
|---|---|---|---|
| Config principal token (`token_env`) | agents / static integrations | MCP | as long as configured |
| User API/MCP token | a user | MCP + `/api/v1` (bearer) | created/revoked in SPA; optional expiry |
| Session cookie | a user | SPA / `/api/v1` | short TTL, sliding; HttpOnly |
| Admin-store client token | legacy AI clients | MCP | until migrated (A3) |

Tokens are stored hashed (salt + PBKDF2, with a stored prefix for O(1)
candidate lookup — the admin-store pattern), shown once at creation, and
revocable individually.

---

## 4. Data model (SQLite)

One SQLite database, `data/cortex.sqlite`, owned by the server process. It
holds **identity and telemetry — never note content**. Notes live only in
vaults; git remains the audit trail for their mutation (§7.2). Schema
versioning/migrations are established in A3 and extended by later
workstreams. Sketch (columns indicative, not exhaustive; `*` = primary key):

```
users            (id*, username UNIQUE, display_name, email,
                  auth_source 'local'|'ldap', password_salt, password_hash,   -- NULL for ldap
                  ldap_dn,                                                    -- NULL for local
                  is_admin BOOL, disabled BOOL, created_at, last_login_at)

groups           (id*, name UNIQUE, source 'local'|'ldap', ldap_dn, created_at)

user_groups      (user_id → users, group_id → groups, PK(user_id, group_id))

sessions         (id*, token_hash, user_id → users,
                  created_at, expires_at, last_seen_at)                       -- SPA cookies

api_tokens       (id*, user_id → users, name,                                 -- "claude-desktop"
                  token_prefix, salt, token_hash,
                  scopes_json,                                                -- optional narrowing, §6.2
                  created_at, expires_at, last_used_at, revoked_at)

mcp_servers      (id*, name UNIQUE, url, transport,                           -- streamable-http | sse | stdio-cmd
                  auth_env,                                                   -- env var NAME holding upstream secret; never the secret
                  owner_user_id → users NULL,                                 -- NULL = admin/global registration
                  visibility 'group'|'personal', enabled BOOL, created_at)

tool_permissions (id*, subject_type 'user'|'group', subject_id,
                  server_id → mcp_servers NULL,                               -- NULL = Cortex's builtin tools
                  tool_pattern,                                               -- glob over "<server>.<tool>" / builtin name
                  effect 'allow'|'deny',
                  created_by → users, created_at)

tool_call_audit  (id*, ts, subject,                                           -- source-tagged: user:x / client:y / plain principal
                  user_id → users NULL, api_token_id → api_tokens NULL,
                  server,                                                     -- 'cortex' or mcp_servers.name
                  tool, decision 'allowed'|'denied'|'error',
                  error_kind, duration_ms,
                  args_digest)                                                -- hash/shape only: NO argument values,
                                                                              -- NO note contents, NO secrets
```

**Who populates what** (workstream → tables):

| Workstream | Tables |
|---|---|
| **A3** (#37) | schema + migrations; `users`, `groups`, `user_groups` structure; migrates `cortex.admin.json` (admin login, roles, clients) into SQLite |
| **A4** (#38) | `users` (local), `sessions`, `api_tokens` |
| **A5** (#39) | `users`/`groups` rows with `auth_source/source = 'ldap'`; group mapping in `user_groups` |
| **B1** (#41) | vault registry metadata (a small `vaults` table or derived-from-disk — B1's call; the design constraint is only that the *filesystem* stays the source of truth for vault content) |
| **D1** (#50) | `tool_permissions` (builtin tools), `tool_call_audit` (builtin calls) |
| **D2** (#51) | `mcp_servers`, `tool_permissions` (proxied tools) |
| **D3** (#52) | `tool_call_audit` (proxied calls) |

Deny-wins semantics for `tool_permissions` are specified in §8.4.

---

## 5. On-disk layout

Everything stateful that v2 adds lives under one `data/` directory (location
configurable; relative paths resolve next to `cortex.yaml`):

```
data/
  cortex.sqlite               # identity + gateway DB (§4). Never committed.
  indexes/
    main.index.sqlite         # search index for the main/shared vault
    <username>.index.sqlite   # one rebuildable search index per user vault
  vaults/                     # per-user vaults root (vaults.root)
    <username>/               # ONE Obsidian vault per user
      .git/                   # ONE git repo per vault — its audit trail
      ...notes (.md)
```

- **`vault.path` (the main/shared vault) is unchanged** — its own directory,
  its own git repo, wherever v1 put it. It is *not* moved under
  `data/vaults/`. Config principals and shared-vault group grants (§6.4)
  target it.
- **Per-user vaults** are provisioned by B1 on user creation (or first
  login): directory named for the username (sanitized to a filesystem- and
  scope-safe slug), `git init`, an initial commit, a welcome note. Deleting
  a user never deletes their vault directory by default — it is unregistered
  and left on disk for the operator.
- **One git repo per vault.** Actor/reason commit conventions from v1 apply
  identically in each; user mutations commit as `user:<username> via mcp`
  (or `via web`). Sync adapters configure per vault, defaulting to `none`;
  the v1 hard rule stands per vault: `.git/` never propagates to a file-sync
  backend.
- **Indexes are rebuildable caches**, one per vault, kept outside the vaults
  so they are never committed or synced.
- The SQLite DB, indexes, and `data/` in general are in `.gitignore` and
  never inside any vault — so no vault scope, sync adapter, or janitor rule
  can ever reach them (§7.3).

Illustrative config (shape only — the real schema lands with the
implementing issues):

```yaml
vaults:
  root: ./data/vaults        # per-user vaults live here
  auto_provision: true       # create a vault on user creation / first login

database:
  path: ./data/cortex.sqlite

ldap:
  enabled: false
  url: ldaps://…             # config value, no default host
  bind_dn: cn=cortex,…       # service account DN
  bind_password_env: CORTEX_LDAP_PASSWORD   # env NAME only — never a value
  user_base: …
  group_base: …
  admin_group: …             # LDAP group granted is_admin

gateway:
  enabled: false
  allow_user_servers: false  # users may register personal MCP servers
```

---

## 6. Scoping model v2

### 6.1 From "principal → scopes" to "identity → set of (vault, scopes)"

v1 scoping maps a principal to a list of path globs over *the* vault. v2
generalizes the grant to a set of **(vault, path-scopes)** pairs. Nothing
about how a single grant is evaluated changes: within a vault, the A1
pipeline applies verbatim — canonicalize the caller path first, check the
canonical path against the globs (directory-bounded `*`, only `**` crosses
`/`), operate on the canonical path, report out-of-scope as
indistinguishable-from-absent. The vault dimension is resolved **before**
any path logic runs; a path can never name a vault.

Default grants by identity source:

| Identity | Vault(s) | Scopes |
|---|---|---|
| Config principal | main/shared vault only | its configured `scopes` / `write_scopes` (v1, unchanged) |
| User | own vault | `**` read+write (container view) |
| User (via groups) | main/shared vault | the union of their groups' grants (§6.4) |
| Admin, janitor | all vaults | macro view (§6.3) |

### 6.2 Container view (users)

A user's MCP client and vault-viewer session operate **inside their own
vault**: paths are vault-relative exactly as in v1, and the other vaults do
not exist from their perspective — not listed, not searchable, no error
wording that reveals them. Shared-vault access, when granted, is an explicit
second surface (§6.4), not a widening of the container. A user's `api_tokens`
may carry an optional `scopes_json` narrowing (path globs within the vaults
the user can already reach) so a user can mint a token for one project folder
— a token can only ever narrow, never widen, its owner's grants.

### 6.3 Macro view (admin + janitor)

Admins and the janitor see **across** vaults. Cross-vault addressing is a
(vault, path) pair — carried as an explicit `vault` parameter/field on macro
APIs and macro tools, never smuggled into the path string. Uses: the admin
panel's vault administration and aggregated audit (C3), macro janitor/sync
runs and cross-vault reporting (B4). The janitor's macro view is still bound
by its v1 category prohibitions plus the new one in §7.3.

### 6.4 Shared-vault group grants

The main vault is where common knowledge lives. Groups map to scope grants
on it — e.g. group `research` → read `Projects/Research/**`, write
`Projects/Research/Inbox/**`. A user's shared-vault scopes are the union of
their groups' grants; read and write scopes stay independent, with write
falling back to read exactly as v1 `write_scopes` does. This replaces the
admin store's "roles" concept (A3 migrates roles → groups).

---

## 7. Safety model v2

Extends [`ARCHITECTURE.md` §4](../ARCHITECTURE.md); every v1 rule stands.
Restating the v1 list with v2 amendments (**bold**):

1. Safety is enforced **server-side at the tool/API layer** — now including
   every `/api/v1` route and every gateway call, never the SPA.
2. Writes are **opt-in** (`writes.enabled`, default off); deletes remain the
   most-gated operation; every mutation is a git commit in **that vault's**
   repo.
3. Reads are identity-scoped **per (vault, path)**; no grant → not visible.
   **Cross-vault invisibility is absolute for non-macro identities.**
4. Credential→identity mapping is mandatory before any non-local exposure —
   now across **four credential kinds** (§3.3), each source-tagged so scopes
   never cross-resolve.
5. The janitor cannot touch the four protected categories (scopes,
   principals, credentials, its own ruleset) — **and now also the SQLite
   identity/gateway DB and the session/token tables inside it.** The DB
   lives outside every vault root (§5), so no vault-path rule can reach it;
   the janitor additionally gets no code path that opens it for writing.
   Same reasoning as v1: git would faithfully commit a privilege escalation,
   so the class of change is *prevented*, not audited.
6. Everything is auditable: **git for vault mutations (per-vault), SQLite
   `tool_call_audit` for tool-call access telemetry** (§7.2). Complementary,
   not redundant.
7. No secrets in the repo, image, or DB: LDAP bind credentials and upstream
   MCP-server secrets are referenced by **env var name** only (`auth_env`,
   `bind_password_env`); token/password columns store salted hashes;
   `tool_call_audit` stores argument digests, never values.

### 7.1 Web-app surface

- SPA served **same-origin** by the existing Starlette server — no CORS
  opening, no separate origin to secure.
- Session cookies: HttpOnly, SameSite=Lax, Secure under HTTPS, HMAC-signed
  with the per-install random secret, expiring server-side via `sessions`.
- Every state-changing `/api/v1` route requires CSRF protection when
  cookie-authenticated; bearer-authenticated calls are CSRF-immune by
  construction.
- Login is rate-limited; failures are uniform (no user-exists oracle, and
  LDAP vs local failure is indistinguishable to the caller).

### 7.2 Audit split — git vs `tool_call_audit`

- **Git answers "what changed in memory, by whom, and how do I undo it?"**
  One commit per mutation, per vault, actor+reason, `git revert` rollback.
  v1's model, now × N vaults.
- **`tool_call_audit` answers "who called what, when, and was it allowed?"**
  Every MCP tool call — builtin or proxied, allowed or denied — is one row.
  Reads (which git never sees) and denials (which never reach a vault) are
  telemetry only this table captures. It stores call *shape* (subject, tool,
  decision, timing, args digest) and never payloads: no note content, no
  argument values, no secrets — so the audit trail itself can't become an
  exfiltration channel or a second copy of the vault.

### 7.3 Gateway trust boundaries

- **SSRF surface.** A registered MCP server URL is a server-side request
  Cortex makes on a user's behalf. Registration is privileged (admin always;
  users only behind `gateway.allow_user_servers`), URLs are validated
  (scheme allowlist; loopback/link-local/private ranges refused by default
  with an explicit opt-in for genuinely-local upstreams), and redirects are
  not followed to new hosts. The gateway never proxies to Cortex's own
  endpoints.
- **Upstream secrets.** Whatever an upstream needs (API key, bearer token)
  is referenced by env-var name in `mcp_servers.auth_env`, resolved at call
  time, sent only to that upstream, and never logged, never stored, never
  echoed through tool results or the SPA.
- **A malicious upstream reaches the user's AI.** Proxied tool *names*,
  *descriptions*, and *results* are attacker-controlled input that Cortex
  forwards into the user's model context — a prompt-injection channel that
  permission gating does not close (gating controls *whether* a tool is
  visible/callable, not *what it says*). The design treats upstream text as
  untrusted: descriptions are length-capped and sanitized where lossless,
  tools are always presented under the `<server>.` namespace so an upstream
  cannot impersonate a builtin vault tool, and the residual risk is
  documented for operators (E2 carries the focused review, #55). Registering
  a server is therefore a *trust decision*, which is exactly why it is
  privileged.
- **Blast-radius rule:** a proxied call executes with *no* Cortex authority.
  The upstream never receives the user's Cortex token, never gets vault
  access, and a compromised upstream can affect at most the conversations of
  users permitted to call it.

### 7.4 LDAP

- Service-account bind password: env var only (`bind_password_env`).
- User authentication is a bind with the user's own credentials over
  `ldaps://` (or STARTTLS); Cortex never stores or logs user LDAP passwords.
- Directory outage degrades to "LDAP users can't start *new* sessions" —
  existing sessions and API tokens keep working until expiry/revocation, and
  local users (including the local admin) are unaffected, so an operator can
  always get in.

---

## 8. Web app + API

### 8.1 Shape

A React/Vite SPA — admin panel + Obsidian vault viewer — built to static
assets and served **same-origin** by the existing Starlette server (C1 wires
the build; the Python package ships the built assets so `pip install` +
`cortex serve` still needs no Node at runtime). It talks to a JSON API under
`/api/v1`. MCP stays on its existing endpoint; the SPA never speaks MCP.

Auth: session cookie for browsers, bearer token accepted on `/api/v1` for
programmatic use. Both resolve through the same identity layer (§3.1);
authorization per route is user vs admin, and vault-content routes apply the
§6 scoping identically to the MCP tools — the SPA gets no side door.

### 8.2 Surface sketch (indicative)

- `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, `GET /api/v1/me`
- Admin: users, groups, memberships, token revocation; LDAP import/preview;
  vault registry + macro audit (git log across vaults); gateway servers +
  permission matrix + `tool_call_audit` viewer
- User: own profile/password (local), own API tokens (mint/revoke), own
  vault: tree, note read (rendered + raw), frontmatter, search, backlinks/tags
- The vault viewer is read-first; note *editing* via the web is not a v2
  commitment (if a route mutates, it goes through the same write-scope +
  git-commit path as an MCP write, actor `user:<name> via web`).

### 8.3 MCP gateway (client's view)

An AI client connects to the same MCP endpoint with a user token and sees:
Cortex's builtin vault tools (bound to the user's vault + shared-vault
grants) **plus** every proxied tool the user is permitted, namespaced
`<server>.<tool>` (e.g. `github.create_issue`). Tool listing is
permission-filtered per identity — a denied tool is not listed, mirroring
the "out of scope = invisible" rule for paths.

### 8.4 Permission gating (deny-wins)

For a call to tool `T` on server `S` by user `U` (builtin tools use
`server_id NULL` / their bare name):

1. Collect matching `tool_permissions` rows for subject `U` and each of
   `U`'s groups, where `tool_pattern` matches `S.T` (glob, same directory-
   bounded semantics as path scopes — `github.*`, `**`).
2. **Any matching `deny` → denied.** User-level deny beats group-level
   allow; deny always beats allow at equal specificity. No rules → denied
   (default-closed).
3. Otherwise, any matching `allow` → allowed.
4. Either way, exactly one `tool_call_audit` row is written (§7.2), for
   denials too.

Config principals and legacy clients get **no** gateway tools — the gateway
is a user-identity feature; their surface stays exactly v1's.

---

## 9. Request flows

### 9.1 SPA login — local user

1. Browser `POST /api/v1/auth/login` `{username, password}`.
2. Server looks up `users` by username; `auth_source = local` → PBKDF2
   verify against stored salt+hash (constant-time).
3. On success: insert `sessions` row (hashed session token, TTL), set the
   HttpOnly signed cookie, return the user's profile + groups.
4. Subsequent `/api/v1` requests: cookie → session row (unexpired) → user →
   groups → effective (vault, scopes) grants per §6.

### 9.2 SPA login — LDAP user

1. Same `POST`; user row (or username pattern) says `auth_source = ldap`.
2. Server binds to the directory **as the user** (DN from the stored
   `ldap_dn`, or resolved via the service account + `user_base` search),
   over TLS. Bind failure → the same uniform 401 as a local failure.
3. On success: refresh the user's group memberships from the directory into
   `groups`/`user_groups` (create-on-first-login if configured).
4. Session creation proceeds exactly as 9.1 step 3 — from here on, LDAP and
   local users are indistinguishable.

### 9.3 MCP call with a user token

1. AI client sends an MCP request with `Authorization: Bearer <token>`.
2. Token resolution walks the §3.1 order: not a config principal token → 
   prefix-lookup in `api_tokens`, PBKDF2 verify, not revoked/expired →
   subject `user:<username>`.
3. Per-call identity resolution (the A1 `_get_principal` pattern,
   generalized) sees the `user:` prefix and consults **only** the user
   store: user row → groups → effective grants: own vault (`**`), plus
   shared-vault group scopes, minus any token-level narrowing (§6.2).
4. A vault tool call (say `read_note`) binds to the user's **own vault**
   store/index/git triple, canonicalizes the path, scope-checks, reads.
   Tool listing shows builtin tools + permitted proxied tools (§8.3).
5. One `tool_call_audit` row records the call.

### 9.4 Proxied gateway tool call

1. Client calls `github.create_issue` (a namespaced proxied tool) with the
   user's token; identity resolves as in 9.3.
2. Gateway splits the namespace → server `github` in `mcp_servers` (enabled,
   and visible to this user: global, or personal-and-owned-by-them).
3. **Permission check** per §8.4 (deny-wins, default-closed). Denied →
   uniform error, audit row `decision=denied`, nothing forwarded.
4. Allowed → forward the call to the upstream over its configured transport,
   attaching the upstream's own credential from `auth_env`. The user's
   Cortex token is never forwarded. Timeouts and response-size caps apply.
5. Result (treated as untrusted text, §7.3) is returned to the client under
   the namespaced tool; audit row records `decision=allowed`, duration, and
   error kind if the upstream failed. No arguments or payloads are stored.

---

## 10. Build order (v2 issue tree, #35–#55)

Five workstreams. A is the foundation; B/C/D fan out from it; E closes.
Within a workstream, issues are strictly ordered; across workstreams, the
dependency notes on each issue govern. An agent picking up issue *N* should
read this document plus its issue body, and can assume every issue listed
above it here is merged.

**A — Foundation (identity & API)**
- **A1 (#35)** — security hardening baseline: source-tagged subjects,
  canonicalize-then-check, admin-store/cookie hardening. **Landed**; §2.
- **A2 (#36)** — this document.
- **A3 (#37)** — SQLite data layer: schema + migrations (§4), migrate
  `cortex.admin.json` (admin login, roles→groups, clients) into SQLite.
- **A4 (#38)** — local user accounts: creation, password auth, web sessions,
  per-user API tokens (§3, §9.1).
- **A5 (#39)** — LDAP/AD: bind auth, user pull, group mapping (§3.2, §7.4, §9.2).
- **A6 (#40)** — JSON REST API foundation: `/api/v1`, session+bearer auth on
  routes, CSRF (§8.1–8.2).

**B — Multi-vault**
- **B1 (#41)** — vault registry & provisioning: one directory + git repo per
  user under `vaults.root` (§5).
- **B2 (#42)** — multi-vault scoping: container vs macro views, per-vault
  store/index/git binding (§6).
- **B3 (#43)** — vault-content REST API for the viewer: tree, note read,
  search, frontmatter (§8.2).
- **B4 (#44)** — macro operations: janitor, sync, aggregated audit across
  all vaults (§6.3).

**C — Web app**
- **C1 (#45)** — React/Vite SPA scaffold: build integration, login flow,
  app shell (§8.1).
- **C2 (#46)** — admin panel: users, groups, tokens, LDAP import.
- **C3 (#47)** — admin panel: vault administration + macro audit view.
- **C4 (#48)** — vault viewer: tree, Markdown rendering, wikilinks,
  frontmatter.
- **C5 (#49)** — vault viewer: search, backlinks, tag exploration.

**D — MCP gateway**
- **D1 (#50)** — per-user MCP access: tool-level permission gating +
  `tool_call_audit` for Cortex's own tools (§8.4, §7.2).
- **D2 (#51)** — external MCP server registry: admin- and (toggled)
  user-level registration (`mcp_servers`, §7.3 SSRF rules).
- **D3 (#52)** — gateway proxy runtime: aggregate + proxy external tools,
  namespacing, forwarding, audit (§9.4).
- **D4 (#53)** — web UI: MCP tooling pages, permission matrix, token setup,
  audit viewer.

**E — Ship**
- **E1 (#54)** — packaging & deployment: Docker, DB migrations on upgrade,
  systemd, upgrade path from v1.
- **E2 (#55)** — documentation + focused security review of the new surface
  (SSRF, cross-vault isolation, CSRF, prompt-injection trust model,
  audit-content hygiene), README rewrite, `cortex.example.yaml` for every
  new section. **Also closes the residual #26 drift items**: the
  `LLMConfig` provider-list comment in `src/cortex/config.py` (missing
  `openrouter`) and the stale "v1 is read-only" framing in the
  `src/cortex/gitlog.py` module docstring. (The `ARCHITECTURE.md` §3.5/§4
  wording and the README tool table were reconciled in A2, alongside this
  document.)

v2 is "done" at E2: a multi-user, multi-vault, web-managed, gateway-capable
Cortex whose v1 core — scoped, deterministic, git-audited memory — is
unchanged underneath.
