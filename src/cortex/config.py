"""Configuration loading for Cortex.

Config is split in two on purpose:

* The **config file** (``cortex.yaml``) is public-safe. It contains structure —
  vault path, principals, scopes, which adapters/providers are active — but no
  secrets.
* **Secrets** (bearer tokens, API keys) are supplied via environment variables.
  A principal's token is referenced by ``token_env: CORTEX_TOKEN_<NAME>``; the
  server reads the actual value from the environment at startup.

This keeps a committed config (and a built image) free of credentials, which is
a hard requirement from the architecture's safety model.

Any string value in the YAML may use ``${ENV_VAR}`` interpolation, resolved
against the process environment at load time.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")


class ConfigError(Exception):
    """Raised when the configuration is missing or invalid."""


def _interpolate(value: Any) -> Any:
    """Recursively replace ``${ENV_VAR}`` references with environment values."""
    if isinstance(value, str):
        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in os.environ:
                raise ConfigError(f"config references undefined env var ${{{name}}}")
            return os.environ[name]

        return _ENV_PATTERN.sub(repl, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


@dataclass
class GitConfig:
    enabled: bool = True
    actor_name: str = "cortex"
    actor_email: str = "cortex@localhost"


@dataclass
class VaultConfig:
    path: Path = Path("./vault")
    git: GitConfig = field(default_factory=GitConfig)


@dataclass
class SyncConfig:
    # Default is local-only: the vault is just a folder + git audit, and the
    # user brings their own sync if they want one. Opt-in adapters layer on top.
    adapter: str = "none"  # none | git | nextcloud | s3
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class Principal:
    """A named identity that may be granted scoped access to the vault."""

    name: str
    scopes: list[str] = field(default_factory=list)
    # Name of the env var holding this principal's bearer token (HTTP transport).
    token_env: str | None = None
    # Resolved token value (populated at load; never written back to disk).
    token: str | None = None
    # Scopes a principal may *mutate* (write/delete). Empty/unset => falls back
    # to `scopes` (read scopes), so writes work immediately with no extra
    # config. Set this to narrow the writable area independent of what's
    # readable — the hook for per-principal write permissioning later.
    write_scopes: list[str] = field(default_factory=list)


@dataclass
class AuthConfig:
    enabled: bool = True
    # Principal used for local stdio connections, which carry no bearer token.
    # Must be the name of a defined principal, or None to deny stdio.
    local_principal: str | None = None
    # Run a full OAuth 2.1 authorization server (http transport) so one-click
    # connector UIs (Claude.ai / ChatGPT / Grok) can authorize. When false,
    # http is a bearer-only resource server.
    oauth_enabled: bool = False

@dataclass
class AdminConfig:
    enabled: bool = True
    # Local JSON state containing the generated admin password hash, roles, and
    # hashed AI-client tokens. Relative paths resolve next to cortex.yaml.
    path: Path = Path("./cortex.admin.json")


@dataclass
class DatabaseConfig:
    # SQLite identity/gateway database (v2 design §4/§5): users, groups,
    # sessions, API tokens, MCP server registry, tool permissions, tool-call
    # audit. Holds salted hashes only — never plaintext secrets, never note
    # content. Relative paths resolve next to cortex.yaml. Never commit this.
    path: Path = Path("./data/cortex.sqlite")


@dataclass
class IndexConfig:
    enabled: bool = True
    # SQLite FTS5 ranked-search cache, derived from the vault. Relative paths
    # resolve next to cortex.yaml. Never commit this — it's a rebuildable cache.
    path: Path = Path("./cortex.index.sqlite")
    chunk_chars: int = 1500
    overlap: int = 150

@dataclass
class ServerConfig:
    transport: str = "stdio"  # stdio | http
    host: str = "127.0.0.1"
    port: int = 8765
    path: str = "/mcp"  # Streamable HTTP endpoint path
    # Externally-visible base URL (https://...), used as the OAuth issuer /
    # resource identifier. Defaults to http://host:port when unset.
    public_url: str | None = None
    # Host/Origin allowlists for DNS-rebinding protection. Empty => allow all
    # (fine behind a trusted reverse proxy; set these for direct exposure).
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_origins: list[str] = field(default_factory=list)
    # Structured per-request access logging for the /api/v1 surface (#30
    # direction): one log record per request — method, path, principal,
    # status, latency. Never bodies, never tokens, never note content.
    # Off by default; a single boolean check when disabled.
    request_log: bool = False


@dataclass
class LLMConfig:
    provider: str = "none"  # anthropic | openai | ollama | none
    model: str = ""
    api_key_env: str | None = None
    api_key: str | None = None
    base_url: str | None = None
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class JanitorConfig:
    enabled: bool = False  # dark by default
    dry_run: bool = True  # report-only before write mode
    interval_seconds: int = 3600
    allowed_paths: list[str] = field(default_factory=list)
    forbidden_paths: list[str] = field(default_factory=list)


@dataclass
class LdapAttributeMap:
    """Directory attribute → Cortex user-field mapping. Defaults suit a
    generic OpenLDAP tree; Active Directory typically wants
    ``username: sAMAccountName`` and ``display_name: displayName``."""

    username: str = "uid"
    display_name: str = "cn"
    email: str = "mail"


@dataclass
class LdapConfig:
    """LDAP / Active Directory integration (A5, design §3.2/§7.4/§9.2).

    Public-safe by construction: the service-account bind password is
    referenced by env-var *name* (``bind_password_env``) and resolved from
    the environment at load time — the secret never appears in the file.
    The whole feature is off unless an ``ldap:`` block exists in cortex.yaml
    (``CortexConfig.ldap`` stays ``None``).
    """

    # ldap://host[:port] or ldaps://host[:port]
    server_uri: str = ""
    # Upgrade a plain ldap:// connection to TLS before any bind (STARTTLS).
    starttls: bool = False
    # Explicit opt-out of the TLS requirement (labs/dev only): binds carry
    # user passwords, so ldaps:// or starttls is mandatory unless this is set.
    allow_insecure: bool = False
    # Service account used for search-then-bind and for `cortex ldap sync`.
    bind_dn: str = ""
    # Name of the env var holding the service-account password (never the
    # secret itself — §7 safety model).
    bind_password_env: str = ""
    # Resolved at load; never written back to disk.
    bind_password: str | None = None
    # Where users live and how a login name finds exactly one entry.
    # ``{username}`` is substituted with the RFC 4515-escaped login name.
    user_base_dn: str = ""
    user_filter: str = "(uid={username})"
    attributes: LdapAttributeMap = field(default_factory=LdapAttributeMap)
    # Where groups live; group_filter selects group entries, and membership
    # is one level deep: (&(<group_filter>)(<group_member_attr>=<user DN>)).
    group_base_dn: str = ""
    group_filter: str = "(objectClass=groupOfNames)"
    group_member_attr: str = "member"
    # LDAP group (DN, or its name attribute) → Cortex group name. Only
    # mapped groups are reconciled; unmapped directory groups are ignored
    # and local-only Cortex groups are never touched.
    group_mappings: dict[str, str] = field(default_factory=dict)
    # Create a Cortex user row (auth_source=ldap, no password material) on
    # first successful directory login. When false, only users pre-created
    # by `cortex ldap sync` can log in.
    jit_provisioning: bool = True


@dataclass
class WritesConfig:
    # Single global switch for the mutating MCP tools (write_note, patch_note,
    # append_note, update_frontmatter, delete_note). Default false: Cortex is a
    # public "anyone can spin one up" project, so destructive-by-default would
    # be a footgun. Flip on in your own cortex.yaml once you're ready — every
    # mutation is still a single git commit (via GitAudit), so it's always
    # revertible with ordinary `git revert`.
    enabled: bool = False


@dataclass
class CortexConfig:
    vault: VaultConfig = field(default_factory=VaultConfig)
    sync: SyncConfig = field(default_factory=SyncConfig)
    principals: list[Principal] = field(default_factory=list)
    auth: AuthConfig = field(default_factory=AuthConfig)
    admin: AdminConfig = field(default_factory=AdminConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    index: IndexConfig = field(default_factory=IndexConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    janitor: JanitorConfig = field(default_factory=JanitorConfig)
    writes: WritesConfig = field(default_factory=WritesConfig)
    # None ⇒ LDAP integration fully off (the default).
    ldap: LdapConfig | None = None

    def principal(self, name: str) -> Principal | None:
        for p in self.principals:
            if p.name == name:
                return p
        return None


def _build(raw: dict[str, Any], base_dir: Path) -> CortexConfig:
    vault_raw = raw.get("vault", {}) or {}
    vault_path = Path(vault_raw.get("path", "./vault"))
    if not vault_path.is_absolute():
        vault_path = (base_dir / vault_path).resolve()
    git_raw = vault_raw.get("git", {}) or {}
    vault = VaultConfig(
        path=vault_path,
        git=GitConfig(
            enabled=git_raw.get("enabled", True),
            actor_name=git_raw.get("actor_name", "cortex"),
            actor_email=git_raw.get("actor_email", "cortex@localhost"),
        ),
    )

    sync_raw = raw.get("sync", {}) or {}
    sync = SyncConfig(
        adapter=sync_raw.get("adapter", "none"),
        options=sync_raw.get("options", {}) or {},
    )

    principals: list[Principal] = []
    for p_raw in raw.get("principals", []) or []:
        name = p_raw.get("name")
        if not name:
            raise ConfigError("each principal requires a 'name'")
        token_env = p_raw.get("token_env")
        token = None
        if token_env:
            token = os.environ.get(token_env)
            if not token:
                raise ConfigError(
                    f"principal '{name}' references token_env '{token_env}' "
                    "but that env var is unset"
                )
        principals.append(
            Principal(
                name=name,
                scopes=list(p_raw.get("scopes", []) or []),
                token_env=token_env,
                token=token,
                write_scopes=list(p_raw.get("write_scopes", []) or []),
            )
        )

    auth_raw = raw.get("auth", {}) or {}
    auth = AuthConfig(
        enabled=auth_raw.get("enabled", True),
        local_principal=auth_raw.get("local_principal"),
        oauth_enabled=auth_raw.get("oauth_enabled", False),
    )

    admin_raw = raw.get("admin", {}) or {}
    admin_path = Path(admin_raw.get("path", "./cortex.admin.json"))
    if not admin_path.is_absolute():
        admin_path = (base_dir / admin_path).resolve()
    admin = AdminConfig(
        enabled=admin_raw.get("enabled", True),
        path=admin_path,
    )

    database_raw = raw.get("database", {}) or {}
    database_path = Path(database_raw.get("path", "./data/cortex.sqlite"))
    if not database_path.is_absolute():
        database_path = (base_dir / database_path).resolve()
    database = DatabaseConfig(path=database_path)

    index_raw = raw.get("index", {}) or {}
    index_path = Path(index_raw.get("path", "./cortex.index.sqlite"))
    if not index_path.is_absolute():
        index_path = (base_dir / index_path).resolve()
    index = IndexConfig(
        enabled=index_raw.get("enabled", True),
        path=index_path,
        chunk_chars=int(index_raw.get("chunk_chars", 1500)),
        overlap=int(index_raw.get("overlap", 150)),
    )

    server_raw = raw.get("server", {}) or {}
    server = ServerConfig(
        transport=server_raw.get("transport", "stdio"),
        host=server_raw.get("host", "127.0.0.1"),
        port=int(server_raw.get("port", 8765)),
        path=server_raw.get("path", "/mcp"),
        public_url=server_raw.get("public_url"),
        allowed_hosts=list(server_raw.get("allowed_hosts", []) or []),
        allowed_origins=list(server_raw.get("allowed_origins", []) or []),
        request_log=bool(server_raw.get("request_log", False)),
    )

    llm_raw = raw.get("llm", {}) or {}
    api_key_env = llm_raw.get("api_key_env")
    api_key = os.environ.get(api_key_env) if api_key_env else None
    llm = LLMConfig(
        provider=llm_raw.get("provider", "none"),
        model=llm_raw.get("model", ""),
        api_key_env=api_key_env,
        api_key=api_key,
        base_url=llm_raw.get("base_url"),
        options=llm_raw.get("options", {}) or {},
    )

    jan_raw = raw.get("janitor", {}) or {}
    janitor = JanitorConfig(
        enabled=jan_raw.get("enabled", False),
        dry_run=jan_raw.get("dry_run", True),
        interval_seconds=int(jan_raw.get("interval_seconds", 3600)),
        allowed_paths=list(jan_raw.get("allowed_paths", []) or []),
        forbidden_paths=list(jan_raw.get("forbidden_paths", []) or []),
    )

    writes_raw = raw.get("writes", {}) or {}
    writes = WritesConfig(
        enabled=writes_raw.get("enabled", False),
    )

    ldap = _build_ldap(raw.get("ldap"))

    cfg = CortexConfig(
        vault=vault,
        sync=sync,
        principals=principals,
        auth=auth,
        admin=admin,
        database=database,
        index=index,
        server=server,
        llm=llm,
        janitor=janitor,
        writes=writes,
        ldap=ldap,
    )
    _validate(cfg)
    return cfg


def _build_ldap(ldap_raw: Any) -> LdapConfig | None:
    """Build + validate the optional ``ldap:`` block. Absent ⇒ None (the
    integration is inert). Present ⇒ every structural requirement is checked
    here so a misconfiguration fails at startup, not at first login."""
    if ldap_raw is None:
        return None
    if not isinstance(ldap_raw, dict):
        raise ConfigError("'ldap' must be a mapping")

    attrs_raw = ldap_raw.get("attributes", {}) or {}
    if not isinstance(attrs_raw, dict):
        raise ConfigError("ldap.attributes must be a mapping")
    attributes = LdapAttributeMap(
        username=str(attrs_raw.get("username", "uid")),
        display_name=str(attrs_raw.get("display_name", "cn")),
        email=str(attrs_raw.get("email", "mail")),
    )

    mappings_raw = ldap_raw.get("group_mappings", {}) or {}
    if not isinstance(mappings_raw, dict):
        raise ConfigError("ldap.group_mappings must be a mapping of "
                          "LDAP group (DN or name) -> Cortex group name")
    group_mappings: dict[str, str] = {}
    for ldap_group, cortex_group in mappings_raw.items():
        if not str(ldap_group).strip() or not str(cortex_group or "").strip():
            raise ConfigError(
                "ldap.group_mappings entries need a non-empty LDAP group "
                "and a non-empty Cortex group name"
            )
        group_mappings[str(ldap_group).strip()] = str(cortex_group).strip()

    bind_password_env = ldap_raw.get("bind_password_env") or ""
    if not bind_password_env:
        raise ConfigError(
            "ldap.bind_password_env is required: the service-account password "
            "is supplied via an environment variable, never in the config file"
        )
    bind_password = os.environ.get(bind_password_env)
    if not bind_password:
        raise ConfigError(
            f"ldap.bind_password_env references '{bind_password_env}' "
            "but that env var is unset"
        )

    ldap_cfg = LdapConfig(
        server_uri=str(ldap_raw.get("server_uri", "") or ""),
        starttls=bool(ldap_raw.get("starttls", False)),
        allow_insecure=bool(ldap_raw.get("allow_insecure", False)),
        bind_dn=str(ldap_raw.get("bind_dn", "") or ""),
        bind_password_env=bind_password_env,
        bind_password=bind_password,
        user_base_dn=str(ldap_raw.get("user_base_dn", "") or ""),
        user_filter=str(ldap_raw.get("user_filter", "(uid={username})")),
        attributes=attributes,
        group_base_dn=str(ldap_raw.get("group_base_dn", "") or ""),
        group_filter=str(ldap_raw.get("group_filter", "(objectClass=groupOfNames)")),
        group_member_attr=str(ldap_raw.get("group_member_attr", "member")),
        group_mappings=group_mappings,
        jit_provisioning=bool(ldap_raw.get("jit_provisioning", True)),
    )

    if not ldap_cfg.server_uri:
        raise ConfigError("ldap.server_uri is required")
    if not ldap_cfg.server_uri.startswith(("ldap://", "ldaps://")):
        raise ConfigError(
            f"ldap.server_uri must start with ldap:// or ldaps://: "
            f"{ldap_cfg.server_uri!r}"
        )
    is_ldaps = ldap_cfg.server_uri.startswith("ldaps://")
    if is_ldaps and ldap_cfg.starttls:
        raise ConfigError("ldap.starttls does not apply to an ldaps:// URI")
    if not is_ldaps and not ldap_cfg.starttls and not ldap_cfg.allow_insecure:
        raise ConfigError(
            "ldap binds carry user passwords: use ldaps:// or starttls: true "
            "(or set allow_insecure: true for a lab setup, at your own risk)"
        )
    if not ldap_cfg.bind_dn:
        raise ConfigError("ldap.bind_dn (service account) is required")
    if not ldap_cfg.user_base_dn:
        raise ConfigError("ldap.user_base_dn is required")
    if "{username}" not in ldap_cfg.user_filter:
        raise ConfigError(
            "ldap.user_filter must contain the {username} placeholder, "
            "e.g. (sAMAccountName={username})"
        )
    if not ldap_cfg.user_filter.startswith("("):
        raise ConfigError("ldap.user_filter must be a parenthesized LDAP filter")
    if group_mappings and not ldap_cfg.group_base_dn:
        raise ConfigError("ldap.group_mappings requires ldap.group_base_dn")
    if ldap_cfg.group_base_dn and not ldap_cfg.group_filter.startswith("("):
        raise ConfigError("ldap.group_filter must be a parenthesized LDAP filter")
    return ldap_cfg


def _validate(cfg: CortexConfig) -> None:
    for p in cfg.principals:
        # Reserved subject namespaces (kept in sync with cortex.auth): a
        # config principal may not squat on another identity source's prefix.
        if p.name.startswith("client:"):
            raise ConfigError(
                f"principal name {p.name!r} is invalid: the 'client:' prefix is "
                "reserved for admin-store AI clients"
            )
        if p.name.startswith("user:"):
            raise ConfigError(
                f"principal name {p.name!r} is invalid: the 'user:' prefix is "
                "reserved for database user accounts"
            )
    if cfg.auth.local_principal and cfg.principal(cfg.auth.local_principal) is None:
        raise ConfigError(
            f"auth.local_principal '{cfg.auth.local_principal}' is not a defined principal"
        )
    if cfg.server.transport == "http" and not cfg.auth.enabled:
        raise ConfigError("auth must be enabled for http transport (no public exposure unmapped)")
    if cfg.server.transport == "http" and not any(p.token for p in cfg.principals) and not cfg.admin.enabled:
        raise ConfigError(
            "http transport requires at least one principal with a token_env or admin.enabled; "
            "otherwise no client can authenticate."
        )
    if cfg.auth.oauth_enabled and cfg.server.transport != "http":
        raise ConfigError("auth.oauth_enabled requires server.transport: http")
    if cfg.server.transport not in ("stdio", "http"):
        raise ConfigError(f"unknown server.transport '{cfg.server.transport}'")
    if cfg.writes.enabled and not cfg.vault.git.enabled:
        raise ConfigError(
            "writes.enabled requires vault.git.enabled: every mutation must be a "
            "git commit (the audit trail and the only rollback mechanism), so "
            "enabling writes without git audit — which would allow unaudited, "
            "unrecoverable changes — is not permitted."
        )


def load_config(path: str | os.PathLike[str]) -> CortexConfig:
    """Load and validate a Cortex config file, resolving ``${ENV}`` and secrets."""
    cfg_path = Path(path).expanduser()
    if not cfg_path.exists():
        raise ConfigError(f"config file not found: {cfg_path}")
    raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")
    raw = _interpolate(raw)
    return _build(raw, base_dir=cfg_path.resolve().parent)
