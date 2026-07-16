"""Cortex SQLite data layer (v2 design §4).

One SQLite database holds identity and gateway state — users, groups,
sessions, API tokens, MCP server registry, tool permissions, and tool-call
audit telemetry. It never holds note content; notes live in vaults and git
remains their audit trail.

Public surface:

* :class:`Database` — the connection manager + migration runner.
* Repositories (:class:`UsersRepo`, :class:`GroupsRepo`, :class:`ApiTokensRepo`,
  :class:`SessionsRepo`) — typed CRUD primitives over the tables A3 makes
  usable now. Later workstreams (D1/D2/D3) add repositories for the gateway
  tables, whose schema already exists.
* :func:`import_admin_state` — one-shot, idempotent import of the legacy
  ``cortex.admin.json`` store.
"""

from .core import (
    Database,
    Migration,
    MIGRATIONS,
    MigrationsPendingError,
    SchemaVersionError,
    latest_version,
    schema_version_of,
)
from .repos import (
    ApiTokensRepo,
    CreatedApiToken,
    CreatedSession,
    GroupsRepo,
    McpServersRepo,
    SessionsRepo,
    ToolAuditRepo,
    ToolPermissionsRepo,
    UsersRepo,
)
from .admin_import import import_admin_state

__all__ = [
    "Database",
    "Migration",
    "MIGRATIONS",
    "MigrationsPendingError",
    "SchemaVersionError",
    "latest_version",
    "schema_version_of",
    "UsersRepo",
    "GroupsRepo",
    "ApiTokensRepo",
    "SessionsRepo",
    "McpServersRepo",
    "ToolPermissionsRepo",
    "ToolAuditRepo",
    "CreatedApiToken",
    "CreatedSession",
    "import_admin_state",
]
