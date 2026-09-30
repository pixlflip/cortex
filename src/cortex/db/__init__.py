"""Cortex SQLite data layer (v2 design §4).

One SQLite database holds users, groups, sessions, API tokens, memory tool
permissions and call audit. Historical upstream tables remain inert for
rollback; there is no registry repository. It never holds note content;
notes live in vaults and git remains their audit trail.

Public surface:

* :class:`Database` — the connection manager + migration runner.
* Repositories (:class:`UsersRepo`, :class:`GroupsRepo`, :class:`ApiTokensRepo`,
  :class:`SessionsRepo`) — typed CRUD primitives for identity, memory policy
  and audit. Migration history is retained unchanged.
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
    SessionsRepo,
    ToolAuditRepo,
    ToolPermissionsRepo,
    SettingsRepo,
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
    "ToolPermissionsRepo",
    "SettingsRepo",
    "ToolAuditRepo",
    "CreatedApiToken",
    "CreatedSession",
    "import_admin_state",
]
