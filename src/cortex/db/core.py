"""Database core: connection management, schema versioning, migrations.

Design points (and the past bugs they answer):

* **Connection-per-call.** ``sqlite3`` connections are not safe to share
  across threads without external locking, and a long-lived shared connection
  has already bitten this codebase. :meth:`Database.connection` opens a fresh
  connection per unit of work and always closes it. WAL mode makes concurrent
  readers cheap; a ``busy_timeout`` makes concurrent writers wait instead of
  erroring.
* **Schema version is checked on open, not just recorded** (contrast #13,
  where a version was written and never read back). Opening a database that
  is *ahead* of this code raises :class:`SchemaVersionError`; a database that
  is *behind* is migrated forward (or, with ``auto_migrate=False``, raises
  :class:`MigrationsPendingError`).
* **Migrations are numbered, transactional, and race-safe.** Each migration
  runs inside ``BEGIN IMMEDIATE``; the version row is re-checked under that
  write lock, so two processes migrating concurrently apply each step exactly
  once. Adding a future migration is appending one :class:`Migration` to
  :data:`MIGRATIONS`.
* **Per-connection pragmas:** ``journal_mode=WAL``, ``foreign_keys=ON``,
  ``sqlite3.Row`` row factory (dict-like access).
"""

from __future__ import annotations

import contextlib
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

_BUSY_TIMEOUT_MS = 10_000


class SchemaVersionError(Exception):
    """The on-disk schema is newer than this code understands."""


class MigrationsPendingError(Exception):
    """The on-disk schema is behind and auto-migration was declined."""


def _now() -> int:
    return int(time.time())


@dataclass(frozen=True)
class Migration:
    """One numbered schema step. ``apply`` receives a connection that is
    already inside a write transaction; it must not commit/rollback itself."""

    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


# --------------------------------------------------------------------------
# Migration 1 — the full v2-design §4 table set.
#
# All eight tables are created up front, including the gateway tables that
# later workstreams (D1/D2/D3) populate, so their arrival causes no schema
# churn. Columns follow the §4 sketch; deviations are commented inline.
# --------------------------------------------------------------------------

def _m0001_initial_schema(conn: sqlite3.Connection) -> None:
    # Individual execute() calls, not executescript(): executescript issues an
    # implicit COMMIT first, which would break the migration runner's
    # one-transaction-per-migration guarantee.
    statements = _split_statements(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY,
            username      TEXT NOT NULL UNIQUE,
            display_name  TEXT,
            email         TEXT,
            auth_source   TEXT NOT NULL DEFAULT 'local'
                          CHECK (auth_source IN ('local', 'ldap')),
            password_salt TEXT,             -- NULL for ldap users
            password_hash TEXT,             -- NULL for ldap users
            ldap_dn       TEXT,             -- NULL for local users
            is_admin      INTEGER NOT NULL DEFAULT 0,
            disabled      INTEGER NOT NULL DEFAULT 0,
            created_at    INTEGER NOT NULL,
            last_login_at INTEGER
        );

        CREATE TABLE IF NOT EXISTS groups (
            id          INTEGER PRIMARY KEY,
            name        TEXT NOT NULL UNIQUE,
            source      TEXT NOT NULL DEFAULT 'local'
                        CHECK (source IN ('local', 'ldap')),
            ldap_dn     TEXT,
            -- Shared-vault scope grants (design §6.4): JSON list of path
            -- globs. Not in the §4 sketch (which is explicitly
            -- non-exhaustive) but required so the legacy admin-store roles
            -- migrate to groups without losing their scopes.
            scopes_json TEXT,
            created_at  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS user_groups (
            user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            PRIMARY KEY (user_id, group_id)
        );
        CREATE INDEX IF NOT EXISTS idx_user_groups_group
            ON user_groups(group_id);

        CREATE TABLE IF NOT EXISTS sessions (
            id           INTEGER PRIMARY KEY,
            token_hash   TEXT NOT NULL UNIQUE,   -- sha256 of the random token
            user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at   INTEGER NOT NULL,
            expires_at   INTEGER NOT NULL,
            last_seen_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user
            ON sessions(user_id);

        CREATE TABLE IF NOT EXISTS api_tokens (
            id           INTEGER PRIMARY KEY,
            user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name         TEXT NOT NULL,
            token_prefix TEXT NOT NULL,
            salt         TEXT NOT NULL,
            token_hash   TEXT NOT NULL,
            scopes_json  TEXT,                   -- optional narrowing, §6.2
            created_at   INTEGER NOT NULL,
            expires_at   INTEGER,
            last_used_at INTEGER,
            revoked_at   INTEGER
        );
        -- The #14 lesson: prefix-indexed lookup so a bearer check hashes only
        -- the candidate rows sharing the presented token's prefix.
        CREATE INDEX IF NOT EXISTS idx_api_tokens_prefix
            ON api_tokens(token_prefix);
        CREATE INDEX IF NOT EXISTS idx_api_tokens_user
            ON api_tokens(user_id);

        CREATE TABLE IF NOT EXISTS mcp_servers (
            id            INTEGER PRIMARY KEY,
            name          TEXT NOT NULL UNIQUE,
            url           TEXT,
            transport     TEXT NOT NULL DEFAULT 'streamable-http'
                          CHECK (transport IN ('streamable-http', 'sse', 'stdio-cmd')),
            auth_env      TEXT,                  -- env var NAME; never the secret
            -- NULL owner = admin/global registration. CASCADE (not SET NULL)
            -- on owner deletion: silently promoting a personal server to
            -- global would widen its audience.
            owner_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            visibility    TEXT NOT NULL DEFAULT 'group'
                          CHECK (visibility IN ('group', 'personal')),
            enabled       INTEGER NOT NULL DEFAULT 1,
            created_at    INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tool_permissions (
            id           INTEGER PRIMARY KEY,
            subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'group')),
            subject_id   INTEGER NOT NULL,
            server_id    INTEGER REFERENCES mcp_servers(id) ON DELETE CASCADE,
                                                 -- NULL = Cortex builtin tools
            tool_pattern TEXT NOT NULL,
            effect       TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
            created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at   INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_tool_permissions_subject
            ON tool_permissions(subject_type, subject_id);

        CREATE TABLE IF NOT EXISTS tool_call_audit (
            id           INTEGER PRIMARY KEY,
            ts           INTEGER NOT NULL,
            subject      TEXT NOT NULL,          -- source-tagged: user:x / client:y / plain
            user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
            api_token_id INTEGER REFERENCES api_tokens(id) ON DELETE SET NULL,
            server       TEXT NOT NULL,          -- 'cortex' or mcp_servers.name
            tool         TEXT NOT NULL,
            decision     TEXT NOT NULL CHECK (decision IN ('allowed', 'denied', 'error')),
            error_kind   TEXT,
            duration_ms  INTEGER,
            args_digest  TEXT                    -- hash/shape only: never values
        );
        CREATE INDEX IF NOT EXISTS idx_tool_call_audit_ts
            ON tool_call_audit(ts);
        CREATE INDEX IF NOT EXISTS idx_tool_call_audit_subject
            ON tool_call_audit(subject, ts);
        """
    )
    for stmt in statements:
        conn.execute(stmt)


def _split_statements(script: str) -> list[str]:
    """Split a DDL script into single statements for ``execute()``.

    Statement-terminating semicolons in our DDL always end a line (modulo
    trailing whitespace/comments never containing ';'), so a line-aware split
    is sufficient and keeps the schema readable as one block above.
    """
    statements: list[str] = []
    current: list[str] = []
    for line in script.splitlines():
        current.append(line)
        if line.rstrip().endswith(";"):
            stmt = "\n".join(current).strip().rstrip(";").strip()
            if stmt:
                statements.append(stmt)
            current = []
    tail = "\n".join(current).strip().rstrip(";").strip()
    if tail:
        statements.append(tail)
    return statements


#: Ordered, append-only. To add a schema change in a later issue: write a
#: ``_mNNNN_<name>`` function and append ``Migration(N, "<name>", fn)`` here.
#: Versions must be contiguous starting at 1.
MIGRATIONS: list[Migration] = [
    Migration(1, "initial_schema", _m0001_initial_schema),
]


def latest_version() -> int:
    return MIGRATIONS[-1].version if MIGRATIONS else 0


def schema_version_of(path: Path | str) -> int:
    """On-disk schema version of the database at *path* (0 = absent/empty),
    without opening it through :class:`Database` (so no migration or version
    check is triggered)."""
    path = Path(path)
    if not path.exists():
        return 0
    conn = sqlite3.connect(str(path))
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
        ).fetchone()
        if row is None:
            return 0
        got = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        return int(got[0] or 0)
    finally:
        conn.close()


class Database:
    """SQLite database handle: path + migration state, no live connection.

    Opening (constructing) a ``Database`` checks the on-disk schema version
    against :data:`MIGRATIONS` and applies pending migrations forward
    (default) or raises. Every unit of work then gets its own connection via
    :meth:`connection` / :meth:`transaction`.
    """

    def __init__(self, path: Path | str, *, auto_migrate: bool = True):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        version = self.schema_version()
        latest = latest_version()
        if version > latest:
            raise SchemaVersionError(
                f"database {self.path} is at schema version {version}, but this "
                f"Cortex build understands only up to {latest} — refusing to "
                "open (upgrade Cortex, or restore the matching database)."
            )
        if version < latest:
            if not auto_migrate:
                raise MigrationsPendingError(
                    f"database {self.path} is at schema version {version}; "
                    f"{latest - version} migration(s) pending (run 'cortex db migrate')."
                )
            self.migrate()

    # -- connections -----------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=_BUSY_TIMEOUT_MS / 1000)
        conn.row_factory = sqlite3.Row
        # Explicit transaction control: no implicit BEGIN from the driver.
        conn.isolation_level = None
        conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextlib.contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """A fresh connection for one unit of read work, always closed."""
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """A fresh connection wrapping one write transaction.

        ``BEGIN IMMEDIATE`` takes the write lock up front so concurrent
        writers queue on ``busy_timeout`` instead of failing mid-transaction.
        Commits on success, rolls back on any exception.
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

    # -- schema versioning -----------------------------------------------
    def schema_version(self) -> int:
        """Current on-disk schema version (0 = empty/new database)."""
        return schema_version_of(self.path)

    def applied_migrations(self) -> list[dict]:
        if self.schema_version() == 0:
            return []
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT version, name, applied_at FROM schema_version ORDER BY version"
            ).fetchall()
            return [dict(r) for r in rows]

    def migrate(self) -> list[Migration]:
        """Apply pending migrations forward. Returns the ones applied here.

        Each migration is one ``BEGIN IMMEDIATE`` transaction; the version is
        re-checked under the write lock, so concurrent migrators (two
        processes starting at once) each apply a given step at most once and
        re-running is a no-op — idempotent by construction.
        """
        applied: list[Migration] = []
        with self.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_version (
                        version    INTEGER PRIMARY KEY,
                        name       TEXT NOT NULL,
                        applied_at INTEGER NOT NULL
                    )
                    """
                )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        for mig in MIGRATIONS:
            with self.transaction() as conn:
                row = conn.execute(
                    "SELECT 1 FROM schema_version WHERE version = ?", (mig.version,)
                ).fetchone()
                if row is not None:
                    continue  # already applied (possibly by a racing process)
                mig.apply(conn)
                conn.execute(
                    "INSERT INTO schema_version (version, name, applied_at) VALUES (?, ?, ?)",
                    (mig.version, mig.name, _now()),
                )
                applied.append(mig)
        return applied

    # -- introspection -----------------------------------------------------
    def table_counts(self) -> dict[str, int]:
        """Row counts for every schema table (for ``cortex db status``)."""
        counts: dict[str, int] = {}
        with self.connection() as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' AND name != 'schema_version' "
                "ORDER BY name"
            ).fetchall()
            for t in tables:
                name = t["name"]
                counts[name] = int(
                    conn.execute(f'SELECT COUNT(*) AS c FROM "{name}"').fetchone()["c"]
                )
        return counts
