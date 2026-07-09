"""Typed CRUD primitives over the A3 tables.

These are deliberately *primitives*: create/get/list/update/delete plus the
credential-shaped operations (password set/verify, token mint/resolve,
session mint/resolve). Business logic — login flows, rate limiting, LDAP
sync, token-scope enforcement — belongs to A4/A5/A6 and is built on top of
these, not inside them.

All rows are returned as plain ``dict``s (converted from ``sqlite3.Row``)
so callers never hold anything tied to a closed connection.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from ..pwhash import TOKEN_PREFIX_LEN, check_secret, hash_secret, sha256_hex
from .core import Database

# User API tokens share the legacy client token shape ("ctx_" + urlsafe) so
# one prefix-lookup strategy serves both stores.
TOKEN_PREFIX = "ctx_"


def _now() -> int:
    return int(time.time())


def _row(row: Any) -> dict | None:
    return dict(row) if row is not None else None


def _rows(rows: Any) -> list[dict]:
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# users
# --------------------------------------------------------------------------

_USER_UPDATABLE = {
    "display_name",
    "email",
    "is_admin",
    "disabled",
    "ldap_dn",
    "auth_source",
}


class UsersRepo:
    def __init__(self, db: Database):
        self.db = db

    def create(
        self,
        username: str,
        *,
        display_name: str | None = None,
        email: str | None = None,
        auth_source: str = "local",
        password: str | None = None,
        password_salt: str | None = None,
        password_hash: str | None = None,
        ldap_dn: str | None = None,
        is_admin: bool = False,
        disabled: bool = False,
    ) -> dict:
        """Create a user. For local users pass either a plaintext ``password``
        (hashed here) or a pre-existing ``password_salt``/``password_hash``
        pair (the admin.json import path). LDAP users carry neither."""
        username = username.strip()
        if not username:
            raise ValueError("username is required")
        if auth_source not in ("local", "ldap"):
            raise ValueError(f"invalid auth_source: {auth_source!r}")
        if password is not None and (password_salt or password_hash):
            raise ValueError("pass either password or salt+hash, not both")
        if auth_source == "ldap" and (password or password_salt or password_hash):
            raise ValueError("ldap users carry no password material")
        if password is not None:
            password_salt, password_hash = hash_secret(password)
        with self.db.transaction() as conn:
            cur = conn.execute(
                """
                INSERT INTO users (username, display_name, email, auth_source,
                                   password_salt, password_hash, ldap_dn,
                                   is_admin, disabled, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    display_name,
                    email,
                    auth_source,
                    password_salt,
                    password_hash,
                    ldap_dn,
                    int(is_admin),
                    int(disabled),
                    _now(),
                ),
            )
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (cur.lastrowid,)
            ).fetchone()
            return dict(row)

    def get(self, user_id: int) -> dict | None:
        with self.db.connection() as conn:
            return _row(
                conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            )

    def get_by_username(self, username: str) -> dict | None:
        with self.db.connection() as conn:
            return _row(
                conn.execute(
                    "SELECT * FROM users WHERE username = ?", (username,)
                ).fetchone()
            )

    def list(self) -> list[dict]:
        with self.db.connection() as conn:
            return _rows(conn.execute("SELECT * FROM users ORDER BY username").fetchall())

    def update(self, user_id: int, **fields: Any) -> dict | None:
        """Update whitelisted profile fields. Password changes go through
        :meth:`set_password`; unknown fields raise."""
        bad = set(fields) - _USER_UPDATABLE
        if bad:
            raise ValueError(f"cannot update field(s): {', '.join(sorted(bad))}")
        if not fields:
            return self.get(user_id)
        sets = ", ".join(f"{k} = ?" for k in fields)
        values = [
            int(v) if isinstance(v, bool) else v for v in fields.values()
        ]
        with self.db.transaction() as conn:
            conn.execute(f"UPDATE users SET {sets} WHERE id = ?", (*values, user_id))
            return _row(
                conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            )

    def delete(self, user_id: int) -> bool:
        with self.db.transaction() as conn:
            cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            return cur.rowcount > 0

    # -- credentials ------------------------------------------------------
    def set_password(self, user_id: int, password: str) -> None:
        if not password:
            raise ValueError("password is required")
        salt, digest = hash_secret(password)
        with self.db.transaction() as conn:
            user = conn.execute(
                "SELECT auth_source FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if user is None:
                raise ValueError(f"no such user id: {user_id}")
            if user["auth_source"] != "local":
                raise ValueError("only local users carry a password")
            conn.execute(
                "UPDATE users SET password_salt = ?, password_hash = ? WHERE id = ?",
                (salt, digest, user_id),
            )

    def verify_password(self, username: str, password: str) -> dict | None:
        """Constant-time password check for a local, enabled user. Returns
        the user row on success, else ``None`` — never distinguishes missing
        user / wrong password / disabled / non-local (no oracle)."""
        user = self.get_by_username(username)
        if (
            user is None
            or user["disabled"]
            or user["auth_source"] != "local"
            or not user["password_salt"]
            or not user["password_hash"]
        ):
            return None
        if not check_secret(
            password, salt=user["password_salt"], digest=user["password_hash"]
        ):
            return None
        return user

    def touch_last_login(self, user_id: int, when: int | None = None) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE users SET last_login_at = ? WHERE id = ?",
                (when or _now(), user_id),
            )


# --------------------------------------------------------------------------
# groups + membership
# --------------------------------------------------------------------------

_GROUP_UPDATABLE = {"ldap_dn", "scopes_json"}


class GroupsRepo:
    def __init__(self, db: Database):
        self.db = db

    def create(
        self,
        name: str,
        *,
        source: str = "local",
        ldap_dn: str | None = None,
        scopes: list[str] | None = None,
    ) -> dict:
        name = name.strip()
        if not name:
            raise ValueError("group name is required")
        if source not in ("local", "ldap"):
            raise ValueError(f"invalid group source: {source!r}")
        with self.db.transaction() as conn:
            cur = conn.execute(
                """
                INSERT INTO groups (name, source, ldap_dn, scopes_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    name,
                    source,
                    ldap_dn,
                    json.dumps(scopes) if scopes is not None else None,
                    _now(),
                ),
            )
            return dict(
                conn.execute(
                    "SELECT * FROM groups WHERE id = ?", (cur.lastrowid,)
                ).fetchone()
            )

    def get(self, group_id: int) -> dict | None:
        with self.db.connection() as conn:
            return _row(
                conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
            )

    def get_by_name(self, name: str) -> dict | None:
        with self.db.connection() as conn:
            return _row(
                conn.execute("SELECT * FROM groups WHERE name = ?", (name,)).fetchone()
            )

    def list(self) -> list[dict]:
        with self.db.connection() as conn:
            return _rows(conn.execute("SELECT * FROM groups ORDER BY name").fetchall())

    def update(self, group_id: int, **fields: Any) -> dict | None:
        bad = set(fields) - _GROUP_UPDATABLE
        if bad:
            raise ValueError(f"cannot update field(s): {', '.join(sorted(bad))}")
        if not fields:
            return self.get(group_id)
        sets = ", ".join(f"{k} = ?" for k in fields)
        with self.db.transaction() as conn:
            conn.execute(
                f"UPDATE groups SET {sets} WHERE id = ?", (*fields.values(), group_id)
            )
            return _row(
                conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
            )

    def set_scopes(self, group_id: int, scopes: list[str]) -> None:
        self.update(group_id, scopes_json=json.dumps(scopes))

    def scopes(self, group_id: int) -> list[str]:
        group = self.get(group_id)
        if group is None or not group["scopes_json"]:
            return []
        return list(json.loads(group["scopes_json"]))

    def delete(self, group_id: int) -> bool:
        with self.db.transaction() as conn:
            cur = conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
            return cur.rowcount > 0

    # -- membership --------------------------------------------------------
    def add_member(self, group_id: int, user_id: int) -> bool:
        """Add a user to a group; returns False if already a member."""
        with self.db.transaction() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)",
                (user_id, group_id),
            )
            return cur.rowcount > 0

    def remove_member(self, group_id: int, user_id: int) -> bool:
        with self.db.transaction() as conn:
            cur = conn.execute(
                "DELETE FROM user_groups WHERE user_id = ? AND group_id = ?",
                (user_id, group_id),
            )
            return cur.rowcount > 0

    def members(self, group_id: int) -> list[dict]:
        with self.db.connection() as conn:
            return _rows(
                conn.execute(
                    """
                    SELECT u.* FROM users u
                    JOIN user_groups ug ON ug.user_id = u.id
                    WHERE ug.group_id = ? ORDER BY u.username
                    """,
                    (group_id,),
                ).fetchall()
            )

    def groups_for_user(self, user_id: int) -> list[dict]:
        with self.db.connection() as conn:
            return _rows(
                conn.execute(
                    """
                    SELECT g.* FROM groups g
                    JOIN user_groups ug ON ug.group_id = g.id
                    WHERE ug.user_id = ? ORDER BY g.name
                    """,
                    (user_id,),
                ).fetchall()
            )


# --------------------------------------------------------------------------
# api_tokens
# --------------------------------------------------------------------------


@dataclass
class CreatedApiToken:
    """The one moment the plaintext token exists — show it, then drop it."""

    id: int
    user_id: int
    name: str
    token: str
    token_prefix: str


class ApiTokensRepo:
    def __init__(self, db: Database):
        self.db = db

    def create(
        self,
        user_id: int,
        name: str,
        *,
        scopes: list[str] | None = None,
        expires_at: int | None = None,
    ) -> CreatedApiToken:
        name = name.strip()
        if not name:
            raise ValueError("token name is required")
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        salt, digest = hash_secret(token)
        with self.db.transaction() as conn:
            cur = conn.execute(
                """
                INSERT INTO api_tokens (user_id, name, token_prefix, salt,
                                        token_hash, scopes_json, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    name,
                    token[:TOKEN_PREFIX_LEN],
                    salt,
                    digest,
                    json.dumps(scopes) if scopes is not None else None,
                    _now(),
                    expires_at,
                ),
            )
            token_id = cur.lastrowid
        return CreatedApiToken(
            id=token_id,
            user_id=user_id,
            name=name,
            token=token,
            token_prefix=token[:TOKEN_PREFIX_LEN],
        )

    def import_hashed(
        self,
        user_id: int,
        name: str,
        *,
        token_prefix: str,
        salt: str,
        token_hash: str,
        created_at: int | None = None,
        scopes: list[str] | None = None,
    ) -> dict:
        """Insert a token whose hash already exists (admin.json import) —
        the plaintext is never seen, so existing tokens keep working."""
        with self.db.transaction() as conn:
            cur = conn.execute(
                """
                INSERT INTO api_tokens (user_id, name, token_prefix, salt,
                                        token_hash, scopes_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    name,
                    token_prefix,
                    salt,
                    token_hash,
                    json.dumps(scopes) if scopes is not None else None,
                    created_at or _now(),
                ),
            )
            return dict(
                conn.execute(
                    "SELECT * FROM api_tokens WHERE id = ?", (cur.lastrowid,)
                ).fetchone()
            )

    def get(self, token_id: int) -> dict | None:
        with self.db.connection() as conn:
            return _row(
                conn.execute(
                    "SELECT * FROM api_tokens WHERE id = ?", (token_id,)
                ).fetchone()
            )

    def list_for_user(self, user_id: int) -> list[dict]:
        with self.db.connection() as conn:
            return _rows(
                conn.execute(
                    "SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at, id",
                    (user_id,),
                ).fetchall()
            )

    def resolve(self, token: str | None, *, touch: bool = True) -> dict | None:
        """Resolve a presented bearer token to its live row, or ``None``.

        Prefix-indexed candidate lookup first, PBKDF2 verify second (#14):
        a token matching no stored prefix costs zero PBKDF2 iterations.
        Revoked and expired tokens do not resolve. On success the row's
        ``last_used_at`` is touched (best-effort) unless ``touch=False``.
        """
        if not token:
            return None
        prefix = token[:TOKEN_PREFIX_LEN]
        now = _now()
        with self.db.connection() as conn:
            candidates = conn.execute(
                "SELECT * FROM api_tokens WHERE token_prefix = ?", (prefix,)
            ).fetchall()
        for cand in candidates:
            if cand["revoked_at"] is not None:
                continue
            if cand["expires_at"] is not None and cand["expires_at"] <= now:
                continue
            if check_secret(token, salt=cand["salt"], digest=cand["token_hash"]):
                if touch:
                    with self.db.transaction() as conn:
                        conn.execute(
                            "UPDATE api_tokens SET last_used_at = ? WHERE id = ?",
                            (now, cand["id"]),
                        )
                row = dict(cand)
                row["last_used_at"] = now if touch else row["last_used_at"]
                return row
        return None

    def revoke(self, token_id: int) -> bool:
        """Idempotently mark a token revoked; returns False if already revoked
        or missing."""
        with self.db.transaction() as conn:
            cur = conn.execute(
                "UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (_now(), token_id),
            )
            return cur.rowcount > 0

    def delete(self, token_id: int) -> bool:
        with self.db.transaction() as conn:
            cur = conn.execute("DELETE FROM api_tokens WHERE id = ?", (token_id,))
            return cur.rowcount > 0


# --------------------------------------------------------------------------
# sessions
# --------------------------------------------------------------------------


@dataclass
class CreatedSession:
    id: int
    user_id: int
    token: str
    expires_at: int


class SessionsRepo:
    def __init__(self, db: Database):
        self.db = db

    def create(self, user_id: int, *, ttl_seconds: int) -> CreatedSession:
        """Mint a session: random token, stored as an (unsalted) SHA-256 —
        the token is high-entropy random, and the digest doubles as the
        unique O(1) lookup key."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        token = secrets.token_urlsafe(32)
        now = _now()
        expires_at = now + ttl_seconds
        with self.db.transaction() as conn:
            cur = conn.execute(
                """
                INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (sha256_hex(token), user_id, now, expires_at, now),
            )
            session_id = cur.lastrowid
        return CreatedSession(
            id=session_id, user_id=user_id, token=token, expires_at=expires_at
        )

    def resolve(self, token: str | None, *, touch: bool = True) -> dict | None:
        """Resolve a session token to its unexpired row (else ``None``),
        sliding ``last_seen_at`` forward unless ``touch=False``."""
        if not token:
            return None
        now = _now()
        with self.db.connection() as conn:
            row = _row(
                conn.execute(
                    "SELECT * FROM sessions WHERE token_hash = ? AND expires_at > ?",
                    (sha256_hex(token), now),
                ).fetchone()
            )
        if row is None:
            return None
        if touch:
            with self.db.transaction() as conn:
                conn.execute(
                    "UPDATE sessions SET last_seen_at = ? WHERE id = ?", (now, row["id"])
                )
            row["last_seen_at"] = now
        return row

    def extend(self, session_id: int, expires_at: int) -> None:
        """Move a session's expiry forward (sliding renewal — A4)."""
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE sessions SET expires_at = ? WHERE id = ?",
                (expires_at, session_id),
            )

    def get(self, session_id: int) -> dict | None:
        with self.db.connection() as conn:
            return _row(
                conn.execute(
                    "SELECT * FROM sessions WHERE id = ?", (session_id,)
                ).fetchone()
            )

    def list_for_user(self, user_id: int) -> list[dict]:
        with self.db.connection() as conn:
            return _rows(
                conn.execute(
                    "SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at, id",
                    (user_id,),
                ).fetchall()
            )

    def delete(self, session_id: int) -> bool:
        with self.db.transaction() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            return cur.rowcount > 0

    def delete_by_token(self, token: str) -> bool:
        """Delete the session identified by its (plaintext) token — logout."""
        with self.db.transaction() as conn:
            cur = conn.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (sha256_hex(token),)
            )
            return cur.rowcount > 0

    def delete_for_user(self, user_id: int) -> int:
        with self.db.transaction() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            return cur.rowcount

    def purge_expired(self, *, now: int | None = None) -> int:
        with self.db.transaction() as conn:
            cur = conn.execute(
                "DELETE FROM sessions WHERE expires_at <= ?", (now or _now(),)
            )
            return cur.rowcount
