"""Durable account-ID-bound vault grants. Authorization lives in users/access."""
from __future__ import annotations

import json
import logging
import time

from .core import Database
from ..scopes import validate_grant_scopes

log = logging.getLogger(__name__)


class VaultGrantsRepo:
    def __init__(self, db: Database):
        self.db = db

    def set(
        self, principal_user_id: int, owner_user_id: int, *,
        read_scopes: list[str], write_scopes: list[str], updated_by: int | None,
    ) -> None:
        read = validate_grant_scopes(read_scopes)
        write = validate_grant_scopes(write_scopes)
        with self.db.transaction() as conn:
            conn.execute(
                """INSERT INTO vault_grants
                   (principal_user_id, owner_user_id, read_scopes_json,
                    write_scopes_json, updated_by, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(principal_user_id, owner_user_id) DO UPDATE SET
                     read_scopes_json = excluded.read_scopes_json,
                     write_scopes_json = excluded.write_scopes_json,
                     updated_by = excluded.updated_by,
                     updated_at = excluded.updated_at""",
                (principal_user_id, owner_user_id, json.dumps(read), json.dumps(write),
                 updated_by, int(time.time())),
            )

    def list(self, principal_user_id: int | None = None, *, active_only: bool = False) -> list[dict]:
        # Join actual account rows, never directory names or group membership.
        sql = """SELECT g.*, p.username AS principal, o.username AS vault
                 FROM vault_grants g
                 JOIN users p ON p.id = g.principal_user_id
                 JOIN users o ON o.id = g.owner_user_id WHERE 1=1"""
        params = []
        if principal_user_id is not None:
            sql += " AND g.principal_user_id = ?"
            params.append(principal_user_id)
        if active_only:
            sql += " AND p.disabled = 0 AND o.disabled = 0"
        sql += " ORDER BY p.username, o.username"
        with self.db.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["read_scopes"] = validate_grant_scopes(json.loads(item.pop("read_scopes_json")))
                item["write_scopes"] = validate_grant_scopes(json.loads(item.pop("write_scopes_json")))
            except (ValueError, TypeError):
                # Corrupt/hand-edited state must never create a fallback grant.
                log.warning("ignoring malformed vault grant for account IDs %s/%s",
                            row["principal_user_id"], row["owner_user_id"])
                continue
            result.append(item)
        return result

    def delete(self, principal_user_id: int, owner_user_id: int) -> bool:
        with self.db.transaction() as conn:
            return conn.execute(
                "DELETE FROM vault_grants WHERE principal_user_id = ? AND owner_user_id = ?",
                (principal_user_id, owner_user_id),
            ).rowcount > 0
