"""Multi-vault authorization (B2).

This module is the single identity -> vault/scopes resolver shared by MCP and
the JSON API.  Storage lives in :mod:`cortex.vaults`; this layer decides which
of those stores a caller may address before any path-level scope check runs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .config import CortexConfig, Principal
from .vaults import MAIN_VAULT_ID, VaultBundle, VaultManager, VaultManagerError


class VaultAccessError(Exception):
    """Uniform, non-leaking failure for an invisible vault."""


@dataclass(frozen=True)
class VaultGrant:
    vault_id: str
    scopes: tuple[str, ...]
    write_scopes: tuple[str, ...]
    relation: str

    def principal(self, source: Principal) -> Principal:
        return Principal(
            name=source.name,
            scopes=list(self.scopes),
            token_env=source.token_env,
            token=source.token,
            write_scopes=list(self.write_scopes),
        )


class VaultAccessResolver:
    """Resolve container and macro views for one request.

    * SQLite users own exactly one private vault.  Admin users get the macro
      view across every registered vault.
    * Group ``scopes_json`` grants read access into ``main``; migration 2's
      ``write_scopes_json`` independently grants mutations there.
    * Config principals and legacy admin clients remain main-vault identities
      for backward compatibility.
    """

    def __init__(
        self,
        config: CortexConfig,
        manager: VaultManager,
        identity=None,
    ):
        self.config = config
        self.manager = manager
        self.identity = identity

    def _user(self, principal: Principal) -> dict | None:
        if self.identity is None:
            return None
        return self.identity.users.get_by_username(principal.name)

    def grants(self, principal: Principal) -> list[VaultGrant]:
        user = self._user(principal)
        if user is None:
            return [
                VaultGrant(
                    MAIN_VAULT_ID,
                    tuple(principal.scopes),
                    tuple(principal.write_scopes or principal.scopes),
                    "principal",
                )
            ]

        if user["disabled"]:
            return []
        token_scopes = principal.token_scopes
        if user["is_admin"]:
            scopes = tuple(token_scopes) if token_scopes is not None else ("**",)
            return [
                VaultGrant(vault_id, scopes, scopes, "admin")
                for vault_id in self.manager.vault_ids()
                if scopes
            ]

        grants: list[VaultGrant] = []
        if self.manager.exists(user["username"]):
            owner_scopes = (
                tuple(token_scopes) if token_scopes is not None else ("**",)
            )
            if owner_scopes:
                grants.append(
                    VaultGrant(
                        user["username"], owner_scopes, owner_scopes, "owner"
                    )
                )

        read_scopes: list[str] = []
        write_scopes: list[str] = []
        for group in self.identity.groups.groups_for_user(user["id"]):
            raw_read = group.get("scopes_json")
            for scope in json.loads(raw_read or "[]"):
                if scope not in read_scopes:
                    read_scopes.append(scope)
            raw_write = group.get("write_scopes_json") if isinstance(group, dict) else None
            # NULL preserves the v1 behavior: writable scope falls back to
            # readable scope. An explicit [] means deliberately read-only.
            for scope in json.loads(raw_write if raw_write is not None else (raw_read or "[]")):
                if scope not in write_scopes:
                    write_scopes.append(scope)
        if token_scopes is not None:
            # ``principal.scopes`` is the already-contained intersection of
            # token constraints with shared read grants. Write grants must be
            # narrowed independently with the same containment rule.
            read_scopes = list(principal.scopes)

            def within(candidate: str, grant: str) -> bool:
                if grant == "**" or candidate == grant:
                    return True
                if grant.endswith("/**"):
                    prefix = grant[:-3].rstrip("/")
                    return candidate == prefix or candidate.startswith(prefix + "/")
                return False

            write_scopes = [
                candidate
                for candidate in token_scopes
                if any(within(candidate, grant) for grant in write_scopes)
            ]
        if read_scopes or write_scopes:
            grants.append(
                VaultGrant(
                    MAIN_VAULT_ID,
                    tuple(read_scopes),
                    tuple(write_scopes),
                    "group",
                )
            )
        return grants

    def visible_vaults(self, principal: Principal) -> list[str]:
        return [g.vault_id for g in self.grants(principal)]

    def select(
        self,
        principal: Principal,
        requested_vault: str | None = None,
        *,
        write: bool = False,
    ) -> tuple[VaultBundle, Principal, VaultGrant]:
        grants = self.grants(principal)
        if requested_vault:
            grant = next((g for g in grants if g.vault_id == requested_vault), None)
        else:
            user = self._user(principal)
            preferred = (
                user["username"]
                if user is not None and not user["is_admin"]
                else MAIN_VAULT_ID
            )
            grant = next((g for g in grants if g.vault_id == preferred), None)
            if grant is None:
                grant = grants[0] if grants else None
        if grant is None or (write and not grant.write_scopes):
            raise VaultAccessError("vault not found or not in scope")
        try:
            bundle = self.manager.get(grant.vault_id)
        except VaultManagerError as exc:
            raise VaultAccessError("vault not found or not in scope") from exc
        return bundle, grant.principal(principal), grant
