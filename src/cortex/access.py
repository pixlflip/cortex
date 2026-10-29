"""Multi-vault authorization (B2).

This module is the single identity -> vault/scopes resolver shared by MCP and
the JSON API.  Storage lives in :mod:`cortex.vaults`; this layer decides which
of those stores a caller may address before any path-level scope check runs.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import CortexConfig, Principal
from .scopes import Scope, intersect_scopes
from .vaults import VaultBundle, VaultManager, VaultManagerError


class VaultAccessError(Exception):
    """Uniform, non-leaking failure for an invisible vault."""


@dataclass(frozen=True)
class VaultGrant:
    vault_id: str
    scopes: tuple[Scope, ...]
    write_scopes: tuple[Scope, ...]
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
    """Resolve account-owned memory. No global/shared-vault fallback.

    Group tool policies remain independent of memory ownership. Legacy group
    path grants do not confer access to any account's vault.
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
            # Config-only local identities have exactly their named account.
            # On an identity-backed server, a missing DB account is not a user.
            if self.identity is not None or not self.manager.exists(principal.name):
                return []
            writes = principal.scopes if principal.write_scopes is None else principal.write_scopes
            return [VaultGrant(principal.name, tuple(principal.scopes), tuple(writes), "owner")]
        if user["disabled"]:
            return []
        token_scopes = principal.token_scopes
        scopes = tuple(token_scopes) if token_scopes is not None else ("**",)
        if not scopes:
            return []
        ids = [user["username"]]
        if user["is_admin"]:
            # Unowned directories never confer access, even for administrators.
            ids += [u["username"] for u in self.identity.list_users()
                    if u["username"] != user["username"]]
        grants = [VaultGrant(v, scopes, scopes,
                             "owner" if v == user["username"] else "admin")
                  for v in ids if self.manager.exists(v)]
        if not user["is_admin"]:
            # Read current durable policy on EVERY resolution (no grant cache).
            # Account deletion cascades both ends; disabled owners/grantees do
            # not activate explicit grants. Owner/admin powers are independent.
            for row in self.identity.vault_grants.list(user["id"], active_only=True):
                read = intersect_scopes(row["read_scopes"], token_scopes)
                write = intersect_scopes(row["write_scopes"], token_scopes)
                if (read or write) and self.manager.exists(row["vault"]):
                    grants.append(VaultGrant(row["vault"], read, write, "explicit"))
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
            # Never default to a different account, even for administrators.
            grant = next((g for g in grants if g.vault_id == principal.name), None)
        if grant is None or not (grant.write_scopes if write else grant.scopes):
            raise VaultAccessError("vault not found or not in scope")
        try:
            bundle = self.manager.get(grant.vault_id)
        except VaultManagerError as exc:
            raise VaultAccessError("vault not found or not in scope") from exc
        return bundle, grant.principal(principal), grant
