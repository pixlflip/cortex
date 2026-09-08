"""Multi-vault authorization (B2).

This module is the single identity -> vault/scopes resolver shared by MCP and
the JSON API.  Storage lives in :mod:`cortex.vaults`; this layer decides which
of those stores a caller may address before any path-level scope check runs.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import CortexConfig, Principal
from .vaults import VaultBundle, VaultManager, VaultManagerError


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
            return [VaultGrant(principal.name, tuple(principal.scopes),
                               tuple(principal.write_scopes or principal.scopes), "owner")]
        if user["disabled"]:
            return []
        token_scopes = principal.token_scopes
        scopes = tuple(token_scopes) if token_scopes is not None else ("**",)
        if not scopes:
            return []
        ids = [user["username"]]
        if user["is_admin"]:
            # Cross-account access remains explicit and admin-only. Unowned
            # directories are not grants, even if left behind by old versions.
            ids += [u["username"] for u in self.identity.list_users()
                    if u["username"] != user["username"]]
        return [VaultGrant(v, scopes, scopes,
                           "owner" if v == user["username"] else "admin")
                for v in ids if self.manager.exists(v)]

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
        if grant is None or (write and not grant.write_scopes):
            raise VaultAccessError("vault not found or not in scope")
        try:
            bundle = self.manager.get(grant.vault_id)
        except VaultManagerError as exc:
            raise VaultAccessError("vault not found or not in scope") from exc
        return bundle, grant.principal(principal), grant
