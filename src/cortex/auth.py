"""Auth — map a credential to a principal.

A bearer token maps to exactly one principal. The server treats "principal X
called this" and "a holder of X's token called this" as identical — which is
precisely why the mapping must be explicit and enforced.

Transport rules (from the architecture's safety model):

* **stdio** (local, trusted): carries no bearer token. Resolves to the
  configured ``auth.local_principal``. If none is configured, access is denied.
* **http** (remote/public): a bearer token is required and must map to a
  principal. No mapping → 401. Public exposure without this mapping is not
  permitted (``CortexConfig`` validation enforces ``auth.enabled`` for http).

Token comparison is constant-time to avoid leaking validity via timing.
"""

from __future__ import annotations

import hmac

from .config import CortexConfig, Principal


class AuthError(Exception):
    """Raised when a credential cannot be mapped to a principal."""


# Subject namespace for principals resolved from the admin store's AI clients.
# Config principal names may not start with this (enforced at config load and
# again here), and AdminStore._clean_name strips ':' from client names, so a
# namespaced subject can never be forged by either side (#9).
ADMIN_SUBJECT_PREFIX = "client:"

# Subject namespace for identities resolved from SQLite user API tokens (v2
# design §3.1). Config principal names may not start with this, and the
# username charset (cortex.users) admits no ':', so a user can never forge a
# foreign subject — the generalized #9 model.
USER_SUBJECT_PREFIX = "user:"

_RESERVED_SUBJECT_PREFIXES = (ADMIN_SUBJECT_PREFIX, USER_SUBJECT_PREFIX)


class Authenticator:
    def __init__(self, config: CortexConfig, admin_store=None, user_service=None):
        self.config = config
        self.admin_store = admin_store
        # An IdentityService (cortex.users) when the SQLite identity DB is in
        # play; duck-typed here to keep this module import-light.
        self.user_service = user_service
        # Index principals by their (resolved) token for HTTP lookups.
        self._by_token: dict[str, Principal] = {
            p.token: p for p in config.principals if p.token
        }
        self._guard_collisions()

    def _guard_collisions(self) -> None:
        """Refuse to start when identities collide across sources: an
        admin-store client or a DB user sharing a name with a config
        principal, or a config principal squatting on a reserved subject
        namespace. Subject namespacing already prevents *resolving* across
        stores, but a collision is always operator error and silently keeping
        two identically-named identities invites confusion in the audit
        trail (#9, generalized to the ``user:`` source)."""
        config_names = {p.name for p in self.config.principals}
        for name in config_names:
            for prefix in _RESERVED_SUBJECT_PREFIXES:
                if name.startswith(prefix):
                    raise AuthError(
                        f"config principal name {name!r} is reserved: names may "
                        f"not start with {prefix!r}"
                    )
        if self.admin_store is not None and self.admin_store.exists():
            colliding = sorted(config_names & set(self.admin_store.clients()))
            if colliding:
                raise AuthError(
                    "admin-store client name(s) collide with config principals: "
                    + ", ".join(colliding)
                    + " — rename the client or the principal"
                )
        if self.user_service is not None:
            colliding = sorted(config_names & self.user_service.usernames())
            if colliding:
                raise AuthError(
                    "database username(s) collide with config principals: "
                    + ", ".join(colliding)
                    + " — rename the user or the principal"
                )

    def for_stdio(self) -> Principal:
        """Resolve the principal for a local stdio connection."""
        name = self.config.auth.local_principal
        if not name:
            raise AuthError(
                "stdio access denied: set auth.local_principal to a defined principal"
            )
        principal = self.config.principal(name)
        if principal is None:  # pragma: no cover - validated at load
            raise AuthError(f"auth.local_principal '{name}' is not defined")
        return principal

    def for_token(self, token: str | None) -> Principal:
        """Resolve the principal for an HTTP bearer token (constant-time)."""
        return self.resolve_token(token)[0]

    def resolve_token(self, token: str | None) -> tuple[Principal, str]:
        """Resolve a bearer token to ``(principal, subject)``.

        Resolution walks the fixed v2 §3.1 order, stopping at the first
        match: config principals → SQLite user API tokens → legacy
        admin-store clients. The subject carries the auth *source*: config
        principals use their plain name, user tokens are namespaced
        ``user:<username>``, admin-store clients ``client:<name>``.
        Subject-based resolution later (``_get_principal``) must consult the
        same store that authenticated the token — otherwise an identity in
        one store named like an identity in another inherits its scopes (#9).
        """
        if not token:
            raise AuthError("missing bearer token")
        for candidate_token, principal in self._by_token.items():
            if hmac.compare_digest(candidate_token, token):
                return principal, principal.name
        if self.user_service is not None:
            resolved = self.user_service.resolve_api_token(token)
            if resolved is not None:
                principal, username = resolved
                return principal, f"{USER_SUBJECT_PREFIX}{username}"
        if self.admin_store is not None:
            principal = self.admin_store.principal_for_token(token)
            if principal is not None:
                return principal, f"{ADMIN_SUBJECT_PREFIX}{principal.name}"
        raise AuthError("invalid bearer token")
