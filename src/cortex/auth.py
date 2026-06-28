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


class Authenticator:
    def __init__(self, config: CortexConfig):
        self.config = config
        # Index principals by their (resolved) token for HTTP lookups.
        self._by_token: dict[str, Principal] = {
            p.token: p for p in config.principals if p.token
        }

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
        if not token:
            raise AuthError("missing bearer token")
        for candidate_token, principal in self._by_token.items():
            if hmac.compare_digest(candidate_token, token):
                return principal
        raise AuthError("invalid bearer token")
