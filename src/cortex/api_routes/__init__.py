"""Route handler groups mixed into :class:`cortex.api.ApiV1`."""

from .identity import IdentityRoutesMixin
from .policy import PolicyRoutesMixin
from .vaults import VaultRoutesMixin

__all__ = ["IdentityRoutesMixin", "PolicyRoutesMixin", "VaultRoutesMixin"]
