"""Shared envelope, identity and throttling primitives for ``/api/v1``."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from starlette.responses import JSONResponse

from ..config import Principal

API_PREFIX = "/api/v1"

log = logging.getLogger("cortex.api")
access_log = logging.getLogger("cortex.api.access")

#: Uniform 401 wording — never distinguishes missing vs invalid vs foreign-
#: source credentials (no oracle).
_UNAUTHENTICATED = "authentication required"

#: Uniform login-failure wording — unknown user, wrong password, disabled
#: account, and LDAP-vs-local are indistinguishable (design §7.1).
_BAD_LOGIN = "invalid username or password"

#: Uniform not-found wording — also used for resources the caller is not
#: allowed to know exist (#21: out-of-authz is indistinguishable from absent).
_NOT_FOUND = "not found"


def error_response(status: int, code: str, message: str) -> JSONResponse:
    """The one error envelope every ``/api/v1`` error uses."""
    return JSONResponse(
        {"error": {"code": code, "message": message}}, status_code=status
    )


class ApiError(Exception):
    """Control-flow error rendered as the uniform envelope by the wrapper."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message

    def response(self) -> JSONResponse:
        return error_response(self.status, self.code, self.message)


def _unauthenticated() -> ApiError:
    return ApiError(401, "unauthenticated", _UNAUTHENTICATED)


@dataclass
class ApiIdentity:
    """The resolved caller of one request: a user row plus how it
    authenticated (``session`` or ``bearer``)."""

    user: dict
    via: str  # "session" | "bearer"
    principal: Principal | None = None

    @property
    def username(self) -> str:
        return self.user["username"]

    @property
    def is_admin(self) -> bool:
        return bool(self.user["is_admin"]) and not self.user["disabled"]

    @property
    def subject(self) -> str:
        return f"user:{self.username}"


class LoginRateLimiter:
    """Minimal fixed-window failure throttle for the login route (§7.1).

    Keyed by lowercased username so an attacker can't hammer one account;
    applied *before* any credential check so the throttle itself leaks
    nothing about whether the account exists. In-memory — a restart clears
    it, which is fine for the brute-force class it addresses.
    """

    def __init__(self, max_failures: int = 5, window_seconds: int = 300):
        self.max_failures = int(max_failures)
        self.window_seconds = int(window_seconds)
        self._failures: dict[str, list[float]] = {}

    def _prune(self, key: str, now: float) -> list[float]:
        stamps = [
            t for t in self._failures.get(key, []) if now - t < self.window_seconds
        ]
        if stamps:
            self._failures[key] = stamps
        else:
            self._failures.pop(key, None)
        return stamps

    def blocked(self, key: str) -> bool:
        return len(self._prune(key.lower(), time.monotonic())) >= self.max_failures

    def record_failure(self, key: str) -> None:
        self._failures.setdefault(key.lower(), []).append(time.monotonic())

    def reset(self, key: str) -> None:
        self._failures.pop(key.lower(), None)
