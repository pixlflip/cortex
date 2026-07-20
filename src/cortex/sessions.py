"""HTTP glue for user login sessions: cookie handling + CSRF enforcement.

This is the thin, framework-facing layer over
:class:`cortex.users.IdentityService` that the A6 ``/api/v1`` routes (and any
other server route) attach to. It deliberately renders no pages — the SPA is
C1's — it only knows how to:

* set/clear the session cookie with the #19 hardening flags (HttpOnly,
  SameSite=Lax, Secure under HTTPS, Max-Age),
* resolve a request's cookie to a user (server-side session lookup with
  expiry + sliding renewal), and
* enforce CSRF on state-changing, cookie-authenticated requests.

**CSRF scheme (documented choice): session-bound double-submit token.**
At login the client receives ``csrf_token = sha256("cortex-csrf:" +
session_token)`` once, alongside the HttpOnly cookie. Every state-changing
request must echo it in the ``X-Cortex-CSRF`` header; the server recomputes
the expected value from the presented cookie and compares constant-time. A
cross-site attacker can *send* the cookie but can neither read it nor derive
the header value, so forged requests fail. The token is stateless (nothing
stored, dies with its session) and, being header-carried, is immune to the
cookie-tossing weaknesses of the classic cookie-pair double-submit. Bearer-
authenticated calls are CSRF-immune by construction (§7.1) — this layer only
governs cookie auth. This aligns with the A1 admin-cookie hardening (same
flag set, same TTL) rather than inventing a second scheme; the admin UI's
HMAC-signed stateless cookie remains legacy-only until the SPA replaces it.
"""

from __future__ import annotations

import hmac

from starlette.requests import Request
from starlette.responses import Response

from .users import IdentityService

#: Name of the user session cookie (distinct from the legacy ``cortex_admin``).
SESSION_COOKIE = "cortex_session"

#: Header carrying the session-bound CSRF token on state-changing requests.
CSRF_HEADER = "x-cortex-csrf"

#: Methods that never change state and therefore need no CSRF proof.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class SessionAuth:
    """Cookie-based request authentication over an :class:`IdentityService`.

    ``secure_cookies`` should be True whenever the public base URL is
    https:// — the same rule the admin UI applies (#19): only skip the
    Secure flag for plain-HTTP localhost setups that could otherwise never
    log in.
    """

    def __init__(self, identity: IdentityService, *, secure_cookies: bool):
        self.identity = identity
        self.secure_cookies = bool(secure_cookies)

    # -- cookie lifecycle ---------------------------------------------------

    def set_session_cookie(self, response: Response, session_token: str) -> None:
        response.set_cookie(
            SESSION_COOKIE,
            session_token,
            max_age=self.identity.session_ttl,
            httponly=True,
            samesite="lax",
            secure=self.secure_cookies,
            path="/",
        )

    def clear_session_cookie(self, response: Response) -> None:
        response.delete_cookie(SESSION_COOKIE, path="/")

    # -- request resolution ---------------------------------------------------

    @staticmethod
    def session_token(request: Request) -> str | None:
        return request.cookies.get(SESSION_COOKIE) or None

    def user_for_request(self, request: Request) -> dict | None:
        """The enabled user behind the request's session cookie, or None.
        Resolution slides the session's expiry (see IdentityService)."""
        return self.identity.resolve_session(self.session_token(request))

    def csrf_ok(self, request: Request) -> bool:
        """True iff the request needs no CSRF proof (safe method) or carries
        a valid session-bound CSRF header for its cookie."""
        if request.method.upper() in SAFE_METHODS:
            return True
        token = self.session_token(request)
        presented = request.headers.get(CSRF_HEADER, "")
        if not token or not presented:
            return False
        expected = self.identity.csrf_token_for(token)
        return hmac.compare_digest(presented, expected)

    def authenticate(self, request: Request) -> dict | None:
        """Full cookie-auth pipeline for one request: session → user, plus
        CSRF enforcement on state-changing methods. Returns the user row, or
        None if the request must be treated as unauthenticated (A6 turns
        that into 401/403)."""
        user = self.user_for_request(request)
        if user is None:
            return None
        if not self.csrf_ok(request):
            return None
        return user

    def logout(self, request: Request, response: Response) -> bool:
        """Destroy the request's session server-side and clear its cookie.
        Logout is state-changing, so callers should gate it on csrf_ok."""
        destroyed = self.identity.logout(self.session_token(request))
        self.clear_session_cookie(response)
        return destroyed
