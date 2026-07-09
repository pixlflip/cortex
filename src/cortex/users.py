"""Local user accounts, groups, per-user API tokens, and login sessions (A4).

This is the *domain* layer over the A3 SQLite repositories: the REST API
(A6) and the SPA (C1) call into it later, and the CLI (``cortex user`` /
``cortex token``) calls into it now. It owns the rules the repositories
deliberately do not:

* **Name hygiene** — usernames are validated against one charset and checked
  against every other identity namespace (config principals, the ``client:``
  admin-client namespace, the ``user:`` namespace itself), generalizing the
  #9 lesson: no identity may squat on another source's name.
* **Admin gating** — mutating operations require an admin *actor*. ``actor``
  is either a user row ``dict`` (checked for ``is_admin``) or
  :data:`OPERATOR` (``None``), meaning the trusted local operator running the
  CLI on the box — the same trust level as editing ``cortex.yaml``.
* **Login/session flow** (design §9.1) — password verify with no
  user-enumeration oracle, opaque random server-side session tokens with
  expiry + sliding renewal, and a session-bound CSRF token (see
  :meth:`IdentityService.csrf_token_for`).
* **API-token identity** — minting (raw token shown exactly once, stored
  salted-hash + prefix, #14) and resolution of a bearer token to its owning
  user's effective :class:`~cortex.config.Principal`.

Scopes here still target the single shared vault (v1 model): a user's
effective scopes are the union of their groups' ``scopes_json`` grants
(design §6.4). Per-user vaults and the container/macro split are B1/B2.
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass

from .auth import ADMIN_SUBJECT_PREFIX, USER_SUBJECT_PREFIX
from .config import CortexConfig, Principal
from .db import Database
from .db.repos import (
    ApiTokensRepo,
    CreatedApiToken,
    GroupsRepo,
    SessionsRepo,
    UsersRepo,
)
from .pwhash import sha256_hex

#: Default session lifetime — matches the legacy admin cookie TTL so the two
#: cookie schemes age identically during the transition.
DEFAULT_SESSION_TTL = 12 * 3600

#: Sentinel actor for the trusted local operator (CLI on the server box).
OPERATOR = None

# Usernames double as subjects (``user:<name>``) and, come B1, as vault
# directory slugs — so the charset is strict: leading alphanumeric, then
# alphanumerics plus ``. _ -``. Notably no ``:`` (subject-namespace safety)
# and no path separators (filesystem safety).
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Prefixes owned by other identity sources; a username squatting on one could
# forge a foreign subject if the charset rule ever loosened (defense in depth
# on top of _USERNAME_RE rejecting ':').
_RESERVED_PREFIXES = (USER_SUBJECT_PREFIX, ADMIN_SUBJECT_PREFIX)


class IdentityError(ValueError):
    """A domain-rule violation (bad name, collision, unknown user, ...)."""


class AuthzError(Exception):
    """The acting user is not permitted to perform this operation."""


def _now() -> int:
    return int(time.time())


@dataclass
class LoginResult:
    """A freshly minted session. ``session_token`` goes into the HttpOnly
    cookie; ``csrf_token`` is returned to the client once and echoed back in
    a header on every state-changing request (see :mod:`cortex.sessions`)."""

    user: dict
    session_id: int
    session_token: str
    csrf_token: str
    expires_at: int


class IdentityService:
    """User/group/token/session lifecycle over one :class:`Database`.

    ``config`` (optional) supplies the config-principal names that usernames
    must not collide with; pass it whenever a config is available.
    """

    def __init__(
        self,
        db: Database,
        config: CortexConfig | None = None,
        *,
        session_ttl: int = DEFAULT_SESSION_TTL,
    ):
        self.db = db
        self.config = config
        self.session_ttl = int(session_ttl)
        self.users = UsersRepo(db)
        self.groups = GroupsRepo(db)
        self.tokens = ApiTokensRepo(db)
        self.sessions = SessionsRepo(db)

    # -- authorization ------------------------------------------------------

    def _require_admin(self, actor: dict | None) -> None:
        """Gate an admin-only operation. ``OPERATOR`` (None) is the trusted
        local operator — the CLI running on the server box, equivalent in
        power to whoever edits cortex.yaml. Any other actor must be an
        enabled user row with ``is_admin`` set."""
        if actor is OPERATOR:
            return
        if actor.get("is_admin") and not actor.get("disabled"):
            return
        raise AuthzError("this operation requires an admin")

    @staticmethod
    def _is_self(actor: dict | None, user: dict) -> bool:
        return actor is not None and actor.get("id") == user["id"]

    def _require_admin_or_self(self, actor: dict | None, user: dict) -> None:
        if self._is_self(actor, user) and not actor.get("disabled"):
            return
        self._require_admin(actor)

    # -- user lifecycle -------------------------------------------------------

    def _validate_username(self, username: str) -> str:
        username = (username or "").strip()
        if not _USERNAME_RE.match(username):
            raise IdentityError(
                f"invalid username {username!r}: use 1-64 characters "
                "[A-Za-z0-9._-], starting with a letter or digit"
            )
        lowered = username.lower()
        for prefix in _RESERVED_PREFIXES:
            if lowered.startswith(prefix):
                raise IdentityError(
                    f"invalid username {username!r}: the {prefix!r} prefix is "
                    "reserved for subject namespacing"
                )
        if self.config is not None and self.config.principal(username) is not None:
            raise IdentityError(
                f"username {username!r} collides with a config principal — "
                "identities must be unique across all sources (#9)"
            )
        return username

    def create_user(
        self,
        username: str,
        *,
        password: str | None = None,
        display_name: str | None = None,
        email: str | None = None,
        is_admin: bool = False,
        actor: dict | None = OPERATOR,
    ) -> dict:
        """Create a **local** user (LDAP rows arrive via A5's sync, not here).
        Admin-only. Password may be set now or later via :meth:`set_password`."""
        self._require_admin(actor)
        username = self._validate_username(username)
        try:
            return self.users.create(
                username,
                display_name=display_name,
                email=email,
                auth_source="local",
                password=password,
                is_admin=is_admin,
            )
        except sqlite3.IntegrityError as exc:
            raise IdentityError(f"username already exists: {username}") from exc

    def get_user(self, username: str) -> dict:
        user = self.users.get_by_username(username)
        if user is None:
            raise IdentityError(f"no such user: {username}")
        return user

    def list_users(self) -> list[dict]:
        return self.users.list()

    def disable_user(self, username: str, *, actor: dict | None = OPERATOR) -> dict:
        """Disable a user: password login, session resolution, and API-token
        resolution all stop immediately (live sessions are deleted)."""
        self._require_admin(actor)
        user = self.get_user(username)
        updated = self.users.update(user["id"], disabled=True)
        self.sessions.delete_for_user(user["id"])
        return updated

    def enable_user(self, username: str, *, actor: dict | None = OPERATOR) -> dict:
        self._require_admin(actor)
        user = self.get_user(username)
        return self.users.update(user["id"], disabled=False)

    def delete_user(self, username: str, *, actor: dict | None = OPERATOR) -> None:
        """Delete a user row; sessions and API tokens go with it (FK CASCADE).
        Vault directories are B1's concern and are never touched from here."""
        self._require_admin(actor)
        user = self.get_user(username)
        self.users.delete(user["id"])

    def set_admin(self, username: str, is_admin: bool, *, actor: dict | None = OPERATOR) -> dict:
        self._require_admin(actor)
        user = self.get_user(username)
        return self.users.update(user["id"], is_admin=bool(is_admin))

    def set_password(
        self, username: str, password: str, *, actor: dict | None = OPERATOR
    ) -> None:
        """Set/reset a local user's password (PBKDF2 via cortex.pwhash).
        Allowed for admins and for the user themself."""
        user = self.get_user(username)
        self._require_admin_or_self(actor, user)
        if not password:
            raise IdentityError("password must not be empty")
        self.users.set_password(user["id"], password)

    # -- groups ---------------------------------------------------------------

    def create_group(
        self,
        name: str,
        *,
        scopes: list[str] | None = None,
        actor: dict | None = OPERATOR,
    ) -> dict:
        self._require_admin(actor)
        name = (name or "").strip()
        if not name:
            raise IdentityError("group name is required")
        try:
            return self.groups.create(name, source="local", scopes=scopes)
        except sqlite3.IntegrityError as exc:
            raise IdentityError(f"group already exists: {name}") from exc

    def get_group(self, name: str) -> dict:
        group = self.groups.get_by_name(name)
        if group is None:
            raise IdentityError(f"no such group: {name}")
        return group

    def list_groups(self) -> list[dict]:
        return self.groups.list()

    def delete_group(self, name: str, *, actor: dict | None = OPERATOR) -> None:
        """Delete a group; memberships go with it (FK CASCADE). Scope grants
        the group carried disappear with it — users lose that access."""
        self._require_admin(actor)
        group = self.get_group(name)
        self.groups.delete(group["id"])

    def set_group_scopes(
        self, name: str, scopes: list[str], *, actor: dict | None = OPERATOR
    ) -> dict:
        """Replace a group's shared-vault scope grants (design §6.4)."""
        self._require_admin(actor)
        group = self.get_group(name)
        self.groups.set_scopes(group["id"], list(scopes))
        return self.get_group(name)

    def add_to_group(
        self, username: str, group_name: str, *, actor: dict | None = OPERATOR
    ) -> bool:
        self._require_admin(actor)
        user = self.get_user(username)
        group = self.get_group(group_name)
        return self.groups.add_member(group["id"], user["id"])

    def remove_from_group(
        self, username: str, group_name: str, *, actor: dict | None = OPERATOR
    ) -> bool:
        self._require_admin(actor)
        user = self.get_user(username)
        group = self.get_group(group_name)
        return self.groups.remove_member(group["id"], user["id"])

    # -- identity → scopes ------------------------------------------------------

    def scopes_for_user(self, user: dict) -> list[str]:
        """The user's effective shared-vault scopes: the ordered, deduped
        union of their groups' grants (design §6.4). Own-vault ``**`` and the
        admin macro view are the multi-vault model — B2, not here."""
        seen: list[str] = []
        for group in self.groups.groups_for_user(user["id"]):
            if not group["scopes_json"]:
                continue
            for scope in json.loads(group["scopes_json"]):
                if scope not in seen:
                    seen.append(scope)
        return seen

    def principal_for_username(
        self, username: str, *, token_scopes: list[str] | None = None
    ) -> Principal | None:
        """Resolve a username to its effective :class:`Principal`, or None
        for a missing/disabled user.

        ``token_scopes`` is an API token's optional ``scopes_json`` narrowing:
        the effective scopes become the token scopes that are *also* granted
        to the user (exact-glob match — conservative: a token can only ever
        narrow, never widen; glob-aware subset narrowing is B2's refinement).
        """
        user = self.users.get_by_username(username)
        if user is None or user["disabled"]:
            return None
        scopes = self.scopes_for_user(user)
        if token_scopes is not None:
            scopes = [s for s in token_scopes if s in scopes]
        return Principal(name=username, scopes=scopes)

    # -- API tokens -------------------------------------------------------------

    def mint_token(
        self,
        username: str,
        name: str,
        *,
        scopes: list[str] | None = None,
        expires_in: int | None = None,
        actor: dict | None = OPERATOR,
    ) -> CreatedApiToken:
        """Mint a named bearer token for a user. The raw token exists only in
        the returned value — persistence is salted-hash + prefix (#14).
        Allowed for admins and for the user themself."""
        user = self.get_user(username)
        self._require_admin_or_self(actor, user)
        if user["disabled"]:
            raise IdentityError(f"user is disabled: {username}")
        expires_at = None
        if expires_in is not None:
            if expires_in <= 0:
                raise IdentityError("expires_in must be positive")
            expires_at = _now() + int(expires_in)
        return self.tokens.create(
            user["id"], name, scopes=scopes, expires_at=expires_at
        )

    def list_tokens(self, username: str) -> list[dict]:
        user = self.get_user(username)
        return self.tokens.list_for_user(user["id"])

    def revoke_token(
        self, username: str, name: str, *, actor: dict | None = OPERATOR
    ) -> int:
        """Revoke every live token of ``username`` named ``name``. Returns
        the number revoked. Allowed for admins and for the user themself."""
        user = self.get_user(username)
        self._require_admin_or_self(actor, user)
        revoked = 0
        for row in self.tokens.list_for_user(user["id"]):
            if row["name"] == name and row["revoked_at"] is None:
                if self.tokens.revoke(row["id"]):
                    revoked += 1
        return revoked

    def resolve_api_token(self, token: str | None) -> tuple[Principal, str] | None:
        """Resolve a presented bearer token to ``(principal, username)``, or
        None. Revoked/expired tokens and disabled/deleted owners do not
        resolve. The principal carries the user's *current* group scopes,
        narrowed by the token's mint-time ``scopes_json`` if present."""
        row = self.tokens.resolve(token)
        if row is None:
            return None
        user = self.users.get(row["user_id"])
        if user is None or user["disabled"]:
            return None
        token_scopes = (
            list(json.loads(row["scopes_json"])) if row["scopes_json"] else None
        )
        principal = self.principal_for_username(
            user["username"], token_scopes=token_scopes
        )
        if principal is None:  # pragma: no cover - covered by the checks above
            return None
        return principal, user["username"]

    def usernames(self) -> set[str]:
        with self.db.connection() as conn:
            return {r["username"] for r in conn.execute("SELECT username FROM users")}

    # -- sessions (design §9.1) ---------------------------------------------------

    def login(self, username: str, password: str) -> LoginResult | None:
        """Verify a local user's password and mint a session. Returns None on
        *any* failure — unknown user, wrong password, disabled, non-local —
        with no distinguishing signal (no enumeration oracle; the PBKDF2 cost
        asymmetry between paths is accepted for A4, rate limiting is A6's)."""
        user = self.users.verify_password(username, password)
        if user is None:
            return None
        return self.start_session(user)

    def start_session(self, user: dict) -> LoginResult:
        """Mint a session for an *already-authenticated*, enabled user row.

        Two callers: :meth:`login` (after local PBKDF2 verify) and the A5
        LDAP path (:class:`cortex.ldap.DirectoryService`, after a successful
        directory bind — design §9.2 step 4: from here on, LDAP and local
        users are indistinguishable). Callers own authentication; this owns
        only session minting."""
        if user.get("disabled"):
            raise IdentityError(f"user is disabled: {user['username']}")
        created = self.sessions.create(user["id"], ttl_seconds=self.session_ttl)
        self.users.touch_last_login(user["id"])
        return LoginResult(
            user=user,
            session_id=created.id,
            session_token=created.token,
            csrf_token=self.csrf_token_for(created.token),
            expires_at=created.expires_at,
        )

    @staticmethod
    def csrf_token_for(session_token: str) -> str:
        """The CSRF token bound to a session (double-submit, session-bound).

        Derived as ``sha256("cortex-csrf:" + session_token)``: anyone holding
        the session token can compute it, nobody else can — and the session
        token lives only in an HttpOnly cookie, unreadable cross-origin. The
        client receives this value once at login and echoes it in the
        ``X-Cortex-CSRF`` header on every state-changing request; the server
        recomputes it from the presented cookie (:mod:`cortex.sessions`).
        Stateless — nothing extra to store, revoke, or rotate: it dies with
        its session."""
        return sha256_hex("cortex-csrf:" + session_token)

    def resolve_session(self, session_token: str | None) -> dict | None:
        """Resolve a session cookie value to its (enabled) user row, or None.

        Sliding renewal: touching a session in the second half of its life
        extends ``expires_at`` by a full TTL, so an active user is never
        logged out mid-use while an abandoned session still dies on schedule.
        A disabled/deleted owner kills the session immediately."""
        row = self.sessions.resolve(session_token)
        if row is None:
            return None
        user = self.users.get(row["user_id"])
        if user is None or user["disabled"]:
            self.sessions.delete(row["id"])
            return None
        now = _now()
        if row["expires_at"] - now < self.session_ttl / 2:
            self.sessions.extend(row["id"], now + self.session_ttl)
        return user

    def logout(self, session_token: str | None) -> bool:
        """Destroy a session server-side (idempotent)."""
        if not session_token:
            return False
        return self.sessions.delete_by_token(session_token)

    def purge_expired_sessions(self) -> int:
        return self.sessions.purge_expired()

    # -- bootstrap ---------------------------------------------------------------

    def has_admin(self) -> bool:
        with self.db.connection() as conn:
            return (
                conn.execute(
                    "SELECT 1 FROM users WHERE is_admin = 1 AND disabled = 0 LIMIT 1"
                ).fetchone()
                is not None
            )


def bootstrap_admin(identity: IdentityService, username: str = "admin") -> str | None:
    """First-run admin creation against the DB — replaces the legacy
    admin.json one-time-password bootstrap as the source of truth for the
    admin identity. If any enabled admin user already exists (including one
    imported from cortex.admin.json by A3), this is a no-op returning None.
    Otherwise it creates (or, if the username exists without the flag,
    promotes) ``username`` with a freshly generated password and returns that
    password — the only time it is ever visible."""
    if identity.has_admin():
        return None
    password = secrets.token_urlsafe(18)
    existing = identity.users.get_by_username(username)
    if existing is not None:
        identity.users.update(existing["id"], is_admin=True, disabled=False)
        identity.users.set_password(existing["id"], password)
    else:
        identity.create_user(
            username,
            password=password,
            display_name="Administrator",
            is_admin=True,
            actor=OPERATOR,
        )
    return password
