"""Admin account, role, and AI-client management for Cortex HTTP servers.

Legacy identity compatibility persists state in a local JSON file next to the
public-safe config. It contains password/token hashes and must never be committed.
There are no browser administration routes; use the CLI or authenticated API.
"""

from __future__ import annotations

import contextlib
import copy
import json
import os
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


from .config import Principal
from .pwhash import PASSWORD_ITERS, TOKEN_PREFIX_LEN, check_secret, hash_secret

_PASSWORD_ITERS = PASSWORD_ITERS
# Length of the persisted token_prefix used to index client-token lookups.
# Must match what create_client stores (token[:_TOKEN_PREFIX_LEN]).
_TOKEN_PREFIX_LEN = TOKEN_PREFIX_LEN


class AdminNotInitializedError(Exception):
    """The admin state file does not exist yet (run ``cortex init``)."""


def _now() -> int:
    return int(time.time())


# Hashing primitives are shared with the SQLite identity store (cortex.pwhash)
# so admin/client hashes import into SQLite verbatim. The module-level aliases
# stay because callers (and tests) patch/refer to them by these names.
def _hash_secret(secret: str, salt: str | None = None) -> tuple[str, str]:
    return hash_secret(secret, salt)


def _check_secret(secret: str, *, salt: str, digest: str) -> bool:
    return check_secret(secret, salt=salt, digest=digest)


@dataclass
class CreatedClient:
    name: str
    role: str
    token: str


class AdminStore:
    """Persistent admin state: one admin login, named roles, and AI clients."""

    def __init__(self, path: Path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # In-process guard around read-modify-write cycles; the flock in
        # _locked() extends the same guarantee across processes (#17).
        self._mutex = threading.Lock()
        # Parsed-state cache keyed by (mtime_ns, size) so hot paths (every
        # bearer-token lookup) don't re-read and re-parse the JSON file (#14).
        self._cache_sig: tuple[int, int] | None = None
        self._cache_data: dict[str, Any] | None = None

    # -- persistence -----------------------------------------------------
    def exists(self) -> bool:
        return self.path.exists()

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialize read-modify-write cycles: a threading lock for callers in
        this process plus an ``flock`` on a sidecar lock file for other
        processes sharing the state file (#17)."""
        with self._mutex:
            lock_path = self.path.with_name(self.path.name + ".lock")
            fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                try:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_EX)
                except ImportError:  # pragma: no cover - non-POSIX fallback
                    pass
                yield
            finally:
                os.close(fd)

    def load(self) -> dict[str, Any]:
        if not self.exists():
            return {}
        stat = self.path.stat()
        sig = (stat.st_mtime_ns, stat.st_size)
        if sig != self._cache_sig:
            self._cache_data = json.loads(self.path.read_text(encoding="utf-8"))
            self._cache_sig = sig
        # Deep-copy so callers mutating the returned dict (load→mutate→save)
        # can't corrupt the cache behind other readers.
        return copy.deepcopy(self._cache_data or {})

    def save(self, data: dict[str, Any]) -> None:
        """Atomically persist state, owner-readable from the very first byte.

        The temp file is created 0600 by ``mkstemp`` in the same directory and
        swapped into place with ``os.replace``, so there is never a moment
        where the file exists world-readable (#18) or half-written."""
        payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=f".{self.path.name}."
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self.path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        self._cache_sig = None

    def ensure_initialized(self) -> str | None:
        """Create admin state if absent. Returns the one-time password if new."""
        with self._locked():
            if self.exists():
                return None
            password = secrets.token_urlsafe(18)
            salt, digest = _hash_secret(password)
            self.save(
                {
                    "admin": {
                        "username": "admin",
                        "salt": salt,
                        "password_hash": digest,
                        # Random server secret for signing admin session
                        # cookies — never derived from a constant or from the
                        # password hash (#7, #19).
                        "cookie_secret": secrets.token_hex(32),
                    },
                    "roles": {
                        "admin": ["**"],
                        "public": ["Public/**"],
                    },
                    "clients": {},
                    "created_at": _now(),
                }
            )
            return password

    # -- admin auth ------------------------------------------------------
    def authenticate_admin(self, username: str, password: str) -> bool:
        data = self.load()
        admin = data.get("admin", {})
        if username != admin.get("username", "admin"):
            return False
        salt = admin.get("salt")
        digest = admin.get("password_hash")
        if not salt or not digest:
            return False
        return _check_secret(password, salt=salt, digest=digest)

    def cookie_secret(self) -> str:
        """The random per-install secret that signs admin session cookies.

        Never a constant and never derived from the password hash: an
        uninitialized store raises instead of returning a guessable value
        (#7), and a pre-#19 state file lacking a secret is migrated by
        minting one on first use."""
        admin = self.load().get("admin", {})
        if not admin:
            raise AdminNotInitializedError(
                f"admin store is not initialized: {self.path} (run 'cortex init')"
            )
        secret = admin.get("cookie_secret")
        if secret:
            return str(secret)
        with self._locked():
            data = self.load()
            admin = data.setdefault("admin", {})
            if not admin.get("cookie_secret"):
                admin["cookie_secret"] = secrets.token_hex(32)
                self.save(data)
            return str(admin["cookie_secret"])

    # -- roles -----------------------------------------------------------
    def roles(self) -> dict[str, list[str]]:
        return dict(self.load().get("roles", {}))

    def add_role(self, name: str, scopes: list[str]) -> None:
        name = _clean_name(name)
        scopes = [s.strip() for s in scopes if s.strip()]
        if not name:
            raise ValueError("role name is required")
        if not scopes:
            raise ValueError("at least one scope is required")
        with self._locked():
            data = self.load()
            data.setdefault("roles", {})[name] = scopes
            self.save(data)

    # -- clients ---------------------------------------------------------
    def clients(self) -> dict[str, dict[str, Any]]:
        return dict(self.load().get("clients", {}))

    def create_client(self, name: str, role: str) -> CreatedClient:
        name = _clean_name(name)
        if not name:
            raise ValueError("client name is required")
        token = "ctx_" + secrets.token_urlsafe(32)
        salt, digest = _hash_secret(token)
        with self._locked():
            data = self.load()
            roles = data.setdefault("roles", {})
            if role not in roles:
                raise ValueError(f"unknown role: {role}")
            data.setdefault("clients", {})[name] = {
                "role": role,
                "salt": salt,
                "token_hash": digest,
                "token_prefix": token[:_TOKEN_PREFIX_LEN],
                "created_at": _now(),
            }
            self.save(data)
        return CreatedClient(name=name, role=role, token=token)

    def principal_for_token(self, token: str | None) -> Principal | None:
        """Resolve a client token, running PBKDF2 only against the candidates
        whose persisted ``token_prefix`` matches the presented token's prefix
        — normally exactly one — instead of every client. An invalid token
        that matches no prefix costs zero PBKDF2 iterations, closing the
        CPU-exhaustion DoS of hashing per client per bogus request (#14)."""
        if not token:
            return None
        data = self.load()
        roles = data.get("roles", {})
        prefix = token[:_TOKEN_PREFIX_LEN]
        for name, info in data.get("clients", {}).items():
            if info.get("token_prefix") != prefix:
                continue
            salt = info.get("salt")
            digest = info.get("token_hash")
            role = info.get("role")
            if salt and digest and _check_secret(token, salt=salt, digest=digest):
                return Principal(name=name, scopes=list(roles.get(role, [])))
        return None

    def principal_by_name(self, name: str) -> Principal | None:
        data = self.load()
        info = data.get("clients", {}).get(name)
        if not info:
            return None
        scopes = data.get("roles", {}).get(info.get("role"), [])
        return Principal(name=name, scopes=list(scopes))



def _clean_name(name: str) -> str:
    return "".join(ch for ch in name.strip() if ch.isalnum() or ch in "-_ .")[:80].strip()
