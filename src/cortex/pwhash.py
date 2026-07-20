"""Shared password/token hashing primitives.

One PBKDF2 implementation for every credential store in Cortex — the legacy
JSON admin store (:mod:`cortex.admin`) and the SQLite identity store
(:mod:`cortex.db`) hash secrets identically, which is what lets A3 import
existing admin/client hashes into SQLite without invalidating anything.

Salts and digests are hex strings; the salt is random per secret. Token
prefixes (the first :data:`TOKEN_PREFIX_LEN` characters of a plaintext token)
are persisted alongside the hash so lookups run PBKDF2 only against candidate
rows that share the prefix — normally exactly one — instead of every row
(the #14 lesson).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

# PBKDF2-HMAC-SHA256 iteration count. Matches the legacy admin store so
# imported hashes verify unchanged.
PASSWORD_ITERS = 200_000

# Length of the persisted token_prefix used to index token lookups. Must match
# what token creation stores (token[:TOKEN_PREFIX_LEN]).
TOKEN_PREFIX_LEN = 12


def hash_secret(secret: str, salt: str | None = None) -> tuple[str, str]:
    """PBKDF2-hash *secret*, minting a random salt when none is supplied.

    Returns ``(salt_hex, digest_hex)``.
    """
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", secret.encode("utf-8"), bytes.fromhex(salt), PASSWORD_ITERS
    ).hex()
    return salt, digest


def check_secret(secret: str, *, salt: str, digest: str) -> bool:
    """Constant-time verification of *secret* against a stored salt+digest."""
    _, candidate = hash_secret(secret, salt)
    return hmac.compare_digest(candidate, digest)


def sha256_hex(value: str) -> str:
    """Plain SHA-256 hex digest — for high-entropy random tokens (session
    tokens) where a salted KDF adds latency but no security, and where an
    unsalted digest doubles as the unique lookup key."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
