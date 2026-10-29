"""Scoping — decide which vault paths a principal may see.

A scope is a glob over vault-relative POSIX paths. A principal carries a list of
scopes; a path is visible if it matches **any** of them. Matching is enforced
server-side: a non-matching path is *invisible* (not listed, not searchable, not
readable), not merely unreadable.

Glob semantics (fnmatch-based, with ``**`` support):

* ``**``            → everything
* ``Projects/**``   → everything under Projects/ (recursive)
* ``Notes/*.md``    → direct .md children of Notes/
* ``Daily/2026-*``  → prefix match within a directory
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from functools import lru_cache


# A tuple is a conjunction, not another union. Only the resolver constructs
# these terms; configuration, tokens and persisted grants contain plain globs.
# JSON discovery serializes a conjunction as an array of globs (all must match).
Scope = str | tuple[str, ...]


def intersect_scopes(grants: Sequence[str], limits: Sequence[str] | None) -> tuple[Scope, ...]:
    """Exact intersection of two glob unions, evaluated on concrete paths.

    Neither prefix containment nor matching one glob *as a path* is sound for
    arbitrary overlapping patterns. Distribute AND over OR instead: each term
    requires BOTH a grant and a token glob. No restriction (None) differs from
    an empty restriction (deny all). Never enumerate today's files to derive
    permissions: the same constraints must govern future writes.
    """
    if limits is None:
        return tuple(grants)
    terms: list[Scope] = []
    seen: set[Scope] = set()
    for grant in grants:
        for limit in limits:
            # Only identical patterns can be elided unconditionally. In the
            # existing matcher ** uses regex '.', while * uses [^/]; they even
            # differ on newline-containing filenames. Preserve exact semantics.
            term: Scope = grant if grant == limit else (grant, limit)
            if term not in seen:
                seen.add(term)
                terms.append(term)
    return tuple(terms)


def validate_grant_scopes(value: object) -> list[str]:
    """Validate explicit, vault-relative globs without repairing input."""
    if not isinstance(value, list) or len(value) > 128:
        raise ValueError("scopes must be a list of at most 128 path globs")
    for pattern in value:
        if (
            not isinstance(pattern, str) or not pattern or len(pattern) > 1024
            or pattern != pattern.strip() or "\\" in pattern
            or any(ord(c) < 32 or ord(c) == 127 for c in pattern)
            or any(not part or part.startswith(".") for part in pattern.split("/"))
        ):
            raise ValueError("scopes must contain canonical vault-relative path globs")
    return list(dict.fromkeys(value))


@lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern[str]:
    """Translate a vault glob into a regex.

    Crucially, ``*`` is directory-bounded (matches ``[^/]*``) so ``Notes/*.md``
    does NOT match ``Notes/sub/a.md`` — only ``**`` crosses ``/``. Getting this
    wrong is a scope leak, not a cosmetic bug.
    """
    pattern = pattern.lstrip("/")
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                out.append(".*")  # ** crosses directory separators
                i += 2
            else:
                out.append("[^/]*")  # * stays within one path segment
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile(r"\A" + "".join(out) + r"\Z")


def _match_one(path: str, pattern: str) -> bool:
    return _compile(pattern).match(path.lstrip("/")) is not None


def path_allowed(path: str, scopes: Sequence[Scope]) -> bool:
    """Match a union of globs/conjunctions. Empty or invalid terms deny."""
    return any(
        _match_one(path, scope) if isinstance(scope, str) else
        isinstance(scope, tuple) and bool(scope)
        and all(isinstance(pattern, str) and _match_one(path, pattern) for pattern in scope)
        for scope in scopes
    )


def filter_paths(paths: list[str], scopes: Sequence[Scope]) -> list[str]:
    """Return only the paths visible under the given scopes."""
    return [p for p in paths if path_allowed(p, scopes)]
