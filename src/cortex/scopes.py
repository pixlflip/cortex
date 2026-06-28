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
from functools import lru_cache


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


def path_allowed(path: str, scopes: list[str]) -> bool:
    """True if ``path`` matches any scope in ``scopes``."""
    return any(_match_one(path, s) for s in scopes)


def filter_paths(paths: list[str], scopes: list[str]) -> list[str]:
    """Return only the paths visible under the given scopes."""
    return [p for p in paths if path_allowed(p, scopes)]
