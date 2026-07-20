"""Bounded, report-first maintenance across every registered vault.

The janitor deliberately starts with analysis only: it scans eligible Markdown
notes, reports malformed frontmatter and unresolved wikilinks, and persists a
per-vault report plus a rollup.  It never receives a path to the identity
database as vault content and never mutates notes.  A future opt-in writer can
reuse :class:`JanitorBoundary`; keeping the guard independent of the scanner
makes the safety rule testable before write mode exists.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass
from fnmatch import fnmatchcase
from pathlib import PurePosixPath

import yaml

from ..config import CortexConfig, JanitorConfig
from ..db.core import Database
from ..vaults import VaultManager

_WIKILINK = re.compile(r"!?(?:\[\[)([^\]|#]+)(?:#[^\]|]+)?(?:\|[^\]]+)?\]\]")
_FRONTMATTER = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.DOTALL)

# These are hard boundaries, not configuration defaults.  Operator-provided
# allow rules cannot override them.  The identity DB and configuration normally
# live outside a vault; names are still denied defensively if copied into one.
_PROTECTED = (
    "cortex.yaml", "cortex.yml", "cortex.example.yaml", "cortex.db",
    "**/cortex.yaml", "**/cortex.yml", "**/cortex.example.yaml", "**/cortex.db",
    "*.sqlite", "*.sqlite3", "**/*.sqlite", "**/*.sqlite3",
    "**/credentials/**", "**/secrets/**", "**/.env", ".env",
    "**/principals/**", "**/scopes/**", "**/janitor/**",
)


@dataclass(frozen=True)
class JanitorFinding:
    path: str
    kind: str
    detail: str


@dataclass(frozen=True)
class JanitorReport:
    vault: str
    scanned_notes: int
    skipped_notes: int
    findings: tuple[JanitorFinding, ...]
    dry_run: bool = True

    @property
    def summary(self) -> str:
        return (
            f"scanned {self.scanned_notes} notes; skipped {self.skipped_notes}; "
            f"found {len(self.findings)} maintenance items"
        )


class JanitorBoundary:
    """Deny protected/forbidden paths before applying optional allow rules."""

    def __init__(self, config: JanitorConfig):
        self.allowed = tuple(_normalise_pattern(p) for p in config.allowed_paths)
        self.forbidden = tuple(_normalise_pattern(p) for p in config.forbidden_paths)

    def allows(self, path: str) -> bool:
        normal = _normalise_path(path)
        if any(_matches(normal, pattern) for pattern in _PROTECTED):
            return False
        if any(_matches(normal, pattern) for pattern in self.forbidden):
            return False
        return not self.allowed or any(_matches(normal, pattern) for pattern in self.allowed)


def _normalise_path(path: str) -> str:
    candidate = str(PurePosixPath(path.replace("\\", "/")))
    if candidate == ".." or candidate.startswith("../") or candidate.startswith("/"):
        raise ValueError("janitor path escapes its vault")
    return candidate.removeprefix("./")


def _normalise_pattern(pattern: str) -> str:
    return pattern.strip().replace("\\", "/").removeprefix("./")


def _matches(path: str, pattern: str) -> bool:
    return fnmatchcase(path, pattern) or (
        pattern.endswith("/**") and path == pattern[:-3].rstrip("/")
    )


def inspect_vault(vault_id: str, store, boundary: JanitorBoundary) -> JanitorReport:
    """Analyze one vault without modifying it."""
    notes = store.list_notes()
    visible = {p.casefold(): p for p in notes}
    visible.update({p.removesuffix(".md").casefold(): p for p in notes})
    findings: list[JanitorFinding] = []
    scanned = skipped = 0
    for path in notes:
        if not boundary.allows(path):
            skipped += 1
            continue
        scanned += 1
        raw = store.read_text(path)
        match = _FRONTMATTER.match(raw)
        if raw.startswith("---") and match is None:
            findings.append(JanitorFinding(path, "frontmatter", "unclosed frontmatter block"))
        elif match is not None:
            try:
                value = yaml.safe_load(match.group(1))
                if value is not None and not isinstance(value, dict):
                    findings.append(JanitorFinding(path, "frontmatter", "frontmatter must be a mapping"))
            except yaml.YAMLError:
                findings.append(JanitorFinding(path, "frontmatter", "invalid YAML frontmatter"))
        parent = PurePosixPath(path).parent
        for target in _WIKILINK.findall(raw):
            target = target.strip().replace("\\", "/")
            candidates = {target.casefold(), target.removesuffix(".md").casefold()}
            relative = str(parent / target)
            candidates |= {relative.casefold(), relative.removesuffix(".md").casefold()}
            if not any(candidate in visible for candidate in candidates):
                findings.append(JanitorFinding(path, "broken_link", target[:200]))
    return JanitorReport(vault_id, scanned, skipped, tuple(findings))


def run_janitor_all(config: CortexConfig, db: Database) -> list[tuple[str, JanitorReport | Exception]]:
    """Scan all vaults independently and persist per-vault reports + rollup."""
    manager = VaultManager(config)
    boundary = JanitorBoundary(config.janitor)
    results: list[tuple[str, JanitorReport | Exception]] = []
    try:
        for vault_id in manager.vault_ids():
            try:
                report = inspect_vault(vault_id, manager.store_for(vault_id), boundary)
                _persist(db, report)
                results.append((vault_id, report))
            except Exception as exc:  # isolate corrupt/unavailable vaults
                results.append((vault_id, exc))
        succeeded = [r for _, r in results if isinstance(r, JanitorReport)]
        failed = [vault for vault, r in results if isinstance(r, Exception)]
        rollup = JanitorReport(
            "*", sum(r.scanned_notes for r in succeeded),
            sum(r.skipped_notes for r in succeeded),
            tuple(f for r in succeeded for f in r.findings),
        )
        _persist(db, rollup, extra={"failed_vaults": failed})
    finally:
        manager.close()
    return results


def _persist(db: Database, report: JanitorReport, *, extra: dict | None = None) -> None:
    details = {
        "scanned_notes": report.scanned_notes,
        "skipped_notes": report.skipped_notes,
        "findings": [asdict(finding) for finding in report.findings],
        **(extra or {}),
    }
    with db.connection() as conn:
        conn.execute(
            "INSERT INTO janitor_reports(vault, created_at, dry_run, summary, details_json) "
            "VALUES (?, ?, 1, ?, ?)",
            (report.vault, int(time.time()), report.summary, json.dumps(details)),
        )
        conn.commit()


__all__ = [
    "JanitorBoundary", "JanitorFinding", "JanitorReport", "inspect_vault",
    "run_janitor_all",
]
