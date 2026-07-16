"""Git Audit — the single audit trail and rollback mechanism.

Every mutation to the vault is followed immediately by a commit whose message
encodes *actor* and *reason*. Git is the only version store; there is no
separate history database. Rollback is ordinary git (``revert`` / ``checkout``).

In v1 the server is read-only, so the only writers are the bootstrap (initial
snapshot) and — once enabled — the Janitor. This module gives them a consistent,
attributable commit convention and the read side (log/diff) that tooling needs.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config import GitConfig


class GitError(Exception):
    pass


@dataclass
class Commit:
    sha: str
    actor: str
    subject: str
    iso_date: str


def _run(args: list[str], cwd: Path, env_extra: dict[str, str] | None = None) -> str:
    import os

    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env=env,
    )
    if proc.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


class GitAudit:
    """Attributable commits over the vault repository."""

    def __init__(self, root: Path, config: GitConfig):
        self.root = Path(root).resolve()
        self.config = config

    # -- lifecycle ---------------------------------------------------------

    def is_repo(self) -> bool:
        return (self.root / ".git").exists()

    def ensure_repo(self) -> bool:
        """Initialize the repo if needed. Returns True if it created one."""
        if self.is_repo():
            return False
        _run(["init", "-q"], self.root)
        _run(["config", "user.name", self.config.actor_name], self.root)
        _run(["config", "user.email", self.config.actor_email], self.root)
        return True

    # -- commit convention -------------------------------------------------

    @staticmethod
    def message(actor: str, reason: str) -> str:
        """Build a commit message encoding actor and reason.

        Convention: ``<actor>: <reason>`` — e.g.
        ``cortex-janitor: normalize frontmatter`` or
        ``principal:didact via mcp: append decision record``.
        """
        actor = actor.strip() or "cortex"
        reason = reason.strip() or "update"
        return f"{actor}: {reason}"

    def commit(
        self,
        actor: str,
        reason: str,
        paths: list[str] | None = None,
    ) -> str | None:
        """Stage paths (or everything) and commit. Returns the sha, or None if
        there was nothing to commit.

        The commit author/committer identity carries the actor so ``git log``
        attribution matches the message, independent of the configured default.
        """
        if not self.config.enabled:
            return None
        if paths:
            # A move can begin with an untracked source (for example a human
            # created it immediately before the operation). After the rename
            # that source path neither exists nor is tracked, and passing it
            # directly makes `git add` abort before staging the destination.
            # Keep existing paths plus tracked deletions, skip only truly
            # unknown/missing pathspecs, and use -A so deletions are recorded.
            stageable = [
                path
                for path in paths
                if (self.root / path).exists()
                or bool(_run(["ls-files", "--", path], self.root).strip())
            ]
            if stageable:
                _run(["add", "-A", "--", *stageable], self.root)
        else:
            _run(["add", "-A"], self.root)

        status = _run(["status", "--porcelain"], self.root).strip()
        if not status:
            return None

        author = f"{actor} <{self.config.actor_email}>"
        env = {
            "GIT_AUTHOR_NAME": actor,
            "GIT_AUTHOR_EMAIL": self.config.actor_email,
            "GIT_COMMITTER_NAME": self.config.actor_name,
            "GIT_COMMITTER_EMAIL": self.config.actor_email,
        }
        _run(
            ["commit", "-q", "-m", self.message(actor, reason), "--author", author],
            self.root,
            env_extra=env,
        )
        return _run(["rev-parse", "HEAD"], self.root).strip()

    # -- read side ---------------------------------------------------------

    def log(self, limit: int = 20, path: str | None = None) -> list[Commit]:
        if not self.is_repo():
            return []
        fmt = "%H%x1f%an%x1f%s%x1f%aI"
        args = ["log", f"-n{limit}", f"--pretty=format:{fmt}"]
        if path:
            args += ["--", path]
        out = _run(args, self.root).strip()
        commits: list[Commit] = []
        for line in out.splitlines():
            if not line:
                continue
            sha, actor, subject, date = line.split("\x1f")
            commits.append(Commit(sha=sha, actor=actor, subject=subject, iso_date=date))
        return commits

    def head(self) -> str | None:
        if not self.is_repo():
            return None
        try:
            return _run(["rev-parse", "HEAD"], self.root).strip()
        except GitError:
            return None  # no commits yet

    def head_time(self) -> str | None:
        """ISO 8601 committer date of HEAD, or None if there's no repo / no
        commits yet. This is the freshness signal ``status()`` exposes: when
        this was written, the snapshot on disk is at least that current."""
        try:
            commits = self.log(limit=1)
        except GitError:
            return None  # repo exists but has zero commits yet
        return commits[0].iso_date if commits else None

    def diff_summary(self, sha: str) -> dict:
        """Bounded, content-free file/line summary for an audit commit."""
        out = _run(["show", "--numstat", "--format=", sha, "--"], self.root)
        files: list[dict] = []
        insertions = 0
        deletions = 0
        for line in out.splitlines()[:200]:
            parts = line.split("\t", 2)
            if len(parts) != 3:
                continue
            added, removed, path = parts
            added_n = int(added) if added.isdigit() else 0
            removed_n = int(removed) if removed.isdigit() else 0
            insertions += added_n
            deletions += removed_n
            if len(files) < 50:
                files.append(
                    {"path": path, "insertions": added_n, "deletions": removed_n}
                )
        return {
            "files": files,
            "file_count": len(out.splitlines()),
            "insertions": insertions,
            "deletions": deletions,
        }

    # -- remote sync (best-effort; caller decides whether failure is fatal) --

    def pull_rebase(self, remote: str = "origin", branch: str | None = None) -> None:
        """Best-effort ``git pull --rebase`` so a periodic sync picks up
        commits made elsewhere before pushing its own. Raises ``GitError`` on
        failure (e.g. no such remote, conflicts) — the caller decides whether
        that's fatal; a local snapshot + reindex can still have succeeded."""
        args = ["pull", "--rebase", remote]
        if branch:
            args.append(branch)
        _run(args, self.root)

    def push(self, remote: str = "origin", branch: str | None = None) -> None:
        """Best-effort ``git push``. Raises ``GitError`` on failure (e.g. no
        remote configured, rejected push) — the caller decides whether that's
        fatal."""
        args = ["push", remote]
        if branch:
            args.append(branch)
        _run(args, self.root)
