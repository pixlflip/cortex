"""One-shot, idempotent import of the legacy ``cortex.admin.json`` store.

Mapping (design §3.1/§6.4: A3 migrates the admin store into SQLite):

* the single **admin login** → a local user ``admin`` with ``is_admin=1``.
  The PBKDF2 salt+hash are copied verbatim (same primitives, same iteration
  count), so the existing admin password keeps working.
* **roles** → local **groups**; a role's scope globs become the group's
  ``scopes_json`` (shared-vault grants, §6.4).
* **AI clients** → one local user per client (no password material — these
  identities authenticate only by token) + one ``api_tokens`` row copying the
  stored ``token_prefix``/``salt``/``token_hash`` verbatim, so every existing
  client token stays valid. The client's role becomes a group membership.

Idempotency: every step is skipped when its target row already exists
(matched by username / group name / token hash), so re-running the import —
or running it after A4 has already created users — never duplicates or
overwrites anything. The legacy JSON file is left untouched; the admin store
keeps working through the transition (full cutover is A4's).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .core import Database
from .repos import ApiTokensRepo, GroupsRepo, UsersRepo


@dataclass
class AdminImportReport:
    users_created: list[str] = field(default_factory=list)
    users_skipped: list[str] = field(default_factory=list)
    groups_created: list[str] = field(default_factory=list)
    groups_skipped: list[str] = field(default_factory=list)
    tokens_created: list[str] = field(default_factory=list)
    tokens_skipped: list[str] = field(default_factory=list)
    memberships_added: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(
            self.users_created
            or self.groups_created
            or self.tokens_created
            or self.memberships_added
        )


def import_admin_state(db: Database, admin_path: Path | str) -> AdminImportReport:
    """Import ``cortex.admin.json`` at *admin_path* into *db*. Idempotent."""
    report = AdminImportReport()
    admin_path = Path(admin_path)
    if not admin_path.exists():
        report.warnings.append(f"admin state file not found: {admin_path}")
        return report
    data = json.loads(admin_path.read_text(encoding="utf-8"))

    users = UsersRepo(db)
    groups = GroupsRepo(db)
    tokens = ApiTokensRepo(db)

    # -- admin login → is_admin local user --------------------------------
    admin = data.get("admin") or {}
    admin_username = str(admin.get("username") or "admin")
    if users.get_by_username(admin_username) is not None:
        report.users_skipped.append(admin_username)
    elif admin.get("salt") and admin.get("password_hash"):
        users.create(
            admin_username,
            display_name="Administrator",
            password_salt=str(admin["salt"]),
            password_hash=str(admin["password_hash"]),
            is_admin=True,
        )
        report.users_created.append(admin_username)
    else:
        report.warnings.append(
            "admin account has no password hash; not imported"
        )

    # -- roles → groups (scopes preserved as shared-vault grants) ---------
    for role_name, scopes in sorted((data.get("roles") or {}).items()):
        if groups.get_by_name(role_name) is not None:
            report.groups_skipped.append(role_name)
            continue
        groups.create(role_name, scopes=[str(s) for s in (scopes or [])])
        report.groups_created.append(role_name)

    # -- AI clients → token-only users + verbatim api_tokens rows ---------
    for client_name, info in sorted((data.get("clients") or {}).items()):
        info = info or {}
        salt = info.get("salt")
        token_hash = info.get("token_hash")
        token_prefix = info.get("token_prefix")
        if not (salt and token_hash and token_prefix):
            report.warnings.append(
                f"client '{client_name}' lacks token material; skipped"
            )
            continue

        user = users.get_by_username(client_name)
        if user is None:
            user = users.create(
                client_name,
                display_name=f"AI client (imported): {client_name}",
            )
            report.users_created.append(client_name)
        else:
            report.users_skipped.append(client_name)

        existing = [
            t
            for t in tokens.list_for_user(user["id"])
            if t["token_hash"] == token_hash
        ]
        if existing:
            report.tokens_skipped.append(f"{client_name}/imported")
        else:
            tokens.import_hashed(
                user["id"],
                "imported",
                token_prefix=str(token_prefix),
                salt=str(salt),
                token_hash=str(token_hash),
                created_at=info.get("created_at"),
            )
            report.tokens_created.append(f"{client_name}/imported")

        role = info.get("role")
        if role:
            group = groups.get_by_name(str(role))
            if group is None:
                report.warnings.append(
                    f"client '{client_name}' references unknown role '{role}'"
                )
            elif groups.add_member(group["id"], user["id"]):
                report.memberships_added.append(f"{client_name} -> {role}")

    return report
