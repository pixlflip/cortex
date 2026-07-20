"""LDAP / Active Directory integration (A5, design §3.2, §7.4, §9.2).

Two layers live here, both fully inert unless an ``ldap:`` block exists in
cortex.yaml (``CortexConfig.ldap`` is ``None`` otherwise):

* :class:`LdapClient` — a thin wrapper over ``ldap3``. Search-then-bind
  authentication (service-account bind → find the user's DN by filter →
  rebind as that DN with the presented password) and directory searches
  returning mapped user records plus one level of group membership. The
  module imports fine without ``ldap3`` installed; only *using* the client
  raises a clear "install cortex[ldap]" error.

* :class:`DirectoryService` — the coordinating layer over
  :class:`cortex.users.IdentityService` that A6/C2 will call:

  - :meth:`DirectoryService.login` — local users always take the local
    PBKDF2 path (never bound to LDAP); LDAP-backed or unknown usernames are
    verified by directory bind, JIT-provisioned (``jit_provisioning``) as
    ``auth_source='ldap'`` rows with *no password material*, and their
    mapped group memberships refreshed.
  - :meth:`DirectoryService.sync` — pull all directory users matching the
    filter into ``users``, reconcile mapped groups, and disable (never
    delete) LDAP rows whose directory entry is gone. ``dry_run=True``
    reports without writing.

Safety notes (§7.4): the service-account password comes from an env var
only; user passwords are never stored or logged; usernames are escaped per
RFC 4515 before filter substitution (no LDAP injection); a directory outage
raises :class:`LdapUnavailableError` — LDAP users just can't start *new*
sessions, while local logins never touch this module at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .config import LdapConfig
from .users import IdentityError, IdentityService, LoginResult

try:  # pragma: no cover - exercised via the import-safety test
    import ldap3
    from ldap3.core.exceptions import LDAPException
except ImportError:  # pragma: no cover
    ldap3 = None  # type: ignore[assignment]

    class LDAPException(Exception):  # type: ignore[no-redef]
        """Placeholder so `except LDAPException` stays valid without ldap3."""


class LdapError(Exception):
    """LDAP integration failure (config, protocol, or missing dependency)."""


class LdapUnavailableError(LdapError):
    """The directory can't be reached. Degradation contract (§7.4): LDAP
    users can't start *new* sessions; existing sessions, API tokens, and
    every local login are unaffected."""


def _require_ldap3() -> None:
    if ldap3 is None:
        raise LdapError(
            "LDAP support requires the 'ldap3' package — "
            "install it with: pip install 'cortex-memory[ldap]'"
        )


def escape_filter_value(value: str) -> str:
    """Escape a string for embedding in an LDAP search filter (RFC 4515).

    ``\\ * ( )`` and NUL (plus the other C0 controls, harmless to escape)
    become ``\\XX`` hex escapes, so a hostile login name like
    ``*)(uid=admin`` cannot restructure the filter it is substituted into.
    """
    out: list[str] = []
    for ch in value:
        if ch in '\\*()' or ord(ch) < 32:
            out.append("\\{:02x}".format(ord(ch)))
        else:
            out.append(ch)
    return "".join(out)


@dataclass
class LdapGroup:
    dn: str
    name: str


@dataclass
class LdapUser:
    """A directory entry mapped through ``ldap.attributes``."""

    dn: str
    username: str
    display_name: str | None = None
    email: str | None = None
    groups: list[LdapGroup] = field(default_factory=list)


#: factory(user_dn, password) -> an *unbound* ldap3 Connection (or a
#: compatible fake). Tests inject a MOCK_SYNC-backed factory here.
ConnectionFactory = Callable[[str | None, str | None], Any]


class LdapClient:
    """Thin, connection-per-operation wrapper over ldap3.

    ``connection_factory`` exists for tests (ldap3 MOCK_SYNC) and unusual
    deployments; the default factory builds a real ``ldap3.Connection`` from
    the config's URI with LDAPS or STARTTLS as configured.
    """

    def __init__(
        self,
        cfg: LdapConfig,
        *,
        connection_factory: ConnectionFactory | None = None,
    ):
        self.cfg = cfg
        if connection_factory is None:
            _require_ldap3()
            connection_factory = self._default_connection_factory
        self._factory = connection_factory

    # -- connections --------------------------------------------------------

    def _default_connection_factory(self, user: str | None, password: str | None):
        _require_ldap3()
        use_ssl = self.cfg.server_uri.startswith("ldaps://")
        server = ldap3.Server(self.cfg.server_uri, use_ssl=use_ssl, get_info=ldap3.NONE)
        conn = ldap3.Connection(
            server, user=user, password=password, raise_exceptions=False
        )
        if self.cfg.starttls and not use_ssl:
            conn.open()
            if not conn.start_tls():
                raise LdapError("STARTTLS negotiation failed")
        return conn

    def _connect(self, user: str | None, password: str | None):
        try:
            return self._factory(user, password)
        except LdapError:
            raise
        except Exception as exc:
            raise LdapUnavailableError(f"cannot reach LDAP server: {exc}") from exc

    @staticmethod
    def _bind(conn) -> bool:
        """Bind an open connection. False = bad credentials; network/protocol
        trouble surfaces as LdapUnavailableError, never a silent False."""
        try:
            return bool(conn.bind())
        except LDAPException as exc:
            raise LdapUnavailableError(f"cannot reach LDAP server: {exc}") from exc

    @staticmethod
    def _unbind(conn) -> None:
        try:
            conn.unbind()
        except Exception:  # pragma: no cover - best-effort cleanup
            pass

    def _service_conn(self):
        conn = self._connect(self.cfg.bind_dn, self.cfg.bind_password)
        if not self._bind(conn):
            raise LdapError(
                "LDAP service-account bind failed — check ldap.bind_dn and "
                f"the password in ${self.cfg.bind_password_env}"
            )
        return conn

    # -- searching -----------------------------------------------------------

    def _search(self, conn, base: str, flt: str, attributes: list[str]) -> list:
        try:
            conn.search(base, flt, attributes=attributes)
        except LDAPException as exc:
            raise LdapUnavailableError(f"LDAP search failed: {exc}") from exc
        return list(conn.entries)

    @staticmethod
    def _attr(entry, name: str) -> str | None:
        values = entry.entry_attributes_as_dict.get(name)
        if not values:
            return None
        if isinstance(values, (list, tuple)):
            values = values[0]
        text = str(values).strip()
        return text or None

    def _entry_to_user(self, conn, entry, *, with_groups: bool = True) -> LdapUser | None:
        amap = self.cfg.attributes
        username = self._attr(entry, amap.username)
        if not username:
            return None
        user = LdapUser(
            dn=str(entry.entry_dn),
            username=username,
            display_name=self._attr(entry, amap.display_name),
            email=self._attr(entry, amap.email),
        )
        if with_groups:
            user.groups = self.groups_of(conn, user.dn)
        return user

    def _user_attributes(self) -> list[str]:
        amap = self.cfg.attributes
        return [amap.username, amap.display_name, amap.email]

    def find_user(self, conn, username: str) -> LdapUser | None:
        """Locate exactly one directory entry for ``username`` (escaped per
        RFC 4515 before substitution). Zero or multiple matches ⇒ None."""
        flt = self.cfg.user_filter.replace(
            "{username}", escape_filter_value(username)
        )
        entries = self._search(conn, self.cfg.user_base_dn, flt, self._user_attributes())
        if len(entries) != 1:
            return None
        return self._entry_to_user(conn, entries[0])

    def groups_of(self, conn, user_dn: str) -> list[LdapGroup]:
        """One level of group membership (no nested-group recursion):
        groups matching ``group_filter`` whose member attr holds the DN."""
        if not self.cfg.group_base_dn:
            return []
        flt = (
            f"(&{self.cfg.group_filter}"
            f"({self.cfg.group_member_attr}={escape_filter_value(user_dn)}))"
        )
        entries = self._search(conn, self.cfg.group_base_dn, flt, ["cn"])
        groups = []
        for entry in entries:
            dn = str(entry.entry_dn)
            groups.append(LdapGroup(dn=dn, name=self._attr(entry, "cn") or dn))
        return groups

    # -- public operations -----------------------------------------------------

    def check(self) -> None:
        """Service-account bind round-trip — `cortex ldap check`."""
        conn = self._service_conn()
        self._unbind(conn)

    def authenticate(self, username: str, password: str) -> LdapUser | None:
        """Search-then-bind (§9.2). Returns the mapped record on success,
        None on any credential failure (no oracle: unknown user, ambiguous
        filter, and wrong password are indistinguishable). Raises
        :class:`LdapUnavailableError` if the directory can't be reached."""
        if not username or not password:
            # An empty password is an LDAP *unauthenticated bind* and would
            # "succeed" against many servers — never forward one.
            return None
        conn = self._service_conn()
        try:
            user = self.find_user(conn, username)
        finally:
            self._unbind(conn)
        if user is None:
            return None
        user_conn = self._connect(user.dn, password)
        try:
            if not self._bind(user_conn):
                return None
        finally:
            self._unbind(user_conn)
        return user

    def search_users(self) -> list[LdapUser]:
        """All directory users matching ``user_filter`` (with ``{username}``
        as a wildcard), each with mapped attributes + group membership —
        the `cortex ldap sync` input."""
        flt = self.cfg.user_filter.replace("{username}", "*")
        conn = self._service_conn()
        try:
            entries = self._search(
                conn, self.cfg.user_base_dn, flt, self._user_attributes()
            )
            users = []
            for entry in entries:
                user = self._entry_to_user(conn, entry)
                if user is not None:
                    users.append(user)
            return users
        finally:
            self._unbind(conn)


# --------------------------------------------------------------------------
# coordinating layer: bind login + JIT provisioning + directory sync
# --------------------------------------------------------------------------


@dataclass
class SyncReport:
    """What `cortex ldap sync` did — or, under ``dry_run``, would do."""

    dry_run: bool = False
    added: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    disabled: list[str] = field(default_factory=list)
    group_changes: list[str] = field(default_factory=list)  # "user: +g -g"
    skipped: list[str] = field(default_factory=list)  # human-readable reasons

    @property
    def changed(self) -> bool:
        return bool(self.added or self.updated or self.disabled or self.group_changes)


class DirectoryService:
    """LDAP-aware identity coordination over an :class:`IdentityService`.

    A6 exposes :meth:`login` behind ``POST /api/v1/auth/login`` and
    :meth:`sync` behind an admin route; C2 adds the admin panel. The CLI
    (`cortex ldap`) calls both today.
    """

    def __init__(
        self,
        identity: IdentityService,
        cfg: LdapConfig,
        client: LdapClient | None = None,
    ):
        self.identity = identity
        self.cfg = cfg
        self.client = client or LdapClient(cfg)
        # Case-insensitive lookup: LDAP group DN or name -> Cortex group name.
        self._mappings = {k.lower(): v for k, v in cfg.group_mappings.items()}

    # -- login (design §9.2) -------------------------------------------------

    def login(self, username: str, password: str) -> LoginResult | None:
        """The v2 login flow for an LDAP-configured deployment.

        * ``auth_source='local'`` rows *always* take the local PBKDF2 path —
          a local user's password is never sent to the directory.
        * LDAP rows and (with ``jit_provisioning``) unknown usernames are
          verified by directory bind; on first success a row is created with
          ``auth_source='ldap'`` and no password material, and mapped group
          memberships are refreshed on every login.
        * Credential failure ⇒ None (uniform with local failures — no
          oracle). Directory outage ⇒ :class:`LdapUnavailableError`; local
          logins never reach this branch, so they keep working (§7.4).
        """
        existing = self.identity.users.get_by_username(username)
        if existing is not None and existing["auth_source"] == "local":
            return self.identity.login(username, password)
        if existing is not None and existing["disabled"]:
            return None
        if existing is None and not self.cfg.jit_provisioning:
            return None
        record = self.client.authenticate(username, password)
        if record is None:
            return None
        user = self._apply_record(record, allow_create=self.cfg.jit_provisioning)
        if user is None or user["disabled"]:
            return None
        return self.identity.start_session(user)

    # -- provisioning ----------------------------------------------------------

    def _valid_username(self, record: LdapUser) -> str | None:
        """The record's Cortex-side username, or None if the directory value
        violates the shared name-hygiene rules (charset, reserved prefixes,
        config-principal collisions — the #9 lesson applies to LDAP too)."""
        try:
            return self.identity._validate_username(record.username)
        except IdentityError:
            return None

    def _apply_record(
        self, record: LdapUser, *, allow_create: bool = True
    ) -> dict | None:
        """Create/update the ``users`` row for a directory record and
        reconcile its mapped groups. Never touches a local-auth row."""
        username = self._valid_username(record)
        if username is None:
            return None
        row = self.identity.users.get_by_username(username)
        if row is not None and row["auth_source"] != "ldap":
            return None  # a local user is never converted or overwritten
        if row is None:
            if not allow_create:
                return None
            row = self.identity.users.create(
                username,
                display_name=record.display_name,
                email=record.email,
                auth_source="ldap",
                ldap_dn=record.dn,
            )
        else:
            updates = self._row_updates(row, record)
            if updates:
                row = self.identity.users.update(row["id"], **updates)
        self._reconcile_groups(row, record, apply=True)
        return row

    @staticmethod
    def _row_updates(row: dict, record: LdapUser) -> dict:
        updates = {}
        if row["display_name"] != record.display_name:
            updates["display_name"] = record.display_name
        if row["email"] != record.email:
            updates["email"] = record.email
        if row["ldap_dn"] != record.dn:
            updates["ldap_dn"] = record.dn
        return updates

    # -- group reconciliation -----------------------------------------------------

    def _desired_groups(self, record: LdapUser) -> dict[str, LdapGroup]:
        """Cortex group name -> the LDAP group that grants it, for the
        record's memberships that appear in ``group_mappings`` (matched by
        DN or by name, case-insensitively)."""
        desired: dict[str, LdapGroup] = {}
        for group in record.groups:
            target = self._mappings.get(group.dn.lower()) or self._mappings.get(
                group.name.lower()
            )
            if target:
                desired.setdefault(target, group)
        return desired

    def _reconcile_groups(
        self, row: dict | None, record: LdapUser, *, apply: bool
    ) -> list[str]:
        """Make the user's membership in *mapped* Cortex groups match the
        directory (add + remove); groups outside the mapping table are never
        touched, so purely local memberships survive. Returns the change
        list (``+name`` / ``-name``); with ``apply=False`` it only reports.
        """
        desired = self._desired_groups(record)
        managed = set(self.cfg.group_mappings.values())
        current: set[str] = set()
        if row is not None:
            current = {
                g["name"]
                for g in self.identity.groups.groups_for_user(row["id"])
                if g["name"] in managed
            }
        additions = sorted(set(desired) - current)
        removals = sorted(current - set(desired))
        if apply and row is not None:
            for name in additions:
                group = self.identity.groups.get_by_name(name)
                if group is None:
                    group = self.identity.groups.create(
                        name, source="ldap", ldap_dn=desired[name].dn
                    )
                self.identity.groups.add_member(group["id"], row["id"])
            for name in removals:
                group = self.identity.groups.get_by_name(name)
                if group is not None:
                    self.identity.groups.remove_member(group["id"], row["id"])
        return [f"+{n}" for n in additions] + [f"-{n}" for n in removals]

    # -- directory sync ------------------------------------------------------------

    def sync(self, *, dry_run: bool = False) -> SyncReport:
        """Reconcile the ``users`` table with the directory (A5 task 4).

        Adds/updates ``auth_source='ldap'`` rows for every directory user
        matching the filter, reconciles mapped group membership, and
        *disables* (never deletes) LDAP rows whose directory entry is gone —
        their sessions die with them. Local users are never touched; a
        directory username colliding with a local user is skipped with a
        warning. ``dry_run=True`` computes the full report with zero writes.
        Raises :class:`LdapUnavailableError` (before any write) on outage.
        """
        records = self.client.search_users()
        report = SyncReport(dry_run=dry_run)
        seen: set[str] = set()
        for record in records:
            username = self._valid_username(record)
            if username is None:
                report.skipped.append(
                    f"{record.dn}: username {record.username!r} fails Cortex "
                    "name rules"
                )
                continue
            if username in seen:
                report.skipped.append(
                    f"{record.dn}: duplicate username {username!r} in directory"
                )
                continue
            seen.add(username)
            row = self.identity.users.get_by_username(username)
            if row is not None and row["auth_source"] != "ldap":
                report.skipped.append(
                    f"{username}: exists as a local user — refusing to touch"
                )
                continue
            if row is None:
                report.added.append(username)
            elif self._row_updates(row, record):
                report.updated.append(username)
            # Compute the membership diff against the *current* DB state
            # (works for row=None too: everything desired is an addition),
            # then apply it unless this is a dry run.
            changes = self._reconcile_groups(row, record, apply=False)
            if changes:
                report.group_changes.append(f"{username}: {' '.join(changes)}")
            if not dry_run:
                self._apply_record(record)
        # Disable LDAP rows that vanished from the directory.
        for user in self.identity.users.list():
            if user["auth_source"] != "ldap":
                continue
            if user["username"] in seen or user["disabled"]:
                continue
            report.disabled.append(user["username"])
            if not dry_run:
                self.identity.users.update(user["id"], disabled=True)
                self.identity.sessions.delete_for_user(user["id"])
        return report
