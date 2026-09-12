"""Multi-tenant admin delegation and scoped authorization.

Identities authenticate with their own bearer tokens and carry roles; a role
is a set of ``(action, scope)`` permissions. Scopes form the delegation chain

    global  ⊇  region(r)  ⊇  tenant(t)

so a grant at a broader scope *inherits* everything narrower: a global grant
covers every resource, a region grant covers that region's resources and all
tenant-level resources (tenant rules are region-independent in this system,
so tenant administration is delegated through region admins), and a tenant
grant covers exactly that tenant. Tenant being the leaf of the chain, a
tenant-scoped grant can never be widened to region or global resources --
delegation (``admin:manage``) may only create roles/identities whose
permissions are covered by the delegator's own ``admin:manage`` scope.

Enforcement model:
- Every control-plane request is authenticated (401 on failure) and then
  authorized per action and resource scope (403 on failure, before any
  mutation runs, so a denied request produces no config or cache side
  effects). Both outcomes are written to the audit log.
- Deactivation and token rotation take effect immediately: the token index
  lives in memory and is updated synchronously before a mutation returns.
- Every role/identity mutation bumps a persisted, monotonically increasing
  global ``authz_version`` plus the per-entity version, and supports
  optimistic concurrency (``expected_version``) and idempotent retries
  (``Idempotency-Key`` header; the first response is persisted and replayed
  for duplicate submissions, while the same key with a different payload is
  rejected with a conflict).

Emergency grants: an identity (or an admin on its behalf) can request a
*temporary* permission elevation carrying a reason, a permission set and a
validity duration. The request is inert until a *different* caller holding
``admin:manage`` over the requested scopes approves it (approvers can never
rule on their own requests, and the granted permissions may not exceed the
approver's delegable scope). While approved and unexpired, the grant's
permissions are folded into the identity's permission set on *every*
control-plane request, so config, cache, health and version endpoints all
execute against the grant's scopes. Expiry (lazy, audited and persisted the
moment it is noticed) and revocation take effect immediately: permissions
are recomputed per request, never cached in tokens, so an old token cannot
keep using a lapsed grant. Every transition (requested, approved, rejected,
revoked, expired) is persisted and audited, and writes against terminal or
expired states are rejected with a conflict.

Legacy interop: the static ``GEORESOLVE_ADMIN_TOKEN`` (when set) acts as a
built-in global "bootstrap" caller so existing deployments keep working;
when no token is configured and no identities exist yet, the control plane
stays open (development mode). As soon as the first identity exists,
authentication is enforced.
"""
from __future__ import annotations

import hashlib
import json
import math
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from .audit import AuditLog
from .models import ScopeType, canonical_json

#: Actions a role can grant. Every control-plane endpoint maps to exactly one.
ACTIONS = frozenset(
    {
        "config:read",
        "config:write",
        "versions:read",
        "cache:read",
        "cache:flush",
        "health:read",
        "health:write",
        "audit:read",
        "admin:manage",
    }
)

BOOTSTRAP_ID = "bootstrap"  # caller id used for the static admin token
OPEN_ID = "open"  # caller id when auth is not configured at all


# -- exceptions (translated to HTTP status codes by the API layer) ----------


class AuthnError(Exception):
    """Authentication failed (unknown, malformed or revoked credential)."""


class Forbidden(Exception):
    """Authenticated caller lacks the action/scope for this request."""


class AuthzNotFound(Exception):
    pass


class AuthzConflict(Exception):
    """Optimistic-concurrency or uniqueness violation (HTTP 409)."""


class IdempotencyConflict(AuthzConflict):
    """An Idempotency-Key was reused with a different request payload."""


class RoleInUse(AuthzConflict):
    """Role cannot be deleted while identities still reference it."""


# -- scope and permission models --------------------------------------------


class Scope(BaseModel):
    """A grant or resource scope: global, one region, or one tenant."""

    scope: ScopeType = "global"
    region: Optional[str] = None
    tenant: Optional[str] = None

    @model_validator(mode="after")
    def _check_scope(self) -> "Scope":
        if self.scope == "global" and (self.region or self.tenant):
            raise ValueError("global scope must not set region/tenant")
        if self.scope == "region" and (not self.region or self.tenant):
            raise ValueError("region scope requires 'region' and must not set 'tenant'")
        if self.scope == "tenant" and (not self.tenant or self.region):
            raise ValueError("tenant scope requires 'tenant' and must not set 'region'")
        return self

    def key(self) -> tuple:
        return (self.scope, self.region or "", self.tenant or "")

    def covers(self, other: "Scope") -> bool:
        """True when a grant at this scope also covers ``other`` (inheritance)."""
        if self.scope == "global":
            return True
        if self.scope == "region":
            if other.scope == "global":
                return False
            # A region grant inherits every tenant-level resource; tenant
            # rules are region-independent, so tenant administration is
            # delegated to region admins of any region.
            return other.scope == "tenant" or self.region == other.region
        return other.scope == "tenant" and self.tenant == other.tenant

    def describe(self) -> str:
        if self.scope == "global":
            return "global"
        if self.scope == "region":
            return f"region:{self.region}"
        return f"tenant:{self.tenant}"


class Permission(BaseModel):
    action: str
    scope: Scope = Field(default_factory=Scope)

    @field_validator("action")
    @classmethod
    def _known_action(cls, v: str) -> str:
        if v not in ACTIONS:
            raise ValueError(
                f"unknown action {v!r}; known actions: {sorted(ACTIONS)}"
            )
        return v


class Role(BaseModel):
    id: str
    description: str = ""
    permissions: list[Permission] = Field(min_length=1)
    role_version: int = 1
    created_at: float = 0.0
    updated_at: float = 0.0

    @field_validator("id")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("role id must be a non-empty string")
        return v

    def public(self) -> dict:
        out = self.model_dump()
        out["scopes"] = [p.scope.describe() for p in self.permissions]
        return out


class Identity(BaseModel):
    id: str
    token_hash: str
    roles: list[str] = Field(default_factory=list)
    status: str = "active"  # "active" | "deactivated"
    identity_version: int = 1
    created_at: float = 0.0
    updated_at: float = 0.0
    deactivated_at: Optional[float] = None

    def public(self) -> dict:
        """API view: the token hash never leaves the store."""
        return {
            "id": self.id,
            "roles": list(self.roles),
            "status": self.status,
            "identity_version": self.identity_version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "deactivated_at": self.deactivated_at,
        }


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token() -> str:
    return "grz_" + secrets.token_urlsafe(24)


# -- emergency grants ---------------------------------------------------------

#: Lifecycle states of an emergency grant.
GRANT_STATUSES = frozenset({"pending", "approved", "rejected", "revoked", "expired"})

#: States no transition may leave.
GRANT_TERMINAL_STATUSES = frozenset({"rejected", "revoked", "expired"})


class EmergencyGrant(BaseModel):
    """A temporary, approval-gated permission elevation for one identity.

    Lifecycle: ``pending`` -> ``approved`` -> ``expired`` | ``revoked``, or
    ``pending`` -> ``rejected``. Only an approved grant inside its validity
    window participates in permission computation; the window starts at
    approval time (``expires_at = approved_at + duration_seconds``), so the
    effective lifetime never depends on how long approval took.
    """

    id: str
    identity_id: str  # grantee: the identity the permissions apply to
    reason: str
    permissions: list[Permission] = Field(min_length=1)
    duration_seconds: float = Field(gt=0)
    status: str = "pending"
    requested_by: str = ""
    requested_at: float = 0.0
    decided_by: Optional[str] = None
    decided_at: Optional[float] = None
    decision_comment: Optional[str] = None
    approved_at: Optional[float] = None
    expires_at: Optional[float] = None
    revoked_by: Optional[str] = None
    revoked_at: Optional[float] = None
    grant_version: int = 1
    updated_at: float = 0.0

    @field_validator("reason")
    @classmethod
    def _reason_non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("reason must be a non-empty string")
        return v

    @field_validator("duration_seconds")
    @classmethod
    def _duration_finite_positive(cls, v: float) -> float:
        if not math.isfinite(v) or v <= 0:
            raise ValueError("duration_seconds must be a finite positive number")
        return v

    @field_validator("status")
    @classmethod
    def _known_status(cls, v: str) -> str:
        if v not in GRANT_STATUSES:
            raise ValueError(
                f"unknown grant status {v!r}; known: {sorted(GRANT_STATUSES)}"
            )
        return v

    def is_active(self, now: float) -> bool:
        """True while the grant's permissions must be computed into callers."""
        return (
            self.status == "approved"
            and self.expires_at is not None
            and self.expires_at > now
        )

    def public(self, now: Optional[float] = None) -> dict:
        out = self.model_dump()
        out["scopes"] = [p.scope.describe() for p in self.permissions]
        if now is not None:
            active = self.is_active(now)
            out["active"] = active
            out["remaining_seconds"] = (
                max(0.0, self.expires_at - now)
                if active and self.expires_at is not None
                else 0.0
            )
        return out


# -- caller ------------------------------------------------------------------


@dataclass(frozen=True)
class Caller:
    """An authenticated control-plane caller with flattened permissions."""

    identity_id: str
    kind: str  # "identity" | "bootstrap" | "open"
    permissions: tuple[Permission, ...]
    #: Ids of the emergency grants contributing permissions right now;
    #: recorded in authorization-decision audits for traceability.
    emergency_grants: tuple[str, ...] = ()

    @property
    def is_global(self) -> bool:
        """True when the caller may act on any scope (bootstrap/open/global grant)."""
        if self.kind in ("bootstrap", "open"):
            return True
        return any(p.scope.scope == "global" for p in self.permissions)

    def grants(self, action: str) -> list[Scope]:
        return [p.scope for p in self.permissions if p.action == action]

    def allows(self, action: str, scope: Scope) -> bool:
        return any(g.covers(scope) for g in self.grants(action))


# -- store -------------------------------------------------------------------


class AuthzStore:
    """Roles, identities, token index, idempotency keys and the authz version.

    State is persisted to SQLite (survives restarts) and mirrored in memory;
    every mutation updates the in-memory view synchronously under a lock, so
    deactivation, token rotation and permission changes are visible to the
    very next request.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        audit: AuditLog,
        clock: Callable[[], float] = time.time,
        admin_token: Optional[str] = None,
    ):
        self._conn = conn
        self._audit = audit
        self._clock = clock
        self._admin_token = admin_token
        self._lock = threading.RLock()
        self._roles: dict[str, Role] = {}
        self._identities: dict[str, Identity] = {}
        self._grants: dict[str, EmergencyGrant] = {}
        self._token_index: dict[str, str] = {}  # token hash -> identity id
        self._version = 0
        self._load()

    # -- persistence -----------------------------------------------------

    def _load(self) -> None:
        with self._lock:
            for row in self._conn.execute("SELECT payload FROM authz_roles"):
                role = Role(**json.loads(row["payload"]))
                self._roles[role.id] = role
            for row in self._conn.execute("SELECT payload FROM authz_identities"):
                ident = Identity(**json.loads(row["payload"]))
                self._identities[ident.id] = ident
                # The index holds every known hash (active or not) so a
                # deactivated identity is denied with a precise reason.
                self._token_index[ident.token_hash] = ident.id
            for row in self._conn.execute("SELECT payload FROM authz_emergency_grants"):
                grant = EmergencyGrant(**json.loads(row["payload"]))
                self._grants[grant.id] = grant
            row = self._conn.execute(
                "SELECT v FROM authz_meta WHERE k = 'authz_version'"
            ).fetchone()
            self._version = int(row["v"]) if row else 0

    def _persist_role(self, role: Role) -> None:
        self._conn.execute(
            "INSERT INTO authz_roles (id, role_version, payload, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT(id) DO UPDATE SET role_version=excluded.role_version,"
            " payload=excluded.payload, updated_at=excluded.updated_at",
            (
                role.id,
                role.role_version,
                role.model_dump_json(),
                role.created_at,
                role.updated_at,
            ),
        )
        self._conn.commit()

    def _persist_identity(self, ident: Identity) -> None:
        self._conn.execute(
            "INSERT INTO authz_identities"
            " (id, identity_version, token_hash, status, roles, payload,"
            "  created_at, updated_at, deactivated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(id) DO UPDATE SET identity_version=excluded.identity_version,"
            " token_hash=excluded.token_hash, status=excluded.status,"
            " roles=excluded.roles, payload=excluded.payload,"
            " updated_at=excluded.updated_at,"
            " deactivated_at=excluded.deactivated_at",
            (
                ident.id,
                ident.identity_version,
                ident.token_hash,
                ident.status,
                json.dumps(ident.roles),
                ident.model_dump_json(),
                ident.created_at,
                ident.updated_at,
                ident.deactivated_at,
            ),
        )
        self._conn.commit()

    def _persist_grant(self, grant: EmergencyGrant) -> None:
        self._conn.execute(
            "INSERT INTO authz_emergency_grants"
            " (id, identity_id, status, payload, created_at, updated_at, expires_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(id) DO UPDATE SET status=excluded.status,"
            " payload=excluded.payload, updated_at=excluded.updated_at,"
            " expires_at=excluded.expires_at",
            (
                grant.id,
                grant.identity_id,
                grant.status,
                grant.model_dump_json(),
                grant.requested_at,
                grant.updated_at,
                grant.expires_at,
            ),
        )
        self._conn.commit()

    def _bump_version(self) -> int:
        self._version += 1
        self._conn.execute(
            "INSERT INTO authz_meta (k, v) VALUES ('authz_version', ?)"
            " ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            (self._version,),
        )
        self._conn.commit()
        return self._version

    # -- authentication ----------------------------------------------------

    def authenticate(self, token: Optional[str]) -> Caller:
        """Resolve a bearer token to a Caller, or raise AuthnError.

        Lookup hits the in-memory index only; mutations update that index
        before returning, so revocation is effective immediately.
        """
        with self._lock:
            if self._admin_token is None and not self._identities:
                # Development mode: nothing configured to authenticate
                # against; any credential (or none) is ignored.
                return Caller(OPEN_ID, "open", ())
            if token:
                ident_id = self._token_index.get(hash_token(token))
                if ident_id is not None:
                    ident = self._identities[ident_id]
                    if ident.status != "active":
                        self._audit.record(
                            "authz_denied",
                            {
                                "identity": ident.id,
                                "action": "authenticate",
                                "reason": "identity_deactivated",
                                "authz_version": self._version,
                            },
                        )
                        raise AuthnError(f"identity {ident.id!r} is deactivated")
                    # Lapse overdue grants before computing permissions so an
                    # expired grant never survives into this request.
                    self._expire_overdue_grants()
                    permissions, grant_ids = self._permissions_of(ident)
                    return Caller(
                        identity_id=ident.id,
                        kind="identity",
                        permissions=tuple(permissions),
                        emergency_grants=tuple(grant_ids),
                    )
                if self._admin_token and secrets.compare_digest(
                    token, self._admin_token
                ):
                    return Caller(BOOTSTRAP_ID, "bootstrap", ())
                self._audit.record(
                    "authz_denied",
                    {
                        "identity": None,
                        "action": "authenticate",
                        "reason": "unknown_token",
                        "authz_version": self._version,
                    },
                )
                raise AuthnError("invalid or missing admin token")
            self._audit.record(
                "authz_denied",
                {
                    "identity": None,
                    "action": "authenticate",
                    "reason": "missing_token",
                    "authz_version": self._version,
                },
            )
            raise AuthnError("invalid or missing admin token")

    def _permissions_of(self, ident: Identity) -> tuple[list[Permission], list[str]]:
        """Role permissions plus every active emergency grant.

        Permissions are recomputed from live store state on every request --
        never baked into tokens -- so revocation and expiry of a grant take
        effect on the very next request made with the same token.
        """
        perms: list[Permission] = []
        for role_id in ident.roles:
            role = self._roles.get(role_id)
            if role:
                perms.extend(role.permissions)
        grant_ids: list[str] = []
        now = self._clock()
        for grant in self._grants.values():
            if grant.identity_id == ident.id and grant.is_active(now):
                perms.extend(grant.permissions)
                grant_ids.append(grant.id)
        return perms, grant_ids

    # -- authorization -----------------------------------------------------

    def authorize(
        self,
        caller: Caller,
        action: str,
        scopes: Optional[list[Scope]] = None,
    ) -> None:
        """Allow or deny ``action`` on ``scopes``; every decision is audited.

        ``scopes=None`` means the endpoint only needs the action itself
        (list/read endpoints filter their output by scope afterwards).
        Raises Forbidden on denial -- before the caller mutates anything.
        """
        if caller.kind in ("bootstrap", "open"):
            self._record_decision(caller, action, scopes, "allow", None)
            return
        grants = caller.grants(action)
        if not grants:
            self._record_decision(
                caller, action, scopes, "deny", f"no {action!r} permission"
            )
            raise Forbidden(
                f"identity {caller.identity_id!r} lacks permission {action!r}"
            )
        for scope in scopes or []:
            if not any(g.covers(scope) for g in grants):
                reason = (
                    f"scope {scope.describe()} is not covered by any "
                    f"{action!r} grant"
                )
                self._record_decision(caller, action, scopes, "deny", reason)
                raise Forbidden(
                    f"identity {caller.identity_id!r} may not perform {action!r} "
                    f"on {scope.describe()}"
                )
        self._record_decision(caller, action, scopes, "allow", None)

    def _record_decision(
        self,
        caller: Caller,
        action: str,
        scopes: Optional[list[Scope]],
        outcome: str,
        reason: Optional[str],
    ) -> None:
        details = {
            "identity": caller.identity_id,
            "caller_kind": caller.kind,
            "action": action,
            "scopes": [s.describe() for s in scopes] if scopes else [],
            "outcome": outcome,
            "authz_version": self._version,
        }
        if caller.emergency_grants:
            details["emergency_grants"] = list(caller.emergency_grants)
        if reason:
            details["reason"] = reason
        self._audit.record(
            "authz_decision" if outcome == "allow" else "authz_denied", details
        )

    # -- delegation constraint ----------------------------------------------

    def _check_delegation(self, caller: Caller, permissions: list[Permission]) -> None:
        """A caller may only delegate scopes its own admin:manage covers.

        This is what stops a tenant-scoped admin from minting region or
        global permissions for itself or others.
        """
        if caller.kind in ("bootstrap", "open"):
            return
        grants = caller.grants("admin:manage")
        for perm in permissions:
            if not any(g.covers(perm.scope) for g in grants):
                raise Forbidden(
                    f"identity {caller.identity_id!r} cannot delegate "
                    f"{perm.action!r} at {perm.scope.describe()}: not covered "
                    "by its admin:manage scope"
                )

    def check_visible(self, caller: Caller, permissions: list[Permission]) -> None:
        """Raise Forbidden unless every permission is delegable by the caller."""
        self._check_delegation(caller, permissions)

    def _check_roles_visible(self, caller: Caller, role_ids: list[str]) -> None:
        for role_id in role_ids:
            role = self._roles.get(role_id)
            if role is None:
                raise AuthzNotFound(f"role {role_id!r} does not exist")
            self._check_delegation(caller, role.permissions)

    # -- role lifecycle ------------------------------------------------------

    def create_role(
        self,
        caller: Caller,
        role_id: str,
        description: str,
        permissions: list[Permission],
    ) -> Role:
        with self._lock:
            self._check_delegation(caller, permissions)
            if role_id in self._roles:
                raise AuthzConflict(f"role {role_id!r} already exists")
            now = self._clock()
            role = Role(
                id=role_id,
                description=description,
                permissions=permissions,
                role_version=1,
                created_at=now,
                updated_at=now,
            )
            version = self._bump_version()
            self._roles[role_id] = role
            self._persist_role(role)
            self._audit.record(
                "role_change",
                {
                    "action": "created",
                    "role_id": role_id,
                    "actor": caller.identity_id,
                    "old": None,
                    "new": role.public(),
                    "authz_version": version,
                },
            )
            return role

    def update_role(
        self,
        caller: Caller,
        role_id: str,
        description: Optional[str],
        permissions: Optional[list[Permission]],
        expected_version: Optional[int],
    ) -> Role:
        with self._lock:
            role = self._roles.get(role_id)
            if role is None:
                raise AuthzNotFound(f"role {role_id!r} does not exist")
            # Both the old and the new permission set must be delegable:
            # otherwise a narrower admin could rewrite a broader role.
            self._check_delegation(caller, role.permissions)
            if permissions is not None:
                self._check_delegation(caller, permissions)
            if expected_version is not None and expected_version != role.role_version:
                raise AuthzConflict(
                    f"optimistic concurrency check failed for role {role_id!r}: "
                    f"expected version {expected_version}, "
                    f"current {role.role_version}"
                )
            old = role.public()
            changed = False
            if permissions is not None and permissions != role.permissions:
                role.permissions = permissions
                changed = True
            if description is not None and description != role.description:
                role.description = description
                changed = True
            if not changed:
                return role  # idempotent no-op: no version bump, no audit
            role.role_version += 1
            role.updated_at = self._clock()
            version = self._bump_version()
            self._persist_role(role)
            self._audit.record(
                "role_change",
                {
                    "action": "updated",
                    "role_id": role_id,
                    "actor": caller.identity_id,
                    "old": old,
                    "new": role.public(),
                    "authz_version": version,
                },
            )
            return role

    def delete_role(self, caller: Caller, role_id: str) -> None:
        with self._lock:
            role = self._roles.get(role_id)
            if role is None:
                raise AuthzNotFound(f"role {role_id!r} does not exist")
            self._check_delegation(caller, role.permissions)
            users = [i.id for i in self._identities.values() if role_id in i.roles]
            if users:
                raise RoleInUse(
                    f"role {role_id!r} is still assigned to identities: {users}"
                )
            version = self._bump_version()
            del self._roles[role_id]
            self._conn.execute("DELETE FROM authz_roles WHERE id = ?", (role_id,))
            self._conn.commit()
            self._audit.record(
                "role_change",
                {
                    "action": "deleted",
                    "role_id": role_id,
                    "actor": caller.identity_id,
                    "old": role.public(),
                    "new": None,
                    "authz_version": version,
                },
            )

    def get_role(self, role_id: str) -> Role:
        with self._lock:
            role = self._roles.get(role_id)
            if role is None:
                raise AuthzNotFound(f"role {role_id!r} does not exist")
            return role

    def list_roles(self, caller: Caller) -> list[Role]:
        """Roles whose permissions are fully covered by the caller's scope."""
        with self._lock:
            return [
                r
                for r in sorted(self._roles.values(), key=lambda r: r.id)
                if self._delegable(caller, r.permissions)
            ]

    def _delegable(self, caller: Caller, permissions: list[Permission]) -> bool:
        if caller.kind in ("bootstrap", "open"):
            return True
        grants = caller.grants("admin:manage")
        return all(
            any(g.covers(p.scope) for g in grants) for p in permissions
        )

    # -- identity lifecycle ---------------------------------------------------

    def create_identity(
        self,
        caller: Caller,
        identity_id: str,
        role_ids: list[str],
        token: Optional[str] = None,
    ) -> tuple[Identity, str]:
        """Create an identity; returns it plus its plaintext token (shown once)."""
        with self._lock:
            if identity_id in (BOOTSTRAP_ID, OPEN_ID):
                raise AuthzConflict(f"identity id {identity_id!r} is reserved")
            self._check_roles_visible(caller, role_ids)
            if identity_id in self._identities:
                raise AuthzConflict(f"identity {identity_id!r} already exists")
            if not identity_id or not identity_id.strip():
                raise AuthzConflict("identity id must be a non-empty string")
            raw_token = token or generate_token()
            token_hash = hash_token(raw_token)
            if token_hash in self._token_index or (
                self._admin_token
                and secrets.compare_digest(raw_token, self._admin_token)
            ):
                raise AuthzConflict("token is already in use")
            now = self._clock()
            ident = Identity(
                id=identity_id,
                token_hash=token_hash,
                roles=list(role_ids),
                status="active",
                identity_version=1,
                created_at=now,
                updated_at=now,
            )
            version = self._bump_version()
            self._identities[identity_id] = ident
            self._token_index[token_hash] = identity_id
            self._persist_identity(ident)
            self._audit.record(
                "identity_change",
                {
                    "action": "created",
                    "identity": identity_id,
                    "actor": caller.identity_id,
                    "old": None,
                    "new": ident.public(),
                    "authz_version": version,
                },
            )
            return ident, raw_token

    def update_identity(
        self,
        caller: Caller,
        identity_id: str,
        role_ids: Optional[list[str]],
        rotate_token: bool,
        expected_version: Optional[int],
    ) -> tuple[Identity, Optional[str]]:
        """Replace role assignments and/or rotate the token.

        Token rotation revokes the old token synchronously: the index entry
        is swapped before this method returns, so the old token fails the
        very next authentication attempt.
        """
        with self._lock:
            ident = self._identities.get(identity_id)
            if ident is None:
                raise AuthzNotFound(f"identity {identity_id!r} does not exist")
            self._check_roles_visible(caller, ident.roles)
            if role_ids is not None:
                self._check_roles_visible(caller, role_ids)
            if (
                expected_version is not None
                and expected_version != ident.identity_version
            ):
                raise AuthzConflict(
                    f"optimistic concurrency check failed for identity "
                    f"{identity_id!r}: expected version {expected_version}, "
                    f"current {ident.identity_version}"
                )
            old = ident.public()
            new_token: Optional[str] = None
            changed = False
            if role_ids is not None and list(role_ids) != ident.roles:
                ident.roles = list(role_ids)
                changed = True
            if rotate_token:
                new_token = generate_token()
                new_hash = hash_token(new_token)
                # Revoke the old hash synchronously; it fails authentication
                # from the very next request on.
                self._token_index.pop(ident.token_hash, None)
                ident.token_hash = new_hash
                self._token_index[new_hash] = identity_id
                changed = True
            if not changed:
                return ident, None
            ident.identity_version += 1
            ident.updated_at = self._clock()
            version = self._bump_version()
            self._persist_identity(ident)
            details = {
                "action": "updated",
                "identity": identity_id,
                "actor": caller.identity_id,
                "old": old,
                "new": ident.public(),
                "authz_version": version,
            }
            if rotate_token:
                details["token_rotated"] = True
            self._audit.record("identity_change", details)
            return ident, new_token

    def set_status(
        self, caller: Caller, identity_id: str, active: bool
    ) -> tuple[Identity, bool]:
        """(De)activate an identity. Returns (identity, changed).

        Deactivation removes the token from the live index before returning,
        so it takes effect immediately. Repeating the call is an idempotent
        no-op (no version bump, no duplicate audit record).
        """
        with self._lock:
            ident = self._identities.get(identity_id)
            if ident is None:
                raise AuthzNotFound(f"identity {identity_id!r} does not exist")
            self._check_roles_visible(caller, ident.roles)
            target = "active" if active else "deactivated"
            if ident.status == target:
                return ident, False
            old = ident.public()
            ident.status = target
            ident.identity_version += 1
            ident.updated_at = self._clock()
            ident.deactivated_at = None if active else ident.updated_at
            # The hash stays indexed either way; authenticate() checks the
            # status, so deactivation is effective from the next request.
            self._token_index[ident.token_hash] = identity_id
            version = self._bump_version()
            self._persist_identity(ident)
            self._audit.record(
                "identity_change",
                {
                    "action": "reactivated" if active else "deactivated",
                    "identity": identity_id,
                    "actor": caller.identity_id,
                    "old": old,
                    "new": ident.public(),
                    "authz_version": version,
                },
            )
            return ident, True

    def get_identity(self, identity_id: str) -> Identity:
        with self._lock:
            ident = self._identities.get(identity_id)
            if ident is None:
                raise AuthzNotFound(f"identity {identity_id!r} does not exist")
            return ident

    def list_identities(self, caller: Caller) -> list[Identity]:
        with self._lock:
            return [
                i
                for i in sorted(self._identities.values(), key=lambda i: i.id)
                if self._identity_visible(caller, i)
            ]

    def _identity_visible(self, caller: Caller, ident: Identity) -> bool:
        if caller.kind in ("bootstrap", "open"):
            return True
        if ident.id == caller.identity_id:
            return True  # an identity can always see itself
        perms: list[Permission] = []
        for role_id in ident.roles:
            role = self._roles.get(role_id)
            if role:
                perms.extend(role.permissions)
        return self._delegable(caller, perms)

    def identity_visible(self, caller: Caller, ident: Identity) -> bool:
        with self._lock:
            return self._identity_visible(caller, ident)

    # -- emergency grants -------------------------------------------------

    def _new_grant_id(self) -> str:
        while True:
            grant_id = "egrant_" + secrets.token_urlsafe(9)
            if grant_id not in self._grants:
                return grant_id

    def _grant_audit_details(
        self,
        action: str,
        grant: EmergencyGrant,
        actor: str,
        version: int,
        comment: Optional[str] = None,
    ) -> dict:
        details = {
            "action": action,
            "grant_id": grant.id,
            "identity": grant.identity_id,
            "requested_by": grant.requested_by,
            "actor": actor,
            "reason": grant.reason,
            "permissions": [p.model_dump() for p in grant.permissions],
            "scopes": [p.scope.describe() for p in grant.permissions],
            "duration_seconds": grant.duration_seconds,
            "status": grant.status,
            "grant_version": grant.grant_version,
            "expires_at": grant.expires_at,
            "authz_version": version,
        }
        if comment:
            details["comment"] = comment
        return details

    def _expire_overdue_grants(self) -> None:
        """Lapse every active grant whose window has closed.

        Expiry is lazy: the transition is detected, persisted and audited the
        first time anyone looks (authentication, grant reads, decisions),
        which is also the moment the permissions stop applying.
        """
        now = self._clock()
        for grant in self._grants.values():
            if (
                grant.status == "approved"
                and grant.expires_at is not None
                and grant.expires_at <= now
            ):
                grant.status = "expired"
                grant.grant_version += 1
                grant.updated_at = now
                version = self._bump_version()
                self._persist_grant(grant)
                self._audit.record(
                    "emergency_grant",
                    self._grant_audit_details("expired", grant, "system", version),
                )

    def request_grant(
        self,
        caller: Caller,
        identity_id: str,
        reason: str,
        permissions: list[Permission],
        duration_seconds: float,
    ) -> EmergencyGrant:
        """File an emergency grant request. The request itself grants nothing.

        Any authenticated caller may request (for itself or another
        identity); the permission gate is the approval step, where the
        approver's delegable scope is enforced.
        """
        with self._lock:
            self._expire_overdue_grants()
            if identity_id not in self._identities:
                raise AuthzNotFound(f"identity {identity_id!r} does not exist")
            now = self._clock()
            grant = EmergencyGrant(
                id=self._new_grant_id(),
                identity_id=identity_id,
                reason=reason,
                permissions=list(permissions),
                duration_seconds=duration_seconds,
                status="pending",
                requested_by=caller.identity_id,
                requested_at=now,
                updated_at=now,
            )
            version = self._bump_version()
            self._grants[grant.id] = grant
            self._persist_grant(grant)
            self._audit.record(
                "emergency_grant",
                self._grant_audit_details(
                    "requested", grant, caller.identity_id, version
                ),
            )
            return grant

    def decide_grant(
        self,
        caller: Caller,
        grant_id: str,
        approve: bool,
        comment: Optional[str],
        expected_version: Optional[int],
    ) -> EmergencyGrant:
        """Approve or reject a pending request.

        Separation of duties: a caller can never rule on its own request.
        The granted permissions must be fully covered by the decider's
        ``admin:manage`` scope, so a narrower admin cannot approve an
        elevation beyond what it could itself delegate. Only one decision is
        possible: concurrent deciders are serialized by the lock and the
        loser sees a conflict, as does anyone deciding an already decided or
        lapsed grant.
        """
        with self._lock:
            self._expire_overdue_grants()
            grant = self._grants.get(grant_id)
            if grant is None:
                raise AuthzNotFound(f"emergency grant {grant_id!r} does not exist")
            if caller.kind != "open" and caller.identity_id == grant.requested_by:
                raise Forbidden(
                    f"caller {caller.identity_id!r} cannot approve or reject "
                    "its own emergency grant request"
                )
            self._check_delegation(caller, grant.permissions)
            if grant.status != "pending":
                raise AuthzConflict(
                    f"emergency grant {grant_id!r} is already {grant.status}; "
                    "only a pending request can be decided"
                )
            if expected_version is not None and expected_version != grant.grant_version:
                raise AuthzConflict(
                    f"optimistic concurrency check failed for emergency grant "
                    f"{grant_id!r}: expected version {expected_version}, "
                    f"current {grant.grant_version}"
                )
            now = self._clock()
            grant.status = "approved" if approve else "rejected"
            grant.decided_by = caller.identity_id
            grant.decided_at = now
            grant.decision_comment = comment
            if approve:
                grant.approved_at = now
                grant.expires_at = now + grant.duration_seconds
            grant.grant_version += 1
            grant.updated_at = now
            version = self._bump_version()
            self._persist_grant(grant)
            self._audit.record(
                "emergency_grant",
                self._grant_audit_details(
                    "approved" if approve else "rejected",
                    grant,
                    caller.identity_id,
                    version,
                    comment=comment,
                ),
            )
            return grant

    def _can_revoke(self, caller: Caller, grant: EmergencyGrant) -> bool:
        if caller.kind in ("bootstrap", "open"):
            return True
        # The grantee and the original requester may always give the
        # elevation up; anyone else needs admin:manage over the scopes.
        if caller.identity_id in (grant.identity_id, grant.requested_by):
            return True
        return self._delegable(caller, grant.permissions)

    def revoke_grant(
        self,
        caller: Caller,
        grant_id: str,
        expected_version: Optional[int],
    ) -> EmergencyGrant:
        """Revoke an active grant; the permissions lapse immediately.

        Revoking a grant that is not currently active -- including one that
        has already expired -- is a conflict, so concurrent revokers and
        late writes against a lapsed grant are rejected.
        """
        with self._lock:
            self._expire_overdue_grants()
            grant = self._grants.get(grant_id)
            if grant is None:
                raise AuthzNotFound(f"emergency grant {grant_id!r} does not exist")
            scopes = [p.scope for p in grant.permissions]
            if not self._can_revoke(caller, grant):
                self._record_decision(
                    caller,
                    "emergency:revoke",
                    scopes,
                    "deny",
                    "caller may not revoke this grant",
                )
                raise Forbidden(
                    f"identity {caller.identity_id!r} may not revoke "
                    f"emergency grant {grant_id!r}"
                )
            self._record_decision(caller, "emergency:revoke", scopes, "allow", None)
            if grant.status != "approved":
                raise AuthzConflict(
                    f"emergency grant {grant_id!r} is {grant.status}; only an "
                    "active (approved and unexpired) grant can be revoked"
                )
            if expected_version is not None and expected_version != grant.grant_version:
                raise AuthzConflict(
                    f"optimistic concurrency check failed for emergency grant "
                    f"{grant_id!r}: expected version {expected_version}, "
                    f"current {grant.grant_version}"
                )
            now = self._clock()
            grant.status = "revoked"
            grant.revoked_by = caller.identity_id
            grant.revoked_at = now
            grant.grant_version += 1
            grant.updated_at = now
            version = self._bump_version()
            self._persist_grant(grant)
            self._audit.record(
                "emergency_grant",
                self._grant_audit_details(
                    "revoked", grant, caller.identity_id, version
                ),
            )
            return grant

    def get_grant(self, grant_id: str) -> EmergencyGrant:
        with self._lock:
            self._expire_overdue_grants()
            grant = self._grants.get(grant_id)
            if grant is None:
                raise AuthzNotFound(f"emergency grant {grant_id!r} does not exist")
            return grant

    def list_grants(
        self,
        caller: Caller,
        status: Optional[str] = None,
        identity_id: Optional[str] = None,
    ) -> list[EmergencyGrant]:
        with self._lock:
            self._expire_overdue_grants()
            grants = [
                g for g in self._grants.values() if self._grant_visible(caller, g)
            ]
            if status is not None:
                grants = [g for g in grants if g.status == status]
            if identity_id is not None:
                grants = [g for g in grants if g.identity_id == identity_id]
            return sorted(grants, key=lambda g: (g.requested_at, g.id))

    def _grant_visible(self, caller: Caller, grant: EmergencyGrant) -> bool:
        if caller.kind in ("bootstrap", "open"):
            return True
        if caller.identity_id in (grant.requested_by, grant.identity_id):
            return True  # requesters and grantees always see their own grants
        return self._delegable(caller, grant.permissions)

    def grant_visible(self, caller: Caller, grant: EmergencyGrant) -> bool:
        with self._lock:
            return self._grant_visible(caller, grant)

    def grant_view(self, grant: EmergencyGrant) -> dict:
        """API view of a grant, with liveness computed against the store clock."""
        with self._lock:
            return grant.public(self._clock())

    # -- idempotency -----------------------------------------------------------

    def idempotency_lookup(self, key: str, fingerprint: str) -> Optional[dict]:
        """Return the stored response for this key, or None if unseen.

        A known key with a different request fingerprint is a conflict.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT request_fingerprint, status_code, response"
                " FROM authz_idempotency WHERE key = ?",
                (key,),
            ).fetchone()
            if row is None:
                return None
            if row["request_fingerprint"] != fingerprint:
                raise IdempotencyConflict(
                    "Idempotency-Key was already used with a different request"
                )
            return {
                "status_code": row["status_code"],
                "body": json.loads(row["response"]),
            }

    def idempotency_store(
        self, key: str, fingerprint: str, status_code: int, body: dict
    ) -> None:
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO authz_idempotency"
                    " (key, request_fingerprint, status_code, response, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        key,
                        fingerprint,
                        status_code,
                        json.dumps(body, sort_keys=True),
                        self._clock(),
                    ),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                # A concurrent request with the same key committed first.
                raise IdempotencyConflict(
                    "Idempotency-Key is being processed by a concurrent request"
                ) from exc

    # -- introspection ---------------------------------------------------------

    @property
    def version(self) -> int:
        with self._lock:
            return self._version


def request_fingerprint(method: str, path: str, caller_id: str, body: dict) -> str:
    """Stable hash binding an idempotency key to one exact request."""
    material = {
        "method": method,
        "path": path,
        "caller": caller_id,
        "body": body,
    }
    return hashlib.sha256(canonical_json(material).encode()).hexdigest()
