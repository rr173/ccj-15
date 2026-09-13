"""Resolution-usage metering and per-tenant budget alerting.

Every resolution request produces one *replayable usage event*, keyed by a
client-supplied or server-generated ``event_id`` and archived by **event
time** rather than ingestion time. Duplicate events are detected on that key
and never billed twice; late/out-of-order events land in the period their
event time belongs to, and aggregates are recomputed incrementally so the
detail log and every aggregate row always agree.

Budgets
-------
A tenant budget fixes a daily or monthly allowance, alert thresholds
(percentages of the allowance) and an over-budget policy:

- ``allow``  : keep serving, only meter;
- ``degrade``: serve a deterministic degraded answer, still metered;
- ``reject`` : refuse resolution (HTTP 402), the refusal itself is archived
               as a zero-quantity ``budget_rejected`` event so denials are
               explainable and replayable.

Crossing a threshold creates exactly one *open* audit alert per
(tenant, period, threshold), including when a late/backfilled event pushes a
past period over a threshold retroactively. Alerts survive restarts until an
authorized administrator acknowledges them (optimistically versioned).

Policy inheritance and temporary overrides
------------------------------------------
Budgets form a three-level resolution chain, highest precedence first:

1. a **temporary override** that is approved and whose validity window
   contains the resolution time;
2. the tenant's **dedicated budget** (the ``budgets`` table);
3. the tenant's **group default** -- a budget group's policy, inherited up an
   acyclic ``parent_id`` chain when the group itself carries no policy.

Every resolved policy reports its *source* (``override`` / ``tenant`` /
``group``), the source row id and that row's *version*, so resolution
requests and budget queries show exactly which policy and which revision is
in force. Group policy changes, member migrations and override
approval/revocation are all computed live under the store lock, so the very
next resolution uses the new policy.

The policy actually applied to each (tenant, period) is kept in
``budget_policy_snapshots``. The still-open period follows live policy. The
first event that lands in an already closed period (a late/backfilled event
or a recompute) materializes the policy *as of the period boundary* and
freezes it; every later observation of that historical period -- alerts,
usage recomputation -- keeps using that frozen snapshot, so group edits and
membership moves never rewrite the past.

Temporary overrides are requested for an explicit [start, end) window and are
inert until a **different** authorized administrator approves them. Two
non-terminal overrides for one tenant may never have overlapping windows,
and acting on an expired/terminal override, creating a cyclic group
inheritance chain, moving a tenant whose membership version changed
concurrently, or writing one tenant's override/group through another
tenant's scope is explicitly rejected (and audited as
``budget_policy_denied``).

Persistence / concurrency
-------------------------
Events, aggregates, budgets and alerts all live in SQLite. One process-wide
lock serializes mutations and every write is a transaction, so an event
insert and its aggregate deltas commit together (or not at all). Budget,
group, membership, override and alert rows carry monotonically increasing
versions with ``expected_version`` optimistic concurrency; control-plane
writes also accept ``Idempotency-Key`` (reused via the authz store).
"""
from __future__ import annotations

import calendar
import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, replace as dataclasses_replace
from datetime import datetime, timezone
from typing import Callable, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from .audit import AuditLog

PERIOD_DAY = "day"
PERIOD_MONTH = "month"
PERIOD_TYPES = (PERIOD_DAY, PERIOD_MONTH)

POLICIES = ("allow", "degrade", "reject")

#: Event outcomes recorded in the detail log.
RESULT_SERVED = "served"
RESULT_DEGRADED = "budget_degraded"
RESULT_REJECTED = "budget_rejected"

EVENT_SOURCES = ("live", "backfill")

#: Where an effective policy came from.
SOURCE_OVERRIDE = "override"
SOURCE_TENANT = "tenant"
SOURCE_GROUP = "group"
POLICY_SOURCES = (SOURCE_OVERRIDE, SOURCE_TENANT, SOURCE_GROUP)

#: Override lifecycle.
OVERRIDE_STATUSES = (
    "pending", "approved", "rejected", "revoked", "expired",
)
OVERRIDE_TERMINAL_STATUSES = ("rejected", "revoked", "expired")


# -- exceptions ---------------------------------------------------------------


class BudgetExceeded(Exception):
    """Raised by the data plane when a tenant budget rejects the request."""

    def __init__(self, decision: "BudgetDecision", event_id: Optional[str] = None):
        self.decision = decision
        self.event_id = event_id
        super().__init__(decision.reason)


class MeteringConflict(Exception):
    """Optimistic-concurrency or uniqueness violation (HTTP 409)."""


class MeteringNotFound(Exception):
    pass


class MeteringValidationError(Exception):
    """Malformed control-plane input (HTTP 422)."""


class PolicyDenied(Exception):
    """A policy/override/membership rule refused the write (HTTP 409).

    Distinct from MeteringConflict so callers can distinguish semantic
    refusals (cyclic inheritance, cross-scope writes, expired overrides,
    separation-of-duties violations) from plain optimistic-concurrency
    losses; every refusal is audited by the store.
    """


# -- models -------------------------------------------------------------------


def _validate_thresholds(v: list[float]) -> list[float]:
    for t in v:
        if t != t or t in (float("inf"), float("-inf")) or not (0.0 < t <= 10.0):
            raise ValueError(
                "alert thresholds must be finite numbers in (0, 10] "
                "(fractions of the budget)"
            )
    return sorted(set(round(float(t), 6) for t in v))


class BudgetSpec(BaseModel):
    """A tenant's metering budget, thresholds and over-budget policy."""

    tenant: str
    period_type: str = PERIOD_DAY
    amount: float = Field(gt=0, allow_inf_nan=False)
    alert_thresholds: list[float] = Field(default_factory=lambda: [0.8, 1.0])
    over_policy: str = "reject"
    expected_version: Optional[int] = Field(default=None, ge=1)

    @field_validator("tenant")
    @classmethod
    def _tenant_nonempty(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if not v:
            raise ValueError("tenant must be a non-empty string")
        return v

    @field_validator("period_type")
    @classmethod
    def _known_period(cls, v: str) -> str:
        if v not in PERIOD_TYPES:
            raise ValueError(f"period_type must be one of {PERIOD_TYPES}")
        return v

    @field_validator("over_policy")
    @classmethod
    def _known_policy(cls, v: str) -> str:
        if v not in POLICIES:
            raise ValueError(f"over_policy must be one of {POLICIES}")
        return v

    @field_validator("alert_thresholds")
    @classmethod
    def _thresholds_sane(cls, v: list[float]) -> list[float]:
        return _validate_thresholds(v)


class PolicyFields(BaseModel):
    """The budget knobs shared by tenant budgets, groups and overrides."""

    period_type: str = PERIOD_DAY
    amount: float = Field(gt=0, allow_inf_nan=False)
    alert_thresholds: list[float] = Field(default_factory=lambda: [0.8, 1.0])
    over_policy: str = "reject"

    @field_validator("period_type")
    @classmethod
    def _known_period(cls, v: str) -> str:
        if v not in PERIOD_TYPES:
            raise ValueError(f"period_type must be one of {PERIOD_TYPES}")
        return v

    @field_validator("over_policy")
    @classmethod
    def _known_policy(cls, v: str) -> str:
        if v not in POLICIES:
            raise ValueError(f"over_policy must be one of {POLICIES}")
        return v

    @field_validator("alert_thresholds")
    @classmethod
    def _thresholds_sane(cls, v: list[float]) -> list[float]:
        return _validate_thresholds(v)


class BudgetGroupSpec(BaseModel):
    """Create/replace a tenant budget group and its default policy.

    All four policy fields are ``None`` together: the group then carries no
    policy of its own and inherits ``parent_id``'s policy. When present they
    must all be present, and ``parent_id`` must not (re)introduce a cycle.
    """

    id: Optional[str] = None
    description: str = ""
    parent_id: Optional[str] = None
    period_type: Optional[str] = None
    amount: Optional[float] = Field(default=None, allow_inf_nan=False)
    alert_thresholds: Optional[list[float]] = None
    over_policy: Optional[str] = None
    expected_version: Optional[int] = Field(default=None, ge=1)

    @field_validator("id", "parent_id")
    @classmethod
    def _norm_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip().lower()
        if not v:
            raise ValueError("group id must be a non-empty string")
        return v

    @field_validator("period_type")
    @classmethod
    def _known_period(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in PERIOD_TYPES:
            raise ValueError(f"period_type must be one of {PERIOD_TYPES}")
        return v

    @field_validator("over_policy")
    @classmethod
    def _known_policy(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in POLICIES:
            raise ValueError(f"over_policy must be one of {POLICIES}")
        return v

    @field_validator("amount")
    @classmethod
    def _positive_amount(cls, v: Optional[float]) -> Optional[float]:
        if v is not None:
            if v != v or v in (float("inf"), float("-inf")) or v <= 0:
                raise ValueError("amount must be a finite positive number")
        return v

    @field_validator("alert_thresholds")
    @classmethod
    def _thresholds_sane(cls, v: Optional[list[float]]) -> Optional[list[float]]:
        return None if v is None else _validate_thresholds(v)

    @model_validator(mode="after")
    def _policy_complete_or_absent(self) -> "BudgetGroupSpec":
        fields = (self.period_type, self.amount,
                  self.alert_thresholds, self.over_policy)
        present = [f is not None for f in fields]
        if any(present) and not all(present):
            raise ValueError(
                "group policy fields (period_type, amount, alert_thresholds, "
                "over_policy) must all be present or all absent; an absent "
                "policy makes the group inherit its parent's policy"
            )
        return self

    def has_policy(self) -> bool:
        return self.period_type is not None


class OverrideSpec(BaseModel):
    """A requested temporary override: policy plus a half-open time window."""

    tenant: Optional[str] = None  # filled from the URL path by the API
    period_type: str = PERIOD_DAY
    amount: float = Field(gt=0, allow_inf_nan=False)
    alert_thresholds: list[float] = Field(default_factory=lambda: [0.8, 1.0])
    over_policy: str = "reject"
    window_start: float = Field(allow_inf_nan=False)
    window_end: float = Field(allow_inf_nan=False)
    reason: str = ""
    expected_version: Optional[int] = Field(default=None, ge=1)

    @field_validator("tenant")
    @classmethod
    def _tenant_nonempty(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip().lower()
        if not v:
            raise ValueError("tenant must be a non-empty string")
        return v

    @field_validator("period_type")
    @classmethod
    def _known_period(cls, v: str) -> str:
        if v not in PERIOD_TYPES:
            raise ValueError(f"period_type must be one of {PERIOD_TYPES}")
        return v

    @field_validator("over_policy")
    @classmethod
    def _known_policy(cls, v: str) -> str:
        if v not in POLICIES:
            raise ValueError(f"over_policy must be one of {POLICIES}")
        return v

    @field_validator("alert_thresholds")
    @classmethod
    def _thresholds_sane(cls, v: list[float]) -> list[float]:
        return _validate_thresholds(v)

    @model_validator(mode="after")
    def _check_window(self) -> "OverrideSpec":
        for bound in (self.window_start, self.window_end):
            if bound != bound or bound in (float("inf"), float("-inf")):
                raise ValueError("window bounds must be finite epoch seconds")
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be greater than window_start")
        return self


@dataclass(frozen=True)
class EffectivePolicy:
    """A resolved budget policy with full attribution of its origin."""

    tenant: str
    source: str  # SOURCE_OVERRIDE | SOURCE_TENANT | SOURCE_GROUP
    source_id: str
    source_version: int
    period_type: str
    amount: float
    alert_thresholds: tuple[float, ...]
    over_policy: str
    #: resolved_at for live resolution; for historical resolution this is the
    #: as-of time the chain (membership/override/group revisions) was read at.
    resolved_at: float
    #: override-only attribution
    override_id: Optional[str] = None
    override_version: Optional[int] = None
    #: group attribution, including when the tenant inherited via a chain
    group_id: Optional[str] = None
    #: the tenant's directly assigned group at resolution time, if any
    member_group_id: Optional[str] = None
    window_start: Optional[float] = None
    window_end: Optional[float] = None

    def policy_dict(self) -> dict:
        return {
            "period_type": self.period_type,
            "amount": self.amount,
            "alert_thresholds": list(self.alert_thresholds),
            "over_policy": self.over_policy,
        }

    def origin(self) -> dict:
        return {
            "source": self.source,
            "source_id": self.source_id,
            "source_version": self.source_version,
            "group_id": self.group_id,
            "member_group_id": self.member_group_id,
            "override_id": self.override_id,
            "override_version": self.override_version,
            "window_start": self.window_start,
            "window_end": self.window_end,
        }



# -- period math (UTC) --------------------------------------------------------


def period_start(ts: float, period_type: str) -> float:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    if period_type == PERIOD_MONTH:
        dt = dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    else:
        dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    return dt.timestamp()


def period_label(ts: float, period_type: str) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m") if period_type == PERIOD_MONTH else dt.strftime("%Y-%m-%d")


def next_period_start(ts: float, period_type: str) -> float:
    start = period_start(ts, period_type)
    if period_type == PERIOD_MONTH:
        dt = datetime.fromtimestamp(start, tz=timezone.utc)
        year, month = dt.year, dt.month + 1
        if month == 13:
            year, month = year + 1, 1
        return calendar.timegm((year, month, 1, 0, 0, 0, 0, 0, 0)) * 1.0
    return start + 86400.0


def new_event_id() -> str:
    return "uevt_" + secrets.token_urlsafe(12)


def new_alert_id() -> str:
    return "balert_" + secrets.token_urlsafe(9)


# -- data-plane decision ------------------------------------------------------


class BudgetDecision:
    """The budget gate's verdict for one resolution request."""

    def __init__(
        self,
        *,
        budget: Optional[dict],
        period_type: Optional[str],
        period_started_at: Optional[float],
        used: float,
        amount: Optional[float],
        policy: str,
        allowed: bool,
        degraded: bool,
        reason: str,
        thresholds: Optional[list[float]] = None,
        open_alerts: Optional[list[dict]] = None,
        origin: Optional[dict] = None,
        raw_used: Optional[float] = None,
        normal_adjustment: float = 0.0,
    ):
        self.budget = budget
        self.period_type = period_type
        self.period_started_at = period_started_at
        self.used = used
        self.amount = amount
        self.policy = policy
        self.allowed = allowed
        self.degraded = degraded
        self.reason = reason
        self.thresholds = thresholds or []
        self.open_alerts = open_alerts or []
        self.origin = origin
        #: Raw billed quantity from the immutable aggregates, before dispute
        #: adjustments; equal to ``used`` when no dispute adjustment applies.
        self.raw_used = raw_used if raw_used is not None else used
        self.normal_adjustment = normal_adjustment

    @property
    def remaining(self) -> float:
        if self.amount is None:
            return None
        return max(0.0, self.amount - self.used)

    @property
    def usage_ratio(self) -> Optional[float]:
        if not self.amount:
            return None
        return self.used / self.amount

    def public(self) -> dict:
        remaining = self.remaining
        return {
            "enabled": self.budget is not None,
            "tenant": (self.budget or {}).get("tenant"),
            "period_type": self.period_type,
            "period": period_label(self.period_started_at, self.period_type)
            if self.period_started_at is not None and self.period_type
            else None,
            "period_start": self.period_started_at,
            "amount": self.amount,
            "used": self.used,
            "raw_used": self.raw_used,
            "normal_adjustment": self.normal_adjustment,
            "remaining": remaining,
            "usage_ratio": self.usage_ratio,
            "adjusted": abs(self.normal_adjustment) > 1e-12,
            "policy": self.policy if self.budget is not None else None,
            "allowed": self.allowed,
            "degraded": self.degraded,
            "reason": self.reason,
            "alert_thresholds": self.thresholds,
            "open_alerts": self.open_alerts,
            # Where the policy actually came from (override/tenant/group) and
            # which revision of it; None when no policy governs the tenant.
            "policy_source": (self.origin or {}).get("source")
            if self.budget is not None
            else None,
            "policy_origin": self.origin,
        }


# -- the store ----------------------------------------------------------------


class MeteringStore:
    """Events, aggregates, budgets and alerts with a single mutation lock."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        audit: AuditLog,
        clock: Callable[[], float] = time.time,
        max_future_skew: float = 60.0,
    ):
        self._conn = conn
        self._audit = audit
        self._clock = clock
        self.max_future_skew = max_future_skew
        self._lock = threading.RLock()

    # -- helpers -------------------------------------------------------------

    @property
    def lock(self) -> threading.RLock:
        """Reentrant mutation lock, shared with sibling budget stores.

        The dispute/adjustment store serializes against event ingestion and
        budget writes through this same lock, so an adjustment transaction
        can never interleave with an event transaction.
        """
        return self._lock

    @staticmethod
    def _budget_row(row: sqlite3.Row) -> dict:
        return {
            "tenant": row["tenant"],
            "period_type": row["period_type"],
            "amount": row["amount"],
            "alert_thresholds": json.loads(row["alert_thresholds"]),
            "over_policy": row["over_policy"],
            "version": row["version"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "created_by": row["created_by"],
            "updated_by": row["updated_by"],
        }

    def _get_budget_row(self, tenant: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM budgets WHERE tenant = ?", (tenant,)
        ).fetchone()

    def get_budget(self, tenant: str) -> Optional[dict]:
        with self._lock:
            row = self._get_budget_row(tenant)
            return None if row is None else self._budget_row(row)

    def list_budgets(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM budgets ORDER BY tenant"
            ).fetchall()
            return [self._budget_row(r) for r in rows]

    # -- groups, memberships, overrides: row mappers --------------------------

    @staticmethod
    def _group_row(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "description": row["description"],
            "parent_id": row["parent_id"],
            "period_type": row["period_type"],
            "amount": row["amount"],
            "alert_thresholds": (
                json.loads(row["alert_thresholds"])
                if row["alert_thresholds"] is not None
                else None
            ),
            "over_policy": row["over_policy"],
            "version": row["version"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "created_by": row["created_by"],
            "updated_by": row["updated_by"],
        }

    @staticmethod
    def _override_row(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "tenant": row["tenant"],
            "period_type": row["period_type"],
            "amount": row["amount"],
            "alert_thresholds": json.loads(row["alert_thresholds"]),
            "over_policy": row["over_policy"],
            "window_start": row["window_start"],
            "window_end": row["window_end"],
            "status": row["status"],
            "requested_by": row["requested_by"],
            "requested_at": row["requested_at"],
            "decided_by": row["decided_by"],
            "decided_at": row["decided_at"],
            "decision_comment": row["decision_comment"],
            "approved_at": row["approved_at"],
            "revoked_by": row["revoked_by"],
            "revoked_at": row["revoked_at"],
            "version": row["version"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _snapshot_row(row: sqlite3.Row) -> dict:
        return {
            "period_type": row["period_type"],
            "period_start": row["period_start"],
            "period": period_label(row["period_start"], row["period_type"]),
            "tenant": row["tenant"],
            "source": row["source"],
            "source_id": row["source_id"],
            "source_version": row["source_version"],
            "amount": row["amount"],
            "alert_thresholds": json.loads(row["alert_thresholds"]),
            "over_policy": row["over_policy"],
            "frozen": bool(row["frozen"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _new_entity_id(self, prefix: str, table: str, n: int = 9) -> str:
        while True:
            eid = prefix + secrets.token_urlsafe(n)
            exists = self._conn.execute(
                f"SELECT 1 FROM {table} WHERE id = ?", (eid,)
            ).fetchone()
            if exists is None:
                return eid

    def _audit_policy_denied(self, action: str, reason: str, **details) -> None:
        """Record an explicit policy-rule refusal (also raised to the caller)."""
        payload = {"action": action, "reason": reason, **details}
        self._audit.record("budget_policy_denied", payload)

    # -- policy resolution ----------------------------------------------------

    def resolve_policy(
        self, tenant: str, at: Optional[float] = None
    ) -> Optional[EffectivePolicy]:
        """Resolve the policy governing ``tenant`` at time ``at`` (live now).

        A past ``at`` reconstructs the chain (membership intervals, override
        lifecycle, group revisions) exactly as it stood then. Overdue
        approved overrides are lapsed (persisted + audited) before a live
        evaluation.
        """
        tenant = (tenant or "").strip().lower()
        now = self._clock()
        at = now if at is None else at
        with self._lock:
            if at >= now:
                self._expire_overdue_overrides(now=now)
                return self._resolve_policy(tenant, at)
            return self._resolve_policy(tenant, at, historical=True)

    def _active_override(
        self, conn: sqlite3.Connection, tenant: str, at: float
    ) -> Optional[sqlite3.Row]:
        return conn.execute(
            "SELECT * FROM budget_overrides"
            " WHERE tenant = ? AND status = 'approved'"
            " AND window_start <= ? AND ? < window_end"
            " ORDER BY approved_at DESC, id DESC LIMIT 1",
            (tenant, at, at),
        ).fetchone()

    def _active_override_as_of(
        self, conn: sqlite3.Connection, tenant: str, at: float
    ) -> Optional[sqlite3.Row]:
        """Override that was active at ``at``, even if later revoked/expired."""
        return conn.execute(
            "SELECT * FROM budget_overrides"
            " WHERE tenant = ? AND window_start <= ? AND ? < window_end"
            " AND approved_at IS NOT NULL AND approved_at <= ?"
            " AND (revoked_at IS NULL OR revoked_at > ?)"
            " ORDER BY approved_at DESC, id DESC LIMIT 1",
            (tenant, at, at, at, at),
        ).fetchone()

    def _member_group(self, conn: sqlite3.Connection, tenant: str) -> Optional[str]:
        row = conn.execute(
            "SELECT group_id FROM budget_group_members WHERE tenant = ?",
            (tenant,),
        ).fetchone()
        return None if row is None else row["group_id"]

    def _member_group_as_of(
        self, conn: sqlite3.Connection, tenant: str, at: float
    ) -> Optional[str]:
        row = conn.execute(
            "SELECT group_id FROM budget_group_membership_history"
            " WHERE tenant = ? AND start_at <= ?"
            " AND (end_at IS NULL OR ? < end_at)"
            " ORDER BY start_at DESC, id DESC LIMIT 1",
            (tenant, at, at),
        ).fetchone()
        return None if row is None else row["group_id"]

    def _group_policy(
        self,
        conn: sqlite3.Connection,
        group_id: str,
        at: float,
        *,
        chain: tuple[str, ...] = (),
        member_group_id: Optional[str] = None,
    ) -> Optional[EffectivePolicy]:
        """Walk the live parent chain until a group defines its own policy.

        A repeated group id on the chain is a cyclic inheritance graph: the
        walk is refused rather than looping forever.
        """
        if group_id in chain:
            raise PolicyDenied(
                f"cyclic budget group inheritance detected via {group_id!r}"
            )
        row = conn.execute(
            "SELECT * FROM budget_groups WHERE id = ?", (group_id,)
        ).fetchone()
        if row is None:
            return None
        chain = (*chain, group_id)
        if row["period_type"] is not None:
            return EffectivePolicy(
                tenant="",
                source=SOURCE_GROUP,
                source_id=row["id"],
                source_version=row["version"],
                period_type=row["period_type"],
                amount=float(row["amount"]),
                alert_thresholds=tuple(json.loads(row["alert_thresholds"])),
                over_policy=row["over_policy"],
                resolved_at=at,
                group_id=row["id"],
                member_group_id=member_group_id,
            )
        if row["parent_id"] is None:
            return None
        return self._group_policy(
            conn, row["parent_id"], at,
            chain=chain, member_group_id=member_group_id,
        )

    def _group_policy_as_of(
        self,
        conn: sqlite3.Connection,
        group_id: str,
        at: float,
        *,
        chain: tuple[str, ...] = (),
        member_group_id: Optional[str] = None,
    ) -> Optional[EffectivePolicy]:
        """Same walk, but each group is read at its revision current at ``at``."""
        if group_id in chain:
            raise PolicyDenied(
                f"cyclic budget group inheritance detected via {group_id!r}"
            )
        row = conn.execute(
            "SELECT payload FROM budget_group_revisions"
            " WHERE group_id = ? AND ts <= ? AND action != 'deleted'"
            " ORDER BY version DESC LIMIT 1",
            (group_id, at),
        ).fetchone()
        if row is None:
            return None
        state = json.loads(row["payload"])
        chain = (*chain, group_id)
        if state.get("period_type") is not None:
            return EffectivePolicy(
                tenant="",
                source=SOURCE_GROUP,
                source_id=state["id"],
                source_version=state["version"],
                period_type=state["period_type"],
                amount=float(state["amount"]),
                alert_thresholds=tuple(state["alert_thresholds"]),
                over_policy=state["over_policy"],
                resolved_at=at,
                group_id=state["id"],
                member_group_id=member_group_id,
            )
        parent_id = state.get("parent_id")
        if parent_id is None:
            return None
        return self._group_policy_as_of(
            conn, parent_id, at,
            chain=chain, member_group_id=member_group_id,
        )

    def _policy_from_override(
        self, row: sqlite3.Row, at: float
    ) -> EffectivePolicy:
        return EffectivePolicy(
            tenant=row["tenant"],
            source=SOURCE_OVERRIDE,
            source_id=row["id"],
            source_version=row["version"],
            period_type=row["period_type"],
            amount=float(row["amount"]),
            alert_thresholds=tuple(json.loads(row["alert_thresholds"])),
            over_policy=row["over_policy"],
            resolved_at=at,
            override_id=row["id"],
            override_version=row["version"],
            window_start=row["window_start"],
            window_end=row["window_end"],
        )

    def _resolve_policy(
        self, tenant: str, at: float, *, historical: bool = False
    ) -> Optional[EffectivePolicy]:
        """Effective policy chain at time ``at``.

        Precedence: approved active override, then the tenant's dedicated
        budget, then the group default inherited through the member's group
        (and its parent chain). ``historical=True`` reconstructs memberships,
        overrides and group revisions exactly as they were at ``at``.
        """
        conn = self._conn
        if historical:
            ov = self._active_override_as_of(conn, tenant, at)
        else:
            ov = self._active_override(conn, tenant, at)
        if ov is not None:
            return self._policy_from_override(ov, at)

        budget = conn.execute(
            "SELECT * FROM budgets WHERE tenant = ?", (tenant,)
        ).fetchone()
        # Dedicated budgets are not version-historied; as in the rest of the
        # system the current row represents the tenant-specific policy.
        if budget is not None:
            return EffectivePolicy(
                tenant=tenant,
                source=SOURCE_TENANT,
                source_id=tenant,
                source_version=budget["version"],
                period_type=budget["period_type"],
                amount=float(budget["amount"]),
                alert_thresholds=tuple(json.loads(budget["alert_thresholds"])),
                over_policy=budget["over_policy"],
                resolved_at=at,
            )

        if historical:
            group_id = self._member_group_as_of(conn, tenant, at)
            policy = (
                self._group_policy_as_of(
                    conn, group_id, at, member_group_id=group_id
                )
                if group_id is not None
                else None
            )
        else:
            group_id = self._member_group(conn, tenant)
            policy = (
                self._group_policy(
                    conn, group_id, at, member_group_id=group_id
                )
                if group_id is not None
                else None
            )
        if policy is None:
            return None
        policy = dataclasses_replace(
            policy, tenant=tenant, resolved_at=at,
        )
        return policy

    # -- per-period policy snapshots ------------------------------------------

    def _get_snapshot(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        period_type: str,
        period_started_at: float,
    ) -> Optional[sqlite3.Row]:
        return conn.execute(
            "SELECT * FROM budget_policy_snapshots"
            " WHERE period_type = ? AND period_start = ? AND tenant = ?",
            (period_type, period_started_at, tenant),
        ).fetchone()

    @staticmethod
    def _policy_from_snapshot(row: sqlite3.Row, at: float) -> EffectivePolicy:
        return EffectivePolicy(
            tenant=row["tenant"],
            source=row["source"],
            source_id=row["source_id"],
            source_version=row["source_version"],
            period_type=row["period_type"],
            amount=float(row["amount"]),
            alert_thresholds=tuple(json.loads(row["alert_thresholds"])),
            over_policy=row["over_policy"],
            resolved_at=at,
            override_id=row["source_id"] if row["source"] == SOURCE_OVERRIDE
            else None,
            override_version=row["source_version"]
            if row["source"] == SOURCE_OVERRIDE
            else None,
            group_id=row["source_id"] if row["source"] == SOURCE_GROUP else None,
            member_group_id=row["source_id"]
            if row["source"] == SOURCE_GROUP
            else None,
        )

    def _upsert_snapshot(
        self,
        conn: sqlite3.Connection,
        policy: EffectivePolicy,
        period_started_at: float,
        *,
        frozen: bool,
        now: float,
    ) -> None:
        conn.execute(
            "INSERT INTO budget_policy_snapshots"
            " (period_type, period_start, tenant, source, source_id,"
            "  source_version, amount, alert_thresholds, over_policy, frozen,"
            "  created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(period_type, period_start, tenant) DO UPDATE SET"
            "  source=excluded.source, source_id=excluded.source_id,"
            "  source_version=excluded.source_version, amount=excluded.amount,"
            "  alert_thresholds=excluded.alert_thresholds,"
            "  over_policy=excluded.over_policy, frozen=excluded.frozen,"
            "  updated_at=excluded.updated_at",
            (
                policy.period_type, period_started_at, policy.tenant,
                policy.source, policy.source_id, policy.source_version,
                policy.amount, json.dumps(list(policy.alert_thresholds)),
                policy.over_policy, 1 if frozen else 0, now, now,
            ),
        )

    def _materialize_period_policy(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        event_time: float,
        now: float,
    ) -> Optional[EffectivePolicy]:
        """Return the policy governing ``event_time``'s period, persisting it.

        - open period: follow live policy; the row is refreshed (unfrozen) on
          every event so immediate re-resolution always shows the current
          source/version;
        - closed period: the first observation resolves the policy as it was
          an instant before the period boundary and freezes it; every later
          observation reuses the frozen row, so group edits, migrations and
          override changes never rewrite history.
        """
        live = self._resolve_policy(tenant, now)
        if live is None:
            # Even with no current policy, a historical policy may have been
            # in force at the period boundary (the tenant was later
            # detached); resolve it below before deciding there is nothing.
            ptype = PERIOD_DAY
            pstart = period_start(event_time, ptype)
            open_start = period_start(now, ptype)
            if pstart == open_start:
                return None
        else:
            ptype = live.period_type
            pstart = period_start(event_time, ptype)
            open_start = period_start(now, ptype)
        existing = self._get_snapshot(conn, tenant, ptype, pstart)
        if existing is not None and existing["frozen"]:
            return self._policy_from_snapshot(existing, now)

        if pstart == open_start:
            # Open period: always track the live chain.
            policy, frozen, ptype_out = live, False, ptype
        else:
            # The historical policy is the one in force when the period
            # *closed* (an instant before the next period began): a policy
            # adopted during the period governs it at its boundary, while
            # group edits, member migrations or overrides that happened only
            # after it closed are invisible to it. The first such
            # observation freezes it forever.
            boundary = next_period_start(pstart, ptype) - 1e-6
            policy = self._resolve_policy(tenant, boundary, historical=True)
            if policy is None:
                # Nothing existed at the boundary. Dedicated budgets have no
                # version history and retroactive evaluation elsewhere uses
                # the current configuration; mirror that: freeze the live
                # policy (if any) as the period's policy.
                if live is None:
                    return None
                policy = live
            frozen = True
            ptype_out = policy.period_type
            if ptype_out != ptype:
                ptype = ptype_out
                pstart = period_start(event_time, ptype)
                deeper = self._get_snapshot(conn, tenant, ptype, pstart)
                if deeper is not None and deeper["frozen"]:
                    return self._policy_from_snapshot(deeper, now)
        self._upsert_snapshot(conn, policy, pstart, frozen=frozen, now=now)
        return dataclasses_replace(policy, period_type=ptype)

    def list_policy_snapshots(
        self,
        *,
        tenant: Optional[str] = None,
        period_type: Optional[str] = None,
        limit: int = 500,
    ) -> list[dict]:
        sql = "SELECT * FROM budget_policy_snapshots WHERE 1=1"
        args: list = []
        if tenant is not None:
            sql += " AND tenant = ?"
            args.append(tenant.strip().lower())
        if period_type is not None:
            sql += " AND period_type = ?"
            args.append(period_type)
        sql += " ORDER BY period_start DESC, tenant LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [self._snapshot_row(r) for r in rows]

    # -- groups: control plane ------------------------------------------------

    def _get_group_row(self, group_id: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM budget_groups WHERE id = ?", (group_id,)
        ).fetchone()

    def _group_persisted_dict(self, row: sqlite3.Row) -> dict:
        """Full state archived into budget_group_revisions."""
        return self._group_row(row)

    def _would_cycle(
        self, conn: sqlite3.Connection, group_id: str, parent_id: Optional[str]
    ) -> bool:
        seen = {group_id}
        cur = parent_id
        while cur is not None:
            if cur in seen:
                return True
            seen.add(cur)
            row = conn.execute(
                "SELECT parent_id FROM budget_groups WHERE id = ?", (cur,)
            ).fetchone()
            if row is None:
                return False
            cur = row["parent_id"]
        return False

    def upsert_group(self, spec: BudgetGroupSpec, *, actor: str) -> tuple[dict, bool]:
        """Create or update a budget group (optimistically versioned)."""
        if spec.id is None:
            raise MeteringValidationError("group id is required")
        group_id = spec.id
        now = self._clock()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._get_group_row(group_id)
                created = row is None
                if row is None:
                    if spec.expected_version is not None:
                        self._conn.rollback()
                        raise MeteringConflict(
                            f"budget group {group_id!r} does not exist; "
                            "expected_version can only be sent on update"
                        )
                    if spec.parent_id is not None and self._get_group_row(
                        spec.parent_id
                    ) is None:
                        self._conn.rollback()
                        raise MeteringNotFound(
                            f"parent group {spec.parent_id!r} does not exist"
                        )
                    if not spec.has_policy() and spec.parent_id is None:
                        self._conn.rollback()
                        raise MeteringValidationError(
                            "group must define a policy or set parent_id to "
                            "inherit one"
                        )
                    if spec.parent_id == group_id or self._would_cycle(
                        self._conn, group_id, spec.parent_id
                    ):
                        self._conn.rollback()
                        self._audit_policy_denied(
                            "group_upsert",
                            "cyclic_inheritance",
                            group_id=group_id,
                            parent_id=spec.parent_id,
                            actor=actor,
                        )
                        raise PolicyDenied(
                            "refusing to create a cyclic group inheritance chain"
                        )
                    version = 1
                    self._conn.execute(
                        "INSERT INTO budget_groups"
                        " (id, description, parent_id, period_type, amount,"
                        "  alert_thresholds, over_policy, version, created_at,"
                        "  updated_at, created_by, updated_by)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            group_id, spec.description, spec.parent_id,
                            spec.period_type, spec.amount,
                            json.dumps(spec.alert_thresholds)
                            if spec.alert_thresholds is not None
                            else None,
                            spec.over_policy, version, now, now, actor, actor,
                        ),
                    )
                else:
                    if (
                        spec.expected_version is not None
                        and spec.expected_version != row["version"]
                    ):
                        self._conn.rollback()
                        raise MeteringConflict(
                            f"optimistic concurrency check failed for group "
                            f"{group_id!r}: expected version "
                            f"{spec.expected_version}, current {row['version']}"
                        )
                    new_parent = (
                        spec.parent_id
                        if spec.parent_id is not None or spec.has_policy()
                        else row["parent_id"]
                    )
                    if new_parent is not None and new_parent != row["parent_id"]:
                        if self._get_group_row(new_parent) is None:
                            self._conn.rollback()
                            raise MeteringNotFound(
                                f"parent group {new_parent!r} does not exist"
                            )
                        if new_parent == group_id or self._would_cycle(
                            self._conn, group_id, new_parent
                        ):
                            self._conn.rollback()
                            self._audit_policy_denied(
                                "group_upsert",
                                "cyclic_inheritance",
                                group_id=group_id,
                                parent_id=new_parent,
                                actor=actor,
                            )
                            raise PolicyDenied(
                                "refusing to create a cyclic group inheritance "
                                "chain"
                            )
                    if not spec.has_policy() and new_parent is None:
                        self._conn.rollback()
                        raise MeteringValidationError(
                            "group must define a policy or inherit one via "
                            "parent_id"
                        )
                    old = self._group_row(row)
                    unchanged = (
                        old["description"] == spec.description
                        and old["parent_id"] == new_parent
                        and old["period_type"] == spec.period_type
                        and _amounts_equal(old["amount"], spec.amount)
                        and old["alert_thresholds"] == spec.alert_thresholds
                        and old["over_policy"] == spec.over_policy
                    )
                    if unchanged:
                        self._conn.rollback()
                        return old, False
                    version = row["version"] + 1
                    self._conn.execute(
                        "UPDATE budget_groups SET description=?, parent_id=?,"
                        " period_type=?, amount=?, alert_thresholds=?,"
                        " over_policy=?, version=?, updated_at=?, updated_by=?"
                        " WHERE id=?",
                        (
                            spec.description, new_parent,
                            spec.period_type, spec.amount,
                            json.dumps(spec.alert_thresholds)
                            if spec.alert_thresholds is not None
                            else None,
                            spec.over_policy, version, now, actor, group_id,
                        ),
                    )
                new_row = self._get_group_row(group_id)
                self._conn.execute(
                    "INSERT INTO budget_group_revisions"
                    " (group_id, version, action, payload, actor, ts)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        group_id, version,
                        "created" if created else "updated",
                        json.dumps(self._group_persisted_dict(new_row),
                                   sort_keys=True),
                        actor, now,
                    ),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            result = self._group_row(self._get_group_row(group_id))
            self._audit.record(
                "budget_group",
                {
                    "action": "created" if created else "updated",
                    "group_id": group_id,
                    "actor": actor,
                    "version": version,
                    "policy": result["period_type"] is not None,
                    "parent_id": result["parent_id"],
                },
            )
            return result, created

    def delete_group(self, group_id: str, *, actor: str) -> None:
        group_id = (group_id or "").strip().lower()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._get_group_row(group_id)
                if row is None:
                    self._conn.rollback()
                    raise MeteringNotFound(
                        f"budget group {group_id!r} does not exist"
                    )
                members = self._conn.execute(
                    "SELECT COUNT(1) AS n FROM budget_group_members"
                    " WHERE group_id = ?",
                    (group_id,),
                ).fetchone()["n"]
                children = self._conn.execute(
                    "SELECT COUNT(1) AS n FROM budget_groups WHERE parent_id = ?",
                    (group_id,),
                ).fetchone()["n"]
                if members or children:
                    self._conn.rollback()
                    reason = (
                        f"has {members} member(s)"
                        if members
                        else f"has {children} child group(s)"
                    )
                    self._audit_policy_denied(
                        "group_delete", "group_in_use",
                        group_id=group_id, members=members,
                        children=children, actor=actor,
                    )
                    raise PolicyDenied(
                        f"cannot delete budget group {group_id!r}: {reason}"
                    )
                self._conn.execute(
                    "DELETE FROM budget_groups WHERE id = ?", (group_id,)
                )
                self._conn.execute(
                    "INSERT INTO budget_group_revisions"
                    " (group_id, version, action, payload, actor, ts)"
                    " VALUES (?, ?, 'deleted', ?, ?, ?)",
                    (
                        group_id, row["version"] + 1,
                        json.dumps(self._group_row(row), sort_keys=True),
                        actor, self._clock(),
                    ),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            self._audit.record(
                "budget_group",
                {
                    "action": "deleted",
                    "group_id": group_id,
                    "actor": actor,
                },
            )

    def get_group(self, group_id: str) -> dict:
        group_id = (group_id or "").strip().lower()
        with self._lock:
            row = self._get_group_row(group_id)
            if row is None:
                raise MeteringNotFound(
                    f"budget group {group_id!r} does not exist"
                )
            group = self._group_row(row)
        group["members"] = self.list_members(group_id)
        group["member_count"] = len(group["members"])
        return group

    def list_groups(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM budget_groups ORDER BY id"
            ).fetchall()
            groups = [self._group_row(r) for r in rows]
            counts = {
                r["group_id"]: r["n"]
                for r in self._conn.execute(
                    "SELECT group_id, COUNT(1) AS n FROM budget_group_members"
                    " GROUP BY group_id"
                )
            }
        for g in groups:
            g["member_count"] = counts.get(g["id"], 0)
        return groups

    # -- membership -----------------------------------------------------------

    def list_members(self, group_id: str) -> list[dict]:
        group_id = (group_id or "").strip().lower()
        with self._lock:
            rows = self._conn.execute(
                "SELECT tenant, group_id, version, added_at, added_by"
                " FROM budget_group_members WHERE group_id = ?"
                " ORDER BY tenant",
                (group_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_membership(self, tenant: str) -> Optional[dict]:
        tenant = (tenant or "").strip().lower()
        with self._lock:
            row = self._conn.execute(
                "SELECT tenant, group_id, version, added_at, added_by"
                " FROM budget_group_members WHERE tenant = ?",
                (tenant,),
            ).fetchone()
            return None if row is None else dict(row)

    def list_memberships(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT tenant, group_id, version, added_at, added_by"
                " FROM budget_group_members ORDER BY group_id, tenant"
            ).fetchall()
            return [dict(r) for r in rows]

    def move_member(
        self,
        tenant: str,
        dest_group_id: Optional[str],
        *,
        actor: str,
        expected_version: Optional[int] = None,
    ) -> tuple[Optional[dict], bool]:
        """Assign a tenant to a group (or detach with ``dest_group_id=None``).

        The membership row's version is the optimistic-concurrency token, so
        two concurrent migrations of the same tenant cannot silently
        overwrite each other: the loser is rejected with a conflict.
        """
        tenant = (tenant or "").strip().lower()
        now = self._clock()
        with self._lock:
            # Read-then-write under the process lock; the conditional UPDATE
            # additionally re-checks the version after the SQLite write lock
            # is taken, so two migrations that both observed version N
            # cannot overwrite each other: the loser's UPDATE matches no row.
            row = self._conn.execute(
                "SELECT * FROM budget_group_members WHERE tenant = ?",
                (tenant,),
            ).fetchone()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if dest_group_id is not None and self._get_group_row(
                    dest_group_id
                ) is None:
                    self._conn.rollback()
                    raise MeteringNotFound(
                        f"budget group {dest_group_id!r} does not exist"
                    )
                if row is None:
                    if dest_group_id is None:
                        self._conn.rollback()
                        return None, False
                    if expected_version is not None and expected_version != 0:
                        self._conn.rollback()
                        raise MeteringConflict(
                            f"tenant {tenant!r} is not a member of any group; "
                            "expected_version must be 0 (or omitted) to assign"
                        )
                    try:
                        self._conn.execute(
                            "INSERT INTO budget_group_members"
                            " (tenant, group_id, version, added_at, added_by)"
                            " VALUES (?, ?, 1, ?, ?)",
                            (tenant, dest_group_id, now, actor),
                        )
                    except sqlite3.IntegrityError as exc:
                        self._conn.rollback()
                        self._audit_policy_denied(
                            "member_move",
                            "concurrent_migration",
                            tenant=tenant, actor=actor,
                        )
                        raise MeteringConflict(
                            f"concurrent membership insert for tenant {tenant!r}"
                        ) from exc
                    self._conn.execute(
                        "INSERT INTO budget_group_membership_history"
                        " (tenant, group_id, start_at, end_at, moved_by)"
                        " VALUES (?, ?, ?, NULL, ?)",
                        (tenant, dest_group_id, now, actor),
                    )
                    action, version = "member_added", 1
                else:
                    if (
                        expected_version is not None
                        and expected_version != row["version"]
                    ):
                        self._conn.rollback()
                        self._audit_policy_denied(
                            "member_move",
                            "concurrent_migration",
                            tenant=tenant,
                            expected_version=expected_version,
                            current_version=row["version"],
                            actor=actor,
                        )
                        raise MeteringConflict(
                            f"optimistic concurrency check failed for membership "
                            f"{tenant!r}: expected version {expected_version}, "
                            f"current {row['version']}"
                        )
                    if dest_group_id is None:
                        self._conn.rollback()
                        return self.remove_member(
                            tenant, actor=actor,
                            expected_version=expected_version,
                        )
                    if row["group_id"] == dest_group_id:
                        self._conn.rollback()
                        return dict(row), False
                    version = row["version"] + 1
                    if expected_version is not None:
                        cur = self._conn.execute(
                            "UPDATE budget_group_members SET group_id=?,"
                            " version=?, added_at=?, added_by=?"
                            " WHERE tenant=? AND version=?",
                            (dest_group_id, version, now, actor,
                             tenant, expected_version),
                        )
                        if cur.rowcount == 0:
                            self._conn.rollback()
                            current = self._conn.execute(
                                "SELECT version FROM budget_group_members"
                                " WHERE tenant=?", (tenant,)
                            ).fetchone()
                            self._audit_policy_denied(
                                "member_move",
                                "concurrent_migration",
                                tenant=tenant,
                                expected_version=expected_version,
                                current_version=(
                                    current["version"] if current else None
                                ),
                                actor=actor,
                            )
                            raise MeteringConflict(
                                f"concurrent membership migration for tenant "
                                f"{tenant!r}: expected version "
                                f"{expected_version}"
                            )
                    else:
                        self._conn.execute(
                            "UPDATE budget_group_members SET group_id=?,"
                            " version=?, added_at=?, added_by=? WHERE tenant=?",
                            (dest_group_id, version, now, actor, tenant),
                        )
                    self._conn.execute(
                        "UPDATE budget_group_membership_history SET end_at=?, "
                        "moved_by=? WHERE tenant=? AND end_at IS NULL",
                        (now, actor, tenant),
                    )
                    self._conn.execute(
                        "INSERT INTO budget_group_membership_history"
                        " (tenant, group_id, start_at, end_at, moved_by)"
                        " VALUES (?, ?, ?, NULL, ?)",
                        (tenant, dest_group_id, now, actor),
                    )
                    action = "member_moved"
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            new_row = self._conn.execute(
                "SELECT tenant, group_id, version, added_at, added_by"
                " FROM budget_group_members WHERE tenant=?",
                (tenant,),
            ).fetchone()
            membership = None if new_row is None else dict(new_row)
            self._audit.record(
                "budget_membership",
                {
                    "action": action,
                    "tenant": tenant,
                    "group_id": dest_group_id,
                    "actor": actor,
                    "version": version,
                },
            )
            return membership, True

    def remove_member(
        self,
        tenant: str,
        *,
        actor: str,
        expected_version: Optional[int] = None,
    ) -> tuple[Optional[dict], bool]:
        tenant = (tenant or "").strip().lower()
        now = self._clock()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT * FROM budget_group_members WHERE tenant = ?",
                    (tenant,),
                ).fetchone()
                if row is None:
                    self._conn.rollback()
                    return None, False
                if (
                    expected_version is not None
                    and expected_version != row["version"]
                ):
                    self._conn.rollback()
                    self._audit_policy_denied(
                        "member_remove",
                        "concurrent_migration",
                        tenant=tenant,
                        expected_version=expected_version,
                        current_version=row["version"],
                        actor=actor,
                    )
                    raise MeteringConflict(
                        f"optimistic concurrency check failed for membership "
                        f"{tenant!r}: expected version {expected_version}, "
                        f"current {row['version']}"
                    )
                old_group = row["group_id"]
                version = row["version"] + 1
                self._conn.execute(
                    "DELETE FROM budget_group_members WHERE tenant=?", (tenant,)
                )
                self._conn.execute(
                    "UPDATE budget_group_membership_history SET end_at=?, "
                    "moved_by=? WHERE tenant=? AND end_at IS NULL",
                    (now, actor, tenant),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            self._audit.record(
                "budget_membership",
                {
                    "action": "member_removed",
                    "tenant": tenant,
                    "group_id": old_group,
                    "actor": actor,
                    "version": version,
                },
            )
            return None, True

    def membership_history(self, tenant: str) -> list[dict]:
        tenant = (tenant or "").strip().lower()
        with self._lock:
            rows = self._conn.execute(
                "SELECT tenant, group_id, start_at, end_at, moved_by"
                " FROM budget_group_membership_history"
                " WHERE tenant=? ORDER BY start_at",
                (tenant,),
            ).fetchall()
            return [dict(r) for r in rows]

    # -- temporary overrides --------------------------------------------------

    def _get_override_row(self, override_id: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM budget_overrides WHERE id = ?", (override_id,)
        ).fetchone()

    def _override_overlaps(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        start: float,
        end: float,
        *,
        statuses: tuple[str, ...],
        exclude_id: Optional[str] = None,
    ) -> Optional[sqlite3.Row]:
        sql = (
            "SELECT * FROM budget_overrides"
            " WHERE tenant = ? AND status IN ("
            + ",".join("?" for _ in statuses)
            + ") AND window_start < ? AND ? < window_end"
        )
        args: list = [tenant, *statuses, end, start]
        if exclude_id is not None:
            sql += " AND id != ?"
            args.append(exclude_id)
        sql += " ORDER BY window_start LIMIT 1"
        return conn.execute(sql, args).fetchone()

    def _expire_overdue_overrides(self, now: Optional[float] = None) -> list[str]:
        """Lapse approved overrides whose windows have closed.

        Detected, persisted and audited the first moment anyone looks; the
        status flip takes effect for the resolution chain immediately.
        """
        now = self._clock() if now is None else now
        expired: list[dict] = []
        with self._lock:
            in_txn = bool(self._conn.in_transaction)
            if not in_txn:
                self._conn.execute("BEGIN IMMEDIATE")
            try:
                rows = self._conn.execute(
                    "SELECT * FROM budget_overrides"
                    " WHERE status = 'approved' AND window_end <= ?",
                    (now,),
                ).fetchall()
                for row in rows:
                    version = row["version"] + 1
                    self._conn.execute(
                        "UPDATE budget_overrides SET status='expired',"
                        " version=?, updated_at=? WHERE id=?",
                        (version, now, row["id"]),
                    )
                    expired.append(
                        {**self._override_row(row), "version": version}
                    )
                if not in_txn:
                    self._conn.commit()
            except Exception:
                if not in_txn:
                    self._conn.rollback()
                raise
        for ov in expired:
            self._audit.record(
                "budget_override",
                {
                    "action": "expired",
                    "override_id": ov["id"],
                    "tenant": ov["tenant"],
                    "actor": "system",
                    "window_start": ov["window_start"],
                    "window_end": ov["window_end"],
                    "version": ov["version"],
                },
            )
        return [ov["id"] for ov in expired]

    def request_override(
        self, spec: OverrideSpec, *, tenant: str, actor: str
    ) -> dict:
        tenant = (tenant or "").strip().lower()
        now = self._clock()
        if spec.window_end <= now:
            self._audit_policy_denied(
                "override_request", "window_elapsed",
                tenant=tenant, window_end=spec.window_end, actor=actor,
            )
            raise PolicyDenied(
                "cannot request an override whose window has already ended"
            )
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                clash = self._override_overlaps(
                    self._conn, tenant, spec.window_start, spec.window_end,
                    statuses=("pending", "approved"),
                )
                if clash is not None:
                    self._conn.rollback()
                    self._audit_policy_denied(
                        "override_request", "window_overlap",
                        tenant=tenant,
                        window_start=spec.window_start,
                        window_end=spec.window_end,
                        conflicting_override=clash["id"],
                        conflicting_status=clash["status"],
                        actor=actor,
                    )
                    raise PolicyDenied(
                        f"override window overlaps "
                        f"{clash['status']} override {clash['id']!r}"
                    )
                oid = self._new_entity_id("bovr_", "budget_overrides")
                self._conn.execute(
                    "INSERT INTO budget_overrides"
                    " (id, tenant, period_type, amount, alert_thresholds,"
                    "  over_policy, window_start, window_end, status,"
                    "  requested_by, requested_at, version, created_at,"
                    "  updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, 1, ?, ?)",
                    (
                        oid, tenant, spec.period_type, spec.amount,
                        json.dumps(spec.alert_thresholds), spec.over_policy,
                        spec.window_start, spec.window_end,
                        actor, now, now, now,
                    ),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            row = self._override_row(self._get_override_row(oid))
            self._audit.record(
                "budget_override",
                {
                    "action": "requested",
                    "override_id": oid,
                    "tenant": tenant,
                    "actor": actor,
                    "reason": spec.reason,
                    "window_start": spec.window_start,
                    "window_end": spec.window_end,
                    "policy": {
                        "period_type": spec.period_type,
                        "amount": spec.amount,
                        "alert_thresholds": spec.alert_thresholds,
                        "over_policy": spec.over_policy,
                    },
                    "version": 1,
                },
            )
            return row

    def decide_override(
        self,
        override_id: str,
        approve: bool,
        *,
        actor: str,
        comment: Optional[str] = None,
        expected_version: Optional[int] = None,
    ) -> dict:
        """Approve/reject a pending override; a different admin must decide."""
        now = self._clock()
        with self._lock:
            self._expire_overdue_overrides(now)
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._get_override_row(override_id)
                if row is None:
                    self._conn.rollback()
                    raise MeteringNotFound(
                        f"budget override {override_id!r} does not exist"
                    )
                if actor not in ("bootstrap", "open") and actor == row["requested_by"]:
                    self._conn.rollback()
                    self._audit_policy_denied(
                        "override_decide", "self_approval",
                        override_id=override_id, tenant=row["tenant"],
                        actor=actor, requested_by=row["requested_by"],
                    )
                    raise PolicyDenied(
                        "an override must be approved by a different "
                        "administrator than its requester"
                    )
                if row["status"] != "pending":
                    self._conn.rollback()
                    self._audit_policy_denied(
                        "override_decide",
                        f"not_pending_{row['status']}",
                        override_id=override_id, tenant=row["tenant"],
                        actor=actor, status=row["status"],
                    )
                    raise PolicyDenied(
                        f"override {override_id!r} is already {row['status']}; "
                        "only a pending request can be decided"
                    )
                if (
                    expected_version is not None
                    and expected_version != row["version"]
                ):
                    self._conn.rollback()
                    raise MeteringConflict(
                        f"optimistic concurrency check failed for override "
                        f"{override_id!r}: expected version {expected_version}, "
                        f"current {row['version']}"
                    )
                if row["window_end"] <= now:
                    self._conn.rollback()
                    self._audit_policy_denied(
                        "override_decide", "window_elapsed",
                        override_id=override_id, tenant=row["tenant"],
                        actor=actor, window_end=row["window_end"],
                    )
                    raise PolicyDenied(
                        f"override {override_id!r} window has already ended"
                    )
                if approve:
                    clash = self._override_overlaps(
                        self._conn, row["tenant"],
                        row["window_start"], row["window_end"],
                        statuses=("approved",), exclude_id=override_id,
                    )
                    if clash is not None:
                        self._conn.rollback()
                        self._audit_policy_denied(
                            "override_decide", "window_overlap",
                            override_id=override_id, tenant=row["tenant"],
                            actor=actor,
                            conflicting_override=clash["id"],
                        )
                        raise PolicyDenied(
                            f"approved window overlaps override "
                            f"{clash['id']!r}"
                        )
                version = row["version"] + 1
                status = "approved" if approve else "rejected"
                self._conn.execute(
                    "UPDATE budget_overrides SET status=?, decided_by=?,"
                    " decided_at=?, decision_comment=?,"
                    " approved_at=?, version=?, updated_at=? WHERE id=?",
                    (
                        status, actor, now, comment,
                        now if approve else None,
                        version, now, override_id,
                    ),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            result = self._override_row(self._get_override_row(override_id))
            self._audit.record(
                "budget_override",
                {
                    "action": "approved" if approve else "rejected",
                    "override_id": override_id,
                    "tenant": result["tenant"],
                    "actor": actor,
                    "requested_by": result["requested_by"],
                    "comment": comment,
                    "window_start": result["window_start"],
                    "window_end": result["window_end"],
                    "version": version,
                },
            )
            return result

    def revoke_override(
        self,
        override_id: str,
        *,
        actor: str,
        expected_version: Optional[int] = None,
    ) -> dict:
        """Revoke an active override; the policy reverts on the next request."""
        now = self._clock()
        with self._lock:
            self._expire_overdue_overrides(now)
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._get_override_row(override_id)
                if row is None:
                    self._conn.rollback()
                    raise MeteringNotFound(
                        f"budget override {override_id!r} does not exist"
                    )
                if row["status"] != "approved":
                    self._conn.rollback()
                    self._audit_policy_denied(
                        "override_revoke",
                        f"not_active_{row['status']}",
                        override_id=override_id, tenant=row["tenant"],
                        actor=actor, status=row["status"],
                    )
                    raise PolicyDenied(
                        f"override {override_id!r} is {row['status']}; only an "
                        "active (approved and unexpired) override can be revoked"
                    )
                if row["window_end"] <= now:
                    self._conn.rollback()
                    self._audit_policy_denied(
                        "override_revoke", "window_elapsed",
                        override_id=override_id, tenant=row["tenant"],
                        actor=actor,
                    )
                    raise PolicyDenied(
                        f"override {override_id!r} window has already ended"
                    )
                if (
                    expected_version is not None
                    and expected_version != row["version"]
                ):
                    self._conn.rollback()
                    raise MeteringConflict(
                        f"optimistic concurrency check failed for override "
                        f"{override_id!r}: expected version {expected_version}, "
                        f"current {row['version']}"
                    )
                version = row["version"] + 1
                self._conn.execute(
                    "UPDATE budget_overrides SET status='revoked',"
                    " revoked_by=?, revoked_at=?, version=?, updated_at=?"
                    " WHERE id=?",
                    (actor, now, version, now, override_id),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            result = self._override_row(self._get_override_row(override_id))
            self._audit.record(
                "budget_override",
                {
                    "action": "revoked",
                    "override_id": override_id,
                    "tenant": result["tenant"],
                    "actor": actor,
                    "requested_by": result["requested_by"],
                    "version": version,
                },
            )
            return result

    def get_override(self, override_id: str) -> dict:
        with self._lock:
            self._expire_overdue_overrides()
            row = self._get_override_row(override_id)
            if row is None:
                raise MeteringNotFound(
                    f"budget override {override_id!r} does not exist"
                )
            return self._override_row(row)

    def list_overrides(
        self,
        *,
        tenant: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        if status is not None and status not in OVERRIDE_STATUSES:
            raise MeteringValidationError(
                f"status must be one of {OVERRIDE_STATUSES}"
            )
        sql = "SELECT * FROM budget_overrides WHERE 1=1"
        args: list = []
        if tenant is not None:
            sql += " AND tenant = ?"
            args.append(tenant.strip().lower())
        if status is not None:
            sql += " AND status = ?"
            args.append(status)
        sql += " ORDER BY requested_at DESC, id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            self._expire_overdue_overrides()
            rows = self._conn.execute(sql, args).fetchall()
        return [self._override_row(r) for r in rows]

    # -- aggregates -----------------------------------------------------------

    @staticmethod
    def _bump_aggregate(
        period_type: str,
        start: float,
        tenant: str,
        client_key: str,
        rule_scope: str,
        quantity: float,
        result: str,
        now: float,
        conn: sqlite3.Connection,
    ) -> None:
        """Incrementally fold one event into both aggregate periods.

        Executed inside the caller's transaction; safe to call while holding
        the store lock because the lock is reentrant.
        """
        for ptype in PERIOD_TYPES:
            pstart = start if ptype == period_type else period_start(start, ptype)
            conn.execute(
                "INSERT INTO usage_aggregates"
                " (period_type, period_start, tenant, client_key, rule_scope,"
                "  events, quantity, allowed_qty, rejected_qty, degraded_qty,"
                "  updated_at)"
                " VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)"
                " ON CONFLICT(period_type, period_start, tenant, client_key,"
                "               rule_scope) DO UPDATE SET"
                "  events = events + 1,"
                "  quantity = quantity + excluded.quantity,"
                "  allowed_qty = allowed_qty + excluded.allowed_qty,"
                "  rejected_qty = rejected_qty + excluded.rejected_qty,"
                "  degraded_qty = degraded_qty + excluded.degraded_qty,"
                "  updated_at = excluded.updated_at",
                (
                    ptype,
                    pstart,
                    tenant,
                    client_key,
                    rule_scope,
                    quantity,
                    quantity if result == RESULT_SERVED else 0.0,
                    quantity if result == RESULT_REJECTED else 0.0,
                    quantity if result == RESULT_DEGRADED else 0.0,
                    now,
                ),
            )

    def _period_used(self, tenant: str, start: float, period_type: str) -> float:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(quantity), 0) AS q"
            " FROM usage_aggregates"
            " WHERE period_type = ? AND period_start = ? AND tenant = ?",
            (period_type, start, tenant),
        ).fetchone()
        return float(row["q"])

    # -- immutable adjustments and the budget usage projection ---------------

    def _adjustment_delta(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        start: float,
        period_type: str,
        kind: str,
    ) -> float:
        """Net signed adjustment delta of one ledger kind for a period.

        ``normal`` deltas alter the open period's projection; ``retroactive``
        deltas only append traceable history to a closed period. A reverse
        row carries the negated quantity, so a plain SUM yields the net.
        """
        row = conn.execute(
            "SELECT COALESCE(SUM(quantity), 0) AS q FROM budget_adjustments"
            " WHERE period_type = ? AND period_start = ? AND tenant = ?"
            " AND kind = ?",
            (period_type, start, tenant, kind),
        ).fetchone()
        return float(row["q"])

    def _refresh_projection(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        start: float,
        period_type: str,
        now: float,
    ) -> None:
        """Upsert the period's materialized budget projection.

        Raw billed quantity is recomputed from the immutable aggregates and
        the normal adjustment delta from the immutable adjustment ledger, so
        a rebuild always converges; retroactive adjustments never enter the
        gate projection.
        """
        raw = self._period_used(tenant, start, period_type)
        delta = self._adjustment_delta(
            conn, tenant, start, period_type, "normal"
        )
        conn.execute(
            "INSERT INTO budget_usage_projections"
            " (period_type, period_start, tenant, raw_quantity,"
            "  adjustment_delta, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(period_type, period_start, tenant) DO UPDATE SET"
            "  raw_quantity=excluded.raw_quantity,"
            "  adjustment_delta=excluded.adjustment_delta,"
            "  updated_at=excluded.updated_at",
            (period_type, start, tenant, raw, delta, now),
        )

    def _period_usage(
        self,
        tenant: str,
        start: float,
        period_type: str,
        *,
        include_retroactive: bool = False,
    ) -> dict:
        """Raw, net-adjusted and retroactive usage for one period.

        The budget gate and threshold evaluation use ``adjusted``
        (raw + net normal delta); a retroactive-only view additionally
        includes closed-period retroactive adjustments, which exist solely
        to document corrected historical usage and never feed the gate.
        """
        conn = self._conn
        raw = self._period_used(tenant, start, period_type)
        normal = self._adjustment_delta(conn, tenant, start, period_type, "normal")
        retroactive = self._adjustment_delta(
            conn, tenant, start, period_type, "retroactive"
        )
        adjusted = raw + normal
        return {
            "raw": raw,
            "normal_adjustment": normal,
            "retroactive_adjustment": retroactive,
            "adjusted": adjusted,
            "adjusted_including_retroactive": (
                adjusted + retroactive if include_retroactive else adjusted
            ),
        }

    # -- alerts ---------------------------------------------------------------

    @staticmethod
    def _alert_row(row: sqlite3.Row) -> dict:
        keys = row.keys()
        raw_origin = row["policy_origin"] if "policy_origin" in keys else None
        origin = json.loads(raw_origin) if raw_origin else None
        return {
            "id": row["id"],
            "tenant": row["tenant"],
            "period_type": row["period_type"],
            "period_start": row["period_start"],
            "period": period_label(row["period_start"], row["period_type"]),
            "threshold": row["threshold"],
            "usage": row["usage"],
            "budget_amount": row["budget_amount"],
            "event_id": row["event_id"],
            "fired_at": row["fired_at"],
            "status": row["status"],
            "acknowledged_by": row["acknowledged_by"],
            "acknowledged_at": row["acknowledged_at"],
            "comment": row["comment"],
            "version": row["version"],
            "policy_origin": origin,
        }

    def _open_alerts(self, tenant: str, start: float, period_type: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM budget_alerts"
            " WHERE tenant = ? AND period_type = ? AND period_start = ?"
            " AND status = 'open' ORDER BY threshold",
            (tenant, period_type, start),
        ).fetchall()
        return [self._alert_row(r) for r in rows]

    def _evaluate_thresholds(
        self,
        *,
        tenant: str,
        period_type: str,
        amount: float,
        thresholds: list[float],
        start: float,
        used: float,
        event_id: Optional[str],
        fired_at: float,
        retroactive: bool,
        policy: Optional[EffectivePolicy] = None,
    ) -> list[dict]:
        """Create any not-yet-fired threshold alerts for one period.

        One open alert per (tenant, period, threshold); the UNIQUE constraint
        plus the lock make crossing a threshold exactly-once even under
        concurrent requests. Thresholds are evaluated against the *resolved*
        policy -- live for the open period, the frozen snapshot for a
        historical one. Runs inside the caller's transaction and only
        mutates the database; the caller writes the ``budget_alert`` audit
        records after the transaction commits.
        """
        created: list[dict] = []
        for threshold in thresholds:
            if used + 1e-9 < amount * threshold:
                continue
            alert_id = new_alert_id()
            try:
                self._conn.execute(
                    "INSERT INTO budget_alerts"
                    " (id, tenant, period_type, period_start, threshold, usage,"
                    "  budget_amount, event_id, fired_at, status, version,"
                    "  policy_origin)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 1, ?)",
                    (
                        alert_id, tenant, period_type, start, threshold, used,
                        amount, event_id, fired_at,
                        json.dumps(policy.origin(), sort_keys=True)
                        if policy is not None
                        else None,
                    ),
                )
            except sqlite3.IntegrityError:
                # Alert already exists for this (tenant, period, threshold).
                continue
            row = self._conn.execute(
                "SELECT * FROM budget_alerts WHERE id = ?", (alert_id,)
            ).fetchone()
            alert = self._alert_row(row)
            alert["retroactive"] = retroactive
            created.append(alert)
        return created

    def _audit_alert_fired(self, alert: dict) -> None:
        self._audit.record(
            "budget_alert",
            {
                "action": "fired",
                "alert_id": alert["id"],
                "tenant": alert["tenant"],
                "scope": "tenant",
                "period_type": alert["period_type"],
                "period_start": alert["period_start"],
                "period": alert["period"],
                "threshold": alert["threshold"],
                "usage": alert["usage"],
                "budget_amount": alert["budget_amount"],
                "event_id": alert["event_id"],
                "retroactive": alert.get("retroactive", False),
            },
            ts=alert["fired_at"] if alert.get("retroactive") else None,
        )

    # -- event ingestion (data plane + backfill) ------------------------------

    def record_event(
        self,
        *,
        tenant: str,
        client_key: str,
        name: str,
        region: str = "",
        labels_sig: str = "",
        rule_scope: str,
        rule_version: Optional[int],
        group_id: Optional[str],
        config_version: int,
        result: str,
        quantity: float = 1.0,
        degraded: bool = False,
        event_time: Optional[float] = None,
        event_id: Optional[str] = None,
        source: str = "live",
        actor: Optional[str] = None,
    ) -> dict:
        """Archive one usage event idempotently and fold it into aggregates.

        Returns the stored event (``"duplicate": True`` when the event id was
        already known, in which case nothing is billed again).
        """
        now = self._clock()
        event_time = now if event_time is None else event_time
        if event_time != event_time or event_time in (float("inf"), float("-inf")):
            raise MeteringValidationError("event_time must be a finite epoch second")
        if quantity != quantity or quantity == float("inf") or quantity < 0:
            raise MeteringValidationError("quantity must be a finite non-negative number")
        if result not in (RESULT_SERVED, RESULT_DEGRADED, RESULT_REJECTED):
            raise MeteringValidationError(f"unknown result {result!r}")
        if source not in EVENT_SOURCES:
            raise MeteringValidationError(f"unknown source {source!r}")
        if source == "live" and event_time > now + self.max_future_skew:
            raise MeteringValidationError(
                f"event_time {event_time} is more than {self.max_future_skew}s "
                "in the future"
            )
        event_id = event_id or new_event_id()
        tenant = (tenant or "").strip().lower()
        client_key = client_key or ""

        with self._lock:
            # BEGIN IMMEDIATE takes the write lock up front and keeps the
            # dedup check, the event insert and the aggregate deltas in one
            # atomic transaction; an early duplicate return rolls back the
            # read transaction cleanly instead of leaving it open.
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    "SELECT * FROM usage_events WHERE event_id = ?", (event_id,)
                ).fetchone()
                if existing is not None:
                    self._conn.rollback()
                    return {**self._event_row(existing), "duplicate": True}

                pstart = period_start(event_time, PERIOD_DAY)
                self._conn.execute(
                    "INSERT INTO usage_events"
                    " (event_id, event_time, recorded_at, tenant, client_key,"
                    "  name, region, labels_sig, rule_scope, rule_version,"
                    "  group_id, config_version, result, quantity, degraded,"
                    "  source, backfilled_by)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        event_id, event_time, now, tenant, client_key,
                        name, region or "", labels_sig or "", rule_scope,
                        rule_version, group_id, config_version, result,
                        quantity, 1 if degraded else 0, source, actor,
                    ),
                )
                self._bump_aggregate(
                    PERIOD_DAY, pstart, tenant, client_key, rule_scope,
                    quantity, result, now, self._conn,
                )
                # Keep both period projections aligned with the immutable
                # aggregates; normal adjustment deltas are preserved because
                # the projection refresh recomputes them from the ledger.
                for ptype in PERIOD_TYPES:
                    self._refresh_projection(
                        self._conn, tenant,
                        period_start(event_time, ptype), ptype, now,
                    )

                # Threshold alerts follow the policy governing the period the
                # *event time* belongs to: the live policy for the open
                # period (refreshed so its source/version stay current) and
                # the frozen snapshot for a past period, so late events can
                # fire retroactive alerts against the policy that was in
                # force back then.
                created_alerts: list[dict] = []
                effective = self._materialize_period_policy(
                    self._conn, tenant, event_time, now
                )
                if effective is not None and quantity > 0:
                    bstart = period_start(event_time, effective.period_type)
                    usage = self._period_usage(
                        tenant, bstart, effective.period_type
                    )
                    retroactive = bstart < period_start(
                        now, effective.period_type
                    )
                    # Open periods evaluate against the dispute-adjusted
                    # projection (applied disputes take effect immediately);
                    # closed periods keep the raw historical fact -- their
                    # retroactive adjustments append traceability but never
                    # rewrite the alerts the period actually fired.
                    used_for_alerts = (
                        usage["raw"] if retroactive else usage["adjusted"]
                    )
                    created_alerts = self._evaluate_thresholds(
                        tenant=tenant,
                        period_type=effective.period_type,
                        amount=effective.amount,
                        thresholds=list(effective.alert_thresholds),
                        start=bstart,
                        used=used_for_alerts,
                        event_id=event_id,
                        fired_at=now if retroactive else event_time,
                        retroactive=retroactive,
                        policy=effective,
                    )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                # A concurrent committer may have won the same event id.
                winner = self._conn.execute(
                    "SELECT * FROM usage_events WHERE event_id = ?", (event_id,)
                ).fetchone()
                if winner is not None:
                    return {**self._event_row(winner), "duplicate": True}
                raise

            for alert in created_alerts:
                self._audit_alert_fired(alert)

            self._audit.record(
                "usage_event",
                {
                    "event_id": event_id,
                    "tenant": tenant,
                    "scope": "tenant",
                    "client_key": client_key,
                    "name": name,
                    "region": region or "",
                    "rule_scope": rule_scope,
                    "result": result,
                    "quantity": quantity,
                    "event_time": event_time,
                    "source": source,
                    "duplicate": False,
                    "alerts_fired": [a["id"] for a in created_alerts],
                    "actor": actor if source == "backfill" else None,
                    # Which policy/version this event was resolved under.
                    "policy_source": effective.source if effective else None,
                    "policy_origin": effective.origin() if effective else None,
                },
            )
            row = self._conn.execute(
                "SELECT * FROM usage_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            return {**self._event_row(row), "duplicate": False}

    @staticmethod
    def _event_row(row: sqlite3.Row) -> dict:
        return {
            "event_id": row["event_id"],
            "event_time": row["event_time"],
            "recorded_at": row["recorded_at"],
            "tenant": row["tenant"],
            "client_key": row["client_key"],
            "name": row["name"],
            "region": row["region"],
            "labels_sig": row["labels_sig"],
            "rule_scope": row["rule_scope"],
            "rule_version": row["rule_version"],
            "group_id": row["group_id"],
            "config_version": row["config_version"],
            "result": row["result"],
            "quantity": row["quantity"],
            "degraded": bool(row["degraded"]),
            "source": row["source"],
            "backfilled_by": row["backfilled_by"],
        }

    # -- data-plane gate -------------------------------------------------------

    def check(
        self,
        tenant: str,
        *,
        amount_to_charge: float = 1.0,
        now: Optional[float] = None,
        audit_resolution: bool = False,
    ) -> BudgetDecision:
        """Gate one incoming request against the tenant's current-period budget.

        ``used`` is the post-charge projection (current aggregates plus the
        pending charge); no state is mutated. With ``audit_resolution`` the
        adopted source/version is written to the audit log (real data-plane
        resolutions; the explain projection leaves it off).
        """
        now = self._clock() if now is None else now
        tenant = (tenant or "").strip().lower()
        with self._lock:
            self._expire_overdue_overrides(now)
            effective = self._resolve_policy(tenant, now)
            if effective is None:
                result = BudgetDecision(
                    budget=None,
                    period_type=None,
                    period_started_at=None,
                    used=0.0,
                    amount=None,
                    policy="allow",
                    allowed=True,
                    degraded=False,
                    reason="no_budget",
                )
                if audit_resolution:
                    self._audit.record(
                        "budget_resolution",
                        {
                            "tenant": tenant,
                            "resolved_at": now,
                            "enabled": False,
                            "source": None,
                        },
                    )
                return result
            thresholds = list(effective.alert_thresholds)
            budget = {
                "tenant": tenant,
                "period_type": effective.period_type,
                "amount": effective.amount,
                "alert_thresholds": thresholds,
                "over_policy": effective.over_policy,
                "version": effective.source_version,
                "source": effective.source,
            }
            origin = effective.origin()
            ptype = effective.period_type
            start = period_start(now, ptype)
            # The gate projects against the dispute-adjusted usage: an
            # applied open-period dispute takes effect for the very next
            # resolution, while closed-period retroactive adjustments never
            # reach the open-period gate by construction.
            usage = self._period_usage(tenant, start, ptype)
            raw_used = usage["raw"]
            used_adjusted = usage["adjusted"]
            projected = used_adjusted + max(0.0, amount_to_charge)
            over = projected > effective.amount + 1e-9
            open_alerts = self._open_alerts(tenant, start, ptype)

            def decision(
                *, used_qty: float, allowed: bool, degraded: bool, reason: str
            ) -> BudgetDecision:
                return BudgetDecision(
                    budget=budget,
                    period_type=ptype,
                    period_started_at=start,
                    used=used_qty,
                    amount=effective.amount,
                    policy=effective.over_policy,
                    allowed=allowed,
                    degraded=degraded,
                    reason=reason,
                    thresholds=thresholds,
                    open_alerts=open_alerts,
                    origin=origin,
                    raw_used=raw_used,
                    normal_adjustment=used_adjusted - raw_used,
                )

            if not over:
                result = decision(
                    used_qty=projected, allowed=True, degraded=False,
                    reason="within_budget",
                )
            elif effective.over_policy == "allow":
                result = decision(
                    used_qty=projected, allowed=True, degraded=False,
                    reason="over_budget_allow",
                )
            elif effective.over_policy == "degrade":
                result = decision(
                    used_qty=projected, allowed=True, degraded=True,
                    reason="over_budget_degraded",
                )
            else:
                result = decision(
                    used_qty=used_adjusted, allowed=False, degraded=False,
                    reason="budget_exceeded",
                )
            if audit_resolution:
                self._audit.record(
                    "budget_resolution",
                    {
                        "tenant": tenant,
                        "resolved_at": now,
                        "enabled": True,
                        "source": effective.source,
                        "source_id": effective.source_id,
                        "source_version": effective.source_version,
                        "group_id": effective.group_id,
                        "member_group_id": effective.member_group_id,
                        "override_id": effective.override_id,
                        "period_type": ptype,
                        "period_start": start,
                        "amount": effective.amount,
                        "projected_used": result.used,
                        "decision": result.reason,
                        "allowed": result.allowed,
                        "degraded": result.degraded,
                    },
                )
            return result

    # -- control plane: budgets ------------------------------------------------

    def upsert_budget(
        self,
        spec: BudgetSpec,
        *,
        actor: str,
    ) -> tuple[dict, bool]:
        """Create or replace a tenant budget (optimistically versioned).

        Returns ``(budget, created)``. A same-content PUT is an idempotent
        no-op (no version bump, no audit).
        """
        now = self._clock()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._get_budget_row(spec.tenant)
                created = row is None
                if row is not None:
                    if spec.expected_version is not None and spec.expected_version != row["version"]:
                        self._conn.rollback()
                        raise MeteringConflict(
                            f"optimistic concurrency check failed for budget "
                            f"{spec.tenant!r}: expected version "
                            f"{spec.expected_version}, current {row['version']}"
                        )
                    unchanged = (
                        row["period_type"] == spec.period_type
                        and float(row["amount"]) == float(spec.amount)
                        and json.loads(row["alert_thresholds"]) == spec.alert_thresholds
                        and row["over_policy"] == spec.over_policy
                    )
                    if unchanged:
                        self._conn.rollback()
                        return self._budget_row(row), False
                    version = row["version"] + 1
                    old = self._budget_row(row)
                else:
                    if spec.expected_version is not None:
                        self._conn.rollback()
                        raise MeteringConflict(
                            f"budget for tenant {spec.tenant!r} does not exist; "
                            "expected_version can only be sent on update"
                        )
                    version = 1
                    old = None

                self._conn.execute(
                    "INSERT INTO budgets"
                    " (tenant, period_type, amount, alert_thresholds, over_policy,"
                    "  version, created_at, updated_at, created_by, updated_by)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT(tenant) DO UPDATE SET"
                    "  period_type=excluded.period_type, amount=excluded.amount,"
                    "  alert_thresholds=excluded.alert_thresholds,"
                    "  over_policy=excluded.over_policy, version=excluded.version,"
                    "  updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                    (
                        spec.tenant, spec.period_type, spec.amount,
                        json.dumps(spec.alert_thresholds), spec.over_policy,
                        version,
                        now if created else (row["created_at"] if row else now),
                        now,
                        actor if created else (row["created_by"] if row else actor),
                        actor,
                    ),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            new_row = self._get_budget_row(spec.tenant)
            self._audit.record(
                "budget_change",
                {
                    "action": "created" if created else "updated",
                    "tenant": spec.tenant,
                    "scope": "tenant",
                    "actor": actor,
                    "old": old,
                    "new": self._budget_row(new_row),
                    "version": version,
                },
            )
            return self._budget_row(new_row), created

    def delete_budget(self, tenant: str, actor: str) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._get_budget_row(tenant)
                if row is None:
                    self._conn.rollback()
                    raise MeteringNotFound(
                        f"no budget configured for tenant {tenant!r}"
                    )
                old = self._budget_row(row)
                self._conn.execute("DELETE FROM budgets WHERE tenant = ?", (tenant,))
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            self._audit.record(
                "budget_change",
                {
                    "action": "deleted",
                    "tenant": tenant,
                    "scope": "tenant",
                    "actor": actor,
                    "old": old,
                    "new": None,
                    "version": old["version"],
                },
            )

    # -- control plane: alerts -------------------------------------------------

    def list_alerts(
        self,
        *,
        tenant: Optional[str] = None,
        status: Optional[str] = None,
        period_type: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        sql = "SELECT * FROM budget_alerts WHERE 1=1"
        args: list = []
        if tenant is not None:
            sql += " AND tenant = ?"
            args.append(tenant.strip().lower())
        if status is not None:
            sql += " AND status = ?"
            args.append(status)
        if period_type is not None:
            sql += " AND period_type = ?"
            args.append(period_type)
        sql += " ORDER BY fired_at DESC, id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [self._alert_row(r) for r in rows]

    def get_alert(self, alert_id: str) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM budget_alerts WHERE id = ?", (alert_id,)
            ).fetchone()
            if row is None:
                raise MeteringNotFound(f"budget alert {alert_id!r} does not exist")
            return self._alert_row(row)

    def acknowledge_alert(
        self,
        alert_id: str,
        *,
        actor: str,
        comment: Optional[str] = None,
        expected_version: Optional[int] = None,
    ) -> tuple[dict, bool]:
        """Mark an alert acknowledged; idempotent re-ack returns changed=False."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT * FROM budget_alerts WHERE id = ?", (alert_id,)
                ).fetchone()
                if row is None:
                    self._conn.rollback()
                    raise MeteringNotFound(
                        f"budget alert {alert_id!r} does not exist"
                    )
                if expected_version is not None and expected_version != row["version"]:
                    self._conn.rollback()
                    raise MeteringConflict(
                        f"optimistic concurrency check failed for alert {alert_id!r}: "
                        f"expected version {expected_version}, current {row['version']}"
                    )
                if row["status"] == "acknowledged":
                    self._conn.rollback()
                    return self._alert_row(row), False
                now = self._clock()
                version = row["version"] + 1
                self._conn.execute(
                    "UPDATE budget_alerts SET status = 'acknowledged',"
                    " acknowledged_by = ?, acknowledged_at = ?, comment = ?,"
                    " version = ? WHERE id = ?",
                    (actor, now, comment, version, alert_id),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            new_row = self._conn.execute(
                "SELECT * FROM budget_alerts WHERE id = ?", (alert_id,)
            ).fetchone()
            alert = self._alert_row(new_row)
            self._audit.record(
                "budget_alert",
                {
                    "action": "acknowledged",
                    "alert_id": alert_id,
                    "tenant": alert["tenant"],
                    "scope": "tenant",
                    "actor": actor,
                    "comment": comment,
                    "period_type": alert["period_type"],
                    "period_start": alert["period_start"],
                    "threshold": alert["threshold"],
                    "version": version,
                },
            )
            return alert, True

    # -- control plane: queries ------------------------------------------------

    def list_events(
        self,
        *,
        tenant: Optional[str] = None,
        client_key: Optional[str] = None,
        rule_scope: Optional[str] = None,
        start: Optional[float] = None,
        end: Optional[float] = None,
        limit: int = 500,
    ) -> list[dict]:
        """Detail log over an event-time window; newest event time first."""
        sql = "SELECT * FROM usage_events WHERE 1=1"
        args: list = []
        if tenant is not None:
            sql += " AND tenant = ?"
            args.append(tenant.strip().lower())
        if client_key is not None:
            sql += " AND client_key = ?"
            args.append(client_key)
        if rule_scope is not None:
            sql += " AND rule_scope = ?"
            args.append(rule_scope)
        if start is not None:
            sql += " AND event_time >= ?"
            args.append(start)
        if end is not None:
            sql += " AND event_time < ?"
            args.append(end)
        sql += " ORDER BY event_time DESC, rowid DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [self._event_row(r) for r in rows]

    def aggregates(
        self,
        *,
        tenant: Optional[str] = None,
        period_type: str,
        start: Optional[float] = None,
        end: Optional[float] = None,
        group_by_client: bool = False,
        group_by_scope: bool = False,
    ) -> list[dict]:
        """Aggregated statistics bucketed into UTC day/month periods.

        Periods are aligned by event time (a late event lands in the period
        its event time belongs to). Rows are summed into the requested
        grouping and returned oldest period first.
        """
        if period_type not in PERIOD_TYPES:
            raise MeteringValidationError(f"period_type must be one of {PERIOD_TYPES}")
        dims = ["period_start"]
        if tenant is None:
            dims.append("tenant")
        if group_by_client:
            dims.append("client_key")
        if group_by_scope:
            dims.append("rule_scope")
        cols = ", ".join(dims)
        sql = (
            f"SELECT {cols},"
            " SUM(events) AS events, SUM(quantity) AS quantity,"
            " SUM(allowed_qty) AS allowed_qty,"
            " SUM(rejected_qty) AS rejected_qty,"
            " SUM(degraded_qty) AS degraded_qty"
            " FROM usage_aggregates WHERE period_type = ?"
        )
        args: list = [period_type]
        if tenant is not None:
            sql += " AND tenant = ?"
            args.append(tenant.strip().lower())
        if start is not None:
            sql += " AND period_start >= ?"
            args.append(period_start(start, period_type))
        if end is not None:
            sql += " AND period_start < ?"
            args.append(period_start(end, period_type))
        sql += f" GROUP BY {cols} ORDER BY period_start"
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        out = []
        for r in rows:
            item = {
                "period_type": period_type,
                "period_start": r["period_start"],
                "period": period_label(r["period_start"], period_type),
                "events": r["events"],
                "quantity": r["quantity"],
                "allowed_quantity": r["allowed_qty"],
                "rejected_quantity": r["rejected_qty"],
                "degraded_quantity": r["degraded_qty"],
            }
            if tenant is None:
                item["tenant"] = r["tenant"]
            else:
                item["tenant"] = tenant.strip().lower()
            if group_by_client:
                item["client_key"] = r["client_key"]
            if group_by_scope:
                item["rule_scope"] = r["rule_scope"]
            out.append(item)
        return out

    def budget_status(
        self,
        tenant: str,
        *,
        now: Optional[float] = None,
        at: Optional[float] = None,
    ) -> Optional[dict]:
        """Effective budget, remaining allowance and alerts for one tenant.

        The default query resolves the *current* chain (override > dedicated
        budget > group default) and reports the adopting source/version. With
        ``at`` set to a past epoch time the query answers historically: the
        policy is reconstructed as of that time, reusing the frozen period
        snapshot when one already exists; usage is the period aggregate.
        """
        now = self._clock() if now is None else now
        at = now if at is None else at
        tenant = tenant.strip().lower()
        with self._lock:
            self._expire_overdue_overrides(now)
            historical = at < period_start(now, PERIOD_DAY)
            # Resolve just enough to know which period kind the query asks
            # about; a frozen snapshot always wins for a closed period.
            probe = self._resolve_policy(tenant, at, historical=historical)
            if probe is None:
                live_probe = self._resolve_policy(tenant, now)
                if live_probe is None:
                    return None
                ptype_probe = live_probe.period_type
            else:
                ptype_probe = probe.period_type
            pstart = period_start(at, ptype_probe)
            snap_row = self._get_snapshot(
                self._conn, tenant, ptype_probe, pstart
            )
            if historical:
                if snap_row is not None and snap_row["frozen"]:
                    effective = self._policy_from_snapshot(snap_row, at)
                elif probe is not None:
                    effective = probe
                else:
                    return None
                frozen = bool(snap_row is not None and snap_row["frozen"])
            else:
                if probe is None:
                    return None
                effective = probe
                frozen = False
            start = period_start(at, effective.period_type)
            usage = self._period_usage(
                tenant, start, effective.period_type,
                include_retroactive=historical,
            )
            used = (
                usage["adjusted_including_retroactive"]
                if historical
                else usage["adjusted"]
            )
            nxt = next_period_start(at, effective.period_type)
            budget = {
                "tenant": tenant,
                "period_type": effective.period_type,
                "amount": effective.amount,
                "alert_thresholds": list(effective.alert_thresholds),
                "over_policy": effective.over_policy,
                "version": effective.source_version,
                "source": effective.source,
            }
            return {
                "budget": budget,
                "period_type": effective.period_type,
                "period_start": start,
                "period_end": nxt,
                "period": period_label(start, effective.period_type),
                "used": used,
                # Adjusted-usage attribution: raw billed quantity, the net
                # normal delta applied to the projection, and (for closed
                # periods) the traceable retroactive delta that does not
                # alter the period's projection or its fired alerts.
                "raw_used": usage["raw"],
                "normal_adjustment": usage["normal_adjustment"],
                "retroactive_adjustment": usage["retroactive_adjustment"],
                "adjusted": (
                    abs(usage["normal_adjustment"]) > 1e-12
                    or (
                        historical
                        and abs(usage["retroactive_adjustment"]) > 1e-12
                    )
                ),
                "amount": effective.amount,
                "remaining": max(0.0, effective.amount - used),
                "usage_ratio": used / effective.amount if effective.amount else None,
                "over_budget": used > effective.amount + 1e-9,
                "historical": historical,
                "frozen": frozen,
                "policy_origin": effective.origin(),
                "open_alerts": self._open_alerts(
                    tenant, start, effective.period_type
                ),
            }

    # -- control plane: backfill and recompute ---------------------------------

    def backfill(self, events: list[dict], *, actor: str) -> dict:
        """Idempotently insert operator-supplied past events.

        Each entry is validated, archived by its own ``event_time`` and folded
        into aggregates/alerts exactly like a live event; duplicate event ids
        are skipped rather than billed again.
        """
        if not events:
            raise MeteringValidationError("events must be a non-empty list")
        accepted, duplicates = [], []
        for raw in events:
            ev = dict(raw)
            event_time = ev.get("event_time")
            if event_time is None:
                raise MeteringValidationError(
                    f"event {ev.get('event_id')!r}: event_time is required"
                )
            stored = self.record_event(
                tenant=ev.get("tenant", ""),
                client_key=ev.get("client_key", ""),
                name=ev.get("name", ""),
                region=ev.get("region", ""),
                labels_sig=ev.get("labels_sig", ""),
                rule_scope=ev.get("rule_scope")
                or _infer_rule_scope(ev.get("region"), ev.get("tenant")),
                rule_version=ev.get("rule_version"),
                group_id=ev.get("group_id"),
                config_version=int(ev.get("config_version", 0)),
                result=ev.get("result", RESULT_SERVED),
                quantity=float(ev.get("quantity", 1.0)),
                degraded=bool(ev.get("degraded", False)),
                event_time=float(event_time),
                event_id=ev.get("event_id"),
                source="backfill",
                actor=actor,
            )
            (duplicates if stored["duplicate"] else accepted).append(
                stored["event_id"]
            )
        self._audit.record(
            "usage_backfill",
            {
                "actor": actor,
                "submitted": len(events),
                "accepted": len(accepted),
                "duplicates": len(duplicates),
                "event_ids": accepted,
                "duplicate_ids": duplicates,
            },
        )
        return {
            "submitted": len(events),
            "accepted": len(accepted),
            "duplicates": len(duplicates),
            "event_ids": accepted,
        }

    def recompute(
        self,
        *,
        actor: str,
        tenant: Optional[str] = None,
        start: Optional[float] = None,
        end: Optional[float] = None,
    ) -> dict:
        """Rebuild aggregates from the immutable detail log, then reconcile.

        Aggregates covered by the window are deleted and rebuilt from events
        (so late/backfilled/out-of-order events and any drift are healed),
        after which threshold alerts are reconciled per affected
        tenant-period against the policy that actually governed the period:
        live policy for the still-open period, the frozen period snapshot
        (materializing it on first use, as for late events) for closed
        periods. Existing alerts are never removed; only missing threshold
        crossings are created (marked retroactive).
        """
        with self._lock:
            where = "1=1"
            args: list = []
            if tenant is not None:
                where += " AND tenant = ?"
                args.append(tenant.strip().lower())
            if start is not None:
                where += " AND event_time >= ?"
                args.append(start)
            if end is not None:
                where += " AND event_time < ?"
                args.append(end)

            # One immediate transaction: read the immutable detail log,
            # replace the touched aggregate cells and reconcile alerts, so
            # either all of it commits or none does.
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                rows = self._conn.execute(
                    f"SELECT * FROM usage_events WHERE {where}"
                    " ORDER BY event_time, rowid",
                    args,
                ).fetchall()
                events = [self._event_row(r) for r in rows]
                if not events:
                    self._conn.rollback()
                    result = {"events_scanned": 0, "periods_rebuilt": 0,
                              "alerts_created": 0}
                    self._audit.record("usage_recompute",
                                       {"actor": actor, **result})
                    return result

                tenants = sorted({e["tenant"] for e in events})
                window_start = min(e["event_time"] for e in events)
                window_end = max(e["event_time"] for e in events)
                period_ranges = {
                    ptype: (
                        period_start(window_start, ptype),
                        period_start(window_end, ptype),
                    )
                    for ptype in PERIOD_TYPES
                }

                # Drop the aggregate cells the window touches.
                deleted = 0
                for ptype, (pfrom, pto) in period_ranges.items():
                    cur = self._conn.execute(
                        "DELETE FROM usage_aggregates"
                        " WHERE period_type = ? AND period_start BETWEEN ? AND ?"
                        + (" AND tenant = ?" if tenant is not None else ""),
                        (ptype, pfrom, pto, *((tenant.strip().lower(),) if tenant is not None else ())),
                    )
                    deleted += cur.rowcount

                # Rebuild straight from the immutable detail log, grouped by
                # the aggregate primary key. Events are folded in event-time
                # order.
                cells: dict[tuple, dict] = {}
                for e in events:
                    for ptype in PERIOD_TYPES:
                        pstart = period_start(e["event_time"], ptype)
                        key = (
                            ptype, pstart, e["tenant"], e["client_key"],
                            e["rule_scope"],
                        )
                        cell = cells.setdefault(
                            key,
                            {"events": 0, "quantity": 0.0, "allowed_qty": 0.0,
                             "rejected_qty": 0.0, "degraded_qty": 0.0},
                        )
                        cell["events"] += 1
                        cell["quantity"] += e["quantity"]
                        bucket = {
                            RESULT_SERVED: "allowed_qty",
                            RESULT_REJECTED: "rejected_qty",
                            RESULT_DEGRADED: "degraded_qty",
                        }[e["result"]]
                        cell[bucket] += e["quantity"]

                rebuild_at = self._clock()
                for (ptype, pstart, t, client, scope), cell in cells.items():
                    self._conn.execute(
                        "INSERT INTO usage_aggregates"
                        " (period_type, period_start, tenant, client_key, rule_scope,"
                        "  events, quantity, allowed_qty, rejected_qty, degraded_qty,"
                        "  updated_at)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            ptype, pstart, t, client, scope,
                            cell["events"], cell["quantity"], cell["allowed_qty"],
                            cell["rejected_qty"], cell["degraded_qty"], rebuild_at,
                        ),
                    )

                # Rebuild the materialized per-period projections from the
                # rebuilt aggregates and the immutable adjustment ledger, so
                # the gate's adjusted usage agrees with both sources.
                projection_keys = {
                    (ptype, period_start(e["event_time"], ptype), e["tenant"])
                    for e in events
                    for ptype in PERIOD_TYPES
                }
                for ptype, pstart, t in sorted(projection_keys):
                    self._refresh_projection(
                        self._conn, t, pstart, ptype, rebuild_at
                    )

                # Resolve (and persist, freezing closed periods) the policy
                # governing each distinct event period, then reconcile
                # missing threshold crossings against it.
                fired_alerts: list[dict] = []
                policies: dict[tuple[str, float], EffectivePolicy] = {}
                for e in events:
                    policy = self._materialize_period_policy(
                        self._conn, e["tenant"], e["event_time"], rebuild_at
                    )
                    if policy is None:
                        continue
                    bstart = period_start(e["event_time"], policy.period_type)
                    policies[(e["tenant"], bstart)] = policy
                for (t, bstart), policy in policies.items():
                    ptype = policy.period_type
                    usage = self._period_usage(t, bstart, ptype)
                    retroactive = bstart < period_start(rebuild_at, ptype)
                    # Closed periods keep their raw historical fact; only
                    # the open period re-evaluates against adjusted usage.
                    used = usage["raw"] if retroactive else usage["adjusted"]
                    fired_alerts.extend(
                        self._evaluate_thresholds(
                            tenant=t,
                            period_type=ptype,
                            amount=policy.amount,
                            thresholds=list(policy.alert_thresholds),
                            start=bstart,
                            used=used,
                            event_id=None,
                            fired_at=rebuild_at,
                            retroactive=retroactive,
                            policy=policy,
                        )
                    )

                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

            alerts_created = [a["id"] for a in fired_alerts]
            for alert in fired_alerts:
                self._audit_alert_fired(alert)
            result = {
                "events_scanned": len(events),
                "tenants": tenants,
                "cells_deleted": deleted,
                "cells_rebuilt": len(cells),
                "periods_rebuilt": len(
                    {(ptype, ps) for ptype, ps, *_ in cells}
                ),
                "alerts_created": len(alerts_created),
                "alert_ids": alerts_created,
            }
            self._audit.record(
                "usage_recompute", {"actor": actor, **result}
            )
            return result


def _infer_rule_scope(region: Optional[str], tenant: Optional[str]) -> str:
    if tenant:
        return "tenant"
    if region:
        return "region"
    return "global"


def _amounts_equal(a: Optional[float], b: Optional[float]) -> bool:
    if a is None or b is None:
        return a is None and b is None
    return abs(float(a) - float(b)) < 1e-9
