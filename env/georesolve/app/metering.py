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

Persistence / concurrency
-------------------------
Events, aggregates, budgets and alerts all live in SQLite. One process-wide
lock serializes mutations and every write is a transaction, so an event
insert and its aggregate deltas commit together (or not at all). Budget and
alert rows carry monotonically increasing versions with
``expected_version`` optimistic concurrency; control-plane writes also accept
``Idempotency-Key`` (reused via the authz store).
"""
from __future__ import annotations

import calendar
import json
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from pydantic import BaseModel, Field, field_validator

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


# -- models -------------------------------------------------------------------


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
        for t in v:
            if t != t or t in (float("inf"), float("-inf")) or not (0.0 < t <= 10.0):
                raise ValueError(
                    "alert thresholds must be finite numbers in (0, 10] "
                    "(fractions of the budget)"
                )
        return sorted(set(round(float(t), 6) for t in v))


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
            "remaining": remaining,
            "usage_ratio": self.usage_ratio,
            "policy": self.policy if self.budget is not None else None,
            "allowed": self.allowed,
            "degraded": self.degraded,
            "reason": self.reason,
            "alert_thresholds": self.thresholds,
            "open_alerts": self.open_alerts,
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

    # -- alerts ---------------------------------------------------------------

    @staticmethod
    def _alert_row(row: sqlite3.Row) -> dict:
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
        budget_row: sqlite3.Row,
        start: float,
        used: float,
        event_id: Optional[str],
        fired_at: float,
        retroactive: bool,
    ) -> list[dict]:
        """Create any not-yet-fired threshold alerts for one period.

        One open alert per (tenant, period, threshold); the UNIQUE constraint
        plus the lock make crossing a threshold exactly-once even under
        concurrent requests. Runs inside the caller's transaction and only
        mutates the database; the caller writes the ``budget_alert`` audit
        records after the transaction commits.
        """
        amount = float(budget_row["amount"])
        period_type = budget_row["period_type"]
        tenant = budget_row["tenant"]
        thresholds = json.loads(budget_row["alert_thresholds"])
        created: list[dict] = []
        for threshold in thresholds:
            if used + 1e-9 < amount * threshold:
                continue
            alert_id = new_alert_id()
            try:
                self._conn.execute(
                    "INSERT INTO budget_alerts"
                    " (id, tenant, period_type, period_start, threshold, usage,"
                    "  budget_amount, event_id, fired_at, status, version)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 1)",
                    (
                        alert_id, tenant, period_type, start, threshold, used,
                        amount, event_id, fired_at,
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

                # Threshold alerts follow the tenant's budget; evaluated
                # against the period the *event time* belongs to, so late
                # events can fire retroactive alerts on past periods.
                created_alerts: list[dict] = []
                budget_row = self._get_budget_row(tenant)
                if budget_row is not None and quantity > 0:
                    bstart = period_start(event_time, budget_row["period_type"])
                    used = self._period_used(
                        tenant, bstart, budget_row["period_type"]
                    )
                    retroactive = bstart < period_start(
                        now, budget_row["period_type"]
                    )
                    created_alerts = self._evaluate_thresholds(
                        budget_row, bstart, used, event_id,
                        now if retroactive else event_time, retroactive,
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
                self._audit.record(
                    "budget_alert",
                    {
                        "action": "fired",
                        "alert_id": alert["id"],
                        "tenant": tenant,
                        "scope": "tenant",
                        "period_type": alert["period_type"],
                        "period_start": alert["period_start"],
                        "period": alert["period"],
                        "threshold": alert["threshold"],
                        "usage": alert["usage"],
                        "budget_amount": alert["budget_amount"],
                        "event_id": event_id,
                        "retroactive": alert["period_start"]
                        < period_start(now, alert["period_type"]),
                    },
                )

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
    ) -> BudgetDecision:
        """Gate one incoming request against the tenant's current-period budget.

        ``used`` is the post-charge projection (current aggregates plus the
        pending charge); no state is mutated.
        """
        now = self._clock() if now is None else now
        tenant = (tenant or "").strip().lower()
        with self._lock:
            row = self._get_budget_row(tenant)
            if row is None:
                return BudgetDecision(
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
            budget = self._budget_row(row)
            ptype = budget["period_type"]
            start = period_start(now, ptype)
            used = self._period_used(tenant, start, ptype)
            projected = used + max(0.0, amount_to_charge)
            over = projected > budget["amount"] + 1e-9
            open_alerts = self._open_alerts(tenant, start, ptype)
            if not over:
                return BudgetDecision(
                    budget=budget,
                    period_type=ptype,
                    period_started_at=start,
                    used=projected,
                    amount=budget["amount"],
                    policy=budget["over_policy"],
                    allowed=True,
                    degraded=False,
                    reason="within_budget",
                    thresholds=budget["alert_thresholds"],
                    open_alerts=open_alerts,
                )
            policy = budget["over_policy"]
            if policy == "allow":
                return BudgetDecision(
                    budget=budget,
                    period_type=ptype,
                    period_started_at=start,
                    used=projected,
                    amount=budget["amount"],
                    policy=policy,
                    allowed=True,
                    degraded=False,
                    reason="over_budget_allow",
                    thresholds=budget["alert_thresholds"],
                    open_alerts=open_alerts,
                )
            if policy == "degrade":
                return BudgetDecision(
                    budget=budget,
                    period_type=ptype,
                    period_started_at=start,
                    used=projected,
                    amount=budget["amount"],
                    policy=policy,
                    allowed=True,
                    degraded=True,
                    reason="over_budget_degraded",
                    thresholds=budget["alert_thresholds"],
                    open_alerts=open_alerts,
                )
            return BudgetDecision(
                budget=budget,
                period_type=ptype,
                period_started_at=start,
                used=used,
                amount=budget["amount"],
                policy=policy,
                allowed=False,
                degraded=False,
                reason="budget_exceeded",
                thresholds=budget["alert_thresholds"],
                open_alerts=open_alerts,
            )

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
            already = False
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
        self, tenant: str, *, now: Optional[float] = None
    ) -> Optional[dict]:
        """Current budget, remaining allowance and open alerts for one tenant."""
        now = self._clock() if now is None else now
        tenant = tenant.strip().lower()
        with self._lock:
            row = self._get_budget_row(tenant)
            if row is None:
                return None
            budget = self._budget_row(row)
            start = period_start(now, budget["period_type"])
            used = self._period_used(tenant, start, budget["period_type"])
            nxt = next_period_start(now, budget["period_type"])
            return {
                "budget": budget,
                "period_type": budget["period_type"],
                "period_start": start,
                "period_end": nxt,
                "period": period_label(start, budget["period_type"]),
                "used": used,
                "amount": budget["amount"],
                "remaining": max(0.0, budget["amount"] - used),
                "usage_ratio": used / budget["amount"] if budget["amount"] else None,
                "over_budget": used > budget["amount"] + 1e-9,
                "open_alerts": self._open_alerts(
                    tenant, start, budget["period_type"]
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
        after which threshold alerts are reconciled against each affected
        tenant-period using the *current* budget configuration. Existing
        alerts are never removed; only missing threshold crossings are
        created (marked retroactive).
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

                # Reconcile threshold alerts on each affected tenant-period
                # using each tenant's current budget configuration.
                fired_alerts: list[dict] = []
                affected: set[tuple[str, str, float]] = set()
                for e in events:
                    budget_row = self._get_budget_row(e["tenant"])
                    if budget_row is None:
                        continue
                    ptype = budget_row["period_type"]
                    bstart = period_start(e["event_time"], ptype)
                    pfrom, pto = period_ranges[ptype]
                    if pfrom <= bstart <= pto:
                        affected.add((e["tenant"], ptype, bstart))
                for t, ptype, bstart in affected:
                    budget_row = self._get_budget_row(t)
                    used = self._period_used(t, bstart, ptype)
                    fired_alerts.extend(
                        self._evaluate_thresholds(
                            budget_row, bstart, used, None, rebuild_at,
                            retroactive=True,
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
