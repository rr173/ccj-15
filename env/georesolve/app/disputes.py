"""Budget billing disputes and immutable billing adjustments.

An administrator disputes the billing of one tenant period by filing a
*dispute* that cites one or more immutable usage events, states a reason
and a signed billing quantity to adjust. The dispute then follows the
lifecycle::

    draft -> pending_review -> approved -> applied
                            \\-> rejected
    draft / pending_review / approved -> revoked
    applied (open period only) -> revoked   (append-only reverse)

Freezing
--------
At submission time (``draft -> pending_review``) the store freezes, inside
the dispute row:

- the cited event list (full event payloads in submission order);
- the period's raw aggregates (per client/rule-scope cells and totals);
- the currently resolved budget policy with its source and version.

The original usage events are never modified. Closed periods additionally
keep their frozen ``budget_policy_snapshots``; only an explicitly
``retroactive`` adjustment may touch a closed period, and it appends a
traceable ledger row plus audit records without changing the projection the
gate saw or the alerts the period actually fired.

Separation of duties and concurrency
------------------------------------
Only a *different* administrator holding ``budget:write`` on the tenant may
approve or reject; the creator can never decide their own dispute. Approve,
reject, apply and revoke all accept ``expected_version`` optimistic
concurrency plus the control-plane ``Idempotency-Key`` (handled by the API
layer): concurrent transitions are serialized and exactly one wins, while
a retried idempotent request replays the original result.

Applying
--------
Applying an approved dispute performs, in one transaction:

1. the immutable ``budget_adjustments`` row (signed quantity),
2. the open period's materialized projection
   (``budget_usage_projections``),
3. threshold re-evaluation against the adjusted projection (missing
   crossings are appended as ordinary alerts; existing alerts are never
   removed or altered).

Once an open-period adjustment is applied, the very next resolution uses
the new projection (the gate reads adjusted usage live). A closed-period
adjustment must be ``retroactive``: it only appends the ledger row and
audit records -- the period's original projection and fired alerts stay
untouched.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from typing import Callable, Optional

from pydantic import BaseModel, Field, field_validator

from .audit import AuditLog
from .metering import (
    PERIOD_TYPES,
    EffectivePolicy,
    MeteringConflict,
    MeteringNotFound,
    MeteringStore,
    MeteringValidationError,
    PolicyDenied,
    next_period_start,
    period_label,
    period_start,
)

#: Dispute lifecycle states.
STATUS_DRAFT = "draft"
STATUS_PENDING = "pending_review"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_APPLIED = "applied"
STATUS_REVOKED = "revoked"

DISPUTE_STATUSES = (
    STATUS_DRAFT,
    STATUS_PENDING,
    STATUS_APPROVED,
    STATUS_REJECTED,
    STATUS_APPLIED,
    STATUS_REVOKED,
)
#: States no transition may leave (except that applied -> revoked exists, so
#: rejected alone is fully terminal).
DISPUTE_TERMINAL_STATUSES = (STATUS_REJECTED,)

ADJUSTMENT_KINDS = ("normal", "retroactive")
LEDGER_DIRECTIONS = ("apply", "reverse")

#: Refusal reason codes (also written to the audit log).
REASON_UNKNOWN_EVENT = "unknown_event"
REASON_CROSS_TENANT_EVENT = "cross_tenant_event"
REASON_DUPLICATE_EVENT = "duplicate_event"
REASON_EVENT_WRONG_PERIOD = "event_wrong_period"
REASON_NEGATIVE_USAGE = "negative_usage"
REASON_FROZEN_PERIOD = "frozen_period"
REASON_PERIOD_OPEN = "period_open"
REASON_SELF_APPROVAL = "self_approval"
REASON_STATUS_CONFLICT = "status_conflict"
REASON_VERSION_CONFLICT = "version_conflict"
REASON_POLICY_PERIOD_MISMATCH = "policy_period_mismatch"


class DisputeConflict(PolicyDenied):
    """A lifecycle/version conflict on a dispute (HTTP 409)."""


class DisputeNotFound(MeteringNotFound):
    pass


# -- input models -------------------------------------------------------------


class DisputeSpec(BaseModel):
    """Create a dispute for one tenant period.

    ``event_ids`` cite immutable usage events; ``adjustment_quantity`` is
    signed (a credit negative, an extra debit positive). With
    ``submit=True`` the freeze is taken immediately and the dispute enters
    ``pending_review``; otherwise it stays a ``draft`` whose references are
    frozen on a later submit.
    """

    tenant: Optional[str] = None  # filled from the URL path
    period_type: str = "day"
    period: Optional[str] = Field(
        default=None,
        description="period label (YYYY-MM-DD or YYYY-MM); defaults to now",
    )
    event_ids: list[str] = Field(default_factory=list)
    reason: str = ""
    adjustment_quantity: float = Field(allow_inf_nan=False)
    retroactive: bool = False
    submit: bool = False
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

    @field_validator("reason")
    @classmethod
    def _reason_non_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("reason must be a non-empty string")
        return v.strip()

    @field_validator("adjustment_quantity")
    @classmethod
    def _finite_nonzero(cls, v: float) -> float:
        if v != v or v in (float("inf"), float("-inf")):
            raise ValueError("adjustment_quantity must be finite")
        if v == 0:
            raise ValueError("adjustment_quantity must be non-zero")
        return float(v)


class DisputeSubmitRequest(BaseModel):
    retroactive: bool = False


class DisputeDecisionRequest(BaseModel):
    comment: Optional[str] = None
    expected_version: Optional[int] = Field(default=None, ge=1)


class DisputeApplyRequest(BaseModel):
    expected_version: Optional[int] = Field(default=None, ge=1)


class DisputeRevokeRequest(BaseModel):
    reason: Optional[str] = None
    expected_version: Optional[int] = Field(default=None, ge=1)


# -- the store ----------------------------------------------------------------


class DisputeStore:
    """Dispute lifecycle, the frozen references and the adjustment ledger."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        metering: MeteringStore,
        audit: AuditLog,
        clock: Callable[[], float] = time.time,
    ):
        self._conn = conn
        self._metering = metering
        self._audit = audit
        self._clock = clock
        # Shares the metering store's lock: disputes, events and budget
        # writes serialize as one mutation stream over the same database.
        self._lock = metering.lock

    # -- row mappers ----------------------------------------------------------

    @staticmethod
    def _row(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "tenant": row["tenant"],
            "period_type": row["period_type"],
            "period_start": row["period_start"],
            "period": period_label(row["period_start"], row["period_type"]),
            "period_end": next_period_start(row["period_start"], row["period_type"]),
            "reason": row["reason"],
            "adjustment_quantity": row["adjustment_quantity"],
            "retroactive": bool(row["retroactive"]),
            "status": row["status"],
            "event_count": row["event_count"],
            "frozen_events": (
                json.loads(row["frozen_events"])
                if row["frozen_events"] is not None
                else None
            ),
            "frozen_aggregates": (
                json.loads(row["frozen_aggregates"])
                if row["frozen_aggregates"] is not None
                else None
            ),
            "frozen_policy": (
                json.loads(row["frozen_policy"])
                if row["frozen_policy"] is not None
                else None
            ),
            "frozen_at": row["frozen_at"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "submitted_by": row["submitted_by"],
            "submitted_at": row["submitted_at"],
            "decided_by": row["decided_by"],
            "decided_at": row["decided_at"],
            "decision_comment": row["decision_comment"],
            "applied_by": row["applied_by"],
            "applied_at": row["applied_at"],
            "revoked_by": row["revoked_by"],
            "revoked_at": row["revoked_at"],
            "revoke_reason": row["revoke_reason"],
            "version": row["version"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _adjustment_row(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "dispute_id": row["dispute_id"],
            "tenant": row["tenant"],
            "period_type": row["period_type"],
            "period_start": row["period_start"],
            "period": period_label(row["period_start"], row["period_type"]),
            "kind": row["kind"],
            "direction": row["direction"],
            "quantity": row["quantity"],
            "reverses_id": row["reverses_id"],
            "raw_quantity": row["raw_quantity"],
            "adjusted_quantity": row["adjusted_quantity"],
            "policy_origin": (
                json.loads(row["policy_origin"])
                if row["policy_origin"] is not None
                else None
            ),
            "actor": row["actor"],
            "created_at": row["created_at"],
        }

    def _new_id(self, prefix: str, table: str, n: int = 12) -> str:
        while True:
            eid = prefix + secrets.token_urlsafe(n)
            exists = self._conn.execute(
                f"SELECT 1 FROM {table} WHERE id = ?", (eid,)
            ).fetchone()
            if exists is None:
                return eid

    def _denied(
        self,
        action: str,
        reason: str,
        *,
        audit: bool = True,
        **details,
    ) -> DisputeConflict:
        """Build the conflict and record the refusal audit when asked."""
        if audit:
            self._audit.record(
                "budget_policy_denied",
                {"action": action, "module": "budget_dispute",
                 "reason": reason, **details},
            )
        return DisputeConflict(f"{action} refused: {reason}")

    # -- reads ---------------------------------------------------------------

    def _get_row(self, dispute_id: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM budget_disputes WHERE id = ?", (dispute_id,)
        ).fetchone()

    def get(self, dispute_id: str) -> dict:
        with self._lock:
            row = self._get_row(dispute_id)
            if row is None:
                raise DisputeNotFound(
                    f"budget dispute {dispute_id!r} does not exist"
                )
            return self._row(row)

    def list_disputes(
        self,
        *,
        tenant: Optional[str] = None,
        period_type: Optional[str] = None,
        period: Optional[str] = None,
        status: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: int = 200,
    ) -> list[dict]:
        """List disputes newest-first; time filters apply to ``created_at``."""
        if status is not None and status not in DISPUTE_STATUSES:
            raise MeteringValidationError(
                f"status must be one of {DISPUTE_STATUSES}"
            )
        if period_type is not None and period_type not in PERIOD_TYPES:
            raise MeteringValidationError(
                f"period_type must be one of {PERIOD_TYPES}"
            )
        sql = "SELECT * FROM budget_disputes WHERE 1=1"
        args: list = []
        if tenant is not None:
            sql += " AND tenant = ?"
            args.append(tenant.strip().lower())
        if period_type is not None:
            sql += " AND period_type = ?"
            args.append(period_type)
        if period is not None:
            start = self._parse_period(period, period_type or "day")
            sql += " AND period_start = ?"
            args.append(start)
        if status is not None:
            sql += " AND status = ?"
            args.append(status)
        if since is not None:
            sql += " AND created_at >= ?"
            args.append(since)
        if until is not None:
            sql += " AND created_at < ?"
            args.append(until)
        sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [self._row(r) for r in rows]

    @staticmethod
    def _parse_period(label: str, period_type: str) -> float:
        """Parse a YYYY-MM-DD (day) or YYYY-MM (month) label to a UTC start."""
        from datetime import datetime, timezone
        fmt = "%Y-%m-%d" if period_type == "day" else "%Y-%m"
        try:
            dt = datetime.strptime(label, fmt).replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise MeteringValidationError(
                f"period must match {fmt}"
            ) from exc
        return dt.timestamp()

    def history(
        self,
        dispute_id: str,
        *,
        since: Optional[float] = None,
        until: Optional[float] = None,
    ) -> list[dict]:
        """Append-only lifecycle timeline of one dispute, oldest first."""
        with self._lock:
            if self._get_row(dispute_id) is None:
                raise DisputeNotFound(
                    f"budget dispute {dispute_id!r} does not exist"
                )
            sql = (
                "SELECT * FROM budget_dispute_events WHERE dispute_id = ?"
            )
            args: list = [dispute_id]
            if since is not None:
                sql += " AND ts >= ?"
                args.append(since)
            if until is not None:
                sql += " AND ts < ?"
                args.append(until)
            sql += " ORDER BY id"
            rows = self._conn.execute(sql, args).fetchall()
        return [
            {
                "id": r["id"],
                "dispute_id": r["dispute_id"],
                "ts": r["ts"],
                "actor": r["actor"],
                "action": r["action"],
                "from_status": r["from_status"],
                "to_status": r["to_status"],
                "version": r["version"],
                "details": json.loads(r["details"]),
            }
            for r in rows
        ]

    def list_adjustments(
        self,
        *,
        tenant: Optional[str] = None,
        period_type: Optional[str] = None,
        period: Optional[str] = None,
        kind: Optional[str] = None,
        limit: int = 500,
    ) -> list[dict]:
        if kind is not None and kind not in ADJUSTMENT_KINDS:
            raise MeteringValidationError(
                f"kind must be one of {ADJUSTMENT_KINDS}"
            )
        sql = "SELECT * FROM budget_adjustments WHERE 1=1"
        args: list = []
        if tenant is not None:
            sql += " AND tenant = ?"
            args.append(tenant.strip().lower())
        if period_type is not None:
            sql += " AND period_type = ?"
            args.append(period_type)
        if period is not None:
            start = self._parse_period(period, period_type or "day")
            sql += " AND period_start = ?"
            args.append(start)
        if kind is not None:
            sql += " AND kind = ?"
            args.append(kind)
        sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [self._adjustment_row(r) for r in rows]

    # -- freeze computation ---------------------------------------------------

    def _load_event(self, event_id: str) -> Optional[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM usage_events WHERE event_id = ?", (event_id,)
        ).fetchone()

    def _frozen_aggregates(
        self, tenant: str, start: float, period_type: str
    ) -> dict:
        """Raw aggregate cells frozen at submission (unadjusted fact)."""
        rows = self._conn.execute(
            "SELECT client_key, rule_scope, events, quantity,"
            " allowed_qty, rejected_qty, degraded_qty"
            " FROM usage_aggregates"
            " WHERE period_type = ? AND period_start = ? AND tenant = ?"
            " ORDER BY client_key, rule_scope",
            (period_type, start, tenant),
        ).fetchall()
        cells = [dict(r) for r in rows]
        return {
            "period_type": period_type,
            "period_start": start,
            "tenant": tenant,
            "total_quantity": sum(float(c["quantity"]) for c in cells),
            "total_events": sum(int(c["events"]) for c in cells),
            "cells": cells,
        }

    @staticmethod
    def _frozen_policy(policy: Optional[EffectivePolicy]) -> Optional[dict]:
        if policy is None:
            return None
        return {
            "source": policy.source,
            "source_id": policy.source_id,
            "source_version": policy.source_version,
            "period_type": policy.period_type,
            "amount": policy.amount,
            "alert_thresholds": list(policy.alert_thresholds),
            "over_policy": policy.over_policy,
            "origin": policy.origin(),
            "resolved_at": policy.resolved_at,
        }

    def _freeze(
        self,
        conn: sqlite3.Connection,
        *,
        tenant: str,
        start: float,
        period_type: str,
        event_ids: list[str],
        now: float,
    ) -> tuple[str, dict, dict, Optional[dict]]:
        """Validate the cited events and build the frozen submission payload.

        Raises DisputeConflict (already audited) or MeteringNotFound; runs
        inside the caller's immediate transaction.
        """
        # Duplicate references within the same submission are rejected.
        seen: set[str] = set()
        for eid in event_ids:
            if eid in seen:
                raise self._denied(
                    "dispute_submit", REASON_DUPLICATE_EVENT,
                    tenant=tenant, event_id=eid,
                )
            seen.add(eid)

        frozen_events: list[dict] = []
        for eid in event_ids:
            row = conn.execute(
                "SELECT * FROM usage_events WHERE event_id = ?", (eid,)
            ).fetchone()
            if row is None:
                raise self._denied(
                    "dispute_submit", REASON_UNKNOWN_EVENT,
                    tenant=tenant, event_id=eid,
                )
            if row["tenant"] != tenant:
                # Another tenant's event may never be cited (or even frozen
                # into this tenant's dispute).
                raise self._denied(
                    "dispute_submit", REASON_CROSS_TENANT_EVENT,
                    tenant=tenant, event_id=eid,
                    event_tenant=row["tenant"],
                )
            estart = period_start(row["event_time"], period_type)
            if estart != start:
                raise self._denied(
                    "dispute_submit", REASON_EVENT_WRONG_PERIOD,
                    tenant=tenant, event_id=eid,
                    event_period=period_label(estart, period_type),
                    dispute_period=period_label(start, period_type),
                )
            frozen_events.append(self._metering._event_row(row))

        aggregates = self._frozen_aggregates(tenant, start, period_type)
        policy = self._metering._resolve_policy(tenant, now)
        if policy is not None and policy.period_type != period_type:
            # A dispute for a period kind with no policy of that kind cannot
            # be evaluated coherently; refuse rather than silently switching
            # the alerting period.
            raise self._denied(
                "dispute_submit", REASON_POLICY_PERIOD_MISMATCH,
                tenant=tenant, period_type=period_type,
                policy_period_type=policy.period_type,
            )
        frozen_policy = self._frozen_policy(policy)
        return (
            json.dumps(frozen_events, sort_keys=True),
            aggregates,
            {"policy": frozen_policy, "resolved_at": now},
            frozen_policy,
        )

    # -- lifecycle ------------------------------------------------------------

    def _append_event(
        self,
        conn: sqlite3.Connection,
        dispute_id: str,
        *,
        ts: float,
        actor: str,
        action: str,
        from_status: Optional[str],
        to_status: Optional[str],
        version: int,
        details: Optional[dict] = None,
    ) -> None:
        conn.execute(
            "INSERT INTO budget_dispute_events"
            " (dispute_id, ts, actor, action, from_status, to_status,"
            "  version, details)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                dispute_id, ts, actor, action, from_status, to_status,
                version, json.dumps(details or {}, sort_keys=True),
            ),
        )

    def create(self, spec: DisputeSpec, *, tenant: str, actor: str) -> dict:
        """Create a dispute as draft or submit it immediately."""
        tenant = (tenant or "").strip().lower()
        now = self._clock()
        pstart = (
            self._parse_period(spec.period, spec.period_type)
            if spec.period is not None
            else period_start(now, spec.period_type)
        )
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                did = self._new_id("disp_", "budget_disputes")
                status = STATUS_PENDING if spec.submit else STATUS_DRAFT
                self._conn.execute(
                    "INSERT INTO budget_disputes"
                    " (id, tenant, period_type, period_start, reason,"
                    "  adjustment_quantity, retroactive, status, event_count,"
                    "  created_by, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        did, tenant, spec.period_type, pstart, spec.reason,
                        spec.adjustment_quantity,
                        1 if spec.retroactive else 0, status,
                        len(spec.event_ids), actor, now, now,
                    ),
                )
                for pos, eid in enumerate(spec.event_ids):
                    self._conn.execute(
                        "INSERT INTO budget_dispute_refs (dispute_id, event_id,"
                        " position) VALUES (?, ?, ?)",
                        (did, eid, pos),
                    )
                version = 1
                self._append_event(
                    self._conn, did, ts=now, actor=actor,
                    action="created", from_status=None, to_status=status,
                    version=version,
                    details={"submit": spec.submit,
                             "retroactive": spec.retroactive,
                             "adjustment_quantity": spec.adjustment_quantity,
                             "event_count": len(spec.event_ids)},
                )
                if spec.submit:
                    self._do_submit(
                        self._conn, did,
                        retroactive=spec.retroactive, actor=actor, now=now,
                    )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            row = self._row(self._get_row(did))
            self._audit.record(
                "budget_dispute",
                {
                    "action": "created",
                    "dispute_id": did,
                    "tenant": tenant,
                    "scope": "tenant",
                    "actor": actor,
                    "status": row["status"],
                    "period_type": spec.period_type,
                    "period": row["period"],
                    "retroactive": spec.retroactive,
                    "adjustment_quantity": spec.adjustment_quantity,
                    "event_count": len(spec.event_ids),
                    "version": row["version"],
                },
            )
            if row["status"] == STATUS_PENDING:
                self._audit.record(
                    "budget_dispute",
                    {
                        "action": "submitted",
                        "dispute_id": did,
                        "tenant": tenant,
                        "scope": "tenant",
                        "actor": actor,
                        "version": row["version"],
                        "frozen_policy": row["frozen_policy"],
                    },
                )
            return row

    def submit(
        self,
        dispute_id: str,
        *,
        actor: str,
        retroactive: bool = False,
    ) -> dict:
        """Move a draft into review, freezing references/aggregates/policy."""
        now = self._clock()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._get_row(dispute_id)
                if row is None:
                    self._conn.rollback()
                    raise DisputeNotFound(
                        f"budget dispute {dispute_id!r} does not exist"
                    )
                if row["status"] != STATUS_DRAFT:
                    self._conn.rollback()
                    raise self._denied(
                        "dispute_submit",
                        f"{REASON_STATUS_CONFLICT}_{row['status']}",
                        dispute_id=dispute_id, tenant=row["tenant"],
                        actor=actor, status=row["status"],
                    )
                self._do_submit(
                    self._conn, dispute_id,
                    retroactive=retroactive, actor=actor, now=now,
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            out = self._row(self._get_row(dispute_id))
            self._audit.record(
                "budget_dispute",
                {
                    "action": "submitted",
                    "dispute_id": dispute_id,
                    "tenant": out["tenant"],
                    "scope": "tenant",
                    "actor": actor,
                    "version": out["version"],
                    "frozen_policy": out["frozen_policy"],
                },
            )
            return out

    def _do_submit(
        self,
        conn: sqlite3.Connection,
        dispute_id: str,
        *,
        retroactive: bool,
        actor: str,
        now: float,
    ) -> None:
        """Freeze and flip draft -> pending_review inside the transaction."""
        row = conn.execute(
            "SELECT * FROM budget_disputes WHERE id = ?", (dispute_id,)
        ).fetchone()
        tenant = row["tenant"]
        ptype = row["period_type"]
        pstart = row["period_start"]
        refs = [
            r["event_id"]
            for r in conn.execute(
                "SELECT event_id FROM budget_dispute_refs"
                " WHERE dispute_id = ? ORDER BY position",
                (dispute_id,),
            )
        ]
        if not refs:
            raise self._denied(
                "dispute_submit", "no_events",
                dispute_id=dispute_id, tenant=tenant,
            )

        period_open = pstart == period_start(now, ptype)
        if retroactive and period_open:
            # Retroactive adjustments exist to correct closed, frozen
            # periods; an open period is corrected through the live
            # projection.
            raise self._denied(
                "dispute_submit", REASON_PERIOD_OPEN,
                dispute_id=dispute_id, tenant=tenant,
                period=period_label(pstart, ptype),
            )
        if not retroactive and not period_open:
            # A non-retroactive adjustment is defined as changing the gate
            # projection; the gate no longer serves a closed period, so the
            # historical freeze must not be rewritten.
            raise self._denied(
                "dispute_submit", REASON_FROZEN_PERIOD,
                dispute_id=dispute_id, tenant=tenant,
                period=period_label(pstart, ptype),
            )

        events_json, aggregates, policy_wrap, _frozen = self._freeze(
            conn, tenant=tenant, start=pstart, period_type=ptype,
            event_ids=refs, now=now,
        )

        # The adjusted billed quantity may never go negative.
        adjusted_total = (
            float(aggregates["total_quantity"])
            + float(row["adjustment_quantity"])
        )
        if adjusted_total < -1e-9:
            raise self._denied(
                "dispute_submit", REASON_NEGATIVE_USAGE,
                dispute_id=dispute_id, tenant=tenant,
                raw_quantity=aggregates["total_quantity"],
                adjustment_quantity=row["adjustment_quantity"],
                adjusted_quantity=adjusted_total,
            )

        version = row["version"] + 1
        conn.execute(
            "UPDATE budget_disputes SET status=?, retroactive=?,"
            " event_count=?, frozen_events=?, frozen_aggregates=?,"
            " frozen_policy=?, frozen_at=?, submitted_by=?, submitted_at=?,"
            " version=?, updated_at=? WHERE id=?",
            (
                STATUS_PENDING, 1 if retroactive else 0, len(refs),
                events_json,
                json.dumps(aggregates, sort_keys=True),
                json.dumps(policy_wrap, sort_keys=True),
                now, actor, now, version, now, dispute_id,
            ),
        )
        self._append_event(
            conn, dispute_id, ts=now, actor=actor, action="submitted",
            from_status=STATUS_DRAFT if row["status"] == STATUS_DRAFT else None,
            to_status=STATUS_PENDING, version=version,
            details={
                "retroactive": retroactive,
                "event_ids": refs,
                "raw_quantity": aggregates["total_quantity"],
                "adjusted_quantity": adjusted_total,
            },
        )

    # -- review ---------------------------------------------------------------

    def decide(
        self,
        dispute_id: str,
        approve: bool,
        *,
        actor: str,
        comment: Optional[str] = None,
        expected_version: Optional[int] = None,
    ) -> dict:
        """Approve or reject a pending dispute; a different admin decides."""
        now = self._clock()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._get_row(dispute_id)
                if row is None:
                    self._conn.rollback()
                    raise DisputeNotFound(
                        f"budget dispute {dispute_id!r} does not exist"
                    )
                # Separation of duties, audited like override self-approval.
                if actor not in ("bootstrap", "open") and actor == row["created_by"]:
                    self._conn.rollback()
                    raise self._denied(
                        "dispute_decide", REASON_SELF_APPROVAL,
                        dispute_id=dispute_id, tenant=row["tenant"],
                        actor=actor, created_by=row["created_by"],
                    )
                if expected_version is not None and expected_version != row["version"]:
                    self._conn.rollback()
                    raise MeteringConflict(
                        f"optimistic concurrency check failed for dispute "
                        f"{dispute_id!r}: expected version {expected_version}, "
                        f"current {row['version']}"
                    )
                if row["status"] != STATUS_PENDING:
                    self._conn.rollback()
                    raise self._denied(
                        "dispute_decide",
                        f"{REASON_STATUS_CONFLICT}_{row['status']}",
                        dispute_id=dispute_id, tenant=row["tenant"],
                        actor=actor, status=row["status"],
                    )
                new_status = STATUS_APPROVED if approve else STATUS_REJECTED
                version = row["version"] + 1
                self._conn.execute(
                    "UPDATE budget_disputes SET status=?, decided_by=?,"
                    " decided_at=?, decision_comment=?, version=?,"
                    " updated_at=? WHERE id=?",
                    (
                        new_status, actor, now, comment, version, now,
                        dispute_id,
                    ),
                )
                self._append_event(
                    self._conn, dispute_id, ts=now, actor=actor,
                    action="approved" if approve else "rejected",
                    from_status=STATUS_PENDING, to_status=new_status,
                    version=version, details={"comment": comment},
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            out = self._row(self._get_row(dispute_id))
            self._audit.record(
                "budget_dispute",
                {
                    "action": "approved" if approve else "rejected",
                    "dispute_id": dispute_id,
                    "tenant": out["tenant"],
                    "scope": "tenant",
                    "actor": actor,
                    "created_by": out["created_by"],
                    "comment": comment,
                    "version": version,
                },
            )
            return out

    # -- apply ----------------------------------------------------------------

    def apply(
        self,
        dispute_id: str,
        *,
        actor: str,
        expected_version: Optional[int] = None,
    ) -> dict:
        """Apply an approved dispute: ledger + projection + alerts, atomic."""
        now = self._clock()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._get_row(dispute_id)
                if row is None:
                    self._conn.rollback()
                    raise DisputeNotFound(
                        f"budget dispute {dispute_id!r} does not exist"
                    )
                if expected_version is not None and expected_version != row["version"]:
                    self._conn.rollback()
                    raise MeteringConflict(
                        f"optimistic concurrency check failed for dispute "
                        f"{dispute_id!r}: expected version {expected_version}, "
                        f"current {row['version']}"
                    )
                if row["status"] != STATUS_APPROVED:
                    self._conn.rollback()
                    raise self._denied(
                        "dispute_apply",
                        f"{REASON_STATUS_CONFLICT}_{row['status']}",
                        dispute_id=dispute_id, tenant=row["tenant"],
                        actor=actor, status=row["status"],
                    )
                tenant = row["tenant"]
                ptype = row["period_type"]
                pstart = row["period_start"]
                retroactive = bool(row["retroactive"])
                period_open = pstart == period_start(now, ptype)

                # The period kind must match what the dispute was filed for;
                # a retroactive dispute must still target a closed period
                # (the closed freeze must never be rewritten), and a normal
                # one must still target the open period.
                if retroactive and period_open:
                    self._conn.rollback()
                    raise self._denied(
                        "dispute_apply", REASON_PERIOD_OPEN,
                        dispute_id=dispute_id, tenant=tenant,
                        actor=actor,
                        period=period_label(pstart, ptype),
                    )
                if not retroactive and not period_open:
                    self._conn.rollback()
                    raise self._denied(
                        "dispute_apply", REASON_FROZEN_PERIOD,
                        dispute_id=dispute_id, tenant=tenant,
                        actor=actor,
                        period=period_label(pstart, ptype),
                    )

                existing = self._conn.execute(
                    "SELECT id FROM budget_adjustments WHERE dispute_id = ?",
                    (dispute_id,),
                ).fetchone()
                if existing is not None:
                    # Defense in depth: the status guard already prevents a
                    # second apply; never append a second ledger row.
                    self._conn.rollback()
                    raise self._denied(
                        "dispute_apply", "already_applied",
                        dispute_id=dispute_id, tenant=tenant, actor=actor,
                    )

                quantity = float(row["adjustment_quantity"])
                usage = self._metering._period_usage(tenant, pstart, ptype)
                raw = usage["raw"]
                adjusted = raw + quantity
                if adjusted < -1e-9:
                    self._conn.rollback()
                    raise self._denied(
                        "dispute_apply", REASON_NEGATIVE_USAGE,
                        dispute_id=dispute_id, tenant=tenant,
                        actor=actor, raw_quantity=raw,
                        adjustment_quantity=quantity,
                        adjusted_quantity=adjusted,
                    )

                frozen_policy_wrap = (
                    json.loads(row["frozen_policy"])
                    if row["frozen_policy"] is not None
                    else None
                )
                frozen_policy = (
                    frozen_policy_wrap.get("policy")
                    if frozen_policy_wrap is not None
                    else None
                )
                kind = "retroactive" if retroactive else "normal"
                adj_id = self._new_id_adj(self._conn)
                self._conn.execute(
                    "INSERT INTO budget_adjustments"
                    " (id, dispute_id, tenant, period_type, period_start, kind,"
                    "  direction, quantity, reverses_id, raw_quantity,"
                    "  adjusted_quantity, policy_origin, actor, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, 'apply', ?, NULL, ?, ?, ?, ?, ?)",
                    (
                        adj_id, dispute_id, tenant, ptype, pstart, kind,
                        quantity, raw, adjusted,
                        json.dumps(frozen_policy.get("origin"), sort_keys=True)
                        if frozen_policy
                        else None,
                        actor, now,
                    ),
                )

                fired_alerts: list[dict] = []
                policy_for_alerts: Optional[EffectivePolicy] = None
                if period_open:
                    # Rewrite the projection and re-evaluate thresholds
                    # against the new adjusted usage, all in this same
                    # transaction. Existing alerts are never deleted; only
                    # not-yet-fired crossings get appended.
                    self._metering._refresh_projection(
                        self._conn, tenant, pstart, ptype, now
                    )
                    live = self._metering._resolve_policy(tenant, now)
                    if live is not None and live.period_type == ptype:
                        policy_for_alerts = live
                        fired_alerts = self._metering._evaluate_thresholds(
                            tenant=tenant,
                            period_type=ptype,
                            amount=live.amount,
                            thresholds=list(live.alert_thresholds),
                            start=pstart,
                            used=adjusted,
                            event_id=None,
                            fired_at=now,
                            retroactive=False,
                            policy=live,
                        )
                # Closed + retroactive: projection and alerts are
                # deliberately untouched -- only the ledger row above is
                # appended, keeping the original alert facts intact.

                version = row["version"] + 1
                self._conn.execute(
                    "UPDATE budget_disputes SET status=?, applied_by=?,"
                    " applied_at=?, version=?, updated_at=? WHERE id=?",
                    (STATUS_APPLIED, actor, now, version, now, dispute_id),
                )
                self._append_event(
                    self._conn, dispute_id, ts=now, actor=actor,
                    action="applied", from_status=STATUS_APPROVED,
                    to_status=STATUS_APPLIED, version=version,
                    details={
                        "adjustment_id": adj_id,
                        "kind": kind,
                        "quantity": quantity,
                        "raw_quantity": raw,
                        "adjusted_quantity": adjusted,
                        "alerts_fired": [a["id"] for a in fired_alerts],
                    },
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            out = self._row(self._get_row(dispute_id))
            self._audit.record(
                "budget_dispute",
                {
                    "action": "applied",
                    "dispute_id": dispute_id,
                    "tenant": out["tenant"],
                    "scope": "tenant",
                    "actor": actor,
                    "retroactive": out["retroactive"],
                    "version": version,
                    "adjustment_id": adj_id,
                    "quantity": quantity,
                    "raw_quantity": raw,
                    "adjusted_quantity": adjusted,
                    "alerts_fired": [a["id"] for a in fired_alerts],
                },
            )
            for alert in fired_alerts:
                self._metering._audit_alert_fired(alert)
            return out

    def _new_id_adj(self, conn: sqlite3.Connection) -> str:
        while True:
            aid = "badj_" + secrets.token_urlsafe(12)
            if conn.execute(
                "SELECT 1 FROM budget_adjustments WHERE id = ?", (aid,)
            ).fetchone() is None:
                return aid

    # -- revoke ---------------------------------------------------------------

    def revoke(
        self,
        dispute_id: str,
        *,
        actor: str,
        reason: Optional[str] = None,
        expected_version: Optional[int] = None,
    ) -> dict:
        """Cancel a draft/pending/approved dispute, or reverse an applied one.

        Reversing an applied dispute is only possible while its period is
        still open: the reverse is an immutable ledger row appended in the
        same transaction as the projection rewrite (net delta back to the
        raw usage), so the audit trail always explains the correction.
        Applied retroactive adjustments to closed periods cannot be revoked.
        """
        now = self._clock()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._get_row(dispute_id)
                if row is None:
                    self._conn.rollback()
                    raise DisputeNotFound(
                        f"budget dispute {dispute_id!r} does not exist"
                    )
                if expected_version is not None and expected_version != row["version"]:
                    self._conn.rollback()
                    raise MeteringConflict(
                        f"optimistic concurrency check failed for dispute "
                        f"{dispute_id!r}: expected version {expected_version}, "
                        f"current {row['version']}"
                    )
                status = row["status"]
                if status not in (
                    STATUS_DRAFT,
                    STATUS_PENDING,
                    STATUS_APPROVED,
                    STATUS_APPLIED,
                ):
                    self._conn.rollback()
                    raise self._denied(
                        "dispute_revoke",
                        f"{REASON_STATUS_CONFLICT}_{status}",
                        dispute_id=dispute_id, tenant=row["tenant"],
                        actor=actor, status=status,
                    )

                reverse_id: Optional[str] = None
                raw = adjusted_after = None
                if status == STATUS_APPLIED:
                    tenant = row["tenant"]
                    ptype = row["period_type"]
                    pstart = row["period_start"]
                    period_open = pstart == period_start(now, ptype)
                    if bool(row["retroactive"]) or not period_open:
                        self._conn.rollback()
                        raise self._denied(
                            "dispute_revoke", REASON_FROZEN_PERIOD,
                            dispute_id=dispute_id, tenant=tenant,
                            actor=actor,
                            period=period_label(pstart, ptype),
                            retroactive=bool(row["retroactive"]),
                        )
                    applied = self._conn.execute(
                        "SELECT * FROM budget_adjustments"
                        " WHERE dispute_id = ? AND direction = 'apply'",
                        (dispute_id,),
                    ).fetchone()
                    usage = self._metering._period_usage(tenant, pstart, ptype)
                    raw = usage["raw"]
                    adjusted_after = raw  # net adjustment returns to zero
                    reverse_id = self._new_id_adj(self._conn)
                    self._conn.execute(
                        "INSERT INTO budget_adjustments"
                        " (id, dispute_id, tenant, period_type, period_start,"
                        "  kind, direction, quantity, reverses_id, raw_quantity,"
                        "  adjusted_quantity, policy_origin, actor, created_at)"
                        " VALUES (?, ?, ?, ?, ?, ?, 'reverse', ?, ?, ?, ?, ?, ?, ?)",
                        (
                            reverse_id, dispute_id, tenant, ptype, pstart,
                            applied["kind"], -float(applied["quantity"]),
                            applied["id"], raw, adjusted_after,
                            applied["policy_origin"], actor, now,
                        ),
                    )
                    self._metering._refresh_projection(
                        self._conn, tenant, pstart, ptype, now
                    )

                version = row["version"] + 1
                self._conn.execute(
                    "UPDATE budget_disputes SET status=?, revoked_by=?,"
                    " revoked_at=?, revoke_reason=?, version=?,"
                    " updated_at=? WHERE id=?",
                    (
                        STATUS_REVOKED, actor, now, reason, version, now,
                        dispute_id,
                    ),
                )
                self._append_event(
                    self._conn, dispute_id, ts=now, actor=actor,
                    action="revoked", from_status=status,
                    to_status=STATUS_REVOKED, version=version,
                    details={
                        "reason": reason,
                        "reverse_adjustment_id": reverse_id,
                    },
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            out = self._row(self._get_row(dispute_id))
            self._audit.record(
                "budget_dispute",
                {
                    "action": "revoked",
                    "dispute_id": dispute_id,
                    "tenant": out["tenant"],
                    "scope": "tenant",
                    "actor": actor,
                    "from_status": status,
                    "reason": reason,
                    "reverse_adjustment_id": reverse_id,
                    "version": version,
                },
            )
            return out

    # -- adjusted-budget view -------------------------------------------------

    def adjusted_budget(
        self,
        tenant: str,
        period_type: str,
        period_started_at: float,
    ) -> dict:
        """Raw/adjusted usage and the adjustment ledger for one period."""
        if period_type not in PERIOD_TYPES:
            raise MeteringValidationError(
                f"period_type must be one of {PERIOD_TYPES}"
            )
        tenant = (tenant or "").strip().lower()
        start = period_start(period_started_at, period_type)
        with self._lock:
            usage = self._metering._period_usage(
                tenant, start, period_type, include_retroactive=True
            )
            rows = self._conn.execute(
                "SELECT * FROM budget_adjustments"
                " WHERE tenant = ? AND period_type = ? AND period_start = ?"
                " ORDER BY created_at, id",
                (tenant, period_type, start),
            ).fetchall()
            adjustments = [self._adjustment_row(r) for r in rows]
            disputes = [
                self._row(r)
                for r in self._conn.execute(
                    "SELECT * FROM budget_disputes"
                    " WHERE tenant = ? AND period_type = ? AND period_start = ?"
                    " AND status IN ('approved', 'applied')"
                    " ORDER BY created_at, id",
                    (tenant, period_type, start),
                ).fetchall()
            ]
        return {
            "tenant": tenant,
            "period_type": period_type,
            "period_start": start,
            "period_end": next_period_start(start, period_type),
            "period": period_label(start, period_type),
            "raw_used": usage["raw"],
            "normal_adjustment": usage["normal_adjustment"],
            "adjusted_used": usage["adjusted"],
            "retroactive_adjustment": usage["retroactive_adjustment"],
            "adjusted_including_retroactive": usage[
                "adjusted_including_retroactive"
            ],
            "adjustments": adjustments,
            "open_disputes": disputes,
        }
