"""Alert policy drills: isolated replay of the alert pipeline.

An alert-policy drill lets an administrator check how *one* subscription
would have behaved over a *frozen* slice of the real health history. At
creation time the drill permanently saves:

- the full subscription snapshot at a chosen ``sub_version`` (including a
  copy of the signing secret, which is never exposed on the read API);
- an ordered slice of real ``health_check_history`` rows (matched
  transitions plus every check row after the first match, so consecutive
  threshold streaks can be confirmed exactly like production), copied
  verbatim;
- a scripted webhook send-outcome plan (which attempts fail) and a fixed
  simulated clock anchor.

Advancing a drill feeds the next frozen history rows into a private copy
of the production alert semantics (target/source matching, consecutive
threshold confirmation, silence-window suppression, exponential-backoff
retries). A clock-only advance (``to_time``) moves the simulated clock
without consuming a row, so retries mature and silence windows expire;
``settle`` pumps the simulated queue through every future retry deadline.

Isolation
---------
The replay engine touches **only** the ``alert_drill_*`` tables. It never
writes ``health_check_history`` / ``health_alert_events`` /
``health_alert_deliveries``, never changes live health state, never calls
the real audit log and never performs network I/O: every "webhook" is
appended to the per-drill simulated inbox, which is queryable through the
API. The simulated clock is a stored scalar driven solely by advances
(event time, never backwards); the wall clock is used only for
``created_at`` / ``recorded_at`` bookkeeping.

Lifecycle
---------
``ready -> running <-> paused -> completed``. The drill completes once all
frozen rows are consumed and no outbox work is open; clock-only advances
stay valid in ``completed`` so an already-finished timeline can still be
inspected at a later instant. ``reset`` starts a new *run epoch* back at
``ready``; prior-epoch rows are kept (epoch-scoped) for the audit trail
and old idempotency keys cannot replay across epochs. State, the outbox,
the inbox, idempotency keys and the one-shot report are all SQLite-backed,
so a replay resumes unchanged after a restart. Concurrent advances
serialize on the store lock; ``expected_version`` conflicts return 409 and
an ``Idempotency-Key`` replays the original response.

The report permanently captures the frozen input, every per-step
suppression/retry decision, final statistics and a diff against what the
live pipeline actually did for the same transitions.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from typing import Callable, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .health_alerts import (
    ACTIVE_DELIVERY_STATUSES,
    EV_MAINTENANCE_BEGIN,
    EV_MAINTENANCE_END,
    EV_OVERRIDE_EXPIRED,
    EV_RECOVERED,
    EV_UNHEALTHY,
    ST_DEAD,
    ST_FAILED,
    ST_PENDING,
    ST_SUCCEEDED,
    ST_SUPERSEDED,
    ST_SUPPRESSED,
    ST_UNCONFIRMED,
    TRANSITION_EVENT_MAP,
    SendOutcome,
)

# -- lifecycle / limits -------------------------------------------------------

STATUS_READY = "ready"
STATUS_RUNNING = "running"
STATUS_PAUSED = "paused"
STATUS_COMPLETED = "completed"
LIFECYCLE = frozenset(
    {STATUS_READY, STATUS_RUNNING, STATUS_PAUSED, STATUS_COMPLETED}
)

KIND_EVENT = "event"
KIND_CLOCK = "clock"

DELIVERY_STATUSES = frozenset(
    {
        ST_UNCONFIRMED, ST_SUPPRESSED, ST_PENDING, ST_SUCCEEDED, ST_FAILED,
        ST_DEAD, ST_SUPERSEDED,
    }
)

MAX_DETAIL_CHARS = 1000
DEFAULT_MAX_EVENTS = 2000
HARD_MAX_EVENTS = 10_000
#: Safety bound for a ``settle`` pump (retries always end dead eventually).
SETTLE_PUMP_LIMIT = 10_000

# -- refusal codes (also written to alert_drill_audit) ------------------------

CODE_NOT_FOUND = "alert_drill_not_found"
CODE_BAD_CREATE_PAYLOAD = "invalid_alert_drill"
CODE_SUB_NOT_FOUND = "subscription_not_found"
CODE_SUB_DELETED = "subscription_deleted"
CODE_SUB_VERSION_NOT_FOUND = "subscription_version_not_found"
CODE_NO_HISTORY = "no_history_rows_selected"
CODE_HISTORY_RANGE = "empty_history_range"
CODE_TOO_MANY_ROWS = "too_many_history_rows"
CODE_BAD_ADVANCE_PAYLOAD = "invalid_advance"
CODE_STATUS_CONFLICT = "status_conflict"
CODE_VERSION_CONFLICT = "expected_version"
CODE_ROWS_EXHAUSTED = "frozen_rows_exhausted"
CODE_IDEMPOTENCY_CONFLICT = "idempotency_conflict"


# -- errors -------------------------------------------------------------------


class AlertDrillError(Exception):
    code = "alert_drill_error"
    status_code = 409

    def __init__(self, message: str, *, code: Optional[str] = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class AlertDrillNotFound(AlertDrillError):
    code = CODE_NOT_FOUND
    status_code = 404


class AlertDrillConflict(AlertDrillError):
    code = "alert_drill_conflict"
    status_code = 409


class AlertDrillValidation(AlertDrillError):
    code = CODE_BAD_CREATE_PAYLOAD
    status_code = 422


# -- request models -----------------------------------------------------------


_EVENT_TYPES = (
    EV_UNHEALTHY, EV_RECOVERED, EV_MAINTENANCE_BEGIN,
    EV_MAINTENANCE_END, EV_OVERRIDE_EXPIRED,
)


class SendRuleIn(BaseModel):
    """One scripted webhook outcome for the simulated sender.

    Rules are evaluated in order; the first matching rule wins. A rule with
    ``attempt: null`` matches every attempt (a common ``default``); more
    specific rules pin the 1-based attempt number and optionally the event
    type/target.
    """

    model_config = ConfigDict(extra="forbid")

    result: str = Field(description="ok | fail")
    status_code: Optional[int] = Field(default=None, ge=100, le=599)
    error: Optional[str] = None
    attempt: Optional[int] = Field(default=None, ge=1)
    event_type: Optional[str] = None
    target_id: Optional[str] = None

    @field_validator("result")
    @classmethod
    def _result(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in ("ok", "fail"):
            raise ValueError("result must be 'ok' or 'fail'")
        return v

    @field_validator("error")
    @classmethod
    def _error(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > MAX_DETAIL_CHARS:
            return v[:MAX_DETAIL_CHARS]
        return v

    @field_validator("event_type")
    @classmethod
    def _event_type(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if v not in _EVENT_TYPES:
            raise ValueError(f"unknown event_type {v!r}")
        return v

    def matches(self, *, attempt: int, event_type: str, target_id: str) -> bool:
        if self.attempt is not None and self.attempt != attempt:
            return False
        if self.event_type is not None and self.event_type != event_type:
            return False
        if self.target_id is not None and self.target_id != target_id:
            return False
        return True

    def outcome(self) -> SendOutcome:
        if self.result == "ok":
            return SendOutcome(
                ok=True,
                status_code=self.status_code if self.status_code is not None else 200,
            )
        return SendOutcome(
            ok=False,
            status_code=self.status_code,
            error=(self.error or "scripted failure"),
        )


class AlertDrillCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subscription_id: str = Field(min_length=1)
    sub_version: Optional[int] = Field(
        default=None,
        ge=1,
        description="revision to freeze; defaults to the current revision",
    )
    drill_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: str = ""
    since: Optional[float] = Field(default=None, allow_inf_nan=False)
    until: Optional[float] = Field(default=None, allow_inf_nan=False)
    start_at: Optional[float] = Field(
        default=None,
        allow_inf_nan=False,
        description="simulated clock anchor; defaults to the first row ts",
    )
    max_events: int = Field(default=DEFAULT_MAX_EVENTS, ge=1, le=HARD_MAX_EVENTS)
    send_script: list[SendRuleIn] = Field(default_factory=list)
    default_outcome: str = Field(
        default="ok",
        description="simulated send result when no send_script rule matches",
    )

    @field_validator("subscription_id")
    @classmethod
    def _sub(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("subscription_id is required")
        return v

    @field_validator("default_outcome")
    @classmethod
    def _default(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in ("ok", "fail"):
            raise ValueError("default_outcome must be 'ok' or 'fail'")
        return v


class AlertDrillAdvanceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: Optional[int] = Field(default=None, ge=1)
    steps: int = Field(
        default=1,
        ge=1,
        le=100,
        description="frozen history rows to consume in this advance",
    )
    to_time: Optional[float] = Field(
        default=None,
        allow_inf_nan=False,
        description="clock-only advance: move the simulated clock here "
        "(releasing silence / maturing retries) without consuming a row",
    )
    settle: bool = Field(
        default=False,
        description="after consuming rows, pump through every future retry/"
        "silence deadline until no more deliveries are actionable",
    )


class AlertDrillTransitionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: Optional[int] = Field(default=None, ge=1)
    reason: Optional[str] = Field(default=None, max_length=500)


# -- frozen subscription snapshot ---------------------------------------------


def snapshot_payload(sub: dict) -> dict:
    """Public snapshot shape, mirrored from the production AlertStore."""
    return {
        "sub_id": sub["sub_id"],
        "sub_version": sub["sub_version"],
        "target_id": sub["target_id"],
        "sources": sub["sources"],
        "consecutive_threshold": sub["consecutive_threshold"],
        "webhook_url": sub["webhook_url"],
        "headers": sub["headers"],
        "has_signing_secret": sub.get("signing_secret") is not None,
        "silence_windows": sub["silence_windows"],
        "max_retries": sub["max_retries"],
        "backoff_base_seconds": sub["backoff_base_seconds"],
        "backoff_max_seconds": sub["backoff_max_seconds"],
    }


def build_http_request(
    *,
    snapshot: dict,
    payload: dict,
    attempt: int,
    signing_secret: Optional[str] = None,
) -> tuple[str, dict, bytes]:
    """Assemble (url, headers, body) using production webhook conventions."""
    body_payload = dict(payload)
    body_payload["attempt"] = attempt
    body = json.dumps(body_payload, sort_keys=True).encode()
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "georesolve-health-alerts/1.0",
        "X-Georesolve-Event-Uid": payload["id"],
        "X-Georesolve-Event-Type": payload["type"],
        "X-Georesolve-Delivery-Uid": payload["delivery_uid"],
        "Idempotency-Key": payload["delivery_uid"],
        "X-Georesolve-Subscription": (
            f"{snapshot['sub_id']}/{snapshot['sub_version']}"
        ),
        "X-Georesolve-Drill": payload["drill_id"],
    }
    if payload.get("replayed_count"):
        headers["X-Georesolve-Replay-Count"] = str(payload["replayed_count"])
    if signing_secret:
        headers["X-Georesolve-Signature"] = "sha256=" + hmac.new(
            signing_secret.encode(), body, hashlib.sha256
        ).hexdigest()
    for k, v in snapshot.get("headers", {}).items():
        headers[k] = v
    return snapshot["webhook_url"], headers, body


def _active_window(windows: list[dict], now: float):
    for w in windows:
        if w["start"] <= now < w["end"]:
            return w
    return None


def _window_record(window: Optional[dict]) -> Optional[dict]:
    if window is None:
        return None
    return {"start": window["start"], "end": window["end"],
            "note": window.get("note", "")}


# -- module helpers ------------------------------------------------------------


def _row_to_sub(row: sqlite3.Row) -> dict:
    return {
        "sub_id": row["sub_id"],
        "sub_version": row["sub_version"],
        "target_id": row["target_id"],
        "sources": json.loads(row["sources"]),
        "consecutive_threshold": row["consecutive_threshold"],
        "webhook_url": row["webhook_url"],
        "headers": json.loads(row["headers"]),
        "signing_secret": row["signing_secret"],
        "silence_windows": json.loads(row["silence_windows"]),
        "max_retries": row["max_retries"],
        "backoff_base_seconds": row["backoff_base_seconds"],
        "backoff_max_seconds": row["backoff_max_seconds"],
        "enabled": bool(row["enabled"]),
        "deleted": bool(row["deleted"]),
    }


def history_row_to_dict(r: sqlite3.Row) -> dict:
    """Copy a real history row into a frozen, self-contained dict."""
    return {
        "id": r["id"],
        "target_id": r["target_id"],
        "seq": r["seq"],
        "kind": r["kind"],
        "ts": r["ts"],
        "started_at": r["started_at"],
        "policy_version": r["policy_version"],
        "state_version": r["state_version"],
        "verdict": r["verdict"],
        "failure_reason": r["failure_reason"],
        "effective_healthy": (
            None if r["effective_healthy"] is None
            else bool(r["effective_healthy"])
        ),
        "effective_source": r["effective_source"],
        "transition": (
            None
            if r["transition_reason"] is None
            else {
                "reason": r["transition_reason"],
                "from_healthy": (
                    None if r["from_healthy"] is None
                    else bool(r["from_healthy"])
                ),
                "to_healthy": (
                    None if r["to_healthy"] is None
                    else bool(r["to_healthy"])
                ),
                "from_source": r["from_source"],
                "to_source": r["to_source"],
                "from_policy_version": r["from_policy_version"],
                "to_policy_version": r["to_policy_version"],
            }
        ),
        "detail": json.loads(r["detail"] or "{}"),
    }


def _build_event_payload(
    *,
    event_uid: str,
    history_row: dict,
    event_type: str,
    source: str,
    detail: dict,
    sub: dict,
    delivery_uid: str,
    drill_id: str,
) -> dict:
    """Frozen webhook body, shaped exactly like the production payload."""
    transition = history_row.get("transition") or {}
    return {
        "id": event_uid,
        "type": event_type,
        "target_id": history_row["target_id"],
        "source": source,
        "ts": history_row["ts"],
        "transition_seq": history_row["seq"],
        "state_version": history_row.get("state_version"),
        "policy_version": history_row["policy_version"],
        "from_healthy": transition.get("from_healthy"),
        "to_healthy": transition.get("to_healthy"),
        "detail": detail,
        "subscription": {"id": sub["sub_id"], "version": sub["sub_version"]},
        "delivery_uid": delivery_uid,
        "drill_id": drill_id,
    }


def _empty_stats() -> dict:
    return {
        "events_by_status": {},
        "deliveries_by_status": {},
        "attempts": 0,
        "inbox_messages": 0,
        "succeeded": 0,
        "dead": 0,
        "suppressed_now": 0,
        "pending_now": 0,
        "unconfirmed_now": 0,
    }


def _empty_step_record(kind: str, sim_time: Optional[float]) -> dict:
    return {
        "kind": kind,
        "sim_time": sim_time,
        "rows": [],
        "sends": [],
        "suppression_releases": [],
        "activations": [],
        "superseded": [],
        "settled_at": None,
    }


def _has_open_work(stats: dict) -> bool:
    """Time-actionable outbox work a future clock advance could still change.

    Pending/failed deliveries wait on a send/backoff instant and suppressed
    deliveries wait on a window end; unconfirmed streaks are deliberately
    excluded because they can only be advanced by further *check rows*, and
    when the frozen slice is exhausted no such row will ever arrive, so an
    unconfirmed delivery left at the end is a final 'never fired' outcome.
    """
    return bool(stats.get("pending_now") or stats.get("suppressed_now"))


def public_step_result(result: dict) -> dict:
    """Stable projection of a recorded step (no secrets live in it)."""
    return result


def _public_delivery(d: dict) -> dict:
    return {
        k: v
        for k, v in d.items()
        if k not in ("signing_secret", "event_payload", "drill_id", "run_epoch")
    }


# -- the store ----------------------------------------------------------------


class AlertDrillStore:
    """Create, drive and inspect isolated alert-policy replays."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        clock: Callable[[], float] = time.time,
    ):
        self._conn = conn
        self._clock = clock
        self._lock = threading.RLock()

    # -- small helpers -------------------------------------------------------

    def _audit(
        self,
        drill_id: Optional[str],
        action: str,
        details: dict,
        *,
        version: Optional[int] = None,
        actor: Optional[str] = None,
        ts: Optional[float] = None,
    ) -> None:
        self._conn.execute(
            "INSERT INTO alert_drill_audit"
            " (drill_id, ts, actor, action, version, details)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                drill_id,
                self._clock() if ts is None else ts,
                actor,
                action,
                version,
                json.dumps(details, sort_keys=True, default=str),
            ),
        )

    def _refuse(
        self,
        drill_id: Optional[str],
        action: str,
        code: str,
        detail: str,
        *,
        version: Optional[int] = None,
        actor: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> AlertDrillConflict:
        details = {"code": code, "detail": detail}
        if extra:
            details.update(extra)
        with self._lock:
            self._audit(drill_id, action, details, version=version, actor=actor)
            self._conn.commit()
        return AlertDrillConflict(detail, code=code)

    # -- frozen subscription / history selection -----------------------------

    def _load_subscription(self, sub_id: str, sub_version: Optional[int]) -> dict:
        row = self._conn.execute(
            "SELECT * FROM health_alert_subscriptions WHERE sub_id = ?",
            (sub_id,),
        ).fetchone()
        if row is None:
            raise AlertDrillNotFound(
                f"no subscription {sub_id!r}", code=CODE_SUB_NOT_FOUND
            )
        if bool(row["deleted"]):
            raise AlertDrillConflict(
                f"subscription {sub_id!r} was deleted", code=CODE_SUB_DELETED
            )
        version = sub_version if sub_version is not None else row["sub_version"]
        if version == int(row["sub_version"]):
            return _row_to_sub(row)
        if version > int(row["sub_version"]):
            raise AlertDrillNotFound(
                f"subscription {sub_id!r} has no revision {version}",
                code=CODE_SUB_VERSION_NOT_FOUND,
            )
        rev = self._conn.execute(
            "SELECT payload, action FROM health_alert_sub_revisions"
            " WHERE sub_id = ? AND sub_version = ?",
            (sub_id, version),
        ).fetchone()
        if rev is None:
            raise AlertDrillNotFound(
                f"subscription {sub_id!r} has no revision {version}",
                code=CODE_SUB_VERSION_NOT_FOUND,
            )
        if rev["action"] == "deleted":
            raise AlertDrillConflict(
                f"subscription {sub_id!r} revision {version} is a deletion",
                code=CODE_SUB_DELETED,
            )
        # Revision payloads are SubscriptionUpsertIn.model_dump(); normalize
        # them to the live-row shape the replay engine consumes.
        p = json.loads(rev["payload"])
        return {
            "sub_id": sub_id,
            "sub_version": version,
            "target_id": p["target_id"],
            "sources": p["sources"],
            "consecutive_threshold": p["consecutive_threshold"],
            "webhook_url": p["webhook_url"],
            "headers": p["headers"],
            "signing_secret": p.get("signing_secret"),
            "silence_windows": [dict(w) for w in p["silence_windows"]],
            "max_retries": p["max_retries"],
            "backoff_base_seconds": p["backoff_base_seconds"],
            "backoff_max_seconds": p["backoff_max_seconds"],
            "enabled": bool(p.get("enabled", True)),
            "deleted": False,
        }

    def _select_history(
        self, sub: dict, spec: AlertDrillCreateIn
    ) -> list[dict]:
        """Pick the frozen, ordered history rows this drill will replay.

        This mirrors the production ingestor exactly: include *every* check
        row in the window (a check only touches an existing unconfirmed
        streak for its target, so extra rows are harmless) plus every
        transition that the subscription's target/source filter would turn
        into an event. Global ``id`` order preserves interleaving across
        targets for wildcard subscriptions. Starting from the beginning of
        the window means streaks already in progress at ``since`` are not
        silently truncated.
        """
        target_id = sub["target_id"]
        clauses: list[str] = []
        args: list = []
        if target_id != "*":
            clauses.append("target_id = ?")
            args.append(target_id)
        if spec.since is not None:
            clauses.append("ts >= ?")
            args.append(spec.since)
        if spec.until is not None:
            clauses.append("ts < ?")
            args.append(spec.until)
        sql = "SELECT * FROM health_check_history"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id ASC LIMIT ?"
        # Fetch one beyond the cap so an over-large slice is a clear refusal
        # rather than a silently truncated replay.
        args.append(spec.max_events + 1)
        rows = self._conn.execute(sql, args).fetchall()
        if len(rows) > spec.max_events:
            raise AlertDrillValidation(
                f"more than {spec.max_events} history rows match; narrow the "
                "time range or raise max_events",
                code=CODE_TOO_MANY_ROWS,
            )

        sources = set(sub["sources"])
        selected: list[dict] = []
        for r in rows:
            if r["kind"] == "check":
                selected.append(history_row_to_dict(r))
                continue
            mapping = TRANSITION_EVENT_MAP.get(r["transition_reason"])
            if mapping is None:
                continue
            _event_type, source = mapping
            if "*" in sources or source in sources:
                selected.append(history_row_to_dict(r))
        return selected

    # -- create --------------------------------------------------------------

    def create(
        self, spec: AlertDrillCreateIn, *, actor: Optional[str] = None
    ) -> dict:
        now = self._clock()
        drill_id = (spec.drill_id or f"adrill_{secrets.token_urlsafe(12)}").strip()

        sub = self._load_subscription(spec.subscription_id, spec.sub_version)
        if spec.since is not None and spec.until is not None \
                and spec.until <= spec.since:
            raise AlertDrillValidation(
                "until must be greater than since", code=CODE_HISTORY_RANGE
            )

        rows = self._select_history(sub, spec)
        if not rows:
            raise AlertDrillConflict(
                "no health history rows match this subscription/source/time "
                "window; the drill would replay nothing",
                code=CODE_NO_HISTORY,
            )

        if spec.start_at is not None and spec.start_at > rows[0]["ts"]:
            raise AlertDrillValidation(
                "start_at must not be later than the first history row ts",
                code=CODE_HISTORY_RANGE,
            )
        base_sim_time = (
            spec.start_at if spec.start_at is not None else rows[0]["ts"]
        )

        frozen_input = {
            "subscription": snapshot_payload(sub),
            # The secret is frozen alongside the input but the public view
            # below only exposes the subset in ``subscription``; the read API
            # can therefore serialize the whole frozen_input without leaking.
            "_signing_secret": sub.get("signing_secret"),
            "signing_secret_present": sub.get("signing_secret") is not None,
            "history_rows": rows,
            "history_row_ids": [r["id"] for r in rows],
            "selection": {
                "since": spec.since,
                "until": spec.until,
                "max_events": spec.max_events,
                "target_id": sub["target_id"],
                "sources": sub["sources"],
            },
            "base_sim_time": base_sim_time,
            "send_script": [r.model_dump() for r in spec.send_script],
            "default_outcome": spec.default_outcome,
        }
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO alert_drills"
                    " (id, status, run_epoch, version, sub_id, sub_version,"
                    "  input, cursor, total_rows, sim_clock, base_sim_time,"
                    "  stats, description, created_by, created_at,"
                    "  started_at, paused_at, completed_at, updated_at)"
                    " VALUES (?, ?, 1, 1, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?,"
                    " ?, NULL, NULL, NULL, ?)",
                    (
                        drill_id,
                        STATUS_READY,
                        sub["sub_id"],
                        sub["sub_version"],
                        json.dumps(frozen_input, sort_keys=True),
                        len(rows),
                        base_sim_time,  # sim_clock starts at the frozen anchor
                        base_sim_time,
                        json.dumps(_empty_stats(), sort_keys=True),
                        spec.description,
                        actor,
                        now,  # created_at
                        now,  # updated_at
                    ),
                )
                self._audit(
                    drill_id,
                    "alert_drill_created",
                    {
                        "sub_id": sub["sub_id"],
                        "sub_version": sub["sub_version"],
                        "history_rows": len(rows),
                        "base_sim_time": base_sim_time,
                    },
                    version=1,
                    actor=actor,
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise AlertDrillConflict(
                    f"alert drill id {drill_id!r} already exists",
                    code="alert_drill_id_conflict",
                ) from exc
        return self.get(drill_id)

    # -- loading / views -----------------------------------------------------

    def _row(self, drill_id: str) -> sqlite3.Row:
        row = self._conn.execute(
            "SELECT * FROM alert_drills WHERE id = ?", (drill_id,)
        ).fetchone()
        if row is None:
            raise AlertDrillNotFound(f"alert drill {drill_id!r} does not exist")
        return row

    def _load(self, drill_id: str) -> dict:
        return self._row_to_dict(self._row(drill_id))

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "status": row["status"],
            "run_epoch": row["run_epoch"],
            "version": row["version"],
            "sub_id": row["sub_id"],
            "sub_version": row["sub_version"],
            "input": json.loads(row["input"]),
            "cursor": row["cursor"],
            "total_rows": row["total_rows"],
            "sim_clock": row["sim_clock"],
            "base_sim_time": row["base_sim_time"],
            "stats": json.loads(row["stats"]),
            "description": row["description"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "paused_at": row["paused_at"],
            "completed_at": row["completed_at"],
            "updated_at": row["updated_at"],
        }

    def get(self, drill_id: str) -> dict:
        with self._lock:
            d = self._load(drill_id)
            return self._public(d, include_steps=False)

    def list_drills(
        self,
        *,
        status: Optional[str] = None,
        sub_id: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        if status is not None and status not in LIFECYCLE:
            raise AlertDrillValidation(f"unknown status {status!r}")
        sql = "SELECT * FROM alert_drills WHERE 1=1"
        args: list = []
        if status:
            sql += " AND status = ?"
            args.append(status)
        if sub_id:
            sql += " AND sub_id = ?"
            args.append(sub_id)
        sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
            return [self._summary(self._row_to_dict(r)) for r in rows]

    @staticmethod
    def _summary(d: dict) -> dict:
        return {
            "id": d["id"],
            "status": d["status"],
            "run_epoch": d["run_epoch"],
            "version": d["version"],
            "sub_id": d["sub_id"],
            "sub_version": d["sub_version"],
            "cursor": d["cursor"],
            "total_rows": d["total_rows"],
            "sim_clock": d["sim_clock"],
            "base_sim_time": d["base_sim_time"],
            "stats": d["stats"],
            "description": d["description"],
            "created_by": d["created_by"],
            "created_at": d["created_at"],
            "started_at": d["started_at"],
            "paused_at": d["paused_at"],
            "completed_at": d["completed_at"],
            "updated_at": d["updated_at"],
        }

    def _frozen_input_view(self, frozen_input: dict) -> dict:
        return {
            "subscription": frozen_input["subscription"],
            "signing_secret_present": frozen_input["signing_secret_present"],
            "history_row_ids": frozen_input["history_row_ids"],
            "history_row_count": len(frozen_input["history_rows"]),
            "selection": frozen_input["selection"],
            "base_sim_time": frozen_input["base_sim_time"],
            "send_script": frozen_input["send_script"],
            "default_outcome": frozen_input["default_outcome"],
        }

    def _public(self, d: dict, *, include_steps: bool) -> dict:
        out = self._summary(d)
        out["frozen_input"] = self._frozen_input_view(d["input"])
        with self._lock:
            out["events"] = self._events(d["id"], d["run_epoch"])
            out["deliveries"] = [
                _public_delivery(self._delivery_dict(r))
                for r in self._delivery_rows(d["id"], d["run_epoch"])
            ]
            out["inbox_count"] = self._conn.execute(
                "SELECT COUNT(*) AS c FROM alert_drill_inbox"
                " WHERE drill_id = ? AND run_epoch = ?",
                (d["id"], d["run_epoch"]),
            ).fetchone()["c"]
            if include_steps:
                out["steps"] = self.steps(d)
        return out

    # -- simulation primitives -----------------------------------------------

    def _events(self, drill_id: str, epoch: int) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM alert_drill_events"
            " WHERE drill_id = ? AND run_epoch = ? ORDER BY id ASC",
            (drill_id, epoch),
        ).fetchall()
        return [
            {
                "id": r["id"],
                "event_uid": r["event_uid"],
                "history_id": r["history_id"],
                "target_id": r["target_id"],
                "event_type": r["event_type"],
                "source": r["source"],
                "ts": r["ts"],
                "status": r["status"],
                "confirm_count": r["confirm_count"],
                "threshold": r["threshold"],
                "activated_at": r["activated_at"],
                "detail": json.loads(r["detail"]),
            }
            for r in rows
        ]

    def _delivery_rows(self, drill_id: str, epoch: int) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT * FROM alert_drill_deliveries"
            " WHERE drill_id = ? AND run_epoch = ? ORDER BY id ASC",
            (drill_id, epoch),
        ).fetchall()

    @staticmethod
    def _delivery_dict(r: sqlite3.Row) -> dict:
        return {
            "id": r["id"],
            "drill_id": r["drill_id"],
            "run_epoch": r["run_epoch"],
            "delivery_uid": r["delivery_uid"],
            "event_id": r["event_id"],
            "snapshot": json.loads(r["snapshot"]),
            "signing_secret": r["signing_secret"],
            "event_payload": json.loads(r["event_payload"]),
            "status": r["status"],
            "attempts": r["attempts"],
            "max_retries": r["max_retries"],
            "next_attempt_at": r["next_attempt_at"],
            "suppress_until": r["suppress_until"],
            "last_error": r["last_error"],
            "last_status_code": r["last_status_code"],
            "sent_at": r["sent_at"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }

    def _event_uid(self, d: dict, history_id: int) -> str:
        digest = hashlib.sha1(
            f"{d['id']}:{d['run_epoch']}:{history_id}".encode()
        ).hexdigest()[:16]
        return f"adev-{digest}"

    def _delivery_uid(self, d: dict, history_id: int) -> str:
        return f"ad-{d['run_epoch']}-{history_id}-{d['sub_id']}"

    @staticmethod
    def _seeded_counter(event_type: str, detail: dict) -> int:
        if event_type == EV_UNHEALTHY:
            return int(detail.get("consecutive_failures") or 0)
        if event_type == EV_RECOVERED:
            return int(detail.get("consecutive_successes") or 0)
        return 0

    @staticmethod
    def _streak_counter(event_type: str, detail: dict, verdict: str) -> int:
        if event_type == EV_UNHEALTHY and verdict == "failure":
            return int(
                detail.get("failures")
                or detail.get("consecutive_failures") or 0
            )
        if event_type == EV_RECOVERED and verdict == "success":
            return int(
                detail.get("successes")
                or detail.get("consecutive_successes") or 0
            )
        return 0

    # -- history row processing ----------------------------------------------

    def _process_history_row(
        self, d: dict, row: dict, sim_now: float, record: dict
    ) -> None:
        """Apply one frozen history row to the private engine state."""
        sub_sources = set(d["input"]["subscription"]["sources"])
        if row["kind"] == "transition":
            mapping = TRANSITION_EVENT_MAP.get(
                (row.get("transition") or {}).get("reason")
            )
            if mapping is None:
                record["note"] = "transition not in event map"
                return
            event_type, source = mapping
            if not ("*" in sub_sources or source in sub_sources):
                record["note"] = f"source {source!r} not subscribed"
                return
            self._create_event_and_delivery(
                d, row, event_type, source, sim_now, record
            )
            return

        # check row: advance/supersede unconfirmed streak deliveries, mirroring
        # AlertStore._ingest_check_locked.
        verdict = row.get("verdict")
        if verdict not in ("success", "failure"):
            record["note"] = f"check verdict {verdict!r} ignored"
            return
        detail = row.get("detail") or {}
        pending = self._conn.execute(
            "SELECT dl.id AS d_id, e.id AS e_id, e.event_type AS event_type"
            " FROM alert_drill_deliveries dl"
            " JOIN alert_drill_events e ON e.id = dl.event_id"
            " WHERE dl.drill_id = ? AND dl.run_epoch = ?"
            " AND dl.status = ? AND e.target_id = ?",
            (d["id"], d["run_epoch"], ST_UNCONFIRMED, row["target_id"]),
        ).fetchall()
        confirmations: dict[int, int] = {}
        for pr in pending:
            event_type = pr["event_type"]
            opposite = (
                (event_type == EV_UNHEALTHY and verdict == "success")
                or (event_type == EV_RECOVERED and verdict == "failure")
            )
            confirms = self._streak_counter(event_type, detail, verdict)
            threshold = self._delivery_threshold(pr["d_id"])
            if not opposite and confirms >= threshold:
                self._activate_delivery(
                    d, pr["d_id"], pr["e_id"], sim_now, record,
                    reason="streak_confirmed",
                )
            elif opposite:
                self._set_delivery_status(
                    pr["d_id"], ST_SUPERSEDED, sim_now,
                    next_attempt_at=None, suppress_until=None,
                )
                record.setdefault("superseded", []).append(
                    {"delivery_id": pr["d_id"], "event_type": event_type}
                )
                self._refresh_event(pr["e_id"], sim_now)
            confirmations[pr["e_id"]] = confirms
        for e_id, confirms in confirmations.items():
            self._conn.execute(
                "UPDATE alert_drill_events SET confirm_count = ? WHERE id = ?",
                (confirms, e_id),
            )
            self._refresh_event(e_id, sim_now)

    def _delivery_threshold(self, delivery_id: int) -> int:
        row = self._conn.execute(
            "SELECT snapshot FROM alert_drill_deliveries WHERE id = ?",
            (delivery_id,),
        ).fetchone()
        return int(json.loads(row["snapshot"])["consecutive_threshold"])

    def _create_event_and_delivery(
        self,
        d: dict,
        row: dict,
        event_type: str,
        source: str,
        sim_now: float,
        record: dict,
    ) -> None:
        sub = self._frozen_sub(d)
        detail = row.get("detail") or {}
        threshold = int(sub["consecutive_threshold"])
        seeded = self._seeded_counter(event_type, detail)
        event_uid = self._event_uid(d, row["id"])
        immediate = event_type not in (EV_UNHEALTHY, EV_RECOVERED)
        cur = self._conn.execute(
            "INSERT OR IGNORE INTO alert_drill_events"
            " (drill_id, run_epoch, event_uid, history_id, target_id,"
            "  event_type, source, ts, status, confirm_count, threshold,"
            "  activated_at, detail)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
            (
                d["id"], d["run_epoch"], event_uid, row["id"], row["target_id"],
                event_type, source, row["ts"], ST_UNCONFIRMED, seeded,
                threshold, json.dumps(detail, sort_keys=True),
            ),
        )
        if cur.rowcount == 0:
            record["note"] = "duplicate transition for this history id"
            return
        event_id = cur.lastrowid
        if immediate or seeded >= threshold:
            window = _active_window(sub["silence_windows"], sim_now)
            status = ST_SUPPRESSED if window is not None else ST_PENDING
            next_at = sim_now if status == ST_PENDING else None
            suppress_until = float(window["end"]) if window is not None else None
        else:
            status, next_at, suppress_until = ST_UNCONFIRMED, None, None
            window = None
        delivery_uid = self._delivery_uid(d, row["id"])
        payload = _build_event_payload(
            event_uid=event_uid,
            history_row=row,
            event_type=event_type,
            source=source,
            detail=detail,
            sub=sub,
            delivery_uid=delivery_uid,
            drill_id=d["id"],
        )
        self._conn.execute(
            "INSERT INTO alert_drill_deliveries"
            " (drill_id, run_epoch, delivery_uid, event_id, snapshot,"
            "  signing_secret, event_payload, status, attempts, max_retries,"
            "  next_attempt_at, suppress_until, last_error, last_status_code,"
            "  sent_at, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, NULL, NULL, NULL,"
            " ?, ?)",
            (
                d["id"], d["run_epoch"], delivery_uid, event_id,
                json.dumps(snapshot_payload(sub), sort_keys=True),
                sub.get("signing_secret"),
                json.dumps(payload, sort_keys=True),
                status, sub["max_retries"], next_at, suppress_until,
                sim_now, sim_now,
            ),
        )
        delivery_id = self._conn.execute(
            "SELECT id FROM alert_drill_deliveries"
            " WHERE drill_id = ? AND run_epoch = ? AND delivery_uid = ?",
            (d["id"], d["run_epoch"], delivery_uid),
        ).fetchone()["id"]
        self._refresh_event(event_id, sim_now)
        record["matched"] = True
        record["event"] = {
            "event_id": event_id,
            "event_uid": event_uid,
            "event_type": event_type,
            "source": source,
            "threshold": threshold,
            "seeded_confirm_count": seeded,
        }
        record["initial_delivery"] = {
            "delivery_id": delivery_id,
            "status": status,
            "suppressed": status == ST_SUPPRESSED,
            "suppress_until": suppress_until,
            "silence_window": _window_record(window),
        }

    def _frozen_sub(self, d: dict) -> dict:
        """Full snapshot (including the frozen secret) for engine use."""
        return {
            **d["input"]["subscription"],
            "silence_windows": d["input"]["subscription"]["silence_windows"],
            "signing_secret": d["input"].get("_signing_secret"),
        }

    def _activate_delivery(
        self,
        d: dict,
        delivery_id: int,
        event_id: int,
        sim_now: float,
        record: dict,
        *,
        reason: str,
    ) -> None:
        row = self._conn.execute(
            "SELECT * FROM alert_drill_deliveries WHERE id = ?", (delivery_id,)
        ).fetchone()
        snap = json.loads(row["snapshot"])
        # Deliver against the frozen snapshot: its silence windows govern
        # this event even if the live subscription changed afterwards.
        window = _active_window(snap.get("silence_windows") or [], sim_now)
        self._set_delivery_status(
            delivery_id,
            ST_SUPPRESSED if window is not None else ST_PENDING,
            sim_now,
            next_attempt_at=None if window is not None else sim_now,
            suppress_until=float(window["end"]) if window is not None else None,
        )
        if window is None:
            self._conn.execute(
                "UPDATE alert_drill_events SET activated_at = ? WHERE id = ?",
                (sim_now, event_id),
            )
        record.setdefault("activations", []).append(
            {
                "delivery_id": delivery_id,
                "reason": reason,
                "suppressed": window is not None,
                "silence_window": _window_record(window),
            }
        )
        self._refresh_event(event_id, sim_now)

    def _set_delivery_status(
        self,
        delivery_id: int,
        status: str,
        sim_now: float,
        *,
        next_attempt_at: Optional[float],
        suppress_until: Optional[float],
    ) -> None:
        self._conn.execute(
            "UPDATE alert_drill_deliveries SET status = ?, next_attempt_at = ?,"
            " suppress_until = ?, updated_at = ? WHERE id = ?",
            (status, next_attempt_at, suppress_until, sim_now, delivery_id),
        )

    def _refresh_event(self, event_id: int, sim_now: float) -> None:
        """Derive the aggregate event status from its delivery row."""
        rows = self._conn.execute(
            "SELECT status FROM alert_drill_deliveries WHERE event_id = ?",
            (event_id,),
        ).fetchall()
        statuses = [r["status"] for r in rows]
        if any(s in ACTIVE_DELIVERY_STATUSES for s in statuses):
            for cand in (ST_FAILED, ST_DEAD, ST_PENDING,
                         ST_SUCCEEDED, ST_SUPPRESSED):
                if cand in statuses:
                    status = cand
                    break
            else:  # pragma: no cover - ACTIVE set is non-empty
                status = "active"
        elif statuses and all(s == ST_SUPERSEDED for s in statuses):
            status = ST_SUPERSEDED
        else:
            status = ST_UNCONFIRMED
        self._conn.execute(
            "UPDATE alert_drill_events SET status = ? WHERE id = ?",
            (status, event_id),
        )

    # -- suppression release / sends / retries --------------------------------

    def _release_suppressed(
        self, d: dict, sim_now: float, record: dict
    ) -> None:
        rows = self._conn.execute(
            "SELECT * FROM alert_drill_deliveries"
            " WHERE drill_id = ? AND run_epoch = ? AND status = ?"
            " AND (suppress_until IS NULL OR suppress_until <= ?)"
            " ORDER BY id ASC",
            (d["id"], d["run_epoch"], ST_SUPPRESSED, sim_now),
        ).fetchall()
        for r in rows:
            snap = json.loads(r["snapshot"])
            window = _active_window(snap.get("silence_windows") or [], sim_now)
            if window is not None:
                # Another (later) frozen window is still active.
                self._conn.execute(
                    "UPDATE alert_drill_deliveries SET suppress_until = ?,"
                    " updated_at = ? WHERE id = ?",
                    (float(window["end"]), sim_now, r["id"]),
                )
                continue
            self._conn.execute(
                "UPDATE alert_drill_deliveries SET status = ?,"
                " next_attempt_at = ?, suppress_until = NULL, updated_at = ?"
                " WHERE id = ?",
                (ST_PENDING, sim_now, sim_now, r["id"]),
            )
            self._conn.execute(
                "UPDATE alert_drill_events SET activated_at = ?"
                " WHERE id = ? AND activated_at IS NULL",
                (sim_now, r["event_id"]),
            )
            record.setdefault("suppression_releases", []).append(
                {"delivery_id": r["id"], "released_at": sim_now}
            )
            self._refresh_event(r["event_id"], sim_now)

    def _due_rows(self, d: dict, sim_now: float) -> list[sqlite3.Row]:
        # The simulated queue is instantaneous (no crash window), so rows live
        # in pending (due now) or failed (parked on the backoff deadline).
        return self._conn.execute(
            "SELECT * FROM alert_drill_deliveries"
            " WHERE drill_id = ? AND run_epoch = ?"
            " AND status IN (?, ?)"
            " AND next_attempt_at IS NOT NULL AND next_attempt_at <= ?"
            " ORDER BY id ASC",
            (d["id"], d["run_epoch"], ST_PENDING, ST_FAILED, sim_now),
        ).fetchall()

    def _script_outcome(
        self, d: dict, *, attempt: int, event_type: str, target_id: str
    ) -> SendOutcome:
        for raw in d["input"].get("send_script") or []:
            rule = SendRuleIn(**raw)
            if rule.matches(
                attempt=attempt, event_type=event_type, target_id=target_id
            ):
                return rule.outcome()
        if d["input"].get("default_outcome", "ok") == "ok":
            return SendOutcome(ok=True, status_code=200)
        return SendOutcome(ok=False, error="scripted default failure")

    def _send_due(self, d: dict, sim_now: float, record: dict) -> None:
        """Attempt every due delivery once at this simulated instant."""
        for r in self._due_rows(d, sim_now):
            delivery = self._delivery_dict(r)
            ev = self._conn.execute(
                "SELECT event_type, target_id FROM alert_drill_events"
                " WHERE id = ?",
                (r["event_id"],),
            ).fetchone()
            attempt = int(r["attempts"]) + 1
            url, headers, body = build_http_request(
                snapshot=delivery["snapshot"],
                payload=delivery["event_payload"],
                attempt=attempt,
                signing_secret=delivery["signing_secret"],
            )
            # The simulated inbox stores exactly what would have hit the wire
            # (never the signing secret itself); no network I/O occurs.
            self._conn.execute(
                "INSERT INTO alert_drill_inbox"
                " (drill_id, run_epoch, delivery_id, attempt, url, headers,"
                "  body, delivered_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    d["id"], d["run_epoch"], r["id"], attempt, url,
                    json.dumps(headers, sort_keys=True),
                    body.decode("utf-8"), sim_now,
                ),
            )
            outcome = self._script_outcome(
                d,
                attempt=attempt,
                event_type=ev["event_type"],
                target_id=ev["target_id"],
            )
            send_record = {
                "delivery_id": r["id"],
                "delivery_uid": r["delivery_uid"],
                "event_type": ev["event_type"],
                "target_id": ev["target_id"],
                "attempt": attempt,
                "outcome": {
                    "ok": outcome.ok,
                    "status_code": outcome.status_code,
                    "error": outcome.error,
                },
                "at": sim_now,
            }
            if outcome.ok:
                self._conn.execute(
                    "UPDATE alert_drill_deliveries SET status = ?,"
                    " attempts = ?, next_attempt_at = NULL,"
                    " suppress_until = NULL, last_error = NULL,"
                    " last_status_code = ?, sent_at = ?, updated_at = ?"
                    " WHERE id = ?",
                    (ST_SUCCEEDED, attempt, outcome.status_code, sim_now,
                     sim_now, r["id"]),
                )
            else:
                # max_retries is retries after the initial attempt: dead once
                # attempts == 1 + max_retries, mirroring production.
                dead = attempt >= int(r["max_retries"]) + 1
                if dead:
                    status, next_at = ST_DEAD, None
                else:
                    status = ST_FAILED
                    snap = delivery["snapshot"]
                    delay = min(
                        float(snap["backoff_max_seconds"]),
                        float(snap["backoff_base_seconds"])
                        * (2 ** (attempt - 1)),
                    )
                    next_at = sim_now + delay
                    send_record["backoff_seconds"] = delay
                    send_record["next_attempt_at"] = next_at
                self._conn.execute(
                    "UPDATE alert_drill_deliveries SET status = ?,"
                    " attempts = ?, next_attempt_at = ?, last_error = ?,"
                    " last_status_code = ?, updated_at = ? WHERE id = ?",
                    (status, attempt, next_at, outcome.error,
                     outcome.status_code, sim_now, r["id"]),
                )
            self._refresh_event(r["event_id"], sim_now)
            record.setdefault("sends", []).append(send_record)

    def _pump(self, d: dict, sim_now: float, record: dict) -> None:
        """Release silence and attempt all currently-due deliveries."""
        self._release_suppressed(d, sim_now, record)
        self._send_due(d, sim_now, record)

    def _next_actionable_deadline(
        self, d: dict, sim_now: float
    ) -> Optional[float]:
        """Earliest future instant that could release or retry a delivery."""
        row = self._conn.execute(
            "SELECT MIN(m) AS m FROM ("
            " SELECT suppress_until AS m FROM alert_drill_deliveries"
            " WHERE drill_id = ? AND run_epoch = ? AND status = ?"
            " UNION ALL"
            " SELECT next_attempt_at AS m FROM alert_drill_deliveries"
            " WHERE drill_id = ? AND run_epoch = ? AND status = ?"
            ") WHERE m IS NOT NULL AND m > ?",
            (d["id"], d["run_epoch"], ST_SUPPRESSED,
             d["id"], d["run_epoch"], ST_FAILED, sim_now),
        ).fetchone()
        m = row["m"]
        return float(m) if m is not None else None

    # -- stats ----------------------------------------------------------------

    def _compute_stats(self, d: dict) -> dict:
        drill_id, epoch = d["id"], d["run_epoch"]
        out = _empty_stats()
        for r in self._conn.execute(
            "SELECT status, COUNT(*) AS c FROM alert_drill_events"
            " WHERE drill_id = ? AND run_epoch = ? GROUP BY status",
            (drill_id, epoch),
        ).fetchall():
            out["events_by_status"][r["status"]] = r["c"]
        for r in self._conn.execute(
            "SELECT status, COUNT(*) AS c, COALESCE(SUM(attempts),0) AS a"
            " FROM alert_drill_deliveries"
            " WHERE drill_id = ? AND run_epoch = ? GROUP BY status",
            (drill_id, epoch),
        ).fetchall():
            out["deliveries_by_status"][r["status"]] = r["c"]
            out["attempts"] += int(r["a"])
        out["inbox_messages"] = self._conn.execute(
            "SELECT COUNT(*) AS c FROM alert_drill_inbox"
            " WHERE drill_id = ? AND run_epoch = ?",
            (drill_id, epoch),
        ).fetchone()["c"]
        by_dl = out["deliveries_by_status"]
        out["succeeded"] = by_dl.get(ST_SUCCEEDED, 0)
        out["dead"] = by_dl.get(ST_DEAD, 0)
        out["suppressed_now"] = by_dl.get(ST_SUPPRESSED, 0)
        out["pending_now"] = (
            by_dl.get(ST_PENDING, 0) + by_dl.get(ST_FAILED, 0)
        )
        out["unconfirmed_now"] = by_dl.get(ST_UNCONFIRMED, 0)
        return out

    # -- advance --------------------------------------------------------------

    def advance(
        self,
        drill_id: str,
        body: AlertDrillAdvanceIn,
        *,
        actor: Optional[str] = None,
        idem_key: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> tuple[int, dict]:
        with self._lock:
            if idem_key:
                replay = self._idem_lookup(drill_id, idem_key, fingerprint)
                if replay is not None:
                    return replay

            d = self._load(drill_id)
            status = d["status"]
            version = d["version"]
            epoch = d["run_epoch"]
            clock_only = body.to_time is not None
            if clock_only:
                allowed = (STATUS_READY, STATUS_RUNNING, STATUS_COMPLETED)
            else:
                allowed = (STATUS_READY, STATUS_RUNNING)
            if status not in allowed:
                raise self._refuse(
                    drill_id,
                    "alert_drill_advance_rejected",
                    CODE_STATUS_CONFLICT,
                    f"drill is {status!r}; cannot advance"
                    + (" (resume it first)" if status == STATUS_PAUSED else ""),
                    version=version,
                    actor=actor,
                )
            if (
                body.expected_version is not None
                and body.expected_version != version
            ):
                raise self._refuse(
                    drill_id,
                    "alert_drill_advance_rejected",
                    CODE_VERSION_CONFLICT,
                    f"expected_version {body.expected_version} does not match "
                    f"current drill version {version}",
                    version=version,
                    actor=actor,
                )

            started_at = self._clock()
            seq = self._next_seq(drill_id, epoch)
            if clock_only:
                if body.steps != 1:
                    raise AlertDrillValidation(
                        "to_time is a clock-only advance and cannot be combined "
                        "with steps > 1",
                        code=CODE_BAD_ADVANCE_PAYLOAD,
                    )
                sim_now, record, consumed, kind, history_id = self._clock_advance(
                    d, body, seq
                )
            else:
                sim_now, record, consumed, kind, history_id = self._event_advance(
                    d, body, seq
                )

            new_cursor = d["cursor"] + consumed
            stats = self._compute_stats({**d, "sim_clock": sim_now})
            # Finalize once the frozen slice is consumed and no delivery is
            # still waiting on the clock (pending send, parked backoff or an
            # open silence window). Unconfirmed streaks are already final at
            # that point (no later check row can ever confirm them). A settle
            # pump or a later clock-only advance drains time-actionable work
            # and flips a running drill to completed.
            rows_done = new_cursor >= d["total_rows"]
            completed = rows_done and not _has_open_work(stats)
            if completed:
                new_status = STATUS_COMPLETED
            elif status == STATUS_COMPLETED:
                new_status = STATUS_COMPLETED
            else:
                new_status = STATUS_RUNNING
            new_version = version + 1
            wall_now = self._clock()
            result = {
                "seq": seq,
                "kind": kind,
                "history_id": history_id,
                "sim_time": sim_now,
                "started_at": started_at,
                "recorded_at": wall_now,
                "consumed_rows": consumed,
                "decisions": record,
                "stats": stats,
                "status_before": status,
                "version_before": version,
            }
            self._conn.execute(
                "INSERT INTO alert_drill_steps"
                " (drill_id, run_epoch, seq, kind, history_id, sim_time,"
                "  recorded_at, actor, result)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    drill_id, epoch, seq, kind, history_id, sim_now, wall_now,
                    actor, json.dumps(result, sort_keys=True, default=str),
                ),
            )
            self._conn.execute(
                "UPDATE alert_drills SET status = ?, cursor = ?, sim_clock = ?,"
                " version = ?, stats = ?, started_at = COALESCE(started_at, ?),"
                " paused_at = NULL,"
                " completed_at = CASE WHEN ? = 'completed' THEN ? ELSE"
                " completed_at END, updated_at = ? WHERE id = ?",
                (
                    new_status, new_cursor, sim_now, new_version,
                    json.dumps(stats, sort_keys=True), started_at,
                    new_status, wall_now, wall_now, drill_id,
                ),
            )
            self._audit(
                drill_id,
                "alert_drill_step",
                {
                    "seq": seq,
                    "kind": kind,
                    "consumed_rows": consumed,
                    "sim_time": sim_now,
                    "new_status": new_status,
                    "sends": len(record.get("sends", [])),
                },
                version=new_version,
                actor=actor,
            )
            if completed:
                self._audit(
                    drill_id,
                    "alert_drill_completed",
                    {"cursor": new_cursor, "rows": d["total_rows"]},
                    version=new_version,
                    actor=actor,
                )
            self._conn.commit()
            payload = {
                "drill_id": drill_id,
                "step": public_step_result(result),
                "status": new_status,
                "version": new_version,
                "run_epoch": epoch,
                "cursor": new_cursor,
                "total_rows": d["total_rows"],
                "sim_clock": sim_now,
                "stats": stats,
            }
            if idem_key:
                self._idem_store(
                    drill_id, epoch, idem_key, "advance", fingerprint, 200, payload
                )
                self._conn.commit()
            return 200, payload

    def _clock_advance(
        self, d: dict, body: AlertDrillAdvanceIn, seq: int
    ) -> tuple[float, dict, int, str, Optional[int]]:
        sim_now = float(body.to_time)  # type: ignore[arg-type]
        if sim_now < d["sim_clock"]:
            raise self._refuse(
                d["id"],
                "alert_drill_advance_rejected",
                CODE_BAD_ADVANCE_PAYLOAD,
                "to_time must not be before the current simulated clock",
                version=d["version"],
            )
        record = _empty_step_record(KIND_CLOCK, sim_now)
        self._pump(d, sim_now, record)
        return sim_now, record, 0, KIND_CLOCK, None

    def _event_advance(
        self,
        d: dict,
        body: AlertDrillAdvanceIn,
        seq: int,
    ) -> tuple[float, dict, int, str, Optional[int]]:
        remaining = d["total_rows"] - d["cursor"]
        if remaining <= 0:
            raise self._refuse(
                d["id"],
                "alert_drill_advance_rejected",
                CODE_ROWS_EXHAUSTED,
                "all frozen history rows have been consumed; use a clock-only "
                "advance (to_time) to let retries mature or inspect a later "
                "instant",
                version=d["version"],
            )
        consume = min(body.steps, remaining)
        rows = d["input"]["history_rows"]
        record = _empty_step_record(KIND_EVENT, d["sim_clock"])
        sim_now = d["sim_clock"]
        consumed_ids: list[int] = []
        for i in range(consume):
            hrow = rows[d["cursor"] + i]
            # The simulated clock follows event time (never backwards).
            if hrow["ts"] > sim_now:
                sim_now = hrow["ts"]
            self._pump(d, sim_now, record)
            sub_record = {
                "history_id": hrow["id"],
                "target_id": hrow["target_id"],
                "kind": hrow["kind"],
                "ts": hrow["ts"],
                "verdict": hrow.get("verdict"),
                "transition_reason": (
                    (hrow.get("transition") or {}).get("reason")
                ),
                "matched": False,
            }
            self._process_history_row(d, hrow, sim_now, sub_record)
            record["rows"].append(sub_record)
            consumed_ids.append(hrow["id"])
        self._pump(d, sim_now, record)
        if body.settle:
            pumps = 0
            while True:
                deadline = self._next_actionable_deadline(d, sim_now)
                if deadline is None or pumps >= SETTLE_PUMP_LIMIT:
                    break
                sim_now = deadline
                self._pump(d, sim_now, record)
                pumps += 1
            record["settled_at"] = sim_now
        record["sim_time"] = sim_now
        return sim_now, record, consume, KIND_EVENT, consumed_ids[-1]

    def _next_seq(self, drill_id: str, epoch: int) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(seq), 0) + 1 AS s FROM alert_drill_steps"
            " WHERE drill_id = ? AND run_epoch = ?",
            (drill_id, epoch),
        ).fetchone()
        return int(row["s"])

    # -- lifecycle ------------------------------------------------------------

    def _check_version_and_state(
        self,
        d: dict,
        action: str,
        allowed: tuple[str, ...],
        *,
        expected_version: Optional[int],
        actor: Optional[str],
    ) -> None:
        if (
            expected_version is not None
            and expected_version != d["version"]
        ):
            raise self._refuse(
                d["id"],
                f"alert_drill_{action}_rejected",
                CODE_VERSION_CONFLICT,
                f"expected_version {expected_version} does not match current "
                f"drill version {d['version']}",
                version=d["version"],
                actor=actor,
            )
        if d["status"] not in allowed:
            raise self._refuse(
                d["id"],
                f"alert_drill_{action}_rejected",
                CODE_STATUS_CONFLICT,
                f"cannot {action} a drill in status {d['status']!r}",
                version=d["version"],
                actor=actor,
                extra={"allowed": list(allowed)},
            )

    def pause(
        self,
        drill_id: str,
        *,
        actor: Optional[str] = None,
        expected_version: Optional[int] = None,
        reason: Optional[str] = None,
        idem_key: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> tuple[int, dict]:
        with self._lock:
            if idem_key:
                replay = self._idem_lookup(drill_id, idem_key, fingerprint)
                if replay is not None:
                    return replay
            d = self._load(drill_id)
            self._check_version_and_state(
                d, "pause", (STATUS_RUNNING,),
                expected_version=expected_version, actor=actor,
            )
            new_version = d["version"] + 1
            now = self._clock()
            self._conn.execute(
                "UPDATE alert_drills SET status = ?, version = ?,"
                " paused_at = ?, updated_at = ? WHERE id = ?",
                (STATUS_PAUSED, new_version, now, now, drill_id),
            )
            self._audit(
                drill_id, "alert_drill_paused",
                {"from": d["status"], "to": STATUS_PAUSED, "reason": reason},
                version=new_version, actor=actor,
            )
            self._conn.commit()
            payload = self._transition_payload(drill_id, d, STATUS_PAUSED,
                                               new_version)
            if idem_key:
                self._idem_store(
                    drill_id, d["run_epoch"], idem_key, "pause", fingerprint,
                    200, payload,
                )
                self._conn.commit()
            return 200, payload

    def resume(
        self,
        drill_id: str,
        *,
        actor: Optional[str] = None,
        expected_version: Optional[int] = None,
        reason: Optional[str] = None,
        idem_key: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> tuple[int, dict]:
        with self._lock:
            if idem_key:
                replay = self._idem_lookup(drill_id, idem_key, fingerprint)
                if replay is not None:
                    return replay
            d = self._load(drill_id)
            self._check_version_and_state(
                d, "resume", (STATUS_READY, STATUS_PAUSED),
                expected_version=expected_version, actor=actor,
            )
            new_version = d["version"] + 1
            now = self._clock()
            self._conn.execute(
                "UPDATE alert_drills SET status = ?, version = ?,"
                " started_at = COALESCE(started_at, ?), paused_at = NULL,"
                " updated_at = ? WHERE id = ?",
                (STATUS_RUNNING, new_version, now, now, drill_id),
            )
            self._audit(
                drill_id, "alert_drill_resumed",
                {"from": d["status"], "to": STATUS_RUNNING, "reason": reason},
                version=new_version, actor=actor,
            )
            self._conn.commit()
            payload = self._transition_payload(drill_id, d, STATUS_RUNNING,
                                               new_version)
            if idem_key:
                self._idem_store(
                    drill_id, d["run_epoch"], idem_key, "resume", fingerprint,
                    200, payload,
                )
                self._conn.commit()
            return 200, payload

    @staticmethod
    def _transition_payload(
        drill_id: str, d: dict, status: str, version: int
    ) -> dict:
        return {
            "drill_id": drill_id,
            "status": status,
            "version": version,
            "run_epoch": d["run_epoch"],
            "cursor": d["cursor"],
            "sim_clock": d["sim_clock"],
        }

    def reset(
        self,
        drill_id: str,
        *,
        actor: Optional[str] = None,
        expected_version: Optional[int] = None,
        reason: Optional[str] = None,
        idem_key: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> tuple[int, dict]:
        with self._lock:
            if idem_key:
                replay = self._idem_lookup(drill_id, idem_key, fingerprint)
                if replay is not None:
                    return replay
            d = self._load(drill_id)
            self._check_version_and_state(
                # Any non-ready state can reset; ready can reset too.
                d, "reset", tuple(LIFECYCLE),
                expected_version=expected_version, actor=actor,
            )
            old_epoch = d["run_epoch"]
            new_epoch = old_epoch + 1
            new_version = d["version"] + 1
            now = self._clock()
            # Prior-epoch rows (steps, events, deliveries, inbox, reports,
            # idempotency keys) are intentionally kept for the audit trail;
            # every read filters by the current run epoch, so they cannot
            # influence the fresh run or replay old responses.
            self._conn.execute(
                "UPDATE alert_drills SET status = ?, cursor = 0,"
                " sim_clock = ?, version = ?, run_epoch = ?, stats = ?,"
                " paused_at = NULL, completed_at = NULL, started_at = NULL,"
                " updated_at = ? WHERE id = ?",
                (
                    STATUS_READY, d["base_sim_time"], new_version, new_epoch,
                    json.dumps(_empty_stats(), sort_keys=True), now, drill_id,
                ),
            )
            self._audit(
                drill_id,
                "alert_drill_reset",
                {
                    "old_epoch": old_epoch,
                    "new_epoch": new_epoch,
                    "reason": reason,
                    "cleared_cursor": d["cursor"],
                },
                version=new_version,
                actor=actor,
            )
            self._conn.commit()
            payload = {
                "drill_id": drill_id,
                "status": STATUS_READY,
                "version": new_version,
                "run_epoch": new_epoch,
                "cursor": 0,
                "sim_clock": d["base_sim_time"],
            }
            if idem_key:
                self._idem_store(
                    drill_id, new_epoch, idem_key, "reset", fingerprint,
                    200, payload,
                )
                self._conn.commit()
            return 200, payload

    # -- steps / inbox / audit reads ------------------------------------------

    def steps(self, d: dict) -> list[dict]:
        rows = self._conn.execute(
            "SELECT result FROM alert_drill_steps"
            " WHERE drill_id = ? AND run_epoch = ? ORDER BY seq ASC",
            (d["id"], d["run_epoch"]),
        ).fetchall()
        return [public_step_result(json.loads(r["result"])) for r in rows]

    def get_step(self, drill_id: str, seq: int) -> dict:
        with self._lock:
            d = self._load(drill_id)
            row = self._conn.execute(
                "SELECT result FROM alert_drill_steps"
                " WHERE drill_id = ? AND run_epoch = ? AND seq = ?",
                (drill_id, d["run_epoch"], seq),
            ).fetchone()
        if row is None:
            raise AlertDrillNotFound(
                f"step {seq} has not been recorded in alert drill "
                f"{drill_id!r}'s current run"
            )
        return public_step_result(json.loads(row["result"]))

    def inbox(
        self,
        drill_id: str,
        *,
        status: Optional[str] = None,
        attempt: Optional[int] = None,
        limit: int = 100,
    ) -> dict:
        if status is not None and status not in DELIVERY_STATUSES:
            raise AlertDrillValidation(f"unknown delivery status {status!r}")
        with self._lock:
            d = self._load(drill_id)
            sql = (
                "SELECT m.* FROM alert_drill_inbox m"
                " WHERE m.drill_id = ? AND m.run_epoch = ?"
            )
            args: list = [drill_id, d["run_epoch"]]
            if attempt is not None:
                sql += " AND m.attempt = ?"
                args.append(attempt)
            if status is not None:
                sql += (
                    " AND EXISTS (SELECT 1 FROM alert_drill_deliveries x"
                    " WHERE x.id = m.delivery_id AND x.status = ?)"
                )
                args.append(status)
            sql += " ORDER BY m.id ASC LIMIT ?"
            args.append(limit)
            rows = self._conn.execute(sql, args).fetchall()
            messages = [
                {
                    "id": r["id"],
                    "delivery_id": r["delivery_id"],
                    "attempt": r["attempt"],
                    "url": r["url"],
                    "headers": json.loads(r["headers"]),
                    "body": json.loads(r["body"]),
                    "delivered_at": r["delivered_at"],
                }
                for r in rows
            ]
        return {
            "drill_id": drill_id,
            "run_epoch": d["run_epoch"],
            "messages": messages,
            "count": len(messages),
            "order": "id:asc",
        }

    def drill_audit(
        self,
        drill_id: Optional[str] = None,
        *,
        action: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 500,
    ) -> list[dict]:
        sql = "SELECT * FROM alert_drill_audit WHERE 1=1"
        args: list = []
        if drill_id is not None:
            sql += " AND drill_id = ?"
            args.append(drill_id)
        if action:
            sql += " AND action = ?"
            args.append(action)
        if since is not None:
            sql += " AND ts >= ?"
            args.append(since)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [
            {
                "id": r["id"],
                "drill_id": r["drill_id"],
                "ts": r["ts"],
                "actor": r["actor"],
                "action": r["action"],
                "version": r["version"],
                "details": json.loads(r["details"]),
            }
            for r in rows
        ]

    # -- idempotency ----------------------------------------------------------

    def _idem_lookup(
        self, drill_id: str, key: str, fingerprint: Optional[str]
    ) -> Optional[tuple[int, dict]]:
        # Only the current run epoch's keys are live, exactly like the
        # resolution fault drills: a reset invalidates every old key.
        cur = self._conn.execute(
            "SELECT run_epoch FROM alert_drills WHERE id = ?", (drill_id,)
        ).fetchone()
        if cur is None:
            return None
        row = self._conn.execute(
            "SELECT fingerprint, status_code, response FROM"
            " alert_drill_idempotency"
            " WHERE drill_id = ? AND run_epoch = ? AND idem_key = ?",
            (drill_id, cur["run_epoch"], key),
        ).fetchone()
        if row is None:
            return None
        if fingerprint is not None and fingerprint != row["fingerprint"]:
            raise AlertDrillConflict(
                "Idempotency-Key was already used with a different request "
                "payload",
                code=CODE_IDEMPOTENCY_CONFLICT,
            )
        body = json.loads(row["response"])
        return row["status_code"], {**body, "idempotent_replay": True}

    def _idem_store(
        self,
        drill_id: str,
        run_epoch: int,
        key: str,
        action: str,
        fingerprint: Optional[str],
        status_code: int,
        body: dict,
    ) -> None:
        try:
            self._conn.execute(
                "INSERT INTO alert_drill_idempotency"
                " (drill_id, run_epoch, idem_key, action, fingerprint,"
                "  status_code, response, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    drill_id, run_epoch, key, action, fingerprint or "",
                    status_code, json.dumps(body, sort_keys=True, default=str),
                    self._clock(),
                ),
            )
        except sqlite3.IntegrityError:
            # A concurrent first-submit won the same key; its replay wins.
            self._conn.rollback()

    # -- report / diff against production -------------------------------------

    def report(self, drill_id: str) -> dict:
        """Frozen per-epoch report; generated at most once, then replayed."""
        with self._lock:
            d = self._load(drill_id)
            row = self._conn.execute(
                "SELECT content, checksum, created_at FROM alert_drill_reports"
                " WHERE drill_id = ? AND run_epoch = ?",
                (drill_id, d["run_epoch"]),
            ).fetchone()
            if row is not None:
                return {
                    "report": json.loads(row["content"]),
                    "checksum": row["checksum"],
                    "generated_at": row["created_at"],
                    "idempotent_replay": True,
                }
            steps = self.steps(d)
            deliveries = [
                self._delivery_dict(r)
                for r in self._delivery_rows(d["id"], d["run_epoch"])
            ]
            content = self._build_report(d, steps, deliveries)
            canonical = json.dumps(
                content, sort_keys=True, separators=(",", ":"), default=str
            )
            checksum = hashlib.blake2b(
                canonical.encode(), digest_size=16
            ).hexdigest()
            generated_at = self._clock()
            self._conn.execute(
                "INSERT INTO alert_drill_reports"
                " (drill_id, run_epoch, created_at, content, checksum)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    drill_id, d["run_epoch"], generated_at,
                    json.dumps(content, sort_keys=True, default=str),
                    checksum,
                ),
            )
            self._audit(
                drill_id,
                "alert_drill_report_generated",
                {
                    "checksum": checksum,
                    "steps_included": len(steps),
                    "run_epoch": d["run_epoch"],
                },
                version=d["version"],
            )
            self._conn.commit()
            return {
                "report": content,
                "checksum": checksum,
                "generated_at": generated_at,
                "idempotent_replay": False,
            }

    def _build_report(
        self, d: dict, steps: list[dict], deliveries: list[dict]
    ) -> dict:
        frozen = d["input"]
        stats = self._compute_stats(d)
        diff = self._production_diff(d, deliveries)
        decision_log = [
            {
                "seq": s["seq"],
                "kind": s["kind"],
                "history_id": s.get("history_id"),
                "sim_time": s["sim_time"],
                "consumed_rows": s["consumed_rows"],
                "settled_at": (s.get("decisions") or {}).get("settled_at"),
                "rows": (s.get("decisions") or {}).get("rows", []),
                "activations": (s.get("decisions") or {}).get("activations", []),
                "superseded": (s.get("decisions") or {}).get("superseded", []),
                "suppression_releases": (
                    s.get("decisions") or {}
                ).get("suppression_releases", []),
                "sends": (s.get("decisions") or {}).get("sends", []),
            }
            for s in steps
        ]
        return {
            "drill_id": d["id"],
            "generated_for_run_epoch": d["run_epoch"],
            "run_epoch": d["run_epoch"],
            "status": d["status"],
            "created_at": d["created_at"],
            "created_by": d["created_by"],
            "description": d["description"],
            "frozen_input": self._frozen_input_view(frozen),
            "progress": {
                "cursor": d["cursor"],
                "total_rows": d["total_rows"],
                "sim_clock": d["sim_clock"],
                "steps_recorded": len(steps),
            },
            "statistics": stats,
            "decisions": decision_log,
            "inbox": {"count": stats["inbox_messages"]},
            "production_diff": diff,
        }

    def _production_diff(self, d: dict, deliveries: list[dict]) -> dict:
        """Compare each replay delivery with the real production outcome.

        Matched on the underlying history transition id: a drill delivery
        belongs to history row H iff its drill event has ``history_id = H``,
        and production's matching event carries ``transition_id = H``. The
        drill deliberately replays a frozen sub_version, so revision drift
        is reported as data but not as an outcome mismatch.
        """
        live_events = {
            int(r["transition_id"]): r
            for r in self._conn.execute(
                "SELECT * FROM health_alert_events"
            ).fetchall()
        }
        live_delivery_index: dict[tuple[int, str], sqlite3.Row] = {}
        for ev in live_events.values():
            for r in self._conn.execute(
                "SELECT * FROM health_alert_deliveries WHERE event_id = ?",
                (ev["id"],),
            ).fetchall():
                live_delivery_index[(int(ev["transition_id"]), r["sub_id"])] = r
        drill_events = {
            int(r["id"]): r
            for r in self._conn.execute(
                "SELECT * FROM alert_drill_events"
                " WHERE drill_id = ? AND run_epoch = ?",
                (d["id"], d["run_epoch"]),
            ).fetchall()
        }
        counts = {
            "compared": 0,
            "no_production_event": 0,
            "event_without_delivery": 0,
            "status_match": 0,
            "status_mismatch": 0,
            "attempts_match": 0,
        }
        items: list[dict] = []
        for dl in deliveries:
            ev = drill_events[int(dl["event_id"])]
            history_id = int(ev["history_id"])
            item = {
                "delivery_uid": dl["delivery_uid"],
                "history_id": history_id,
                "event_type": ev["event_type"],
                "simulated": {
                    "status": dl["status"],
                    "attempts": dl["attempts"],
                    "frozen_sub_version": dl["snapshot"]["sub_version"],
                },
            }
            live_dl = live_delivery_index.get((history_id, d["sub_id"]))
            if live_dl is None:
                item["production"] = None
                if live_events.get(history_id) is not None:
                    item["difference"] = "event_without_delivery"
                    counts["event_without_delivery"] += 1
                else:
                    item["difference"] = "no_production_event"
                    counts["no_production_event"] += 1
            else:
                counts["compared"] += 1
                snap = json.loads(live_dl["snapshot"])
                item["production"] = {
                    "status": live_dl["status"],
                    "attempts": live_dl["attempts"],
                    "sub_version": live_dl["sub_version"],
                    "snapshot_webhook_url": snap.get("webhook_url"),
                }
                status_same = live_dl["status"] == dl["status"]
                attempts_same = int(live_dl["attempts"]) == int(dl["attempts"])
                if status_same and attempts_same:
                    item["difference"] = "same"
                elif not status_same:
                    item["difference"] = "status_mismatch"
                else:
                    item["difference"] = "attempt_count_mismatch"
                counts["status_match" if status_same else "status_mismatch"] += 1
                if attempts_same:
                    counts["attempts_match"] += 1
            items.append(item)
        return {"counts": counts, "deliveries": items}
