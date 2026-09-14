"""Health event subscriptions, alert suppression and webhook delivery.

Administrators subscribe to the health-check orchestrator's transition
stream. A subscription selects transitions **by target** (``"*"`` matches
every target) and **by effective status source** (``check`` /
``manual_override`` / ``maintenance`` / ``"*"``), adds its own
**consecutive threshold** confirmation and carries silence windows, retry
settings and a webhook endpoint.

Generated event types (only these transitions ever become events):

  unhealthy           check_fail_threshold       source=check
  recovered           check_recover_threshold    source=check
  maintenance_begin   maintenance window enter   source=maintenance
  maintenance_end     maintenance window leave   source=maintenance
  override_expired    manual_override_expired    source=manual_override

Deduplication / persistence
---------------------------
The ingestor tails ``health_check_history`` in global ``id`` order behind a
persisted cursor (``health_alert_meta``): one ``health_alert_events`` row
per ``(target_id, transition_id)``, so the same transition can never
produce duplicate events even across restart catch-up, and one
``health_alert_deliveries`` outbox row per (event, subscription). The first
ingest seeds the cursor at the newest history id, so creating a
subscription never replays the pre-existing past; a restart re-scans every
uncommitted row and the unique constraints make the catch-up idempotent.

Consecutive threshold
---------------------
For check-sourced events a transition only *confirms* after the
subscription's ``consecutive_threshold`` consecutive same-verdict checks:
a matching transition creates an ``unconfirmed`` delivery seeded with the
transition's threshold counter, later failure/success check rows advance or
supersede it. Maintenance/override events are not check-streak based and
activate immediately.

Suppression
-----------
At activation, an event whose (frozen) subscription silence window is
active is stored as ``suppressed`` and parked until the window ends;
nothing is sent meanwhile. Manual replay always forces a send.

Snapshots
---------
Each delivery freezes the full subscription payload (and sub_version) at
activation/matching time, **including the signing secret**: editing or
deleting a subscription appends a new revision but never rewrites an old
event's snapshot -- "旧事件只能按原订阅快照投递". Rotating a subscription's
signing secret therefore never changes how an already generated event is
signed: retries, crash reclaim and manual replay all HMAC the body with the
secret frozen on the delivery row, so a receiver that verified the first
attempt keeps verifying later attempts.

Retries / restart
-----------------
Webhooks are delivered out-of-band from the outbox. A failed send records
the error, increments attempts and schedules ``min(backoff_max,
backoff_base * 2**(attempts-1))``; after ``max_retries`` failed attempts
the delivery is ``dead``. In-flight rows (``sending``) are reclaimed, so a
crash mid-send is at-least-once (the delivery uid is the Idempotency-Key).
Nothing is held only in memory: pending/suppressed/retrying/dead rows all
survive a restart.

Drill isolation
---------------
Fault drills keep their private in-memory health registry and never write
``health_check_history``; this module only tails that table, so a drill can
never generate a production alert, in either direction.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .audit import AuditLog
from .config_store import ConfigManager

# -- event types / sources / statuses ----------------------------------------

EV_UNHEALTHY = "unhealthy"
EV_RECOVERED = "recovered"
EV_MAINTENANCE_BEGIN = "maintenance_begin"
EV_MAINTENANCE_END = "maintenance_end"
EV_OVERRIDE_EXPIRED = "override_expired"

EVENT_TYPES = frozenset(
    {
        EV_UNHEALTHY,
        EV_RECOVERED,
        EV_MAINTENANCE_BEGIN,
        EV_MAINTENANCE_END,
        EV_OVERRIDE_EXPIRED,
    }
)

SRC_CHECK = "check"
SRC_OVERRIDE = "manual_override"
SRC_MAINTENANCE = "maintenance"
SOURCE_ANY = "*"
SELECTABLE_SOURCES = frozenset({SRC_CHECK, SRC_OVERRIDE, SRC_MAINTENANCE})

#: health_check_history.transition_reason -> (event_type, matched source)
TRANSITION_EVENT_MAP = {
    "check_fail_threshold": (EV_UNHEALTHY, SRC_CHECK),
    "check_recover_threshold": (EV_RECOVERED, SRC_CHECK),
    "maintenance_begin": (EV_MAINTENANCE_BEGIN, SRC_MAINTENANCE),
    "maintenance_end": (EV_MAINTENANCE_END, SRC_MAINTENANCE),
    "manual_override_expired": (EV_OVERRIDE_EXPIRED, SRC_OVERRIDE),
}

# Delivery lifecycle:
#   unconfirmed - threshold streak not yet reached (check-sourced only)
#   suppressed  - active, but parked inside a subscription silence window
#   pending     - due (or not yet due) for the webhook worker
#   sending     - claimed by a worker; reclaimed after a crash
#   succeeded   - 2xx received
#   failed      - transient failure, next_attempt_at scheduled
#   dead        - max_retries exhausted
#   superseded  - an opposite check broke the streak before confirmation
ST_UNCONFIRMED = "unconfirmed"
ST_SUPPRESSED = "suppressed"
ST_PENDING = "pending"
ST_SENDING = "sending"
ST_SUCCEEDED = "succeeded"
ST_FAILED = "failed"
ST_DEAD = "dead"
ST_SUPERSEDED = "superseded"

#: statuses that represent an activated delivery (event really happened)
ACTIVE_DELIVERY_STATUSES = frozenset(
    {ST_PENDING, ST_SUPPRESSED, ST_SENDING, ST_SUCCEEDED, ST_FAILED, ST_DEAD}
)

EVENT_STATUSES = frozenset(
    {ST_UNCONFIRMED, ST_PENDING, ST_SUPPRESSED, ST_SENDING, ST_SUCCEEDED,
     ST_FAILED, ST_DEAD, ST_SUPERSEDED, "active"}
)

INGEST_BATCH = 500
MAX_DETAIL_CHARS = 1000

META_CURSOR_KEY = "history_cursor"


# -- errors -------------------------------------------------------------------


class AlertError(Exception):
    code = "health_alert_error"
    status_code = 409


class AlertNotFound(AlertError):
    code = "subscription_not_found"
    status_code = 404


class AlertEventNotFound(AlertNotFound):
    code = "event_not_found"
    status_code = 404


class AlertConflict(AlertError):
    code = "health_alert_conflict"
    status_code = 409


class AlertValidation(AlertError):
    code = "invalid_subscription"
    status_code = 422


# -- request models -----------------------------------------------------------


class SilenceWindowSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start: float = Field(allow_inf_nan=False)
    end: float = Field(allow_inf_nan=False)
    note: str = ""

    @model_validator(mode="after")
    def _check_window(self) -> "SilenceWindowSpec":
        if self.end <= self.start:
            raise ValueError("silence window end must be greater than start")
        return self


class SubscriptionUpsertIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(description="target id, or '*' for every target")
    sources: list[str] = Field(
        default_factory=lambda: [SOURCE_ANY],
        description="status sources to subscribe to: check, "
        "manual_override, maintenance, or '*'",
    )
    consecutive_threshold: int = Field(
        default=1,
        ge=1,
        description="consecutive same-verdict checks required before a "
        "check-sourced event fires (maintenance/override events fire at once)",
    )
    webhook_url: str = Field(min_length=1)
    headers: dict[str, str] = Field(default_factory=dict)
    signing_secret: Optional[str] = Field(
        default=None,
        description="when set, webhooks carry an HMAC-SHA256 signature of "
        "the body in X-Georesolve-Signature",
    )
    silence_windows: list[SilenceWindowSpec] = Field(default_factory=list)
    max_retries: int = Field(default=5, ge=0, le=50)
    backoff_base_seconds: float = Field(default=1.0, gt=0, allow_inf_nan=False)
    backoff_max_seconds: float = Field(default=300.0, gt=0, allow_inf_nan=False)
    enabled: bool = True
    expected_version: Optional[int] = Field(default=None, ge=1)

    @field_validator("target_id")
    @classmethod
    def _target(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("target_id must be non-empty")
        return v

    @field_validator("sources")
    @classmethod
    def _sources(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("sources must be non-empty")
        norm = []
        for raw in v:
            s = (raw or "").strip().lower()
            if s == SOURCE_ANY:
                return [SOURCE_ANY]
            if s not in SELECTABLE_SOURCES:
                raise ValueError(
                    "sources must be check, manual_override, maintenance or '*'"
                )
            if s not in norm:
                norm.append(s)
        return norm

    @field_validator("webhook_url")
    @classmethod
    def _url(cls, v: str) -> str:
        parsed = urlparse(v.strip())
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("webhook_url must be an http(s) URL")
        return v.strip()

    @field_validator("signing_secret")
    @classmethod
    def _secret(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v:
            return None
        return v

    @model_validator(mode="after")
    def _backoff(self) -> "SubscriptionUpsertIn":
        if self.backoff_base_seconds > self.backoff_max_seconds:
            raise ValueError(
                "backoff_base_seconds must be <= backoff_max_seconds"
            )
        return self


# -- webhook sending ----------------------------------------------------------


@dataclass
class SendOutcome:
    ok: bool
    status_code: Optional[int] = None
    error: Optional[str] = None


def default_webhook_sender(
    *,
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout: float,
) -> SendOutcome:
    """POST ``body`` to ``url`` with urllib (no extra runtime dependency)."""
    req = urllib.request.Request(url, data=body, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            code = getattr(resp, "status", None) or resp.getcode()
            return SendOutcome(ok=200 <= int(code) < 300, status_code=int(code))
    except urllib.error.HTTPError as exc:
        return SendOutcome(
            ok=False,
            status_code=exc.code,
            error=f"HTTP {exc.code}: {exc.reason}"[:MAX_DETAIL_CHARS],
        )
    except Exception as exc:  # noqa: BLE001 - any network problem is a failure
        return SendOutcome(
            ok=False, error=f"{type(exc).__name__}: {exc}"[:MAX_DETAIL_CHARS]
        )


# -- the store ----------------------------------------------------------------


class AlertStore:
    """Subscriptions, event ingestion/dedup and the delivery outbox."""

    def __init__(
        self,
        conn,
        config: ConfigManager,
        audit: AuditLog,
        clock: Callable[[], float] = time.time,
        *,
        sender: Optional[Callable[..., SendOutcome]] = None,
        send_timeout: float = 10.0,
    ):
        self._conn = conn
        self._config = config
        self._audit = audit
        self._clock = clock
        self._lock = threading.RLock()
        self._sender = sender or default_webhook_sender
        self._send_timeout = send_timeout

    @property
    def lock(self) -> threading.RLock:
        """Shared mutation lock (proposal application serializes on it too)."""
        return self._lock

    # -- target helpers ------------------------------------------------------

    def _validate_target(self, target_id: str) -> None:
        if target_id == SOURCE_ANY:
            return
        snap = self._config.snapshot()
        for item in (*snap.all_rules(), *snap.all_release_groups()):
            if any(t.id == target_id for t in item.targets):
                return
        raise AlertNotFound(
            f"target {target_id!r} is not referenced by any current rule "
            "or release group"
        )

    # -- (de)serialization ---------------------------------------------------

    @staticmethod
    def _row_to_sub(row) -> dict:
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
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "created_by": row["created_by"],
            "updated_by": row["updated_by"],
        }

    def _public_sub(self, row_or_dict: dict) -> dict:
        d = dict(row_or_dict)
        d.pop("signing_secret", None)
        return d

    def _get_sub_row(self, sub_id: str):
        return self._conn.execute(
            "SELECT * FROM health_alert_subscriptions WHERE sub_id = ?",
            (sub_id,),
        ).fetchone()

    def _load_sub(self, sub_id: str) -> dict:
        row = self._get_sub_row(sub_id)
        if row is None:
            raise AlertNotFound(f"no subscription {sub_id!r}")
        return self._row_to_sub(row)

    # -- subscription CRUD ---------------------------------------------------

    def create_subscription(
        self,
        req: SubscriptionUpsertIn,
        *,
        actor: Optional[str] = None,
        sub_id: Optional[str] = None,
    ) -> tuple[dict, bool]:
        self._validate_target(req.target_id)
        sub_id = sub_id or secrets.token_hex(16)
        now = self._clock()
        windows = [w.model_dump() for w in req.silence_windows]
        with self._lock:
            if self._get_sub_row(sub_id) is not None:
                # Explicit caller-supplied id collision: treat as upsert only
                # when the caller also passes the current version.
                raise AlertConflict(f"subscription {sub_id!r} already exists")
            self._conn.execute(
                "INSERT INTO health_alert_subscriptions"
                " (sub_id, sub_version, target_id, sources,"
                "  consecutive_threshold, webhook_url, headers, signing_secret,"
                "  silence_windows, max_retries, backoff_base_seconds,"
                "  backoff_max_seconds, enabled, deleted, created_at,"
                "  updated_at, created_by, updated_by)"
                " VALUES (?,1,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?,?)",
                (
                    sub_id, req.target_id,
                    json.dumps(req.sources, sort_keys=True),
                    req.consecutive_threshold, req.webhook_url,
                    json.dumps(req.headers, sort_keys=True),
                    req.signing_secret,
                    json.dumps(windows, sort_keys=True),
                    req.max_retries, req.backoff_base_seconds,
                    req.backoff_max_seconds, int(req.enabled), now, now,
                    actor, actor,
                ),
            )
            self._append_revision(sub_id, 1, "created", req, actor, now)
            self._conn.commit()
            self._audit.record(
                "health_alert_subscription_change",
                {"sub_id": sub_id, "sub_version": 1, "action": "created",
                 "target_id": req.target_id, "identity": actor},
                ts=now,
            )
            return self._load_sub(sub_id), True

    def update_subscription(
        self,
        sub_id: str,
        req: SubscriptionUpsertIn,
        *,
        actor: Optional[str] = None,
    ) -> tuple[dict, bool]:
        self._validate_target(req.target_id)
        if req.expected_version is None:
            raise AlertValidation(
                "updating a subscription requires expected_version"
            )
        windows = [w.model_dump() for w in req.silence_windows]
        with self._lock:
            row = self._get_sub_row(sub_id)
            if row is None:
                raise AlertNotFound(f"no subscription {sub_id!r}")
            if row["deleted"]:
                raise AlertConflict(f"subscription {sub_id!r} was deleted")
            if req.expected_version != row["sub_version"]:
                raise AlertConflict(
                    f"expected_version {req.expected_version} does not match "
                    f"current subscription version {row['sub_version']}"
                )
            old = self._row_to_sub(row)
            if self._same_sub(old, req, windows):
                return old, False
            version = row["sub_version"] + 1
            now = self._clock()
            self._conn.execute(
                "UPDATE health_alert_subscriptions SET sub_version = ?,"
                " target_id = ?, sources = ?, consecutive_threshold = ?,"
                " webhook_url = ?, headers = ?, signing_secret = ?,"
                " silence_windows = ?, max_retries = ?, backoff_base_seconds = ?,"
                " backoff_max_seconds = ?, enabled = ?, updated_at = ?,"
                " updated_by = ? WHERE sub_id = ?",
                (
                    version, req.target_id,
                    json.dumps(req.sources, sort_keys=True),
                    req.consecutive_threshold, req.webhook_url,
                    json.dumps(req.headers, sort_keys=True),
                    req.signing_secret,
                    json.dumps(windows, sort_keys=True),
                    req.max_retries, req.backoff_base_seconds,
                    req.backoff_max_seconds, int(req.enabled), now, actor,
                    sub_id,
                ),
            )
            # Disabling / retargeting can never confirm an in-flight streak.
            if not req.enabled:
                self._conn.execute(
                    "UPDATE health_alert_deliveries SET status = ?,"
                    " updated_at = ? WHERE sub_id = ? AND status = ?",
                    (ST_SUPERSEDED, now, sub_id, ST_UNCONFIRMED),
                )
            # The old revision's delivery-edge cache is stale from here on.
            self.invalidate_delivery_cache_locked(
                sub_id, reason="subscription_updated", now=now
            )
            self._append_revision(sub_id, version, "updated", req, actor, now)
            self._conn.commit()
            self._audit.record(
                "health_alert_subscription_change",
                {"sub_id": sub_id, "sub_version": version, "action": "updated",
                 "old_version": version - 1, "target_id": req.target_id,
                 "identity": actor},
                ts=now,
            )
            return self._load_sub(sub_id), True

    @staticmethod
    def _same_sub(old: dict, req: SubscriptionUpsertIn, windows: list) -> bool:
        return (
            old["target_id"] == req.target_id
            and old["sources"] == req.sources
            and old["consecutive_threshold"] == req.consecutive_threshold
            and old["webhook_url"] == req.webhook_url
            and old["headers"] == req.headers
            and (old["signing_secret"] or None) == req.signing_secret
            and old["silence_windows"] == windows
            and old["max_retries"] == req.max_retries
            and old["backoff_base_seconds"] == req.backoff_base_seconds
            and old["backoff_max_seconds"] == req.backoff_max_seconds
            and old["enabled"] == req.enabled
        )

    def delete_subscription(
        self,
        sub_id: str,
        *,
        expected_version: Optional[int] = None,
        actor: Optional[str] = None,
    ) -> None:
        with self._lock:
            row = self._get_sub_row(sub_id)
            if row is None:
                raise AlertNotFound(f"no subscription {sub_id!r}")
            if row["deleted"]:
                raise AlertConflict(f"subscription {sub_id!r} already deleted")
            if expected_version is not None \
                    and expected_version != row["sub_version"]:
                raise AlertConflict(
                    f"expected_version {expected_version} does not match "
                    f"current subscription version {row['sub_version']}"
                )
            version = row["sub_version"]
            now = self._clock()
            payload = self._row_to_sub(row)
            self._conn.execute(
                "UPDATE health_alert_subscriptions SET deleted = 1,"
                " enabled = 0, updated_at = ?, updated_by = ? WHERE sub_id = ?",
                (now, actor, sub_id),
            )
            # Unconfirmed streaks die with the subscription; already enqueued
            # deliveries keep their frozen snapshot and are still delivered.
            self._conn.execute(
                "UPDATE health_alert_deliveries SET status = ?,"
                " updated_at = ? WHERE sub_id = ? AND status = ?",
                (ST_SUPERSEDED, now, sub_id, ST_UNCONFIRMED),
            )
            self.invalidate_delivery_cache_locked(
                sub_id, reason="subscription_deleted", now=now
            )
            self._conn.execute(
                "INSERT INTO health_alert_sub_revisions"
                " (sub_id, sub_version, action, payload, actor, ts)"
                " VALUES (?, ?, 'deleted', ?, ?, ?)",
                (sub_id, version + 1,
                 json.dumps(payload, sort_keys=True), actor, now),
            )
            self._conn.commit()
            self._audit.record(
                "health_alert_subscription_change",
                {"sub_id": sub_id, "sub_version": version + 1,
                 "action": "deleted", "identity": actor},
                ts=now,
            )

    def _append_revision(
        self,
        sub_id: str,
        version: int,
        action: str,
        req: SubscriptionUpsertIn,
        actor: Optional[str],
        now: float,
    ) -> None:
        payload = req.model_dump()
        self._conn.execute(
            "INSERT INTO health_alert_sub_revisions"
            " (sub_id, sub_version, action, payload, actor, ts)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (sub_id, version, action,
             json.dumps(payload, sort_keys=True), actor, now),
        )

    def get_subscription(self, sub_id: str) -> dict:
        with self._lock:
            return self._load_sub(sub_id)

    def list_subscriptions(self, *, include_deleted: bool = False) -> list[dict]:
        sql = "SELECT * FROM health_alert_subscriptions"
        if not include_deleted:
            sql += " WHERE deleted = 0"
        sql += " ORDER BY created_at ASC, sub_id ASC"
        with self._lock:
            rows = self._conn.execute(sql).fetchall()
            return [self._row_to_sub(r) for r in rows]

    def sub_revisions(
        self,
        sub_id: Optional[str] = None,
        *,
        limit: int = 200,
    ) -> list[dict]:
        sql = "SELECT * FROM health_alert_sub_revisions"
        args: list = []
        if sub_id is not None:
            sql += " WHERE sub_id = ?"
            args.append(sub_id)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [
            {
                "id": r["id"],
                "sub_id": r["sub_id"],
                "sub_version": r["sub_version"],
                "action": r["action"],
                "payload": json.loads(r["payload"]),
                "actor": r["actor"],
                "ts": r["ts"],
            }
            for r in rows
        ]

    # -- ingestion cursor ----------------------------------------------------

    def _get_cursor_locked(self) -> int:
        row = self._conn.execute(
            "SELECT value FROM health_alert_meta WHERE key = ?",
            (META_CURSOR_KEY,),
        ).fetchone()
        if row is not None:
            return int(row["value"])
        # First ever run: start at the newest history row so pre-existing
        # transitions are not replayed for future subscriptions.
        newest = self._conn.execute(
            "SELECT COALESCE(MAX(id), 0) AS m FROM health_check_history"
        ).fetchone()
        cursor = int(newest["m"])
        self._conn.execute(
            "INSERT OR REPLACE INTO health_alert_meta (key, value) VALUES (?, ?)",
            (META_CURSOR_KEY, str(cursor)),
        )
        self._conn.commit()
        return cursor

    def ingest_new(self, *, batch_size: int = INGEST_BATCH) -> int:
        """Tail health_check_history past the cursor; idempotent.

        Safe to call at any time (health-store commit listener, periodic
        worker tick and post-restart catch-up all use this one path).
        Returns the number of history rows processed.
        """
        processed = 0
        with self._lock:
            cursor = self._get_cursor_locked()
            while True:
                rows = self._conn.execute(
                    "SELECT * FROM health_check_history WHERE id > ?"
                    " ORDER BY id ASC LIMIT ?",
                    (cursor, batch_size),
                ).fetchall()
                if not rows:
                    break
                for r in rows:
                    if r["kind"] == "transition":
                        self._ingest_transition_locked(r)
                    else:
                        self._ingest_check_locked(r)
                cursor = int(rows[-1]["id"])
                self._conn.execute(
                    "INSERT OR REPLACE INTO health_alert_meta (key, value)"
                    " VALUES (?, ?)",
                    (META_CURSOR_KEY, str(cursor)),
                )
                self._conn.commit()
                processed += len(rows)
                if len(rows) < batch_size:
                    break
        return processed

    # -- transition -> events + deliveries -----------------------------------

    def _matching_subs_locked(self, target_id: str, source: str) -> list:
        rows = self._conn.execute(
            "SELECT * FROM health_alert_subscriptions"
            " WHERE deleted = 0 AND enabled = 1"
            " AND (target_id = '*' OR target_id = ?)"
            " ORDER BY created_at ASC, sub_id ASC",
            (target_id,),
        ).fetchall()
        out = []
        for r in rows:
            sources = json.loads(r["sources"])
            if SOURCE_ANY in sources or source in sources:
                out.append(r)
        return out

    @staticmethod
    def _event_uid(target_id: str, history_id: int) -> str:
        digest = hashlib.sha1(
            f"{target_id}:{history_id}".encode()
        ).hexdigest()[:16]
        return f"hev-{digest}"

    def _ingest_transition_locked(self, row) -> None:
        mapping = TRANSITION_EVENT_MAP.get(row["transition_reason"])
        if mapping is None:
            return
        event_type, source = mapping
        subs = self._matching_subs_locked(row["target_id"], source)
        if not subs:
            return
        now = self._clock()
        detail = json.loads(row["detail"] or "{}")
        event_uid = self._event_uid(row["target_id"], row["id"])
        threshold = min(int(s["consecutive_threshold"]) for s in subs)
        seeded = (
            int(detail.get("consecutive_failures") or 0)
            if event_type == EV_UNHEALTHY
            else int(detail.get("consecutive_successes") or 0)
            if event_type == EV_RECOVERED
            else 0
        )
        cur = self._conn.execute(
            "INSERT OR IGNORE INTO health_alert_events"
            " (event_uid, target_id, transition_id, transition_seq, event_type,"
            "  source, from_healthy, to_healthy, state_version,"
            "  policy_version, detail, ts, status, confirm_count, threshold,"
            "  activated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_uid, row["target_id"], row["id"], row["seq"], event_type,
                source, row["from_healthy"], row["to_healthy"],
                row["state_version"], row["policy_version"],
                json.dumps(detail, sort_keys=True), row["ts"],
                ST_UNCONFIRMED, seeded, threshold, None,
            ),
        )
        if cur.rowcount == 0:
            # Dedup: this transition already produced an event (restart
            # catch-up or listener double-fire); deliveries exist already.
            return
        event_id = cur.lastrowid
        immediate = event_type not in (EV_UNHEALTHY, EV_RECOVERED)
        for s in subs:
            sub = self._row_to_sub(s)
            confirms = seeded
            need = int(s["consecutive_threshold"])
            if immediate or confirms >= need:
                status, next_at = self._activation_state(sub, now)
            else:
                status, next_at = ST_UNCONFIRMED, None
            payload = self._build_payload(
                self._row_to_event(self._event_row_by_id(event_id)), sub
            )
            self._conn.execute(
                "INSERT OR IGNORE INTO health_alert_deliveries"
                " (delivery_uid, event_id, sub_id, sub_version, snapshot,"
                "  signing_secret, event_payload, status, attempts, max_retries,"
                "  next_attempt_at, last_error, last_status_code, sent_at,"
                "  created_at, updated_at, replayed_count)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
                (
                    f"hdel-{event_uid}-{s['sub_id']}", event_id, s["sub_id"],
                    s["sub_version"],
                    json.dumps(
                        self._cached_snapshot_locked(sub), sort_keys=True
                    ),
                    s["signing_secret"],
                    json.dumps(payload, sort_keys=True), status, 0,
                    s["max_retries"], next_at, None, None, None, now, now,
                ),
            )
        self._refresh_event_locked(event_id, now)

    @staticmethod
    def _snapshot_payload(sub: dict) -> dict:
        """What an old event keeps delivering with, regardless of later edits.

        The public snapshot only carries ``has_signing_secret``; the secret
        itself is frozen alongside on the delivery row's ``signing_secret``
        column (never exposed on the read API) so a rotated subscription key
        cannot change the signature of retries/replays.
        """
        return {
            "sub_id": sub["sub_id"],
            "sub_version": sub["sub_version"],
            "target_id": sub["target_id"],
            "sources": sub["sources"],
            "consecutive_threshold": sub["consecutive_threshold"],
            "webhook_url": sub["webhook_url"],
            "headers": sub["headers"],
            "has_signing_secret": sub["signing_secret"] is not None,
            "silence_windows": sub["silence_windows"],
            "max_retries": sub["max_retries"],
            "backoff_base_seconds": sub["backoff_base_seconds"],
            "backoff_max_seconds": sub["backoff_max_seconds"],
        }

    # -- delivery-edge snapshot cache -----------------------------------------

    def _cached_snapshot_locked(self, sub: dict) -> dict:
        """Snapshot for stamping new deliveries, memoized per (sub, version).

        The delivery edge caches the subscription snapshot of the current
        revision instead of rebuilding it for every matching transition.
        Because the cache key includes ``sub_version``, a version bump can
        never serve stale content; the old version's rows are additionally
        marked invalidated (same transaction as the bump) so the gate's
        "invalidate affected old delivery caches" step is observable and
        audited. Already-generated deliveries never read this cache: they
        carry their own frozen snapshot column.
        """
        row = self._conn.execute(
            "SELECT snapshot FROM health_alert_delivery_cache"
            " WHERE sub_id = ? AND sub_version = ? AND invalidated_at IS NULL",
            (sub["sub_id"], sub["sub_version"]),
        ).fetchone()
        if row is not None:
            self._conn.execute(
                "UPDATE health_alert_delivery_cache"
                " SET deliveries_served = deliveries_served + 1"
                " WHERE sub_id = ? AND sub_version = ?",
                (sub["sub_id"], sub["sub_version"]),
            )
            return json.loads(row["snapshot"])
        snap = self._snapshot_payload(sub)
        self._conn.execute(
            "INSERT INTO health_alert_delivery_cache"
            " (sub_id, sub_version, snapshot, deliveries_served, created_at)"
            " VALUES (?, ?, ?, 1, ?)"
            " ON CONFLICT(sub_id, sub_version) DO UPDATE SET"
            " snapshot = excluded.snapshot,"
            " deliveries_served = deliveries_served + 1,"
            " invalidated_at = NULL, invalidate_reason = NULL",
            (
                sub["sub_id"], sub["sub_version"],
                json.dumps(snap, sort_keys=True), self._clock(),
            ),
        )
        return snap

    def invalidate_delivery_cache_locked(
        self, sub_id: str, *, reason: str, now: Optional[float] = None
    ) -> int:
        """Invalidate every active cached snapshot of a subscription.

        Caller must hold the lock and runs inside the version-change
        transaction; returns the number of cache rows invalidated.
        """
        now = self._clock() if now is None else now
        cur = self._conn.execute(
            "UPDATE health_alert_delivery_cache"
            " SET invalidated_at = ?, invalidate_reason = ?"
            " WHERE sub_id = ? AND invalidated_at IS NULL",
            (now, reason, sub_id),
        )
        return cur.rowcount

    def delivery_cache_entries(self, sub_id: Optional[str] = None) -> list[dict]:
        """Read view over the delivery-edge cache (newest versions first)."""
        sql = "SELECT * FROM health_alert_delivery_cache"
        args: list = []
        if sub_id is not None:
            sql += " WHERE sub_id = ?"
            args.append(sub_id)
        sql += " ORDER BY sub_id ASC, sub_version DESC"
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [
            {
                "sub_id": r["sub_id"],
                "sub_version": r["sub_version"],
                "snapshot": json.loads(r["snapshot"]),
                "deliveries_served": r["deliveries_served"],
                "created_at": r["created_at"],
                "invalidated_at": r["invalidated_at"],
                "invalidate_reason": r["invalidate_reason"],
                "active": r["invalidated_at"] is None,
            }
            for r in rows
        ]

    def _build_payload(self, ev: dict, sub: dict) -> dict:
        return {
            "id": ev["event_uid"],
            "type": ev["event_type"],
            "target_id": ev["target_id"],
            "source": ev["source"],
            "ts": ev["ts"],
            "transition_seq": ev["transition_seq"],
            "state_version": ev["state_version"],
            "policy_version": ev["policy_version"],
            "from_healthy": ev["from_healthy"],
            "to_healthy": ev["to_healthy"],
            "detail": ev["detail"],
            "subscription": {"id": sub["sub_id"], "version": sub["sub_version"]},
        }

    @staticmethod
    def _active_window(windows: list[dict], now: float):
        for w in windows:
            if w["start"] <= now < w["end"]:
                return w
        return None

    def _activation_state(
        self, sub: dict, now: float
    ) -> tuple[str, Optional[float]]:
        """Decide pending vs silence-suppressed at activation time."""
        window = self._active_window(sub["silence_windows"], now)
        if window is not None:
            return ST_SUPPRESSED, float(window["end"])
        return ST_PENDING, now

    def _event_row_by_id(self, event_id: int):
        return self._conn.execute(
            "SELECT * FROM health_alert_events WHERE id = ?", (event_id,)
        ).fetchone()

    def _ingest_check_locked(self, row) -> None:
        """Advance/supersede unconfirmed check-sourced deliveries."""
        if row["verdict"] not in ("success", "failure"):
            return
        detail = json.loads(row["detail"] or "{}")
        failures = int(detail.get("failures") or detail.get(
            "consecutive_failures") or 0)
        successes = int(detail.get("successes") or detail.get(
            "consecutive_successes") or 0)
        now = self._clock()
        pending_rows = self._conn.execute(
            "SELECT d.id AS d_id, d.snapshot AS snapshot, e.id AS e_id,"
            " e.event_type AS event_type FROM health_alert_deliveries d"
            " JOIN health_alert_events e ON e.id = d.event_id"
            " WHERE e.target_id = ? AND d.status = ?",
            (row["target_id"], ST_UNCONFIRMED),
        ).fetchall()
        touched_events: dict[int, int] = {}
        for pr in pending_rows:
            snap = json.loads(pr["snapshot"])
            need = int(snap["consecutive_threshold"])
            confirms = 0
            if pr["event_type"] == EV_UNHEALTHY:
                confirms = failures
                if row["verdict"] == "failure" and failures >= need:
                    self._activate_delivery_locked(
                        pr["d_id"], pr["e_id"], now
                    )
                elif row["verdict"] == "success":
                    # Any success breaks the consecutive-failure streak.
                    self._supersede_delivery_locked(pr["d_id"], now)
            elif pr["event_type"] == EV_RECOVERED:
                confirms = successes
                if row["verdict"] == "success" and successes >= need:
                    self._activate_delivery_locked(
                        pr["d_id"], pr["e_id"], now
                    )
                elif row["verdict"] == "failure":
                    self._supersede_delivery_locked(pr["d_id"], now)
            touched_events[pr["e_id"]] = max(
                touched_events.get(pr["e_id"], 0), confirms
            )
        # Mirror the observed streak on the event row for listings.
        for e_id, confirms in touched_events.items():
            self._conn.execute(
                "UPDATE health_alert_events SET confirm_count = ? WHERE id = ?",
                (confirms, e_id),
            )
            self._refresh_event_locked(e_id, now)

    def _supersede_delivery_locked(self, delivery_id: int, now: float) -> None:
        self._conn.execute(
            "UPDATE health_alert_deliveries SET status = ?,"
            " next_attempt_at = NULL, updated_at = ? WHERE id = ?",
            (ST_SUPERSEDED, now, delivery_id),
        )

    def _activate_delivery_locked(
        self, delivery_id: int, event_id: int, now: float
    ) -> None:
        d = self._conn.execute(
            "SELECT * FROM health_alert_deliveries WHERE id = ?",
            (delivery_id,),
        ).fetchone()
        # Deliver against the frozen snapshot: its silence windows (and
        # threshold/url) are what govern this event, so an edited subscription
        # can neither change suppression nor the destination of an old event.
        snap = json.loads(d["snapshot"])
        window = self._active_window(snap["silence_windows"], now)
        if window is not None:
            status, next_at = ST_SUPPRESSED, float(window["end"])
            activated = None
        else:
            status, next_at = ST_PENDING, now
            activated = now
        self._conn.execute(
            "UPDATE health_alert_deliveries SET status = ?,"
            " next_attempt_at = ?, updated_at = ? WHERE id = ?",
            (status, next_at, now, delivery_id),
        )
        if activated is not None:
            self._conn.execute(
                "UPDATE health_alert_events SET activated_at = ? WHERE id = ?",
                (activated, event_id),
            )

    def _refresh_event_locked(self, event_id: int, now: float) -> None:
        """Derive the aggregate event status from its delivery rows."""
        rows = self._conn.execute(
            "SELECT status FROM health_alert_deliveries WHERE event_id = ?",
            (event_id,),
        ).fetchall()
        statuses = [r["status"] for r in rows]
        if any(s in ACTIVE_DELIVERY_STATUSES for s in statuses):
            # Surface the most interesting active status for list views.
            for cand in (ST_FAILED, ST_DEAD, ST_SENDING, ST_PENDING,
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
            "UPDATE health_alert_events SET status = ? WHERE id = ?",
            (status, event_id),
        )

    # -- suppression release -------------------------------------------------

    def release_suppressed(self, *, now: Optional[float] = None) -> int:
        """Release parked deliveries once their silence window ends.

        Uses the store clock; the ``now`` argument is accepted for call
        symmetry but the worker always drives this on its own clock.
        """
        now = self._clock() if now is None else now
        released = 0
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM health_alert_deliveries WHERE status = ?"
                " AND (next_attempt_at IS NULL OR next_attempt_at <= ?)",
                (ST_SUPPRESSED, now),
            ).fetchall()
            for d in rows:
                snap = json.loads(d["snapshot"])
                window = self._active_window(snap["silence_windows"], now)
                if window is not None:
                    # Another (later) frozen window is still active.
                    self._conn.execute(
                        "UPDATE health_alert_deliveries SET next_attempt_at = ?,"
                        " updated_at = ? WHERE id = ?",
                        (float(window["end"]), now, d["id"]),
                    )
                    continue
                self._conn.execute(
                    "UPDATE health_alert_deliveries SET status = ?,"
                    " next_attempt_at = ?, updated_at = ? WHERE id = ?",
                    (ST_PENDING, now, now, d["id"]),
                )
                released += 1
                self._refresh_event_locked(d["event_id"], now)
            if rows:
                self._conn.commit()
        return released

    # -- delivery outbox / webhook sends -------------------------------------

    def claim_due(
        self,
        *,
        now: Optional[float] = None,
        limit: int = 8,
        reclaim_after: float = 30.0,
    ) -> list[dict]:
        """Atomically claim due deliveries and reclaim crashed sends.

        A claimed row is ``sending`` with ``next_attempt_at`` parked at the
        reclaim deadline: a normal result overwrites it, but a crash leaves
        the row visible to the next claim once the deadline passes, so an
        in-flight webhook is never lost (at-least-once; the delivery uid is
        the Idempotency-Key the receiver deduplicates on).
        """
        now = self._clock() if now is None else now
        claimed: list[dict] = []
        with self._lock:
            # ``failed`` rows are parked on their exponential backoff deadline
            # and become due again when it passes; only ``dead`` stays parked.
            rows = self._conn.execute(
                "SELECT * FROM health_alert_deliveries"
                " WHERE status IN (?, ?, ?)"
                " AND next_attempt_at IS NOT NULL AND next_attempt_at <= ?"
                " ORDER BY id ASC LIMIT ?",
                (ST_PENDING, ST_SENDING, ST_FAILED, now, limit),
            ).fetchall()
            for r in rows:
                cur = self._conn.execute(
                    "UPDATE health_alert_deliveries SET status = ?,"
                    " next_attempt_at = ?, updated_at = ?"
                    " WHERE id = ? AND status IN (?, ?, ?)",
                    (ST_SENDING, now + reclaim_after, now, r["id"],
                     ST_PENDING, ST_SENDING, ST_FAILED),
                )
                if cur.rowcount:
                    claimed.append(
                        self._delivery_row(
                            self._conn.execute(
                                "SELECT * FROM health_alert_deliveries WHERE id = ?",
                                (r["id"],),
                            ).fetchone()
                        )
                    )
            if claimed:
                self._conn.commit()
        return claimed

    def build_http_request(self, delivery: dict) -> tuple[str, dict, bytes]:
        """Assemble (url, headers, body) for one delivery attempt."""
        payload = dict(delivery["event_payload"])
        payload["attempt"] = delivery["attempts"] + 1
        body = json.dumps(payload, sort_keys=True).encode()
        snap = delivery["snapshot"] if isinstance(
            delivery["snapshot"], dict
        ) else json.loads(delivery["snapshot"])
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "georesolve-health-alerts/1.0",
            "X-Georesolve-Event-Uid": payload["id"],
            "X-Georesolve-Event-Type": payload["type"],
            "X-Georesolve-Delivery-Uid": delivery["delivery_uid"],
            "Idempotency-Key": delivery["delivery_uid"],
            "X-Georesolve-Subscription": (
                f"{snap['sub_id']}/{snap['sub_version']}"
            ),
        }
        if delivery.get("replayed_count"):
            headers["X-Georesolve-Replay-Count"] = str(
                delivery["replayed_count"]
            )
        secret = self._delivery_signing_secret(delivery)
        if secret:
            headers["X-Georesolve-Signature"] = "sha256=" + hmac.new(
                secret.encode(), body, hashlib.sha256
            ).hexdigest()
        for k, v in snap.get("headers", {}).items():
            headers[k] = v
        return snap["webhook_url"], headers, body

    def _delivery_signing_secret(self, delivery: dict) -> Optional[str]:
        """The secret this delivery must sign with: the one frozen when the
        event was generated, never the subscription's current secret.

        Rows created before secrets were frozen per-delivery (column NULL on
        a pre-upgrade database) resolve it from the immutable revision of the
        frozen ``sub_version`` they were generated against and backfill the
        column, so retry/replay after a rotation still verifies with the
        original key. There is deliberately no fallback to the live
        subscription row: that lookup is the rotation bug this replaces.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT signing_secret FROM health_alert_deliveries WHERE id = ?",
                (delivery["id"],),
            ).fetchone()
            if row is None:
                return None
            secret = row["signing_secret"]
            if secret is not None:
                return secret
            rev = self._conn.execute(
                "SELECT payload FROM health_alert_sub_revisions"
                " WHERE sub_id = ? AND sub_version = ?",
                (delivery["sub_id"], delivery["sub_version"]),
            ).fetchone()
            if rev is not None:
                secret = json.loads(rev["payload"]).get("signing_secret")
                self._conn.execute(
                    "UPDATE health_alert_deliveries SET signing_secret = ?"
                    " WHERE id = ?",
                    (secret, delivery["id"]),
                )
                self._conn.commit()
            return secret

    def send_delivery(self, delivery: dict) -> SendOutcome:
        """Perform one blocking webhook attempt (run in a worker thread)."""
        url, headers, body = self.build_http_request(delivery)
        return self._sender(
            url=url, headers=headers, body=body, timeout=self._send_timeout
        )

    def record_result(
        self,
        delivery_id: int,
        outcome: SendOutcome,
        *,
        now: Optional[float] = None,
    ) -> dict:
        now = self._clock() if now is None else now
        with self._lock:
            d = self._conn.execute(
                "SELECT * FROM health_alert_deliveries WHERE id = ?",
                (delivery_id,),
            ).fetchone()
            if d is None or d["status"] != ST_SENDING:
                # Replay/delete raced the attempt; drop the result, the
                # outbox state is authoritative.
                return self._delivery_row(d) if d is not None else {}
            attempts = int(d["attempts"]) + 1
            if outcome.ok:
                self._conn.execute(
                    "UPDATE health_alert_deliveries SET status = ?,"
                    " attempts = ?, next_attempt_at = NULL, last_error = NULL,"
                    " last_status_code = ?, sent_at = ?, updated_at = ?"
                    " WHERE id = ?",
                    (ST_SUCCEEDED, attempts, outcome.status_code, now, now,
                     delivery_id),
                )
            else:
                # max_retries is the number of retries allowed after the
                # initial attempt: dead once attempts == 1 + max_retries.
                dead = attempts >= int(d["max_retries"]) + 1
                if dead:
                    status, next_at = ST_DEAD, None
                else:
                    status = ST_FAILED
                    snap = json.loads(d["snapshot"])
                    base = snap["backoff_base_seconds"]
                    cap = snap["backoff_max_seconds"]
                    delay = min(cap, base * (2 ** (attempts - 1)))
                    next_at = now + delay
                self._conn.execute(
                    "UPDATE health_alert_deliveries SET status = ?,"
                    " attempts = ?, next_attempt_at = ?, last_error = ?,"
                    " last_status_code = ?, updated_at = ? WHERE id = ?",
                    (status, attempts, next_at, outcome.error,
                     outcome.status_code, now, delivery_id),
                )
            self._refresh_event_locked(d["event_id"], now)
            self._conn.commit()
            return self._delivery_row(
                self._conn.execute(
                    "SELECT * FROM health_alert_deliveries WHERE id = ?",
                    (delivery_id,),
                ).fetchone()
            )

    async def dispatch_once(self, *, now: Optional[float] = None) -> list[dict]:
        """Ingest, release and send one batch; used by the worker and tests.

        Ingestion and suppression always use the live clock; ``now`` only
        overrides the due-claim cut-off (and defaults to the live clock too).
        """
        self.ingest_new()
        self.release_suppressed()
        due = self.claim_due()
        results = []
        loop = asyncio.get_running_loop()
        for d in due:
            outcome = await loop.run_in_executor(
                None, self.send_delivery, d
            )
            results.append(
                await loop.run_in_executor(
                    None, self.record_result, d["id"], outcome
                )
            )
        return results

    # -- replay --------------------------------------------------------------

    def replay_event(
        self,
        event_id: int,
        *,
        actor: Optional[str] = None,
        now: Optional[float] = None,
    ) -> dict:
        """Force every delivery of an event back onto the outbox.

        The frozen snapshot/event payload is reused verbatim; replay even
        overrides an active silence window. Unconfirmed/superseded events
        never fired and have nothing to replay (409).
        """
        now = self._clock() if now is None else now
        with self._lock:
            ev = self._event_row_by_id(event_id)
            if ev is None:
                raise AlertEventNotFound(f"no event {event_id}")
            rows = self._conn.execute(
                "SELECT * FROM health_alert_deliveries WHERE event_id = ?",
                (event_id,),
            ).fetchall()
            replayable = [
                d for d in rows
                if d["status"] not in (ST_UNCONFIRMED, ST_SUPERSEDED)
            ]
            if not replayable:
                raise AlertConflict(
                    f"event {event_id} never activated; nothing to replay"
                )
            for d in replayable:
                self._conn.execute(
                    "UPDATE health_alert_deliveries SET status = ?,"
                    " attempts = 0, next_attempt_at = ?, last_error = NULL,"
                    " last_status_code = NULL, replayed_count ="
                    " replayed_count + 1, updated_at = ? WHERE id = ?",
                    (ST_PENDING, now, now, d["id"]),
                )
            self._refresh_event_locked(event_id, now)
            self._conn.commit()
            self._audit.record(
                "health_alert_replay",
                {"event_id": event_id, "event_uid": ev["event_uid"],
                 "target_id": ev["target_id"],
                 "deliveries": [d["id"] for d in replayable],
                 "identity": actor},
                ts=now,
            )
            return self.get_event(event_id)

    # -- read side -----------------------------------------------------------

    @staticmethod
    def _row_to_event(row) -> dict:
        return {
            "id": row["id"],
            "event_uid": row["event_uid"],
            "target_id": row["target_id"],
            "transition_id": row["transition_id"],
            "transition_seq": row["transition_seq"],
            "event_type": row["event_type"],
            "source": row["source"],
            "from_healthy": (
                None if row["from_healthy"] is None
                else bool(row["from_healthy"])
            ),
            "to_healthy": (
                None if row["to_healthy"] is None else bool(row["to_healthy"])
            ),
            "state_version": row["state_version"],
            "policy_version": row["policy_version"],
            "detail": json.loads(row["detail"]),
            "ts": row["ts"],
            "status": row["status"],
            "confirm_count": row["confirm_count"],
            "threshold": row["threshold"],
            "activated_at": row["activated_at"],
        }

    @staticmethod
    def _delivery_row(r) -> dict:
        return {
            "id": r["id"],
            "delivery_uid": r["delivery_uid"],
            "event_id": r["event_id"],
            "sub_id": r["sub_id"],
            "sub_version": r["sub_version"],
            "snapshot": json.loads(r["snapshot"]),
            "event_payload": json.loads(r["event_payload"]),
            "status": r["status"],
            "attempts": r["attempts"],
            "max_retries": r["max_retries"],
            "next_attempt_at": r["next_attempt_at"],
            "last_error": r["last_error"],
            "last_status_code": r["last_status_code"],
            "sent_at": r["sent_at"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
            "replayed_count": r["replayed_count"],
        }

    def list_events(
        self,
        *,
        target_id: Optional[str] = None,
        status: Optional[str] = None,
        event_type: Optional[str] = None,
        sub_id: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 100,
    ) -> dict:
        if status is not None and status not in EVENT_STATUSES:
            raise AlertValidation(f"unknown event status {status!r}")
        if event_type is not None and event_type not in EVENT_TYPES:
            raise AlertValidation(f"unknown event type {event_type!r}")
        sql = "SELECT DISTINCT e.* FROM health_alert_events e"
        args: list = []
        if sub_id is not None:
            sql += " JOIN health_alert_deliveries d ON d.event_id = e.id"
            sql += " AND d.sub_id = ?"
            args.append(sub_id)
        sql += " WHERE 1=1"
        if target_id is not None:
            sql += " AND e.target_id = ?"
            args.append(target_id)
        if status is not None:
            sql += " AND e.status = ?"
            args.append(status)
        if event_type is not None:
            sql += " AND e.event_type = ?"
            args.append(event_type)
        if since is not None:
            sql += " AND e.ts >= ?"
            args.append(since)
        sql += " ORDER BY e.id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
            events = [self._row_to_event(r) for r in rows]
            self._attach_deliveries(events)
        return {"events": events, "count": len(events), "order": "id:desc"}

    def _attach_deliveries(self, events: list[dict]) -> None:
        if not events:
            return
        ids = [e["id"] for e in events]
        q = ",".join("?" * len(ids))
        rows = self._conn.execute(
            f"SELECT * FROM health_alert_deliveries WHERE event_id IN ({q})"
            " ORDER BY id ASC",
            ids,
        ).fetchall()
        by_event: dict[int, list] = {}
        for r in rows:
            d = self._delivery_row(r)
            # Listings summarize; the full payloads live on the detail
            # endpoints to keep this response compact.
            for k in ("snapshot", "event_payload"):
                d.pop(k, None)
            by_event.setdefault(r["event_id"], []).append(d)
        for e in events:
            e["deliveries"] = by_event.get(e["id"], [])

    def get_event(self, event_id: int) -> dict:
        with self._lock:
            row = self._event_row_by_id(event_id)
            if row is None:
                raise AlertEventNotFound(f"no event {event_id}")
            ev = self._row_to_event(row)
            rows = self._conn.execute(
                "SELECT * FROM health_alert_deliveries WHERE event_id = ?"
                " ORDER BY id ASC",
                (event_id,),
            ).fetchall()
            ev["deliveries"] = [self._delivery_row(r) for r in rows]
        return ev

    def list_deliveries(
        self,
        *,
        sub_id: Optional[str] = None,
        event_id: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> dict:
        sql = "SELECT * FROM health_alert_deliveries WHERE 1=1"
        args: list = []
        if sub_id is not None:
            sql += " AND sub_id = ?"
            args.append(sub_id)
        if event_id is not None:
            sql += " AND event_id = ?"
            args.append(event_id)
        if status is not None:
            sql += " AND status = ?"
            args.append(status)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
            out = []
            for r in rows:
                d = self._delivery_row(r)
                d.pop("event_payload", None)
                # The webhook URL/headers are enough to identify the target;
                # the full frozen snapshot is available on single fetch.
                out.append(d)
        return {"deliveries": out, "count": len(out), "order": "id:desc"}

    def get_delivery(self, delivery_id: int) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM health_alert_deliveries WHERE id = ?",
                (delivery_id,),
            ).fetchone()
            if row is None:
                raise AlertEventNotFound(f"no delivery {delivery_id}")
            return self._delivery_row(row)


# -- background worker --------------------------------------------------------


class AlertWorker:
    """Periodically ingests history, releases silence and sends webhooks."""

    def __init__(
        self,
        alerts: AlertStore,
        tick_seconds: float = 0.25,
        batch: int = 8,
    ):
        self._alerts = alerts
        self._tick = tick_seconds
        self._batch = batch

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await self.tick()
            except Exception as exc:  # noqa: BLE001 - keep the loop alive
                print(f"health alert tick failed: {exc}", flush=True)
            try:
                await asyncio.wait_for(stop.wait(), self._tick)
            except asyncio.TimeoutError:
                pass

    async def tick(self) -> list[dict]:
        # Blocking DB scans run off the event loop; sends are threaded.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._alerts.ingest_new)
        await loop.run_in_executor(None, self._alerts.release_suppressed)
        due = await loop.run_in_executor(
            None, lambda: self._alerts.claim_due(limit=self._batch)
        )
        results = []
        for d in due:
            outcome = await loop.run_in_executor(
                None, self._alerts.send_delivery, d
            )
            results.append(
                await loop.run_in_executor(
                    None, self._alerts.record_result, d["id"], outcome
                )
            )
        return results
