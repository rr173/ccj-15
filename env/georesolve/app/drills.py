"""Isolated fault drills and resolution replay.

A drill is an administrator-authored replay of the *real* resolution logic
against a *frozen, saved* configuration version. At creation time the drill
freezes:

- the config version and its full bundle payload;
- the target manifest (every target id referenced by any rule or release
  group in that version, deduplicated);
- a rule summary (the effective rule/groups/tiers by lookup triple);
- an ordered, numbered client request sequence (the steps);
- the initial simulated health set (the live health view at creation,
  optionally overridden) and a fixed simulated clock anchor.

Replay isolation
----------------
Each step is replayed with the production :class:`Resolver` running against
**private** collaborators:

- a frozen :class:`~app.config_store.Snapshot` rebuilt from the saved bundle
  (never the live config manager);
- a per-drill simulated health registry -- the live health view is never
  written;
- a per-drill :class:`~app.cache.ResolutionCache` on a simulated clock -- the
  live resolution cache is never read or written;
- no rate limiter and no metering -- no tokens are consumed, no usage events
  are archived, and no budget gate runs;
- a null audit sink -- the production resolver's *internal* audit calls
  (``release_group_hit``) vanish, while drill lifecycle and refusal events go
  to the separate, drill-only ``drill_audit`` table (never the real audit).

Thus a drill can mutate health, age cache entries and replay answers any
number of times without a single side effect leaking into production state.

Lifecycle
---------
``ready -> running <-> paused -> completed``. A drill is created ``ready``;
``resume`` starts it (``ready -> running``), ``pause`` holds it, ``resume``
continues it, and advancing the final step flips it to ``completed``.
``reset`` clears all recorded steps, the simulated cache and the report and
starts a new *run epoch* back at ``ready``: the idempotency keys of the
previous epoch cannot replay old results.

Concurrency
-----------
Every mutation serializes on the store lock. Step submission accepts
``expected_version`` (the drill's optimistic-concurrency token) and an
``Idempotency-Key`` (scoped per drill and run epoch): a retried submission
replays the exact original response, the same key with a different payload
is a conflict, and two concurrent advances of the same drill cannot both
succeed. State, versions, audit order and report checksums are all persisted
to SQLite and therefore stay consistent across restarts.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from pydantic import BaseModel, ConfigDict, Field

from .cache import CacheEntry, ResolutionCache
from .config_store import ConfigManager, Snapshot
from .health import HealthRegistry
from .models import (
    ConfigBundle,
    RateLimitTier,
    ReleaseGroup,
    Rule,
    labels_signature,
    normalize_labels,
)
from .resolver import Resolver

# -- lifecycle ---------------------------------------------------------------

STATUS_READY = "ready"
STATUS_RUNNING = "running"
STATUS_PAUSED = "paused"
STATUS_COMPLETED = "completed"
STATUS_REJECTED = "rejected"  # only used when creation validation itself fails

LIVE_STATUSES = (STATUS_READY, STATUS_RUNNING, STATUS_PAUSED, STATUS_COMPLETED)

# -- refusal codes (also written to drill_audit) -----------------------------

CODE_UNKNOWN_VERSION = "config_version_not_found"
CODE_TARGET_NOT_FROZEN = "target_not_in_frozen_manifest"
CODE_STEP_GAP = "step_sequence_gap"
CODE_STEP_DUPLICATE = "duplicate_step_number"
CODE_ILLEGAL_HEALTH = "illegal_health_change"
CODE_BAD_STEP_PAYLOAD = "invalid_step"
CODE_BAD_CREATE_PAYLOAD = "invalid_drill"
CODE_VERSION_CONFLICT = "expected_version"
CODE_STATUS_CONFLICT = "status_conflict"
CODE_STEP_NOT_FOUND = "step_not_found"
CODE_IDEMPOTENCY_CONFLICT = "idempotency_conflict"
CODE_STEPS_MISSING = "steps_missing"


# -- errors ------------------------------------------------------------------


class DrillError(Exception):
    """Base class for drill failures; mapped to an HTTP status in the API."""

    code = "drill_error"
    status_code = 409

    def __init__(self, message: str, *, code: Optional[str] = None):
        super().__init__(message)
        if code is not None:
            self.code = code


class DrillNotFound(DrillError):
    code = "drill_not_found"
    status_code = 404


class DrillValidation(DrillError):
    """Malformed request body (422); not audited, nothing was attempted."""

    code = "invalid_request"
    status_code = 422


class DrillConflict(DrillError):
    """An audited semantic refusal or optimistic-concurrency failure (409)."""

    code = "drill_conflict"
    status_code = 409


# -- frozen configuration view ----------------------------------------------


def _snapshot_from_bundle(bundle: ConfigBundle) -> Snapshot:
    """Rebuild a Snapshot exactly as an apply would install it at ``now=0``.

    Every bundled rule is in effect at replay anchor time unless it carries a
    future ``effective_from`` (such rules are handled by the snapshot's
    effective-rule lookup just like in production), so the rule map keeps the
    scheduled version tuple directly.
    """
    rules: dict[tuple, tuple[Rule, ...]] = {}
    for r in bundle.rules:
        rules.setdefault(r.key(), []).append(r)
    rule_map = {
        key: tuple(sorted(rs, key=lambda r: r.rule_version))
        for key, rs in rules.items()
    }
    groups: dict[str, list[ReleaseGroup]] = {}
    for g in bundle.release_groups:
        groups.setdefault(g.name, []).append(g)
    group_map = {
        name: tuple(sorted(gs, key=lambda g: (g.priority, g.id)))
        for name, gs in groups.items()
    }
    tiers: dict[tuple, list[RateLimitTier]] = {}
    for t in bundle.rate_limit_tiers:
        tiers.setdefault(t.scope_key(), []).append(t)
    tier_map = {
        key: tuple(sorted(ts, key=lambda t: (t.priority, t.id)))
        for key, ts in tiers.items()
    }
    return Snapshot(bundle.version, bundle.defaults, rule_map, group_map, tier_map)


@dataclass
class _FrozenConfig:
    """Minimal ConfigManager surface the Resolver consumes; frozen forever."""

    snapshot_obj: Snapshot

    def snapshot(self) -> Snapshot:
        return self.snapshot_obj

    def add_listener(self, fn, preview_fn=None) -> None:  # noqa: ARG002
        # A frozen version never changes: no listener can ever fire.
        return None


class _Holder:
    """Mutable value box so a frozen clock can be moved between steps."""

    def __init__(self, value: float):
        self.value = value

    def __call__(self) -> float:
        return self.value


class _NullAudit:
    """Audit sink that discards everything (the replay's internal audit)."""

    def record(self, type_: str, details: dict, ts: Optional[float] = None) -> None:
        return None


def build_frozen(bundle: ConfigBundle, live_health: dict[str, bool]) -> dict:
    """Compute the immutable freeze payload from a saved bundle."""
    snap = _snapshot_from_bundle(bundle)

    manifest: dict[str, dict] = {}
    for tgt in bundle_targets(bundle):
        manifest.setdefault(
            tgt.id, {"id": tgt.id, "address": tgt.address, "weight": tgt.weight}
        )

    rule_summary = []
    for key, versions in sorted(snap.rules.items()):
        name, scope, region, tenant = key
        for r in versions:
            rule_summary.append(
                {
                    "name": name,
                    "scope": scope,
                    "region": region or None,
                    "tenant": tenant or None,
                    "rule_version": r.rule_version,
                    "effective_from": r.effective_from,
                    "ttl": r.ttl,
                    "negative_ttl": r.negative_ttl,
                    "target_ids": [t.id for t in r.targets],
                    "fingerprint": r.fingerprint(),
                }
            )
    group_summary = []
    for name, gs in sorted(snap.release_groups.items()):
        for g in gs:
            group_summary.append(
                {
                    "id": g.id,
                    "name": name,
                    "scope": g.scope,
                    "region": g.region,
                    "tenant": g.tenant,
                    "priority": g.priority,
                    "percent": g.percent,
                    "match_labels": dict(g.match_labels),
                    "window_start": g.window_start,
                    "window_end": g.window_end,
                    "target_ids": [t.id for t in g.targets],
                    "fingerprint": g.fingerprint(),
                }
            )
    tier_summary = []
    for scope_key, ts in sorted(snap.rate_limit_tiers.items()):
        for t in ts:
            tier_summary.append(
                {
                    "id": t.id,
                    "scope": t.scope,
                    "region": t.region,
                    "tenant": t.tenant,
                    "priority": t.priority,
                    "rate_per_second": t.rate_per_second,
                    "burst": t.burst,
                    "match_labels": dict(t.match_labels),
                }
            )
    return {
        "config_version": bundle.version,
        "bundle": json.loads(bundle.model_dump_json()),
        "target_manifest": manifest,
        "initial_health_source": live_health,
        "rule_summary": rule_summary,
        "release_group_summary": group_summary,
        "rate_limit_tier_summary": tier_summary,
    }


def bundle_targets(bundle: ConfigBundle):
    """All target objects referenced by rules and release groups."""
    out: list = []
    for r in bundle.rules:
        out.extend(r.targets)
    for g in bundle.release_groups:
        out.extend(g.targets)
    return out


# -- simulated cache (de)serialization --------------------------------------


def _dump_cache(cache: ResolutionCache) -> list[dict]:
    out = []
    for e in cache.items():
        out.append(
            {
                "name": e.name,
                "region": e.region,
                "tenant": e.tenant,
                "client_key": e.client_key,
                "kind": e.kind,
                "rule_version": e.rule_version,
                "rule_scope": e.rule_scope,
                "rule_fingerprint": e.rule_fingerprint,
                "health_sig": sorted(e.health_sig),
                "payload": e.payload,
                "stored_at": e.stored_at,
                "expires_at": e.expires_at,
                "config_version": e.config_version,
                "labels_sig": e.labels_sig,
                "labels": dict(e.labels),
                "group_id": e.group_id,
                "group_token": e.group_token,
            }
        )
    return out


def _load_cache(clock: Callable[[], float], rows: list[dict]) -> ResolutionCache:
    cache = ResolutionCache(clock)
    for row in rows or []:
        entry = CacheEntry(
            name=row["name"],
            region=row["region"],
            tenant=row["tenant"],
            client_key=row["client_key"],
            kind=row["kind"],
            rule_version=row["rule_version"],
            rule_scope=row["rule_scope"],
            rule_fingerprint=row["rule_fingerprint"],
            health_sig=frozenset(row.get("health_sig") or []),
            payload=row["payload"],
            stored_at=row["stored_at"],
            expires_at=row["expires_at"],
            config_version=row["config_version"],
            labels_sig=row.get("labels_sig", ""),
            labels=row.get("labels", {}),
            group_id=row.get("group_id"),
            group_token=row.get("group_token"),
        )
        cache.put(entry)
    return cache


# -- request models (intentionally permissive; semantics validated & audited)


class DrillRequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    region: str = ""
    tenant: str = ""
    client: str = ""
    labels: Optional[dict] = None
    # Simulated time for this step: an absolute epoch ("at") or a delta from
    # the previous step ("advance_seconds"). Both default to the drill's
    # fixed creation anchor, which keeps replays deterministic.
    at: Optional[float] = Field(default=None)
    advance_seconds: Optional[float] = Field(default=None)
    expected: Optional[dict] = None


class DrillStepIn(DrillRequestIn):
    # Simulated health changes applied before resolution: target id -> healthy.
    health_changes: Optional[dict] = None


class DrillCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    drill_id: Optional[str] = None
    config_version: int = Field(ge=1)
    description: str = ""
    initial_health: Optional[dict] = None
    steps: list[DrillStepIn] = Field(min_length=1)


class AdvanceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seq: Optional[int] = Field(default=None, ge=1)
    expected_version: Optional[int] = Field(default=None, ge=1)


class TransitionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: Optional[int] = Field(default=None, ge=1)
    reason: Optional[str] = None


# -- the store ---------------------------------------------------------------


def _norm(value) -> str:
    return str(value if value is not None else "").strip().lower()


def _finite_number(value, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DrillValidation(f"{field} must be a finite number", code=CODE_BAD_STEP_PAYLOAD)
    f = float(value)
    if f != f or f in (float("inf"), float("-inf")):
        raise DrillValidation(f"{field} must be finite", code=CODE_BAD_STEP_PAYLOAD)
    return f


class DrillStore:
    def __init__(
        self,
        conn: sqlite3.Connection,
        config: ConfigManager,
        live_health: HealthRegistry,
        clock: Callable[[], float] = time.time,
    ):
        self._conn = conn
        self._config = config
        self._live_health = live_health
        self._clock = clock
        self._lock = threading.RLock()

    # -- helpers -------------------------------------------------------------

    def _audit(
        self,
        drill_id: Optional[str],
        action: str,
        details: dict,
        *,
        version: Optional[int] = None,
        actor: Optional[str] = None,
        ts: Optional[float] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> None:
        conn = conn or self._conn
        conn.execute(
            "INSERT INTO drill_audit (drill_id, ts, actor, action, version, details)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                drill_id,
                self._clock() if ts is None else ts,
                actor,
                action,
                version,
                json.dumps(details, sort_keys=True),
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
    ) -> DrillConflict:
        details = {"code": code, "detail": detail}
        if extra:
            details.update(extra)
        with self._lock:
            self._audit(drill_id, action, details, version=version, actor=actor)
            self._conn.commit()
        return DrillConflict(detail, code=code)

    def _row(self, drill_id: str) -> sqlite3.Row:
        row = self._conn.execute(
            "SELECT * FROM drills WHERE id = ?", (drill_id,)
        ).fetchone()
        if row is None:
            raise DrillNotFound(f"drill {drill_id!r} does not exist")
        return row

    def _load(self, drill_id: str) -> dict:
        row = self._row(drill_id)
        return self._row_to_dict(row)

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "status": row["status"],
            "config_version": row["config_version"],
            "base_sim_time": row["base_sim_time"],
            "spec": json.loads(row["spec"]),
            "frozen": json.loads(row["frozen"]),
            "health": json.loads(row["health"]),
            "cache_state": json.loads(row["cache_state"]),
            "current_seq": row["current_seq"],
            "last_sim_time": row["last_sim_time"],
            "run_epoch": row["run_epoch"],
            "version": row["version"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "paused_at": row["paused_at"],
            "completed_at": row["completed_at"],
            "rejection": json.loads(row["rejection"]) if row["rejection"] else None,
            "updated_at": row["updated_at"],
        }

    # -- validation ----------------------------------------------------------

    def _validate_step(self, step: dict, seq: int, manifest: set[str]) -> dict:
        """Normalize and semantically validate one creation-time step."""
        if not isinstance(step, dict):
            raise DrillValidation(
                f"step {seq}: must be an object", code=CODE_BAD_STEP_PAYLOAD
            )
        try:
            parsed = DrillStepIn(**step)
        except Exception as exc:  # pydantic ValidationError
            raise DrillValidation(
                f"step {seq}: {exc}", code=CODE_BAD_STEP_PAYLOAD
            ) from exc
        name = _norm(parsed.name)
        if not name:
            raise DrillValidation(
                f"step {seq}: name is required", code=CODE_BAD_STEP_PAYLOAD
            )
        labels = normalize_labels(parsed.labels or {})
        changes: dict[str, bool] = {}
        for tid, healthy in (parsed.health_changes or {}).items():
            if not isinstance(tid, str) or not tid.strip():
                raise DrillConflict(
                    f"step {seq}: health change keys must be target id strings",
                    code=CODE_ILLEGAL_HEALTH,
                )
            if not isinstance(healthy, bool):
                raise DrillConflict(
                    f"step {seq}: health change for {tid!r} must be a boolean",
                    code=CODE_ILLEGAL_HEALTH,
                )
            if tid not in manifest:
                raise DrillConflict(
                    f"step {seq}: target {tid!r} is not in the frozen manifest",
                    code=CODE_TARGET_NOT_FROZEN,
                )
            changes[tid] = healthy
        at = (
            _finite_number(parsed.at, f"step {seq}.at")
            if parsed.at is not None
            else None
        )
        advance = (
            _finite_number(parsed.advance_seconds, f"step {seq}.advance_seconds")
            if parsed.advance_seconds is not None
            else None
        )
        if at is not None and advance is not None:
            raise DrillValidation(
                f"step {seq}: 'at' and 'advance_seconds' are mutually exclusive",
                code=CODE_BAD_STEP_PAYLOAD,
            )
        if advance is not None and advance < 0:
            raise DrillValidation(
                f"step {seq}: advance_seconds must not be negative",
                code=CODE_ILLEGAL_HEALTH,
            )
        expected = self._validate_expected(parsed.expected, seq)
        return {
            "seq": seq,
            "name": name,
            "region": _norm(parsed.region),
            "tenant": _norm(parsed.tenant),
            "client": str(parsed.client or ""),
            "labels": labels,
            "at": at,
            "advance_seconds": advance,
            "health_changes": changes,
            "expected": expected,
        }

    @staticmethod
    def _validate_expected(expected, seq: int) -> Optional[dict]:
        if expected is None:
            return None
        if not isinstance(expected, dict):
            raise DrillValidation(
                f"step {seq}: expected must be an object", code=CODE_BAD_STEP_PAYLOAD
            )
        out: dict = {}
        if "chosen" in expected:
            chosen = expected["chosen"]
            if chosen is not None and not isinstance(chosen, str):
                raise DrillValidation(
                    f"step {seq}: expected.chosen must be a string or null",
                    code=CODE_BAD_STEP_PAYLOAD,
                )
            out["chosen"] = chosen
        if "status" in expected:
            if not isinstance(expected["status"], str):
                raise DrillValidation(
                    f"step {seq}: expected.status must be a string",
                    code=CODE_BAD_STEP_PAYLOAD,
                )
            out["status"] = expected["status"]
        if "order" in expected:
            order = expected["order"]
            if not isinstance(order, list) or not all(isinstance(x, str) for x in order):
                raise DrillValidation(
                    f"step {seq}: expected.order must be a list of target ids",
                    code=CODE_BAD_STEP_PAYLOAD,
                )
            out["order"] = list(order)
        if "degraded" in expected:
            if not isinstance(expected["degraded"], bool):
                raise DrillValidation(
                    f"step {seq}: expected.degraded must be a boolean",
                    code=CODE_BAD_STEP_PAYLOAD,
                )
            out["degraded"] = expected["degraded"]
        return out or None

    # -- create --------------------------------------------------------------

    def create(self, spec: DrillCreateIn, *, actor: Optional[str] = None) -> dict:
        now = self._clock()
        drill_id = (spec.drill_id or f"drill_{secrets.token_urlsafe(12)}").strip()
        if not drill_id:
            raise DrillValidation("drill_id must be non-empty", code=CODE_BAD_CREATE_PAYLOAD)

        # The frozen version must exist in saved history. Look it up before
        # touching anything; a missing version is a 404 (nothing to anchor to).
        try:
            bundle = self._config.saved_bundle(spec.config_version)
        except Exception as exc:
            self._audit(
                drill_id,
                "drill_create_rejected",
                {
                    "code": CODE_UNKNOWN_VERSION,
                    "config_version": spec.config_version,
                    "detail": str(exc),
                },
                actor=actor,
            )
            self._conn.commit()
            raise DrillNotFound(str(exc), code=CODE_UNKNOWN_VERSION) from exc

        frozen = build_frozen(bundle, self._live_health.snapshot())
        manifest = set(frozen["target_manifest"])

        # Validate and normalize the whole request sequence up front. Any
        # refusal is audited against the would-be drill id; the drill itself
        # is persisted only when everything is valid.
        steps: list[dict] = []
        seen: set[int] = set()
        try:
            if not spec.steps:
                raise DrillConflict(
                    "a drill requires at least one step", code=CODE_STEPS_MISSING
                )
            for i, raw in enumerate(spec.steps, start=1):
                step = self._validate_step(raw.model_dump(), i, manifest)
                if step["seq"] in seen:
                    raise DrillConflict(
                        f"duplicate step number {i}", code=CODE_STEP_DUPLICATE
                    )
                seen.add(step["seq"])
                steps.append(step)
        except DrillConflict as exc:
            self._audit(
                drill_id,
                "drill_create_rejected",
                {
                    "code": exc.code,
                    "config_version": spec.config_version,
                    "detail": str(exc),
                },
                actor=actor,
            )
            self._conn.commit()
            raise

        # Initial health: every frozen target is healthy by default, then
        # the current live view is folded in, then the caller's overrides.
        initial: dict[str, bool] = {tid: True for tid in manifest}
        for tid, st in frozen["initial_health_source"].items():
            if tid in initial:
                initial[tid] = bool(st.get("healthy", True))
        for tid, healthy in (spec.initial_health or {}).items():
            if not isinstance(tid, str) or not tid.strip():
                raise DrillValidation(
                    "initial_health keys must be target id strings",
                    code=CODE_BAD_CREATE_PAYLOAD,
                )
            if not isinstance(healthy, bool):
                raise DrillConflict(
                    f"initial health for {tid!r} must be a boolean",
                    code=CODE_ILLEGAL_HEALTH,
                )
            if tid not in manifest:
                exc = self._refuse(
                    drill_id,
                    "drill_create_rejected",
                    CODE_TARGET_NOT_FROZEN,
                    f"target {tid!r} is not in the frozen manifest",
                    actor=actor,
                    extra={"config_version": spec.config_version},
                )
                raise exc
            initial[tid] = healthy

        frozen_spec = {
            "description": spec.description,
            "steps": steps,
            "step_count": len(steps),
        }

        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO drills (id, status, config_version, base_sim_time,"
                    " spec, frozen, health, cache_state, current_seq, last_sim_time,"
                    " run_epoch, version, created_by, created_at, started_at,"
                    " paused_at, completed_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, 1, 1, ?, ?, NULL, NULL,"
                    " NULL, ?)",
                    (
                        drill_id,
                        STATUS_READY,
                        spec.config_version,
                        now,
                        json.dumps(frozen_spec, sort_keys=True),
                        json.dumps(frozen, sort_keys=True),
                        json.dumps(initial, sort_keys=True),
                        "[]",
                        actor,
                        now,
                        now,
                    ),
                )
                self._audit(
                    drill_id,
                    "drill_created",
                    {
                        "config_version": spec.config_version,
                        "steps": len(steps),
                        "targets": sorted(manifest),
                    },
                    version=1,
                    actor=actor,
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise DrillConflict(
                    f"drill id {drill_id!r} already exists",
                    code="drill_id_conflict",
                ) from exc

        return self._load(drill_id)

    # -- read side -----------------------------------------------------------

    def get(self, drill_id: str) -> dict:
        with self._lock:
            drill = self._load(drill_id)
        return self._public(drill, include_steps=True)

    @staticmethod
    def _frozen_view(frozen: dict) -> _FrozenConfig:
        bundle = ConfigBundle(**frozen["bundle"])
        return _FrozenConfig(_snapshot_from_bundle(bundle))

    def _replay(
        self,
        drill: dict,
        step_spec: dict,
        sim_now: float,
    ) -> tuple[dict, ResolutionCache, dict]:
        """Run one isolated replay; returns (answer, cache_after, health_after)."""
        frozen = drill["frozen"]
        # Seed every frozen target explicitly (unknown targets fail open
        # anyway, but seeding makes the recorded health set complete).
        health_map = {tid: True for tid in frozen["target_manifest"]}
        health_map.update(drill["health"])

        # Apply the step's simulated health changes to the private registry.
        sim_health = _SimHealth(health_map)
        changes = step_spec.get("health_changes") or {}
        applied = {}
        for tid, healthy in changes.items():
            sim_health.set(tid, bool(healthy), now=sim_now)
            applied[tid] = bool(healthy)
        health_after = sim_health.snapshot_booleans()

        labels = normalize_labels(step_spec.get("labels") or {})
        holder = _Holder(sim_now)
        cache = _load_cache(holder, drill.get("cache_state") or [])
        resolver = Resolver(
            self._frozen_view(frozen),
            cache,
            sim_health,
            _NullAudit(),
            rate_limiter=None,
            metering=None,
            clock=holder,
        )
        client = step_spec.get("client") or ""
        answer = resolver.resolve(
            step_spec["name"],
            step_spec.get("region", ""),
            step_spec.get("tenant", ""),
            client,
            labels=labels,
            now=sim_now,
        )
        return answer, cache, health_after

    @staticmethod
    def _expected_diff(expected: Optional[dict], answer: dict, order: list[str]) -> list[dict]:
        if not expected:
            return []
        diffs: list[dict] = []
        if "chosen" in expected and expected["chosen"] != answer.get("chosen"):
            diffs.append(
                {
                    "field": "chosen",
                    "expected": expected["chosen"],
                    "actual": answer.get("chosen"),
                }
            )
        if "status" in expected and expected["status"] != answer.get("status"):
            diffs.append(
                {
                    "field": "status",
                    "expected": expected["status"],
                    "actual": answer.get("status"),
                }
            )
        if "order" in expected and list(expected["order"]) != order:
            diffs.append(
                {
                    "field": "order",
                    "expected": list(expected["order"]),
                    "actual": order,
                }
            )
        if "degraded" in expected and bool(expected["degraded"]) != bool(
            answer.get("degraded")
        ):
            diffs.append(
                {
                    "field": "degraded",
                    "expected": bool(expected["degraded"]),
                    "actual": bool(answer.get("degraded")),
                }
            )
        return diffs

    @staticmethod
    def _target_order(answer: dict) -> list[str]:
        return [t["id"] for t in answer.get("targets", [])]

    def _advance(
        self,
        drill_id: str,
        body: AdvanceIn,
        *,
        actor: Optional[str],
        idem_key: Optional[str],
        fingerprint: Optional[str],
    ) -> tuple[int, dict]:
        with self._lock:
            # Idempotent replay first, before any state read of consequences.
            if idem_key:
                replay = self._idem_lookup(drill_id, idem_key, fingerprint)
                if replay is not None:
                    return replay[0], replay[1]

            row = self._row(drill_id)
            drill = self._row_to_dict(row)
            status = drill["status"]
            version = drill["version"]
            epoch = drill["run_epoch"]
            specs = drill["spec"]["steps"]
            total = len(specs)

            if status not in (STATUS_READY, STATUS_RUNNING):
                raise DrillConflict(
                    f"drill is {status!r}; only ready/running drills can advance"
                    + (" (resume it first)" if status == STATUS_PAUSED else ""),
                    code=CODE_STATUS_CONFLICT,
                )
            if (
                body.expected_version is not None
                and body.expected_version != version
            ):
                raise DrillConflict(
                    f"expected_version {body.expected_version} does not match "
                    f"current drill version {version}",
                    code=CODE_VERSION_CONFLICT,
                )

            seq = body.seq if body.seq is not None else drill["current_seq"] + 1
            if seq != drill["current_seq"] + 1:
                raise DrillConflict(
                    f"step sequence gap: next step is "
                    f"{drill['current_seq'] + 1}, got {seq}",
                    code=CODE_STEP_GAP,
                )
            if seq > total:
                raise DrillConflict(
                    f"step {seq} is beyond the frozen {total}-step sequence",
                    code=CODE_STEP_GAP,
                )
            step_spec = specs[seq - 1]

            # Defense in depth (the sequence is frozen, but re-validate that
            # every health target still belongs to this drill's manifest).
            manifest = set(drill["frozen"]["target_manifest"])
            for tid in (step_spec.get("health_changes") or {}):
                if tid not in manifest:
                    raise self._refuse(
                        drill_id,
                        "drill_step_rejected",
                        CODE_TARGET_NOT_FROZEN,
                        f"target {tid!r} is not in the frozen manifest",
                        version=version,
                        actor=actor,
                        extra={"seq": seq},
                    )

            # Simulated clock resolution.
            if step_spec.get("at") is not None:
                sim_now = step_spec["at"]
            elif step_spec.get("advance_seconds") is not None:
                base = (
                    drill["last_sim_time"]
                    if drill["last_sim_time"] is not None
                    else drill["base_sim_time"]
                )
                sim_now = base + step_spec["advance_seconds"]
            else:
                sim_now = drill["base_sim_time"]

            started_at = self._clock()
            input_snapshot = {
                "seq": seq,
                "request": {
                    "name": step_spec["name"],
                    "region": step_spec.get("region", ""),
                    "tenant": step_spec.get("tenant", ""),
                    "client": step_spec.get("client", ""),
                    "labels": step_spec.get("labels", {}),
                    "labels_sig": labels_signature(step_spec.get("labels") or {}),
                },
                "sim_time": sim_now,
                "health_before": dict(drill["health"]),
                "health_changes": dict(step_spec.get("health_changes") or {}),
                "cache_keys_before": sorted(
                    {
                        (e["name"], e["region"], e["tenant"], e["client_key"], e["labels_sig"])
                        for e in drill.get("cache_state") or []
                    }
                ),
                "status_before": status,
                "version_before": version,
            }

            answer, cache_after, health_after = self._replay(
                drill, step_spec, sim_now
            )
            order = self._target_order(answer)
            expected = step_spec.get("expected")
            diffs = self._expected_diff(expected, answer, order)
            matched = not diffs

            # Whether the served answer came from the simulated cache. The
            # resolver returns cached=True only for a valid, unexpired entry.
            cached_hit = bool(answer.get("cached"))
            cache_rows = _dump_cache(cache_after)

            result = {
                "seq": seq,
                "started_at": started_at,
                "recorded_at": self._clock(),
                "sim_time": sim_now,
                "input": input_snapshot,
                "health_after": health_after,
                "request": input_snapshot["request"],
                "answer": {
                    "status": answer.get("status"),
                    "chosen": answer.get("chosen"),
                    "degraded": answer.get("degraded", False),
                    "order": order,
                    "targets": answer.get("targets", []),
                    "rule_version": answer.get("rule_version"),
                    "rule_scope": answer.get("rule_scope"),
                    "release_group": answer.get("release_group"),
                    "config_version": answer.get("config_version"),
                    "ttl": answer.get("ttl"),
                    "expires_at": answer.get("expires_at"),
                },
                "order": order,
                "cache_hit": cached_hit,
                "cache_state_after": [
                    {
                        "kind": e["kind"],
                        "name": e["name"],
                        "region": e["region"],
                        "tenant": e["tenant"],
                        "client_key": e["client_key"],
                        "labels_sig": e["labels_sig"],
                        "rule_version": e["rule_version"],
                        "group_id": e["group_id"],
                        "stored_at": e["stored_at"],
                        "expires_at": e["expires_at"],
                    }
                    for e in cache_rows
                ],
                "expected": expected,
                "matched_expected": matched,
                "diffs": diffs,
                "diff_reasons": [d["field"] for d in diffs],
            }

            new_status = (
                STATUS_COMPLETED if seq == total else STATUS_RUNNING
            )
            new_version = version + 1
            now = self._clock()

            self._conn.execute(
                "INSERT INTO drill_steps"
                " (drill_id, run_epoch, seq, spec, result, started_at, recorded_at, actor)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    drill_id,
                    epoch,
                    seq,
                    json.dumps(step_spec, sort_keys=True),
                    json.dumps(result, sort_keys=True),
                    started_at,
                    result["recorded_at"],
                    actor,
                ),
            )
            self._conn.execute(
                "UPDATE drills SET status = ?, health = ?, cache_state = ?,"
                " current_seq = ?, last_sim_time = ?, version = ?,"
                " started_at = COALESCE(started_at, ?), paused_at = NULL,"
                " completed_at = CASE WHEN ? = 'completed' THEN ? ELSE completed_at END,"
                " updated_at = ? WHERE id = ? AND version = ?",
                (
                    new_status,
                    json.dumps(health_after, sort_keys=True),
                    json.dumps(cache_rows, sort_keys=True, default=_json_default),
                    seq,
                    sim_now,
                    new_version,
                    started_at,
                    new_status,
                    now,
                    now,
                    drill_id,
                    version,
                ),
            )
            self._audit(
                drill_id,
                "drill_step",
                {
                    "seq": seq,
                    "chosen": answer.get("chosen"),
                    "cache_hit": cached_hit,
                    "matched_expected": matched,
                    "diff_reasons": result["diff_reasons"],
                    "health_changes": step_spec.get("health_changes") or {},
                    "new_status": new_status,
                },
                version=new_version,
                actor=actor,
            )
            if new_status == STATUS_COMPLETED:
                self._audit(
                    drill_id,
                    "drill_completed",
                    {"seq": seq, "steps": total},
                    version=new_version,
                    actor=actor,
                )
            self._conn.commit()

            payload = {
                "drill_id": drill_id,
                "step": result,
                "status": new_status,
                "version": new_version,
                "current_seq": seq,
                "matched_expected": matched,
            }
            if idem_key:
                self._idem_store(drill_id, epoch, idem_key, "advance", fingerprint, 200, payload)
                self._conn.commit()
            return 200, payload

    def advance(
        self,
        drill_id: str,
        body: AdvanceIn,
        *,
        actor: Optional[str] = None,
        idem_key: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> tuple[int, dict]:
        try:
            return self._advance(
                drill_id, body, actor=actor, idem_key=idem_key, fingerprint=fingerprint
            )
        except DrillConflict as exc:
            # Audited semantic/version refusals: persist a drill_audit row so
            # the failed attempt is traceable alongside the lifecycle.
            if exc.code in (CODE_STATUS_CONFLICT, CODE_VERSION_CONFLICT, CODE_STEP_GAP):
                with self._lock:
                    row = self._conn.execute(
                        "SELECT version FROM drills WHERE id = ?", (drill_id,)
                    ).fetchone()
                    version = row["version"] if row else None
                    self._audit(
                        drill_id,
                        "drill_step_rejected",
                        {
                            "code": exc.code,
                            "detail": str(exc),
                            "seq": body.seq,
                        },
                        version=version,
                        actor=actor,
                    )
                    self._conn.commit()
            raise

    # -- lifecycle -----------------------------------------------------------

    def _transition(
        self,
        drill_id: str,
        action: str,
        allowed: tuple[str, ...],
        new_status: str,
        *,
        actor: Optional[str],
        expected_version: Optional[int],
        reason: Optional[str],
        idem_key: Optional[str],
        fingerprint: Optional[str],
        audit_action: str,
        time_field: Optional[str],
        clear_fields: Optional[tuple[str, ...]] = None,
        coalesce_time: bool = False,
    ) -> tuple[int, dict]:
        with self._lock:
            if idem_key:
                replay = self._idem_lookup(drill_id, idem_key, fingerprint)
                if replay is not None:
                    return replay[0], replay[1]
            row = self._row(drill_id)
            drill = self._row_to_dict(row)
            if (
                expected_version is not None
                and expected_version != drill["version"]
            ):
                raise self._refuse(
                    drill_id,
                    f"drill_{action}_rejected",
                    CODE_VERSION_CONFLICT,
                    f"expected_version {expected_version} does not match current "
                    f"drill version {drill['version']}",
                    version=drill["version"],
                    actor=actor,
                )
            if drill["status"] not in allowed:
                raise self._refuse(
                    drill_id,
                    f"drill_{action}_rejected",
                    CODE_STATUS_CONFLICT,
                    f"cannot {action} a drill in status {drill['status']!r}",
                    version=drill["version"],
                    actor=actor,
                    extra={"allowed": list(allowed)},
                )
            new_version = drill["version"] + 1
            now = self._clock()
            sets = ["status = ?", "version = ?", "updated_at = ?"]
            args: list = [new_status, new_version, now]
            if time_field:
                if coalesce_time:
                    sets.append(f"{time_field} = COALESCE({time_field}, ?)")
                else:
                    sets.append(f"{time_field} = ?")
                args.append(now)
            for field_name in clear_fields or ():
                sets.append(f"{field_name} = NULL")
            args.append(drill_id)
            self._conn.execute(
                f"UPDATE drills SET {', '.join(sets)} WHERE id = ?", args
            )
            self._audit(
                drill_id,
                audit_action,
                {
                    "from": drill["status"],
                    "to": new_status,
                    "reason": reason,
                },
                version=new_version,
                actor=actor,
            )
            self._conn.commit()
            payload = {
                "drill_id": drill_id,
                "status": new_status,
                "version": new_version,
                "current_seq": drill["current_seq"],
            }
            if idem_key:
                self._idem_store(
                    drill_id, drill["run_epoch"], idem_key, action, fingerprint,
                    200, payload,
                )
                self._conn.commit()
            return 200, payload

    def pause(
        self, drill_id, *, actor=None, expected_version=None, reason=None,
        idem_key=None, fingerprint=None,
    ):
        return self._transition(
            drill_id, "pause", (STATUS_RUNNING,), STATUS_PAUSED,
            actor=actor, expected_version=expected_version, reason=reason,
            idem_key=idem_key, fingerprint=fingerprint,
            audit_action="drill_paused", time_field="paused_at",
        )

    def resume(
        self, drill_id, *, actor=None, expected_version=None, reason=None,
        idem_key=None, fingerprint=None,
    ):
        # Resume both starts a ready drill (started_at fixed to first start)
        # and continues a paused one (paused_at cleared).
        return self._transition(
            drill_id, "resume", (STATUS_READY, STATUS_PAUSED), STATUS_RUNNING,
            actor=actor, expected_version=expected_version, reason=reason,
            idem_key=idem_key, fingerprint=fingerprint,
            audit_action="drill_resumed", time_field="started_at",
            clear_fields=("paused_at",), coalesce_time=True,
        )

    def reset(
        self, drill_id, *, actor=None, expected_version=None, reason=None,
        idem_key=None, fingerprint=None,
    ):
        with self._lock:
            if idem_key:
                replay = self._idem_lookup(drill_id, idem_key, fingerprint)
                if replay is not None:
                    return replay[0], replay[1]
            row = self._row(drill_id)
            drill = self._row_to_dict(row)
            if (
                expected_version is not None
                and expected_version != drill["version"]
            ):
                raise self._refuse(
                    drill_id,
                    "drill_reset_rejected",
                    CODE_VERSION_CONFLICT,
                    f"expected_version {expected_version} does not match current "
                    f"drill version {drill['version']}",
                    version=drill["version"],
                    actor=actor,
                )
            if drill["status"] == STATUS_REJECTED:
                raise self._refuse(
                    drill_id,
                    "drill_reset_rejected",
                    CODE_STATUS_CONFLICT,
                    "cannot reset a drill rejected at creation",
                    version=drill["version"],
                    actor=actor,
                )

            manifest = set(drill["frozen"]["target_manifest"])
            initial = {tid: True for tid in manifest}
            for tid, st in drill["frozen"]["initial_health_source"].items():
                if tid in manifest:
                    initial[tid] = bool(st.get("healthy", True))
            new_epoch = drill["run_epoch"] + 1
            new_version = drill["version"] + 1
            now = self._clock()
            # Old step rows are kept for audit but belong to the prior epoch;
            # the new run starts with no current steps.
            self._conn.execute(
                "UPDATE drills SET status = ?, health = ?, cache_state = '[]',"
                " current_seq = 0, last_sim_time = NULL, run_epoch = ?,"
                " version = ?, paused_at = NULL, completed_at = NULL,"
                " started_at = NULL, updated_at = ? WHERE id = ?",
                (STATUS_READY, json.dumps(initial, sort_keys=True),
                 new_epoch, new_version, now, drill_id),
            )
            self._conn.execute(
                "DELETE FROM drill_reports WHERE drill_id = ?", (drill_id,)
            )
            self._audit(
                drill_id,
                "drill_reset",
                {
                    "old_epoch": drill["run_epoch"],
                    "new_epoch": new_epoch,
                    "reason": reason,
                    "cleared_steps": drill["current_seq"],
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
                "current_seq": 0,
            }
            if idem_key:
                self._idem_store(
                    drill_id, new_epoch, idem_key, "reset", fingerprint, 200, payload
                )
                self._conn.commit()
            return 200, payload

    # -- steps, audit, listing ----------------------------------------------

    def step(self, drill_id: str, seq: int) -> dict:
        with self._lock:
            drill = self._load(drill_id)
            row = self._conn.execute(
                "SELECT result FROM drill_steps"
                " WHERE drill_id = ? AND run_epoch = ? AND seq = ?",
                (drill_id, drill["run_epoch"], seq),
            ).fetchone()
        if row is None:
            raise DrillNotFound(
                f"step {seq} has not been recorded in drill {drill_id!r}'s "
                "current run",
            )
        return json.loads(row["result"])

    def steps(self, drill: dict) -> list[dict]:
        rows = self._conn.execute(
            "SELECT result FROM drill_steps"
            " WHERE drill_id = ? AND run_epoch = ? ORDER BY seq",
            (drill["id"], drill["run_epoch"]),
        ).fetchall()
        return [json.loads(r["result"]) for r in rows]

    def list_drills(
        self,
        *,
        status: Optional[str] = None,
        config_version: Optional[int] = None,
        limit: int = 200,
    ) -> list[dict]:
        sql = "SELECT * FROM drills WHERE 1=1"
        args: list = []
        if status:
            sql += " AND status = ?"
            args.append(status)
        if config_version is not None:
            sql += " AND config_version = ?"
            args.append(config_version)
        sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [self._summary(self._row_to_dict(r)) for r in rows]

    def drill_audit(
        self,
        drill_id: Optional[str] = None,
        *,
        action: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 500,
    ) -> list[dict]:
        sql = "SELECT * FROM drill_audit WHERE 1=1"
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

    # -- report --------------------------------------------------------------

    def report(self, drill_id: str) -> dict:
        """Return the frozen read-only report, generating it at most once."""
        with self._lock:
            drill = self._load(drill_id)
            row = self._conn.execute(
                "SELECT content, checksum, created_at FROM drill_reports"
                " WHERE drill_id = ?",
                (drill_id,),
            ).fetchone()
            if row is not None:
                content = json.loads(row["content"])
                return {
                    "report": content,
                    "checksum": row["checksum"],
                    "generated_at": row["created_at"],
                    "idempotent_replay": True,
                }

            steps = self.steps(drill)
            content = self._build_report(drill, steps)
            canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
            checksum = hashlib.blake2b(
                canonical.encode(), digest_size=16
            ).hexdigest()
            generated_at = self._clock()
            self._conn.execute(
                "INSERT INTO drill_reports"
                " (drill_id, run_epoch, created_at, content, checksum)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    drill_id,
                    drill["run_epoch"],
                    generated_at,
                    json.dumps(content, sort_keys=True),
                    checksum,
                ),
            )
            self._audit(
                drill_id,
                "drill_report_generated",
                {
                    "checksum": checksum,
                    "steps_included": len(steps),
                    "run_epoch": drill["run_epoch"],
                },
                version=drill["version"],
            )
            self._conn.commit()
            return {
                "report": content,
                "checksum": checksum,
                "generated_at": generated_at,
                "idempotent_replay": False,
            }

    def _build_report(self, drill: dict, steps: list[dict]) -> dict:
        frozen = drill["frozen"]
        first_diff = None
        step_reports = []
        matched = 0
        for s in steps:
            diffs = s.get("diffs") or []
            if first_diff is None and diffs:
                first_diff = {
                    "seq": s["seq"],
                    "diff_reasons": s.get("diff_reasons") or [d["field"] for d in diffs],
                    "diffs": diffs,
                }
            if s.get("matched_expected"):
                matched += 1
            expected = s.get("expected") or {}
            step_reports.append(
                {
                    "seq": s["seq"],
                    "request": s.get("request"),
                    "sim_time": s.get("sim_time"),
                    "started_at": s.get("started_at"),
                    "health_changes": (s.get("input") or {}).get("health_changes", {}),
                    "health_after": s.get("health_after"),
                    "expected": expected or None,
                    "actual": {
                        "status": (s.get("answer") or {}).get("status"),
                        "chosen": (s.get("answer") or {}).get("chosen"),
                        "degraded": (s.get("answer") or {}).get("degraded"),
                        "order": s.get("order"),
                    },
                    "matched_expected": s.get("matched_expected"),
                    "cache_hit": s.get("cache_hit"),
                    "diffs": diffs,
                }
            )
        return {
            "drill_id": drill["id"],
            "generated_for_run_epoch": drill["run_epoch"],
            "status": drill["status"],
            "config_version": drill["config_version"],
            "created_at": drill["created_at"],
            "created_by": drill["created_by"],
            "description": drill["spec"].get("description", ""),
            "frozen_snapshot": {
                "config_version": frozen["config_version"],
                "target_manifest": frozen["target_manifest"],
                "rule_summary": frozen["rule_summary"],
                "release_group_summary": frozen["release_group_summary"],
                "rate_limit_tier_summary": frozen["rate_limit_tier_summary"],
            },
            "steps_planned": drill["spec"]["step_count"],
            "steps_recorded": len(steps),
            "steps_matched": matched,
            "steps_diverged": len(steps) - matched,
            "first_diff": first_diff,
            "steps": step_reports,
        }

    # -- idempotency ---------------------------------------------------------

    def _idem_lookup(
        self,
        drill_id: str,
        key: str,
        fingerprint: Optional[str],
    ) -> Optional[tuple[int, dict]]:
        # Only the *current* run epoch's keys are live. A reset starts a new
        # epoch, so a key retried after restart/replay must never resurrect
        # the previous run's recorded response; the stale row is left in
        # place for the audit trail but simply ignored.
        cur = self._conn.execute(
            "SELECT version, run_epoch FROM drills WHERE id = ?", (drill_id,)
        ).fetchone()
        if cur is None:
            return None
        row = self._conn.execute(
            "SELECT run_epoch, fingerprint, status_code, response FROM"
            " drill_idempotency"
            " WHERE drill_id = ? AND run_epoch = ? AND idem_key = ?",
            (drill_id, cur["run_epoch"], key),
        ).fetchone()
        if row is None:
            return None
        if fingerprint is not None and fingerprint != row["fingerprint"]:
            raise DrillConflict(
                "Idempotency-Key was already used with a different request payload",
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
                "INSERT INTO drill_idempotency"
                " (drill_id, run_epoch, idem_key, action, fingerprint,"
                "  status_code, response, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    drill_id,
                    run_epoch,
                    key,
                    action,
                    fingerprint or "",
                    status_code,
                    json.dumps(body, sort_keys=True),
                    self._clock(),
                ),
            )
        except sqlite3.IntegrityError:
            # Concurrent first-submit winner persisted first; its row wins.
            self._conn.rollback()

    # -- views ---------------------------------------------------------------

    @staticmethod
    def _summary(d: dict) -> dict:
        return {
            "id": d["id"],
            "status": d["status"],
            "config_version": d["config_version"],
            "run_epoch": d["run_epoch"],
            "version": d["version"],
            "current_seq": d["current_seq"],
            "steps_planned": d["spec"]["step_count"],
            "description": d["spec"].get("description", ""),
            "created_by": d["created_by"],
            "created_at": d["created_at"],
            "started_at": d["started_at"],
            "paused_at": d["paused_at"],
            "completed_at": d["completed_at"],
            "rejection": d["rejection"],
        }

    def _public(self, d: dict, *, include_steps: bool = False) -> dict:
        out = self._summary(d)
        out["base_sim_time"] = d["base_sim_time"]
        out["last_sim_time"] = d["last_sim_time"]
        out["frozen"] = {
            "config_version": d["frozen"]["config_version"],
            "target_manifest": d["frozen"]["target_manifest"],
            "rule_summary": d["frozen"]["rule_summary"],
            "release_group_summary": d["frozen"]["release_group_summary"],
            "rate_limit_tier_summary": d["frozen"]["rate_limit_tier_summary"],
        }
        out["health"] = d["health"]
        out["steps_spec"] = d["spec"]["steps"]
        if include_steps:
            out["steps"] = self.steps(d)
            out["cache_state"] = [
                {
                    "kind": e["kind"],
                    "name": e["name"],
                    "region": e["region"],
                    "tenant": e["tenant"],
                    "client_key": e["client_key"],
                    "labels_sig": e["labels_sig"],
                    "rule_version": e["rule_version"],
                    "group_id": e["group_id"],
                    "stored_at": e["stored_at"],
                    "expires_at": e["expires_at"],
                }
                for e in d["cache_state"]
            ]
        return out


def _json_default(obj):
    if isinstance(obj, frozenset):
        return sorted(obj)
    if isinstance(obj, set):
        return sorted(obj)
    return str(obj)


# -- simulated health registry ----------------------------------------------


class _SimHealth:
    """A private health registry seeded with the drill's current health set.

    Unknown targets fail open, matching the production registry. Targets in
    the frozen manifest are all seeded explicitly, so isolation tests see a
    fully determined view.
    """

    def __init__(self, health_map: dict[str, bool]):
        self._health = dict(health_map)

    def is_healthy(self, target_id: str) -> bool:
        return self._health.get(target_id, True)

    def set(self, target_id: str, healthy: bool, now: Optional[float] = None) -> None:  # noqa: ARG002
        self._health[target_id] = healthy

    def snapshot_booleans(self) -> dict[str, bool]:
        return dict(self._health)
