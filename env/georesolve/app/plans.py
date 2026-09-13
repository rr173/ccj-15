"""Reusable drill plans, independent runs and run branches.

A **plan** turns one completed fault drill (see :mod:`app.drills`) into a
named, reusable, frozen artefact. Saving a plan freezes *exactly* what the
drill was executed against:

- the config version and its full bundle payload (frozen snapshot);
- the target manifest (every target id referenced by the frozen version);
- the rule / release-group / rate-limit-tier summaries;
- the ordered, numbered step inputs (request, labels, simulated time) and
  each step's expected result;
- the deterministic initial simulated health set the sequence starts from.

Plans are immutable; the only later lifecycle event is archival. An archived
plan can no longer spawn runs.

Runs
----
``POST /v1/drill-plans/{id}/runs`` starts a new **independent run** of a plan.
Every run gets its own:

- lifecycle state (``ready -> running <-> paused -> completed``);
- simulated health registry;
- simulated-clock resolution cache;
- recorded step results;
- optimistic-concurrency ``version`` and reset ``run_epoch``;
- owner (``owner_id``) and free-form note.

Two runs of one plan share nothing mutable: advancing, pausing, resetting or
reporting one run can never change another run, the plan, a sibling run or a
branch. Replay itself reuses the exact production-isolation machinery of
:mod:`app.drills` (``replay_step``): the live config, health view, cache,
rate limiter, metering and real audit log are never touched.

Branches
--------
From any already-recorded step of a run, an owner may create a **branch**:

- steps up to and including the branch point are inherited read-only -- the
  branch freezes their inputs *and* their recorded results (answer, order,
  cache-hit flag, health set, full simulated cache state at that point);
- the steps after the branch point are supplied afresh on the branch request
  and may replace request inputs, simulated health changes and expected
  results;
- the branch is an independent run with its own state and owner; whatever the
  parent run does later (advance, pause, reset, report, branch again) can
  never alter the branch, and vice versa.

Comparison reports
------------------
``POST /v1/drill-runs/{id}/compare`` produces a read-only report against
another run. The report pins both runs to the versions they held at
generation time and names the *first* divergence found, in a fixed order:

1. recorded-step progress (one run ahead of the other),
2. step input (request triple / client / labels / simulated time),
3. health set,
4. resolution (parse/rule) ordering,
5. cache hit,
6. expected result.

A given pair of runs at a given pair of versions always yields the same
stored report and checksum; asking for the same pair again replays it.

Persistence
-----------
Plans, runs, steps, branches, idempotency records and comparison reports are
all SQLite-persisted; snapshots, run relationships, owner permissions,
branch results, optimistic versions and report checksums therefore survive
service restarts unchanged.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from typing import Callable, Optional

from pydantic import BaseModel, ConfigDict, Field

from .config_store import ConfigManager
from .drills import (
    CODE_BAD_STEP_PAYLOAD,
    CODE_ILLEGAL_HEALTH,
    CODE_STEP_GAP,
    CODE_STATUS_CONFLICT,
    CODE_STEPS_MISSING,
    CODE_TARGET_NOT_FROZEN,
    CODE_VERSION_CONFLICT,
    DrillConflict,
    DrillError,
    DrillNotFound,
    DrillStore,
    DrillValidation,
    STATUS_COMPLETED,
    STATUS_PAUSED,
    STATUS_READY,
    STATUS_RUNNING,
    build_frozen,
    cache_keys,
    compose_step_result,
    public_cache_view,
    public_step_result,
    replay_step,
    target_order,
)

# -- plan lifecycle ----------------------------------------------------------

PLAN_ACTIVE = "active"
PLAN_ARCHIVED = "archived"

# -- refusal codes (also written to plan_audit) ------------------------------

CODE_PLAN_NOT_FOUND = "plan_not_found"
CODE_RUN_NOT_FOUND = "run_not_found"
CODE_DRILL_NOT_COMPLETED = "drill_not_completed"
CODE_PLAN_ARCHIVED = "plan_archived"
CODE_OWNER_MISMATCH = "owner_mismatch"
CODE_BRANCH_POINT_INVALID = "branch_point_invalid"
CODE_BRANCH_TAIL_LENGTH = "branch_tail_length"
CODE_COMPARE_PLAN_MISMATCH = "compare_plan_mismatch"
CODE_PLAN_IDEMPOTENCY_CONFLICT = "idempotency_conflict"
CODE_PLAN_ID_CONFLICT = "plan_id_conflict"
CODE_RUN_ID_CONFLICT = "run_id_conflict"


class PlanError(DrillError):
    code = "plan_error"
    status_code = 409


class PlanNotFound(PlanError):
    code = CODE_PLAN_NOT_FOUND
    status_code = 404


class RunNotFound(PlanError):
    code = CODE_RUN_NOT_FOUND
    status_code = 404


class PlanValidation(DrillValidation):
    pass


class PlanConflict(DrillConflict):
    pass


class PlanForbidden(PlanError):
    """Authenticated caller is not the run's owner (HTTP 403)."""

    code = CODE_OWNER_MISMATCH
    status_code = 403


# -- request models ----------------------------------------------------------


class PlanCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_id: Optional[str] = Field(default=None, description="optional explicit id")
    name: str = Field(min_length=1, description="human-readable plan name")
    description: str = ""
    # Exactly one source: an existing completed drill, or a saved config
    # version plus a fresh step sequence.
    source_drill_id: Optional[str] = None
    config_version: Optional[int] = Field(default=None, ge=1)
    steps: Optional[list[dict]] = None
    initial_health: Optional[dict] = None
    expected_version: Optional[int] = Field(default=None, ge=0)


class PlanArchiveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: Optional[int] = Field(default=None, ge=1)
    reason: Optional[str] = None


class RunCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: Optional[str] = None
    owner_id: Optional[str] = Field(
        default=None, description="defaults to the calling identity"
    )
    note: str = ""
    expected_version: Optional[int] = Field(
        default=None,
        ge=0,
        description="optimistic token on the *plan* version",
    )


class BranchCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: Optional[str] = None
    branch_point_seq: int = Field(ge=1, description="an already-recorded step")
    steps: list[dict] = Field(
        ...,
        description="replacement specs for the steps after the branch point",
    )
    owner_id: Optional[str] = None
    note: str = ""
    expected_version: Optional[int] = Field(
        default=None,
        ge=1,
        description="optimistic token on the *parent run* version",
    )


class RunAdvanceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seq: Optional[int] = Field(default=None, ge=1)
    expected_version: Optional[int] = Field(default=None, ge=1)


class RunTransitionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: Optional[int] = Field(default=None, ge=1)
    reason: Optional[str] = None


class CompareIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    other_run_id: str


# -- helpers -----------------------------------------------------------------


def _plan_fingerprint(body: dict) -> str:
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _canonical_checksum(content: dict) -> str:
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
    return hashlib.blake2b(canonical.encode(), digest_size=16).hexdigest()


def _normalize_owner(value: Optional[str]) -> str:
    v = (value or "").strip()
    if not v:
        raise PlanValidation("owner_id must be a non-empty string")
    return v


def initial_health_from_frozen(frozen: dict, overrides: Optional[dict]) -> dict:
    """Deterministic initial health set for a fresh run of a frozen plan."""
    manifest = set(frozen["target_manifest"])
    initial = {tid: True for tid in manifest}
    for tid, st in (frozen.get("initial_health_source") or {}).items():
        if tid in initial:
            initial[tid] = bool(st.get("healthy", True))
    for tid, healthy in (overrides or {}).items():
        if tid not in manifest:
            raise PlanConflict(
                f"target {tid!r} is not in the frozen manifest",
                code=CODE_TARGET_NOT_FROZEN,
            )
        if not isinstance(healthy, bool):
            raise PlanConflict(
                f"initial health for {tid!r} must be a boolean",
                code=CODE_ILLEGAL_HEALTH,
            )
        initial[tid] = healthy
    return initial


# -- the store ---------------------------------------------------------------


class PlanStore:
    def __init__(
        self,
        conn: sqlite3.Connection,
        config: ConfigManager,
        drills: DrillStore,
        clock: Callable[[], float] = time.time,
    ):
        self._conn = conn
        self._config = config
        self._drills = drills
        self._clock = clock
        self._lock = threading.RLock()

    # -- audit ---------------------------------------------------------------

    def _audit(
        self,
        action: str,
        details: dict,
        *,
        plan_id: Optional[str] = None,
        run_id: Optional[str] = None,
        version: Optional[int] = None,
        actor: Optional[str] = None,
    ) -> None:
        self._conn.execute(
            "INSERT INTO plan_audit (plan_id, run_id, ts, actor, action, version,"
            " details) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                plan_id,
                run_id,
                self._clock(),
                actor,
                action,
                version,
                json.dumps(details, sort_keys=True),
            ),
        )

    def _refuse(
        self,
        action: str,
        code: str,
        detail: str,
        *,
        plan_id: Optional[str] = None,
        run_id: Optional[str] = None,
        version: Optional[int] = None,
        actor: Optional[str] = None,
        extra: Optional[dict] = None,
        exc_class: type[PlanError] = PlanConflict,
    ) -> PlanError:
        details = {"code": code, "detail": detail}
        if extra:
            details.update(extra)
        with self._lock:
            self._audit(
                action,
                details,
                plan_id=plan_id,
                run_id=run_id,
                version=version,
                actor=actor,
            )
            self._conn.commit()
        return exc_class(detail, code=code)

    # -- row loading ---------------------------------------------------------

    def _plan_row(self, plan_id: str) -> sqlite3.Row:
        row = self._conn.execute(
            "SELECT * FROM drill_plans WHERE id = ?", (plan_id,)
        ).fetchone()
        if row is None:
            raise PlanNotFound(f"drill plan {plan_id!r} does not exist")
        return row

    def _load_plan(self, plan_id: str) -> dict:
        return self._plan_to_dict(self._plan_row(plan_id))

    @staticmethod
    def _plan_to_dict(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "status": row["status"],
            "config_version": row["config_version"],
            "frozen": json.loads(row["frozen"]),
            "spec": json.loads(row["spec"]),
            "initial_health": json.loads(row["initial_health"]),
            "version": row["version"],
            "created_by": row["created_by"],
            "source_drill_id": row["source_drill_id"],
            "created_at": row["created_at"],
            "archived_at": row["archived_at"],
            "updated_at": row["updated_at"],
        }

    def _run_row(self, run_id: str) -> sqlite3.Row:
        row = self._conn.execute(
            "SELECT * FROM plan_runs WHERE id = ?", (run_id,)
        ).fetchone()
        if row is None:
            raise RunNotFound(f"drill run {run_id!r} does not exist")
        return row

    def _load_run(self, run_id: str) -> dict:
        return self._run_to_dict(self._run_row(run_id))

    @staticmethod
    def _run_to_dict(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "plan_id": row["plan_id"],
            "status": row["status"],
            "owner_id": row["owner_id"],
            "note": row["note"],
            "base_sim_time": row["base_sim_time"],
            "branch_point_seq": row["branch_point_seq"],
            "parent_run_id": row["parent_run_id"],
            "parent_run_epoch": row["parent_run_epoch"],
            "spec": json.loads(row["spec"]),
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
            "updated_at": row["updated_at"],
        }

    # -- ownership -----------------------------------------------------------

    def _is_privileged(self, actor: Optional[str]) -> bool:
        # The static bootstrap token and the unauthenticated open mode act as
        # the global administrator and may access every run.
        return actor in (None, "bootstrap", "open")

    def _require_owner(self, run: dict, actor: Optional[str]) -> None:
        if self._is_privileged(actor):
            return
        if actor != run["owner_id"]:
            raise self._refuse(
                "run_access_denied",
                CODE_OWNER_MISMATCH,
                f"identity {actor!r} is not the owner "
                f"{run['owner_id']!r} of run {run['id']!r}",
                plan_id=run["plan_id"],
                run_id=run["id"],
                version=run["version"],
                actor=actor,
                exc_class=PlanForbidden,
            )

    # -- validation ----------------------------------------------------------

    def _validate_steps(self, raw_steps: list, manifest: set[str]) -> list[dict]:
        from .drills import DrillStepIn  # local: avoid a circular import surprise

        if not raw_steps:
            raise PlanConflict(
                "a plan requires at least one step", code=CODE_STEPS_MISSING
            )
        steps: list[dict] = []
        seen: set[int] = set()
        for i, raw in enumerate(raw_steps, start=1):
            if not isinstance(raw, dict):
                raise PlanValidation(
                    f"step {i}: must be an object", code=CODE_BAD_STEP_PAYLOAD
                )
            # Stored specs already carry the normalized position; strip it so
            # the strict input model accepts a re-validated frozen sequence.
            clean = {k: v for k, v in raw.items() if k != "seq"}
            try:
                parsed = DrillStepIn(**clean)
            except Exception as exc:  # pydantic ValidationError
                raise PlanValidation(
                    f"step {i}: {exc}", code=CODE_BAD_STEP_PAYLOAD
                ) from exc
            step = self._drills._validate_step(clean, i, manifest)
            if step["seq"] in seen:
                raise PlanConflict(
                    f"duplicate step number {i}", code="duplicate_step_number"
                )
            seen.add(step["seq"])
            steps.append(step)
        return steps

    # -- create plan ---------------------------------------------------------

    def create_plan(
        self,
        req: PlanCreateIn,
        *,
        actor: Optional[str] = None,
        idem_key: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> tuple[int, dict]:
        # Generic, identity-scoped idempotency (survives reset-less plans
        # forever; the plan never has run epochs).
        if idem_key:
            replay = self._idem_lookup(idem_key, actor, fingerprint)
            if replay is not None:
                return replay

        with self._lock:
            plan_id = (req.plan_id or f"plan_{secrets.token_urlsafe(12)}").strip()
            if not plan_id:
                raise PlanValidation("plan_id must be non-empty")
            name = req.name.strip()
            if not name:
                raise PlanValidation("plan name must be non-empty")
            now = self._clock()

            source_drill_id: Optional[str] = None
            if req.source_drill_id:
                # Freeze from a completed drill: take its frozen bundle and
                # the exact recorded spec (normalized steps + description).
                try:
                    drill = self._drills.get(req.source_drill_id)
                except DrillNotFound as exc:
                    raise PlanNotFound(
                        f"source drill {req.source_drill_id!r} does not exist",
                        code="drill_not_found",
                    ) from exc
                if drill["status"] != STATUS_COMPLETED:
                    raise self._refuse(
                        "plan_create_rejected",
                        CODE_DRILL_NOT_COMPLETED,
                        f"drill {req.source_drill_id!r} is {drill['status']!r}; "
                        "only completed drills can be saved as plans",
                        actor=actor,
                        extra={"drill_status": drill["status"]},
                    )
                config_version = drill["config_version"]
                frozen = self._frozen_from_saved(config_version)
                # Re-normalize the drill's steps against this manifest before
                # freezing, so a plan stores the exact same spec shape.
                steps = self._validate_steps(
                    drill["steps_spec"], set(frozen["target_manifest"])
                )
                initial_health = initial_health_from_frozen(frozen, req.initial_health)
                source_drill_id = req.source_drill_id
                description = req.description or drill.get("description", "")
            else:
                if req.config_version is None:
                    raise PlanValidation(
                        "plan creation requires source_drill_id or config_version"
                    )
                config_version = req.config_version
                frozen = self._frozen_from_saved(config_version)
                steps = self._validate_steps(
                    req.steps or [], set(frozen["target_manifest"])
                )
                initial_health = initial_health_from_frozen(
                    frozen, req.initial_health
                )
                description = req.description

            spec = {
                "steps": steps,
                "step_count": len(steps),
                # Frozen simulated-clock anchor: every run of this plan
                # replays from the same base time, so independent runs are
                # deterministic and directly comparable.
                "base_sim_time": now,
            }
            try:
                self._conn.execute(
                    "INSERT INTO drill_plans (id, name, description, status,"
                    " config_version, source_drill_id, spec, frozen,"
                    " initial_health, version, created_by, created_at,"
                    " archived_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, NULL, ?)",
                    (
                        plan_id,
                        name,
                        description,
                        PLAN_ACTIVE,
                        config_version,
                        source_drill_id,
                        json.dumps(spec, sort_keys=True),
                        json.dumps(frozen, sort_keys=True),
                        json.dumps(initial_health, sort_keys=True),
                        actor,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise PlanConflict(
                    f"plan id {plan_id!r} already exists", code=CODE_PLAN_ID_CONFLICT
                ) from exc
            self._audit(
                "plan_created",
                {
                    "name": name,
                    "config_version": config_version,
                    "steps": len(steps),
                    "targets": sorted(frozen["target_manifest"]),
                    "source_drill_id": source_drill_id,
                },
                plan_id=plan_id,
                version=1,
                actor=actor,
            )
            self._conn.commit()
            payload = {"plan": self.get_plan(plan_id)}
            if idem_key:
                self._idem_store(idem_key, actor, "plan_create", fingerprint, 201, payload)
                self._conn.commit()
            return 201, payload

    def _frozen_from_saved(self, config_version: int) -> dict:
        try:
            bundle = self._config.saved_bundle(config_version)
        except Exception as exc:
            raise PlanNotFound(
                str(exc), code="config_version_not_found"
            ) from exc
        # Plans are not anchored to the mutable live view: the frozen source
        # health set defaults to all-healthy; the live view is folded in only
        # implicitly through a source drill's freeze when one is used.
        return build_frozen(bundle, {})

    # -- plan read side ------------------------------------------------------

    def _plan_public(self, d: dict, *, run_count: Optional[int] = None) -> dict:
        out = {
            "id": d["id"],
            "name": d["name"],
            "description": d["description"],
            "status": d["status"],
            "config_version": d["config_version"],
            "source_drill_id": d["source_drill_id"],
            "version": d["version"],
            "steps_planned": d["spec"]["step_count"],
            "initial_health": d["initial_health"],
            "created_by": d["created_by"],
            "created_at": d["created_at"],
            "archived_at": d["archived_at"],
            "updated_at": d["updated_at"],
            "frozen": {
                "config_version": d["frozen"]["config_version"],
                "target_manifest": d["frozen"]["target_manifest"],
                "rule_summary": d["frozen"]["rule_summary"],
                "release_group_summary": d["frozen"]["release_group_summary"],
                "rate_limit_tier_summary": d["frozen"]["rate_limit_tier_summary"],
            },
            "steps_spec": d["spec"]["steps"],
        }
        if run_count is not None:
            out["run_count"] = run_count
        return out

    def get_plan(self, plan_id: str) -> dict:
        with self._lock:
            plan = self._load_plan(plan_id)
            count = self._conn.execute(
                "SELECT COUNT(*) AS n FROM plan_runs WHERE plan_id = ?", (plan_id,)
            ).fetchone()["n"]
        return self._plan_public(plan, run_count=count)

    def list_plans(
        self,
        *,
        status: Optional[str] = None,
        config_version: Optional[int] = None,
        limit: int = 200,
    ) -> list[dict]:
        sql = "SELECT * FROM drill_plans WHERE 1=1"
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
            out = []
            for row in rows:
                count = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM plan_runs WHERE plan_id = ?",
                    (row["id"],),
                ).fetchone()["n"]
                out.append(self._plan_public(self._plan_to_dict(row), run_count=count))
        return out

    # -- archive -------------------------------------------------------------

    def archive_plan(
        self,
        plan_id: str,
        req: PlanArchiveIn,
        *,
        actor: Optional[str] = None,
        idem_key: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> tuple[int, dict]:
        with self._lock:
            if idem_key:
                replay = self._idem_lookup(idem_key, actor, fingerprint)
                if replay is not None:
                    return replay
            plan = self._load_plan(plan_id)
            if (
                req.expected_version is not None
                and req.expected_version != plan["version"]
            ):
                raise self._refuse(
                    "plan_archive_rejected",
                    CODE_VERSION_CONFLICT,
                    f"expected_version {req.expected_version} does not match plan "
                    f"version {plan['version']}",
                    plan_id=plan_id,
                    version=plan["version"],
                    actor=actor,
                )
            if plan["status"] == PLAN_ARCHIVED:
                # Archiving is an idempotent state: a repeated request (same
                # key) replays above; without a key it is a no-op success.
                payload = {"plan": self.get_plan(plan_id)}
                return 200, payload
            new_version = plan["version"] + 1
            now = self._clock()
            cur = self._conn.execute(
                "UPDATE drill_plans SET status = ?, version = ?, archived_at = ?,"
                " updated_at = ? WHERE id = ? AND version = ?",
                (PLAN_ARCHIVED, new_version, now, now, plan_id, plan["version"]),
            )
            if cur.rowcount == 0:
                raise self._refuse(
                    "plan_archive_rejected",
                    CODE_VERSION_CONFLICT,
                    f"plan {plan_id!r} changed concurrently",
                    plan_id=plan_id,
                    version=plan["version"],
                    actor=actor,
                )
            self._audit(
                "plan_archived",
                {"reason": req.reason, "from_version": plan["version"]},
                plan_id=plan_id,
                version=new_version,
                actor=actor,
            )
            self._conn.commit()
            payload = {"plan": self.get_plan(plan_id)}
            if idem_key:
                self._idem_store(
                    idem_key, actor, "plan_archive", fingerprint, 200, payload
                )
                self._conn.commit()
            return 200, payload

    # -- runs ----------------------------------------------------------------

    def create_run(
        self,
        plan_id: str,
        req: RunCreateIn,
        *,
        actor: Optional[str] = None,
        idem_key: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> tuple[int, dict]:
        with self._lock:
            if idem_key:
                replay = self._idem_lookup(idem_key, actor, fingerprint)
                if replay is not None:
                    return replay
            plan = self._load_plan(plan_id)
            if plan["status"] == PLAN_ARCHIVED:
                raise self._refuse(
                    "run_create_rejected",
                    CODE_PLAN_ARCHIVED,
                    f"plan {plan_id!r} is archived and cannot start new runs",
                    plan_id=plan_id,
                    version=plan["version"],
                    actor=actor,
                )
            if (
                req.expected_version is not None
                and req.expected_version != plan["version"]
            ):
                raise self._refuse(
                    "run_create_rejected",
                    CODE_VERSION_CONFLICT,
                    f"expected_version {req.expected_version} does not match plan "
                    f"version {plan['version']}",
                    plan_id=plan_id,
                    version=plan["version"],
                    actor=actor,
                )
            owner = _normalize_owner(req.owner_id or actor)
            run_id = (req.run_id or f"run_{secrets.token_urlsafe(12)}").strip()
            if not run_id:
                raise PlanValidation("run_id must be non-empty")
            now = self._clock()
            new_plan_version = plan["version"] + 1
            # The plan version is the optimistic token serializing run
            # creation: two concurrent starts cannot both bump it.
            cur = self._conn.execute(
                "UPDATE drill_plans SET version = ?, updated_at = ?"
                " WHERE id = ? AND version = ?",
                (new_plan_version, now, plan_id, plan["version"]),
            )
            if cur.rowcount == 0:
                raise self._refuse(
                    "run_create_rejected",
                    CODE_VERSION_CONFLICT,
                    f"plan {plan_id!r} changed concurrently",
                    plan_id=plan_id,
                    version=plan["version"],
                    actor=actor,
                )
            spec = {"steps": plan["spec"]["steps"], "step_count": plan["spec"]["step_count"]}
            base_sim_time = plan["spec"].get("base_sim_time", now)
            try:
                self._conn.execute(
                    "INSERT INTO plan_runs (id, plan_id, status, owner_id, note,"
                    " base_sim_time, branch_point_seq, parent_run_id,"
                    " parent_run_epoch, spec, health, cache_state, current_seq,"
                    " last_sim_time, run_epoch, version, created_by, created_at,"
                    " started_at, paused_at, completed_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?, ?, 0, NULL,"
                    " 1, 1, ?, ?, NULL, NULL, NULL, ?)",
                    (
                        run_id,
                        plan_id,
                        STATUS_READY,
                        owner,
                        req.note,
                        base_sim_time,
                        json.dumps(spec, sort_keys=True),
                        json.dumps(plan["initial_health"], sort_keys=True),
                        "[]",
                        actor,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise PlanConflict(
                    f"run id {run_id!r} already exists", code=CODE_RUN_ID_CONFLICT
                ) from exc
            self._audit(
                "run_created",
                {
                    "owner_id": owner,
                    "note": req.note,
                    "steps": spec["step_count"],
                    "plan_version": new_plan_version,
                },
                plan_id=plan_id,
                run_id=run_id,
                version=1,
                actor=actor,
            )
            self._conn.commit()
            payload = {
                "run": self._run_public(self._load_run(run_id), include_steps=True)
            }
            if idem_key:
                self._idem_store(
                    idem_key, actor, "run_create", fingerprint, 201, payload
                )
                self._conn.commit()
            return 201, payload

    def _run_summary(self, d: dict) -> dict:
        return {
            "id": d["id"],
            "plan_id": d["plan_id"],
            "status": d["status"],
            "owner_id": d["owner_id"],
            "note": d["note"],
            "version": d["version"],
            "run_epoch": d["run_epoch"],
            "current_seq": d["current_seq"],
            "steps_planned": d["spec"]["step_count"],
            "branch_point_seq": d["branch_point_seq"],
            "parent_run_id": d["parent_run_id"],
            "created_by": d["created_by"],
            "created_at": d["created_at"],
            "started_at": d["started_at"],
            "paused_at": d["paused_at"],
            "completed_at": d["completed_at"],
            "updated_at": d["updated_at"],
        }

    def _run_public(self, d: dict, *, include_steps: bool = False) -> dict:
        out = self._run_summary(d)
        out["base_sim_time"] = d["base_sim_time"]
        out["last_sim_time"] = d["last_sim_time"]
        out["health"] = d["health"]
        out["steps_spec"] = d["spec"]["steps"]
        out["cache_state"] = public_cache_view(d["cache_state"])
        if include_steps:
            out["steps"] = self.run_steps(d)
        return out

    def get_run(self, run_id: str, *, actor: Optional[str] = None) -> dict:
        with self._lock:
            run = self._load_run(run_id)
            self._require_owner(run, actor)
            return self._run_public(run, include_steps=True)

    def list_runs(
        self,
        *,
        plan_id: Optional[str] = None,
        owner_id: Optional[str] = None,
        status: Optional[str] = None,
        actor: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        sql = "SELECT * FROM plan_runs WHERE 1=1"
        args: list = []
        if plan_id is not None:
            sql += " AND plan_id = ?"
            args.append(plan_id)
        if owner_id is not None:
            sql += " AND owner_id = ?"
            args.append(owner_id)
        if status:
            sql += " AND status = ?"
            args.append(status)
        sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
            runs = [self._run_to_dict(r) for r in rows]
        # Owner isolation for listing: a non-privileged caller only ever sees
        # its own runs; an explicit filter for another owner returns nothing.
        if not self._is_privileged(actor):
            runs = [r for r in runs if r["owner_id"] == actor]
        elif owner_id is not None:
            runs = [r for r in runs if r["owner_id"] == owner_id]
        return [self._run_summary(r) for r in runs]

    # -- run steps -----------------------------------------------------------

    def _step_rows(self, run: dict) -> list[sqlite3.Row]:
        return self._conn.execute(
            "SELECT seq, kind, spec, result FROM plan_run_steps"
            " WHERE run_id = ? AND run_epoch = ? ORDER BY seq",
            (run["id"], run["run_epoch"]),
        ).fetchall()

    def run_steps(self, run: dict) -> list[dict]:
        return [
            public_step_result(json.loads(r["result"])) for r in self._step_rows(run)
        ]

    def run_step(self, run_id: str, seq: int, *, actor=None) -> dict:
        with self._lock:
            run = self._load_run(run_id)
            self._require_owner(run, actor)
            row = self._conn.execute(
                "SELECT result FROM plan_run_steps"
                " WHERE run_id = ? AND run_epoch = ? AND seq = ?",
                (run_id, run["run_epoch"], seq),
            ).fetchone()
        if row is None:
            raise RunNotFound(
                f"step {seq} has not been recorded in run {run_id!r}"
            )
        return public_step_result(json.loads(row["result"]))

    # -- advance -------------------------------------------------------------

    def advance(
        self,
        run_id: str,
        body: RunAdvanceIn,
        *,
        actor: Optional[str] = None,
        idem_key: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> tuple[int, dict]:
        with self._lock:
            if idem_key:
                replay = self._idem_run_lookup(run_id, idem_key, fingerprint)
                if replay is not None:
                    return replay
            run = self._load_run(run_id)
            self._require_owner(run, actor)
            status = run["status"]
            version = run["version"]
            epoch = run["run_epoch"]
            specs = run["spec"]["steps"]
            total = len(specs)
            branch_point = run["branch_point_seq"]

            if status not in (STATUS_READY, STATUS_RUNNING):
                raise self._refuse(
                    "run_step_rejected",
                    CODE_STATUS_CONFLICT,
                    f"run is {status!r}; only ready/running runs can advance"
                    + (" (resume it first)" if status == STATUS_PAUSED else ""),
                    plan_id=run["plan_id"],
                    run_id=run_id,
                    version=version,
                    actor=actor,
                    exc_class=PlanConflict,
                )
            if body.expected_version is not None and body.expected_version != version:
                raise self._refuse(
                    "run_step_rejected",
                    CODE_VERSION_CONFLICT,
                    f"expected_version {body.expected_version} does not match run "
                    f"version {version}",
                    plan_id=run["plan_id"],
                    run_id=run_id,
                    version=version,
                    actor=actor,
                )

            seq = body.seq if body.seq is not None else run["current_seq"] + 1
            if seq != run["current_seq"] + 1:
                raise self._refuse(
                    "run_step_rejected",
                    CODE_STEP_GAP,
                    f"step sequence gap: next step is {run['current_seq'] + 1},"
                    f" got {seq}",
                    plan_id=run["plan_id"],
                    run_id=run_id,
                    version=version,
                    actor=actor,
                    extra={"seq": seq},
                )
            if seq > total:
                raise self._refuse(
                    "run_step_rejected",
                    CODE_STEP_GAP,
                    f"step {seq} is beyond the frozen {total}-step sequence",
                    plan_id=run["plan_id"],
                    run_id=run_id,
                    version=version,
                    actor=actor,
                    extra={"seq": seq},
                )
            if seq <= branch_point:
                # Inherited steps are read-only history, never re-executed.
                raise self._refuse(
                    "run_step_rejected",
                    CODE_STATUS_CONFLICT,
                    f"step {seq} is inherited read-only from the parent run; "
                    f"the first branch step is {branch_point + 1}",
                    plan_id=run["plan_id"],
                    run_id=run_id,
                    version=version,
                    actor=actor,
                    extra={"seq": seq, "branch_point_seq": branch_point},
                )

            step_spec = specs[seq - 1]
            plan = self._load_plan(run["plan_id"])
            frozen = plan["frozen"]
            manifest = set(frozen["target_manifest"])
            for tid in step_spec.get("health_changes") or {}:
                if tid not in manifest:
                    raise self._refuse(
                        "run_step_rejected",
                        CODE_TARGET_NOT_FROZEN,
                        f"target {tid!r} is not in the frozen manifest",
                        plan_id=run["plan_id"],
                        run_id=run_id,
                        version=version,
                        actor=actor,
                        extra={"seq": seq},
                    )

            if step_spec.get("at") is not None:
                sim_now = step_spec["at"]
            elif step_spec.get("advance_seconds") is not None:
                base = (
                    run["last_sim_time"]
                    if run["last_sim_time"] is not None
                    else run["base_sim_time"]
                )
                sim_now = base + step_spec["advance_seconds"]
            else:
                sim_now = (
                    run["last_sim_time"]
                    if run["last_sim_time"] is not None
                    else run["base_sim_time"]
                )

            started_at = self._clock()
            keys_before = cache_keys(run["cache_state"])
            answer, cache_rows, health_after = replay_step(
                frozen, run["health"], run["cache_state"], step_spec, sim_now
            )
            recorded_at = self._clock()
            result = compose_step_result(
                seq=seq,
                step_spec=step_spec,
                answer=answer,
                order=target_order(answer),
                cache_rows=cache_rows,
                health_after=health_after,
                sim_now=sim_now,
                status_before=status,
                version_before=version,
                health_before=dict(run["health"]),
                cache_keys_before=keys_before,
                started_at=started_at,
                recorded_at=recorded_at,
            )

            new_status = STATUS_COMPLETED if seq == total else STATUS_RUNNING
            new_version = version + 1
            self._conn.execute(
                "INSERT INTO plan_run_steps (run_id, run_epoch, seq, kind, spec,"
                " result, started_at, recorded_at, actor)"
                " VALUES (?, ?, ?, 'recorded', ?, ?, ?, ?, ?)",
                (
                    run_id,
                    epoch,
                    seq,
                    json.dumps(step_spec, sort_keys=True),
                    json.dumps(result, sort_keys=True, default=_json_default),
                    started_at,
                    recorded_at,
                    actor,
                ),
            )
            self._conn.execute(
                "UPDATE plan_runs SET status = ?, health = ?, cache_state = ?,"
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
                    self._clock(),
                    self._clock(),
                    run_id,
                    version,
                ),
            )
            self._audit(
                "run_step",
                {
                    "seq": seq,
                    "chosen": answer.get("chosen"),
                    "cache_hit": result["cache_hit"],
                    "matched_expected": result["matched_expected"],
                    "diff_reasons": result["diff_reasons"],
                    "new_status": new_status,
                },
                plan_id=run["plan_id"],
                run_id=run_id,
                version=new_version,
                actor=actor,
            )
            if new_status == STATUS_COMPLETED:
                self._audit(
                    "run_completed",
                    {"seq": seq, "steps": total},
                    plan_id=run["plan_id"],
                    run_id=run_id,
                    version=new_version,
                    actor=actor,
                )
            self._conn.commit()

            payload = {
                "run_id": run_id,
                "plan_id": run["plan_id"],
                "step": public_step_result(result),
                "status": new_status,
                "version": new_version,
                "current_seq": seq,
                "matched_expected": result["matched_expected"],
            }
            if idem_key:
                self._idem_run_store(
                    run_id, epoch, idem_key, "advance", fingerprint, 200, payload
                )
                self._conn.commit()
            return 200, payload

    # -- run lifecycle -------------------------------------------------------

    def _run_transition(
        self,
        run_id: str,
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
        clear_fields: tuple[str, ...] = (),
        coalesce_time: bool = False,
    ) -> tuple[int, dict]:
        with self._lock:
            if idem_key:
                replay = self._idem_run_lookup(run_id, idem_key, fingerprint)
                if replay is not None:
                    return replay
            run = self._load_run(run_id)
            self._require_owner(run, actor)
            if expected_version is not None and expected_version != run["version"]:
                raise self._refuse(
                    f"run_{action}_rejected",
                    CODE_VERSION_CONFLICT,
                    f"expected_version {expected_version} does not match run "
                    f"version {run['version']}",
                    plan_id=run["plan_id"],
                    run_id=run_id,
                    version=run["version"],
                    actor=actor,
                )
            if run["status"] not in allowed:
                raise self._refuse(
                    f"run_{action}_rejected",
                    CODE_STATUS_CONFLICT,
                    f"cannot {action} a run in status {run['status']!r}",
                    plan_id=run["plan_id"],
                    run_id=run_id,
                    version=run["version"],
                    actor=actor,
                    extra={"allowed": list(allowed)},
                )
            new_version = run["version"] + 1
            now = self._clock()
            sets = ["status = ?", "version = ?", "updated_at = ?"]
            args: list = [new_status, new_version, now]
            if time_field:
                if coalesce_time:
                    sets.append(f"{time_field} = COALESCE({time_field}, ?)")
                else:
                    sets.append(f"{time_field} = ?")
                args.append(now)
            for field_name in clear_fields:
                sets.append(f"{field_name} = NULL")
            args.extend([run_id, run["version"]])
            cur = self._conn.execute(
                f"UPDATE plan_runs SET {', '.join(sets)} WHERE id = ? AND version = ?",
                args,
            )
            if cur.rowcount == 0:
                raise self._refuse(
                    f"run_{action}_rejected",
                    CODE_VERSION_CONFLICT,
                    f"run {run_id!r} changed concurrently",
                    plan_id=run["plan_id"],
                    run_id=run_id,
                    version=run["version"],
                    actor=actor,
                )
            self._audit(
                audit_action,
                {"from": run["status"], "to": new_status, "reason": reason},
                plan_id=run["plan_id"],
                run_id=run_id,
                version=new_version,
                actor=actor,
            )
            self._conn.commit()
            payload = {
                "run_id": run_id,
                "plan_id": run["plan_id"],
                "status": new_status,
                "version": new_version,
                "current_seq": run["current_seq"],
            }
            if idem_key:
                self._idem_run_store(
                    run_id,
                    run["run_epoch"],
                    idem_key,
                    action,
                    fingerprint,
                    200,
                    payload,
                )
                self._conn.commit()
            return 200, payload

    def pause_run(self, run_id, *, actor=None, expected_version=None, reason=None,
                  idem_key=None, fingerprint=None):
        return self._run_transition(
            run_id, "pause", (STATUS_RUNNING,), STATUS_PAUSED,
            actor=actor, expected_version=expected_version, reason=reason,
            idem_key=idem_key, fingerprint=fingerprint,
            audit_action="run_paused", time_field="paused_at",
        )

    def resume_run(self, run_id, *, actor=None, expected_version=None, reason=None,
                   idem_key=None, fingerprint=None):
        return self._run_transition(
            run_id, "resume", (STATUS_READY, STATUS_PAUSED), STATUS_RUNNING,
            actor=actor, expected_version=expected_version, reason=reason,
            idem_key=idem_key, fingerprint=fingerprint,
            audit_action="run_resumed", time_field="started_at",
            clear_fields=("paused_at",), coalesce_time=True,
        )

    def reset_run(
        self,
        run_id: str,
        *,
        actor=None,
        expected_version=None,
        reason=None,
        idem_key=None,
        fingerprint=None,
    ) -> tuple[int, dict]:
        with self._lock:
            if idem_key:
                replay = self._idem_run_lookup(run_id, idem_key, fingerprint)
                if replay is not None:
                    return replay
            run = self._load_run(run_id)
            self._require_owner(run, actor)
            if expected_version is not None and expected_version != run["version"]:
                raise self._refuse(
                    "run_reset_rejected",
                    CODE_VERSION_CONFLICT,
                    f"expected_version {expected_version} does not match run "
                    f"version {run['version']}",
                    plan_id=run["plan_id"],
                    run_id=run_id,
                    version=run["version"],
                    actor=actor,
                )
            plan = self._load_plan(run["plan_id"])
            new_epoch = run["run_epoch"] + 1
            new_version = run["version"] + 1
            now = self._clock()

            if run["branch_point_seq"]:
                # Branch reset: rewind to the inherited branch-point state and
                # delete this epoch's steps; the read-only inherited prefix is
                # then copied into the new epoch so it stays visible.
                bp = run["branch_point_seq"]
                bp_row = self._conn.execute(
                    "SELECT result FROM plan_run_steps"
                    " WHERE run_id = ? AND run_epoch = ? AND seq = ? AND kind = 'inherited'",
                    (run_id, run["run_epoch"], bp),
                ).fetchone()
                if bp_row is None:  # defensive: branch rows always exist
                    raise PlanConflict(
                        f"branch point step {bp} is missing for run {run_id!r}",
                        code=CODE_BRANCH_POINT_INVALID,
                    )
                bp_result = json.loads(bp_row["result"])
                health = bp_result["health_after"]
                cache_rows = bp_result.get("cache_rows_full") or []
                last_sim = bp_result["sim_time"]
                inherited_rows = self._conn.execute(
                    "SELECT seq, spec, result, started_at, recorded_at, actor FROM"
                    " plan_run_steps WHERE run_id = ? AND run_epoch = ?"
                    " AND kind = 'inherited' ORDER BY seq",
                    (run_id, run["run_epoch"]),
                ).fetchall()
                self._conn.execute(
                    "DELETE FROM plan_run_steps WHERE run_id = ? AND run_epoch = ?",
                    (run_id, run["run_epoch"]),
                )
            else:
                health = plan["initial_health"]
                cache_rows = []
                last_sim = None
                inherited_rows = []
                self._conn.execute(
                    "DELETE FROM plan_run_steps WHERE run_id = ? AND run_epoch = ?",
                    (run_id, run["run_epoch"]),
                )

            self._conn.execute(
                "UPDATE plan_runs SET status = ?, health = ?, cache_state = ?,"
                " current_seq = ?, last_sim_time = ?, run_epoch = ?, version = ?,"
                " paused_at = NULL, completed_at = NULL, started_at = ?,"
                " updated_at = ? WHERE id = ? AND version = ?",
                (
                    STATUS_READY,
                    json.dumps(health, sort_keys=True),
                    json.dumps(cache_rows, sort_keys=True, default=_json_default),
                    run["branch_point_seq"],
                    last_sim,
                    new_epoch,
                    new_version,
                    # A branch reset keeps the inherited prefix, so it stays
                    # 'running' semantically; leave started_at as recorded.
                    None if not run["branch_point_seq"] else run["started_at"],
                    now,
                    run_id,
                    run["version"],
                ),
            )
            # Re-create the immutable inherited prefix in the new epoch.
            for r in inherited_rows:
                self._conn.execute(
                    "INSERT INTO plan_run_steps (run_id, run_epoch, seq, kind,"
                    " spec, result, started_at, recorded_at, actor)"
                    " VALUES (?, ?, ?, 'inherited', ?, ?, ?, ?, ?)",
                    (
                        run_id,
                        new_epoch,
                        r["seq"],
                        r["spec"],
                        r["result"],
                        r["started_at"],
                        r["recorded_at"],
                        r["actor"],
                    ),
                )
            self._conn.execute(
                "DELETE FROM plan_run_reports WHERE run_id = ?", (run_id,)
            )
            self._audit(
                "run_reset",
                {
                    "old_epoch": run["run_epoch"],
                    "new_epoch": new_epoch,
                    "branch_point_seq": run["branch_point_seq"],
                    "reason": reason,
                },
                plan_id=run["plan_id"],
                run_id=run_id,
                version=new_version,
                actor=actor,
            )
            self._conn.commit()
            payload = {
                "run_id": run_id,
                "plan_id": run["plan_id"],
                "status": STATUS_READY,
                "version": new_version,
                "run_epoch": new_epoch,
                "current_seq": run["branch_point_seq"],
            }
            if idem_key:
                self._idem_run_store(
                    run_id, new_epoch, idem_key, "reset", fingerprint, 200, payload
                )
                self._conn.commit()
            return 200, payload

    # -- branching -----------------------------------------------------------

    def create_branch(
        self,
        parent_run_id: str,
        req: BranchCreateIn,
        *,
        actor: Optional[str] = None,
        idem_key: Optional[str] = None,
        fingerprint: Optional[str] = None,
    ) -> tuple[int, dict]:
        with self._lock:
            if idem_key:
                replay = self._idem_lookup(idem_key, actor, fingerprint)
                if replay is not None:
                    return replay
            parent = self._load_run(parent_run_id)
            self._require_owner(parent, actor)
            plan = self._load_plan(parent["plan_id"])
            bp = req.branch_point_seq

            if req.expected_version is not None and req.expected_version != parent["version"]:
                raise self._refuse(
                    "branch_create_rejected",
                    CODE_VERSION_CONFLICT,
                    f"expected_version {req.expected_version} does not match parent "
                    f"run version {parent['version']}",
                    plan_id=parent["plan_id"],
                    run_id=parent_run_id,
                    version=parent["version"],
                    actor=actor,
                )
            if bp < 1 or bp > parent["current_seq"]:
                raise self._refuse(
                    "branch_create_rejected",
                    CODE_BRANCH_POINT_INVALID,
                    f"cannot branch from step {bp}: run {parent_run_id!r} has "
                    f"recorded {parent['current_seq']} step(s)",
                    plan_id=parent["plan_id"],
                    run_id=parent_run_id,
                    version=parent["version"],
                    actor=actor,
                    extra={"branch_point_seq": bp, "current_seq": parent["current_seq"]},
                )
            parent_specs = parent["spec"]["steps"]
            tail_len = len(parent_specs) - bp
            if tail_len < 1:
                raise self._refuse(
                    "branch_create_rejected",
                    CODE_BRANCH_TAIL_LENGTH,
                    f"step {bp} is the final step; no later steps exist to replace",
                    plan_id=parent["plan_id"],
                    run_id=parent_run_id,
                    version=parent["version"],
                    actor=actor,
                )
            if len(req.steps) != tail_len:
                raise self._refuse(
                    "branch_create_rejected",
                    CODE_BRANCH_TAIL_LENGTH,
                    f"branch must replace exactly {tail_len} step(s) after "
                    f"step {bp}, got {len(req.steps)}",
                    plan_id=parent["plan_id"],
                    run_id=parent_run_id,
                    version=parent["version"],
                    actor=actor,
                    extra={"expected": tail_len, "got": len(req.steps)},
                )

            manifest = set(plan["frozen"]["target_manifest"])
            # Validate the replacement tail. Callers number replacements from
            # 1 ("the first step after the branch point"); normalize each to
            # its global position in the run's sequence (bp + position).
            tail_steps = self._validate_steps(req.steps, manifest)
            for step in tail_steps:
                if step["seq"] < 1 or step["seq"] > tail_len:
                    raise self._refuse(
                        "branch_create_rejected",
                        CODE_BRANCH_TAIL_LENGTH,
                        f"replacement step position {step['seq']} is outside the "
                        f"{tail_len} step(s) following branch point {bp}",
                        plan_id=parent["plan_id"],
                        run_id=parent_run_id,
                        version=parent["version"],
                        actor=actor,
                    )
            if sorted(s["seq"] for s in tail_steps) != list(range(1, tail_len + 1)):
                raise self._refuse(
                    "branch_create_rejected",
                    CODE_STEP_GAP,
                    f"replacement steps must be numbered 1..{tail_len} without gaps",
                    plan_id=parent["plan_id"],
                    run_id=parent_run_id,
                    version=parent["version"],
                    actor=actor,
                )
            for step in tail_steps:
                step["seq"] = bp + step["seq"]

            # The branch spec: frozen parent specs up to bp, replacements after.
            branch_specs = [dict(s) for s in parent_specs[:bp]] + tail_steps
            spec = {"steps": branch_specs, "step_count": len(branch_specs)}

            # Snapshot inherited recorded results (read-only) including the
            # full private cache state at the branch point.
            parent_rows = {
                r["seq"]: r
                for r in self._conn.execute(
                    "SELECT seq, spec, result FROM plan_run_steps"
                    " WHERE run_id = ? AND run_epoch = ? AND seq <= ?",
                    (parent_run_id, parent["run_epoch"], bp),
                ).fetchall()
            }
            if len(parent_rows) != bp:
                raise self._refuse(
                    "branch_create_rejected",
                    CODE_BRANCH_POINT_INVALID,
                    f"run {parent_run_id!r} is missing recorded steps before {bp}",
                    plan_id=parent["plan_id"],
                    run_id=parent_run_id,
                    version=parent["version"],
                    actor=actor,
                )
            bp_result = json.loads(parent_rows[bp]["result"])
            branch_health = dict(bp_result["health_after"])
            branch_cache = list(bp_result.get("cache_rows_full") or [])
            branch_last_sim = bp_result["sim_time"]

            owner = _normalize_owner(req.owner_id or actor)
            branch_id = (req.run_id or f"br_{secrets.token_urlsafe(12)}").strip()
            if not branch_id:
                raise PlanValidation("run_id must be non-empty")
            now = self._clock()
            new_parent_version = parent["version"] + 1
            # Branch creation serializes against other parent mutations via
            # the parent run's optimistic token.
            cur = self._conn.execute(
                "UPDATE plan_runs SET version = ?, updated_at = ?"
                " WHERE id = ? AND version = ?",
                (new_parent_version, now, parent_run_id, parent["version"]),
            )
            if cur.rowcount == 0:
                raise self._refuse(
                    "branch_create_rejected",
                    CODE_VERSION_CONFLICT,
                    f"parent run {parent_run_id!r} changed concurrently",
                    plan_id=parent["plan_id"],
                    run_id=parent_run_id,
                    version=parent["version"],
                    actor=actor,
                )
            try:
                self._conn.execute(
                    "INSERT INTO plan_runs (id, plan_id, status, owner_id, note,"
                    " base_sim_time, branch_point_seq, parent_run_id,"
                    " parent_run_epoch, spec, health, cache_state, current_seq,"
                    " last_sim_time, run_epoch, version, created_by, created_at,"
                    " started_at, paused_at, completed_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?,"
                    " ?, ?, NULL, NULL, ?)",
                    (
                        branch_id,
                        parent["plan_id"],
                        STATUS_RUNNING,
                        owner,
                        req.note,
                        parent["base_sim_time"],
                        bp,
                        parent_run_id,
                        parent["run_epoch"],
                        json.dumps(spec, sort_keys=True),
                        json.dumps(branch_health, sort_keys=True),
                        json.dumps(branch_cache, sort_keys=True, default=_json_default),
                        bp,
                        branch_last_sim,
                        actor,
                        now,
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise PlanConflict(
                    f"run id {branch_id!r} already exists", code=CODE_RUN_ID_CONFLICT
                ) from exc

            # Copy inherited steps/results; they are marked immutable.
            for seq in range(1, bp + 1):
                src_spec = json.loads(parent_rows[seq]["spec"])
                src_result = json.loads(parent_rows[seq]["result"])
                inherited_result = dict(src_result)
                inherited_result["inherited"] = True
                inherited_result["inherited_from"] = {
                    "run_id": parent_run_id,
                    "run_epoch": parent["run_epoch"],
                    "seq": seq,
                }
                self._conn.execute(
                    "INSERT INTO plan_run_steps (run_id, run_epoch, seq, kind,"
                    " spec, result, started_at, recorded_at, actor)"
                    " VALUES (?, 1, ?, 'inherited', ?, ?, ?, ?, ?)",
                    (
                        branch_id,
                        seq,
                        json.dumps(src_spec, sort_keys=True),
                        json.dumps(inherited_result, sort_keys=True,
                                   default=_json_default),
                        inherited_result["started_at"],
                        inherited_result["recorded_at"],
                        parent_run_id,
                    ),
                )
            self._audit(
                "branch_created",
                {
                    "branch_run_id": branch_id,
                    "branch_point_seq": bp,
                    "parent_run_epoch": parent["run_epoch"],
                    "owner_id": owner,
                    "tail_steps": tail_len,
                },
                plan_id=parent["plan_id"],
                run_id=branch_id,
                version=1,
                actor=actor,
            )
            self._audit(
                "run_branched",
                {"branch_run_id": branch_id, "branch_point_seq": bp},
                plan_id=parent["plan_id"],
                run_id=parent_run_id,
                version=new_parent_version,
                actor=actor,
            )
            self._conn.commit()
            payload = {
                "run": self._run_public(
                    self._load_run(branch_id), include_steps=True
                )
            }
            if idem_key:
                self._idem_store(
                    idem_key, actor, "branch_create", fingerprint, 201, payload
                )
                self._conn.commit()
            return 201, payload

    # -- per-run report ------------------------------------------------------

    def run_report(self, run_id: str, *, actor=None) -> dict:
        with self._lock:
            run = self._load_run(run_id)
            self._require_owner(run, actor)
            row = self._conn.execute(
                "SELECT content, checksum, created_at FROM plan_run_reports"
                " WHERE run_id = ? AND run_epoch = ?",
                (run_id, run["run_epoch"]),
            ).fetchone()
            if row is not None:
                return {
                    "report": json.loads(row["content"]),
                    "checksum": row["checksum"],
                    "generated_at": row["created_at"],
                    "idempotent_replay": True,
                }
            plan = self._load_plan(run["plan_id"])
            steps = self.run_steps(run)
            content = self._build_run_report(plan, run, steps)
            checksum = _canonical_checksum(content)
            generated_at = self._clock()
            self._conn.execute(
                "INSERT INTO plan_run_reports (run_id, run_epoch, created_at,"
                " content, checksum) VALUES (?, ?, ?, ?, ?)",
                (
                    run_id,
                    run["run_epoch"],
                    generated_at,
                    json.dumps(content, sort_keys=True),
                    checksum,
                ),
            )
            self._audit(
                "run_report_generated",
                {
                    "checksum": checksum,
                    "steps_included": len(steps),
                    "run_epoch": run["run_epoch"],
                },
                plan_id=run["plan_id"],
                run_id=run_id,
                version=run["version"],
                actor=actor,
            )
            self._conn.commit()
            return {
                "report": content,
                "checksum": checksum,
                "generated_at": generated_at,
                "idempotent_replay": False,
            }

    def _build_run_report(self, plan: dict, run: dict, steps: list[dict]) -> dict:
        frozen = plan["frozen"]
        first_diff = None
        step_reports = []
        matched = 0
        for s in steps:
            diffs = s.get("diffs") or []
            if first_diff is None and diffs and not s.get("inherited"):
                first_diff = {
                    "seq": s["seq"],
                    "diff_reasons": s.get("diff_reasons")
                    or [d["field"] for d in diffs],
                    "diffs": diffs,
                }
            if s.get("matched_expected"):
                matched += 1
            step_reports.append(
                {
                    "seq": s["seq"],
                    "inherited": bool(s.get("inherited")),
                    "inherited_from": s.get("inherited_from"),
                    "request": s.get("request"),
                    "sim_time": s.get("sim_time"),
                    "started_at": s.get("started_at"),
                    "health_changes": (s.get("input") or {}).get(
                        "health_changes", {}
                    ),
                    "health_after": s.get("health_after"),
                    "expected": s.get("expected") or None,
                    "actual": {
                        "status": (s.get("answer") or {}).get("status"),
                        "chosen": (s.get("answer") or {}).get("chosen"),
                        "degraded": (s.get("answer") or {}).get("degraded"),
                        "order": s.get("order"),
                    },
                    "matched_expected": s.get("matched_expected"),
                    "cache_hit": s.get("cache_hit"),
                    "diffs": [] if s.get("inherited") else diffs,
                }
            )
        return {
            "run_id": run["id"],
            "plan_id": run["plan_id"],
            "generated_for_run_epoch": run["run_epoch"],
            "status": run["status"],
            "owner_id": run["owner_id"],
            "note": run["note"],
            "parent_run_id": run["parent_run_id"],
            "parent_run_epoch": run["parent_run_epoch"],
            "branch_point_seq": run["branch_point_seq"],
            "config_version": plan["config_version"],
            "plan_name": plan["name"],
            "created_at": run["created_at"],
            "created_by": run["created_by"],
            "description": plan["description"],
            "frozen_snapshot": {
                "config_version": frozen["config_version"],
                "target_manifest": frozen["target_manifest"],
                "rule_summary": frozen["rule_summary"],
                "release_group_summary": frozen["release_group_summary"],
                "rate_limit_tier_summary": frozen["rate_limit_tier_summary"],
            },
            "steps_planned": run["spec"]["step_count"],
            "steps_recorded": len(steps),
            "steps_matched": matched,
            "steps_diverged": len(steps) - matched,
            "first_diff": first_diff,
            "steps": step_reports,
        }

    # -- comparison reports --------------------------------------------------

    @staticmethod
    def _step_view(s: dict) -> dict:
        answer = s.get("answer") or {}
        return {
            "seq": s["seq"],
            "request": s.get("request"),
            "sim_time": s.get("sim_time"),
            "health_before": (s.get("input") or {}).get("health_before"),
            "health_changes": (s.get("input") or {}).get("health_changes"),
            "health_after": s.get("health_after"),
            "order": s.get("order"),
            "chosen": answer.get("chosen"),
            "status": answer.get("status"),
            "degraded": answer.get("degraded"),
            "cache_hit": s.get("cache_hit"),
            "expected": s.get("expected"),
        }

    def compare(self, run_a_id: str, run_b_id: str, *, actor=None) -> dict:
        """Freeze a read-only comparison report for a pair of runs."""
        with self._lock:
            run_a = self._load_run(run_a_id)
            self._require_owner(run_a, actor)
            run_b = self._load_run(run_b_id)
            self._require_owner(run_b, actor)
            if run_a["plan_id"] != run_b["plan_id"]:
                raise self._refuse(
                    "compare_rejected",
                    CODE_COMPARE_PLAN_MISMATCH,
                    f"runs {run_a_id!r} and {run_b_id!r} belong to different plans",
                    plan_id=run_a["plan_id"],
                    run_id=run_a_id,
                    actor=actor,
                    extra={
                        "plan_id": run_a["plan_id"],
                        "other_plan_id": run_b["plan_id"],
                    },
                )

            # Unordered pair identity: the first comparison of a pair pins
            # both run versions; every repeat replays that one stored report
            # regardless of request direction or later run progress.
            pair = sorted((run_a_id, run_b_id))
            va, vb = run_a["version"], run_b["version"]
            row = self._conn.execute(
                "SELECT content, checksum, created_at FROM plan_run_comparisons"
                " WHERE run_id_low = ? AND run_id_high = ?",
                (pair[0], pair[1]),
            ).fetchone()
            if row is not None:
                return {
                    "report": json.loads(row["content"]),
                    "checksum": row["checksum"],
                    "generated_at": row["created_at"],
                    "idempotent_replay": True,
                }

            steps_a = {s["seq"]: self._step_view(s) for s in self.run_steps(run_a)}
            steps_b = {s["seq"]: self._step_view(s) for s in self.run_steps(run_b)}
            divergence = self._first_divergence(steps_a, steps_b)
            plan = self._load_plan(run_a["plan_id"])
            now = self._clock()
            content = {
                "kind": "run_comparison",
                "plan_id": run_a["plan_id"],
                "plan_name": plan["name"],
                "config_version": plan["config_version"],
                "runs": [
                    {
                        "run_id": run_a_id,
                        "version": va,
                        "owner_id": run_a["owner_id"],
                        "status": run_a["status"],
                        "parent_run_id": run_a["parent_run_id"],
                        "branch_point_seq": run_a["branch_point_seq"],
                        "recorded_steps": run_a["current_seq"],
                    },
                    {
                        "run_id": run_b_id,
                        "version": vb,
                        "owner_id": run_b["owner_id"],
                        "status": run_b["status"],
                        "parent_run_id": run_b["parent_run_id"],
                        "branch_point_seq": run_b["branch_point_seq"],
                        "recorded_steps": run_b["current_seq"],
                    },
                ],
                "steps_compared": min(run_a["current_seq"], run_b["current_seq"]),
                "identical": divergence is None
                and run_a["current_seq"] == run_b["current_seq"],
                "first_divergence": divergence,
                "generated_at": now,
            }
            checksum = _canonical_checksum(content)
            # Pin the versions this report was generated at.
            low_version = va if pair[0] == run_a_id else vb
            high_version = vb if pair[1] == run_b_id else va
            try:
                self._conn.execute(
                    "INSERT INTO plan_run_comparisons (run_id_low, run_id_high,"
                    " run_low_version, run_high_version, created_at, content,"
                    " checksum) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        pair[0],
                        pair[1],
                        low_version,
                        high_version,
                        now,
                        json.dumps(content, sort_keys=True),
                        checksum,
                    ),
                )
            except sqlite3.IntegrityError:
                # Concurrent first generation: replay the winner's row.
                self._conn.rollback()
                row = self._conn.execute(
                    "SELECT content, checksum, created_at FROM plan_run_comparisons"
                    " WHERE run_id_low = ? AND run_id_high = ?",
                    (pair[0], pair[1]),
                ).fetchone()
                return {
                    "report": json.loads(row["content"]),
                    "checksum": row["checksum"],
                    "generated_at": row["created_at"],
                    "idempotent_replay": True,
                }
            self._audit(
                "run_comparison_generated",
                {
                    "run_id_low": pair[0],
                    "run_id_high": pair[1],
                    "run_low_version": low_version,
                    "run_high_version": high_version,
                    "checksum": checksum,
                    "identical": content["identical"],
                },
                plan_id=run_a["plan_id"],
                run_id=run_a_id,
                version=va,
                actor=actor,
            )
            self._conn.commit()
            return {
                "report": content,
                "checksum": checksum,
                "generated_at": now,
                "idempotent_replay": False,
            }

    def _first_divergence(
        self, a: dict[int, dict], b: dict[int, dict]
    ) -> Optional[dict]:
        max_seq = max(len(a), len(b), 0)
        for seq in range(1, max_seq + 1):
            sa, sb = a.get(seq), b.get(seq)
            if sa is None or sb is None:
                return {
                    "seq": seq,
                    "dimension": "step_progress",
                    "detail": "one run has not recorded this step yet",
                    "left": {"recorded": sa is not None},
                    "right": {"recorded": sb is not None},
                }
            checks = (
                ("step_input", ("request", "sim_time")),
                ("health_set", ("health_before", "health_changes", "health_after")),
                ("resolution_order", ("order",)),
                ("cache_hit", ("cache_hit",)),
                ("expected_result", ("expected",)),
            )
            for dimension, fields in checks:
                va = {f: sa.get(f) for f in fields}
                vb = {f: sb.get(f) for f in fields}
                if va != vb:
                    return {
                        "seq": seq,
                        "dimension": dimension,
                        "detail": f"first {dimension} difference at step {seq}",
                        "left": va,
                        "right": vb,
                    }
        return None

    # -- audit ----------------------------------------------------------------

    def plan_audit(
        self,
        *,
        plan_id: Optional[str] = None,
        run_id: Optional[str] = None,
        action: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 500,
        actor: Optional[str] = None,
    ) -> list[dict]:
        sql = "SELECT * FROM plan_audit WHERE 1=1"
        args: list = []
        if plan_id is not None:
            sql += " AND plan_id = ?"
            args.append(plan_id)
        if run_id is not None:
            sql += " AND run_id = ?"
            args.append(run_id)
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
            out = []
            for r in rows:
                rec = {
                    "id": r["id"],
                    "plan_id": r["plan_id"],
                    "run_id": r["run_id"],
                    "ts": r["ts"],
                    "actor": r["actor"],
                    "action": r["action"],
                    "version": r["version"],
                    "details": json.loads(r["details"]),
                }
                out.append(rec)
        # Non-privileged callers may only read their own runs' audit trail.
        if not self._is_privileged(actor):
            out = [r for r in out if self._actor_can_see_audit(r, actor)]
        return out

    def _actor_can_see_audit(self, record: dict, actor: str) -> bool:
        # Records carry either a run_id (check ownership) or only a plan_id
        # (plan-level events stay visible to holders of drill:read; the API
        # layer already required that permission).
        run_id = record.get("run_id")
        if not run_id:
            return True
        row = self._conn.execute(
            "SELECT owner_id FROM plan_runs WHERE id = ?", (run_id,)
        ).fetchone()
        return row is not None and row["owner_id"] == actor

    # -- idempotency ----------------------------------------------------------

    def _idem_lookup(
        self, key: str, actor: Optional[str], fingerprint: Optional[str]
    ) -> Optional[tuple[int, dict]]:
        row = self._conn.execute(
            "SELECT identity_id, fingerprint, status_code, response FROM"
            " plan_idempotency WHERE idem_key = ?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        if row["identity_id"] != (actor or ""):
            # A key belongs to the identity that first used it.
            raise PlanConflict(
                "Idempotency-Key was already used by another identity",
                code=CODE_PLAN_IDEMPOTENCY_CONFLICT,
            )
        if fingerprint is not None and fingerprint != row["fingerprint"]:
            raise PlanConflict(
                "Idempotency-Key was already used with a different request payload",
                code=CODE_PLAN_IDEMPOTENCY_CONFLICT,
            )
        body = json.loads(row["response"])
        return row["status_code"], {**body, "idempotent_replay": True}

    def _idem_store(
        self,
        key: str,
        actor: Optional[str],
        action: str,
        fingerprint: Optional[str],
        status_code: int,
        body: dict,
    ) -> None:
        try:
            self._conn.execute(
                "INSERT INTO plan_idempotency (idem_key, identity_id, action,"
                " fingerprint, status_code, response, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    key,
                    actor or "",
                    action,
                    fingerprint or "",
                    status_code,
                    json.dumps(body, sort_keys=True, default=_json_default),
                    self._clock(),
                ),
            )
        except sqlite3.IntegrityError:
            self._conn.rollback()

    def _idem_run_lookup(
        self, run_id: str, key: str, fingerprint: Optional[str]
    ) -> Optional[tuple[int, dict]]:
        cur = self._conn.execute(
            "SELECT run_epoch FROM plan_runs WHERE id = ?", (run_id,)
        ).fetchone()
        if cur is None:
            return None
        row = self._conn.execute(
            "SELECT fingerprint, status_code, response FROM plan_run_idempotency"
            " WHERE run_id = ? AND run_epoch = ? AND idem_key = ?",
            (run_id, cur["run_epoch"], key),
        ).fetchone()
        if row is None:
            return None
        if fingerprint is not None and fingerprint != row["fingerprint"]:
            raise PlanConflict(
                "Idempotency-Key was already used with a different request payload",
                code=CODE_PLAN_IDEMPOTENCY_CONFLICT,
            )
        body = json.loads(row["response"])
        return row["status_code"], {**body, "idempotent_replay": True}

    def _idem_run_store(
        self,
        run_id: str,
        run_epoch: int,
        key: str,
        action: str,
        fingerprint: Optional[str],
        status_code: int,
        body: dict,
    ) -> None:
        try:
            self._conn.execute(
                "INSERT INTO plan_run_idempotency (run_id, run_epoch, idem_key,"
                " action, fingerprint, status_code, response, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    run_epoch,
                    key,
                    action,
                    fingerprint or "",
                    status_code,
                    json.dumps(body, sort_keys=True, default=_json_default),
                    self._clock(),
                ),
            )
        except sqlite3.IntegrityError:
            self._conn.rollback()


def _json_default(obj):
    if isinstance(obj, frozenset):
        return sorted(obj)
    if isinstance(obj, set):
        return sorted(obj)
    return str(obj)
