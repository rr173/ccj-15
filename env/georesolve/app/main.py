"""HTTP API and application wiring.

Data plane (unauthenticated, like a DNS resolver):
  GET /v1/resolve   - resolve a name for a region/tenant; optional
                      `labels=k=v,k2=v2` carries client labels used by
                      gray release groups and rate-limit matching;
                      rejected over-quota requests return HTTP 429
  GET /v1/explain   - show the rule version, targets, effective time and
                      the release-group decision for a name/region/tenant
  GET /healthz      - liveness

Control plane (authenticated; see app.authz for the delegation model):
  GET  /v1/config              - current config snapshot, filtered to the
                                 caller's config:read scope
  POST /v1/config              - apply a new config bundle (monotonic version);
                                 scoped callers submit only their own scope's
                                 items, which are merged over the live config;
                                 optional expected_version (optimistic
                                 concurrency) and preview_token
  POST /v1/config/preview      - dry-run a bundle through the full pipeline
  GET  /v1/config/versions     - saved version summaries, diffs filtered to
                                 the caller's versions:read scope
  GET  /v1/config/versions/{v} - one saved version; payload filtered likewise
  POST /v1/config/rollback     - restore a saved version as a brand-new,
                                 strictly higher version (global scope only)
  POST /v1/config/rollback/preview - dry-run a rollback (global scope only)
  GET  /v1/audit               - audit records, filtered to the caller's
                                 audit:read scope (plus records about itself)
  GET  /v1/health/targets              - effective target health view
                                         (source + versions; scope-filtered)
  GET  /v1/health/targets/{id}         - full per-target state machine state
  GET  /v1/health/policies             - list check policies
  PUT  /v1/health/targets/{id}/policy  - create/update a check policy
                                         (methods, interval/timeout,
                                         thresholds, maintenance windows,
                                         priority; expected_version)
  DELETE /v1/health/targets/{id}/policy - delete a policy (?expected_version=)
  GET  /v1/health/policy-revisions     - immutable policy revision stream
  GET  /v1/health/targets/{id}/history - append-only check/transition history
                                         (fixed seq:asc paging; filter by
                                         policy_version/kind/time window)
  POST /v1/health/targets/{id}/override[/revoke] - manual override (optional
                                         expiry) / release it
  POST /v1/health/targets/{id}/pause|/resume - suspend checking / resume
  POST /v1/health/targets/{id}/check   - run one check round immediately
  POST /v1/health/targets/{id}         - legacy override (permanent)
  GET  /v1/cache               - cache contents, filtered by cache:read
  POST /v1/cache/flush         - drop cached answers inside the caller's
                                 cache:flush scope (audited)

Admin delegation (requires admin:manage; callers can only delegate scopes
their own admin:manage grants cover, so tenant admins can never mint region
or global permissions):
  POST   /v1/admin/roles                 - create a role
  GET    /v1/admin/roles                 - list visible roles
  GET    /v1/admin/roles/{id}            - one role
  PUT    /v1/admin/roles/{id}            - update permissions (versioned)
  DELETE /v1/admin/roles/{id}            - delete an unassigned role
  POST   /v1/admin/identities            - create an identity (token shown once)
  GET    /v1/admin/identities            - list visible identities
  GET    /v1/admin/identities/{id}       - one identity
  PUT    /v1/admin/identities/{id}       - replace roles / rotate token
  POST   /v1/admin/identities/{id}/deactivate - revoke access immediately
  POST   /v1/admin/identities/{id}/reactivate - restore access

Emergency grants (temporary, approval-gated permission elevation; while
approved and unexpired the grant's permissions join the identity's own on
every control-plane request, and expiry/revocation take effect immediately):
  POST   /v1/admin/emergency-grants             - request a grant (reason,
                                                  permissions, duration)
  GET    /v1/admin/emergency-grants             - list visible grants
  GET    /v1/admin/emergency-grants/{id}        - one grant
  POST   /v1/admin/emergency-grants/{id}/approve - approve (admin:manage
                                                  covering the grant; never
                                                  one's own request)
  POST   /v1/admin/emergency-grants/{id}/reject  - reject a pending request
  POST   /v1/admin/emergency-grants/{id}/revoke  - revoke an active grant

All admin mutations accept an `Idempotency-Key` header: the first response
is persisted and replayed for duplicate submissions (no duplicate version
bumps or audit records); reusing the key with a different payload is a 409.
Every authorization decision, denial and identity/role change is audited.

Tenant budget groups and temporary overrides
--------------------------------------------
  POST   /v1/budget-groups?group_id=   - create a group with a default
                                         budget or a parent_id to inherit
  GET    /v1/budget-groups             - list groups (member_count)
  GET    /v1/budget-groups/{id}        - one group and its members
  PUT    /v1/budget-groups/{id}        - update policy/parent (versioned;
                                         cyclic inheritance -> 409)
  DELETE /v1/budget-groups/{id}        - delete an empty group
  POST   /v1/budget-groups/{id}/members?tenant=  - assign/migrate a member
                                                   (optimistically versioned)
  DELETE /v1/budget-groups/members/{tenant}      - detach a member
  GET    /v1/budget-groups/members/{tenant}/history - membership intervals
  GET    /v1/budgets/{tenant}/resolved - effective policy with source and
                                         version attribution (?at= history)
  POST   /v1/budgets/{tenant}/overrides - request a time-windowed override
  GET    /v1/budget-overrides           - list/filter override requests
  GET    /v1/budget-overrides/{id}      - one override
  POST   /v1/budget-overrides/{id}/approve | /reject | /revoke

The resolution chain is: approved active override > tenant budget > group
default (inherited through an acyclic parent chain). Group edits, member
migrations and override approval/revocation take effect for the very next
resolution; closed periods keep the frozen policy snapshot recorded for
them. Groups and migrations require global budget:write; override requests
and decisions require budget:write on the tenant, and a different
administrator than the requester must decide.

Fault drills (isolated resolution replay, global drill:read/drill:write):
  POST   /v1/drills                            - freeze a saved config version
                                                 (manifest/rule summary/request
                                                 sequence) into a new drill
  GET    /v1/drills                            - list drills
  GET    /v1/drills/{id}                       - drill detail
  POST   /v1/drills/{id}/advance               - replay the next step
  POST   /v1/drills/{id}/pause | /resume | /reset
  GET    /v1/drills/{id}/steps/{seq}           - one recorded step
  POST   /v1/drills/{id}/report                - frozen read-only report
  GET    /v1/drills-audit                      - drill-only audit trail

Each replay runs the production Resolver against a private frozen snapshot,
private health registry, private simulated-clock cache and a null audit
sink: the live health view, resolution cache, rate-limit buckets, metering
and the real audit log are never touched. Drill state, steps, per-(drill,
run-epoch) idempotency keys and one-shot reports are all SQLite-persisted.

Reusable drill plans, independent runs and branches (same permissions):
  POST   /v1/drill-plans                        - save a completed drill (or
                                                 a saved version + sequence)
                                                 as a named frozen plan
  GET    /v1/drill-plans                        - list plans
  GET    /v1/drill-plans/{id}                   - frozen plan detail
  POST   /v1/drill-plans/{id}/archive           - archive (no new runs)
  POST   /v1/drill-plans/{id}/runs              - start an independent run
                                                 (owner_id + note)
  GET    /v1/drill-plans/{id}/runs              - runs of one plan
  GET    /v1/drill-runs                         - list/filter runs
                                                 (?plan_id=&owner_id=&status=)
  GET    /v1/drill-runs/{id}                    - run detail (owner only)
  GET    /v1/drill-runs/{id}/steps/{seq}        - one recorded/inherited step
  POST   /v1/drill-runs/{id}/advance            - replay the next step
  POST   /v1/drill-runs/{id}/pause|/resume|/reset
  POST   /v1/drill-runs/{id}/report             - frozen per-run report
  POST   /v1/drill-runs/{id}/branches           - branch from a recorded step
  POST   /v1/drill-runs/{id}/compare            - frozen pair comparison
  GET    /v1/drill-plans-audit                  - plan/run audit trail

A plan freezes the config version, target manifest, normalized step inputs
and expected results and a shared simulated-clock anchor. Runs share no
mutable state (health, cache, step results, lifecycle); a branch inherits a
read-only prefix of another run's inputs/results and replaces the tail, and
the parent's later progress never touches the branch. Non-privileged
identities may read or operate only runs they own. Plan/run/branch creation,
archival and every lifecycle action accept Idempotency-Key plus
expected_version; a run pair has exactly one frozen comparison report,
pinned to the two run versions at first generation.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError, field_validator

from . import __version__
from .audit import AuditLog
from .authz import (
    GRANT_STATUSES,
    AuthnError,
    AuthzConflict,
    AuthzNotFound,
    AuthzStore,
    Caller,
    Forbidden,
    Permission,
    Scope,
    request_fingerprint,
)
from .cache import ResolutionCache
from .config_store import (
    ConfigManager,
    PreviewRejected,
    RollbackRejected,
    VersionConflict,
    VersionNotFound,
)
from .disputes import (
    DisputeApplyRequest,
    DisputeConflict,
    DisputeDecisionRequest,
    DisputeNotFound,
    DisputeRevokeRequest,
    DisputeSpec,
    DisputeStore,
    DisputeSubmitRequest,
    DISPUTE_STATUSES,
)
from .drills import (
    AdvanceIn,
    DrillConflict,
    DrillCreateIn,
    DrillNotFound,
    DrillStore,
    DrillValidation,
    TransitionIn,
)
from .health import HealthChecker, HealthRegistry
from .health_checks import (
    HealthCheckConflict,
    HealthCheckNotFound,
    HealthCheckStore,
    HealthCheckValidation,
    HealthScheduler,
    OverrideIn,
    OverrideRevokeIn,
    PauseIn,
    PolicyUpsertIn,
    ResumeIn,
)
from .metering import (
    BudgetExceeded,
    BudgetGroupSpec,
    BudgetSpec,
    MeteringConflict,
    MeteringNotFound,
    MeteringStore,
    MeteringValidationError,
    OverrideSpec,
    PERIOD_TYPES,
    PolicyDenied,
)
from .models import ConfigBundle
from .plans import (
    BranchCreateIn,
    CompareIn,
    PlanArchiveIn,
    PlanConflict,
    PlanCreateIn,
    PlanForbidden,
    PlanNotFound,
    PlanStore,
    PlanValidation,
    RunCreateIn,
    RunNotFound,
    RunTransitionIn,
    RunAdvanceIn,
)
from .rate_limit import RateLimitExceeded, RateLimiter
from .resolver import Resolver
from .storage import connect


class ConfigApplyRequest(ConfigBundle):
    expected_version: Optional[int] = Field(
        default=None,
        ge=0,
        description="optimistic concurrency: commit only when the live "
        "version equals this one",
    )
    preview_token: Optional[str] = Field(
        default=None,
        description="token returned by /v1/config/preview for this payload",
    )


class ConfigPreviewRequest(ConfigApplyRequest):
    version: Optional[int] = Field(  # type: ignore[assignment]
        default=None,
        ge=1,
        description="defaults to current version + 1",
    )


class RollbackRequest(BaseModel):
    version: int = Field(ge=1, description="saved version to restore")
    expected_version: Optional[int] = Field(default=None, ge=0)
    preview_token: Optional[str] = None
    new_version: Optional[int] = Field(default=None, ge=1)


class RoleCreateRequest(BaseModel):
    id: str
    description: str = ""
    permissions: list[Permission] = Field(min_length=1)


class RoleUpdateRequest(BaseModel):
    description: Optional[str] = None
    permissions: Optional[list[Permission]] = Field(default=None, min_length=1)
    expected_version: Optional[int] = Field(default=None, ge=1)


class IdentityCreateRequest(BaseModel):
    id: str
    roles: list[str] = Field(default_factory=list)
    token: Optional[str] = Field(
        default=None, description="defaults to a generated token"
    )


class IdentityUpdateRequest(BaseModel):
    roles: Optional[list[str]] = None
    rotate_token: bool = False
    expected_version: Optional[int] = Field(default=None, ge=1)


class HealthOverrideRequest(BaseModel):
    healthy: bool


class EmergencyGrantCreateRequest(BaseModel):
    identity_id: str = Field(description="identity the grant elevates")
    reason: str = Field(min_length=1, description="why the elevation is needed")
    permissions: list[Permission] = Field(min_length=1)
    duration_seconds: float = Field(
        gt=0,
        allow_inf_nan=False,
        description="validity window, started at approval time",
    )

    @field_validator("reason")
    @classmethod
    def _reason_non_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("reason must be a non-empty string")
        return v


class EmergencyGrantDecideRequest(BaseModel):
    comment: Optional[str] = None
    expected_version: Optional[int] = Field(default=None, ge=1)


class EmergencyGrantRevokeRequest(BaseModel):
    expected_version: Optional[int] = Field(default=None, ge=1)


class BackfillEvent(BaseModel):
    event_id: Optional[str] = None
    event_time: float = Field(allow_inf_nan=False)
    tenant: str
    client_key: str = ""
    name: str = ""
    region: str = ""
    labels_sig: str = ""
    rule_scope: Optional[str] = None  # inferred from region/tenant when absent
    rule_version: Optional[int] = Field(default=None, ge=1)
    group_id: Optional[str] = None
    config_version: int = Field(default=0, ge=0)
    result: str = "served"
    quantity: float = Field(default=1.0, ge=0)
    degraded: bool = False

    @field_validator("tenant")
    @classmethod
    def _tenant_nonempty(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if not v:
            raise ValueError("backfill events require a tenant")
        return v

    @field_validator("result")
    @classmethod
    def _known_result(cls, v: str) -> str:
        if v not in ("served", "budget_degraded", "budget_rejected"):
            raise ValueError(
                "result must be served, budget_degraded or budget_rejected"
            )
        return v

    def to_record(self) -> dict:
        scope = self.rule_scope or (
            "tenant" if self.tenant else ("region" if self.region else "global")
        )
        if scope not in ("global", "region", "tenant"):
            raise HTTPException(
                status_code=422,
                detail=f"invalid rule_scope {scope!r}",
            )
        return {
            "event_id": self.event_id,
            "event_time": self.event_time,
            "tenant": self.tenant,
            "client_key": self.client_key,
            "name": self.name,
            "region": self.region,
            "labels_sig": self.labels_sig,
            "rule_scope": scope,
            "rule_version": self.rule_version,
            "group_id": self.group_id,
            "config_version": self.config_version,
            "result": self.result,
            "quantity": self.quantity,
            "degraded": self.degraded,
        }


class BackfillRequest(BaseModel):
    events: list[BackfillEvent] = Field(min_length=1, max_length=10_000)


class RecomputeRequest(BaseModel):
    tenant: Optional[str] = None
    start: Optional[float] = Field(default=None, allow_inf_nan=False)
    end: Optional[float] = Field(default=None, allow_inf_nan=False)


class BudgetUpsertRequest(BaseModel):
    period_type: str = "day"
    amount: float = Field(gt=0, allow_inf_nan=False)
    alert_thresholds: list[float] = Field(
        default_factory=lambda: [0.8, 1.0]
    )
    over_policy: str = "reject"
    expected_version: Optional[int] = Field(default=None, ge=1)


class AlertAckRequest(BaseModel):
    comment: Optional[str] = None
    expected_version: Optional[int] = Field(default=None, ge=1)


class BudgetGroupUpsertRequest(BaseModel):
    description: str = ""
    parent_id: Optional[str] = None
    period_type: Optional[str] = None
    amount: Optional[float] = Field(default=None, allow_inf_nan=False)
    alert_thresholds: Optional[list[float]] = None
    over_policy: Optional[str] = None
    expected_version: Optional[int] = Field(default=None, ge=1)


class MemberMoveRequest(BaseModel):
    group_id: Optional[str] = Field(
        default=None, description="destination group; null/omit to detach"
    )
    expected_version: Optional[int] = Field(default=None, ge=0)


class OverrideCreateRequest(BaseModel):
    period_type: str = "day"
    amount: float = Field(gt=0, allow_inf_nan=False)
    alert_thresholds: list[float] = Field(
        default_factory=lambda: [0.8, 1.0]
    )
    over_policy: str = "reject"
    window_start: float = Field(allow_inf_nan=False)
    window_end: float = Field(allow_inf_nan=False)
    reason: str = ""


class OverrideDecideRequest(BaseModel):
    comment: Optional[str] = None
    expected_version: Optional[int] = Field(default=None, ge=1)


class OverrideRevokeRequest(BaseModel):
    expected_version: Optional[int] = Field(default=None, ge=1)


class Components:
    def __init__(
        self,
        db_path: str,
        admin_token: Optional[str] = None,
        config_file: Optional[str] = None,
        config_poll_interval: float = 1.0,
        health_interval: float = 2.0,
        health_timeout: float = 1.0,
        enable_background: bool = True,
        preview_ttl: float = 300.0,
    ):
        self.db_path = db_path
        db_dir = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(db_dir, exist_ok=True)
        self.admin_token = admin_token
        self.config_file = config_file
        self.config_poll_interval = config_poll_interval
        self.health_interval = health_interval
        self.health_timeout = health_timeout
        self.enable_background = enable_background

        db = connect(db_path)
        self.audit = AuditLog(db)
        self.authz = AuthzStore(db, self.audit, admin_token=admin_token)
        self.config = ConfigManager(db, self.audit, preview_ttl=preview_ttl)
        self.cache = ResolutionCache(time.time)
        # The health-check orchestrator owns the live effective health view
        # (per-target policies, thresholded state machines, overrides,
        # maintenance windows and append-only history, all SQLite-backed).
        self.health = HealthCheckStore(db, self.config, self.audit, time.time)
        self.health_scheduler = HealthScheduler(self.health)
        # The plain in-memory registry and the global-interval checker are
        # retained for standalone/library use and existing unit tests.
        self.health_registry = HealthRegistry()
        self.rate_limiter = RateLimiter(self.audit, time.time)
        self.metering = MeteringStore(db, self.audit, time.time)
        self.disputes = DisputeStore(db, self.metering, self.audit, time.time)
        self.drills = DrillStore(db, self.config, self.health, time.time)
        self.plans = PlanStore(db, self.config, self.drills, time.time)
        self.config.add_listener(
            self.rate_limiter.replace_buckets,
            self.rate_limiter.preview_replace,
        )
        self.resolver = Resolver(
            self.config,
            self.cache,
            self.health,
            self.audit,
            self.rate_limiter,
            self.metering,
        )
        self.checker = HealthChecker(
            self.health_registry,
            self.config,
            self.audit,
            interval=health_interval,
            timeout=health_timeout,
        )
        self._stop: Optional[asyncio.Event] = None
        self._tasks: list[asyncio.Task] = []

    def load_config_file(self) -> None:
        """Apply the config file if its version is newer than current."""
        if not self.config_file:
            return
        path = Path(self.config_file)
        if not path.exists():
            return
        bundle = ConfigBundle(**json.loads(path.read_text()))
        if bundle.version > self.config.snapshot().version:
            self.config.apply(bundle, source="file")

    async def _watch_config_file(self, stop: asyncio.Event) -> None:
        last_mtime: Optional[float] = None
        while not stop.is_set():
            try:
                path = Path(self.config_file)  # type: ignore[arg-type]
                mtime = path.stat().st_mtime
                if mtime != last_mtime:
                    last_mtime = mtime
                    self.load_config_file()
            except Exception as exc:  # noqa: BLE001 - keep watching
                print(f"config file reload failed: {exc}", flush=True)
            try:
                await asyncio.wait_for(stop.wait(), self.config_poll_interval)
            except asyncio.TimeoutError:
                pass

    async def start(self) -> None:
        self.config.load_persisted()
        try:
            self.load_config_file()
        except Exception as exc:  # noqa: BLE001
            print(f"initial config file load failed: {exc}", flush=True)
        if not self.enable_background:
            return
        self._stop = asyncio.Event()
        self._tasks.append(asyncio.create_task(self.health_scheduler.run(self._stop)))
        if self.config_file:
            self._tasks.append(asyncio.create_task(self._watch_config_file(self._stop)))

    async def shutdown(self) -> None:
        if self._stop:
            self._stop.set()
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()


def create_app(components: Components) -> FastAPI:
    comp = components

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await comp.start()
        yield
        await comp.shutdown()

    app = FastAPI(title="georesolve", version=__version__, lifespan=lifespan)

    # -- authz error mapping -------------------------------------------------

    @app.exception_handler(AuthnError)
    async def _authn(_req, exc: AuthnError):
        return JSONResponse(status_code=401, content={"detail": str(exc)})

    @app.exception_handler(Forbidden)
    async def _forbidden(_req, exc: Forbidden):
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(AuthzNotFound)
    async def _not_found(_req, exc: AuthzNotFound):
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(AuthzConflict)
    async def _conflict(_req, exc: AuthzConflict):
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(BudgetExceeded)
    async def _budget_exceeded(_req, exc: BudgetExceeded):
        d = exc.decision
        return JSONResponse(
            status_code=402,
            content={
                "detail": d.reason,
                "reason": d.reason,
                "event_id": exc.event_id,
                "budget": d.public(),
            },
        )

    @app.exception_handler(MeteringNotFound)
    async def _metering_not_found(_req, exc: MeteringNotFound):
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(MeteringConflict)
    async def _metering_conflict(_req, exc: MeteringConflict):
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(MeteringValidationError)
    async def _metering_validation(_req, exc: MeteringValidationError):
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(DrillNotFound)
    async def _drill_not_found(_req, exc: DrillNotFound):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": str(exc), "code": exc.code},
        )

    @app.exception_handler(DrillConflict)
    async def _drill_conflict(_req, exc: DrillConflict):
        # Semantic refusals (unknown frozen targets, step gaps, illegal
        # health changes, state/version conflicts) are already recorded in
        # the drill-only audit log by the store.
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": str(exc), "code": exc.code},
        )

    @app.exception_handler(DrillValidation)
    async def _drill_validation(_req, exc: DrillValidation):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": str(exc), "code": exc.code},
        )

    @app.exception_handler(PlanNotFound)
    async def _plan_not_found(_req, exc: PlanNotFound):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": str(exc), "code": exc.code},
        )

    @app.exception_handler(RunNotFound)
    async def _run_not_found(_req, exc: RunNotFound):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": str(exc), "code": exc.code},
        )

    @app.exception_handler(PlanForbidden)
    async def _plan_forbidden(_req, exc: PlanForbidden):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": str(exc), "code": exc.code},
        )

    @app.exception_handler(PlanConflict)
    async def _plan_conflict(_req, exc: PlanConflict):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": str(exc), "code": exc.code},
        )

    @app.exception_handler(PlanValidation)
    async def _plan_validation(_req, exc: PlanValidation):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": str(exc), "code": exc.code},
        )

    @app.exception_handler(PolicyDenied)
    async def _policy_denied(_req, exc: PolicyDenied):
        # Semantic refusals (cycles, expired overrides, cross-scope writes,
        # self-approval, concurrent member migration) surface as 409; the
        # store has already written the budget_policy_denied audit record.
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(HealthCheckNotFound)
    async def _health_check_not_found(_req, exc: HealthCheckNotFound):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": str(exc), "code": exc.code},
        )

    @app.exception_handler(HealthCheckConflict)
    async def _health_check_conflict(_req, exc: HealthCheckConflict):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": str(exc), "code": exc.code},
        )

    @app.exception_handler(HealthCheckValidation)
    async def _health_check_validation(_req, exc: HealthCheckValidation):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": str(exc), "code": exc.code},
        )

    async def authenticated(
        authorization: Optional[str] = Header(default=None),
    ) -> Caller:
        token = None
        if authorization and authorization.startswith("Bearer "):
            token = authorization[len("Bearer "):]
        return comp.authz.authenticate(token)

    # -- scope helpers ---------------------------------------------------------

    def item_scope(obj) -> Scope:
        return Scope(scope=obj.scope, region=obj.region, tenant=obj.tenant)

    def full_access(caller: Caller, action: str) -> bool:
        """True when the caller's grants cover every possible scope."""
        if caller.kind in ("bootstrap", "open"):
            return True
        return any(g.scope == "global" for g in caller.grants(action))

    def covered_by(grants: list[Scope], obj) -> bool:
        scope = item_scope(obj)
        return any(g.covers(scope) for g in grants)

    def scoped_merge(bundle: ConfigBundle, grants: list[Scope]) -> ConfigBundle:
        """Overlay a scoped caller's bundle over the live configuration.

        The bundle is the full desired state *of the caller's scope*: items
        covered by the caller's config:write grants are replaced wholesale,
        everything outside the scope is preserved untouched. ``defaults``
        is global state and is only changed by global callers.
        """
        snap = comp.config.snapshot()
        kept_rules: dict[tuple, object] = {}
        for r in snap.all_rules():
            if covered_by(grants, r):
                continue
            # A key may hold a current plus a scheduled rule; the bundle
            # format carries one rule per key, and the manager re-derives
            # the scheduled pair from live state on apply.
            cur = kept_rules.get(r.key())
            if cur is None or r.rule_version > cur.rule_version:
                kept_rules[r.key()] = r
        try:
            return ConfigBundle(
                version=bundle.version,
                defaults=snap.defaults,
                rules=[*kept_rules.values(), *bundle.rules],
                release_groups=[
                    g for g in snap.all_release_groups()
                    if not covered_by(grants, g)
                ]
                + list(bundle.release_groups),
                rate_limit_tiers=[
                    t for t in snap.all_rate_limit_tiers()
                    if not covered_by(grants, t)
                ]
                + list(bundle.rate_limit_tiers),
            )
        except ValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail=f"scoped merge produced an invalid bundle: {exc}",
            )

    def authorize_config_write(caller: Caller, bundle: ConfigBundle) -> ConfigBundle:
        """Authorize a config submission; returns the bundle to install.

        Global callers apply their bundle as-is. Scoped callers must own
        every submitted item (else 403 before anything mutates) and get a
        bundle merged over the live config for their scope only.
        """
        if full_access(caller, "config:write"):
            comp.authz.authorize(caller, "config:write")
            return bundle
        grants = caller.grants("config:write")
        items = [*bundle.rules, *bundle.release_groups, *bundle.rate_limit_tiers]
        comp.authz.authorize(
            caller, "config:write", [item_scope(i) for i in items]
        )
        return scoped_merge(bundle, grants)

    def filter_summary(summary: Optional[dict], grants: list[Scope]) -> Optional[dict]:
        """Keep only the version-summary diffs covered by the grants."""
        if summary is None:
            return None

        def cov(d: dict) -> bool:
            try:
                scope = Scope(
                    scope=d.get("scope") or "global",
                    region=d.get("region"),
                    tenant=d.get("tenant"),
                )
            except ValidationError:
                return False
            return any(g.covers(scope) for g in grants)

        out = dict(summary)
        rule_diffs = [d for d in summary.get("rule_diffs", []) if cov(d)]
        group_diffs = [
            d for d in summary.get("release_group_diffs", []) if cov(d)
        ]
        tier_diffs = [
            d for d in summary.get("rate_limit_tier_diffs", []) if cov(d)
        ]
        out["rule_diffs"] = rule_diffs
        out["release_group_diffs"] = group_diffs
        out["rate_limit_tier_diffs"] = tier_diffs
        names = {d.get("name") for d in rule_diffs + group_diffs}
        names.discard(None)
        out["affected_names"] = sorted(names)
        return out

    def filter_bundle_dict(bundle: dict, grants: list[Scope]) -> dict:
        """Scope-filter a serialized bundle (version history payloads)."""

        def cov(d: dict) -> bool:
            try:
                scope = Scope(
                    scope=d.get("scope") or "global",
                    region=d.get("region"),
                    tenant=d.get("tenant"),
                )
            except ValidationError:
                return False
            return any(g.covers(scope) for g in grants)

        out = dict(bundle)
        out["rules"] = [r for r in bundle.get("rules", []) if cov(r)]
        out["release_groups"] = [
            g for g in bundle.get("release_groups", []) if cov(g)
        ]
        out["rate_limit_tiers"] = [
            t for t in bundle.get("rate_limit_tiers", []) if cov(t)
        ]
        return out

    def record_scope(details: dict) -> Optional[Scope]:
        """Best-effort scope extraction from an audit record's details."""
        scope = details.get("scope")
        if scope in ("global", "region", "tenant"):
            try:
                return Scope(
                    scope=scope,
                    region=details.get("region"),
                    tenant=details.get("tenant"),
                )
            except ValidationError:
                return None
        rule_key = details.get("rule_key")
        if isinstance(rule_key, str):
            parts = rule_key.split("|")  # name|scope|region|tenant
            if len(parts) == 4 and parts[1] in ("global", "region", "tenant"):
                try:
                    return Scope(
                        scope=parts[1],
                        region=parts[2] or None,
                        tenant=parts[3] or None,
                    )
                except ValidationError:
                    return None
        if details.get("tenant"):
            return Scope(scope="tenant", tenant=details["tenant"])
        if details.get("region"):
            return Scope(scope="region", region=details["region"])
        return None

    def audit_visible(caller: Caller, grants: list[Scope], record: dict) -> bool:
        details = record.get("details") or {}
        # A caller always sees records about its own requests and changes.
        if caller.kind == "identity" and caller.identity_id in (
            details.get("identity"),
            details.get("actor"),
            details.get("requested_by"),
        ):
            return True
        scope = record_scope(details)
        return scope is not None and any(g.covers(scope) for g in grants)

    def entry_predicate(grants: list[Scope]) -> Callable:
        """Cache-entry visibility: entries carry (region, tenant) directly."""
        regions = {g.region for g in grants if g.scope == "region"}
        tenants = {g.tenant for g in grants if g.scope == "tenant"}

        def visible(entry) -> bool:
            return entry.region in regions or entry.tenant in tenants

        return visible

    def run_idempotent(
        idem_key: Optional[str],
        request: Request,
        caller: Caller,
        body: dict,
        produce: Callable[[], tuple[int, dict]],
    ) -> JSONResponse:
        """Execute ``produce`` at most once per Idempotency-Key.

        The first successful response is persisted; a duplicate submission
        replays it (marked idempotent_replay) without re-running the
        mutation, so retries never double-apply version bumps or audits.
        """
        if not idem_key:
            status, payload = produce()
            return JSONResponse(status_code=status, content=payload)
        fp = request_fingerprint(
            request.method, request.url.path, caller.identity_id, body
        )
        stored = comp.authz.idempotency_lookup(idem_key, fp)
        if stored is not None:
            return JSONResponse(
                status_code=stored["status_code"],
                content={**stored["body"], "idempotent_replay": True},
            )
        status, payload = produce()
        comp.authz.idempotency_store(idem_key, fp, status, payload)
        return JSONResponse(status_code=status, content=payload)

    def parse_labels(raw: str) -> dict:
        labels: dict[str, str] = {}
        for pair in (raw or "").split(","):
            pair = pair.strip()
            if not pair:
                continue
            if "=" not in pair:
                raise HTTPException(
                    status_code=400,
                    detail=f"malformed label {pair!r}, expected k=v",
                )
            k, v = pair.split("=", 1)
            labels[k] = v
        return labels

    def rate_limited(exc: RateLimitExceeded) -> JSONResponse:
        d = exc.decision
        return JSONResponse(
            status_code=429,
            headers={
                "Retry-After": str(
                    max(1, math.ceil(d.retry_after if d.retry_after is not None else 1.0))
                )
            },
            content={
                "detail": d.reason,
                "retry_after": d.retry_after,
                "rate_limit": d.public(),
            },
        )

    # -- data plane ------------------------------------------------------

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "config_version": comp.config.snapshot().version}

    @app.get("/v1/resolve")
    async def resolve(
        request: Request,
        name: str,
        region: str = "",
        tenant: str = "",
        client: Optional[str] = None,
        labels: str = "",
        x_request_id: Optional[str] = Header(
            default=None, alias="X-Request-Id"
        ),
    ):
        client_key = client or (request.client.host if request.client else "")
        try:
            return comp.resolver.resolve(
                name, region, tenant, client_key,
                labels=parse_labels(labels), request_id=x_request_id,
            )
        except RateLimitExceeded as exc:
            return rate_limited(exc)

    @app.get("/v1/explain")
    async def explain(
        request: Request,
        name: str,
        region: str = "",
        tenant: str = "",
        client: Optional[str] = None,
        labels: str = "",
    ):
        client_key = client or (request.client.host if request.client else "")
        return comp.resolver.explain(
            name, region, tenant, client_key, labels=parse_labels(labels)
        )

    # -- control plane ---------------------------------------------------

    @app.get("/v1/config")
    async def get_config(caller: Caller = Depends(authenticated)):
        comp.authz.authorize(caller, "config:read")
        snap = comp.config.snapshot()
        rules = sorted(snap.all_rules(), key=lambda r: (r.key(), r.rule_version))
        groups = sorted(
            snap.all_release_groups(), key=lambda g: (g.name, g.priority, g.id)
        )
        tiers = sorted(
            snap.all_rate_limit_tiers(), key=lambda t: (t.scope_key(), t.priority, t.id)
        )
        if not full_access(caller, "config:read"):
            grants = caller.grants("config:read")
            rules = [r for r in rules if covered_by(grants, r)]
            groups = [g for g in groups if covered_by(grants, g)]
            tiers = [t for t in tiers if covered_by(grants, t)]
        return {
            "version": snap.version,
            "defaults": snap.defaults.model_dump(),
            "rules": [r.model_dump() for r in rules],
            "release_groups": [g.model_dump() for g in groups],
            "rate_limit_tiers": [t.model_dump() for t in tiers],
        }

    def render_preview(result) -> dict:
        """Serialize a manager PreviewResult into the API response shape."""
        plan = result.plan
        return {
            "dry_run": True,
            "kind": result.kind,
            "base_version": result.base_version,
            "proposed_version": result.proposed_version,
            "rollback_of": result.rollback_of,
            "fingerprint": result.fingerprint,
            "preview_token": result.token,
            "expires_at": result.expires_at,
            "ttl_seconds": max(0, int(result.expires_at - time.time())),
            "counts": plan.counts(),
            "impact": result.listener_impacts,
            "summary": comp.config.preview_summary(result),
        }

    @app.post("/v1/config")
    async def post_config(
        req: ConfigApplyRequest, caller: Caller = Depends(authenticated)
    ):
        expected = req.expected_version
        token = req.preview_token
        # ConfigApplyRequest is itself a ConfigBundle (version/defaults/...).
        bundle = ConfigBundle(
            **req.model_dump(exclude={"expected_version", "preview_token"})
        )
        bundle = authorize_config_write(caller, bundle)
        try:
            result = comp.config.apply(
                bundle,
                source="api",
                expected_version=expected,
                preview_token=token,
            )
        except VersionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except PreviewRejected as exc:
            raise HTTPException(status_code=getattr(exc, "status_code", 409),
                                detail=str(exc))
        return {
            "applied": True,
            "version": result["version"],
            "changes": result["changes"],
            "release_group_changes": result["release_group_changes"],
            "rate_limit_changes": result["rate_limit_changes"],
            "invalidated": result["invalidated"],
            "summary": result["summary"],
        }

    @app.post("/v1/config/preview")
    async def preview_config(
        req: ConfigPreviewRequest, caller: Caller = Depends(authenticated)
    ):
        if req.version is None:
            req = req.model_copy(update={"version": comp.config.snapshot().version + 1})
        bundle = ConfigBundle(
            **req.model_dump(exclude={"expected_version", "preview_token"})
        )
        bundle = authorize_config_write(caller, bundle)
        try:
            result = comp.config.preview_bundle(bundle)
        except VersionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return render_preview(result)

    @app.get("/v1/config/versions")
    async def list_versions(
        limit: int = Query(default=50, ge=1, le=500),
        caller: Caller = Depends(authenticated),
    ):
        comp.authz.authorize(caller, "versions:read")
        versions = comp.config.versions(limit=limit)
        if not full_access(caller, "versions:read"):
            grants = caller.grants("versions:read")
            for v in versions:
                v["summary"] = filter_summary(v.get("summary"), grants)
        return {"versions": versions}

    @app.get("/v1/config/versions/{version}")
    async def get_version(
        version: int,
        payload: bool = Query(default=True, description="include full bundle"),
        caller: Caller = Depends(authenticated),
    ):
        comp.authz.authorize(caller, "versions:read")
        try:
            info = comp.config.version_info(version, include_payload=payload)
        except VersionNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        if not full_access(caller, "versions:read"):
            grants = caller.grants("versions:read")
            info["summary"] = filter_summary(info.get("summary"), grants)
            if "bundle" in info:
                info["bundle"] = filter_bundle_dict(info["bundle"], grants)
        return info

    @app.post("/v1/config/rollback/preview")
    async def preview_rollback(
        req: RollbackRequest, caller: Caller = Depends(authenticated)
    ):
        # A rollback rewrites the full global state: global scope required.
        comp.authz.authorize(caller, "config:write", [Scope()])
        try:
            result = comp.config.preview_rollback(req.version)
        except VersionNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except RollbackRejected as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return render_preview(result)

    @app.post("/v1/config/rollback")
    async def post_rollback(
        req: RollbackRequest, caller: Caller = Depends(authenticated)
    ):
        comp.authz.authorize(caller, "config:write", [Scope()])
        try:
            result = comp.config.rollback(
                req.version,
                source="api_rollback",
                expected_version=req.expected_version,
                preview_token=req.preview_token,
                new_version=req.new_version,
            )
        except VersionNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except RollbackRejected as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except VersionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except PreviewRejected as exc:
            raise HTTPException(status_code=getattr(exc, "status_code", 409),
                                detail=str(exc))
        return {
            "rolled_back": True,
            "target_version": req.version,
            "version": result["version"],
            "changes": result["changes"],
            "release_group_changes": result["release_group_changes"],
            "rate_limit_changes": result["rate_limit_changes"],
            "invalidated": result["invalidated"],
            "summary": result["summary"],
        }

    @app.get("/v1/audit")
    async def get_audit(
        type: Optional[str] = Query(default=None),
        limit: int = Query(default=200, ge=1, le=1000),
        since: Optional[float] = None,
        caller: Caller = Depends(authenticated),
    ):
        comp.authz.authorize(caller, "audit:read")
        records = comp.audit.query(type_=type, limit=limit, since=since)
        if not full_access(caller, "audit:read"):
            grants = caller.grants("audit:read")
            records = [r for r in records if audit_visible(caller, grants, r)]
        return {"records": records}

    # -- health-check orchestration -----------------------------------------

    def health_target_refs(target_id: str):
        """Every rule/group referencing a target; 404 when it is unknown."""
        snap = comp.config.snapshot()
        refs = [
            item
            for item in (*snap.all_rules(), *snap.all_release_groups())
            if any(t.id == target_id for t in item.targets)
        ]
        if not refs:
            raise HTTPException(
                status_code=404, detail=f"unknown target {target_id!r}"
            )
        return refs

    def authorize_health_read(caller: Caller, target_id: str):
        refs = health_target_refs(target_id)
        comp.authz.authorize(caller, "health:read", [item_scope(i) for i in refs])
        return refs

    def authorize_health_write(caller: Caller, target_id: str):
        refs = health_target_refs(target_id)
        comp.authz.authorize(caller, "health:write", [item_scope(i) for i in refs])
        return refs

    def _state_view(st: dict) -> dict:
        return {
            "target_id": st["target_id"],
            "healthy": st["effective_healthy"],
            "source": st["effective_source"],
            "observed_healthy": st["observed_healthy"],
            "paused": st["paused"],
            "paused_at": st["paused_at"],
            "paused_reason": st["paused_reason"],
            "in_maintenance": st["in_maintenance"],
            "override": (
                None
                if st["override_healthy"] is None
                else {
                    "healthy": st["override_healthy"],
                    "reason": st["override_reason"],
                    "by": st["override_by"],
                    "at": st["override_at"],
                    "expires_at": st["override_expires_at"],
                }
            ),
            "consecutive_failures": st["consecutive_failures"],
            "consecutive_successes": st["consecutive_successes"],
            "policy_version": st["policy_version"],
            "state_version": st["state_version"],
            "last_checked_at": st["last_checked_at"],
            "next_check_at": st["next_check_at"],
        }

    @app.get("/v1/health/targets")
    async def get_health(caller: Caller = Depends(authenticated)):
        comp.authz.authorize(caller, "health:read")
        view = comp.health.snapshot()
        if not full_access(caller, "health:read"):
            grants = caller.grants("health:read")
            snap = comp.config.snapshot()
            visible_ids = {
                t.id
                for item in (*snap.all_rules(), *snap.all_release_groups())
                if covered_by(grants, item)
                for t in item.targets
            }
            view = {tid: st for tid, st in view.items() if tid in visible_ids}
        return {"targets": view}

    @app.get("/v1/health/policies")
    async def list_health_policies(caller: Caller = Depends(authenticated)):
        comp.authz.authorize(caller, "health:read")
        policies = comp.health.list_policies()
        if not full_access(caller, "health:read"):
            grants = caller.grants("health:read")
            policies = [
                p for p in policies
                if all(
                    any(g.covers(item_scope(i)) for g in grants)
                    for i in health_target_refs(p["target_id"])
                )
            ]
        return {"policies": policies, "count": len(policies)}

    @app.get("/v1/health/targets/{target_id}")
    async def get_target_state(
        target_id: str, caller: Caller = Depends(authenticated)
    ):
        authorize_health_read(caller, target_id)
        try:
            st = comp.health.get_state(target_id)
        except HealthCheckNotFound:
            # A referenced target without any state yet is unmanaged/healthy.
            health_target_refs(target_id)
            return {
                "state": {
                    "target_id": target_id,
                    "healthy": True,
                    "source": "unmanaged",
                    "policy_version": 0,
                    "state_version": None,
                }
            }
        return {"state": _state_view(st)}

    @app.put("/v1/health/targets/{target_id}/policy")
    async def put_health_policy(
        target_id: str,
        req: PolicyUpsertIn,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_health_write(caller, target_id)

        def produce():
            policy, created = comp.health.upsert_policy(
                target_id, req, actor=caller.identity_id
            )
            return (201 if created else 200), {
                "policy": policy,
                "created": created,
            }

        return run_idempotent(
            idempotency_key, request, caller,
            {"target_id": target_id, **req.model_dump()}, produce,
        )

    @app.delete("/v1/health/targets/{target_id}/policy")
    async def delete_health_policy(
        target_id: str,
        request: Request,
        expected_version: Optional[int] = Query(default=None, ge=0),
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_health_write(caller, target_id)

        def produce():
            comp.health.delete_policy(
                target_id,
                expected_version=expected_version,
                actor=caller.identity_id,
            )
            return 200, {"deleted": target_id}

        return run_idempotent(idempotency_key, request, caller, {}, produce)

    @app.get("/v1/health/targets/{target_id}/history")
    async def get_health_history(
        target_id: str,
        policy_version: Optional[int] = Query(default=None, ge=1),
        kind: Optional[str] = Query(default=None),
        since: Optional[float] = None,
        until: Optional[float] = None,
        after_seq: Optional[int] = Query(default=None, ge=0),
        limit: int = Query(default=100, ge=1, le=1000),
        caller: Caller = Depends(authenticated),
    ):
        authorize_health_read(caller, target_id)
        if since is not None and until is not None and until < since:
            raise HTTPException(status_code=400, detail="until before since")
        return comp.health.history(
            target_id,
            policy_version=policy_version,
            kind=kind,
            since=since,
            until=until,
            after_seq=after_seq,
            limit=limit,
        )

    @app.get("/v1/health/policy-revisions")
    async def get_policy_revisions(
        target_id: Optional[str] = Query(default=None),
        limit: int = Query(default=200, ge=1, le=1000),
        caller: Caller = Depends(authenticated),
    ):
        comp.authz.authorize(caller, "health:read")
        if target_id is not None:
            authorize_health_read(caller, target_id)
        revisions = comp.health.revisions(target_id, limit=limit)
        if target_id is None and not full_access(caller, "health:read"):
            grants = caller.grants("health:read")
            visible = []
            for rev in revisions:
                try:
                    refs = health_target_refs(rev["target_id"])
                except HTTPException:
                    continue
                if all(
                    any(g.covers(item_scope(i)) for g in grants) for i in refs
                ):
                    visible.append(rev)
            revisions = visible
        return {"revisions": revisions, "count": len(revisions)}

    @app.post("/v1/health/targets/{target_id}/override")
    async def post_health_override(
        target_id: str,
        req: OverrideIn,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_health_write(caller, target_id)

        def produce():
            result = comp.health.override(
                target_id, req, actor=caller.identity_id
            )
            return 200, {
                "changed": result["changed"],
                "state": _state_view(result["state"]),
            }

        return run_idempotent(
            idempotency_key, request, caller,
            {"target_id": target_id, **req.model_dump()}, produce,
        )

    @app.post("/v1/health/targets/{target_id}/override/revoke")
    async def revoke_health_override(
        target_id: str,
        req: OverrideRevokeIn,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_health_write(caller, target_id)

        def produce():
            result = comp.health.revoke_override(
                target_id,
                expected_version=req.expected_version,
                actor=caller.identity_id,
            )
            return 200, {
                "changed": result["changed"],
                "state": _state_view(result["state"]),
            }

        return run_idempotent(
            idempotency_key, request, caller,
            {"target_id": target_id, **req.model_dump()}, produce,
        )

    @app.post("/v1/health/targets/{target_id}/pause")
    async def pause_health_target(
        target_id: str,
        req: PauseIn,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_health_write(caller, target_id)

        def produce():
            result = comp.health.pause(
                target_id,
                reason=req.reason,
                expected_version=req.expected_version,
                actor=caller.identity_id,
            )
            return 200, {
                "changed": result["changed"],
                "state": _state_view(result["state"]),
            }

        return run_idempotent(
            idempotency_key, request, caller,
            {"target_id": target_id, **req.model_dump()}, produce,
        )

    @app.post("/v1/health/targets/{target_id}/resume")
    async def resume_health_target(
        target_id: str,
        req: ResumeIn,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_health_write(caller, target_id)

        def produce():
            result = comp.health.resume(
                target_id,
                expected_version=req.expected_version,
                actor=caller.identity_id,
            )
            return 200, {
                "changed": result["changed"],
                "state": _state_view(result["state"]),
            }

        return run_idempotent(
            idempotency_key, request, caller,
            {"target_id": target_id, **req.model_dump()}, produce,
        )

    @app.post("/v1/health/targets/{target_id}/check")
    async def run_health_check(
        target_id: str, caller: Caller = Depends(authenticated)
    ):
        authorize_health_write(caller, target_id)
        # Make sure the target has a policy; a 404/409 from the store maps via
        # the exception handlers. This endpoint forces one immediate round.
        comp.health.get_policy(target_id)
        result = await comp.health.check_target(target_id)
        if result is None:
            st = comp.health.get_state(target_id)
            return {"ran": False, "reason": st["effective_source"],
                    "state": _state_view(st)}
        return {"ran": True, "check": result}

    @app.post("/v1/health/targets/{target_id}")
    async def override_health(
        target_id: str,
        req: HealthOverrideRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        # Legacy manual override endpoint: backed by the new orchestrator as a
        # permanent (no-expiry) manual override. Authorization requires every
        # referencing rule/group to be inside the caller's scope.
        authorize_health_write(caller, target_id)
        body = {"healthy": req.healthy}

        def produce():
            result = comp.health.override(
                target_id,
                OverrideIn(healthy=req.healthy),
                actor=caller.identity_id,
            )
            return 200, {
                "target_id": target_id,
                "healthy": req.healthy,
                "changed": result["changed"],
                "state_version": result["state"]["state_version"],
            }

        return run_idempotent(
            idempotency_key, request, caller, body, produce
        )

    @app.get("/v1/cache")
    async def get_cache(caller: Caller = Depends(authenticated)):
        comp.authz.authorize(caller, "cache:read")
        entries = comp.cache.items()
        if not full_access(caller, "cache:read"):
            visible = entry_predicate(caller.grants("cache:read"))
            entries = [e for e in entries if visible(e)]
        return {
            "entries": [
                {
                    "name": e.name,
                    "region": e.region,
                    "tenant": e.tenant,
                    "client_key": e.client_key,
                    "labels_sig": e.labels_sig,
                    "kind": e.kind,
                    "rule_version": e.rule_version,
                    "group_id": e.group_id,
                    "expires_at": e.expires_at,
                    "config_version": e.config_version,
                }
                for e in entries
            ]
        }

    @app.post("/v1/cache/flush")
    async def flush_cache(caller: Caller = Depends(authenticated)):
        comp.authz.authorize(caller, "cache:flush")
        if full_access(caller, "cache:flush"):
            n = comp.cache.clear()
            flushed_scope = "global"
        else:
            n = comp.cache.clear_where(
                entry_predicate(caller.grants("cache:flush"))
            )
            flushed_scope = [
                g.describe() for g in caller.grants("cache:flush")
            ]
        comp.audit.record(
            "cache_invalidation",
            {"reason": "manual_flush", "entries": n,
             "identity": caller.identity_id,
             "flush_scope": flushed_scope,
             "config_version": comp.config.snapshot().version},
        )
        return {"flushed": n}

    # -- metering & budgets --------------------------------------------------

    def tenant_scope(tenant: str) -> Scope:
        return Scope(scope="tenant", tenant=tenant)

    def authorize_tenants(
        caller: Caller, action: str, tenants: list[str]
    ) -> None:
        """Authorize an action on a set of tenant resources."""
        comp.authz.authorize(
            caller, action, [tenant_scope(t) for t in tenants if t]
        )

    def visible_tenant_grants(caller: Caller, action: str) -> list[Scope]:
        return caller.grants(action)

    def tenant_visible(caller: Caller, action: str, tenant: str) -> bool:
        if caller.kind in ("bootstrap", "open"):
            return True
        return any(
            g.covers(tenant_scope(tenant)) for g in caller.grants(action)
        )

    def filter_tenant_rows(caller: Caller, action: str, rows: list[dict]):
        if caller.kind in ("bootstrap", "open"):
            return rows
        return [r for r in rows if tenant_visible(caller, action, r["tenant"])]

    @app.get("/v1/metering/events")
    async def metering_events(
        tenant: Optional[str] = Query(default=None),
        client: Optional[str] = Query(default=None),
        rule_scope: Optional[str] = Query(default=None),
        start: Optional[float] = Query(default=None),
        end: Optional[float] = Query(default=None),
        limit: int = Query(default=500, ge=1, le=5000),
        caller: Caller = Depends(authenticated),
    ):
        if rule_scope is not None and rule_scope not in (
            "global", "region", "tenant"
        ):
            raise HTTPException(
                status_code=400,
                detail="rule_scope must be global, region or tenant",
            )
        if start is not None and end is not None and end < start:
            raise HTTPException(status_code=400, detail="end before start")
        # Authorization: a single-tenant query needs coverage of that
        # tenant; a global listing needs the action at all, and the output
        # is afterwards filtered to covered tenants.
        if tenant is not None:
            authorize_tenants(caller, "metering:read", [tenant])
        else:
            comp.authz.authorize(caller, "metering:read")
        events = comp.metering.list_events(
            tenant=tenant, client_key=client, rule_scope=rule_scope,
            start=start, end=end, limit=limit,
        )
        if tenant is None:
            events = filter_tenant_rows(caller, "metering:read", events)
        return {
            "events": events,
            "window": {"start": start, "end": end},
            "count": len(events),
        }

    @app.get("/v1/metering/aggregates")
    async def metering_aggregates(
        period: str = Query(default="day"),
        tenant: Optional[str] = Query(default=None),
        client: Optional[str] = Query(default=None),
        start: Optional[float] = Query(default=None),
        end: Optional[float] = Query(default=None),
        group_by_client: bool = Query(default=False),
        group_by_scope: bool = Query(default=False),
        caller: Caller = Depends(authenticated),
    ):
        if period not in PERIOD_TYPES:
            raise HTTPException(
                status_code=400, detail=f"period must be one of {PERIOD_TYPES}"
            )
        if start is not None and end is not None and end < start:
            raise HTTPException(status_code=400, detail="end before start")
        # A specific tenant must be covered; a global listing is afterwards
        # filtered to the tenants the caller can see.
        if tenant is not None:
            authorize_tenants(caller, "metering:read", [tenant])
        else:
            comp.authz.authorize(caller, "metering:read")
        try:
            rows = comp.metering.aggregates(
                tenant=tenant, period_type=period, start=start, end=end,
                group_by_client=group_by_client or client is not None,
                group_by_scope=group_by_scope,
            )
        except MeteringValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if client is not None:
            rows = [r for r in rows if r.get("client_key") == client]
        if tenant is None:
            rows = filter_tenant_rows(caller, "metering:read", rows)
        return {"period_type": period, "buckets": rows, "count": len(rows)}

    @app.post("/v1/metering/backfill", status_code=201)
    async def metering_backfill(
        req: BackfillRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        records = [e.to_record() for e in req.events]
        tenants = sorted({r["tenant"] for r in records if r["tenant"]})
        authorize_tenants(caller, "metering:backfill", tenants)

        def produce():
            result = comp.metering.backfill(records, actor=caller.identity_id)
            return 201, result

        return run_idempotent(
            idempotency_key, request, caller,
            {"events": records}, produce,
        )

    @app.post("/v1/metering/recompute")
    async def metering_recompute(
        req: RecomputeRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        # Recomputation rewrites aggregates; scoped to one tenant for
        # tenant-scoped callers, global only for global callers.
        if req.tenant:
            authorize_tenants(caller, "metering:recompute", [req.tenant])
        else:
            comp.authz.authorize(
                caller, "metering:recompute", [Scope()]
            )

        def produce():
            result = comp.metering.recompute(
                actor=caller.identity_id,
                tenant=req.tenant, start=req.start, end=req.end,
            )
            return 200, result

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    @app.get("/v1/budgets")
    async def list_budgets(caller: Caller = Depends(authenticated)):
        comp.authz.authorize(caller, "budget:read")
        budgets = comp.metering.list_budgets()
        return {"budgets": filter_tenant_rows(caller, "budget:read", budgets)}

    @app.get("/v1/budgets/{tenant}")
    async def get_budget(
        tenant: str,
        at: Optional[float] = Query(
            default=None,
            description="resolve the policy chain as of this epoch time",
        ),
        caller: Caller = Depends(authenticated),
    ):
        comp.authz.authorize(
            caller, "budget:read", [tenant_scope(tenant)]
        )
        status = comp.metering.budget_status(tenant, at=at)
        if status is None:
            raise HTTPException(
                status_code=404,
                detail=f"no budget policy applies to tenant {tenant!r}"
                + (f" at {at}" if at is not None else ""),
            )
        return status

    # -- tenant budget groups, memberships and temporary overrides ----------

    def require_global_budget_write(caller: Caller) -> None:
        """Groups are cross-tenant resources: only global budget:write manages."""
        grants = caller.grants("budget:write")
        if caller.kind in ("bootstrap", "open"):
            comp.authz.authorize(caller, "budget:write", [Scope()])
            return
        if not any(g.scope == "global" for g in grants):
            # Audit the denial explicitly before refusing, like other
            # cross-scope write attempts.
            comp.authz.authorize(caller, "budget:write", [Scope()])

    def filter_groups_for_caller(caller: Caller, groups: list[dict]) -> list[dict]:
        if caller.kind in ("bootstrap", "open"):
            return groups
        memberships = comp.metering.list_memberships()
        visible_groups: set[str] = set()
        for m in memberships:
            if any(
                g.covers(tenant_scope(m["tenant"]))
                for g in caller.grants("budget:read")
            ):
                visible_groups.add(m["group_id"])
        return [g for g in groups if g["id"] in visible_groups]

    @app.get("/v1/budget-groups")
    async def list_budget_groups(caller: Caller = Depends(authenticated)):
        comp.authz.authorize(caller, "budget:read")
        groups = comp.metering.list_groups()
        return {"groups": filter_groups_for_caller(caller, groups)}

    @app.post("/v1/budget-groups", status_code=201)
    async def create_budget_group(
        req: BudgetGroupUpsertRequest,
        request: Request,
        group_id: str = Query(..., description="id of the new group"),
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        require_global_budget_write(caller)

        def produce():
            spec = BudgetGroupSpec(id=group_id, **req.model_dump())
            group, created = comp.metering.upsert_group(
                spec, actor=caller.identity_id
            )
            return 201, {"group": group, "created": created}

        return run_idempotent(
            idempotency_key, request, caller,
            {"group_id": group_id, **req.model_dump()}, produce,
        )

    @app.get("/v1/budget-groups/{group_id}")
    async def get_budget_group(
        group_id: str, caller: Caller = Depends(authenticated)
    ):
        comp.authz.authorize(caller, "budget:read")
        try:
            group = comp.metering.get_group(group_id)
        except MeteringNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        visible = filter_groups_for_caller(caller, [group])
        if not visible and not caller.is_global:
            raise HTTPException(
                status_code=403,
                detail="no covered tenant belongs to this group",
            )
        return {"group": visible[0] if visible else group}

    @app.put("/v1/budget-groups/{group_id}")
    async def put_budget_group(
        group_id: str,
        req: BudgetGroupUpsertRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        require_global_budget_write(caller)

        def produce():
            spec = BudgetGroupSpec(id=group_id, **req.model_dump())
            group, created = comp.metering.upsert_group(
                spec, actor=caller.identity_id
            )
            return (201 if created else 200), {
                "group": group, "created": created
            }

        return run_idempotent(
            idempotency_key, request, caller,
            {"group_id": group_id, **req.model_dump()}, produce,
        )

    @app.delete("/v1/budget-groups/{group_id}")
    async def delete_budget_group(
        group_id: str,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        require_global_budget_write(caller)

        def produce():
            comp.metering.delete_group(group_id, actor=caller.identity_id)
            return 200, {"deleted": group_id}

        return run_idempotent(idempotency_key, request, caller, {}, produce)

    @app.post("/v1/budget-groups/{group_id}/members", status_code=200)
    async def add_group_members(
        group_id: str,
        req: MemberMoveRequest,
        request: Request,
        tenant: str = Query(..., description="tenant to assign or migrate"),
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        # Migrating a tenant rewrites a cross-tenant grouping resource: the
        # caller must hold global budget:write AND coverage of the moved
        # tenant, so a tenant-scoped admin can never reshuffle memberships.
        require_global_budget_write(caller)
        comp.authz.authorize(
            caller, "budget:write", [tenant_scope(tenant)]
        )

        def produce():
            membership, changed = comp.metering.move_member(
                tenant,
                group_id,
                actor=caller.identity_id,
                expected_version=req.expected_version,
            )
            return 200, {"membership": membership, "changed": changed}

        return run_idempotent(
            idempotency_key, request, caller,
            {"group_id": group_id, "tenant": tenant, **req.model_dump()},
            produce,
        )

    @app.delete("/v1/budget-groups/members/{tenant}")
    async def remove_group_member(
        tenant: str,
        request: Request,
        expected_version: Optional[int] = Query(default=None, ge=0),
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        require_global_budget_write(caller)
        comp.authz.authorize(
            caller, "budget:write", [tenant_scope(tenant)]
        )

        def produce():
            membership, changed = comp.metering.remove_member(
                tenant,
                actor=caller.identity_id,
                expected_version=expected_version,
            )
            return 200, {"membership": membership, "changed": changed}

        return run_idempotent(idempotency_key, request, caller, {}, produce)

    @app.get("/v1/budget-groups/members/{tenant}/history")
    async def get_membership_history(
        tenant: str, caller: Caller = Depends(authenticated)
    ):
        comp.authz.authorize(
            caller, "budget:read", [tenant_scope(tenant)]
        )
        return {
            "tenant": tenant,
            "history": comp.metering.membership_history(tenant),
        }

    @app.get("/v1/budgets/{tenant}/resolved")
    async def get_resolved_policy(
        tenant: str,
        at: Optional[float] = Query(default=None),
        caller: Caller = Depends(authenticated),
    ):
        """Resolve and show the effective policy with source and version."""
        comp.authz.authorize(
            caller, "budget:read", [tenant_scope(tenant)]
        )
        policy = comp.metering.resolve_policy(tenant, at=at)
        if policy is None:
            return {
                "tenant": tenant,
                "enabled": False,
                "policy": None,
            }
        out = policy.policy_dict()
        out["tenant"] = tenant
        out["enabled"] = True
        out["origin"] = policy.origin()
        out["resolved_at"] = policy.resolved_at
        return out

    @app.post("/v1/budgets/{tenant}/overrides", status_code=201)
    async def create_override(
        tenant: str,
        req: OverrideCreateRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        # Filing a request for a tenant's policy needs budget:write on that
        # tenant; the request grants nothing until a different admin approves.
        comp.authz.authorize(
            caller, "budget:write", [tenant_scope(tenant)]
        )

        def produce():
            spec = OverrideSpec(**req.model_dump())
            override = comp.metering.request_override(
                spec, tenant=tenant, actor=caller.identity_id
            )
            return 201, {"override": override}

        return run_idempotent(
            idempotency_key, request, caller,
            {"tenant": tenant, **req.model_dump()}, produce,
        )

    @app.get("/v1/budget-overrides")
    async def list_overrides(
        tenant: Optional[str] = Query(default=None),
        status: Optional[str] = Query(default=None),
        limit: int = Query(default=200, ge=1, le=1000),
        caller: Caller = Depends(authenticated),
    ):
        if tenant is not None:
            comp.authz.authorize(
                caller, "budget:read", [tenant_scope(tenant)]
            )
            overrides = comp.metering.list_overrides(
                tenant=tenant, status=status, limit=limit
            )
        else:
            comp.authz.authorize(caller, "budget:read")
            overrides = comp.metering.list_overrides(
                status=status, limit=limit
            )
            overrides = [
                o for o in overrides
                if tenant_visible(caller, "budget:read", o["tenant"])
            ]
        return {"overrides": overrides, "count": len(overrides)}

    def _get_visible_override(caller: Caller, override_id: str) -> dict:
        override = comp.metering.get_override(override_id)
        comp.authz.authorize(
            caller, "budget:read", [tenant_scope(override["tenant"])]
        )
        return override

    @app.get("/v1/budget-overrides/{override_id}")
    async def get_override(
        override_id: str, caller: Caller = Depends(authenticated)
    ):
        return {"override": _get_visible_override(caller, override_id)}

    def _decide_override(
        override_id: str,
        approve: bool,
        req: OverrideDecideRequest,
        request: Request,
        caller: Caller,
        idempotency_key: Optional[str],
    ):
        override = comp.metering.get_override(override_id)
        # The approver must independently hold budget:write over the tenant;
        # the store additionally refuses the original requester.
        comp.authz.authorize(
            caller, "budget:write", [tenant_scope(override["tenant"])]
        )

        def produce():
            result = comp.metering.decide_override(
                override_id,
                approve,
                actor=caller.identity_id,
                comment=req.comment,
                expected_version=req.expected_version,
            )
            return 200, {"override": result}

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    @app.post("/v1/budget-overrides/{override_id}/approve")
    async def approve_override(
        override_id: str,
        req: OverrideDecideRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        return _decide_override(
            override_id, True, req, request, caller, idempotency_key
        )

    @app.post("/v1/budget-overrides/{override_id}/reject")
    async def reject_override(
        override_id: str,
        req: OverrideDecideRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        return _decide_override(
            override_id, False, req, request, caller, idempotency_key
        )

    @app.post("/v1/budget-overrides/{override_id}/revoke")
    async def revoke_override(
        override_id: str,
        req: OverrideRevokeRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        override = comp.metering.get_override(override_id)
        comp.authz.authorize(
            caller, "budget:write", [tenant_scope(override["tenant"])]
        )

        def produce():
            result = comp.metering.revoke_override(
                override_id,
                actor=caller.identity_id,
                expected_version=req.expected_version,
            )
            return 200, {"override": result}

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    @app.put("/v1/budgets/{tenant}")
    async def put_budget(
        tenant: str,
        req: BudgetUpsertRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        try:
            spec = BudgetSpec(
                tenant=tenant,
                period_type=req.period_type,
                amount=req.amount,
                alert_thresholds=req.alert_thresholds,
                over_policy=req.over_policy,
                expected_version=req.expected_version,
            )
        except ValidationError as exc:
            raise HTTPException(
                status_code=422, detail=json.loads(exc.json())
            )
        comp.authz.authorize(
            caller, "budget:write", [tenant_scope(tenant)]
        )

        def produce():
            budget, created = comp.metering.upsert_budget(
                spec, actor=caller.identity_id
            )
            return (201 if created else 200), {
                "budget": budget, "created": created
            }

        return run_idempotent(
            idempotency_key, request, caller,
            {"tenant": tenant, **req.model_dump()}, produce,
        )

    @app.delete("/v1/budgets/{tenant}")
    async def delete_budget(
        tenant: str,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        comp.authz.authorize(
            caller, "budget:write", [tenant_scope(tenant)]
        )

        def produce():
            comp.metering.delete_budget(tenant, actor=caller.identity_id)
            return 200, {"deleted": tenant}

        return run_idempotent(idempotency_key, request, caller, {}, produce)

    @app.get("/v1/budget-alerts")
    async def list_budget_alerts(
        tenant: Optional[str] = Query(default=None),
        status: Optional[str] = Query(default=None),
        period: Optional[str] = Query(default=None),
        limit: int = Query(default=200, ge=1, le=1000),
        caller: Caller = Depends(authenticated),
    ):
        if status is not None and status not in ("open", "acknowledged"):
            raise HTTPException(
                status_code=400,
                detail="status must be 'open' or 'acknowledged'",
            )
        if period is not None and period not in PERIOD_TYPES:
            raise HTTPException(
                status_code=400, detail=f"period must be one of {PERIOD_TYPES}"
            )
        if tenant is not None:
            authorize_tenants(caller, "budget:read", [tenant])
        else:
            comp.authz.authorize(caller, "budget:read")
        alerts = comp.metering.list_alerts(
            tenant=tenant, status=status, period_type=period, limit=limit
        )
        if tenant is None:
            alerts = filter_tenant_rows(caller, "budget:read", alerts)
        return {"alerts": alerts, "count": len(alerts)}

    @app.post("/v1/budget-alerts/{alert_id}/acknowledge")
    async def acknowledge_budget_alert(
        alert_id: str,
        req: AlertAckRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        alert = comp.metering.get_alert(alert_id)
        comp.authz.authorize(
            caller, "budget:write", [tenant_scope(alert["tenant"])]
        )

        def produce():
            acked, changed = comp.metering.acknowledge_alert(
                alert_id,
                actor=caller.identity_id,
                comment=req.comment,
                expected_version=req.expected_version,
            )
            return 200, {"alert": acked, "changed": changed}

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    # -- budget billing disputes -------------------------------------------

    def _get_visible_dispute(caller: Caller, dispute_id: str) -> dict:
        """Fetch a dispute and require budget:read over its tenant."""
        dispute = comp.disputes.get(dispute_id)
        comp.authz.authorize(
            caller, "budget:read", [tenant_scope(dispute["tenant"])]
        )
        return dispute

    @app.post("/v1/budget-disputes", status_code=201)
    async def create_dispute(
        req: DisputeSpec,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        # The tenant is the path-level resource; the body must provide it.
        tenant = (req.tenant or "").strip().lower()
        if not tenant:
            raise HTTPException(
                status_code=422, detail="tenant is required in the request body"
            )
        comp.authz.authorize(
            caller, "budget:write", [tenant_scope(tenant)]
        )

        def produce():
            dispute = comp.disputes.create(
                req, tenant=tenant, actor=caller.identity_id
            )
            return 201, {"dispute": dispute}

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    @app.get("/v1/budget-disputes")
    async def list_disputes(
        tenant: Optional[str] = Query(default=None),
        period_type: Optional[str] = Query(default=None),
        period: Optional[str] = Query(default=None),
        status: Optional[str] = Query(default=None),
        since: Optional[float] = Query(default=None),
        until: Optional[float] = Query(default=None),
        limit: int = Query(default=200, ge=1, le=1000),
        caller: Caller = Depends(authenticated),
    ):
        if status is not None and status not in DISPUTE_STATUSES:
            raise HTTPException(
                status_code=400,
                detail=f"status must be one of {sorted(DISPUTE_STATUSES)}",
            )
        if period_type is not None and period_type not in PERIOD_TYPES:
            raise HTTPException(
                status_code=400, detail=f"period must be one of {PERIOD_TYPES}"
            )
        if since is not None and until is not None and until < since:
            raise HTTPException(status_code=400, detail="until before since")
        # A single-tenant query is authorized on that tenant; a global
        # listing requires the action and is filtered to covered tenants.
        if tenant is not None:
            authorize_tenants(caller, "budget:read", [tenant])
        else:
            comp.authz.authorize(caller, "budget:read")
        disputes = comp.disputes.list_disputes(
            tenant=tenant, period_type=period_type, period=period,
            status=status, since=since, until=until, limit=limit,
        )
        if tenant is None:
            disputes = filter_tenant_rows(caller, "budget:read", disputes)
        return {"disputes": disputes, "count": len(disputes)}

    @app.get("/v1/budget-disputes/{dispute_id}")
    async def get_dispute(
        dispute_id: str, caller: Caller = Depends(authenticated)
    ):
        dispute = _get_visible_dispute(caller, dispute_id)
        history = comp.disputes.history(dispute_id)
        return {"dispute": dispute, "history": history}

    @app.get("/v1/budget-disputes/{dispute_id}/history")
    async def get_dispute_history(
        dispute_id: str,
        since: Optional[float] = Query(default=None),
        until: Optional[float] = Query(default=None),
        caller: Caller = Depends(authenticated),
    ):
        dispute = _get_visible_dispute(caller, dispute_id)
        history = comp.disputes.history(
            dispute_id, since=since, until=until
        )
        return {
            "dispute_id": dispute_id,
            "tenant": dispute["tenant"],
            "history": history,
        }

    @app.post("/v1/budget-disputes/{dispute_id}/submit")
    async def submit_dispute(
        dispute_id: str,
        req: DisputeSubmitRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        dispute = comp.disputes.get(dispute_id)
        comp.authz.authorize(
            caller, "budget:write", [tenant_scope(dispute["tenant"])]
        )

        def produce():
            result = comp.disputes.submit(
                dispute_id,
                actor=caller.identity_id,
                retroactive=req.retroactive,
            )
            return 200, {"dispute": result}

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    def _decide_dispute(
        dispute_id: str,
        approve: bool,
        req: DisputeDecisionRequest,
        request: Request,
        caller: Caller,
        idempotency_key: Optional[str],
    ):
        # Fetch first only to resolve the tenant for the scope check; the
        # store itself enforces that the decider is not the creator.
        dispute = comp.disputes.get(dispute_id)
        comp.authz.authorize(
            caller, "budget:write", [tenant_scope(dispute["tenant"])]
        )

        def produce():
            result = comp.disputes.decide(
                dispute_id,
                approve,
                actor=caller.identity_id,
                comment=req.comment,
                expected_version=req.expected_version,
            )
            return 200, {"dispute": result}

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    @app.post("/v1/budget-disputes/{dispute_id}/approve")
    async def approve_dispute(
        dispute_id: str,
        req: DisputeDecisionRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        return _decide_dispute(
            dispute_id, True, req, request, caller, idempotency_key
        )

    @app.post("/v1/budget-disputes/{dispute_id}/reject")
    async def reject_dispute(
        dispute_id: str,
        req: DisputeDecisionRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        return _decide_dispute(
            dispute_id, False, req, request, caller, idempotency_key
        )

    @app.post("/v1/budget-disputes/{dispute_id}/apply")
    async def apply_dispute(
        dispute_id: str,
        req: DisputeApplyRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        dispute = comp.disputes.get(dispute_id)
        comp.authz.authorize(
            caller, "budget:write", [tenant_scope(dispute["tenant"])]
        )

        def produce():
            result = comp.disputes.apply(
                dispute_id,
                actor=caller.identity_id,
                expected_version=req.expected_version,
            )
            return 200, {"dispute": result}

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    @app.post("/v1/budget-disputes/{dispute_id}/revoke")
    async def revoke_dispute(
        dispute_id: str,
        req: DisputeRevokeRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        dispute = comp.disputes.get(dispute_id)
        comp.authz.authorize(
            caller, "budget:write", [tenant_scope(dispute["tenant"])]
        )

        def produce():
            result = comp.disputes.revoke(
                dispute_id,
                actor=caller.identity_id,
                reason=req.reason,
                expected_version=req.expected_version,
            )
            return 200, {"dispute": result}

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    @app.get("/v1/budgets/{tenant}/adjustments")
    async def list_tenant_adjustments(
        tenant: str,
        period_type: str = Query(default="day"),
        period: Optional[str] = Query(default=None),
        kind: Optional[str] = Query(default=None),
        limit: int = Query(default=500, ge=1, le=2000),
        caller: Caller = Depends(authenticated),
    ):
        if period_type not in PERIOD_TYPES:
            raise HTTPException(
                status_code=400, detail=f"period must be one of {PERIOD_TYPES}"
            )
        if kind is not None and kind not in ("normal", "retroactive"):
            raise HTTPException(
                status_code=400,
                detail="kind must be 'normal' or 'retroactive'",
            )
        comp.authz.authorize(
            caller, "budget:read", [tenant_scope(tenant)]
        )
        adjustments = comp.disputes.list_adjustments(
            tenant=tenant, period_type=period_type, period=period,
            kind=kind, limit=limit,
        )
        return {"adjustments": adjustments, "count": len(adjustments)}

    @app.get("/v1/budgets/{tenant}/adjusted")
    async def get_adjusted_budget(
        tenant: str,
        period_type: str = Query(default="day"),
        period: Optional[str] = Query(
            default=None,
            description="period label (YYYY-MM-DD / YYYY-MM); current if omitted",
        ),
        caller: Caller = Depends(authenticated),
    ):
        if period_type not in PERIOD_TYPES:
            raise HTTPException(
                status_code=400, detail=f"period must be one of {PERIOD_TYPES}"
            )
        comp.authz.authorize(
            caller, "budget:read", [tenant_scope(tenant)]
        )
        try:
            at = (
                comp.disputes._parse_period(period, period_type)
                if period is not None
                else time.time()
            )
        except MeteringValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        projection = comp.disputes.adjusted_budget(
            tenant, period_type, at
        )
        # Attach the governing policy and budget allowance when one exists so
        # the adjusted usage can be compared against the budget threshold.
        status = comp.metering.budget_status(
            tenant, at=projection["period_start"]
        )
        if status is not None:
            projection["budget"] = status["budget"]
            projection["amount"] = status["amount"]
            projection["policy_origin"] = status["policy_origin"]
            projection["frozen"] = status["frozen"]
        return projection

    # -- fault drills (isolated resolution replay) ------------------------

    def authorize_drill(caller: Caller, action: str) -> None:
        """Drills replay a full global config snapshot: global scope only."""
        comp.authz.authorize(caller, action, [Scope()])

    def drill_fingerprint(body: dict) -> str:
        return hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()

    @app.post("/v1/drills", status_code=201)
    async def create_drill(
        req: DrillCreateIn,
        caller: Caller = Depends(authenticated),
    ):
        # Creation runs its own validation-and-audit inside the store
        # (refusals are written to the drill-only audit log), so authorize
        # first and let the store translate validation into precise codes.
        authorize_drill(caller, "drill:write")
        drill = comp.drills.create(req, actor=caller.identity_id)
        return {"drill": comp.drills.get(drill["id"])}

    @app.get("/v1/drills")
    async def list_drills(
        status: Optional[str] = Query(default=None),
        config_version: Optional[int] = Query(default=None),
        limit: int = Query(default=200, ge=1, le=1000),
        caller: Caller = Depends(authenticated),
    ):
        authorize_drill(caller, "drill:read")
        drills = comp.drills.list_drills(
            status=status, config_version=config_version, limit=limit
        )
        return {"drills": drills, "count": len(drills)}

    @app.get("/v1/drills/{drill_id}")
    async def get_drill(
        drill_id: str, caller: Caller = Depends(authenticated)
    ):
        authorize_drill(caller, "drill:read")
        return {"drill": comp.drills.get(drill_id)}

    @app.post("/v1/drills/{drill_id}/advance")
    async def advance_drill(
        drill_id: str,
        req: AdvanceIn,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_drill(caller, "drill:write")
        status_code, payload = comp.drills.advance(
            drill_id,
            req,
            actor=caller.identity_id,
            idem_key=idempotency_key,
            fingerprint=drill_fingerprint(req.model_dump()) if idempotency_key else None,
        )
        return JSONResponse(status_code=status_code, content=payload)

    @app.post("/v1/drills/{drill_id}/pause")
    async def pause_drill(
        drill_id: str,
        req: TransitionIn,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_drill(caller, "drill:write")
        status_code, payload = comp.drills.pause(
            drill_id,
            actor=caller.identity_id,
            expected_version=req.expected_version,
            reason=req.reason,
            idem_key=idempotency_key,
            fingerprint=drill_fingerprint(req.model_dump()) if idempotency_key else None,
        )
        return JSONResponse(status_code=status_code, content=payload)

    @app.post("/v1/drills/{drill_id}/resume")
    async def resume_drill(
        drill_id: str,
        req: TransitionIn,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_drill(caller, "drill:write")
        status_code, payload = comp.drills.resume(
            drill_id,
            actor=caller.identity_id,
            expected_version=req.expected_version,
            reason=req.reason,
            idem_key=idempotency_key,
            fingerprint=drill_fingerprint(req.model_dump()) if idempotency_key else None,
        )
        return JSONResponse(status_code=status_code, content=payload)

    @app.post("/v1/drills/{drill_id}/reset")
    async def reset_drill(
        drill_id: str,
        req: TransitionIn,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_drill(caller, "drill:write")
        status_code, payload = comp.drills.reset(
            drill_id,
            actor=caller.identity_id,
            expected_version=req.expected_version,
            reason=req.reason,
            idem_key=idempotency_key,
            fingerprint=drill_fingerprint(req.model_dump()) if idempotency_key else None,
        )
        return JSONResponse(status_code=status_code, content=payload)

    @app.get("/v1/drills/{drill_id}/steps/{seq}")
    async def get_drill_step(
        drill_id: str,
        seq: int,
        caller: Caller = Depends(authenticated),
    ):
        authorize_drill(caller, "drill:read")
        return {"drill_id": drill_id, "step": comp.drills.step(drill_id, seq)}

    @app.post("/v1/drills/{drill_id}/report")
    async def drill_report(
        drill_id: str, caller: Caller = Depends(authenticated)
    ):
        authorize_drill(caller, "drill:read")
        # Read-only: generated once per run, then frozen and replayed
        # identically (same content and checksum) for every repeat.
        return comp.drills.report(drill_id)

    @app.get("/v1/drills-audit")
    async def drills_audit(
        drill_id: Optional[str] = Query(default=None),
        action: Optional[str] = Query(default=None),
        since: Optional[float] = Query(default=None),
        limit: int = Query(default=500, ge=1, le=2000),
        caller: Caller = Depends(authenticated),
    ):
        authorize_drill(caller, "drill:read")
        records = comp.drills.drill_audit(
            drill_id, action=action, since=since, limit=limit
        )
        return {"records": records, "count": len(records)}

    # -- reusable drill plans, runs and branches ----------------------------

    def plan_fp(request: Request, caller: Caller, body: dict) -> str:
        # Bind the key to endpoint path as well, so one key can never replay
        # a *different* endpoint's stored response.
        return request_fingerprint(
            request.method, request.url.path, caller.identity_id, body
        )

    @app.post("/v1/drill-plans", status_code=201)
    async def create_plan(
        req: PlanCreateIn,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_drill(caller, "drill:write")
        fp = plan_fp(request, caller, req.model_dump()) if idempotency_key else None
        status_code, payload = comp.plans.create_plan(
            req,
            actor=caller.identity_id,
            idem_key=idempotency_key,
            fingerprint=fp,
        )
        return JSONResponse(status_code=status_code, content=payload)

    @app.get("/v1/drill-plans")
    async def list_plans(
        status: Optional[str] = Query(default=None),
        config_version: Optional[int] = Query(default=None),
        limit: int = Query(default=200, ge=1, le=1000),
        caller: Caller = Depends(authenticated),
    ):
        authorize_drill(caller, "drill:read")
        plans = comp.plans.list_plans(
            status=status, config_version=config_version, limit=limit
        )
        return {"plans": plans, "count": len(plans)}

    @app.get("/v1/drill-plans/{plan_id}")
    async def get_plan(
        plan_id: str, caller: Caller = Depends(authenticated)
    ):
        authorize_drill(caller, "drill:read")
        return {"plan": comp.plans.get_plan(plan_id)}

    @app.post("/v1/drill-plans/{plan_id}/archive")
    async def archive_plan(
        plan_id: str,
        req: PlanArchiveIn,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_drill(caller, "drill:write")
        fp = plan_fp(request, caller, req.model_dump()) if idempotency_key else None
        status_code, payload = comp.plans.archive_plan(
            plan_id,
            req,
            actor=caller.identity_id,
            idem_key=idempotency_key,
            fingerprint=fp,
        )
        return JSONResponse(status_code=status_code, content=payload)

    @app.post("/v1/drill-plans/{plan_id}/runs", status_code=201)
    async def create_plan_run(
        plan_id: str,
        req: RunCreateIn,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_drill(caller, "drill:write")
        fp = plan_fp(request, caller, req.model_dump()) if idempotency_key else None
        status_code, payload = comp.plans.create_run(
            plan_id,
            req,
            actor=caller.identity_id,
            idem_key=idempotency_key,
            fingerprint=fp,
        )
        return JSONResponse(status_code=status_code, content=payload)

    @app.get("/v1/drill-plans/{plan_id}/runs")
    async def list_plan_runs(
        plan_id: str,
        owner_id: Optional[str] = Query(default=None),
        status: Optional[str] = Query(default=None),
        limit: int = Query(default=200, ge=1, le=1000),
        caller: Caller = Depends(authenticated),
    ):
        authorize_drill(caller, "drill:read")
        # 404 on an unknown plan even before owner filtering.
        comp.plans.get_plan(plan_id)
        runs = comp.plans.list_runs(
            plan_id=plan_id,
            owner_id=owner_id,
            status=status,
            actor=caller.identity_id,
            limit=limit,
        )
        return {"runs": runs, "count": len(runs)}

    @app.get("/v1/drill-runs")
    async def list_all_runs(
        plan_id: Optional[str] = Query(default=None),
        owner_id: Optional[str] = Query(default=None),
        status: Optional[str] = Query(default=None),
        limit: int = Query(default=200, ge=1, le=1000),
        caller: Caller = Depends(authenticated),
    ):
        authorize_drill(caller, "drill:read")
        runs = comp.plans.list_runs(
            plan_id=plan_id,
            owner_id=owner_id,
            status=status,
            actor=caller.identity_id,
            limit=limit,
        )
        return {"runs": runs, "count": len(runs)}

    @app.get("/v1/drill-runs/{run_id}")
    async def get_run(
        run_id: str, caller: Caller = Depends(authenticated)
    ):
        authorize_drill(caller, "drill:read")
        return {"run": comp.plans.get_run(run_id, actor=caller.identity_id)}

    @app.get("/v1/drill-runs/{run_id}/steps/{seq}")
    async def get_run_step(
        run_id: str,
        seq: int,
        caller: Caller = Depends(authenticated),
    ):
        authorize_drill(caller, "drill:read")
        return {
            "run_id": run_id,
            "step": comp.plans.run_step(run_id, seq, actor=caller.identity_id),
        }

    @app.post("/v1/drill-runs/{run_id}/advance")
    async def advance_run(
        run_id: str,
        req: RunAdvanceIn,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_drill(caller, "drill:write")
        fp = drill_fingerprint(req.model_dump()) if idempotency_key else None
        status_code, payload = comp.plans.advance(
            run_id,
            req,
            actor=caller.identity_id,
            idem_key=idempotency_key,
            fingerprint=fp,
        )
        return JSONResponse(status_code=status_code, content=payload)

    def _run_transition_endpoint(
        run_id: str,
        req: RunTransitionIn,
        caller: Caller,
        idempotency_key: Optional[str],
        method: Callable,
    ):
        authorize_drill(caller, "drill:write")
        fp = drill_fingerprint(req.model_dump()) if idempotency_key else None
        return method(
            run_id,
            actor=caller.identity_id,
            expected_version=req.expected_version,
            reason=req.reason,
            idem_key=idempotency_key,
            fingerprint=fp,
        )

    @app.post("/v1/drill-runs/{run_id}/pause")
    async def pause_run(
        run_id: str,
        req: RunTransitionIn,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        status_code, payload = _run_transition_endpoint(
            run_id, req, caller, idempotency_key, comp.plans.pause_run
        )
        return JSONResponse(status_code=status_code, content=payload)

    @app.post("/v1/drill-runs/{run_id}/resume")
    async def resume_run(
        run_id: str,
        req: RunTransitionIn,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        status_code, payload = _run_transition_endpoint(
            run_id, req, caller, idempotency_key, comp.plans.resume_run
        )
        return JSONResponse(status_code=status_code, content=payload)

    @app.post("/v1/drill-runs/{run_id}/reset")
    async def reset_run(
        run_id: str,
        req: RunTransitionIn,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        status_code, payload = _run_transition_endpoint(
            run_id, req, caller, idempotency_key, comp.plans.reset_run
        )
        return JSONResponse(status_code=status_code, content=payload)

    @app.post("/v1/drill-runs/{run_id}/report")
    async def run_report(
        run_id: str, caller: Caller = Depends(authenticated)
    ):
        authorize_drill(caller, "drill:read")
        return comp.plans.run_report(run_id, actor=caller.identity_id)

    @app.post("/v1/drill-runs/{run_id}/branches", status_code=201)
    async def create_branch(
        run_id: str,
        req: BranchCreateIn,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        authorize_drill(caller, "drill:write")
        fp = plan_fp(request, caller, req.model_dump()) if idempotency_key else None
        status_code, payload = comp.plans.create_branch(
            run_id,
            req,
            actor=caller.identity_id,
            idem_key=idempotency_key,
            fingerprint=fp,
        )
        return JSONResponse(status_code=status_code, content=payload)

    @app.post("/v1/drill-runs/{run_id}/compare")
    async def compare_runs(
        run_id: str,
        req: CompareIn,
        caller: Caller = Depends(authenticated),
    ):
        authorize_drill(caller, "drill:read")
        return comp.plans.compare(
            run_id, req.other_run_id, actor=caller.identity_id
        )

    @app.get("/v1/drill-plans-audit")
    async def plans_audit(
        plan_id: Optional[str] = Query(default=None),
        run_id: Optional[str] = Query(default=None),
        action: Optional[str] = Query(default=None),
        since: Optional[float] = Query(default=None),
        limit: int = Query(default=500, ge=1, le=2000),
        caller: Caller = Depends(authenticated),
    ):
        authorize_drill(caller, "drill:read")
        records = comp.plans.plan_audit(
            plan_id=plan_id,
            run_id=run_id,
            action=action,
            since=since,
            limit=limit,
            actor=caller.identity_id,
        )
        return {"records": records, "count": len(records)}

    # -- admin delegation ----------------------------------------------------

    @app.post("/v1/admin/roles", status_code=201)
    async def create_role(
        req: RoleCreateRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        comp.authz.authorize(caller, "admin:manage")

        def produce():
            role = comp.authz.create_role(
                caller, req.id, req.description, req.permissions
            )
            return 201, {
                "role": role.public(),
                "authz_version": comp.authz.version,
            }

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    @app.get("/v1/admin/roles")
    async def list_roles(caller: Caller = Depends(authenticated)):
        comp.authz.authorize(caller, "admin:manage")
        return {
            "roles": [r.public() for r in comp.authz.list_roles(caller)],
            "authz_version": comp.authz.version,
        }

    @app.get("/v1/admin/roles/{role_id}")
    async def get_role(role_id: str, caller: Caller = Depends(authenticated)):
        comp.authz.authorize(caller, "admin:manage")
        role = comp.authz.get_role(role_id)
        comp.authz.check_visible(caller, role.permissions)
        return {"role": role.public(), "authz_version": comp.authz.version}

    @app.put("/v1/admin/roles/{role_id}")
    async def update_role(
        role_id: str,
        req: RoleUpdateRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        comp.authz.authorize(caller, "admin:manage")

        def produce():
            role = comp.authz.update_role(
                caller,
                role_id,
                req.description,
                req.permissions,
                req.expected_version,
            )
            return 200, {
                "role": role.public(),
                "authz_version": comp.authz.version,
            }

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    @app.delete("/v1/admin/roles/{role_id}")
    async def delete_role(
        role_id: str,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        comp.authz.authorize(caller, "admin:manage")

        def produce():
            comp.authz.delete_role(caller, role_id)
            return 200, {
                "deleted": role_id,
                "authz_version": comp.authz.version,
            }

        return run_idempotent(idempotency_key, request, caller, {}, produce)

    @app.post("/v1/admin/identities", status_code=201)
    async def create_identity(
        req: IdentityCreateRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        comp.authz.authorize(caller, "admin:manage")

        def produce():
            ident, token = comp.authz.create_identity(
                caller, req.id, req.roles, token=req.token
            )
            # The plaintext token is returned exactly once, here.
            return 201, {
                "identity": ident.public(),
                "token": token,
                "authz_version": comp.authz.version,
            }

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    @app.get("/v1/admin/identities")
    async def list_identities(caller: Caller = Depends(authenticated)):
        comp.authz.authorize(caller, "admin:manage")
        return {
            "identities": [
                i.public() for i in comp.authz.list_identities(caller)
            ],
            "authz_version": comp.authz.version,
        }

    @app.get("/v1/admin/identities/{identity_id}")
    async def get_identity(
        identity_id: str, caller: Caller = Depends(authenticated)
    ):
        comp.authz.authorize(caller, "admin:manage")
        ident = comp.authz.get_identity(identity_id)
        if not comp.authz.identity_visible(caller, ident):
            raise Forbidden(
                f"identity {caller.identity_id!r} may not view "
                f"identity {identity_id!r}"
            )
        return {
            "identity": ident.public(),
            "authz_version": comp.authz.version,
        }

    @app.put("/v1/admin/identities/{identity_id}")
    async def update_identity(
        identity_id: str,
        req: IdentityUpdateRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        comp.authz.authorize(caller, "admin:manage")

        def produce():
            ident, new_token = comp.authz.update_identity(
                caller,
                identity_id,
                req.roles,
                req.rotate_token,
                req.expected_version,
            )
            out = {
                "identity": ident.public(),
                "authz_version": comp.authz.version,
            }
            if new_token is not None:
                out["token"] = new_token
            return 200, out

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    def _set_identity_status(
        identity_id: str,
        active: bool,
        request: Request,
        caller: Caller,
        idempotency_key: Optional[str],
    ):
        comp.authz.authorize(caller, "admin:manage")

        def produce():
            ident, changed = comp.authz.set_status(caller, identity_id, active)
            return 200, {
                "identity": ident.public(),
                "changed": changed,
                "authz_version": comp.authz.version,
            }

        return run_idempotent(idempotency_key, request, caller, {}, produce)

    @app.post("/v1/admin/identities/{identity_id}/deactivate")
    async def deactivate_identity(
        identity_id: str,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        return _set_identity_status(
            identity_id, False, request, caller, idempotency_key
        )

    @app.post("/v1/admin/identities/{identity_id}/reactivate")
    async def reactivate_identity(
        identity_id: str,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        return _set_identity_status(
            identity_id, True, request, caller, idempotency_key
        )

    # -- emergency grants --------------------------------------------------

    @app.post("/v1/admin/emergency-grants", status_code=201)
    async def create_emergency_grant(
        req: EmergencyGrantCreateRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        # Any authenticated caller may file a request; it grants nothing
        # until a different, authorized admin approves it.
        def produce():
            grant = comp.authz.request_grant(
                caller,
                req.identity_id,
                req.reason,
                req.permissions,
                req.duration_seconds,
            )
            return 201, {
                "grant": comp.authz.grant_view(grant),
                "authz_version": comp.authz.version,
            }

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    @app.get("/v1/admin/emergency-grants")
    async def list_emergency_grants(
        status: Optional[str] = Query(default=None),
        identity_id: Optional[str] = Query(default=None),
        caller: Caller = Depends(authenticated),
    ):
        if status is not None and status not in GRANT_STATUSES:
            raise HTTPException(
                status_code=400,
                detail=f"unknown status {status!r}; "
                f"known: {sorted(GRANT_STATUSES)}",
            )
        grants = comp.authz.list_grants(caller, status=status, identity_id=identity_id)
        return {
            "grants": [comp.authz.grant_view(g) for g in grants],
            "authz_version": comp.authz.version,
        }

    @app.get("/v1/admin/emergency-grants/{grant_id}")
    async def get_emergency_grant(
        grant_id: str, caller: Caller = Depends(authenticated)
    ):
        grant = comp.authz.get_grant(grant_id)
        if not comp.authz.grant_visible(caller, grant):
            raise Forbidden(
                f"identity {caller.identity_id!r} may not view "
                f"emergency grant {grant_id!r}"
            )
        return {
            "grant": comp.authz.grant_view(grant),
            "authz_version": comp.authz.version,
        }

    def _decide_emergency_grant(
        grant_id: str,
        approve: bool,
        req: EmergencyGrantDecideRequest,
        request: Request,
        caller: Caller,
        idempotency_key: Optional[str],
    ):
        # Deciding requires admin:manage; the store additionally enforces
        # that the decider is not the requester and that the granted
        # permissions stay within the decider's delegable scope.
        comp.authz.authorize(caller, "admin:manage")

        def produce():
            grant = comp.authz.decide_grant(
                caller, grant_id, approve, req.comment, req.expected_version
            )
            return 200, {
                "grant": comp.authz.grant_view(grant),
                "authz_version": comp.authz.version,
            }

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    @app.post("/v1/admin/emergency-grants/{grant_id}/approve")
    async def approve_emergency_grant(
        grant_id: str,
        req: EmergencyGrantDecideRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        return _decide_emergency_grant(
            grant_id, True, req, request, caller, idempotency_key
        )

    @app.post("/v1/admin/emergency-grants/{grant_id}/reject")
    async def reject_emergency_grant(
        grant_id: str,
        req: EmergencyGrantDecideRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        return _decide_emergency_grant(
            grant_id, False, req, request, caller, idempotency_key
        )

    @app.post("/v1/admin/emergency-grants/{grant_id}/revoke")
    async def revoke_emergency_grant(
        grant_id: str,
        req: EmergencyGrantRevokeRequest,
        request: Request,
        caller: Caller = Depends(authenticated),
        idempotency_key: Optional[str] = Header(
            default=None, alias="Idempotency-Key"
        ),
    ):
        # The grantee, the requester or an admin:manage holder covering the
        # grant's scopes may revoke; the store performs and audits the check.
        def produce():
            grant = comp.authz.revoke_grant(caller, grant_id, req.expected_version)
            return 200, {
                "grant": comp.authz.grant_view(grant),
                "authz_version": comp.authz.version,
            }

        return run_idempotent(
            idempotency_key, request, caller, req.model_dump(), produce
        )

    return app


def build_from_env() -> FastAPI:
    """Uvicorn application factory: ``uvicorn --factory app.main:build_from_env``."""
    comp = Components(
        db_path=os.environ.get("GEORESOLVE_DB_PATH", "/data/georesolve.db"),
        admin_token=os.environ.get("GEORESOLVE_ADMIN_TOKEN") or None,
        config_file=os.environ.get("GEORESOLVE_CONFIG_FILE") or None,
        config_poll_interval=float(os.environ.get("GEORESOLVE_CONFIG_POLL", "1.0")),
        health_interval=float(os.environ.get("GEORESOLVE_HEALTH_INTERVAL", "2.0")),
        health_timeout=float(os.environ.get("GEORESOLVE_HEALTH_TIMEOUT", "1.0")),
        enable_background=os.environ.get("GEORESOLVE_BACKGROUND", "1") != "0",
        preview_ttl=float(os.environ.get("GEORESOLVE_PREVIEW_TTL", "300")),
    )
    return create_app(comp)
