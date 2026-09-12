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
  GET  /v1/health/targets      - target health view, filtered by health:read
  POST /v1/health/targets/{id} - manual health override (health:write; audited)
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
"""
from __future__ import annotations

import asyncio
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
from .health import HealthChecker, HealthRegistry
from .metering import (
    BudgetExceeded,
    BudgetSpec,
    MeteringConflict,
    MeteringNotFound,
    MeteringStore,
    MeteringValidationError,
    PERIOD_TYPES,
)
from .models import ConfigBundle
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
        self.health = HealthRegistry()
        self.rate_limiter = RateLimiter(self.audit, time.time)
        self.metering = MeteringStore(db, self.audit, time.time)
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
            self.health,
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
        self._tasks.append(asyncio.create_task(self.checker.run(self._stop)))
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

    @app.post("/v1/health/targets/{target_id}")
    async def override_health(
        target_id: str,
        req: HealthOverrideRequest,
        caller: Caller = Depends(authenticated),
    ):
        # The override is allowed only when every rule/group referencing the
        # target is inside the caller's scope; otherwise the write would
        # leak side effects into someone else's configuration.
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
        comp.authz.authorize(
            caller, "health:write", [item_scope(i) for i in refs]
        )
        old = comp.health.is_healthy(target_id)
        comp.health.set(target_id, req.healthy)
        comp.audit.record(
            "health_change",
            {
                "target_id": target_id,
                "old": old,
                "new": req.healthy,
                "source": "admin",
                "identity": caller.identity_id,
            },
        )
        return {"target_id": target_id, "healthy": req.healthy}

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
        tenant: str, caller: Caller = Depends(authenticated)
    ):
        comp.authz.authorize(
            caller, "budget:read", [tenant_scope(tenant)]
        )
        status = comp.metering.budget_status(tenant)
        if status is None:
            raise HTTPException(
                status_code=404,
                detail=f"no budget configured for tenant {tenant!r}",
            )
        return status

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
