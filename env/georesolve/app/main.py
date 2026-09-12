"""HTTP API and application wiring.

Data plane (unauthenticated, like a DNS resolver):
  GET /v1/resolve   - resolve a name for a region/tenant
  GET /v1/explain   - show the rule version, targets and effective time
                      currently in force for a name/region/tenant
  GET /healthz      - liveness

Control plane (requires Bearer token when GEORESOLVE_ADMIN_TOKEN is set):
  GET  /v1/config          - current config snapshot
  POST /v1/config          - apply a new config bundle (monotonic version)
  GET  /v1/audit           - rule changes, cache invalidations, health changes
  GET  /v1/health/targets  - current target health view
  GET  /v1/cache           - cache contents (debug)
  POST /v1/cache/flush     - drop all cached answers (audited)
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request

from . import __version__
from .audit import AuditLog
from .cache import ResolutionCache
from .config_store import ConfigManager, VersionConflict
from .health import HealthChecker, HealthRegistry
from .models import ConfigBundle
from .resolver import Resolver
from .storage import connect


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

        self.audit = AuditLog(connect(db_path))
        self.config = ConfigManager(connect(db_path), self.audit)
        self.cache = ResolutionCache(time.time)
        self.health = HealthRegistry()
        self.resolver = Resolver(self.config, self.cache, self.health, self.audit)
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

    async def admin_guard(authorization: Optional[str] = Header(default=None)):
        if comp.admin_token and authorization != f"Bearer {comp.admin_token}":
            raise HTTPException(status_code=401, detail="invalid or missing admin token")

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
    ):
        client_key = client or (request.client.host if request.client else "")
        return comp.resolver.resolve(name, region, tenant, client_key)

    @app.get("/v1/explain")
    async def explain(
        request: Request,
        name: str,
        region: str = "",
        tenant: str = "",
        client: Optional[str] = None,
    ):
        client_key = client or (request.client.host if request.client else "")
        return comp.resolver.explain(name, region, tenant, client_key)

    # -- control plane ---------------------------------------------------

    @app.get("/v1/config", dependencies=[Depends(admin_guard)])
    async def get_config():
        snap = comp.config.snapshot()
        return {
            "version": snap.version,
            "defaults": snap.defaults.model_dump(),
            "rules": [
                r.model_dump()
                for r in sorted(snap.all_rules(), key=lambda r: (r.key(), r.rule_version))
            ],
        }

    @app.post("/v1/config", dependencies=[Depends(admin_guard)])
    async def post_config(bundle: ConfigBundle):
        try:
            result = comp.config.apply(bundle, source="api")
        except VersionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return {"applied": True, **result}

    @app.get("/v1/audit", dependencies=[Depends(admin_guard)])
    async def get_audit(
        type: Optional[str] = Query(default=None),
        limit: int = Query(default=200, ge=1, le=1000),
        since: Optional[float] = None,
    ):
        return {"records": comp.audit.query(type_=type, limit=limit, since=since)}

    @app.get("/v1/health/targets", dependencies=[Depends(admin_guard)])
    async def get_health():
        return {"targets": comp.health.snapshot()}

    @app.get("/v1/cache", dependencies=[Depends(admin_guard)])
    async def get_cache():
        return {
            "entries": [
                {
                    "name": e.name,
                    "region": e.region,
                    "tenant": e.tenant,
                    "kind": e.kind,
                    "rule_version": e.rule_version,
                    "expires_at": e.expires_at,
                    "config_version": e.config_version,
                }
                for e in comp.cache.items()
            ]
        }

    @app.post("/v1/cache/flush", dependencies=[Depends(admin_guard)])
    async def flush_cache():
        n = comp.cache.clear()
        comp.audit.record(
            "cache_invalidation",
            {"reason": "manual_flush", "entries": n,
             "config_version": comp.config.snapshot().version},
        )
        return {"flushed": n}

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
    )
    return create_app(comp)
