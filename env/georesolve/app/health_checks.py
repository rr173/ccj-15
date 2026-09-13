"""Target health-check orchestration.

Administrators configure, per resolution target, an independent check
policy: several probe methods, check interval, timeout, consecutive
failure/recovery thresholds, maintenance windows and a checker priority.
Every probe is recorded with its start time, per-method response summary,
verdict and the governing **policy version**; changing a policy appends a
new immutable revision and never rewrites recorded history.

Per-target state machine
------------------------
Each target has its own persisted state row. The *observed* verdict only
flips after ``fail_threshold`` consecutive failures (healthy -> unhealthy)
or ``recover_threshold`` consecutive successes (unhealthy -> healthy);
unfinished counters survive restarts. The *effective* health used by
resolution has an explicit, auditable source:

  manual_override > paused > maintenance > check > unmanaged

- ``manual_override``: an administrator forced the state, optionally with an
  expiry; probes continue but cannot change the effective answer until the
  override is revoked or expires (then the current check verdict applies).
- ``paused``: checking is suspended; the last effective answer is frozen.
- ``maintenance``: inside a configured maintenance window checking is
  suspended and the target is held out of selection (effective unhealthy).
- ``check``: the thresholded observed verdict.
- ``unmanaged``: no policy exists; unknown targets fail open (healthy).

Concurrency
-----------
Policy writes and override/pause transitions carry a monotonic version and
accept ``expected_version`` (stale versions get 409 and can never overwrite
newer state). API mutations additionally persist Idempotency-Key responses.
All state changes serialize on the store lock and are committed to SQLite,
so status, counters, window/override timing and the fixed history order
survive restarts.

Drill isolation
---------------
This module exposes the small surface the production resolver needs
(``is_healthy`` / ``snapshot``) but it never touches drill state: fault
drills build their own private health registry, and simulated drill
failures are never written to ``health_check_history``; conversely live
checks run against live targets only and cannot alter a drill's frozen
replay (drills do not read this store while replaying either).
"""
from __future__ import annotations

import asyncio
import json
import re
import ssl
import threading
import time
from typing import Callable, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .audit import AuditLog
from .config_store import ConfigManager

# -- effective status sources ------------------------------------------------

SRC_CHECK = "check"
SRC_OVERRIDE = "manual_override"
SRC_MAINTENANCE = "maintenance"
SRC_PAUSED = "paused"
SRC_UNMANAGED = "unmanaged"

# -- verdicts and failure reasons --------------------------------------------

VERDICT_SUCCESS = "success"
VERDICT_FAILURE = "failure"

REASON_TIMEOUT = "timeout"
REASON_FORMAT = "response_format_error"
REASON_BAD_STATUS = "bad_status"
REASON_CONTENT = "content_mismatch"
REASON_CONNECTION = "connection_error"
REASON_PROBE_ERROR = "probe_error"

# -- transition reasons -------------------------------------------------------

TR_FAIL_THRESHOLD = "check_fail_threshold"
TR_RECOVER_THRESHOLD = "check_recover_threshold"
TR_OVERRIDE_SET = "manual_override"
TR_OVERRIDE_REVOKED = "manual_override_revoked"
TR_OVERRIDE_EXPIRED = "manual_override_expired"
TR_PAUSED = "paused"
TR_RESUMED = "resumed"
TR_MAINTENANCE_BEGIN = "maintenance_begin"
TR_MAINTENANCE_END = "maintenance_end"
TR_POLICY_DELETED = "policy_deleted"

KIND_CHECK = "check"
KIND_TRANSITION = "transition"

HTTP_SCHEMES = ("http", "https")
MAX_SUMMARY_DETAIL = 300


# -- errors -------------------------------------------------------------------


class HealthCheckError(Exception):
    code = "health_check_error"
    status_code = 409


class HealthCheckNotFound(HealthCheckError):
    code = "target_not_found"
    status_code = 404


class HealthCheckConflict(HealthCheckError):
    code = "health_check_conflict"
    status_code = 409


class HealthCheckValidation(HealthCheckError):
    code = "invalid_health_policy"
    status_code = 422


# -- request models -----------------------------------------------------------


class CheckMethodSpec(BaseModel):
    """One probe method. Several methods are AND-combined per check round."""

    model_config = ConfigDict(extra="forbid")

    type: str = Field(description="tcp | http | https")
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    path: Optional[str] = Field(default=None, description="HTTP request path")
    timeout_seconds: Optional[float] = Field(default=None, gt=0, allow_inf_nan=False)
    expect_status: Optional[list[int]] = Field(
        default=None,
        description="accepted HTTP status codes; default 2xx/3xx",
    )
    expect_json: bool = Field(
        default=False, description="body must parse as JSON"
    )
    expect_field: Optional[dict] = Field(
        default=None,
        description='{"path": "a.b", "equals": <value>} checked against JSON',
    )
    content_regex: Optional[str] = Field(
        default=None, description="regex searched in the HTTP body"
    )

    @field_validator("type")
    @classmethod
    def _known_type(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in ("tcp", "http", "https"):
            raise ValueError("check type must be tcp, http or https")
        return v

    @field_validator("path")
    @classmethod
    def _path(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not v.startswith("/"):
            raise ValueError("HTTP path must start with '/'")
        return v

    @field_validator("expect_status")
    @classmethod
    def _status(cls, v: Optional[list[int]]) -> Optional[list[int]]:
        if v is not None:
            if not v or any(not (100 <= s <= 599) for s in v):
                raise ValueError("expect_status must contain HTTP status codes")
        return v

    @field_validator("content_regex")
    @classmethod
    def _regex(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            try:
                re.compile(v)
            except re.error as exc:
                raise ValueError(f"invalid content_regex: {exc}") from exc
        return v

    @model_validator(mode="after")
    def _check_method(self) -> "CheckMethodSpec":
        if self.expect_field is not None:
            path = self.expect_field.get("path")
            if not isinstance(path, str) or not path:
                raise ValueError("expect_field requires a non-empty 'path'")
            if "equals" not in self.expect_field:
                raise ValueError("expect_field requires an 'equals' value")
            self.expect_json = True
        if self.type == "tcp" and (
            self.path is not None
            or self.expect_status is not None
            or self.expect_json
            or self.content_regex is not None
        ):
            raise ValueError("TCP probes only support port/timeout settings")
        return self


class MaintenanceWindowSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start: float = Field(allow_inf_nan=False)
    end: float = Field(allow_inf_nan=False)
    note: str = ""

    @model_validator(mode="after")
    def _check_window(self) -> "MaintenanceWindowSpec":
        if self.end <= self.start:
            raise ValueError("maintenance window end must be greater than start")
        return self


class PolicyUpsertIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    checks: Optional[list[CheckMethodSpec]] = None  # default derived from address
    interval_seconds: float = Field(default=2.0, gt=0, allow_inf_nan=False)
    timeout_seconds: float = Field(default=1.0, gt=0, allow_inf_nan=False)
    fail_threshold: int = Field(default=2, ge=1)
    recover_threshold: int = Field(default=1, ge=1)
    maintenance_windows: list[MaintenanceWindowSpec] = Field(default_factory=list)
    priority: int = Field(default=100, ge=0)
    enabled: bool = True
    expected_version: Optional[int] = Field(default=None, ge=0)


class OverrideIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    healthy: bool
    reason: str = ""
    expires_at: Optional[float] = Field(
        default=None,
        allow_inf_nan=False,
        description="epoch seconds; null/omitted means the override stays "
        "until explicitly revoked",
    )
    expected_version: Optional[int] = Field(default=None, ge=0)


class OverrideRevokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: Optional[int] = Field(default=None, ge=0)


class PauseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = ""
    expected_version: Optional[int] = Field(default=None, ge=0)


class ResumeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: Optional[int] = Field(default=None, ge=0)


# -- helpers ------------------------------------------------------------------


def _norm_id(v: str) -> str:
    return (v or "").strip()


def _json_default(obj):
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    return str(obj)


def default_methods_for_address(address: str) -> list[CheckMethodSpec]:
    """Derive the single default probe from a target address."""
    parsed = urlparse(address if "://" in address else f"tcp://{address}")
    if parsed.scheme in HTTP_SCHEMES:
        return [CheckMethodSpec(type=parsed.scheme, path=(parsed.path or "/"))]
    return [CheckMethodSpec(type="tcp")]


def address_endpoint(address: str) -> tuple[str, int, str, str]:
    """Split a target address into (host, port, scheme, path)."""
    parsed = urlparse(address if "://" in address else f"tcp://{address}")
    scheme = parsed.scheme or "tcp"
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    return host, port, scheme, parsed.path or "/"


# -- probing ------------------------------------------------------------------


async def run_probe(
    method: CheckMethodSpec,
    address: str,
    timeout: float,
) -> dict:
    """Execute one probe method; always returns a compact result dict."""
    effective_timeout = method.timeout_seconds or timeout
    host, default_port, scheme, address_path = address_endpoint(address)
    port = method.port or default_port
    started = time.perf_counter()
    if not host:
        return _probe_result(method, False, REASON_PROBE_ERROR,
                             detail=f"unparseable address {address!r}",
                             started=started)
    try:
        if method.type in HTTP_SCHEMES:
            # An explicit method path wins; otherwise the target address's
            # own path (e.g. http://host/healthz) is used.
            return await _probe_http(
                method, host, port, effective_timeout, started,
                method.path or address_path,
            )
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), effective_timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - the probe itself succeeded
            pass
        return _probe_result(method, True, None, started=started)
    except asyncio.TimeoutError:
        return _probe_result(method, False, REASON_TIMEOUT,
                             detail=f"timed out after {effective_timeout}s",
                             started=started)
    except Exception as exc:  # noqa: BLE001 - any failure means a failed probe
        return _probe_result(method, False, REASON_CONNECTION,
                             detail=f"{type(exc).__name__}: {exc}",
                             started=started)


def _probe_result(
    method: CheckMethodSpec,
    ok: bool,
    reason: Optional[str],
    *,
    started: float,
    status: Optional[int] = None,
    detail: str = "",
) -> dict:
    return {
        "type": method.type,
        "ok": ok,
        "reason": reason,
        "status": status,
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "detail": detail[:MAX_SUMMARY_DETAIL],
    }


async def _probe_http(
    method: CheckMethodSpec,
    host: str,
    port: int,
    timeout: float,
    started: float,
    path: str,
) -> dict:
    ssl_ctx = ssl.create_default_context() if method.type == "https" else None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx), timeout
        )
    except asyncio.TimeoutError:
        return _probe_result(method, False, REASON_TIMEOUT,
                             detail=f"connect timed out after {timeout}s",
                             started=started)
    except Exception as exc:  # noqa: BLE001
        return _probe_result(method, False, REASON_CONNECTION,
                             detail=f"{type(exc).__name__}: {exc}",
                             started=started)
    try:
        writer.write(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        )
        await asyncio.wait_for(writer.drain(), timeout)
        line = await asyncio.wait_for(reader.readline(), timeout)
        if not line:
            return _probe_result(method, False, REASON_FORMAT,
                                 detail="empty status line", started=started)
        try:
            status = int(line.split()[1])
        except (IndexError, ValueError):
            return _probe_result(method, False, REASON_FORMAT,
                                 detail=f"malformed status line {line!r}",
                                 started=started)
        # Read header lines, then the remainder is the body (Connection:
        # close -> the server signals end of body by closing).
        while True:
            header_line = await asyncio.wait_for(reader.readline(), timeout)
            if not header_line or header_line in (b"\r\n", b"\n"):
                break
        body_bytes = await asyncio.wait_for(reader.read(), timeout)
    except asyncio.TimeoutError:
        return _probe_result(method, False, REASON_TIMEOUT,
                             detail=f"timed out after {timeout}s",
                             started=started)
    except Exception as exc:  # noqa: BLE001
        return _probe_result(method, False, REASON_CONNECTION,
                             detail=f"{type(exc).__name__}: {exc}",
                             started=started)
    finally:
        writer.close()

    accepted = [int(s) for s in (method.expect_status or range(200, 400))]
    if status not in accepted:
        return _probe_result(method, False, REASON_BAD_STATUS, started=started,
                             status=status, detail=f"http status {status}")

    body = _decode_body(body_bytes)
    if method.expect_json or method.expect_field is not None:
        try:
            parsed = json.loads(body)
        except ValueError as exc:
            return _probe_result(
                method, False, REASON_FORMAT, started=started, status=status,
                detail=f"body is not valid JSON: {exc}",
            )
        if method.expect_field is not None:
            actual = _dig(parsed, str(method.expect_field["path"]))
            expected = method.expect_field["equals"]
            if actual != expected:
                return _probe_result(
                    method, False, REASON_FORMAT, started=started, status=status,
                    detail=(
                        f"JSON field {method.expect_field['path']!r}:"
                        f" expected {expected!r}, got {actual!r}"
                    ),
                )
    if method.content_regex is not None:
        if not re.search(method.content_regex, body, flags=re.DOTALL):
            return _probe_result(
                method, False, REASON_CONTENT, started=started, status=status,
                detail=f"body does not match {method.content_regex!r}",
            )
    return _probe_result(method, True, None, started=started, status=status)


def _decode_body(raw: bytes) -> str:
    if b"\r\n\r\n" in raw:
        raw = raw.split(b"\r\n\r\n", 1)[1]
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def _dig(value, dotted_path: str):
    cur = value
    for part in dotted_path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


# -- the orchestrating store --------------------------------------------------


class HealthCheckStore:
    """SQLite-backed per-target policy + state machine and check history."""

    def __init__(
        self,
        conn,
        config: ConfigManager,
        audit: AuditLog,
        clock: Callable[[], float] = time.time,
        view_ttl: float = 0.25,
        on_history_commit: Optional[Callable[[], None]] = None,
    ):
        self._conn = conn
        self._config = config
        self._audit = audit
        self._clock = clock
        self._lock = threading.RLock()
        # Optional callback fired after every commit that may have appended
        # check/transition history (used by the health-alert ingestor to
        # wake immediately instead of waiting for its polling tick).
        self._on_history_commit = on_history_commit
        # Short-lived materialized view so the per-resolution is_healthy()
        # hot path stays in memory (the resolver calls it for every target).
        self._view_ttl = view_ttl
        self._view_cache: Optional[dict] = None
        self._view_at: float = -1.0

    def set_history_commit_listener(
        self, callback: Optional[Callable[[], None]]
    ) -> None:
        self._on_history_commit = callback

    def _notify_history_commit(self) -> None:
        cb = self._on_history_commit
        if cb is not None:
            try:
                cb()
            except Exception:  # noqa: BLE001 - alerting must never break checks
                pass

    def _invalidate_view(self) -> None:
        self._view_cache = None

    # -- target/config helpers ----------------------------------------------

    def _target_address(self, target_id: str) -> str:
        snap = self._config.snapshot()
        for item in (*snap.all_rules(), *snap.all_release_groups()):
            for t in item.targets:
                if t.id == target_id:
                    return t.address
        raise HealthCheckNotFound(
            f"target {target_id!r} is not referenced by any current rule "
            "or release group"
        )

    def target_references(self, target_id: str) -> list:
        snap = self._config.snapshot()
        return [
            item
            for item in (*snap.all_rules(), *snap.all_release_groups())
            if any(t.id == target_id for t in item.targets)
        ]

    # -- (de)serialization ---------------------------------------------------

    def _row_to_policy(self, row) -> dict:
        return {
            "target_id": row["target_id"],
            "policy_version": row["policy_version"],
            "checks": json.loads(row["checks"]),
            "interval_seconds": row["interval_seconds"],
            "timeout_seconds": row["timeout_seconds"],
            "fail_threshold": row["fail_threshold"],
            "recover_threshold": row["recover_threshold"],
            "maintenance_windows": json.loads(row["maintenance_windows"]),
            "priority": row["priority"],
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "created_by": row["created_by"],
            "updated_by": row["updated_by"],
        }

    def _state_row(self, target_id: str):
        return self._conn.execute(
            "SELECT * FROM health_target_states WHERE target_id = ?",
            (target_id,),
        ).fetchone()

    def _load_state(self, target_id: str) -> Optional[dict]:
        row = self._state_row(target_id)
        if row is None:
            return None
        return self._state_to_dict(row)

    @staticmethod
    def _state_to_dict(row) -> dict:
        return {
            "target_id": row["target_id"],
            "observed_healthy": bool(row["observed_healthy"]),
            "consecutive_failures": row["consecutive_failures"],
            "consecutive_successes": row["consecutive_successes"],
            "effective_source": row["effective_source"],
            "effective_healthy": bool(row["effective_healthy"]),
            "paused": bool(row["paused"]),
            "paused_at": row["paused_at"],
            "paused_reason": row["paused_reason"],
            "override_healthy": (
                None if row["override_healthy"] is None
                else bool(row["override_healthy"])
            ),
            "override_reason": row["override_reason"],
            "override_by": row["override_by"],
            "override_at": row["override_at"],
            "override_expires_at": row["override_expires_at"],
            "policy_version": row["policy_version"],
            "last_check_seq": row["last_check_seq"],
            "last_checked_at": row["last_checked_at"],
            "next_check_at": row["next_check_at"],
            "state_version": row["state_version"],
            "in_maintenance": bool(row["in_maintenance"]),
            "updated_at": row["updated_at"],
        }

    def _policy_row(self, target_id: str):
        return self._conn.execute(
            "SELECT * FROM health_policies WHERE target_id = ?", (target_id,)
        ).fetchone()

    def _load_policy(self, target_id: str) -> dict:
        row = self._policy_row(target_id)
        if row is None:
            raise HealthCheckNotFound(
                f"no health check policy for target {target_id!r}"
            )
        return self._row_to_policy(row)

    def _next_seq(self, target_id: str) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq"
            " FROM health_check_history WHERE target_id = ?",
            (target_id,),
        ).fetchone()
        return int(row["next_seq"])

    def _append_history(
        self,
        target_id: str,
        kind: str,
        *,
        policy_version: int,
        ts: float,
        started_at: Optional[float] = None,
        verdict: Optional[str] = None,
        failure_reason: Optional[str] = None,
        response_summary: Optional[str] = None,
        duration_ms: Optional[float] = None,
        effective_healthy: Optional[bool] = None,
        effective_source: Optional[str] = None,
        transition_reason: Optional[str] = None,
        from_effective: Optional[tuple] = None,
        to_effective: Optional[tuple] = None,
        state_version: Optional[int] = None,
        actor: Optional[str] = None,
        detail: Optional[dict] = None,
    ) -> int:
        """Append one immutable history row; returns the per-target seq."""
        seq = self._next_seq(target_id)
        from_healthy = from_source = from_pv = None
        to_healthy = to_source = to_pv = None
        if from_effective is not None:
            from_healthy, from_source, from_pv = from_effective
        if to_effective is not None:
            to_healthy, to_source, to_pv = to_effective
        self._conn.execute(
            "INSERT INTO health_check_history"
            " (target_id, seq, kind, ts, started_at, policy_version,"
            "  state_version, verdict, failure_reason, response_summary,"
            "  duration_ms, effective_healthy, effective_source,"
            "  transition_reason, from_healthy, to_healthy, from_source,"
            "  to_source, from_policy_version, to_policy_version, actor, detail)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                target_id, seq, kind, ts, started_at, policy_version,
                state_version,
                verdict, failure_reason, response_summary, duration_ms,
                None if effective_healthy is None else int(effective_healthy),
                effective_source, transition_reason,
                None if from_healthy is None else int(from_healthy),
                None if to_healthy is None else int(to_healthy),
                from_source, to_source, from_pv, to_pv, actor,
                json.dumps(detail or {}, sort_keys=True),
            ),
        )
        return seq

    # -- effective status computation ---------------------------------------

    def _active_window(self, windows: list[dict], now: float):
        for w in windows:
            if w["start"] <= now < w["end"]:
                return w
        return None

    @staticmethod
    def _next_window(windows: list[dict], now: float):
        future = [w for w in windows if w["start"] > now]
        return min(future, key=lambda w: w["start"], default=None)

    def _reconcile_locked(
        self,
        target_id: str,
        *,
        actor: Optional[str] = None,
        at: Optional[float] = None,
    ) -> Optional[dict]:
        """Apply lazy expiry/window transitions; return the current state.

        Handles (in order, each appending an immutable transition row and
        bumping state_version): expired manual override, entering a
        maintenance window, leaving maintenance. The check verdict and
        pause/override/admin transitions are applied by their callers.
        ``at`` overrides the clock (used by the scheduler's due scan).
        """
        row = self._state_row(target_id)
        if row is None:
            return None
        st = self._state_to_dict(row)
        at_time = self._clock() if at is None else at
        wall = self._clock()

        policy = self._policy_row(target_id)
        policy_dict = self._row_to_policy(policy) if policy is not None else None
        windows = policy_dict["maintenance_windows"] if policy_dict else []

        changed = False

        # 1. Lazy manual-override expiry (real clock only).
        if (
            at is None
            and st["override_healthy"] is not None
            and st["override_expires_at"] is not None
            and st["override_expires_at"] <= at_time
        ):
            old = (st["effective_healthy"], st["effective_source"], st["policy_version"])
            self._conn.execute(
                "UPDATE health_target_states SET override_healthy = NULL,"
                " override_reason = NULL, override_by = NULL, override_at = NULL,"
                " override_expires_at = NULL, state_version = state_version + 1,"
                " updated_at = ? WHERE target_id = ?",
                (wall, target_id),
            )
            st = self._state_to_dict(self._state_row(target_id))
            new_effective = self._compute_effective(st, windows, wall)
            self._apply_effective(target_id, st, new_effective, wall)
            st = self._state_to_dict(self._state_row(target_id))
            self._append_history(
                target_id, KIND_TRANSITION, policy_version=st["policy_version"],
                ts=wall, transition_reason=TR_OVERRIDE_EXPIRED,
                from_effective=old,
                to_effective=(st["effective_healthy"], st["effective_source"],
                              st["policy_version"]),
                state_version=st["state_version"], actor=actor,
                detail={"override_expires_at": row["override_expires_at"]},
            )
            changed = True

        # 2. Maintenance window entry/exit. Real transitions are only applied
        # under the real clock (at is None); a scheduler scan with a future
        # ``at`` uses the windows purely for due-filtering below.
        active = self._active_window(windows, at_time)
        upcoming = self._next_window(windows, at_time)
        if (
            at is None
            and active is not None
            and not st["in_maintenance"]
            and not st["paused"]
        ):
            old = (st["effective_healthy"], st["effective_source"], st["policy_version"])
            self._conn.execute(
                "UPDATE health_target_states SET in_maintenance = 1,"
                " next_check_at = ?, state_version = state_version + 1,"
                " updated_at = ? WHERE target_id = ?",
                (active["end"], wall, target_id),
            )
            st = self._state_to_dict(self._state_row(target_id))
            self._apply_effective(
                target_id, st, (False, SRC_MAINTENANCE), wall
            )
            st = self._state_to_dict(self._state_row(target_id))
            self._append_history(
                target_id, KIND_TRANSITION, policy_version=st["policy_version"],
                ts=wall, transition_reason=TR_MAINTENANCE_BEGIN,
                from_effective=old,
                to_effective=(st["effective_healthy"], st["effective_source"],
                              st["policy_version"]),
                state_version=st["state_version"], actor=actor,
                detail={"window": active, "at": at_time},
            )
            changed = True
        elif at is None and active is None and st["in_maintenance"]:
            old = (st["effective_healthy"], st["effective_source"], st["policy_version"])
            # Leaving a window: checking resumes immediately rather than
            # waiting out a next_check_at scheduled before the window began.
            self._conn.execute(
                "UPDATE health_target_states SET in_maintenance = 0,"
                " next_check_at = ?, state_version = state_version + 1,"
                " updated_at = ? WHERE target_id = ?",
                (wall, wall, target_id),
            )
            st = self._state_to_dict(self._state_row(target_id))
            new_effective = self._compute_effective(st, windows, wall)
            self._apply_effective(target_id, st, new_effective, wall)
            st = self._state_to_dict(self._state_row(target_id))
            self._append_history(
                target_id, KIND_TRANSITION, policy_version=st["policy_version"],
                ts=wall, transition_reason=TR_MAINTENANCE_END,
                from_effective=old,
                to_effective=(st["effective_healthy"], st["effective_source"],
                              st["policy_version"]),
                state_version=st["state_version"], actor=actor,
                detail={"at": at_time},
            )
            changed = True
        elif (
            active is None
            and not st["in_maintenance"]
            and not st["paused"]
            and upcoming is not None
            and st["next_check_at"] > upcoming["start"]
        ):
            # Park the next probe at the window start so entry is detected on
            # time even with a long check interval (no history event).
            self._conn.execute(
                "UPDATE health_target_states SET next_check_at = ?,"
                " updated_at = ? WHERE target_id = ?",
                (upcoming["start"], wall, target_id),
            )
            self._conn.commit()
            self._invalidate_view()
            return self._state_to_dict(self._state_row(target_id))

        # Virtual window state for scheduler scans with an explicit future
        # ``at``: the window affects due-filtering now but no row is written
        # until real time catches up.
        if (
            at is not None
            and active is not None
            and not st["in_maintenance"]
            and not st["paused"]
        ):
            st["in_maintenance"] = True
            st["effective_source"] = SRC_MAINTENANCE
            st["effective_healthy"] = False
            return st

        if changed:
            self._conn.commit()
            self._invalidate_view()
            self._audit_transition(target_id)
            self._notify_history_commit()
        return self._state_to_dict(self._state_row(target_id))

    @staticmethod
    def _compute_effective(
        st: dict, windows: list[dict], now: float
    ) -> tuple[bool, str]:
        """Pure precedence function for the effective status."""
        if st["override_healthy"] is not None:
            return st["override_healthy"], SRC_OVERRIDE
        if st["paused"]:
            # Freeze the answer observed at pause time.
            return st["effective_healthy"], SRC_PAUSED
        in_window = any(w["start"] <= now < w["end"] for w in windows)
        if in_window:
            return False, SRC_MAINTENANCE
        if st["policy_version"] > 0:
            return st["observed_healthy"], SRC_CHECK
        return True, SRC_UNMANAGED

    def _apply_effective(
        self,
        target_id: str,
        st: dict,
        effective: tuple[bool, str],
        now: float,
    ) -> bool:
        healthy, source = effective
        if st["effective_healthy"] == healthy and st["effective_source"] == source:
            return False
        self._conn.execute(
            "UPDATE health_target_states SET effective_healthy = ?,"
            " effective_source = ?, updated_at = ? WHERE target_id = ?",
            (int(healthy), source, now, target_id),
        )
        return True

    def _audit_transition(self, target_id: str) -> None:
        """Emit the legacy health_change audit for the latest transition."""
        row = self._conn.execute(
            "SELECT * FROM health_check_history WHERE target_id = ?"
            " AND kind = ? ORDER BY id DESC LIMIT 1",
            (target_id, KIND_TRANSITION),
        ).fetchone()
        if row is None:
            return
        self._audit.record(
            "health_change",
            {
                "target_id": target_id,
                "old": bool(row["from_healthy"])
                if row["from_healthy"] is not None else None,
                "new": bool(row["to_healthy"])
                if row["to_healthy"] is not None else None,
                "source": row["to_source"],
                "reason": row["transition_reason"],
                "state_version": row["state_version"],
                "policy_version": row["policy_version"],
                "actor": row["actor"],
            },
        )

    # -- policy CRUD ---------------------------------------------------------

    def upsert_policy(
        self,
        target_id: str,
        spec: PolicyUpsertIn,
        *,
        actor: Optional[str] = None,
    ) -> tuple[dict, bool]:
        target_id = _norm_id(target_id)
        if not target_id:
            raise HealthCheckValidation("target id must be non-empty")
        address = self._target_address(target_id)  # 404 when unknown
        methods = spec.checks or default_methods_for_address(address)
        windows = [w.model_dump() for w in spec.maintenance_windows]
        checks_json = [m.model_dump() for m in methods]
        now = self._clock()

        with self._lock:
            row = self._policy_row(target_id)
            created = row is None
            if row is not None and spec.expected_version is not None \
                    and spec.expected_version != row["policy_version"]:
                raise HealthCheckConflict(
                    f"expected_version {spec.expected_version} does not match "
                    f"current policy version {row['policy_version']}"
                )

            if created:
                version = 1
                self._conn.execute(
                    "INSERT INTO health_policies"
                    " (target_id, policy_version, checks, interval_seconds,"
                    "  timeout_seconds, fail_threshold, recover_threshold,"
                    "  maintenance_windows, priority, enabled, created_at,"
                    "  updated_at, created_by, updated_by)"
                    " VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        target_id, json.dumps(checks_json, sort_keys=True),
                        spec.interval_seconds, spec.timeout_seconds,
                        spec.fail_threshold, spec.recover_threshold,
                        json.dumps(windows, sort_keys=True), spec.priority,
                        int(spec.enabled), now, now, actor, actor,
                    ),
                )
                # A fresh state row: observed healthy (fail open), due now.
                state = self._state_row(target_id)
                if state is None:
                    self._conn.execute(
                        "INSERT INTO health_target_states"
                        " (target_id, observed_healthy, consecutive_failures,"
                        "  consecutive_successes, effective_source,"
                        "  effective_healthy, paused, policy_version,"
                        "  last_check_seq, next_check_at, state_version,"
                        "  created_at, updated_at, in_maintenance)"
                        " VALUES (?, 1, 0, 0, ?, 1, 0, 1, 0, ?, 1, ?, ?, 0)",
                        (
                            target_id,
                            SRC_CHECK if spec.enabled else SRC_PAUSED,
                            now, now, now,
                        ),
                    )
                else:
                    # A state row can already exist from a legacy override.
                    self._conn.execute(
                        "UPDATE health_target_states SET policy_version = 1,"
                        " effective_source = ?, effective_healthy ="
                        " observed_healthy, override_healthy = NULL,"
                        " override_reason = NULL, override_by = NULL,"
                        " override_at = NULL, override_expires_at = NULL,"
                        " paused = 0, paused_at = NULL, paused_reason = NULL,"
                        " in_maintenance = 0, next_check_at = ?,"
                        " state_version = state_version + 1, updated_at = ?"
                        " WHERE target_id = ?",
                        (SRC_CHECK, now, now, target_id),
                    )
                self._append_revision(
                    target_id, version, "created", checks_json, spec, windows,
                    actor, now,
                )
                self._audit_policy("health_policy_created", target_id, version,
                                   actor, now)
                self._append_history(
                    target_id, KIND_TRANSITION, policy_version=1, ts=now,
                    transition_reason="policy_created",
                    from_effective=(True, SRC_UNMANAGED, 0),
                    to_effective=(True, SRC_CHECK, 1),
                    actor=actor,
                )
            else:
                old = self._row_to_policy(row)
                if spec.expected_version is None and self._same_policy(
                    old, spec, checks_json, windows
                ):
                    # Idempotent no-op PUT: nothing is versioned or audited.
                    return old, False
                version = row["policy_version"] + 1
                self._conn.execute(
                    "UPDATE health_policies SET policy_version = ?, checks = ?,"
                    " interval_seconds = ?, timeout_seconds = ?,"
                    " fail_threshold = ?, recover_threshold = ?,"
                    " maintenance_windows = ?, priority = ?, enabled = ?,"
                    " updated_at = ?, updated_by = ? WHERE target_id = ?",
                    (
                        version, json.dumps(checks_json, sort_keys=True),
                        spec.interval_seconds, spec.timeout_seconds,
                        spec.fail_threshold, spec.recover_threshold,
                        json.dumps(windows, sort_keys=True), spec.priority,
                        int(spec.enabled), now, actor, target_id,
                    ),
                )
                # A policy change restarts the threshold ladder (the old
                # counters were produced by the previous policy version);
                # history rows of either version stay untouched.
                self._conn.execute(
                    "UPDATE health_target_states SET policy_version = ?,"
                    " consecutive_failures = 0, consecutive_successes = 0,"
                    " next_check_at = ?, updated_at = ?"
                    " WHERE target_id = ?",
                    (version, now, now, target_id),
                )
                self._append_revision(
                    target_id, version, "updated", checks_json, spec, windows,
                    actor, now,
                )
                self._audit_policy("health_policy_changed", target_id, version,
                                   actor, now, old_version=version - 1)

            self._conn.commit()
            self._invalidate_view()

            # Reconcile maintenance/pause effective state under the new policy
            # (e.g. a window that starts in the past), then reschedule.
            st = self._reconcile_locked(target_id, actor=actor)
            if st is not None and st["paused"]:
                pass
            policy = self._load_policy(target_id)
            self._notify_history_commit()
            return policy, created

    @staticmethod
    def _same_policy(
        old: dict,
        spec: PolicyUpsertIn,
        checks_json: list[dict],
        windows: list[dict],
    ) -> bool:
        return (
            old["checks"] == checks_json
            and old["interval_seconds"] == spec.interval_seconds
            and old["timeout_seconds"] == spec.timeout_seconds
            and old["fail_threshold"] == spec.fail_threshold
            and old["recover_threshold"] == spec.recover_threshold
            and old["maintenance_windows"] == windows
            and old["priority"] == spec.priority
            and old["enabled"] == spec.enabled
        )

    def _append_revision(
        self,
        target_id: str,
        version: int,
        action: str,
        checks_json: list[dict],
        spec: PolicyUpsertIn,
        windows: list[dict],
        actor: Optional[str],
        now: float,
    ) -> None:
        payload = {
            "target_id": target_id,
            "checks": checks_json,
            "interval_seconds": spec.interval_seconds,
            "timeout_seconds": spec.timeout_seconds,
            "fail_threshold": spec.fail_threshold,
            "recover_threshold": spec.recover_threshold,
            "maintenance_windows": windows,
            "priority": spec.priority,
            "enabled": spec.enabled,
        }
        self._conn.execute(
            "INSERT INTO health_policy_revisions"
            " (target_id, policy_version, action, payload, actor, ts)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                target_id, version, action,
                json.dumps(payload, sort_keys=True), actor, now,
            ),
        )

    def _audit_policy(
        self,
        audit_type: str,
        target_id: str,
        version: int,
        actor: Optional[str],
        now: float,
        old_version: Optional[int] = None,
    ) -> None:
        self._audit.record(
            "health_policy_change",
            {
                "target_id": target_id,
                "policy_version": version,
                "old_version": old_version,
                "identity": actor,
            },
            ts=now,
        )

    def delete_policy(
        self,
        target_id: str,
        *,
        expected_version: Optional[int] = None,
        actor: Optional[str] = None,
    ) -> None:
        target_id = _norm_id(target_id)
        with self._lock:
            row = self._policy_row(target_id)
            if row is None:
                raise HealthCheckNotFound(
                    f"no health check policy for target {target_id!r}"
                )
            if expected_version is not None \
                    and expected_version != row["policy_version"]:
                raise HealthCheckConflict(
                    f"expected_version {expected_version} does not match "
                    f"current policy version {row['policy_version']}"
                )
            version = row["policy_version"]
            now = self._clock()
            payload = self._row_to_policy(row)
            self._conn.execute(
                "DELETE FROM health_policies WHERE target_id = ?", (target_id,)
            )
            self._conn.execute(
                "INSERT INTO health_policy_revisions"
                " (target_id, policy_version, action, payload, actor, ts)"
                " VALUES (?, ?, 'deleted', ?, ?, ?)",
                (
                    target_id, version + 1,
                    json.dumps(payload, sort_keys=True), actor, now,
                ),
            )
            # The target goes back to the unmanaged fail-open default; any
            # override/pause/window disappears with the policy.
            state = self._state_row(target_id)
            old_eff = None
            if state is not None:
                st = self._state_to_dict(state)
                old_eff = (st["effective_healthy"], st["effective_source"],
                           st["policy_version"])
                self._conn.execute(
                    "UPDATE health_target_states SET observed_healthy = 1,"
                    " consecutive_failures = 0, consecutive_successes = 0,"
                    " effective_source = 'unmanaged', effective_healthy = 1,"
                    " paused = 0, paused_at = NULL, paused_reason = NULL,"
                    " override_healthy = NULL, override_reason = NULL,"
                    " override_by = NULL, override_at = NULL,"
                    " override_expires_at = NULL, in_maintenance = 0,"
                    " policy_version = 0, next_check_at = ?,"
                    " state_version = state_version + 1, updated_at = ?"
                    " WHERE target_id = ?",
                    (now, now, target_id),
                )
            self._append_history(
                target_id, KIND_TRANSITION, policy_version=version + 1, ts=now,
                transition_reason=TR_POLICY_DELETED,
                from_effective=old_eff,
                to_effective=(True, SRC_UNMANAGED, 0),
                actor=actor,
            )
            self._conn.commit()
            self._invalidate_view()
            self._audit.record(
                "health_policy_change",
                {
                    "target_id": target_id,
                    "policy_version": version + 1,
                    "action": "deleted",
                    "identity": actor,
                },
                ts=now,
            )
            if state is not None:
                self._audit_transition(target_id)
            self._notify_history_commit()

    # -- pause / resume / override ------------------------------------------

    def _require_policy_for_control(self, target_id: str):
        row = self._policy_row(target_id)
        if row is None:
            raise HealthCheckConflict(
                f"target {target_id!r} has no health check policy; create one "
                "before pause/resume/override"
            )
        return row

    def pause(
        self,
        target_id: str,
        *,
        reason: str = "",
        expected_version: Optional[int] = None,
        actor: Optional[str] = None,
    ) -> dict:
        target_id = _norm_id(target_id)
        with self._lock:
            row = self._require_policy_for_control(target_id)
            st = self._reconcile_locked(target_id, actor=actor)
            if expected_version is not None \
                    and expected_version != st["state_version"]:
                raise HealthCheckConflict(
                    f"expected_version {expected_version} does not match "
                    f"current state version {st['state_version']}"
                )
            if st["paused"]:
                return {"changed": False, "state": st}
            now = self._clock()
            old = (st["effective_healthy"], st["effective_source"],
                   st["policy_version"])
            self._conn.execute(
                "UPDATE health_target_states SET paused = 1, paused_at = ?,"
                " paused_reason = ?, state_version = state_version + 1,"
                " updated_at = ? WHERE target_id = ?",
                (now, reason, now, target_id),
            )
            st = self._state_to_dict(self._state_row(target_id))
            # Recompute effective status by precedence: an active override
            # keeps winning while paused; otherwise the answer is frozen
            # under the explicit 'paused' source.
            policy_row = self._policy_row(target_id)
            windows = (
                self._row_to_policy(policy_row)["maintenance_windows"]
                if policy_row is not None else []
            )
            effective = self._compute_effective(st, windows, now)
            self._apply_effective(target_id, st, effective, now)
            st = self._state_to_dict(self._state_row(target_id))
            self._append_history(
                target_id, KIND_TRANSITION, policy_version=st["policy_version"],
                ts=now, transition_reason=TR_PAUSED,
                from_effective=old,
                to_effective=(st["effective_healthy"], SRC_PAUSED,
                              st["policy_version"]),
                state_version=st["state_version"], actor=actor,
                detail={"reason": reason},
            )
            self._conn.commit()
            self._invalidate_view()
            self._audit.record(
                "health_change",
                {
                    "target_id": target_id, "source": SRC_PAUSED,
                    "reason": TR_PAUSED, "identity": actor,
                    "state_version": st["state_version"],
                },
                ts=now,
            )
            self._notify_history_commit()
            return {"changed": True, "state": st}

    def resume(
        self,
        target_id: str,
        *,
        expected_version: Optional[int] = None,
        actor: Optional[str] = None,
    ) -> dict:
        target_id = _norm_id(target_id)
        with self._lock:
            self._require_policy_for_control(target_id)
            st = self._reconcile_locked(target_id, actor=actor)
            if expected_version is not None \
                    and expected_version != st["state_version"]:
                raise HealthCheckConflict(
                    f"expected_version {expected_version} does not match "
                    f"current state version {st['state_version']}"
                )
            if not st["paused"]:
                return {"changed": False, "state": st}
            now = self._clock()
            old = (st["effective_healthy"], SRC_PAUSED, st["policy_version"])
            self._conn.execute(
                "UPDATE health_target_states SET paused = 0, paused_at = NULL,"
                " paused_reason = NULL, next_check_at = ?,"
                " state_version = state_version + 1, updated_at = ?"
                " WHERE target_id = ?",
                (now, now, target_id),
            )
            # Re-apply window/override precedence under the resumed state;
            # reconcile also emits maintenance_end if the window lapsed while
            # the target was paused. When a pause began inside a window the
            # in_maintenance flag is still set, so recompute the effective
            # answer explicitly (maintenance takes over from the frozen one).
            self._conn.commit()
            self._invalidate_view()
            st = self._reconcile_locked(target_id, actor=actor)
            st = self._state_to_dict(self._state_row(target_id))
            policy_row = self._policy_row(target_id)
            if policy_row is not None:
                policy = self._row_to_policy(policy_row)
                effective = self._compute_effective(
                    st, policy["maintenance_windows"], now
                )
                if self._apply_effective(target_id, st, effective, now):
                    self._conn.commit()
            self._invalidate_view()
            st = self._state_to_dict(self._state_row(target_id))
            self._append_history(
                target_id, KIND_TRANSITION, policy_version=st["policy_version"],
                ts=now, transition_reason=TR_RESUMED,
                from_effective=old,
                to_effective=(st["effective_healthy"], st["effective_source"],
                              st["policy_version"]),
                state_version=st["state_version"], actor=actor,
            )
            self._conn.commit()
            self._invalidate_view()
            self._audit_transition(target_id)
            self._notify_history_commit()
            return {"changed": True, "state": st}

    def override(
        self,
        target_id: str,
        req: OverrideIn,
        *,
        actor: Optional[str] = None,
    ) -> dict:
        target_id = _norm_id(target_id)
        now = self._clock()
        if req.expires_at is not None and req.expires_at <= now:
            raise HealthCheckConflict(
                "override expires_at is already in the past"
            )
        with self._lock:
            policy_row = self._policy_row(target_id)
            st = self._reconcile_locked(target_id, actor=actor)
            if st is None:
                # No policy and no prior state row: the legacy admin override
                # can still force a target; it persists as its own state.
                self._require_existing_target(target_id)
                self._conn.execute(
                    "INSERT INTO health_target_states"
                    " (target_id, observed_healthy, consecutive_failures,"
                    "  consecutive_successes, effective_source,"
                    "  effective_healthy, paused, policy_version,"
                    "  last_check_seq, next_check_at, state_version,"
                    "  created_at, updated_at, in_maintenance)"
                    " VALUES (?, 1, 0, 0, ?, ?, 0, 0, 0, ?, 1, ?, ?, 0)",
                    (target_id, SRC_OVERRIDE, int(req.healthy),
                     now + 365 * 86400, now, now),
                )
                st = self._state_to_dict(self._state_row(target_id))
                old = (True, SRC_UNMANAGED, 0)
            else:
                if policy_row is not None and req.expected_version is not None \
                        and req.expected_version != st["state_version"]:
                    raise HealthCheckConflict(
                        f"expected_version {req.expected_version} does not match "
                        f"current state version {st['state_version']}"
                    )
                # Repeated identical override: no-op replay of the same state.
                if (
                    st["override_healthy"] == req.healthy
                    and st["override_expires_at"] == req.expires_at
                    and (st["override_reason"] or "") == req.reason
                ):
                    return {"changed": False, "state": st}
                old = (st["effective_healthy"], st["effective_source"],
                       st["policy_version"])
            self._conn.execute(
                "UPDATE health_target_states SET override_healthy = ?,"
                " override_reason = ?, override_by = ?, override_at = ?,"
                " override_expires_at = ?, state_version = state_version + 1,"
                " updated_at = ? WHERE target_id = ?",
                (
                    int(req.healthy), req.reason, actor, now, req.expires_at,
                    now, target_id,
                ),
            )
            st = self._state_to_dict(self._state_row(target_id))
            self._apply_effective(
                target_id, st, (req.healthy, SRC_OVERRIDE), now
            )
            st = self._state_to_dict(self._state_row(target_id))
            self._append_history(
                target_id, KIND_TRANSITION,
                policy_version=max(st["policy_version"], 1), ts=now,
                transition_reason=TR_OVERRIDE_SET,
                from_effective=old,
                to_effective=(req.healthy, SRC_OVERRIDE, st["policy_version"]),
                state_version=st["state_version"], actor=actor,
                detail={
                    "reason": req.reason,
                    "expires_at": req.expires_at,
                },
            )
            self._conn.commit()
            self._invalidate_view()
            self._audit.record(
                "health_change",
                {
                    "target_id": target_id,
                    "old": old[0], "new": req.healthy,
                    "source": SRC_OVERRIDE, "reason": TR_OVERRIDE_SET,
                    "identity": actor,
                    "state_version": st["state_version"],
                    "expires_at": req.expires_at,
                },
                ts=now,
            )
            self._notify_history_commit()
            return {"changed": True, "state": st}

    def _require_existing_target(self, target_id: str) -> None:
        self._target_address(target_id)

    def revoke_override(
        self,
        target_id: str,
        *,
        expected_version: Optional[int] = None,
        actor: Optional[str] = None,
    ) -> dict:
        target_id = _norm_id(target_id)
        with self._lock:
            st = self._reconcile_locked(target_id, actor=actor)
            if st is None or st["override_healthy"] is None:
                raise HealthCheckConflict(
                    f"target {target_id!r} has no active manual override"
                )
            if expected_version is not None \
                    and expected_version != st["state_version"]:
                raise HealthCheckConflict(
                    f"expected_version {expected_version} does not match "
                    f"current state version {st['state_version']}"
                )
            now = self._clock()
            old = (st["effective_healthy"], SRC_OVERRIDE, st["policy_version"])
            self._conn.execute(
                "UPDATE health_target_states SET override_healthy = NULL,"
                " override_reason = NULL, override_by = NULL, override_at = NULL,"
                " override_expires_at = NULL, state_version = state_version + 1,"
                " updated_at = ? WHERE target_id = ?",
                (now, target_id),
            )
            st = self._state_to_dict(self._state_row(target_id))
            policy_row = self._policy_row(target_id)
            if policy_row is not None:
                policy = self._row_to_policy(policy_row)
                effective = self._compute_effective(
                    st, policy["maintenance_windows"], now
                )
            else:
                effective = (True, SRC_UNMANAGED)
            self._apply_effective(target_id, st, effective, now)
            st = self._state_to_dict(self._state_row(target_id))
            self._append_history(
                target_id, KIND_TRANSITION,
                policy_version=max(st["policy_version"], 1), ts=now,
                transition_reason=TR_OVERRIDE_REVOKED,
                from_effective=old,
                to_effective=(st["effective_healthy"], st["effective_source"],
                              st["policy_version"]),
                state_version=st["state_version"], actor=actor,
            )
            self._conn.commit()
            self._invalidate_view()
            self._audit_transition(target_id)
            self._notify_history_commit()
            return {"changed": True, "state": st}

    # -- check execution / state machine ------------------------------------

    async def check_target(self, target_id: str) -> Optional[dict]:
        """Run one check round for a target and feed the state machine.

        Probing happens outside the store lock; the result is only recorded
        when the target is still managed, enabled, unpaused and outside
        maintenance, and still at the same policy version, so a policy change
        or control action racing the probe cannot be overwritten.
        """
        target_id = _norm_id(target_id)
        with self._lock:
            st = self._reconcile_locked(target_id)
            if st is None or st["policy_version"] == 0:
                return None
            policy = self._load_policy(target_id)
            if (
                not policy["enabled"]
                or st["paused"]
                or st["in_maintenance"]
            ):
                return None
            address = self._target_address(target_id)
            methods = [CheckMethodSpec(**m) for m in policy["checks"]]
            policy_version = st["policy_version"]
            due_state_version = st["state_version"]

        started_wall = self._clock()
        started_perf = time.perf_counter()
        results = await asyncio.gather(
            *(
                run_probe(m, address, policy["timeout_seconds"])
                for m in methods
            ),
            return_exceptions=False,
        )
        duration_ms = round((time.perf_counter() - started_perf) * 1000, 3)

        with self._lock:
            return self._record_probe(
                target_id,
                results=results,
                started_at=started_wall,
                duration_ms=duration_ms,
                policy_version=policy_version,
                state_version_before=due_state_version,
            )

    def _record_probe(
        self,
        target_id: str,
        *,
        results: list[dict],
        started_at: float,
        duration_ms: float,
        policy_version: int,
        state_version_before: int,
    ) -> Optional[dict]:
        row = self._state_row(target_id)
        if row is None:
            return None
        st = self._state_to_dict(row)
        now = self._clock()
        # Stale probe: policy changed or a control transition happened while
        # the probes were in flight. Old results must never touch new state.
        if (
            st["policy_version"] != policy_version
            or st["state_version"] != state_version_before
            or st["paused"]
            or st["in_maintenance"]
        ):
            return None
        policy = self._load_policy(target_id)
        if not policy["enabled"]:
            return None

        ok = all(r["ok"] for r in results)
        first_failure = next((r for r in results if not r["ok"]), None)
        reason = None if ok else (first_failure["reason"] if first_failure else None)
        verdict = VERDICT_SUCCESS if ok else VERDICT_FAILURE

        failures = st["consecutive_failures"]
        successes = st["consecutive_successes"]
        if ok:
            successes += 1
            failures = 0
        else:
            failures += 1
            successes = 0

        old_observed = st["observed_healthy"]
        new_observed = old_observed
        threshold_reason: Optional[str] = None
        if not ok and old_observed and failures >= policy["fail_threshold"]:
            new_observed = False
            threshold_reason = TR_FAIL_THRESHOLD
        elif ok and not old_observed and successes >= policy["recover_threshold"]:
            new_observed = True
            threshold_reason = TR_RECOVER_THRESHOLD

        old_effective = (st["effective_healthy"], st["effective_source"],
                         st["policy_version"])

        self._conn.execute(
            "UPDATE health_target_states SET consecutive_failures = ?,"
            " consecutive_successes = ?, last_check_seq = last_check_seq + 1,"
            " last_checked_at = ?, next_check_at = ?, updated_at = ?"
            " WHERE target_id = ?",
            (failures, successes, now, now + policy["interval_seconds"],
             now, target_id),
        )

        seq = self._append_history(
            target_id, KIND_CHECK, policy_version=policy_version, ts=now,
            started_at=started_at, verdict=verdict, failure_reason=reason,
            response_summary=json.dumps(results, sort_keys=True),
            duration_ms=duration_ms,
            effective_healthy=st["effective_healthy"],
            effective_source=st["effective_source"],
            state_version=st["state_version"],
            detail={
                "failures": failures,
                "successes": successes,
                "fail_threshold": policy["fail_threshold"],
                "recover_threshold": policy["recover_threshold"],
            },
        )

        transition_seq: Optional[int] = None
        if threshold_reason is not None:
            self._conn.execute(
                "UPDATE health_target_states SET observed_healthy = ?,"
                " state_version = state_version + 1, updated_at = ?"
                " WHERE target_id = ?",
                (int(new_observed), now, target_id),
            )
            st = self._state_to_dict(self._state_row(target_id))
            effective = self._compute_effective(
                st, policy["maintenance_windows"], now
            )
            changed_effective = self._apply_effective(
                target_id, st, effective, now
            )
            st = self._state_to_dict(self._state_row(target_id))
            if changed_effective:
                transition_seq = self._append_history(
                    target_id, KIND_TRANSITION, policy_version=policy_version,
                    ts=now, transition_reason=threshold_reason,
                    from_effective=old_effective,
                    to_effective=(st["effective_healthy"],
                                  st["effective_source"], policy_version),
                    state_version=st["state_version"],
                    detail={
                        "consecutive_failures": failures,
                        "consecutive_successes": successes,
                        "check_seq": seq,
                    },
                )
        self._conn.commit()
        self._invalidate_view()
        if transition_seq is not None:
            self._audit_transition(target_id)
        # Every check row may advance a subscription's consecutive-threshold
        # confirmation even when the effective state itself did not flip, so
        # the alert ingestor is notified for both kinds of appends.
        self._notify_history_commit()

        st = self._state_to_dict(self._state_row(target_id))
        return {
            "target_id": target_id,
            "seq": seq,
            "transition_seq": transition_seq,
            "verdict": verdict,
            "failure_reason": reason,
            "results": results,
            "observed_healthy": st["observed_healthy"],
            "effective_healthy": st["effective_healthy"],
            "effective_source": st["effective_source"],
            "consecutive_failures": st["consecutive_failures"],
            "consecutive_successes": st["consecutive_successes"],
            "policy_version": policy_version,
            "next_check_at": st["next_check_at"],
        }

    # -- scheduling ----------------------------------------------------------

    def due_targets(self, now: Optional[float] = None) -> list[dict]:
        """Targets whose scheduler should fire, in priority/id order.

        Runs maintenance/expiry reconciliation first (window entry may park a
        target) and returns managed, enabled, unpaused, not-in-maintenance
        targets with next_check_at <= now.
        """
        now = self._clock() if now is None else now
        with self._lock:
            # Reconcile at the scan time: an expired override or window
            # entry/exit must take effect before deciding which targets to
            # probe. Only real transitions are committed/audited.
            managed = self._conn.execute(
                "SELECT target_id FROM health_policies WHERE enabled = 1"
            ).fetchall()
            for r in managed:
                self._reconcile_locked(r["target_id"], at=now)
            rows = self._conn.execute(
                "SELECT p.target_id AS target_id, p.priority AS priority,"
                " p.interval_seconds AS interval_seconds,"
                " s.next_check_at AS next_check_at"
                " FROM health_policies p JOIN health_target_states s"
                " ON p.target_id = s.target_id"
                " WHERE p.enabled = 1 AND s.paused = 0"
                " AND s.next_check_at <= ?"
                " ORDER BY p.priority ASC, p.target_id ASC",
                (now,),
            ).fetchall()
            due = []
            for r in rows:
                # Reconcile may report a virtual maintenance window for an
                # explicit future scan time; such targets are skipped without
                # persisting anything.
                virtual = self._reconcile_locked(r["target_id"], at=now)
                if virtual is None or virtual["in_maintenance"]:
                    continue
                due.append(
                        {
                            "target_id": r["target_id"],
                            "priority": r["priority"],
                            "interval_seconds": r["interval_seconds"],
                            "next_check_at": r["next_check_at"],
                        }
                    )
            return due

    # -- materialized effective view (resolution hot path) ------------------

    def _effective_view(self, *, force: bool = False) -> dict[str, tuple[bool, str]]:
        """Return {target: (healthy, source)}, reconciling lazily.

        Recomputed at most once per ``view_ttl``; admin/checker writes
        invalidate immediately. Maintenance entry and override expiry are the
        time-driven transitions applied here.
        """
        now = self._clock()
        cache = self._view_cache
        if (
            not force
            and cache is not None
            and now - self._view_at < self._view_ttl
        ):
            return cache
        view: dict[str, tuple[bool, str]] = {}
        rows = self._conn.execute(
            "SELECT target_id FROM health_target_states"
        ).fetchall()
        for r in rows:
            st = self._reconcile_locked(r["target_id"])
            if st is not None:
                view[r["target_id"]] = (
                    st["effective_healthy"], st["effective_source"]
                )
        self._view_cache = view
        self._view_at = self._clock()
        return view

    # -- read side -----------------------------------------------------------

    def is_healthy(self, target_id: str) -> bool:
        """Effective health used by resolution; unknown targets fail open."""
        with self._lock:
            eff = self._effective_view().get(_norm_id(target_id))
        return True if eff is None else eff[0]

    def snapshot(self) -> dict[str, dict]:
        """Effective health view for every referenced target.

        Targets without a state row are unmanaged and fail open, so they are
        included with source='unmanaged' exactly like the old in-memory
        registry's default-healthy view.
        """
        with self._lock:
            view = self._effective_view()
            known = {
                t.id: t.address
                for item in (
                    *self._config.snapshot().all_rules(),
                    *self._config.snapshot().all_release_groups(),
                )
                for t in item.targets
            }
            out: dict[str, dict] = {}
            for tid in sorted(known):
                eff = view.get(tid)
                if eff is None:
                    out[tid] = {
                        "healthy": True,
                        "source": SRC_UNMANAGED,
                        "observed_healthy": True,
                        "state_version": None,
                        "policy_version": 0,
                    }
                    continue
                row = self._state_row(tid)
                st = self._state_to_dict(row)
                out[tid] = {
                    "healthy": eff[0],
                    "source": eff[1],
                    "observed_healthy": st["observed_healthy"],
                    "state_version": st["state_version"],
                    "policy_version": st["policy_version"],
                }
            return out

    def get_policy(self, target_id: str) -> dict:
        with self._lock:
            return self._load_policy(target_id)

    def list_policies(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM health_policies ORDER BY priority, target_id"
            ).fetchall()
            return [self._row_to_policy(r) for r in rows]

    def get_state(self, target_id: str) -> dict:
        with self._lock:
            st = self._reconcile_locked(target_id)
        if st is None:
            raise HealthCheckNotFound(
                f"no health state for target {target_id!r}"
            )
        return st

    def list_states(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT target_id FROM health_target_states"
            ).fetchall()
            out = []
            for r in rows:
                st = self._reconcile_locked(r["target_id"])
                if st is not None:
                    out.append(st)
            return out

    def revisions(
        self,
        target_id: Optional[str] = None,
        *,
        limit: int = 200,
    ) -> list[dict]:
        sql = (
            "SELECT * FROM health_policy_revisions WHERE 1=1"
        )
        args: list = []
        if target_id is not None:
            sql += " AND target_id = ?"
            args.append(target_id)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [
            {
                "id": r["id"],
                "target_id": r["target_id"],
                "policy_version": r["policy_version"],
                "action": r["action"],
                "payload": json.loads(r["payload"]),
                "actor": r["actor"],
                "ts": r["ts"],
            }
            for r in rows
        ]

    @staticmethod
    def _history_row(r) -> dict:
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
            "response_summary": (
                json.loads(r["response_summary"])
                if r["response_summary"] is not None else None
            ),
            "duration_ms": r["duration_ms"],
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
            "actor": r["actor"],
            "detail": json.loads(r["detail"]),
        }

    def history(
        self,
        target_id: str,
        *,
        policy_version: Optional[int] = None,
        kind: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        after_seq: Optional[int] = None,
        limit: int = 100,
    ) -> dict:
        """Fixed-order (ascending per-target seq) paginated history."""
        if kind is not None and kind not in (KIND_CHECK, KIND_TRANSITION):
            raise HealthCheckValidation(
                "kind must be 'check' or 'transition'"
            )
        target_id = _norm_id(target_id)
        with self._lock:
            # The target must be one the system knows about (policy now or
            # history rows left behind after deletion).
            known = self._conn.execute(
                "SELECT 1 FROM health_check_history WHERE target_id = ? LIMIT 1",
                (target_id,),
            ).fetchone()
            if known is None and self._policy_row(target_id) is None \
                    and self._state_row(target_id) is None:
                raise HealthCheckNotFound(
                    f"no health history for target {target_id!r}"
                )
            sql = (
                "SELECT * FROM health_check_history"
                " WHERE target_id = ?"
            )
            args: list = [target_id]
            if policy_version is not None:
                sql += " AND policy_version = ?"
                args.append(policy_version)
            if kind is not None:
                sql += " AND kind = ?"
                args.append(kind)
            if since is not None:
                sql += " AND ts >= ?"
                args.append(since)
            if until is not None:
                sql += " AND ts < ?"
                args.append(until)
            if after_seq is not None:
                sql += " AND seq > ?"
                args.append(after_seq)
            sql += " ORDER BY seq ASC, id ASC LIMIT ?"
            args.append(limit + 1)
            rows = self._conn.execute(sql, args).fetchall()
        has_more = len(rows) > limit
        page = [self._history_row(r) for r in rows[:limit]]
        next_after = page[-1]["seq"] if page else after_seq
        return {
            "target_id": target_id,
            "order": "seq:asc",
            "items": page,
            "count": len(page),
            "has_more": has_more,
            "next_cursor": next_after if has_more else None,
        }


# -- background scheduler -----------------------------------------------------


class HealthScheduler:
    """Runs due target checks independently, priority ordered."""

    def __init__(
        self,
        store: HealthCheckStore,
        tick_seconds: float = 0.25,
    ):
        self._store = store
        self._tick = tick_seconds

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await self.tick()
            except Exception as exc:  # noqa: BLE001 - keep the loop alive
                print(f"health check tick failed: {exc}", flush=True)
            try:
                await asyncio.wait_for(stop.wait(), self._tick)
            except asyncio.TimeoutError:
                pass

    async def tick(self) -> list[dict]:
        results = []
        for item in self._store.due_targets():
            res = await self._store.check_target(item["target_id"])
            if res is not None:
                results.append(res)
        return results
