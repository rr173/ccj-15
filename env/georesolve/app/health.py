"""Target health tracking and background checking.

Health state feeds target selection, which is a pure function of the
healthy set. Every node runs the same checker against the same targets
with the same thresholds, so health views converge within a bounded time
(check interval x thresholds) and with them the answers nodes give.
"""
from __future__ import annotations

import asyncio
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional
from urllib.parse import urlparse

from .audit import AuditLog
from .config_store import ConfigManager


@dataclass
class HealthState:
    healthy: bool = True
    since: float = 0.0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_error: Optional[str] = None


class HealthRegistry:
    """Current health view plus thresholded transition logic."""

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._lock = threading.Lock()
        self._states: dict[str, HealthState] = {}

    def is_healthy(self, target_id: str) -> bool:
        with self._lock:
            st = self._states.get(target_id)
        return True if st is None else st.healthy  # unknown targets fail open

    def report(
        self,
        target_id: str,
        ok: bool,
        error: Optional[str] = None,
        fail_threshold: int = 2,
        pass_threshold: int = 1,
    ) -> Optional[tuple[bool, bool]]:
        """Record one probe result; return (old, new) on transition."""
        now = self._clock()
        with self._lock:
            st = self._states.setdefault(target_id, HealthState(since=now))
            transition = None
            if ok:
                st.consecutive_successes += 1
                st.consecutive_failures = 0
                if not st.healthy and st.consecutive_successes >= pass_threshold:
                    transition = (st.healthy, True)
                    st.healthy = True
                    st.since = now
            else:
                st.consecutive_failures += 1
                st.consecutive_successes = 0
                if st.healthy and st.consecutive_failures >= fail_threshold:
                    transition = (st.healthy, False)
                    st.healthy = False
                    st.since = now
            st.last_error = error
            return transition

    def set(self, target_id: str, healthy: bool) -> None:
        """Direct override (used by tests and by the admin API)."""
        with self._lock:
            self._states[target_id] = HealthState(healthy=healthy, since=self._clock())

    def snapshot(self) -> dict[str, dict]:
        with self._lock:
            return {
                tid: {
                    "healthy": st.healthy,
                    "since": st.since,
                    "consecutive_failures": st.consecutive_failures,
                    "consecutive_successes": st.consecutive_successes,
                    "last_error": st.last_error,
                }
                for tid, st in self._states.items()
            }


async def default_probe(address: str, timeout: float) -> tuple[bool, Optional[str]]:
    """Probe a target. http(s):// -> GET and expect 2xx/3xx; else TCP connect."""
    parsed = urlparse(address if "://" in address else f"tcp://{address}")
    scheme = parsed.scheme or "tcp"
    host = parsed.hostname
    if host is None:
        return False, f"unparseable address {address!r}"
    port = parsed.port or (443 if scheme == "https" else 80)
    try:
        if scheme in ("http", "https"):
            ssl_ctx = ssl.create_default_context() if scheme == "https" else None
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx), timeout
            )
            try:
                path = parsed.path or "/"
                writer.write(
                    f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
                )
                await asyncio.wait_for(writer.drain(), timeout)
                line = await asyncio.wait_for(reader.readline(), timeout)
                code = int(line.split()[1])
                ok = 200 <= code < 400
                return ok, None if ok else f"http status {code}"
            finally:
                writer.close()
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout
            )
            writer.close()
            return True, None
    except Exception as exc:  # noqa: BLE001 - any failure means unhealthy
        return False, f"{type(exc).__name__}: {exc}"


Prober = Callable[[str, float], Awaitable[tuple[bool, Optional[str]]]]


class HealthChecker:
    def __init__(
        self,
        registry: HealthRegistry,
        config: ConfigManager,
        audit: AuditLog,
        interval: float = 2.0,
        timeout: float = 1.0,
        fail_threshold: int = 2,
        pass_threshold: int = 1,
        prober: Prober = default_probe,
    ):
        self._registry = registry
        self._config = config
        self._audit = audit
        self._interval = interval
        self._timeout = timeout
        self._fail_threshold = fail_threshold
        self._pass_threshold = pass_threshold
        self._prober = prober

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            await self.check_once()
            try:
                await asyncio.wait_for(stop.wait(), self._interval)
            except asyncio.TimeoutError:
                pass

    async def check_once(self) -> None:
        snap = self._config.snapshot()
        targets: dict[str, str] = {}
        for rule in snap.all_rules():
            for t in rule.targets:
                targets[t.id] = t.address
        if not targets:
            return
        results = await asyncio.gather(
            *(self._prober(addr, self._timeout) for addr in targets.values()),
            return_exceptions=True,
        )
        for tid, res in zip(targets.keys(), results):
            if isinstance(res, Exception):
                ok, err = False, f"{type(res).__name__}: {res}"
            else:
                ok, err = res
            transition = self._registry.report(
                tid, ok, err, self._fail_threshold, self._pass_threshold
            )
            if transition is not None:
                old, new = transition
                self._audit.record(
                    "health_change",
                    {"target_id": tid, "old": old, "new": new},
                )
