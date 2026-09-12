"""TTL cache for resolution answers.

Cache keys are (name, region, tenant, client_key) quadruples. The
deterministic weighted ranking of a rule's targets is a function of the
client key, so an answer computed for one client is physically a
different entry and can never be served to another client, region, or
tenant. Each entry records the fingerprint of the rule that produced it
and a signature of target health at store time; the resolver treats an
entry as stale the moment the effective rule or the health view moves
on, regardless of remaining TTL.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class CacheEntry:
    name: str
    region: str
    tenant: str
    client_key: str  # effective selection key the answer was computed for
    kind: str  # "positive" | "negative"
    rule_version: Optional[int]  # None when no rule produced this answer
    rule_scope: Optional[str]
    rule_fingerprint: Optional[str]
    health_sig: frozenset  # ids of targets healthy at store time
    payload: dict
    stored_at: float
    expires_at: float
    config_version: int

    def key(self) -> tuple:
        return (self.name, self.region, self.tenant, self.client_key)


class ResolutionCache:
    def __init__(self, clock: Callable[[], float]):
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[tuple, CacheEntry] = {}

    def get(
        self, name: str, region: str, tenant: str, client_key: str = ""
    ) -> Optional[CacheEntry]:
        key = (name, region, tenant, client_key)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_at <= self._clock():
                del self._entries[key]
                return None
            return entry

    def peek(
        self, name: str, region: str, tenant: str, client_key: str = ""
    ) -> Optional[CacheEntry]:
        """Return the entry without expiry eviction (for diagnostics)."""
        with self._lock:
            return self._entries.get((name, region, tenant, client_key))

    def put(self, entry: CacheEntry) -> None:
        if entry.expires_at <= entry.stored_at:
            return  # zero TTL: do not store
        with self._lock:
            self._entries[entry.key()] = entry

    def evict(self, key: tuple) -> Optional[CacheEntry]:
        with self._lock:
            return self._entries.pop(key, None)

    def items(self) -> list[CacheEntry]:
        with self._lock:
            return list(self._entries.values())

    def clear(self) -> int:
        with self._lock:
            n = len(self._entries)
            self._entries.clear()
            return n
