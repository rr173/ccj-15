"""Core resolution logic.

Resolution pipeline for (name, region, tenant, client_key):

1. Take the current config snapshot and find the effective rule
   (tenant > region > global, only rules past their effective_from).
2. Look up the cache by the exact (name, region, tenant) key. An entry is
   served only if it is unexpired AND was produced by the same rule
   content (fingerprint) AND the health signature of the rule's targets
   is unchanged. Otherwise it is evicted and the invalidation is audited.
3. On a miss, compute the answer: deterministic weighted ranking of
   targets, first healthy target wins (deterministic failover order);
   if none is healthy the answer is degraded but still deterministic.
   Positive answers cache for the rule TTL, negative answers (no
   applicable rule, or a rule without targets) for the negative TTL.
   Expiry is clamped to the next scheduled rule transition so a rule
   activating later is picked up immediately.

Because selection is a pure function of (config version, health view,
client key), nodes holding the same inputs cannot give divergent answers,
and once a recovered target is seen healthy again every node flips back
to the same deterministic choice.
"""
from __future__ import annotations

import time
from typing import Callable, Optional

from .audit import AuditLog
from .cache import CacheEntry, ResolutionCache
from .config_store import ConfigManager, Snapshot
from .health import HealthRegistry
from .models import Rule
from .selection import rank_targets


def _norm(value: str) -> str:
    return (value or "").strip().lower()


class Resolver:
    def __init__(
        self,
        config: ConfigManager,
        cache: ResolutionCache,
        health: HealthRegistry,
        audit: AuditLog,
        clock: Callable[[], float] = time.time,
    ):
        self._config = config
        self._cache = cache
        self._health = health
        self._audit = audit
        self._clock = clock
        config.add_listener(self._on_config_applied)

    # -- resolution -----------------------------------------------------

    def resolve(
        self,
        name: str,
        region: str = "",
        tenant: str = "",
        client_key: str = "",
        now: Optional[float] = None,
    ) -> dict:
        now = self._clock() if now is None else now
        name, region, tenant = _norm(name), _norm(region), _norm(tenant)
        snap = self._config.snapshot()
        rule = snap.effective_rule(name, region, tenant, now)
        fingerprint = rule.fingerprint() if rule else None
        health_sig = self._health_signature(rule)

        entry = self._cache.get(name, region, tenant)
        if entry is not None:
            stale_reason = self._staleness(entry, fingerprint, health_sig)
            if stale_reason is None:
                return self._answer(entry, snap, now, cached=True)
            self._cache.evict(entry.key())
            self._audit.record(
                "cache_invalidation",
                {
                    "name": name,
                    "region": region,
                    "tenant": tenant,
                    "reason": stale_reason,
                    "old_rule_version": entry.rule_version,
                    "new_rule_version": rule.rule_version if rule else None,
                    "config_version": snap.version,
                },
            )

        entry = self._compute(snap, rule, name, region, tenant, client_key, now)
        self._cache.put(entry)
        return self._answer(entry, snap, now, cached=False)

    def _compute(
        self,
        snap: Snapshot,
        rule: Optional[Rule],
        name: str,
        region: str,
        tenant: str,
        client_key: str,
        now: float,
    ) -> CacheEntry:
        nxt = snap.next_transition(name, region, tenant, now)

        if rule is None or not rule.targets:
            if rule is not None and rule.negative_ttl is not None:
                ttl = rule.negative_ttl
            else:
                ttl = snap.defaults.negative_ttl
            expires = now + ttl
            if nxt is not None:
                expires = min(expires, nxt)
            return CacheEntry(
                name=name,
                region=region,
                tenant=tenant,
                kind="negative",
                rule_version=rule.rule_version if rule else None,
                rule_scope=rule.scope if rule else None,
                rule_fingerprint=rule.fingerprint() if rule else None,
                health_sig=frozenset(),
                payload={"status": "NXDOMAIN", "targets": [], "chosen": None,
                         "degraded": False},
                stored_at=now,
                expires_at=expires,
                config_version=snap.version,
            )

        key = client_key or f"{name}|{region}|{tenant}"
        ranked = rank_targets(key, rule.targets)
        healthy_ids = {t.id for t in ranked if self._health.is_healthy(t.id)}
        chosen = next((t for t in ranked if t.id in healthy_ids), None)
        degraded = chosen is None
        if chosen is None and ranked:
            chosen = ranked[0]  # fail open, still deterministic

        expires = now + rule.ttl
        if nxt is not None:
            expires = min(expires, nxt)

        targets_payload = [
            {
                "id": t.id,
                "address": t.address,
                "weight": t.weight,
                "healthy": t.id in healthy_ids,
                "rank": i + 1,
            }
            for i, t in enumerate(ranked)
        ]
        return CacheEntry(
            name=name,
            region=region,
            tenant=tenant,
            kind="positive",
            rule_version=rule.rule_version,
            rule_scope=rule.scope,
            rule_fingerprint=rule.fingerprint(),
            health_sig=frozenset(healthy_ids),
            payload={
                "status": "OK",
                "targets": targets_payload,
                "chosen": chosen.id if chosen else None,
                "degraded": degraded,
            },
            stored_at=now,
            expires_at=expires,
            config_version=snap.version,
        )

    # -- cache validity ---------------------------------------------------

    def _health_signature(self, rule: Optional[Rule]) -> frozenset:
        if rule is None:
            return frozenset()
        return frozenset(t.id for t in rule.targets if self._health.is_healthy(t.id))

    @staticmethod
    def _staleness(
        entry: CacheEntry, fingerprint: Optional[str], health_sig: frozenset
    ) -> Optional[str]:
        if entry.rule_fingerprint != fingerprint:
            return "rule_version_changed"
        if entry.kind == "positive" and entry.health_sig != health_sig:
            return "health_changed"
        return None

    def _on_config_applied(self, snap: Snapshot) -> int:
        """Eagerly evict entries whose effective rule changed."""
        now = self._clock()
        invalidated = 0
        for entry in self._cache.items():
            rule = snap.effective_rule(entry.name, entry.region, entry.tenant, now)
            fingerprint = rule.fingerprint() if rule else None
            if fingerprint != entry.rule_fingerprint:
                self._cache.evict(entry.key())
                invalidated += 1
                self._audit.record(
                    "cache_invalidation",
                    {
                        "name": entry.name,
                        "region": entry.region,
                        "tenant": entry.tenant,
                        "reason": "config_applied",
                        "old_rule_version": entry.rule_version,
                        "new_rule_version": rule.rule_version if rule else None,
                        "config_version": snap.version,
                    },
                )
        return invalidated

    # -- answers ----------------------------------------------------------

    def _answer(
        self, entry: CacheEntry, snap: Snapshot, now: float, cached: bool
    ) -> dict:
        return {
            "name": entry.name,
            "region": entry.region,
            "tenant": entry.tenant,
            "status": entry.payload["status"],
            "config_version": snap.version,
            "rule_version": entry.rule_version,
            "rule_scope": entry.rule_scope,
            "chosen": entry.payload.get("chosen"),
            "targets": entry.payload.get("targets", []),
            "degraded": entry.payload.get("degraded", False),
            "cached": cached,
            "ttl": max(0, int(entry.expires_at - now)),
            "expires_at": entry.expires_at,
        }

    # -- introspection ----------------------------------------------------

    def explain(
        self,
        name: str,
        region: str = "",
        tenant: str = "",
        client_key: str = "",
        now: Optional[float] = None,
    ) -> dict:
        now = self._clock() if now is None else now
        name, region, tenant = _norm(name), _norm(region), _norm(tenant)
        snap = self._config.snapshot()
        rule = snap.effective_rule(name, region, tenant, now)
        fingerprint = rule.fingerprint() if rule else None
        health_sig = self._health_signature(rule)

        cache_state = "absent"
        entry = self._cache.peek(name, region, tenant)
        if entry is not None:
            if entry.expires_at <= now:
                cache_state = "expired"
            else:
                reason = self._staleness(entry, fingerprint, health_sig)
                cache_state = "valid" if reason is None else f"stale:{reason}"

        rule_info = None
        selection = None
        if rule is not None:
            key = client_key or f"{name}|{region}|{tenant}"
            ranked = rank_targets(key, rule.targets) if rule.targets else []
            chosen = next((t for t in ranked if self._health.is_healthy(t.id)), None)
            degraded = chosen is None and bool(ranked)
            if chosen is None and ranked:
                chosen = ranked[0]
            rule_info = {
                "rule_version": rule.rule_version,
                "scope": rule.scope,
                "effective_from": rule.effective_from,
                "ttl": rule.ttl,
                "negative_ttl": rule.negative_ttl
                if rule.negative_ttl is not None
                else snap.defaults.negative_ttl,
                "fingerprint": fingerprint,
                "targets": [
                    {
                        "id": t.id,
                        "address": t.address,
                        "weight": t.weight,
                        "healthy": self._health.is_healthy(t.id),
                        "rank": i + 1,
                    }
                    for i, t in enumerate(ranked)
                ],
            }
            selection = {
                "key": key,
                "chosen": chosen.id if chosen else None,
                "degraded": degraded,
                "order": [t.id for t in ranked],
            }

        return {
            "name": name,
            "region": region,
            "tenant": tenant,
            "now": now,
            "config_version": snap.version,
            "effective_rule": rule_info,
            "selection": selection,
            "cache": {
                "state": cache_state,
                "entry": None
                if entry is None
                else {
                    "kind": entry.kind,
                    "rule_version": entry.rule_version,
                    "stored_at": entry.stored_at,
                    "expires_at": entry.expires_at,
                    "config_version": entry.config_version,
                },
            },
            "next_transition": snap.next_transition(name, region, tenant, now),
        }
