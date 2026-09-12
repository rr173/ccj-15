"""Token-bucket rate limiting for resolution requests.

A request selects at most one configured tier: the highest-priority
matching tier in the most specific visible layer (tenant, then region,
then global). Buckets are isolated by a signature containing the selected
tier, client key, tenant, and normalized request labels, so different
clients, tenants, or label sets can never borrow each other's tokens.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Optional

from .audit import AuditLog
from .config_store import Snapshot
from .models import RateLimitTier, labels_signature, normalize_labels


class RateLimitExceeded(Exception):
    def __init__(self, decision: "RateLimitDecision"):
        self.decision = decision
        super().__init__(decision.reason)


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    tier: Optional[RateLimitTier]
    remaining: float
    limit: float
    burst: float
    retry_after: Optional[float]
    reason: str
    bucket_signature: Optional[str]
    config_version: int
    request_labels: Optional[Mapping[str, str]] = None
    candidates: tuple[RateLimitTier, ...] = ()

    def public(self) -> dict:
        labels = normalize_labels(self.request_labels)
        if self.tier is None:
            data = {
                "enabled": False,
                "allowed": True,
                "tier_id": None,
                "scope": None,
                "priority": None,
                "limit": None,
                "burst": None,
                "rate_per_second": None,
                "remaining": None,
                "retry_after": None,
                "reason": self.reason,
                "bucket_signature": None,
            }
        else:
            data = {
                "enabled": True,
                "allowed": self.allowed,
                "tier_id": self.tier.id,
                "scope": self.tier.scope,
                "region": self.tier.region,
                "tenant": self.tier.tenant,
                "priority": self.tier.priority,
                "match_labels": dict(self.tier.match_labels),
                "rate_per_second": self.limit,
                "limit": self.limit,
                "burst": self.burst,
                "remaining": self.remaining,
                "remaining_tokens": self.remaining,
                "retry_after": self.retry_after,
                "reason": self.reason,
                "bucket_signature": self.bucket_signature,
                "config_version": self.config_version,
            }
        selected_id = self.tier.id if self.tier is not None else None
        data["candidates"] = [
            {
                "tier_id": t.id,
                "scope": t.scope,
                "region": t.region,
                "tenant": t.tenant,
                "priority": t.priority,
                "match_labels": dict(t.match_labels),
                "matched": t.labels_match(labels),
                "selected": t.id == selected_id,
            }
            for t in self.candidates
        ]
        return data


@dataclass
class TokenBucket:
    rate: float
    burst: float
    tokens: float
    updated_at: float

    def refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.updated_at)
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.updated_at = now

    def take(self, now: float, amount: float = 1.0) -> tuple[bool, float]:
        self.refill(now)
        if self.tokens + 1e-9 >= amount:
            self.tokens -= amount
            return True, 0.0
        retry_after = (amount - self.tokens) / self.rate
        return False, max(0.0, retry_after)


class RateLimiter:
    def __init__(self, audit: AuditLog, clock: Callable[[], float] = time.time):
        self._audit = audit
        self._clock = clock
        self._lock = threading.RLock()
        self._buckets: dict[str, TokenBucket] = {}
        self._policy_version = 0
        self._policy_fingerprint = ""

    @staticmethod
    def _signature(
        tier: RateLimitTier,
        client_key: str,
        tenant: str,
        labels_sig: str,
    ) -> str:
        material = {
            "tier_id": tier.id,
            "client_key": client_key,
            "tenant": tenant,
            "labels": labels_sig,
        }
        raw = json.dumps(material, sort_keys=True, separators=(",", ":"))
        return hashlib.blake2b(raw.encode(), digest_size=8).hexdigest()

    @staticmethod
    def select(
        snap: Snapshot, region: str, tenant: str, labels: Mapping[str, str]
    ) -> Optional[RateLimitTier]:
        return snap.rate_limit_for(region, tenant, normalize_labels(labels))

    def _decision_unlimited(
        self,
        snap: Snapshot,
        region: str,
        tenant: str,
        labels: Mapping[str, str],
    ) -> RateLimitDecision:
        return RateLimitDecision(
            allowed=True,
            tier=None,
            remaining=0.0,
            limit=0.0,
            burst=0.0,
            retry_after=None,
            reason="no_rate_limit_tier",
            bucket_signature=None,
            config_version=snap.version,
            candidates=tuple(snap.rate_limit_candidates(region, tenant)),
            request_labels=dict(labels),
        )

    def inspect(
        self,
        snap: Snapshot,
        region: str,
        tenant: str,
        client_key: str,
        labels: Optional[Mapping[str, str]] = None,
        now: Optional[float] = None,
    ) -> RateLimitDecision:
        now = self._clock() if now is None else now
        labels = normalize_labels(labels)
        tier = self.select(snap, region, tenant, labels)
        candidates = tuple(snap.rate_limit_candidates(region, tenant))
        if tier is None:
            return self._decision_unlimited(snap, region, tenant, labels)

        sig = self._signature(tier, client_key, tenant, labels_signature(labels))
        with self._lock:
            bucket = self._buckets.get(sig)
            if bucket is not None:
                bucket.refill(now)
                remaining = bucket.tokens
            else:
                remaining = tier.burst
        allowed = remaining + 1e-9 >= 1.0
        retry_after = None if allowed else (1.0 - remaining) / tier.rate_per_second
        return RateLimitDecision(
            allowed=allowed,
            tier=tier,
            remaining=max(0.0, remaining),
            limit=tier.rate_per_second,
            burst=tier.burst,
            retry_after=retry_after,
            reason="allowed" if allowed else "rate_limit_exceeded",
            bucket_signature=sig,
            config_version=snap.version,
            candidates=candidates,
            request_labels=dict(labels),
        )

    def consume(
        self,
        snap: Snapshot,
        name: str,
        region: str,
        tenant: str,
        client_key: str,
        labels: Optional[Mapping[str, str]] = None,
        now: Optional[float] = None,
    ) -> RateLimitDecision:
        now = self._clock() if now is None else now
        labels = normalize_labels(labels)
        tier = self.select(snap, region, tenant, labels)
        candidates = tuple(snap.rate_limit_candidates(region, tenant))
        if tier is None:
            return self._decision_unlimited(snap, region, tenant, labels)

        labels_sig = labels_signature(labels)
        sig = self._signature(tier, client_key, tenant, labels_sig)
        with self._lock:
            bucket = self._buckets.get(sig)
            if bucket is None:
                bucket = TokenBucket(
                    rate=tier.rate_per_second,
                    burst=tier.burst,
                    tokens=tier.burst,
                    updated_at=now,
                )
                self._buckets[sig] = bucket
            allowed, retry_after = bucket.take(now)
            remaining = bucket.tokens

        decision = RateLimitDecision(
            allowed=allowed,
            tier=tier,
            remaining=max(0.0, remaining),
            limit=tier.rate_per_second,
            burst=tier.burst,
            retry_after=None if allowed else retry_after,
            reason="allowed" if allowed else "rate_limit_exceeded",
            bucket_signature=sig,
            config_version=snap.version,
            candidates=candidates,
            request_labels=dict(labels),
        )
        if not allowed:
            self._audit.record(
                "rate_limit_rejected",
                {
                    "name": name,
                    "region": region,
                    "tenant": tenant,
                    "client_key": client_key,
                    "labels": dict(labels),
                    "config_version": snap.version,
                    "tier_id": tier.id,
                    "scope": tier.scope,
                    "priority": tier.priority,
                    "rate_per_second": tier.rate_per_second,
                    "burst": tier.burst,
                    "remaining": max(0.0, remaining),
                    "retry_after": retry_after,
                    "reason": decision.reason,
                    "bucket_signature": sig,
                },
            )
        return decision

    @staticmethod
    def _compute_policy_fingerprint(snap: Snapshot) -> str:
        tiers = [
            t.model_dump()
            for t in sorted(snap.all_rate_limit_tiers(), key=lambda t: t.id)
        ]
        raw = json.dumps(
            {"rate_limit_tiers": tiers},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.blake2b(raw.encode(), digest_size=8).hexdigest()

    def preview_replace(
        self, old_snap: Snapshot, new_snap: Snapshot
    ) -> dict:
        """Dry-run counterpart of ``replace_buckets`` for config previews.

        Projects bucket/policy changes without clearing buckets or writing
        an audit record.
        """
        with self._lock:
            live_buckets = len(self._buckets)
            old_fingerprint = self._policy_fingerprint
        new_fingerprint = self._compute_policy_fingerprint(new_snap)
        return {
            "rate_limit_buckets_reset": live_buckets,
            "rate_limit_policy_changed": int(new_fingerprint != old_fingerprint),
        }

    def replace_buckets(self, snap: Snapshot) -> int:
        """Replace buckets immediately after a new config version is applied."""
        fingerprint = self._compute_policy_fingerprint(snap)
        with self._lock:
            reset = len(self._buckets)
            self._buckets.clear()
            changed = fingerprint != self._policy_fingerprint
            old_version, old_fingerprint = self._policy_version, self._policy_fingerprint
            self._policy_version, self._policy_fingerprint = snap.version, fingerprint

        # A version bump with live quota state replaces the old buckets; a
        # policy change is recorded even if there were no live buckets yet.
        if reset or changed:
            self._audit.record(
                "rate_limit_bucket_reset",
                {
                    "old_config_version": old_version,
                    "config_version": snap.version,
                    "reset_buckets": reset,
                    "old_policy_fingerprint": old_fingerprint or None,
                    "policy_fingerprint": fingerprint,
                    "policy_changed": changed,
                    "reason": "rate_limit_tier_changed"
                    if changed
                    else "config_version_applied",
                },
            )
        return 0
