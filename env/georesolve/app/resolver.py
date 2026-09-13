"""Core resolution logic.

Resolution pipeline for (name, region, tenant, client_key, labels):

1. Take the current config snapshot and find the effective rule
   (tenant > region > global, only rules past their effective_from).
2. Evaluate gray release groups: among the groups of the name visible to
   the request scope that are window-active and label-matching, exactly
   one -- the highest priority -- is selected, and a deterministic
   bucket seeded with (config version, group fingerprint, client key)
   decides whether the client is served from the group's targets or
   falls back to the base rule. The fingerprint covers the window, the
   match labels and the percent, so all of them participate in the
   deterministic choice; a client keeps its group while nothing changes
   and is reshuffled the moment the config version or the group moves.
3. Consume one token from the tenant/label-aware rate-limit tier selected
   before resolution. A request sees only the highest-priority matching
   tier in the most specific visible layer (tenant, then region, then
   global), and buckets are isolated by (tier, client key, tenant, label
   signature). This happens before the cache read, so cache hits consume
   quota; a rejected request neither reads a cached answer through the
   resolver pipeline nor writes a new cache entry.
3b. Metering/budget gate (when configured): the request is charged one unit
   against the tenant's current daily/monthly budget *before* the cache
   read. Over budget, policy ``reject`` archives a zero-quantity
   ``budget_rejected`` event (so the denial is replayable/explainable) and
   raises BudgetExceeded (HTTP 402); policy ``degrade`` proceeds but flags
   the answer ``budget_degraded``; policy ``allow`` proceeds normally.
   Every request that passes the gate archives exactly one idempotent
   usage event after the answer is produced -- cache hits included --
   keyed by its event id (``X-Request-Id`` header or server-generated), so
   a retried request is never billed twice.
4. Look up the cache by the exact (name, region, tenant, client, labels)
   key -- the ranking depends on the client key and the group decision
   on the labels, so answers are cached per client per label set and
   never shared across either. An entry is served only if it is
   unexpired AND was produced by the same rule content (fingerprint)
   AND the same gray decision (token) AND the health signature of the
   producing targets is unchanged. Otherwise it is evicted and the
   invalidation is audited.
5. On a miss, compute the answer: deterministic weighted ranking of the
   producing targets (group targets on a hit, base rule targets
   otherwise), first healthy target wins; if none is healthy the answer
   is degraded but still deterministic. Positive answers cache for the
   rule/group TTL, negative answers for the negative TTL. Expiry is
   clamped to the next scheduled transition -- rule activations and
   group window starts/ends -- so window switches take effect for new
   requests immediately and stale entries are never served across them.

Because selection is a pure function of (config version, health view,
client key, labels), nodes holding the same inputs cannot give divergent
answers, and once a recovered target is seen healthy again every node
flips back to the same deterministic choice.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional

from .audit import AuditLog
from .cache import CacheEntry, ResolutionCache
from .config_store import ConfigManager, Snapshot
from .health import HealthRegistry
from .metering import (
    BudgetDecision,
    BudgetExceeded,
    MeteringStore,
    RESULT_DEGRADED,
    RESULT_REJECTED,
    RESULT_SERVED,
)
from .models import (
    ReleaseGroup,
    Rule,
    labels_signature,
    normalize_labels,
)
from .rate_limit import RateLimitDecision, RateLimitExceeded, RateLimiter
from .selection import gray_bucket, rank_targets


def _norm(value: str) -> str:
    return (value or "").strip().lower()


def _request_scope(region: str, tenant: str) -> str:
    """Scope layer a request resolved against when no rule existed."""
    if tenant:
        return "tenant"
    if region:
        return "region"
    return "global"


@dataclass
class GrayDecision:
    """Outcome of the release-group evaluation for one request."""

    has_groups: bool  # the name has any release groups at all
    group: Optional[ReleaseGroup]  # selected group (before the percent dice)
    bucket: Optional[int]
    hit: bool
    token: Optional[str]  # None only when the name has no groups at all
    reason: str
    candidates: list[dict] = field(default_factory=list)


class Resolver:
    def __init__(
        self,
        config: ConfigManager,
        cache: ResolutionCache,
        health: HealthRegistry,
        audit: AuditLog,
        rate_limiter: Optional[RateLimiter] = None,
        metering: Optional[MeteringStore] = None,
        clock: Callable[[], float] = time.time,
    ):
        self._config = config
        self._cache = cache
        self._health = health
        self._audit = audit
        self._rate_limiter = rate_limiter
        self._metering = metering
        self._clock = clock
        config.add_listener(self._on_config_applied, self.preview_config_impact)

    # -- gray release groups --------------------------------------------

    def _evaluate_gray(
        self,
        snap: Snapshot,
        name: str,
        region: str,
        tenant: str,
        labels: Mapping[str, str],
        key: str,
        now: float,
    ) -> GrayDecision:
        groups = snap.groups_for_name(name)
        if not groups:
            return GrayDecision(False, None, None, False, None, "no_groups")

        candidates: list[dict] = []
        eligible: list[ReleaseGroup] = []
        any_label_match = False
        for g in groups:
            if not g.visible_to(region, tenant):
                continue
            window_active = g.window_active(now)
            labels_matched = g.labels_match(labels)
            any_label_match = any_label_match or labels_matched
            is_eligible = window_active and labels_matched
            candidates.append(
                {
                    "id": g.id,
                    "scope": g.scope,
                    "priority": g.priority,
                    "window_active": window_active,
                    "labels_matched": labels_matched,
                    "eligible": is_eligible,
                }
            )
            if is_eligible:
                eligible.append(g)
        candidates.sort(key=lambda c: (c["priority"], c["id"]))

        if not candidates:
            return GrayDecision(
                True, None, None, False, f"{snap.version}:-", "no_visible_groups"
            )
        if not eligible:
            reason = "window_inactive" if any_label_match else "labels_mismatch"
            return GrayDecision(
                True, None, None, False, f"{snap.version}:-", reason, candidates
            )

        # Exactly one winner: the highest priority (smallest value).
        selected = min(eligible, key=lambda g: (g.priority, g.id))
        bucket = gray_bucket(f"{snap.version}#{selected.fingerprint()}#{key}")
        hit = bucket < selected.percent
        token = f"{snap.version}:{selected.fingerprint()}:{int(hit)}"
        return GrayDecision(
            True,
            selected,
            bucket,
            hit,
            token,
            "hit" if hit else "percentage_miss",
            candidates,
        )

    # -- resolution -----------------------------------------------------

    def resolve(
        self,
        name: str,
        region: str = "",
        tenant: str = "",
        client_key: str = "",
        labels: Optional[Mapping[str, str]] = None,
        now: Optional[float] = None,
        request_id: Optional[str] = None,
    ) -> dict:
        now = self._clock() if now is None else now
        name, region, tenant = _norm(name), _norm(region), _norm(tenant)
        labels = normalize_labels(labels)
        sig = labels_signature(labels)
        # The selection key scopes both ranking and caching: each client
        # gets its own deterministic order and its own cache entries.
        key = client_key or f"{name}|{region}|{tenant}"
        snap = self._config.snapshot()
        # Rate limiting happens before rule evaluation and before the cache
        # read, so cache hits still consume quota and a denied request can
        # neither serve from nor write a resolution cache entry.
        rate_decision: Optional[RateLimitDecision] = None
        if self._rate_limiter is not None:
            rate_decision = self._rate_limiter.consume(
                snap, name, region, tenant, key, labels, now
            )
            if not rate_decision.allowed:
                raise RateLimitExceeded(rate_decision)
            current = self._config.snapshot()
            if current.version != snap.version:
                # A config swap reset buckets during this request; retry once
                # on the new policy rather than using a stale snapshot's tier.
                snap = current
                rate_decision = self._rate_limiter.consume(
                    snap, name, region, tenant, key, labels, now
                )
                if not rate_decision.allowed:
                    raise RateLimitExceeded(rate_decision)

        # Resolve the effective rule before the budget gate so that even a
        # rejected request is archived with the scope of the rule it would
        # have been served by (the producing rule may live at a broader
        # layer than the request's own tenant/region).
        rule = snap.effective_rule(name, region, tenant, now)

        # Budget gate, also before the cache read (a denied request neither
        # serves from cache nor writes a cache entry). The projected charge
        # is one unit; only tenants with a configured budget are gated.
        budget_decision: Optional[BudgetDecision] = None
        if self._metering is not None and tenant:
            budget_decision = self._metering.check(
                tenant, now=now, audit_resolution=True
            )
            if not budget_decision.allowed:
                stored = self._record_usage(
                    tenant, key, name, region, sig, snap,
                    rule=rule, gray=None,
                    result=RESULT_REJECTED, degraded=False,
                    now=now, request_id=request_id,
                )
                raise BudgetExceeded(budget_decision, stored["event_id"])

        decision = self._evaluate_gray(snap, name, region, tenant, labels, key, now)
        fingerprint = rule.fingerprint() if rule else None
        active_targets = (
            decision.group.targets
            if decision.hit and decision.group is not None
            else (rule.targets if rule else [])
        )
        health_sig = self._health_signature(active_targets)

        budget_degraded = bool(budget_decision and budget_decision.degraded)
        entry = self._cache.get(name, region, tenant, key, sig)
        cached = False
        if entry is not None:
            stale_reason = self._staleness(
                entry, fingerprint, health_sig, decision.token
            )
            if stale_reason is None:
                cached = True
            else:
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
                        "group_id": entry.group_id,
                        "new_group_id": decision.group.id
                        if decision.hit and decision.group
                        else None,
                        "config_version": snap.version,
                    },
                )
                entry = None
        if entry is None:
            entry = self._compute(
                snap, rule, decision, name, region, tenant, key, sig, labels, now
            )
            self._cache.put(entry)

        answer = self._answer(entry, snap, now, cached, rate_decision)
        if self._metering is not None and tenant:
            result = RESULT_DEGRADED if budget_degraded else RESULT_SERVED
            stored = self._record_usage(
                tenant, key, name, region, sig, snap,
                rule=rule, gray=decision,
                result=result, degraded=budget_degraded,
                now=now, request_id=request_id,
            )
            answer["event_id"] = stored["event_id"]
            answer["duplicate_event"] = stored["duplicate"]
        answer["budget"] = (
            budget_decision.public() if budget_decision is not None else None
        )
        if budget_degraded:
            answer["degraded"] = True
            answer["degrade_reasons"] = sorted(
                set(answer.get("degrade_reasons") or []) | {"budget_exceeded"}
            )
        return answer

    def _record_usage(
        self,
        tenant: str,
        client_key: str,
        name: str,
        region: str,
        labels_sig: str,
        snap: Snapshot,
        *,
        rule: Optional[Rule],
        gray: Optional[GrayDecision],
        result: str,
        degraded: bool,
        now: float,
        request_id: Optional[str],
    ) -> dict:
        """Archive the one usage event for this request (idempotent).

        Rejected requests are archived with zero quantity so the denial is
        explainable and replayable without consuming budget; the event id
        makes a retried request bill at most once.
        """
        group = gray.group if gray is not None and gray.hit else None
        return self._metering.record_event(  # type: ignore[union-attr]
            tenant=tenant,
            client_key=client_key,
            name=name,
            region=region,
            labels_sig=labels_sig,
            rule_scope=(group.scope if group is not None else (rule.scope if rule is not None else _request_scope(region, tenant))),
            rule_version=group.rule_version if group is not None
            else (rule.rule_version if rule is not None else None),
            group_id=group.id if group is not None else None,
            config_version=snap.version,
            result=result,
            quantity=0.0 if result == RESULT_REJECTED else 1.0,
            degraded=degraded,
            event_time=now,
            event_id=request_id,
            source="live",
        )

    def _compute(
        self,
        snap: Snapshot,
        rule: Optional[Rule],
        decision: GrayDecision,
        name: str,
        region: str,
        tenant: str,
        key: str,
        sig: str,
        labels: Mapping[str, str],
        now: float,
    ) -> CacheEntry:
        nxt = snap.next_transition(name, region, tenant, now)
        common = {
            "name": name,
            "region": region,
            "tenant": tenant,
            "client_key": key,
            "labels_sig": sig,
            "labels": dict(labels),
            "group_token": decision.token,
            "stored_at": now,
            "config_version": snap.version,
        }

        if decision.hit and decision.group is not None:
            group = decision.group
            ranked = rank_targets(f"{key}%{group.id}", group.targets)
            healthy_ids = {t.id for t in ranked if self._health.is_healthy(t.id)}
            chosen = next((t for t in ranked if t.id in healthy_ids), None)
            degraded = chosen is None
            if chosen is None and ranked:
                chosen = ranked[0]  # fail open, still deterministic

            expires = min(now + group.ttl, group.window_end)
            if nxt is not None:
                expires = min(expires, nxt)

            self._audit.record(
                "release_group_hit",
                {
                    "name": name,
                    "region": region,
                    "tenant": tenant,
                    "client_key": key,
                    "labels": dict(labels),
                    "group_id": group.id,
                    "scope": group.scope,
                    "priority": group.priority,
                    "bucket": decision.bucket,
                    "percent": group.percent,
                    "window_start": group.window_start,
                    "window_end": group.window_end,
                    "group_rule_version": group.rule_version,
                    "config_version": snap.version,
                },
            )
            return CacheEntry(
                **common,
                kind="positive",
                rule_version=rule.rule_version if rule else None,
                rule_scope=rule.scope if rule else None,
                rule_fingerprint=rule.fingerprint() if rule else None,
                group_id=group.id,
                health_sig=frozenset(healthy_ids),
                payload={
                    "status": "OK",
                    "targets": [
                        {
                            "id": t.id,
                            "address": t.address,
                            "weight": t.weight,
                            "healthy": t.id in healthy_ids,
                            "rank": i + 1,
                        }
                        for i, t in enumerate(ranked)
                    ],
                    "chosen": chosen.id if chosen else None,
                    "degraded": degraded,
                },
                expires_at=expires,
            )

        if rule is None or not rule.targets:
            if rule is not None and rule.negative_ttl is not None:
                ttl = rule.negative_ttl
            else:
                ttl = snap.defaults.negative_ttl
            expires = now + ttl
            if nxt is not None:
                expires = min(expires, nxt)
            return CacheEntry(
                **common,
                kind="negative",
                rule_version=rule.rule_version if rule else None,
                rule_scope=rule.scope if rule else None,
                rule_fingerprint=rule.fingerprint() if rule else None,
                health_sig=frozenset(),
                payload={"status": "NXDOMAIN", "targets": [], "chosen": None,
                         "degraded": False},
                expires_at=expires,
            )

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
            **common,
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
            expires_at=expires,
        )

    # -- cache validity ---------------------------------------------------

    def _health_signature(self, targets) -> frozenset:
        return frozenset(t.id for t in targets if self._health.is_healthy(t.id))

    @staticmethod
    def _staleness(
        entry: CacheEntry,
        fingerprint: Optional[str],
        health_sig: frozenset,
        group_token: Optional[str],
    ) -> Optional[str]:
        if entry.rule_fingerprint != fingerprint:
            return "rule_version_changed"
        if entry.group_token != group_token:
            return "release_group_changed"
        if entry.kind == "positive" and entry.health_sig != health_sig:
            return "health_changed"
        return None

    def _invalidation_plan(self, new_snap: Snapshot) -> list[tuple]:
        """Entries of the current cache that a move to ``new_snap`` would
        invalidate, with the staleness reason. Pure: evicts nothing."""
        now = self._clock()
        doomed = []
        for entry in self._cache.items():
            rule = new_snap.effective_rule(
                entry.name, entry.region, entry.tenant, now
            )
            fingerprint = rule.fingerprint() if rule else None
            decision = self._evaluate_gray(
                new_snap,
                entry.name,
                entry.region,
                entry.tenant,
                entry.labels,
                entry.client_key,
                now,
            )
            if (
                fingerprint != entry.rule_fingerprint
                or decision.token != entry.group_token
            ):
                if fingerprint != entry.rule_fingerprint:
                    reason = "rule_version_changed"
                else:
                    reason = "release_group_changed"
                doomed.append((entry, reason, rule, decision))
        return doomed

    def preview_config_impact(
        self, old_snap: Snapshot, new_snap: Snapshot
    ) -> dict:
        """Dry-run projection for ConfigManager previews: computes how many
        cached answers the candidate config would evict, without evicting
        them, touching buckets or writing audit records."""
        doomed = self._invalidation_plan(new_snap)
        reasons: dict[str, int] = {}
        affected_names: set[str] = set()
        for entry, reason, _rule, _decision in doomed:
            reasons[reason] = reasons.get(reason, 0) + 1
            affected_names.add(entry.name)
        return {
            "cache_entries_invalidated": len(doomed),
            "cache_invalidation_rule_changed": reasons.get(
                "rule_version_changed", 0
            ),
            "cache_invalidation_group_changed": reasons.get(
                "release_group_changed", 0
            ),
            "cache_invalidation_affected_names": len(affected_names),
        }

    def _on_config_applied(self, snap: Snapshot) -> int:
        """Eagerly evict entries whose effective rule or gray decision changed."""
        invalidated = 0
        for entry, _reason, rule, decision in self._invalidation_plan(snap):
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
                    "group_id": entry.group_id,
                    "new_group_id": decision.group.id
                    if decision.hit and decision.group
                    else None,
                    "config_version": snap.version,
                },
            )
        return invalidated

    # -- answers ----------------------------------------------------------

    def _answer(
        self,
        entry: CacheEntry,
        snap: Snapshot,
        now: float,
        cached: bool,
        rate_decision: Optional[RateLimitDecision] = None,
    ) -> dict:
        answer = {
            "name": entry.name,
            "region": entry.region,
            "tenant": entry.tenant,
            "status": entry.payload["status"],
            "config_version": snap.version,
            "rule_version": entry.rule_version,
            "rule_scope": entry.rule_scope,
            "release_group": entry.group_id,
            "chosen": entry.payload.get("chosen"),
            "targets": entry.payload.get("targets", []),
            "degraded": entry.payload.get("degraded", False),
            "cached": cached,
            "ttl": max(0, int(entry.expires_at - now)),
            "expires_at": entry.expires_at,
        }
        answer["rate_limit"] = (
            rate_decision.public() if rate_decision is not None else None
        )
        return answer

    # -- introspection ----------------------------------------------------

    def explain(
        self,
        name: str,
        region: str = "",
        tenant: str = "",
        client_key: str = "",
        labels: Optional[Mapping[str, str]] = None,
        now: Optional[float] = None,
    ) -> dict:
        now = self._clock() if now is None else now
        name, region, tenant = _norm(name), _norm(region), _norm(tenant)
        labels = normalize_labels(labels)
        sig = labels_signature(labels)
        key = client_key or f"{name}|{region}|{tenant}"
        snap = self._config.snapshot()
        rate_decision = (
            self._rate_limiter.inspect(
                snap, region, tenant, key, labels, now
            )
            if self._rate_limiter is not None
            else None
        )
        rule = snap.effective_rule(name, region, tenant, now)
        decision = self._evaluate_gray(snap, name, region, tenant, labels, key, now)
        fingerprint = rule.fingerprint() if rule else None
        active_targets = (
            decision.group.targets
            if decision.hit and decision.group is not None
            else (rule.targets if rule else [])
        )
        health_sig = self._health_signature(active_targets)

        cache_state = "absent"
        entry = self._cache.peek(name, region, tenant, key, sig)
        if entry is not None:
            if entry.expires_at <= now:
                cache_state = "expired"
            else:
                reason = self._staleness(
                    entry, fingerprint, health_sig, decision.token
                )
                cache_state = "valid" if reason is None else f"stale:{reason}"

        rule_info = None
        selection = None
        if rule is not None:
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

        group_info = None
        if decision.group is not None:
            g = decision.group
            ranked = rank_targets(f"{key}%{g.id}", g.targets)
            chosen = next((t for t in ranked if self._health.is_healthy(t.id)), None)
            if chosen is None and ranked:
                chosen = ranked[0]
            group_info = {
                "id": g.id,
                "scope": g.scope,
                "priority": g.priority,
                "percent": g.percent,
                "match_labels": g.match_labels,
                "window_start": g.window_start,
                "window_end": g.window_end,
                "ttl": g.ttl,
                "rule_version": g.rule_version,
                "fingerprint": g.fingerprint(),
                "chosen": chosen.id if chosen else None,
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

        rate_limit_info = rate_decision.public() if rate_decision else None

        budget_info = None
        if self._metering is not None and tenant:
            budget_info = self._metering.check(tenant, now=now).public()

        return {
            "name": name,
            "region": region,
            "tenant": tenant,
            "now": now,
            "config_version": snap.version,
            "rate_limit": rate_limit_info,
            "budget": budget_info,
            "effective_rule": rule_info,
            "selection": selection,
            "release": {
                "labels": dict(labels),
                "reason": decision.reason,
                "hit": decision.hit,
                "bucket": decision.bucket,
                "group": group_info,
                "candidates": decision.candidates,
            },
            "cache": {
                "state": cache_state,
                "entry": None
                if entry is None
                else {
                    "kind": entry.kind,
                    "client_key": entry.client_key,
                    "labels_sig": entry.labels_sig,
                    "rule_version": entry.rule_version,
                    "group_id": entry.group_id,
                    "stored_at": entry.stored_at,
                    "expires_at": entry.expires_at,
                    "config_version": entry.config_version,
                },
            },
            "next_transition": snap.next_transition(name, region, tenant, now),
        }
