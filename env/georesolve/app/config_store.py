"""Versioned configuration manager.

Semantics:
- Config versions are strictly monotonic: applying a bundle whose version
  is not greater than the current one is rejected.
- ``apply`` is atomic: once it returns, every new resolution uses the new
  snapshot, so new requests immediately see rules at least as new as the
  effective version.
- The effective rule for a (name, region, tenant) triple is the most
  specific in-effect rule: tenant > region > global. A rule whose
  ``effective_from`` lies in the future is stored as a scheduled version
  alongside the currently effective one and activates automatically when
  its time comes; the cache clamps entry expiry to the next scheduled
  transition and re-validates entries against the effective rule on every
  lookup, so activation takes effect for new requests immediately.
- A bundle is the full desired state. Keys absent from the new bundle are
  removed. When a bundle carries a future-dated rule for a key, the
  previously effective rule for that key is retained until the scheduled
  one activates.
- Rate-limit tiers are also full-state, grouped by scope layer. Resolution
  chooses the highest-priority matching tier in the most specific layer
  (tenant, then region, then global). Applying any new bundle version lets
  the rate limiter discard old buckets, so quota state never survives a
  configuration change.
- Listeners are notified after each apply so the resolver can invalidate
  cache entries whose producing rule changed. Entries for names that did
  not change keep serving until their TTL expires.

Change management:
- ``preview_bundle`` / ``preview_rollback`` run the exact same merge, diff
  and impact computation as a real apply (rule selection, gray groups,
  cache invalidations, rate-limit policy) against a *candidate* snapshot
  without touching the effective config, the cache, the rate-limiter
  buckets or the audit log. A preview returns a single-use, time-bounded
  token bound to the base version, the proposed version and a content
  fingerprint; ``apply``/``rollback`` reject expired, reused, mismatched or
  stale-base tokens.
- Every applied version persists a queryable summary: affected names,
  per-rule diffs, release-group diffs and rate-limit tier diffs, plus the
  projected cache/rate-limit impact. ``versions``/``version_info`` expose
  the history.
- ``rollback`` reconstructs the full-state payload of any saved version,
  stamps it with a brand-new strictly-higher version, and commits it through
  the very same validation, persistence, listener (cache invalidation and
  bucket reset) and audit pipeline as a normal apply.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .audit import AuditLog
from .models import (
    ConfigBundle,
    Defaults,
    RateLimitTier,
    ReleaseGroup,
    Rule,
    bundle_fingerprint,
)


class VersionConflict(Exception):
    pass


class VersionNotFound(Exception):
    pass


class RollbackRejected(Exception):
    pass


class PreviewRejected(Exception):
    """Base class for dry-run token failures; carries an HTTP-ish code."""

    status_code = 409


class PreviewExpired(PreviewRejected):
    status_code = 410


class PreviewConsumed(PreviewRejected):
    pass


class PreviewMismatch(PreviewRejected):
    pass


def _best_in_effect(versions: tuple[Rule, ...], now: float) -> Optional[Rule]:
    candidates = [r for r in versions if r.effective_from <= now]
    if not candidates:
        return None
    return max(candidates, key=lambda r: r.rule_version)


@dataclass(frozen=True)
class Snapshot:
    version: int
    defaults: Defaults
    rules: dict  # rule.key() -> tuple[Rule, ...] sorted by rule_version
    release_groups: dict  # name -> tuple[ReleaseGroup, ...] sorted by (priority, id)
    rate_limit_tiers: dict  # scope_key -> tuple[RateLimitTier, ...] sorted by (priority,id)

    def effective_rule(
        self, name: str, region: str, tenant: str, now: float
    ) -> Optional[Rule]:
        candidates = []
        if tenant:
            candidates.append((name, "tenant", "", tenant))
        if region:
            candidates.append((name, "region", region, ""))
        candidates.append((name, "global", "", ""))
        for key in candidates:
            versions = self.rules.get(key)
            if versions:
                rule = _best_in_effect(versions, now)
                if rule is not None:
                    return rule
        return None

    def groups_for_name(self, name: str) -> tuple[ReleaseGroup, ...]:
        return self.release_groups.get(name, ())

    def visible_groups(
        self, name: str, region: str, tenant: str
    ) -> list[ReleaseGroup]:
        """Groups of the name whose scope the request can see."""
        return [
            g for g in self.groups_for_name(name) if g.visible_to(region, tenant)
        ]

    def next_transition(
        self, name: str, region: str, tenant: str, now: float
    ) -> Optional[float]:
        """Earliest future moment the answer may change: scheduled rule
        activations plus release-group window starts/ends."""
        keys = [(name, "global", "", "")]
        if region:
            keys.append((name, "region", region, ""))
        if tenant:
            keys.append((name, "tenant", "", tenant))
        future = [
            r.effective_from
            for k in keys
            for r in self.rules.get(k, ())
            if r.effective_from > now
        ]
        for g in self.visible_groups(name, region, tenant):
            if g.window_start > now:
                future.append(g.window_start)
            elif g.window_active(now):
                future.append(g.window_end)
        return min(future) if future else None

    def all_rules(self) -> list[Rule]:
        return [r for versions in self.rules.values() for r in versions]

    def all_release_groups(self) -> list[ReleaseGroup]:
        return [g for groups in self.release_groups.values() for g in groups]

    def rate_limit_for(
        self, region: str, tenant: str, labels: dict[str, str]
    ) -> Optional[RateLimitTier]:
        """Select one highest-priority tier from the most specific layer."""
        scope_keys: list[tuple] = []
        if tenant:
            scope_keys.append(("tenant", "", tenant))
        if region:
            scope_keys.append(("region", region, ""))
        scope_keys.append(("global", "", ""))

        for scope_key in scope_keys:
            matches = [
                tier
                for tier in self.rate_limit_tiers.get(scope_key, ())
                if tier.labels_match(labels)
            ]
            if matches:
                return min(matches, key=lambda t: (t.priority, t.id))
        return None

    def rate_limit_candidates(
        self, region: str, tenant: str
    ) -> list[RateLimitTier]:
        """Visible tiers ordered from the most to the least specific layer."""
        scope_keys: list[tuple] = []
        if tenant:
            scope_keys.append(("tenant", "", tenant))
        if region:
            scope_keys.append(("region", region, ""))
        scope_keys.append(("global", "", ""))
        return [
            tier
            for scope_key in scope_keys
            for tier in self.rate_limit_tiers.get(scope_key, ())
        ]

    def all_rate_limit_tiers(self) -> list[RateLimitTier]:
        return [tier for tiers in self.rate_limit_tiers.values() for tier in tiers]


@dataclass
class _Preview:
    token: str
    base_version: int
    proposed_version: int
    fingerprint: str
    kind: str  # "apply" | "rollback"
    rollback_of: Optional[int]
    expires_at: float
    consumed: bool = False


class PreviewStore:
    """In-memory, single-use, TTL-bounded dry-run tokens.

    Previews never reach the database, cache or audit log; they only live
    here long enough for the admin to inspect the impact and commit it.
    """

    def __init__(self, clock: Callable[[], float], ttl: float):
        self._clock = clock
        self._ttl = ttl
        self._lock = threading.Lock()
        self._items: dict[str, _Preview] = {}

    def issue(
        self,
        base_version: int,
        proposed_version: int,
        fingerprint: str,
        kind: str,
        rollback_of: Optional[int],
    ) -> tuple[str, float]:
        token = secrets.token_urlsafe(18)
        expires_at = self._clock() + self._ttl
        with self._lock:
            self._items[token] = _Preview(
                token,
                base_version,
                proposed_version,
                fingerprint,
                kind,
                rollback_of,
                expires_at,
            )
        return token, expires_at

    def consume(
        self,
        token: str,
        base_version: int,
        proposed_version: int,
        fingerprint: str,
        kind: str,
        now: float,
    ) -> _Preview:
        """Atomically validate and burn one token, or raise PreviewRejected."""
        with self._lock:
            p = self._items.get(token)
            if p is None:
                raise PreviewRejected(
                    "unknown preview token; run a dry-run preview first"
                )
            if now >= p.expires_at:
                del self._items[token]
                raise PreviewExpired("preview result has expired; run it again")
            if p.consumed:
                raise PreviewConsumed("preview token has already been used")
            if p.base_version != base_version:
                raise PreviewMismatch(
                    f"preview was computed against version {p.base_version}, "
                    f"but the current version is {base_version}; the impact "
                    "assessment is stale"
                )
            if p.proposed_version != proposed_version:
                raise PreviewMismatch(
                    f"preview proposed version {p.proposed_version}, "
                    f"but the commit now carries version {proposed_version}"
                )
            if p.fingerprint != fingerprint:
                raise PreviewMismatch(
                    "config payload no longer matches the previewed content"
                )
            if p.kind != kind:
                raise PreviewMismatch(
                    f"preview kind was {p.kind!r}, cannot use it for {kind!r}"
                )
            p.consumed = True  # keep the record so reuse is reported as such
            return p


@dataclass
class InstallPlan:
    """Everything a (dry-run or real) install computes, before any mutation."""

    bundle: ConfigBundle
    now: float
    rules: dict
    groups: dict
    tiers: dict
    rule_changes: list = field(default_factory=list)
    group_changes: list = field(default_factory=list)
    tier_changes: list = field(default_factory=list)

    @property
    def snapshot(self) -> "Snapshot":
        return Snapshot(
            self.bundle.version, self.bundle.defaults,
            self.rules, self.groups, self.tiers,
        )

    def counts(self) -> dict:
        def tally(changes):
            out = {"added": 0, "updated": 0, "removed": 0}
            for c in changes:
                out[c[0]] += 1
            return out

        rules, groups, tiers = (
            tally(self.rule_changes),
            tally(self.group_changes),
            tally(self.tier_changes),
        )
        return {
            "rules_added": rules["added"],
            "rules_updated": rules["updated"],
            "rules_removed": rules["removed"],
            "release_groups_added": groups["added"],
            "release_groups_updated": groups["updated"],
            "release_groups_removed": groups["removed"],
            "rate_limit_tiers_added": tiers["added"],
            "rate_limit_tiers_updated": tiers["updated"],
            "rate_limit_tiers_removed": tiers["removed"],
        }


@dataclass
class PreviewResult:
    token: str
    expires_at: float
    base_version: int
    proposed_version: int
    kind: str
    rollback_of: Optional[int]
    plan: InstallPlan
    fingerprint: str
    listener_impacts: dict


class ConfigManager:
    def __init__(
        self,
        conn: sqlite3.Connection,
        audit: AuditLog,
        clock: Callable[[], float] = time.time,
        preview_ttl: float = 300.0,
    ):
        self._conn = conn
        self._audit = audit
        self._clock = clock
        self._lock = threading.RLock()
        self._version = 0
        self._defaults = Defaults()
        self._rules: dict[tuple, tuple[Rule, ...]] = {}
        self._groups: dict[str, tuple[ReleaseGroup, ...]] = {}
        self._tiers: dict[tuple, tuple[RateLimitTier, ...]] = {}
        # (listener, preview_listener); the latter projects impact without
        # mutating cache or buckets.
        self._listeners: list[
            tuple[
                Callable[[Snapshot], int],
                Optional[Callable[[Snapshot, Snapshot], dict]],
            ]
        ] = []
        self._previews = PreviewStore(clock, preview_ttl)
        self._current_fingerprint: Optional[str] = None

    # -- read side ------------------------------------------------------

    def snapshot(self) -> Snapshot:
        with self._lock:
            return Snapshot(
                self._version, self._defaults, self._rules, self._groups, self._tiers
            )

    def add_listener(
        self,
        fn: Callable[[Snapshot], int],
        preview_fn: Optional[Callable[[Snapshot, Snapshot], dict]] = None,
    ) -> None:
        """fn(new_snapshot) -> number of cache entries invalidated.

        ``preview_fn(old_snapshot, candidate_snapshot)`` projects the impact
        a candidate config would have on this listener without mutating
        anything; it is used by dry-run previews.
        """
        self._listeners.append((fn, preview_fn))

    # -- write side -----------------------------------------------------

    def load_persisted(self) -> Optional[int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM config_versions ORDER BY version DESC LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            bundle = ConfigBundle(**json.loads(row["payload"]))
            plan = self._plan(bundle, self._clock())
            self._adopt(plan)
            self._current_fingerprint = bundle_fingerprint(bundle)
            return bundle.version

    # -- planning (pure; shared by preview, apply and rollback) ---------

    def _merge_key(
        self, key: tuple, new_rule: Optional[Rule], now: float
    ) -> Optional[tuple[Rule, ...]]:
        """Compute the version list for one key under a new bundle."""
        if new_rule is None:
            return None  # key removed by the new bundle
        if new_rule.effective_from <= now:
            return (new_rule,)  # immediately effective: supersedes everything
        # Scheduled for the future: keep the currently effective rule (if
        # any) so service continues until activation.
        previous = _best_in_effect(self._rules.get(key, ()), now)
        versions = [v for v in (previous, new_rule) if v is not None]
        return tuple(sorted(versions, key=lambda r: r.rule_version))

    def _plan(self, bundle: ConfigBundle, now: float) -> InstallPlan:
        """Compute candidate state and diffs against the live state.

        This mutates nothing: callers either discard the result (dry-run
        preview) or hand it to ``_commit``.
        """
        old_rules = self._rules
        incoming = {r.key(): r for r in bundle.rules}

        new_rules: dict[tuple, tuple[Rule, ...]] = {}
        for key, new_rule in incoming.items():
            merged = self._merge_key(key, new_rule, now)
            if merged:
                new_rules[key] = merged

        changes: list[tuple[str, tuple, tuple, tuple]] = []
        for key, versions in new_rules.items():
            old_versions = old_rules.get(key, ())
            if [r.model_dump() for r in old_versions] != [
                r.model_dump() for r in versions
            ]:
                action = "updated" if old_versions else "added"
                changes.append((action, key, old_versions, versions))
        for key, versions in old_rules.items():
            if key not in new_rules:
                changes.append(("removed", key, versions, ()))

        # Release groups are full-state too: the bundle's list replaces the
        # stored one wholesale (windows, not scheduled versions, drive their
        # activation, so no merging is needed).
        grouped: dict[str, list[ReleaseGroup]] = {}
        for g in bundle.release_groups:
            grouped.setdefault(g.name, []).append(g)
        new_groups = {
            name: tuple(sorted(gs, key=lambda g: (g.priority, g.id)))
            for name, gs in grouped.items()
        }

        grouped_tiers: dict[tuple, list[RateLimitTier]] = {}
        for tier in bundle.rate_limit_tiers:
            grouped_tiers.setdefault(tier.scope_key(), []).append(tier)
        new_tiers = {
            scope_key: tuple(sorted(ts, key=lambda t: (t.priority, t.id)))
            for scope_key, ts in grouped_tiers.items()
        }

        old_groups = self._groups
        group_changes: list[tuple[str, str, Optional[ReleaseGroup], Optional[ReleaseGroup]]] = []
        for name in sorted(set(old_groups) | set(new_groups)):
            old_by_id = {g.id: g for g in old_groups.get(name, ())}
            new_by_id = {g.id: g for g in new_groups.get(name, ())}
            for gid in sorted(set(old_by_id) | set(new_by_id)):
                old_g, new_g = old_by_id.get(gid), new_by_id.get(gid)
                if old_g is None:
                    group_changes.append(("added", name, None, new_g))
                elif new_g is None:
                    group_changes.append(("removed", name, old_g, None))
                elif old_g.model_dump() != new_g.model_dump():
                    group_changes.append(("updated", name, old_g, new_g))

        old_tiers = self._tiers
        tier_changes: list[tuple[str, tuple, Optional[RateLimitTier], Optional[RateLimitTier]]] = []
        for scope_key in sorted(set(old_tiers) | set(new_tiers)):
            old_by_id = {t.id: t for t in old_tiers.get(scope_key, ())}
            new_by_id = {t.id: t for t in new_tiers.get(scope_key, ())}
            for tid in sorted(set(old_by_id) | set(new_by_id)):
                old_t, new_t = old_by_id.get(tid), new_by_id.get(tid)
                if old_t is None:
                    tier_changes.append(("added", scope_key, None, new_t))
                elif new_t is None:
                    tier_changes.append(("removed", scope_key, old_t, None))
                elif old_t.model_dump() != new_t.model_dump():
                    tier_changes.append(("updated", scope_key, old_t, new_t))

        return InstallPlan(
            bundle=bundle,
            now=now,
            rules=new_rules,
            groups=new_groups,
            tiers=new_tiers,
            rule_changes=changes,
            group_changes=group_changes,
            tier_changes=tier_changes,
        )

    # -- commit ----------------------------------------------------------

    def _adopt(self, plan: InstallPlan) -> None:
        self._rules = plan.rules
        self._groups = plan.groups
        self._tiers = plan.tiers
        self._version = plan.bundle.version
        self._defaults = plan.bundle.defaults

    def _persist(
        self,
        plan: InstallPlan,
        source: str,
        summary: Optional[dict],
    ) -> None:
        try:
            self._conn.execute(
                "INSERT INTO config_versions (version, applied_at, source, payload, summary)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    plan.bundle.version,
                    plan.now,
                    source,
                    plan.bundle.model_dump_json(),
                    json.dumps(summary, sort_keys=True) if summary is not None else None,
                ),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            # Another committer won the same version number concurrently; the
            # live state is untouched (persist precedes adoption), so just
            # refuse to overwrite the newer/equal version explicitly.
            raise VersionConflict(
                f"config version {plan.bundle.version} was already committed "
                "by a concurrent submission"
            ) from exc

    def _audit_plan(
        self,
        plan: InstallPlan,
        source: str,
        extra: Optional[dict] = None,
    ) -> None:
        bundle = plan.bundle
        for action, key, old_v, new_v in plan.rule_changes:
            self._audit.record(
                "rule_change",
                {
                    "action": action,
                    "rule_key": "|".join(key),
                    "config_version": bundle.version,
                    "source": source,
                    "old": [r.model_dump() for r in old_v] or None,
                    "new": [r.model_dump() for r in new_v] or None,
                },
            )
        for action, name, old_g, new_g in plan.group_changes:
            group = new_g or old_g
            self._audit.record(
                "release_group_change",
                {
                    "action": action,
                    "name": name,
                    "group_id": group.id if group else None,
                    "scope": group.scope if group else None,
                    "config_version": bundle.version,
                    "source": source,
                    "old": old_g.model_dump() if old_g else None,
                    "new": new_g.model_dump() if new_g else None,
                },
            )
        for action, scope_key, old_t, new_t in plan.tier_changes:
            tier = new_t or old_t
            self._audit.record(
                "rate_limit_change",
                {
                    "action": action,
                    "tier_id": tier.id if tier else None,
                    "scope_key": "|".join(scope_key),
                    "config_version": bundle.version,
                    "source": source,
                    "old": old_t.model_dump() if old_t else None,
                    "new": new_t.model_dump() if new_t else None,
                },
            )
        record = {
            "version": bundle.version,
            "source": source,
            **plan.counts(),
        }
        if extra:
            record.update(extra)
        self._audit.record("config_applied", record)

    @staticmethod
    def _build_summary(
        plan: InstallPlan,
        source: str,
        base_version: int,
        fingerprint: str,
        listener_impacts: dict,
        rollback_of: Optional[int],
        invalidated: int,
    ) -> dict:
        """Queryable per-version summary: affected names, groups and tiers."""
        affected_names: set[str] = set()
        rule_diffs = []
        for action, key, old_v, new_v in plan.rule_changes:
            affected_names.add(key[0])
            rule_diffs.append(
                {
                    "action": action,
                    "name": key[0],
                    "scope": key[1],
                    "region": key[2] or None,
                    "tenant": key[3] or None,
                    "old_rule_version": old_v[-1].rule_version if old_v else None,
                    "new_rule_version": new_v[-1].rule_version if new_v else None,
                    "old_target_ids": [t.id for r in old_v for t in r.targets],
                    "new_target_ids": [t.id for r in new_v for t in r.targets],
                }
            )
        group_diffs = []
        for action, name, old_g, new_g in plan.group_changes:
            affected_names.add(name)
            group = new_g or old_g
            group_diffs.append(
                {
                    "action": action,
                    "name": name,
                    "group_id": group.id if group else None,
                    "scope": group.scope if group else None,
                    "priority": group.priority if group else None,
                    "percent": group.percent if group else None,
                    "match_labels": dict(group.match_labels) if group else None,
                    "old_percent": old_g.percent if old_g else None,
                    "new_percent": new_g.percent if new_g else None,
                    "old_target_ids": [t.id for t in old_g.targets] if old_g else [],
                    "new_target_ids": [t.id for t in new_g.targets] if new_g else [],
                }
            )
        tier_diffs = []
        for action, scope_key, old_t, new_t in plan.tier_changes:
            tier = new_t or old_t
            tier_diffs.append(
                {
                    "action": action,
                    "tier_id": tier.id if tier else None,
                    "scope": scope_key[0],
                    "region": scope_key[1] or None,
                    "tenant": scope_key[2] or None,
                    "match_labels": dict(tier.match_labels) if tier else None,
                    "old_rate_per_second": old_t.rate_per_second if old_t else None,
                    "new_rate_per_second": new_t.rate_per_second if new_t else None,
                    "old_burst": old_t.burst if old_t else None,
                    "new_burst": new_t.burst if new_t else None,
                }
            )
        return {
            "version": plan.bundle.version,
            "base_version": base_version,
            "source": source,
            "applied_at": plan.now,
            "fingerprint": fingerprint,
            "rollback_of": rollback_of,
            "affected_names": sorted(affected_names),
            "rule_diffs": rule_diffs,
            "release_group_diffs": group_diffs,
            "rate_limit_tier_diffs": tier_diffs,
            "impact": {
                "cache_entries_invalidated": invalidated,
                **listener_impacts,
            },
            **plan.counts(),
        }

    def _project_impacts(self, plan: InstallPlan) -> dict:
        """Run every listener's dry-run projection against the candidate."""
        old_snap = self.snapshot()
        new_snap = plan.snapshot
        impacts: dict = {}
        for _, preview_fn in self._listeners:
            if preview_fn is None:
                continue
            projection = preview_fn(old_snap, new_snap) or {}
            for key, value in projection.items():
                impacts.setdefault(key, 0)
                impacts[key] += value
        return impacts

    def _commit(
        self,
        plan: InstallPlan,
        source: str,
        base_version: int,
        fingerprint: str,
        rollback_of: Optional[int] = None,
        persist: bool = True,
        audit_record: bool = True,
        notify: bool = True,
    ) -> dict:
        # Project listener impact first (pure, off the old state), so the
        # persisted summary matches what the real invalidation will do.
        listener_impacts = self._project_impacts(plan) if notify else {}
        projected_invalidated = listener_impacts.get(
            "cache_entries_invalidated", 0
        )

        summary = None
        if persist or audit_record:
            summary = self._build_summary(
                plan, source, base_version, fingerprint,
                listener_impacts, rollback_of, projected_invalidated,
            )

        # Persist BEFORE touching live state: a concurrent committer who wins
        # the same version number must not leave this node half-migrated.
        if persist:
            self._persist(plan, source, summary)

        self._adopt(plan)
        self._current_fingerprint = fingerprint

        invalidated = 0
        if notify:
            for listener, _ in self._listeners:
                invalidated += listener(plan.snapshot) or 0
            if persist and invalidated != projected_invalidated:
                # Data-plane traffic added/removed entries between the pure
                # projection and the real sweep; keep the stored summary exact.
                summary["impact"]["cache_entries_invalidated"] = invalidated
                self._conn.execute(
                    "UPDATE config_versions SET summary = ? WHERE version = ?",
                    (json.dumps(summary, sort_keys=True), plan.bundle.version),
                )
                self._conn.commit()

        if audit_record:
            extra = {"base_version": base_version, "fingerprint": fingerprint}
            if rollback_of is not None:
                extra["rollback_of"] = rollback_of
                self._audit.record(
                    "config_rollback",
                    {
                        "version": plan.bundle.version,
                        "target_version": rollback_of,
                        "base_version": base_version,
                        "source": source,
                        "fingerprint": fingerprint,
                    },
                )
            self._audit_plan(plan, source, extra)

        return {
            "version": plan.bundle.version,
            "changes": len(plan.rule_changes),
            "release_group_changes": len(plan.group_changes),
            "rate_limit_changes": len(plan.tier_changes),
            "invalidated": invalidated,
            "summary": summary,
        }

    def _install(
        self,
        bundle: ConfigBundle,
        persist: bool,
        audit_record: bool,
        source: str,
        notify: bool = True,
    ) -> dict:
        """Internal install path used by restore and the config file watcher."""
        plan = self._plan(bundle, self._clock())
        fingerprint = bundle_fingerprint(bundle)
        return self._commit(
            plan,
            source=source,
            base_version=self._version,
            fingerprint=fingerprint,
            rollback_of=None,
            persist=persist,
            audit_record=audit_record,
            notify=notify,
        )

    # -- apply -----------------------------------------------------------

    def apply(
        self,
        bundle: ConfigBundle,
        source: str = "api",
        expected_version: Optional[int] = None,
        preview_token: Optional[str] = None,
    ) -> dict:
        with self._lock:
            if bundle.version <= self._version:
                raise VersionConflict(
                    f"config version must increase: got {bundle.version}, "
                    f"current {self._version}"
                )
            if expected_version is not None and expected_version != self._version:
                raise VersionConflict(
                    f"optimistic concurrency check failed: expected base "
                    f"version {expected_version}, current {self._version}"
                )
            fingerprint = bundle_fingerprint(bundle)
            base_version = self._version
            if preview_token:
                self._previews.consume(
                    preview_token,
                    base_version=base_version,
                    proposed_version=bundle.version,
                    fingerprint=fingerprint,
                    kind="apply",
                    now=self._clock(),
                )
            plan = self._plan(bundle, self._clock())
            return self._commit(
                plan,
                source=source,
                base_version=base_version,
                fingerprint=fingerprint,
            )

    # -- dry-run preview --------------------------------------------------

    def _preview(
        self,
        bundle: ConfigBundle,
        kind: str,
        rollback_of: Optional[int],
    ) -> PreviewResult:
        with self._lock:
            now = self._clock()
            base_version = self._version
            if bundle.version <= base_version:
                raise VersionConflict(
                    f"config version must increase: got {bundle.version}, "
                    f"current {base_version}"
                )
            fingerprint = bundle_fingerprint(bundle)
            plan = self._plan(bundle, now)
            impacts = self._project_impacts(plan)
            token, expires_at = self._previews.issue(
                base_version, bundle.version, fingerprint, kind, rollback_of
            )
            return PreviewResult(
                token=token,
                expires_at=expires_at,
                base_version=base_version,
                proposed_version=bundle.version,
                kind=kind,
                rollback_of=rollback_of,
                plan=plan,
                fingerprint=fingerprint,
                listener_impacts=impacts,
            )

    def preview_bundle(self, bundle: ConfigBundle) -> PreviewResult:
        """Dry-run a normal config bundle through the full apply pipeline."""
        return self._preview(bundle, kind="apply", rollback_of=None)

    def preview_summary(self, result: PreviewResult) -> dict:
        """The same summary/diff a real commit of this preview would save."""
        return self._build_summary(
            result.plan,
            source="preview",
            base_version=result.base_version,
            fingerprint=result.fingerprint,
            listener_impacts=result.listener_impacts,
            rollback_of=result.rollback_of,
            invalidated=result.listener_impacts.get(
                "cache_entries_invalidated", 0
            ),
        )

    def _restamp(self, target_bundle: ConfigBundle, new_version: int) -> ConfigBundle:
        """Rebuild an old full-state bundle at a brand-new config version.

        Inner rule_version values are content from the past and stay as they
        were (already <= the target version); only the bundle header moves.
        """
        payload = json.loads(target_bundle.model_dump_json())
        payload["version"] = new_version
        return ConfigBundle(**payload)

    def preview_rollback(self, target_version: int) -> PreviewResult:
        """Dry-run restoring a saved version as a new higher version."""
        with self._lock:
            target_bundle, _row = self._load_saved(target_version)
            current_version = self._version
            if target_version == current_version:
                raise RollbackRejected(
                    f"rollback target version {target_version} is already the "
                    "current version"
                )
            if bundle_fingerprint(target_bundle) == self._current_fingerprint:
                raise RollbackRejected(
                    f"version {target_version} has identical content to the "
                    "currently effective configuration; nothing would change"
                )
            bundle = self._restamp(target_bundle, current_version + 1)
        return self._preview(bundle, kind="rollback", rollback_of=target_version)

    # -- rollback ---------------------------------------------------------

    def _load_saved(self, target_version: int) -> tuple[ConfigBundle, dict]:
        row = self._conn.execute(
            "SELECT payload, summary, applied_at, source FROM config_versions"
            " WHERE version = ?",
            (target_version,),
        ).fetchone()
        if row is None:
            raise VersionNotFound(f"config version {target_version} does not exist")
        return ConfigBundle(**json.loads(row["payload"])), dict(row)

    def rollback(
        self,
        target_version: int,
        source: str = "rollback",
        expected_version: Optional[int] = None,
        preview_token: Optional[str] = None,
        new_version: Optional[int] = None,
    ) -> dict:
        with self._lock:
            target_bundle, _row = self._load_saved(target_version)
            current_version = self._version
            if target_version == current_version:
                raise RollbackRejected(
                    f"rollback target version {target_version} is already the "
                    "current version"
                )
            if expected_version is not None and expected_version != current_version:
                raise VersionConflict(
                    f"optimistic concurrency check failed: expected base "
                    f"version {expected_version}, current {current_version}"
                )

            target_fingerprint = bundle_fingerprint(target_bundle)
            if target_fingerprint == self._current_fingerprint:
                raise RollbackRejected(
                    f"version {target_version} has identical content to the "
                    "currently effective configuration; nothing would change"
                )

            next_version = (
                new_version if new_version is not None else current_version + 1
            )
            if next_version <= current_version:
                raise VersionConflict(
                    f"rollback must create a version above {current_version}, "
                    f"got {next_version}"
                )
            bundle = self._restamp(target_bundle, next_version)

            fingerprint = bundle_fingerprint(bundle)
            if preview_token:
                self._previews.consume(
                    preview_token,
                    base_version=current_version,
                    proposed_version=next_version,
                    fingerprint=fingerprint,
                    kind="rollback",
                    now=self._clock(),
                )
            plan = self._plan(bundle, self._clock())
            return self._commit(
                plan,
                source=source,
                base_version=current_version,
                fingerprint=fingerprint,
                rollback_of=target_version,
            )

    # -- history ----------------------------------------------------------

    def versions(self, limit: int = 50) -> list[dict]:
        """Saved version summaries, newest first (without full payloads)."""
        rows = self._conn.execute(
            "SELECT version, applied_at, source, payload, summary"
            " FROM config_versions ORDER BY version DESC LIMIT ?",
            (limit,),
        ).fetchall()
        out = []
        for row in rows:
            summary = json.loads(row["summary"]) if row["summary"] else None
            if summary is None:
                # Versions saved before summaries existed: expose the header
                # without the detailed diff.
                payload = ConfigBundle(**json.loads(row["payload"]))
                summary = {
                    "version": row["version"],
                    "base_version": None,
                    "source": row["source"],
                    "applied_at": row["applied_at"],
                    "fingerprint": bundle_fingerprint(payload),
                    "rollback_of": None,
                    "affected_names": [],
                    "rule_diffs": [],
                    "release_group_diffs": [],
                    "rate_limit_tier_diffs": [],
                }
            out.append(
                {
                    "version": row["version"],
                    "applied_at": row["applied_at"],
                    "source": row["source"],
                    "summary": summary,
                }
            )
        return out

    def version_info(self, version: int, include_payload: bool = True) -> dict:
        """One saved version: persisted summary/diff plus optional payload."""
        row = self._conn.execute(
            "SELECT version, applied_at, source, payload, summary"
            " FROM config_versions WHERE version = ?",
            (version,),
        ).fetchone()
        if row is None:
            raise VersionNotFound(f"config version {version} does not exist")
        bundle = ConfigBundle(**json.loads(row["payload"]))
        summary = json.loads(row["summary"]) if row["summary"] else None
        info: dict = {
            "version": row["version"],
            "applied_at": row["applied_at"],
            "source": row["source"],
            "fingerprint": bundle_fingerprint(bundle),
            "summary": summary,
        }
        if include_payload:
            info["bundle"] = json.loads(bundle.model_dump_json())
        return info
