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
- Listeners are notified after each apply so the resolver can invalidate
  cache entries whose producing rule changed. Entries for names that did
  not change keep serving until their TTL expires.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .audit import AuditLog
from .models import ConfigBundle, Defaults, ReleaseGroup, Rule


class VersionConflict(Exception):
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


class ConfigManager:
    def __init__(
        self,
        conn: sqlite3.Connection,
        audit: AuditLog,
        clock: Callable[[], float] = time.time,
    ):
        self._conn = conn
        self._audit = audit
        self._clock = clock
        self._lock = threading.RLock()
        self._version = 0
        self._defaults = Defaults()
        self._rules: dict[tuple, tuple[Rule, ...]] = {}
        self._groups: dict[str, tuple[ReleaseGroup, ...]] = {}
        self._listeners: list[Callable[[Snapshot], int]] = []

    # -- read side ------------------------------------------------------

    def snapshot(self) -> Snapshot:
        with self._lock:
            return Snapshot(self._version, self._defaults, self._rules, self._groups)

    def add_listener(self, fn: Callable[[Snapshot], int]) -> None:
        """fn(new_snapshot) -> number of cache entries invalidated."""
        self._listeners.append(fn)

    # -- write side -----------------------------------------------------

    def load_persisted(self) -> Optional[int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM config_versions ORDER BY version DESC LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            bundle = ConfigBundle(**json.loads(row["payload"]))
            self._install(bundle, persist=False, audit_record=False, source="restore")
            return bundle.version

    def apply(self, bundle: ConfigBundle, source: str = "api") -> dict:
        with self._lock:
            if bundle.version <= self._version:
                raise VersionConflict(
                    f"config version must increase: got {bundle.version}, "
                    f"current {self._version}"
                )
            return self._install(bundle, persist=True, audit_record=True, source=source)

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

    def _install(
        self, bundle: ConfigBundle, persist: bool, audit_record: bool, source: str
    ) -> dict:
        now = self._clock()
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

        self._rules = new_rules
        self._groups = new_groups
        self._version = bundle.version
        self._defaults = bundle.defaults

        if persist:
            self._conn.execute(
                "INSERT INTO config_versions (version, applied_at, source, payload)"
                " VALUES (?, ?, ?, ?)",
                (bundle.version, now, source, bundle.model_dump_json()),
            )
            self._conn.commit()

        if audit_record:
            counts = {"added": 0, "updated": 0, "removed": 0}
            for action, key, old_v, new_v in changes:
                counts[action] += 1
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
            group_counts = {"added": 0, "updated": 0, "removed": 0}
            for action, name, old_g, new_g in group_changes:
                group_counts[action] += 1
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
            self._audit.record(
                "config_applied",
                {
                    "version": bundle.version,
                    "source": source,
                    **counts,
                    "release_groups_added": group_counts["added"],
                    "release_groups_updated": group_counts["updated"],
                    "release_groups_removed": group_counts["removed"],
                },
            )

        snap = self.snapshot()
        invalidated = 0
        for listener in self._listeners:
            invalidated += listener(snap) or 0

        return {
            "version": bundle.version,
            "changes": len(changes),
            "release_group_changes": len(group_changes),
            "invalidated": invalidated,
        }
