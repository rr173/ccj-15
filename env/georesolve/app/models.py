"""Configuration and rule models.

A config bundle is a full-state snapshot of all rules, identified by a
strictly increasing ``version``. Each rule carries its own ``rule_version``
(the config version at which this rule last changed) and an
``effective_from`` timestamp so rules can be published ahead of time and
activate at a planned moment.
"""
from __future__ import annotations

import hashlib
import math
from typing import Literal, Mapping, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

ScopeType = Literal["global", "region", "tenant"]


class Target(BaseModel):
    id: str
    address: str  # "host:port", "tcp://host:port" or "http(s)://host:port/path"
    weight: int = Field(default=1, ge=0)


class Rule(BaseModel):
    name: str  # resolved name, exact match after normalization (lowercase)
    scope: ScopeType = "global"
    region: Optional[str] = None  # required when scope == "region"
    tenant: Optional[str] = None  # required when scope == "tenant"
    targets: list[Target] = Field(default_factory=list)
    ttl: int = Field(default=60, ge=0)  # positive answer TTL, seconds
    negative_ttl: Optional[int] = Field(default=None, ge=0)  # overrides default
    effective_from: float = 0.0  # epoch seconds; in effect when now >= effective_from
    rule_version: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def _check_scope(self) -> "Rule":
        if self.scope == "global" and (self.region or self.tenant):
            raise ValueError("global rule must not set region/tenant")
        if self.scope == "region" and (not self.region or self.tenant):
            raise ValueError("region rule requires 'region' and must not set 'tenant'")
        if self.scope == "tenant" and (not self.tenant or self.region):
            raise ValueError("tenant rule requires 'tenant' and must not set 'region'")
        return self

    def key(self) -> tuple:
        return (self.name, self.scope, self.region or "", self.tenant or "")

    def fingerprint(self) -> str:
        """Content hash; any semantic change to the rule changes this."""
        return hashlib.blake2b(self.model_dump_json().encode(), digest_size=8).hexdigest()


class Defaults(BaseModel):
    negative_ttl: int = Field(default=30, ge=0)


def normalize_labels(labels: Optional[Mapping[str, str]]) -> dict[str, str]:
    """Canonical request labels: stripped, lowercased, empties dropped."""
    out: dict[str, str] = {}
    for k, v in (labels or {}).items():
        key, val = str(k).strip().lower(), str(v).strip().lower()
        if key and val:
            out[key] = val
    return out


def labels_signature(labels: Mapping[str, str]) -> str:
    """Stable string form of normalized labels; part of the cache key."""
    return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))


def labels_compatible(a: Mapping[str, str], b: Mapping[str, str]) -> bool:
    """True when some client label set could match both condition sets
    (i.e. the two sets do not contradict on any shared key)."""
    shared = set(a) & set(b)
    return all(a[k] == b[k] for k in shared)


def windows_overlap(a_start: float, a_end: float, b_start: float, b_end: float) -> bool:
    return a_start < b_end and b_start < a_end


class ReleaseGroup(BaseModel):
    """A conditional gray-release group for a name.

    A request carrying labels considers every group of the name whose
    scope is visible to it (global always; region/tenant when they match
    the request). Among groups that are window-active and label-matching,
    exactly one -- the highest priority (smallest ``priority``) -- is
    selected, and its ``percent`` then decides deterministically whether
    the client is served from the group's targets or falls back to the
    base rule. Selection is seeded with the config version and the group
    fingerprint (which covers window, labels, percent and targets), so
    any rule change reshuffles immediately while a client is stable
    within an unchanged window.
    """

    id: str
    name: str  # resolved name the group applies to
    scope: ScopeType = "global"
    region: Optional[str] = None  # required when scope == "region"
    tenant: Optional[str] = None  # required when scope == "tenant"
    priority: int = Field(ge=0)  # smaller wins when several groups are eligible
    match_labels: dict[str, str] = Field(default_factory=dict)  # all must match
    percent: int = Field(ge=0, le=100)  # share of matching clients sent to targets
    targets: list[Target] = Field(min_length=1)
    ttl: int = Field(default=60, ge=0)
    window_start: float  # epoch seconds; active when start <= now < end
    window_end: float
    rule_version: int = Field(default=1, ge=1)

    @field_validator("id", "name")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must be a non-empty string")
        return v

    @field_validator("match_labels")
    @classmethod
    def _norm_match_labels(cls, v: dict[str, str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, val in v.items():
            key, value = str(k).strip().lower(), str(val).strip().lower()
            if not key or not value:
                raise ValueError("match label keys and values must be non-empty")
            out[key] = value
        return out

    @model_validator(mode="after")
    def _check_group(self) -> "ReleaseGroup":
        if self.scope == "global" and (self.region or self.tenant):
            raise ValueError("global release group must not set region/tenant")
        if self.scope == "region" and (not self.region or self.tenant):
            raise ValueError("region release group requires 'region' and must not set 'tenant'")
        if self.scope == "tenant" and (not self.tenant or self.region):
            raise ValueError("tenant release group requires 'tenant' and must not set 'region'")
        if not (math.isfinite(self.window_start) and math.isfinite(self.window_end)):
            raise ValueError("window bounds must be finite epoch seconds")
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be greater than window_start")
        return self

    def key(self) -> tuple:
        return (self.name, self.scope, self.region or "", self.tenant or "")

    def fingerprint(self) -> str:
        """Content hash; any semantic change to the group changes this."""
        return hashlib.blake2b(self.model_dump_json().encode(), digest_size=8).hexdigest()

    def window_active(self, now: float) -> bool:
        return self.window_start <= now < self.window_end

    def labels_match(self, labels: Mapping[str, str]) -> bool:
        return all(labels.get(k) == v for k, v in self.match_labels.items())

    def visible_to(self, region: str, tenant: str) -> bool:
        if self.scope == "global":
            return True
        if self.scope == "region":
            return self.region == region
        return self.tenant == tenant


class ConfigBundle(BaseModel):
    version: int = Field(ge=1)
    defaults: Defaults = Field(default_factory=Defaults)
    rules: list[Rule] = Field(default_factory=list)
    release_groups: list[ReleaseGroup] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_bundle(self) -> "ConfigBundle":
        seen: set[tuple] = set()
        for r in self.rules:
            k = r.key()
            if k in seen:
                raise ValueError(f"duplicate rule for {k}")
            seen.add(k)
            if r.rule_version > self.version:
                raise ValueError(
                    f"rule {k} has rule_version {r.rule_version} > bundle version {self.version}"
                )
        self._check_release_groups()
        return self

    def _check_release_groups(self) -> None:
        by_name: dict[str, list[ReleaseGroup]] = {}
        for g in self.release_groups:
            if g.rule_version > self.version:
                raise ValueError(
                    f"release group {g.id!r} has rule_version {g.rule_version} "
                    f"> bundle version {self.version}"
                )
            by_name.setdefault(g.name, []).append(g)
        for name, groups in by_name.items():
            ids = [g.id for g in groups]
            if len(set(ids)) != len(ids):
                raise ValueError(f"duplicate release group id for name {name!r}")
            # Overlapping windows are rejected exactly when they would make
            # the choice ambiguous or contradictory:
            # 1. same scope layer + overlap, regardless of label conditions:
            #    the groups coexist in the same name/layer and are active at
            #    the same time, so the overlap is a plain window conflict
            #    even when their match_labels differ;
            by_key: dict[tuple, list[ReleaseGroup]] = {}
            for g in groups:
                by_key.setdefault(g.key(), []).append(g)
            for key, gs in by_key.items():
                for i, a in enumerate(gs):
                    for b in gs[i + 1:]:
                        if windows_overlap(
                            a.window_start, a.window_end,
                            b.window_start, b.window_end,
                        ):
                            raise ValueError(
                                f"overlapping windows for release groups {a.id!r} "
                                f"and {b.id!r} with the same name and scope "
                                f"layer {key}"
                            )
            # 2. same priority + compatible label conditions + overlap:
            #    either group could win for the same client, which priority
            #    cannot arbitrate because the priorities are equal.
            for i, a in enumerate(groups):
                for b in groups[i + 1:]:
                    if (
                        a.priority == b.priority
                        and labels_compatible(a.match_labels, b.match_labels)
                        and windows_overlap(
                            a.window_start, a.window_end, b.window_start, b.window_end
                        )
                    ):
                        raise ValueError(
                            f"release groups {a.id!r} and {b.id!r} for name {name!r} "
                            f"have the same priority {a.priority} with compatible "
                            f"label conditions and overlapping windows"
                        )
