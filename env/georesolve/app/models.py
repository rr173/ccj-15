"""Configuration and rule models.

A config bundle is a full-state snapshot of all rules, identified by a
strictly increasing ``version``. Each rule carries its own ``rule_version``
(the config version at which this rule last changed) and an
``effective_from`` timestamp so rules can be published ahead of time and
activate at a planned moment.
"""
from __future__ import annotations

import hashlib
from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator

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


class ConfigBundle(BaseModel):
    version: int = Field(ge=1)
    defaults: Defaults = Field(default_factory=Defaults)
    rules: list[Rule] = Field(default_factory=list)

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
        return self
