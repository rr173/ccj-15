from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from app.audit import AuditLog
from app.cache import ResolutionCache
from app.config_store import ConfigManager
from app.health import HealthRegistry
from app.models import ConfigBundle, Defaults, Rule, Target
from app.rate_limit import RateLimiter
from app.resolver import Resolver
from app.storage import connect


class FakeClock:
    def __init__(self, t: float = 1_700_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def target(id: str, weight: int = 1, address: str | None = None) -> Target:
    return Target(id=id, address=address or f"tcp://10.0.0.{id[-1]}:80", weight=weight)


def rule(
    name: str,
    scope: str = "global",
    region: str | None = None,
    tenant: str | None = None,
    targets: list[Target] | None = None,
    ttl: int = 60,
    negative_ttl: int | None = None,
    effective_from: float = 0.0,
    rule_version: int = 1,
) -> Rule:
    return Rule(
        name=name,
        scope=scope,
        region=region,
        tenant=tenant,
        targets=targets or [],
        ttl=ttl,
        negative_ttl=negative_ttl,
        effective_from=effective_from,
        rule_version=rule_version,
    )


def bundle(
    version: int,
    rules: list[Rule],
    negative_ttl: int = 30,
    release_groups: list | None = None,
    rate_limit_tiers: list | None = None,
) -> ConfigBundle:
    return ConfigBundle(
        version=version,
        defaults=Defaults(negative_ttl=negative_ttl),
        rules=rules,
        release_groups=release_groups or [],
        rate_limit_tiers=rate_limit_tiers or [],
    )


def make_stack(db_path: str, clock: FakeClock) -> SimpleNamespace:
    db = connect(db_path)
    audit = AuditLog(db)
    config = ConfigManager(db, audit, clock)
    cache = ResolutionCache(clock)
    health = HealthRegistry(clock)
    rate_limiter = RateLimiter(audit, clock)
    config.add_listener(
        rate_limiter.replace_buckets, rate_limiter.preview_replace
    )
    resolver = Resolver(
        config, cache, health, audit, rate_limiter, clock=clock
    )
    return SimpleNamespace(
        clock=clock, audit=audit, config=config, cache=cache,
        health=health, rate_limiter=rate_limiter, resolver=resolver,
    )


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def stack(tmp_path, clock) -> SimpleNamespace:
    return make_stack(str(tmp_path / "test.db"), clock)
