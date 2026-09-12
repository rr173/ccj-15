"""Tenant/label-aware resolution rate limiting."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models import ConfigBundle, Defaults, RateLimitTier
from app.rate_limit import RateLimitExceeded
from tests.conftest import bundle, rule, target


def tier(
    id: str,
    scope: str = "global",
    region: str | None = None,
    tenant: str | None = None,
    rate: float = 10.0,
    burst: float = 1.0,
    priority: int = 0,
    match_labels: dict | None = None,
) -> RateLimitTier:
    return RateLimitTier(
        id=id,
        scope=scope,
        region=region,
        tenant=tenant,
        rate_per_second=rate,
        burst=burst,
        priority=priority,
        match_labels=match_labels or {},
    )


def test_most_specific_layer_selects_one_highest_priority_matching_tier(stack):
    stack.config.apply(
        bundle(
            1,
            [rule("api", targets=[target("b1")], ttl=60)],
            rate_limit_tiers=[
                tier("global-low", rate=1, burst=1, priority=10),
                tier("global-high", rate=100, burst=100, priority=1),
                tier("region-eu", scope="region", region="eu", rate=2, burst=2, priority=1),
                tier("tenant-vip", scope="tenant", tenant="vip", rate=3, burst=3, priority=1),
                tier(
                    "tenant-vip-canary",
                    scope="tenant",
                    tenant="vip",
                    rate=4,
                    burst=4,
                    priority=0,
                    match_labels={"env": "canary"},
                ),
            ],
        )
    )

    info = stack.resolver.explain("api", region="us", tenant="acme", client_key="c")
    assert info["rate_limit"]["tier_id"] == "global-high"

    info = stack.resolver.explain("api", region="eu", tenant="acme", client_key="c")
    assert info["rate_limit"]["tier_id"] == "region-eu"

    info = stack.resolver.explain("api", region="eu", tenant="vip", client_key="c")
    assert info["rate_limit"]["tier_id"] == "tenant-vip"

    info = stack.resolver.explain(
        "api", region="eu", tenant="vip", client_key="c", labels={"env": "canary"}
    )
    assert info["rate_limit"]["tier_id"] == "tenant-vip-canary"


def test_token_buckets_are_isolated_and_cache_hits_consume_quota(stack):
    stack.config.apply(
        bundle(
            1,
            [rule("api", targets=[target("b1")], ttl=60)],
            rate_limit_tiers=[tier("tight", rate=1, burst=1)],
        )
    )

    first = stack.resolver.resolve("api", client_key="a")
    assert first["rate_limit"]["tier_id"] == "tight"
    assert first["cached"] is False
    cached = stack.resolver.resolve("api", client_key="a")
    # The second request is a cache hit, but it still acquired a token.
    assert cached["cached"] is True
    assert cached["rate_limit"]["remaining"] == 0

    with pytest.raises(RateLimitExceeded) as exc:
        stack.resolver.resolve("api", client_key="a")
    assert exc.value.decision.reason == "rate_limit_exceeded"
    assert exc.value.decision.retry_after > 0

    # Another client has an independently initialized bucket.
    other = stack.resolver.resolve("api", client_key="b")
    assert other["rate_limit"]["remaining"] == 0
    assert other["cached"] is False


def test_buckets_are_isolated_by_tenant_and_labels(stack):
    stack.config.apply(
        bundle(
            1,
            [rule("api", targets=[target("b1")], ttl=60)],
            rate_limit_tiers=[
                tier("default", rate=1, burst=1, priority=10),
                tier("canary", rate=1, burst=1, priority=1, match_labels={"env": "canary"}),
            ],
        )
    )

    stack.resolver.resolve("api", tenant="a", client_key="c")
    # Same client and label value, but different tenant: independent bucket.
    stack.resolver.resolve("api", tenant="b", client_key="c")
    with pytest.raises(RateLimitExceeded):
        stack.resolver.resolve("api", tenant="a", client_key="c")

    stack.resolver.resolve("api", tenant="a", client_key="c2", labels={"env": "canary"})
    with pytest.raises(RateLimitExceeded):
        stack.resolver.resolve(
            "api", tenant="a", client_key="c2", labels={"env": "canary"}
        )
    # Same client/tenant with a different label signature gets its own bucket.
    answer = stack.resolver.resolve(
        "api", tenant="a", client_key="c2", labels={"env": "prod"}
    )
    assert answer["status"] == "OK"


def test_rejected_request_does_not_write_cache(stack):
    stack.config.apply(
        bundle(
            1,
            [rule("api", targets=[target("b1")], ttl=60)],
            rate_limit_tiers=[tier("tight", rate=1, burst=1)],
        )
    )

    stack.resolver.resolve("api", client_key="c")
    with pytest.raises(RateLimitExceeded):
        stack.resolver.resolve("api", client_key="c")

    # The first request consumed the only token and produced the ordinary
    # positive cache entry; the denied request did not replace it.
    entry = stack.cache.peek("api", "", "", "c")
    assert entry is not None and entry.kind == "positive"
    rejected = stack.audit.query(type_="rate_limit_rejected")[0]
    assert rejected["details"]["tier_id"] == "tight"


def test_refill_replenishes_tokens(stack):
    stack.config.apply(
        bundle(
            1,
            [rule("api", targets=[target("b1")], ttl=60)],
            rate_limit_tiers=[tier("tight", rate=2, burst=2)],
        )
    )

    stack.resolver.resolve("api", client_key="c")
    stack.resolver.resolve("api", client_key="c")
    with pytest.raises(RateLimitExceeded):
        stack.resolver.resolve("api", client_key="c")

    stack.clock.advance(1.0)
    answer = stack.resolver.resolve("api", client_key="c")
    assert answer["status"] == "OK"


def test_config_version_or_tier_change_replaces_buckets_and_audits(stack):
    stack.config.apply(
        bundle(
            1,
            [rule("api", targets=[target("b1")], ttl=60)],
            rate_limit_tiers=[tier("t1", rate=1, burst=1)],
        )
    )
    stack.resolver.resolve("api", client_key="c")

    stack.config.apply(
        bundle(
            2,
            [rule("api", targets=[target("b1")], ttl=60)],
            rate_limit_tiers=[tier("t1", rate=1, burst=1)],
        )
    )
    # Same-version policy text but a new bundle version: bucket was reset.
    stack.resolver.resolve("api", client_key="c")

    stack.config.apply(
        bundle(
            3,
            [rule("api", targets=[target("b1")], ttl=60)],
            rate_limit_tiers=[tier("t1", rate=10, burst=10)],
        )
    )
    for _ in range(3):
        stack.resolver.resolve("api", client_key="c")

    resets = stack.audit.query(type_="rate_limit_bucket_reset")
    assert len(resets) == 3
    changes = stack.audit.query(type_="rate_limit_change")
    assert changes[0]["details"]["action"] == "updated"


def test_explain_reports_limit_remaining_and_rejection_reason_without_consuming(stack):
    stack.config.apply(
        bundle(
            1,
            [rule("api", targets=[target("b1")], ttl=60)],
            rate_limit_tiers=[tier("tight", rate=1, burst=1)],
        )
    )

    info = stack.resolver.explain("api", client_key="c")
    assert info["rate_limit"]["enabled"] is True
    assert info["rate_limit"]["remaining"] == 1
    assert info["rate_limit"]["reason"] == "allowed"

    # Repeated explain calls do not consume the one token.
    assert stack.resolver.explain("api", client_key="c")["rate_limit"]["remaining"] == 1

    stack.resolver.resolve("api", client_key="c")
    info = stack.resolver.explain("api", client_key="c")
    assert info["rate_limit"]["allowed"] is False
    assert info["rate_limit"]["reason"] == "rate_limit_exceeded"
    assert info["rate_limit"]["retry_after"] > 0


@pytest.mark.parametrize(
    "kwargs,message",
    [
        ({"rate": 0, "burst": 1}, "positive"),
        ({"rate": -1, "burst": 1}, "positive"),
        ({"rate": 5, "burst": 4}, "burst"),
    ],
)
def test_invalid_rate_capacity_is_rejected(kwargs, message):
    with pytest.raises(ValidationError) as exc:
        tier("bad", **kwargs)
    assert message in str(exc.value)


def test_duplicate_priority_and_compatible_labels_is_rejected():
    with pytest.raises(ValidationError) as exc:
        ConfigBundle(
            version=1,
            defaults=Defaults(),
            rate_limit_tiers=[
                tier("a", priority=1, match_labels={"env": "canary"}),
                tier("b", priority=1, match_labels={"env": "canary", "team": "pay"}),
            ],
        )
    assert "same priority" in str(exc.value)
    assert "duplicate or otherwise compatible label conditions" in str(exc.value)


def test_duplicate_tier_id_is_rejected_even_across_layers():
    with pytest.raises(ValidationError, match="duplicate rate-limit tier id"):
        ConfigBundle(
            version=1,
            defaults=Defaults(),
            rate_limit_tiers=[tier("same", rate=1, burst=1),
                              tier("same", scope="region", region="eu",
                                   rate=1, burst=1)],
        )


def test_same_priority_contradictory_labels_and_different_layers_are_allowed():
    ConfigBundle(
        version=1,
        defaults=Defaults(),
        rate_limit_tiers=[
            tier("a", priority=1, match_labels={"env": "canary"}),
            tier("b", priority=1, match_labels={"env": "prod"}),
            tier("eu", scope="region", region="eu", priority=1),
        ],
    )
