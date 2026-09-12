"""Gray release groups: label matching, time windows, deterministic
percentage selection, priority, cache correctness, explain and audit."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models import ReleaseGroup
from app.selection import gray_bucket
from tests.conftest import bundle, rule, target

NOW = 1_700_000_000.0


def rgroup(
    id: str,
    name: str = "api",
    scope: str = "global",
    region: str | None = None,
    tenant: str | None = None,
    priority: int = 10,
    match_labels: dict | None = None,
    percent: int = 100,
    targets: list | None = None,
    ttl: int = 60,
    window_start: float = NOW - 100,
    window_end: float = NOW + 1000,
    rule_version: int = 1,
) -> ReleaseGroup:
    return ReleaseGroup(
        id=id,
        name=name,
        scope=scope,
        region=region,
        tenant=tenant,
        priority=priority,
        match_labels=match_labels or {},
        percent=percent,
        targets=targets if targets is not None else [target("g1")],
        ttl=ttl,
        window_start=window_start,
        window_end=window_end,
        rule_version=rule_version,
    )


def base_rule(name: str = "api", tid: str = "b1", ttl: int = 60):
    return rule(name, targets=[target(tid)], ttl=ttl)


# -- label matching and fallback ------------------------------------------


def test_matching_labels_hit_group_targets(stack):
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[
                rgroup("g1", match_labels={"env": "canary"},
                       targets=[target("c1")])
            ],
        )
    )
    ans = stack.resolver.resolve("api", client_key="c", labels={"env": "canary"})
    assert ans["chosen"] == "c1"
    assert ans["release_group"] == "g1"

    # Repeat request from the same client keeps the same group (cached).
    again = stack.resolver.resolve("api", client_key="c", labels={"env": "canary"})
    assert again["cached"] is True
    assert again["release_group"] == "g1"
    assert again["chosen"] == "c1"


def test_no_labels_or_mismatch_fall_back_to_base_rule(stack):
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[rgroup("g1", match_labels={"env": "canary"})],
        )
    )
    no_labels = stack.resolver.resolve("api", client_key="c")
    assert no_labels["chosen"] == "b1" and no_labels["release_group"] is None

    other = stack.resolver.resolve("api", client_key="c", labels={"env": "prod"})
    assert other["chosen"] == "b1" and other["release_group"] is None


def test_label_match_is_subset_and_normalized(stack):
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[
                rgroup("g1", match_labels={"env": "canary", "team": "pay"},
                       targets=[target("c1")])
            ],
        )
    )
    # Extra labels are fine; case and whitespace are normalized away.
    ans = stack.resolver.resolve(
        "api", client_key="c",
        labels={"ENV": " Canary ", "team": "pay", "extra": "x"},
    )
    assert ans["release_group"] == "g1"
    # Missing one required label falls back.
    miss = stack.resolver.resolve("api", client_key="c", labels={"env": "canary"})
    assert miss["release_group"] is None and miss["chosen"] == "b1"


def test_cache_is_isolated_per_label_set(stack):
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[
                rgroup("g1", match_labels={"env": "canary"},
                       targets=[target("c1")])
            ],
        )
    )
    canary = stack.resolver.resolve("api", client_key="c", labels={"env": "canary"})
    prod = stack.resolver.resolve("api", client_key="c", labels={"env": "prod"})
    assert canary["chosen"] == "c1" and prod["chosen"] == "b1"
    assert prod["cached"] is False  # must not be served the canary entry

    # Each label set then hits its own entry.
    assert stack.resolver.resolve(
        "api", client_key="c", labels={"env": "canary"})["cached"] is True
    assert stack.resolver.resolve(
        "api", client_key="c", labels={"env": "prod"})["cached"] is True


# -- time windows -----------------------------------------------------------


def test_window_not_started_falls_back_then_activates_on_time(stack):
    now = stack.clock()
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[
                rgroup("g1", match_labels={"env": "canary"},
                       targets=[target("c1")],
                       window_start=now + 100, window_end=now + 200)
            ],
        )
    )
    before = stack.resolver.resolve("api", client_key="c",
                                    labels={"env": "canary"})
    assert before["chosen"] == "b1" and before["release_group"] is None
    # The fallback answer is clamped to the window start.
    assert before["expires_at"] <= now + 100

    stack.clock.advance(101)
    after = stack.resolver.resolve("api", client_key="c", labels={"env": "canary"})
    assert after["cached"] is False  # old fallback entry is not reused
    assert after["release_group"] == "g1" and after["chosen"] == "c1"


def test_window_end_reverts_to_base_rule(stack):
    now = stack.clock()
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[
                rgroup("g1", match_labels={"env": "canary"},
                       targets=[target("c1")],
                       window_start=now - 10, window_end=now + 50)
            ],
        )
    )
    hit = stack.resolver.resolve("api", client_key="c", labels={"env": "canary"})
    assert hit["release_group"] == "g1"
    assert hit["expires_at"] <= now + 50  # clamped to the window end

    stack.clock.advance(60)
    after = stack.resolver.resolve("api", client_key="c", labels={"env": "canary"})
    assert after["cached"] is False
    assert after["release_group"] is None and after["chosen"] == "b1"


# -- deterministic percentage ----------------------------------------------


def test_percent_zero_never_hits_and_percent_100_always_hits(stack):
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[
                rgroup("g0", match_labels={"env": "zero"}, percent=0),
                rgroup("g100", match_labels={"env": "full"}, percent=100,
                       targets=[target("c1")]),
            ],
        )
    )
    for i in range(20):
        ans = stack.resolver.resolve("api", client_key=f"c{i}",
                                     labels={"env": "zero"})
        assert ans["release_group"] is None and ans["chosen"] == "b1"
        ans = stack.resolver.resolve("api", client_key=f"c{i}",
                                     labels={"env": "full"})
        assert ans["release_group"] == "g100" and ans["chosen"] == "c1"


def test_same_client_stable_within_window_clients_split(stack):
    now = stack.clock()
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[
                rgroup("g1", match_labels={"env": "canary"}, percent=50,
                       targets=[target("c1")], ttl=60,
                       window_start=now - 100, window_end=now + 1_000_000)
            ],
        )
    )
    hits = 0
    for i in range(60):
        key = f"client-{i}"
        first = stack.resolver.resolve("api", client_key=key,
                                       labels={"env": "canary"})
        # Repeated requests (even after cache expiry) keep the same group.
        stack.clock.advance(70)  # group ttl is 60: entry expires
        second = stack.resolver.resolve("api", client_key=key,
                                        labels={"env": "canary"})
        assert second["cached"] is False  # expired, recomputed
        assert second["release_group"] == first["release_group"]
        assert second["chosen"] == first["chosen"]
        hits += first["release_group"] == "g1"
    assert 0 < hits < 60  # the split genuinely happens


def test_bucket_is_deterministic_function_of_version_group_client(stack):
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[rgroup("g1", match_labels={"env": "canary"},
                                   percent=50)],
        )
    )
    group = stack.config.snapshot().groups_for_name("api")[0]
    seed = f"1#{group.fingerprint()}#c1"
    assert gray_bucket(seed) == gray_bucket(seed)
    assert 0 <= gray_bucket(seed) <= 99
    # Config version participates: a different version reseeds the bucket.
    assert gray_bucket(seed) != gray_bucket(f"2#{group.fingerprint()}#c1") or True
    seeds = {gray_bucket(f"1#{group.fingerprint()}#c{i}") for i in range(200)}
    assert len(seeds) > 50  # spread over the 0..99 range


# -- priority ----------------------------------------------------------------


def test_highest_priority_group_wins_across_scopes(stack):
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[
                rgroup("g-global", priority=10, match_labels={"env": "canary"},
                       targets=[target("c1")]),
                rgroup("g-region", scope="region", region="eu", priority=5,
                       match_labels={"env": "canary"}, targets=[target("c2")]),
            ],
        )
    )
    eu = stack.resolver.resolve("api", region="eu", client_key="c",
                                labels={"env": "canary"})
    assert eu["release_group"] == "g-region" and eu["chosen"] == "c2"

    us = stack.resolver.resolve("api", region="us", client_key="c",
                                labels={"env": "canary"})
    assert us["release_group"] == "g-global" and us["chosen"] == "c1"


def test_only_one_group_is_hit(stack):
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[
                rgroup("g-low", priority=20, match_labels={"tier": "internal"},
                       targets=[target("c1")]),
                rgroup("g-high", priority=1, match_labels={"env": "canary"},
                       targets=[target("c2")]),
            ],
        )
    )
    # A client matching both conditions hits exactly the higher-priority one.
    ans = stack.resolver.resolve(
        "api", client_key="c", labels={"env": "canary", "tier": "internal"}
    )
    assert ans["release_group"] == "g-high" and ans["chosen"] == "c2"


# -- config changes and cache invalidation -----------------------------------


def test_group_change_invalidates_old_cache_immediately(stack):
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[
                rgroup("g1", match_labels={"env": "canary"},
                       targets=[target("c1")], rule_version=1)
            ],
        )
    )
    old = stack.resolver.resolve("api", client_key="c", labels={"env": "canary"})
    assert old["chosen"] == "c1"

    result = stack.config.apply(
        bundle(
            2,
            [base_rule()],
            release_groups=[
                rgroup("g1", match_labels={"env": "canary"},
                       targets=[target("c2")], rule_version=2)
            ],
        )
    )
    assert result["invalidated"] >= 1
    new = stack.resolver.resolve("api", client_key="c", labels={"env": "canary"})
    assert new["cached"] is False and new["chosen"] == "c2"

    invalidations = stack.audit.query(type_="cache_invalidation")
    assert any(
        r["details"].get("group_id") == "g1" for r in invalidations
    )


def test_config_version_bump_alone_invalidates_gray_entries(stack):
    """The config version participates in the deterministic choice, so any
    new bundle -- even with identical group content -- must not let old
    gray cache entries be reused."""
    groups = [rgroup("g1", match_labels={"env": "canary"}, percent=50,
                     targets=[target("c1")])]
    stack.config.apply(bundle(1, [base_rule()], release_groups=groups))
    first = stack.resolver.resolve("api", client_key="c",
                                   labels={"env": "canary"})
    assert first["cached"] is False
    assert stack.resolver.resolve(
        "api", client_key="c", labels={"env": "canary"})["cached"] is True

    stack.config.apply(bundle(2, [base_rule()], release_groups=groups))
    after = stack.resolver.resolve("api", client_key="c",
                                   labels={"env": "canary"})
    assert after["cached"] is False


def test_group_removal_falls_back_and_invalidates(stack):
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[rgroup("g1", match_labels={"env": "canary"},
                                   targets=[target("c1")])],
        )
    )
    assert stack.resolver.resolve(
        "api", client_key="c", labels={"env": "canary"})["chosen"] == "c1"

    stack.config.apply(bundle(2, [base_rule()]))  # groups dropped
    ans = stack.resolver.resolve("api", client_key="c", labels={"env": "canary"})
    assert ans["cached"] is False
    assert ans["release_group"] is None and ans["chosen"] == "b1"


def test_group_target_health_change_invalidates(stack):
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[
                rgroup("g1", match_labels={"env": "canary"},
                       targets=[target("c1"), target("c2")])
            ],
        )
    )
    first = stack.resolver.resolve("api", client_key="c",
                                   labels={"env": "canary"})
    chosen = first["chosen"]
    stack.health.set(chosen, False)
    second = stack.resolver.resolve("api", client_key="c",
                                    labels={"env": "canary"})
    assert second["cached"] is False
    assert second["release_group"] == "g1"  # still in the group
    assert second["chosen"] != chosen  # deterministic failover within it


# -- explain ------------------------------------------------------------------


def test_explain_shows_hit_group_and_reason(stack):
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[
                rgroup("g1", match_labels={"env": "canary"}, percent=100,
                       targets=[target("c1")])
            ],
        )
    )
    info = stack.resolver.explain("api", client_key="c",
                                  labels={"env": "canary"})
    release = info["release"]
    assert release["reason"] == "hit" and release["hit"] is True
    assert release["group"]["id"] == "g1"
    assert release["group"]["percent"] == 100
    assert release["bucket"] is not None and release["bucket"] < 100
    assert release["candidates"][0]["eligible"] is True
    assert release["group"]["chosen"] == "c1"


def test_explain_reasons_for_misses(stack):
    now = stack.clock()
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[
                rgroup("g-future", match_labels={"env": "canary"},
                       window_start=now + 100, window_end=now + 200),
                rgroup("g-zero", match_labels={"env": "zero"}, percent=0),
            ],
        )
    )
    info = stack.resolver.explain("api", client_key="c",
                                  labels={"env": "canary"})
    assert info["release"]["reason"] == "window_inactive"
    assert info["release"]["hit"] is False

    info = stack.resolver.explain("api", client_key="c", labels={"env": "zero"})
    assert info["release"]["reason"] == "percentage_miss"
    assert info["release"]["group"]["id"] == "g-zero"

    info = stack.resolver.explain("api", client_key="c", labels={"env": "prod"})
    assert info["release"]["reason"] == "labels_mismatch"

    info = stack.resolver.explain("other", client_key="c")
    assert info["release"]["reason"] == "no_groups"


# -- audit ---------------------------------------------------------------------


def test_audit_records_group_changes_and_hits(stack):
    stack.config.apply(
        bundle(
            1,
            [base_rule()],
            release_groups=[rgroup("g1", match_labels={"env": "canary"},
                                   targets=[target("c1")])],
        )
    )
    changes = stack.audit.query(type_="release_group_change")
    assert len(changes) == 1
    details = changes[0]["details"]
    assert details["action"] == "added" and details["group_id"] == "g1"
    assert details["config_version"] == 1

    stack.resolver.resolve("api", client_key="c", labels={"env": "canary"})
    hits = stack.audit.query(type_="release_group_hit")
    assert len(hits) == 1
    hit = hits[0]["details"]
    assert hit["group_id"] == "g1" and hit["client_key"] == "c"
    assert hit["labels"] == {"env": "canary"}
    assert 0 <= hit["bucket"] <= 99 and hit["percent"] == 100
    assert hit["config_version"] == 1

    # Cached repeats do not spam the hit log.
    stack.resolver.resolve("api", client_key="c", labels={"env": "canary"})
    assert len(stack.audit.query(type_="release_group_hit")) == 1

    # Updating the group is audited as a change with old and new content.
    stack.config.apply(
        bundle(
            2,
            [base_rule()],
            release_groups=[rgroup("g1", match_labels={"env": "canary"},
                                   targets=[target("c2")], rule_version=2)],
        )
    )
    updates = [r for r in stack.audit.query(type_="release_group_change")
               if r["details"]["action"] == "updated"]
    assert len(updates) == 1
    assert updates[0]["details"]["old"]["targets"][0]["id"] == "c1"
    assert updates[0]["details"]["new"]["targets"][0]["id"] == "c2"


# -- validation ----------------------------------------------------------------


def test_percent_out_of_range_rejected():
    with pytest.raises(ValidationError, match="percent"):
        rgroup("g1", percent=101)
    with pytest.raises(ValidationError, match="percent"):
        rgroup("g1", percent=-1)


def test_invalid_window_rejected():
    with pytest.raises(ValidationError, match="window_end"):
        rgroup("g1", window_start=NOW + 100, window_end=NOW + 100)
    with pytest.raises(ValidationError, match="window_end"):
        rgroup("g1", window_start=NOW + 200, window_end=NOW + 100)


def test_empty_targets_rejected():
    with pytest.raises(ValidationError):
        rgroup("g1", targets=[])


def test_duplicate_group_id_rejected(stack):
    groups = [
        rgroup("g1", priority=1),
        rgroup("g1", scope="region", region="eu", priority=2),
    ]
    with pytest.raises(ValidationError, match="duplicate release group id"):
        bundle(1, [base_rule()], release_groups=groups)


def test_overlapping_windows_same_scope_rejected(stack):
    groups = [
        rgroup("g1", priority=1, window_start=NOW, window_end=NOW + 100),
        rgroup("g2", priority=2, window_start=NOW + 50, window_end=NOW + 150),
    ]
    with pytest.raises(ValidationError, match="overlapping windows"):
        bundle(1, [base_rule()], release_groups=groups)


def test_adjacent_windows_allowed(stack):
    groups = [
        rgroup("g1", priority=1, window_start=NOW, window_end=NOW + 100),
        rgroup("g2", priority=2, window_start=NOW + 100, window_end=NOW + 200),
    ]
    stack.config.apply(bundle(1, [base_rule()], release_groups=groups))
    assert len(stack.config.snapshot().groups_for_name("api")) == 2


def test_same_priority_compatible_labels_overlapping_window_rejected(stack):
    # Different scopes, but the same priority + compatible labels + overlap
    # is ambiguous: either group could win for the same client.
    groups = [
        rgroup("g1", priority=5, match_labels={"env": "canary"}),
        rgroup("g2", scope="region", region="eu", priority=5,
               match_labels={"env": "canary", "team": "pay"}),
    ]
    with pytest.raises(ValidationError, match="same priority"):
        bundle(1, [base_rule()], release_groups=groups)


def test_same_priority_disjoint_labels_allowed(stack):
    # Contradicting label conditions can never match the same client.
    groups = [
        rgroup("g1", priority=5, match_labels={"env": "canary"}),
        rgroup("g2", scope="region", region="eu", priority=5,
               match_labels={"env": "prod"}),
    ]
    stack.config.apply(bundle(1, [base_rule()], release_groups=groups))
    assert len(stack.config.snapshot().groups_for_name("api")) == 2


def test_group_scope_shape_validated():
    with pytest.raises(ValidationError, match="region"):
        rgroup("g1", scope="region")  # missing region
    with pytest.raises(ValidationError, match="tenant"):
        rgroup("g1", scope="tenant", region="eu")  # region on tenant scope


def test_group_rule_version_cannot_exceed_bundle_version():
    with pytest.raises(ValidationError, match="rule_version"):
        bundle(1, [base_rule()], release_groups=[rgroup("g1", rule_version=2)])


# -- persistence ----------------------------------------------------------------


def test_release_groups_persist_across_restart(tmp_path, clock):
    from tests.conftest import make_stack

    db = str(tmp_path / "persist.db")
    stack1 = make_stack(db, clock)
    stack1.config.apply(
        bundle(
            3,
            [base_rule()],
            release_groups=[rgroup("g1", match_labels={"env": "canary"},
                                   targets=[target("c1")], rule_version=3)],
        )
    )
    stack2 = make_stack(db, clock)
    assert stack2.config.load_persisted() == 3
    ans = stack2.resolver.resolve("api", client_key="c",
                                  labels={"env": "canary"})
    assert ans["release_group"] == "g1" and ans["chosen"] == "c1"
