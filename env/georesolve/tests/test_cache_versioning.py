"""Caching semantics: positive/negative TTLs and config-version invalidation."""
from __future__ import annotations

import pytest

from app.config_store import VersionConflict
from app.selection import rank_targets
from tests.conftest import bundle, rule, target


def test_cache_is_scoped_per_client(stack):
    """Same (name, region, tenant), different clients: each client gets
    its own deterministic ranking and its own cache entry."""
    targets = [target("a"), target("b"), target("c")]
    stack.config.apply(bundle(1, [rule("api", targets=targets, ttl=100)]))

    first_c1 = stack.resolver.resolve("api", client_key="c1")
    first_c3 = stack.resolver.resolve("api", client_key="c3")
    assert first_c1["cached"] is False
    assert first_c3["cached"] is False  # must not be served c1's entry

    order_c1 = [t["id"] for t in first_c1["targets"]]
    order_c3 = [t["id"] for t in first_c3["targets"]]
    assert order_c1 == [t.id for t in rank_targets("c1", targets)]
    assert order_c3 == [t.id for t in rank_targets("c3", targets)]
    assert order_c1 != order_c3  # the rankings genuinely differ
    assert first_c1["chosen"] == order_c1[0]
    assert first_c3["chosen"] == order_c3[0]

    # A repeat request from the same client still hits its own entry.
    second_c1 = stack.resolver.resolve("api", client_key="c1")
    second_c3 = stack.resolver.resolve("api", client_key="c3")
    assert second_c1["cached"] is True
    assert second_c3["cached"] is True
    assert second_c1["chosen"] == first_c1["chosen"]
    assert second_c3["chosen"] == first_c3["chosen"]


def test_positive_answer_cached_until_ttl(stack):
    stack.config.apply(bundle(1, [rule("api", targets=[target("a")], ttl=100)]))
    first = stack.resolver.resolve("api", client_key="c")
    second = stack.resolver.resolve("api", client_key="c")
    assert first["cached"] is False
    assert second["cached"] is True
    assert second["expires_at"] == first["expires_at"]

    stack.clock.advance(101)
    third = stack.resolver.resolve("api", client_key="c")
    assert third["cached"] is False


def test_negative_answer_cached_with_default_negative_ttl(stack):
    stack.config.apply(bundle(1, [], negative_ttl=45))
    first = stack.resolver.resolve("nope", client_key="c")
    second = stack.resolver.resolve("nope", client_key="c")
    assert first["status"] == "NXDOMAIN" and first["cached"] is False
    assert second["status"] == "NXDOMAIN" and second["cached"] is True
    assert second["ttl"] <= 45

    stack.clock.advance(46)
    assert stack.resolver.resolve("nope", client_key="c")["cached"] is False


def test_rule_level_negative_ttl_overrides_default(stack):
    stack.config.apply(
        bundle(1, [rule("empty", targets=[], negative_ttl=5)], negative_ttl=45)
    )
    ans = stack.resolver.resolve("empty", client_key="c")
    assert ans["status"] == "NXDOMAIN"
    assert ans["ttl"] <= 5
    stack.clock.advance(6)
    assert stack.resolver.resolve("empty", client_key="c")["cached"] is False


def test_config_change_invalidates_affected_name_immediately(stack):
    stack.config.apply(bundle(1, [rule("api", targets=[target("a")], ttl=3600,
                                       rule_version=1)]))
    old = stack.resolver.resolve("api", client_key="c")
    assert old["chosen"] == "a" and old["rule_version"] == 1

    # Bump version and change the rule: new requests must see the new rule
    # at once, even though the old answer's TTL has hours left.
    result = stack.config.apply(
        bundle(2, [rule("api", targets=[target("b")], ttl=3600, rule_version=2)])
    )
    assert result["invalidated"] == 1
    new = stack.resolver.resolve("api", client_key="c")
    assert new["cached"] is False
    assert new["chosen"] == "b"
    assert new["rule_version"] == 2
    assert new["config_version"] == 2

    invalidations = stack.audit.query(type_="cache_invalidation")
    assert any(r["details"]["name"] == "api" for r in invalidations)


def test_unaffected_names_keep_their_cache(stack):
    stack.config.apply(
        bundle(1, [
            rule("api", targets=[target("a")], ttl=3600, rule_version=1),
            rule("web", targets=[target("w")], ttl=3600, rule_version=1),
        ])
    )
    stack.resolver.resolve("api", client_key="c")
    stack.resolver.resolve("web", client_key="c")

    # Version 2 only changes "api"; "web" answers may serve until expiry.
    stack.config.apply(
        bundle(2, [
            rule("api", targets=[target("b")], ttl=3600, rule_version=2),
            rule("web", targets=[target("w")], ttl=3600, rule_version=1),
        ])
    )
    assert stack.resolver.resolve("web", client_key="c")["cached"] is True
    assert stack.resolver.resolve("api", client_key="c")["cached"] is False


def test_negative_entry_invalidated_when_rule_appears(stack):
    stack.config.apply(bundle(1, [], negative_ttl=3600))
    assert stack.resolver.resolve("api", client_key="c")["status"] == "NXDOMAIN"

    stack.config.apply(
        bundle(2, [rule("api", targets=[target("a")], rule_version=2)])
    )
    ans = stack.resolver.resolve("api", client_key="c")
    assert ans["status"] == "OK" and ans["chosen"] == "a"


def test_version_must_increase_monotonically(stack):
    stack.config.apply(bundle(3, []))
    with pytest.raises(VersionConflict):
        stack.config.apply(bundle(3, []))
    with pytest.raises(VersionConflict):
        stack.config.apply(bundle(2, []))
    stack.config.apply(bundle(4, []))  # higher is fine


def test_scheduled_rule_activates_without_new_config(stack):
    now = stack.clock()
    stack.config.apply(
        bundle(1, [rule("api", targets=[target("a")], ttl=3600, rule_version=1)])
    )
    assert stack.resolver.resolve("api", client_key="c")["chosen"] == "a"

    # Publish v2 with a rule that only becomes effective at now+100. The
    # in-effect rule is unchanged, so the cached answer must survive.
    result = stack.config.apply(
        bundle(2, [rule("api", targets=[target("b")], ttl=3600, rule_version=2,
                        effective_from=now + 100)])
    )
    assert result["invalidated"] == 0
    before = stack.resolver.resolve("api", client_key="c")
    assert before["chosen"] == "a" and before["rule_version"] == 1
    assert before["cached"] is True  # old answer may serve until its expiry

    # Entries computed after the schedule is known are clamped to it.
    stack.cache.clear()
    fresh = stack.resolver.resolve("api", client_key="c")
    assert fresh["cached"] is False
    assert fresh["expires_at"] <= now + 100

    # Once the activation time passes, new requests immediately use v2.
    stack.clock.advance(101)
    after = stack.resolver.resolve("api", client_key="c")
    assert after["chosen"] == "b"
    assert after["rule_version"] == 2
    assert after["cached"] is False


def test_scheduled_rule_for_new_name_activates(stack):
    now = stack.clock()
    stack.config.apply(
        bundle(1, [rule("new", targets=[target("a")], rule_version=1,
                        effective_from=now + 50)])
    )
    # Not yet effective: negative answer, clamped to the activation time.
    ans = stack.resolver.resolve("new", client_key="c")
    assert ans["status"] == "NXDOMAIN"
    assert ans["expires_at"] <= now + 50

    stack.clock.advance(51)
    ans = stack.resolver.resolve("new", client_key="c")
    assert ans["status"] == "OK" and ans["chosen"] == "a"


def test_config_persists_across_restart(tmp_path, clock):
    from tests.conftest import make_stack

    db = str(tmp_path / "persist.db")
    stack1 = make_stack(db, clock)
    stack1.config.apply(bundle(5, [rule("api", targets=[target("a")],
                                        rule_version=5)]))
    stack2 = make_stack(db, clock)
    restored = stack2.config.load_persisted()
    assert restored == 5
    ans = stack2.resolver.resolve("api", client_key="c")
    assert ans["chosen"] == "a" and ans["config_version"] == 5
