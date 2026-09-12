"""Health-based failover: deterministic order within a config version,
convergence after recovery."""
from __future__ import annotations

from tests.conftest import bundle, make_stack, rule, target

TARGETS = [target("a", 1), target("b", 1), target("c", 1)]


def setup(stack):
    stack.config.apply(
        bundle(1, [rule("api", targets=TARGETS, ttl=3600, rule_version=1)])
    )


def test_failover_follows_deterministic_order(stack):
    setup(stack)
    first = stack.resolver.resolve("api", client_key="client-x")
    order = [t["id"] for t in first["targets"]]
    assert first["chosen"] == order[0]

    # The preferred target loses health: within the same config version the
    # answer must switch to the next target in the deterministic order.
    stack.health.set(order[0], False)
    second = stack.resolver.resolve("api", client_key="client-x")
    assert second["cached"] is False
    assert second["chosen"] == order[1]
    assert second["rule_version"] == first["rule_version"]

    stack.health.set(order[1], False)
    third = stack.resolver.resolve("api", client_key="client-x")
    assert third["chosen"] == order[2]


def test_recovery_flips_back_and_nodes_converge(tmp_path, clock):
    node1 = make_stack(str(tmp_path / "n1.db"), clock)
    node2 = make_stack(str(tmp_path / "n2.db"), clock)
    setup(node1)
    setup(node2)

    key = "client-y"
    healthy1 = node1.resolver.resolve("api", client_key=key)["chosen"]
    healthy2 = node2.resolver.resolve("api", client_key=key)["chosen"]
    assert healthy1 == healthy2

    # Both nodes see the target fail -> both switch to the same fallback.
    for node in (node1, node2):
        node.health.set(healthy1, False)
    assert node1.resolver.resolve("api", client_key=key)["chosen"] == \
           node2.resolver.resolve("api", client_key=key)["chosen"]

    # Both see it recover -> both deterministically return to the original.
    for node in (node1, node2):
        node.health.set(healthy1, True)
    assert node1.resolver.resolve("api", client_key=key)["chosen"] == healthy1
    assert node2.resolver.resolve("api", client_key=key)["chosen"] == healthy1


def test_health_change_invalidates_cached_answer(stack):
    setup(stack)
    key = "client-z"
    first = stack.resolver.resolve("api", client_key=key)
    assert stack.resolver.resolve("api", client_key=key)["cached"] is True

    stack.health.set(first["chosen"], False)
    after = stack.resolver.resolve("api", client_key=key)
    assert after["cached"] is False
    assert after["chosen"] != first["chosen"]

    reasons = [
        r["details"]["reason"]
        for r in stack.audit.query(type_="cache_invalidation")
    ]
    assert "health_changed" in reasons


def test_all_unhealthy_still_deterministic_and_degraded(tmp_path, clock):
    node1 = make_stack(str(tmp_path / "n1.db"), clock)
    node2 = make_stack(str(tmp_path / "n2.db"), clock)
    setup(node1)
    setup(node2)
    for node in (node1, node2):
        for t in TARGETS:
            node.health.set(t.id, False)
    a1 = node1.resolver.resolve("api", client_key="k")
    a2 = node2.resolver.resolve("api", client_key="k")
    assert a1["degraded"] is True and a2["degraded"] is True
    assert a1["chosen"] == a2["chosen"]  # fail-open, same deterministic pick
