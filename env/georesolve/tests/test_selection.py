"""Deterministic weighted selection."""
from __future__ import annotations

from collections import Counter

from app.selection import rank_targets
from tests.conftest import bundle, make_stack, rule, target


def test_ranking_is_deterministic_and_total():
    targets = [target("a", 3), target("b", 1), target("c", 1)]
    first = rank_targets("client-1", targets)
    for _ in range(50):
        assert [t.id for t in rank_targets("client-1", targets)] == \
               [t.id for t in first]
    assert len(first) == 3  # total order, everyone ranked


def test_weight_zero_ranks_last():
    targets = [target("z", 0), target("a", 1), target("b", 1)]
    ranked = rank_targets("client-9", targets)
    assert ranked[-1].id == "z"


def test_weights_skew_selection_distribution():
    targets = [target("heavy", 4), target("light", 1)]
    counts = Counter(
        rank_targets(f"client-{i}", targets)[0].id for i in range(4000)
    )
    ratio = counts["heavy"] / (counts["heavy"] + counts["light"])
    assert 0.72 < ratio < 0.88  # expected ~0.8


def test_same_inputs_same_choice_across_nodes(tmp_path, clock):
    """Two independent resolver instances (two 'nodes') agree."""
    rules = [rule("api", "global",
                  targets=[target("a", 2), target("b", 1), target("c", 1)],
                  rule_version=1)]
    node1 = make_stack(str(tmp_path / "n1.db"), clock)
    node2 = make_stack(str(tmp_path / "n2.db"), clock)
    node1.config.apply(bundle(1, rules))
    node2.config.apply(bundle(1, rules))
    for i in range(50):
        key = f"client-{i}"
        a1 = node1.resolver.resolve("api", client_key=key)
        a2 = node2.resolver.resolve("api", client_key=key)
        assert a1["chosen"] == a2["chosen"]
        assert [t["id"] for t in a1["targets"]] == [t["id"] for t in a2["targets"]]
