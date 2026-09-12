"""Health registry thresholds and the async checker."""
from __future__ import annotations

import asyncio

from app.health import HealthChecker, HealthRegistry
from tests.conftest import bundle, rule, target


def test_thresholded_transitions(clock):
    reg = HealthRegistry(clock)
    assert reg.is_healthy("t1") is True  # unknown fails open

    assert reg.report("t1", False, "boom", fail_threshold=2) is None
    assert reg.is_healthy("t1") is True  # one failure is not enough
    assert reg.report("t1", False, "boom", fail_threshold=2) == (True, False)
    assert reg.is_healthy("t1") is False

    assert reg.report("t1", True, fail_threshold=2, pass_threshold=2) is None
    assert reg.is_healthy("t1") is False
    assert reg.report("t1", True, fail_threshold=2, pass_threshold=2) == (False, True)
    assert reg.is_healthy("t1") is True


def test_success_resets_failure_count(clock):
    reg = HealthRegistry(clock)
    reg.report("t1", False, fail_threshold=2)
    reg.report("t1", True, fail_threshold=2)
    assert reg.report("t1", False, fail_threshold=2) is None
    assert reg.is_healthy("t1") is True


def test_checker_probes_targets_and_audits_transitions(stack):
    stack.config.apply(
        bundle(1, [rule("api", targets=[target("a"), target("b")], rule_version=1)])
    )
    failures = {"a": False, "b": True}

    async def probe(address, timeout):
        snap = stack.config.snapshot()
        for r in snap.all_rules():
            for t in r.targets:
                if t.address == address:
                    ok = failures.get(t.id, True)
                    return ok, None if ok else "connection refused"
        return True, None

    checker = HealthChecker(
        stack.health, stack.config, stack.audit,
        fail_threshold=2, pass_threshold=1, prober=probe,
    )

    asyncio.run(checker.check_once())
    assert stack.health.is_healthy("a") is True  # threshold not reached
    asyncio.run(checker.check_once())
    assert stack.health.is_healthy("a") is False
    assert stack.health.is_healthy("b") is True

    failures["a"] = True
    asyncio.run(checker.check_once())
    assert stack.health.is_healthy("a") is True

    changes = stack.audit.query(type_="health_change")
    transitions = [(r["details"]["target_id"], r["details"]["new"]) for r in changes]
    assert ("a", False) in transitions
    assert ("a", True) in transitions
