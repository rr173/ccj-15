"""Tenant-group budget inheritance and temporary override tests."""
from __future__ import annotations

import threading

import pytest

from app.audit import AuditLog
from app.metering import (
    BudgetGroupSpec,
    BudgetSpec,
    MeteringConflict,
    MeteringNotFound,
    MeteringStore,
    MeteringValidationError,
    OverrideSpec,
    PERIOD_DAY,
    RESULT_SERVED,
    SOURCE_GROUP,
    SOURCE_OVERRIDE,
    SOURCE_TENANT,
    PolicyDenied,
    period_start,
)
from app.storage import connect


@pytest.fixture
def metering(tmp_path, clock):
    db = connect(str(tmp_path / "groups.db"))
    audit = AuditLog(db, clock)
    store = MeteringStore(db, audit, clock)
    return store


def serve(store, eid=None, tenant="acme", client="c1", **kw):
    base = dict(
        tenant=tenant,
        client_key=client,
        name="api",
        region="eu",
        rule_scope="region",
        rule_version=1,
        group_id=None,
        config_version=1,
        result=RESULT_SERVED,
        quantity=1,
    )
    base.update(kw)
    if eid is not None:
        base["event_id"] = eid
    return store.record_event(**base)


def make_group(store, gid="g1", amount=10.0, policy="reject",
               parent=None, actor="root", thresholds=None,
               period_type=PERIOD_DAY, expected_version=None):
    spec = BudgetGroupSpec(
        id=gid,
        parent_id=parent,
        period_type=period_type if amount is not None else None,
        amount=amount,
        alert_thresholds=([1.0] if thresholds is None else thresholds)
        if amount is not None
        else None,
        over_policy=policy if amount is not None else None,
        expected_version=expected_version,
    )
    return store.upsert_group(spec, actor=actor)


# -- inheritance resolution ---------------------------------------------------


def test_tenant_inherits_group_default(metering):
    make_group(metering, amount=3.0)
    group, changed = metering.move_member("acme", "g1", actor="root")
    assert changed and group["group_id"] == "g1"

    policy = metering.resolve_policy("acme")
    assert policy is not None
    assert policy.source == SOURCE_GROUP
    assert policy.source_id == "g1"
    assert policy.source_version == 1
    assert policy.amount == 3.0
    # The decision and the public view carry full attribution.
    d = metering.check("acme")
    assert d.amount == 3.0
    assert d.origin["source"] == SOURCE_GROUP
    assert d.public()["policy_source"] == SOURCE_GROUP

    status = metering.budget_status("acme")
    assert status["budget"]["source"] == SOURCE_GROUP
    assert status["policy_origin"]["source_version"] == 1
    # an explicit data-plane resolution is audited with its source/version
    metering.check("acme", audit_resolution=True)
    resolutions = metering._audit.query("budget_resolution", limit=5)
    assert resolutions and resolutions[0]["details"]["source"] == SOURCE_GROUP
    assert resolutions[0]["details"]["source_id"] == "g1"
    # but the explain-style projection leaves no audit
    before = len(metering._audit.query("budget_resolution", limit=1000))
    metering.check("acme")
    after = len(metering._audit.query("budget_resolution", limit=1000))
    assert before == after


def test_dedicated_tenant_budget_overrides_group_default(metering):
    make_group(metering, amount=3.0)
    metering.move_member("acme", "g1", actor="root")
    metering.upsert_budget(
        BudgetSpec(tenant="acme", amount=100.0, alert_thresholds=[1.0]),
        actor="root",
    )
    policy = metering.resolve_policy("acme")
    assert policy.source == SOURCE_TENANT
    assert policy.amount == 100.0


def test_inheritance_walks_parent_chain(metering):
    # base defines the policy; child and grandchild only carry inheritance.
    make_group(metering, gid="base", amount=7.0)
    make_group(metering, gid="child", amount=None, parent="base")
    make_group(metering, gid="grandchild", amount=None, parent="child")
    metering.move_member("acme", "grandchild", actor="root")
    policy = metering.resolve_policy("acme")
    assert policy.source == SOURCE_GROUP
    assert policy.source_id == "base"
    assert policy.group_id == "base"
    assert policy.member_group_id == "grandchild"
    assert policy.amount == 7.0


def test_group_without_policy_and_without_parent_is_rejected(metering):
    with pytest.raises(MeteringValidationError):
        metering.upsert_group(
            BudgetGroupSpec(id="empty"), actor="root"
        )


def test_cyclic_inheritance_is_rejected_and_audited(metering):
    make_group(metering, gid="a", amount=1.0)
    make_group(metering, gid="b", amount=2.0)
    # a -> b
    g, _ = metering.upsert_group(
        BudgetGroupSpec(id="a", parent_id="b", period_type=PERIOD_DAY,
                        amount=1.0, alert_thresholds=[1.0],
                        over_policy="reject"),
        actor="root",
    )
    assert g["parent_id"] == "b"
    # closing the loop b -> a must be refused
    with pytest.raises(PolicyDenied):
        metering.upsert_group(
            BudgetGroupSpec(id="b", parent_id="a", period_type=PERIOD_DAY,
                            amount=2.0, alert_thresholds=[1.0],
                            over_policy="reject"),
            actor="root",
        )
    denials = [
        r for r in metering._audit.query("budget_policy_denied", limit=50)
        if r["details"]["reason"] == "cyclic_inheritance"
    ]
    assert denials


def test_self_parent_is_rejected(metering):
    make_group(metering, gid="solo", amount=1.0)
    with pytest.raises(PolicyDenied):
        metering.upsert_group(
            BudgetGroupSpec(id="solo", parent_id="solo", period_type=PERIOD_DAY,
                            amount=1.0, alert_thresholds=[1.0],
                            over_policy="reject"),
            actor="root",
        )


# -- immediate re-resolution after changes ------------------------------------


def test_group_policy_change_takes_effect_immediately_and_bumps_version(metering):
    make_group(metering, amount=100.0)
    metering.move_member("acme", "g1", actor="root")
    assert metering.check("acme").amount == 100.0

    group, created = metering.upsert_group(
        BudgetGroupSpec(id="g1", period_type=PERIOD_DAY, amount=1.0,
                        alert_thresholds=[1.0], over_policy="reject",
                        expected_version=1),
        actor="root",
    )
    assert created is False and group["version"] == 2
    policy = metering.resolve_policy("acme")
    assert policy.amount == 1.0 and policy.source_version == 2
    serve(metering, eid="e1")
    assert metering.check("acme").allowed is False


def test_member_migration_takes_effect_immediately(metering, clock):
    make_group(metering, gid="loose", amount=100.0)
    make_group(metering, gid="tight", amount=1.0)
    metering.move_member("acme", "loose", actor="root")
    assert metering.check("acme").allowed is True
    membership, changed = metering.move_member("acme", "tight", actor="root")
    assert changed is True and membership["version"] == 2
    assert metering.resolve_policy("acme").source_id == "tight"
    serve(metering, eid="e1")
    assert metering.check("acme").allowed is False


def test_concurrent_member_migration_one_wins(metering):
    make_group(metering, gid="a", amount=1.0)
    make_group(metering, gid="b", amount=2.0)
    metering.move_member("acme", "a", actor="root")  # version 1
    # Both threads observe version 1 and then race to write; the conditional
    # UPDATE lets exactly one win and rejects the other with a conflict.
    membership = metering.get_membership("acme")
    assert membership["version"] == 1
    outcome = {"a": 0, "b": 0, "conflict": 0}
    lock = threading.Lock()

    def move(target):
        try:
            metering.move_member(
                "acme", target, actor="x",
                expected_version=membership["version"],
            )
            with lock:
                outcome[target] += 1
        except MeteringConflict:
            with lock:
                outcome["conflict"] += 1

    barrier = threading.Barrier(2)

    def race(target):
        barrier.wait()
        move(target)

    threads = [
        threading.Thread(target=race, args=("a",)),
        threading.Thread(target=race, args=("b",)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcome["conflict"] == 1
    assert outcome["a"] + outcome["b"] == 1
    # The winner's write is the surviving membership, at version 2.
    final = metering.get_membership("acme")
    assert final["version"] == 2
    assert final["group_id"] in ("a", "b")


# -- temporary overrides: approval workflow -----------------------------------


def _request_override(metering, tenant="acme", *, requester="ops",
                      approver="admin", amount=1.0, start=None, end=None,
                      policy="reject"):
    now = metering._clock()
    spec = OverrideSpec(
        tenant=tenant,
        amount=amount,
        alert_thresholds=[1.0],
        over_policy=policy,
        window_start=start if start is not None else now - 10,
        window_end=end if end is not None else now + 3600,
    )
    ov = metering.request_override(spec, tenant=tenant, actor=requester)
    approved = metering.decide_override(
        ov["id"], True, actor=approver,
    )
    return ov, approved


def test_override_requires_a_different_approver(metering):
    ov, _ = _request_override(metering, requester="ops", approver="boss")
    assert ov["status"] == "pending"
    with pytest.raises(PolicyDenied):
        metering.decide_override(ov["id"], True, actor="ops")
    rejected_self = [
        r for r in metering._audit.query("budget_policy_denied", limit=50)
        if r["details"]["reason"] == "self_approval"
    ]
    assert rejected_self


def test_approved_active_override_has_top_precedence(metering):
    make_group(metering, amount=100.0)
    metering.move_member("acme", "g1", actor="root")
    metering.upsert_budget(
        BudgetSpec(tenant="acme", amount=50.0, alert_thresholds=[1.0]),
        actor="root",
    )
    _, approved = _request_override(
        metering, amount=1.0, requester="ops", approver="boss"
    )
    assert approved["status"] == "approved"
    policy = metering.resolve_policy("acme")
    assert policy.source == SOURCE_OVERRIDE
    assert policy.source_id == approved["id"]
    assert policy.source_version == approved["version"]
    serve(metering, eid="e1")
    d = metering.check("acme")
    assert d.allowed is False
    assert d.origin["override_id"] == approved["id"]


def test_rejected_override_never_applies(metering):
    make_group(metering, amount=100.0)
    metering.move_member("acme", "g1", actor="root")
    now = metering._clock()
    spec = OverrideSpec(
        tenant="acme", amount=1.0, alert_thresholds=[1.0],
        window_start=now - 10, window_end=now + 3600,
    )
    ov = metering.request_override(spec, tenant="acme", actor="ops")
    metering.decide_override(ov["id"], False, actor="boss", comment="nope")
    assert metering.resolve_policy("acme").source == SOURCE_GROUP


def test_deciding_a_non_pending_override_is_rejected(metering):
    _, approved = _request_override(metering)
    with pytest.raises(PolicyDenied):
        metering.decide_override(approved["id"], True, actor="boss2")


def test_overlapping_windows_are_rejected(metering, clock):
    first_spec = OverrideSpec(
        tenant="acme", amount=1.0, alert_thresholds=[1.0],
        window_start=clock.t, window_end=clock.t + 100,
    )
    first = metering.request_override(first_spec, tenant="acme", actor="ops")
    # even before approval, a second overlapping request is refused
    clash_spec = OverrideSpec(
        tenant="acme", amount=2.0, alert_thresholds=[1.0],
        window_start=clock.t + 50, window_end=clock.t + 200,
    )
    with pytest.raises(PolicyDenied):
        metering.request_override(clash_spec, tenant="acme", actor="ops2")
    metering.decide_override(first["id"], True, actor="boss")
    # adjacent (non-overlapping) windows are fine
    adjacent = OverrideSpec(
        tenant="acme", amount=2.0, alert_thresholds=[1.0],
        window_start=clock.t + 100, window_end=clock.t + 200,
    )
    ov = metering.request_override(adjacent, tenant="acme", actor="ops")
    assert ov["status"] == "pending"


def test_expired_override_is_lapsed_lazily_and_stops_applying(metering, clock):
    _, approved = _request_override(
        metering, amount=1.0,
        start=clock.t - 100, end=clock.t + 10,
    )
    assert metering.resolve_policy("acme").source == SOURCE_OVERRIDE
    clock.advance(20)
    policy = metering.resolve_policy("acme")
    assert policy is None  # no group/budget, override window elapsed
    row = metering.get_override(approved["id"])
    assert row["status"] == "expired"
    audits = metering._audit.query("budget_override", limit=50)
    assert any(a["details"]["action"] == "expired" for a in audits)
    # an expired override cannot be revoked or decided again
    with pytest.raises(PolicyDenied):
        metering.revoke_override(approved["id"], actor="boss")


def test_revocation_takes_effect_immediately(metering, clock):
    _, approved = _request_override(
        metering, amount=1.0,
        start=clock.t - 10, end=clock.t + 3600,
    )
    assert metering.resolve_policy("acme").source == SOURCE_OVERRIDE
    metering.revoke_override(approved["id"], actor="ops")  # requester may revoke
    assert metering.resolve_policy("acme") is None
    with pytest.raises(PolicyDenied):
        metering.revoke_override(approved["id"], actor="boss")


def test_request_with_elapsed_window_is_rejected(metering, clock):
    spec = OverrideSpec(
        tenant="acme", amount=1.0, alert_thresholds=[1.0],
        window_start=clock.t - 100, window_end=clock.t - 1,
    )
    with pytest.raises(PolicyDenied):
        metering.request_override(spec, tenant="acme", actor="ops")


def test_override_optimistic_concurrency(metering, clock):
    spec = OverrideSpec(
        tenant="acme", amount=1.0, alert_thresholds=[1.0],
        window_start=clock.t, window_end=clock.t + 100,
    )
    ov = metering.request_override(spec, tenant="acme", actor="ops")
    metering.decide_override(
        ov["id"], True, actor="boss", expected_version=1
    )
    with pytest.raises(MeteringConflict):
        metering.revoke_override(ov["id"], actor="boss", expected_version=1)


# -- historical periods keep the old snapshot ---------------------------------


def test_historical_period_keeps_policy_snapshot_after_group_change(metering, clock):
    make_group(metering, amount=10.0, thresholds=[1.0])
    metering.move_member("acme", "g1", actor="root")
    # event in the previous period; the group/membership existed at that
    # period's boundary, so its closing policy is the v1 10-unit one
    old_time = clock.t - 2 * 86400 + 7200
    serve(metering, eid="old", event_time=old_time, client="c")
    metering.upsert_group(
        BudgetGroupSpec(id="g1", period_type=PERIOD_DAY, amount=1.0,
                        alert_thresholds=[1.0], over_policy="reject",
                        expected_version=1),
        actor="root",
    )
    # a late event landing in the OLD period must freeze the old policy
    # (amount 10), not the new 1-unit policy: no retroactive overage alert.
    past = old_time + 10
    serve(metering, eid="late", event_time=past, client="c")
    alerts = metering.list_alerts(tenant="acme")
    assert alerts == []
    snapshots = metering.list_policy_snapshots(tenant="acme")
    by_period = {s["period_start"]: s for s in snapshots}
    old_start = period_start(past, PERIOD_DAY)
    assert by_period[old_start]["amount"] == 10.0
    assert by_period[old_start]["frozen"] is True
    assert by_period[old_start]["source_version"] == 1
    # changing the group again still does not rewrite the frozen period
    metering.upsert_group(
        BudgetGroupSpec(id="g1", period_type=PERIOD_DAY, amount=2.0,
                        alert_thresholds=[1.0], over_policy="reject",
                        expected_version=2),
        actor="root",
    )
    serve(metering, eid="late2", event_time=past + 1, client="c")
    by_period = {s["period_start"]: s for s in
                 metering.list_policy_snapshots(tenant="acme")}
    assert by_period[old_start]["amount"] == 10.0
    # the current period follows the newest live policy
    current = metering.resolve_policy("acme")
    assert current.amount == 2.0 and current.source_version == 3


def test_historical_resolution_uses_membership_at_event_time(metering, clock):
    make_group(metering, gid="a", amount=10.0)
    make_group(metering, gid="b", amount=1.0)
    past = clock.t - 3 * 86400 + 7200
    metering.move_member("acme", "a", actor="root")
    serve(metering, eid="old", event_time=past, client="c")
    # migrate to b today; the old period must remain governed by a's policy
    metering.move_member("acme", "b", actor="root")
    serve(metering, eid="late", event_time=past + 10, client="c")
    old_start = period_start(past, PERIOD_DAY)
    snaps = {s["period_start"]: s for s in
             metering.list_policy_snapshots(tenant="acme")}
    assert snaps[old_start]["source_id"] == "a"
    assert snaps[old_start]["frozen"] is True
    history = metering.membership_history("acme")
    assert len(history) == 2
    assert history[0]["group_id"] == "a" and history[1]["group_id"] == "b"


def test_open_period_snapshot_tracks_live_policy(metering):
    make_group(metering, amount=10.0)
    metering.move_member("acme", "g1", actor="root")
    serve(metering, eid="e1")
    metering.upsert_group(
        BudgetGroupSpec(id="g1", period_type=PERIOD_DAY, amount=5.0,
                        alert_thresholds=[1.0], over_policy="reject",
                        expected_version=1),
        actor="root",
    )
    serve(metering, eid="e2")
    snaps = {s["period_start"]: s for s in
             metering.list_policy_snapshots(tenant="acme")}
    (only,) = snaps.values()
    assert only["amount"] == 5.0 and only["source_version"] == 2
    assert only["frozen"] is False


def test_budget_status_historical_uses_frozen_policy(metering, clock):
    make_group(metering, amount=10.0)
    metering.move_member("acme", "g1", actor="root")
    past = clock.t - 2 * 86400 + 7200
    serve(metering, eid="old", event_time=past, client="c")
    # Freeze the old period's policy while the v1 policy is still live.
    serve(metering, eid="late", event_time=past + 10, client="c")
    metering.upsert_group(
        BudgetGroupSpec(id="g1", period_type=PERIOD_DAY, amount=1.0,
                        alert_thresholds=[1.0], over_policy="reject",
                        expected_version=1),
        actor="root",
    )
    status = metering.budget_status("acme", at=past)
    assert status["historical"] is True
    assert status["amount"] == 10.0
    assert status["frozen"] is True
    assert status["policy_origin"]["source_version"] == 1


# -- retargeted alerts after migration ----------------------------------------


def test_mid_period_migration_retargets_threshold_alerts(metering):
    make_group(metering, gid="loose", amount=100.0, thresholds=[1.0])
    make_group(metering, gid="tight", amount=1.0, thresholds=[1.0])
    metering.move_member("acme", "loose", actor="root")
    serve(metering, eid="e1")
    assert metering.list_alerts(tenant="acme") == []
    metering.move_member("acme", "tight", actor="root")
    # next request under the tight inherited budget crosses its threshold
    serve(metering, eid="e2")
    alerts = metering.list_alerts(tenant="acme")
    assert len(alerts) == 1
    assert alerts[0]["budget_amount"] == 1.0
    origin = alerts[0].get("policy_origin")
    assert origin and origin["source"] == SOURCE_GROUP
    assert origin["source_id"] == "tight"


# -- optimistic concurrency, idempotency, persistence -------------------------


def test_group_optimistic_concurrency(metering):
    make_group(metering, amount=5.0)
    with pytest.raises(MeteringConflict):
        metering.upsert_group(
            BudgetGroupSpec(id="g1", period_type=PERIOD_DAY, amount=9.0,
                            alert_thresholds=[1.0], over_policy="reject",
                            expected_version=99),
            actor="root",
        )


def test_same_content_group_put_is_noop(metering):
    g1, created = make_group(metering, amount=5.0)
    g2, created_again = make_group(metering, amount=5.0)
    assert created is True and created_again is False
    assert g1["version"] == g2["version"] == 1


def test_group_delete_blocked_with_members_or_children(metering):
    make_group(metering, gid="parent", amount=5.0)
    make_group(metering, gid="child", amount=None, parent="parent")
    with pytest.raises(PolicyDenied):
        metering.delete_group("parent", actor="root")
    metering.delete_group("child", actor="root")
    metering.move_member("acme", "parent", actor="root")
    with pytest.raises(PolicyDenied):
        metering.delete_group("parent", actor="root")
    metering.remove_member("acme", actor="root")
    metering.delete_group("parent", actor="root")
    with pytest.raises(MeteringNotFound):
        metering.get_group("parent")


def test_move_to_unknown_group_is_not_found(metering):
    with pytest.raises(MeteringNotFound):
        metering.move_member("acme", "ghost", actor="root")


def test_state_survives_restart(tmp_path, clock):
    db_path = str(tmp_path / "persist-groups.db")
    db = connect(db_path)
    store = MeteringStore(db, AuditLog(db, clock), clock)
    make_group(store, amount=2.0, thresholds=[1.0])
    store.move_member("acme", "g1", actor="root")
    _, approved = _request_override(
        store, amount=1.0, start=clock.t - 10, end=clock.t + 3600,
    )
    serve(store, eid="e1")
    db.close()

    db2 = connect(db_path)
    reopened = MeteringStore(db2, AuditLog(db2, clock), clock)
    policy = reopened.resolve_policy("acme")
    assert policy is not None
    assert policy.source == SOURCE_OVERRIDE
    assert policy.source_id == approved["id"]
    membership = reopened.get_membership("acme")
    assert membership["group_id"] == "g1" and membership["version"] == 1
    snaps = reopened.list_policy_snapshots(tenant="acme")
    assert len(snaps) == 1
    ov = reopened.get_override(approved["id"])
    assert ov["status"] == "approved"
    assert len(reopened.membership_history("acme")) == 1
