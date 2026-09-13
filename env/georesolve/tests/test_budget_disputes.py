"""Budget billing disputes: lifecycle, freezing, ledger and projection."""
from __future__ import annotations

import pytest

from app.audit import AuditLog
from app.disputes import (
    DisputeConflict,
    DisputeSpec,
    DisputeStore,
    STATUS_APPLIED,
    STATUS_APPROVED,
    STATUS_DRAFT,
    STATUS_PENDING,
    STATUS_REJECTED,
    STATUS_REVOKED,
)
from app.metering import (
    BudgetSpec,
    MeteringConflict,
    MeteringStore,
    MeteringValidationError,
    PERIOD_DAY,
    RESULT_REJECTED,
    RESULT_SERVED,
    next_period_start,
    period_label,
    period_start,
)
from app.storage import connect

from tests.conftest import FakeClock


@pytest.fixture
def stores(tmp_path, clock):
    db = connect(str(tmp_path / "disp.db"))
    audit = AuditLog(db, clock)
    metering = MeteringStore(db, audit, clock)
    disputes = DisputeStore(db, metering, audit, clock)
    return SimpleStore(metering, disputes, audit, db, clock)


class SimpleStore:
    def __init__(self, metering, disputes, audit, db, clock):
        self.metering = metering
        self.disputes = disputes
        self.audit = audit
        self.db = db
        self.clock = clock


def serve(store, eid, tenant="acme", client="c1", quantity=1.0,
          result=RESULT_SERVED, event_time=None, **kw):
    base = dict(
        tenant=tenant, client_key=client, name="api", region="",
        rule_scope="global", rule_version=1, group_id=None,
        config_version=1, result=result, quantity=quantity,
    )
    base.update(kw)
    return store.record_event(event_id=eid, event_time=event_time, **base)


def budget(store, tenant="acme", amount=10.0, thresholds=(0.5, 1.0),
           period_type=PERIOD_DAY):
    spec = BudgetSpec(
        tenant=tenant, period_type=period_type, amount=amount,
        alert_thresholds=list(thresholds), over_policy="reject",
    )
    store.upsert_budget(spec, actor="root")


def spec(store, events, tenant="acme", qty=-2.0, period_type=PERIOD_DAY,
         retroactive=False, submit=True, reason="double charge", period=None):
    return DisputeSpec(
        tenant=tenant, period_type=period_type, period=period,
        event_ids=events, reason=reason, adjustment_quantity=qty,
        retroactive=retroactive, submit=submit,
    )


def create(stores, events, **kw):
    return stores.disputes.create(
        spec(stores, events, **kw), tenant="acme", actor="alice"
    )


def approve(stores, did, actor="bob", version=None):
    return stores.disputes.decide(
        did, True, actor=actor, expected_version=version
    )


def reject(stores, did, actor="bob", version=None):
    return stores.disputes.decide(
        did, False, actor=actor, expected_version=version
    )


def apply(stores, did, actor="bob", version=None):
    return stores.disputes.apply(did, actor=actor, expected_version=version)


# -- creation, draft/submit and the frozen payload ----------------------------


def test_create_and_full_lifecycle(stores):
    budget(stores.metering)
    serve(stores.metering, "e1")
    serve(stores.metering, "e2")
    d = create(stores, ["e1", "e2"], qty=-1.0)
    assert d["status"] == STATUS_PENDING
    assert d["frozen_at"] is not None
    assert d["event_count"] == 2
    assert [e["event_id"] for e in d["frozen_events"]] == ["e1", "e2"]
    assert d["frozen_aggregates"]["total_quantity"] == 2.0
    assert d["frozen_policy"]["policy"]["source"] == "tenant"
    assert d["frozen_policy"]["policy"]["source_version"] == 1

    approved = approve(stores, d["id"])
    assert approved["status"] == STATUS_APPROVED and approved["decided_by"] == "bob"
    applied = apply(stores, d["id"])
    assert applied["status"] == STATUS_APPLIED and applied["applied_by"] == "bob"

    hist = stores.disputes.history(d["id"])
    assert [h["action"] for h in hist] == [
        "created", "submitted", "approved", "applied"
    ]
    assert [h["version"] for h in hist] == [1, 2, 3, 4]


def test_draft_then_submit_freezes(stores):
    budget(stores.metering)
    serve(stores.metering, "e1")
    d = create(stores, ["e1"], qty=-1.0, submit=False)
    assert d["status"] == STATUS_DRAFT and d["frozen_events"] is None
    submitted = stores.disputes.submit(d["id"], actor="alice")
    assert submitted["status"] == STATUS_PENDING
    assert submitted["frozen_events"] is not None
    assert submitted["submitted_by"] == "alice"


def test_submit_requires_events(stores):
    budget(stores.metering)
    d = stores.disputes.create(
        spec(stores, [], submit=False), tenant="acme", actor="alice"
    )
    with pytest.raises(DisputeConflict) as exc:
        stores.disputes.submit(d["id"], actor="alice")
    assert "no_events" in str(exc.value)
    # The failed submit leaves the draft intact and writes a denial audit.
    assert stores.disputes.get(d["id"])["status"] == STATUS_DRAFT
    denied = stores.audit.query(type_="budget_policy_denied", limit=10)
    assert any(r["details"]["reason"] == "no_events" for r in denied)


def test_reject_is_terminal_and_no_ledger(stores):
    budget(stores.metering)
    serve(stores.metering, "e1")
    d = create(stores, ["e1"], qty=-1.0)
    reject(stores, d["id"])
    with pytest.raises(DisputeConflict):
        approve(stores, d["id"])
    assert stores.disputes.list_adjustments(tenant="acme") == []


# -- submission validation ----------------------------------------------------


def test_unknown_event_rejected(stores):
    budget(stores.metering)
    with pytest.raises(DisputeConflict) as exc:
        create(stores, ["ghost"])
    assert "unknown_event" in str(exc.value)
    assert any(
        r["details"].get("reason") == "unknown_event"
        for r in stores.audit.query(type_="budget_policy_denied", limit=10)
    )


def test_cross_tenant_event_rejected(stores):
    budget(stores.metering)
    serve(stores.metering, "e1")
    serve(stores.metering, "e2", tenant="other")
    with pytest.raises(DisputeConflict) as exc:
        create(stores, ["e1", "e2"])
    assert "cross_tenant_event" in str(exc.value)


def test_duplicate_reference_rejected(stores):
    budget(stores.metering)
    serve(stores.metering, "e1")
    with pytest.raises(DisputeConflict) as exc:
        create(stores, ["e1", "e1"])
    assert "duplicate_event" in str(exc.value)


def test_event_from_other_period_rejected(stores):
    budget(stores.metering)
    now = stores.clock.t
    serve(stores.metering, "e1", event_time=now)
    serve(stores.metering, "e2", event_time=now - 90000)
    with pytest.raises(DisputeConflict) as exc:
        create(stores, ["e1", "e2"])
    assert "event_wrong_period" in str(exc.value)


def test_negative_adjusted_usage_rejected_at_submit(stores):
    budget(stores.metering)
    serve(stores.metering, "e1", quantity=1.0)
    with pytest.raises(DisputeConflict) as exc:
        create(stores, ["e1"], qty=-5.0)
    assert "negative_usage" in str(exc.value)


def test_closed_period_requires_retroactive(stores):
    budget(stores.metering)
    now = stores.clock.t
    past = now - 2 * 86400
    serve(stores.metering, "e1", event_time=past)
    with pytest.raises(DisputeConflict) as exc:
        create(stores, ["e1"], qty=-1.0,
               period=period_label(past, PERIOD_DAY))
    assert "frozen_period" in str(exc.value)
    # Explicit retroactive submission for the closed period is accepted.
    d = create(stores, ["e1"], qty=-1.0, retroactive=True,
               period=period_label(past, PERIOD_DAY))
    assert d["retroactive"] is True


def test_retroactive_dispute_rejected_for_open_period(stores):
    budget(stores.metering)
    serve(stores.metering, "e1")
    with pytest.raises(DisputeConflict) as exc:
        create(stores, ["e1"], qty=-1.0, retroactive=True)
    assert "period_open" in str(exc.value)


# -- separation of duties and concurrency -------------------------------------


def test_creator_cannot_approve(stores):
    budget(stores.metering)
    serve(stores.metering, "e1")
    d = create(stores, ["e1"], qty=-1.0)
    with pytest.raises(DisputeConflict) as exc:
        approve(stores, d["id"], actor="alice")
    assert "self_approval" in str(exc.value)
    assert stores.disputes.get(d["id"])["status"] == STATUS_PENDING


def test_expected_version_conflict(stores):
    budget(stores.metering)
    serve(stores.metering, "e1")
    d = create(stores, ["e1"], qty=-1.0)
    with pytest.raises(MeteringConflict):
        approve(stores, d["id"], version=99)
    approve(stores, d["id"], version=2)
    # A second decider loses: only one decision can win.
    with pytest.raises(DisputeConflict):
        reject(stores, d["id"], actor="carol")


def test_apply_requires_approved(stores):
    budget(stores.metering)
    serve(stores.metering, "e1")
    d = create(stores, ["e1"], qty=-1.0)
    with pytest.raises(DisputeConflict):
        apply(stores, d["id"])


def test_concurrent_apply_only_one_wins(stores):
    budget(stores.metering)
    serve(stores.metering, "e1")
    serve(stores.metering, "e2")
    d = create(stores, ["e1", "e2"], qty=-1.0)
    approve(stores, d["id"])
    apply(stores, d["id"])
    with pytest.raises(DisputeConflict):
        apply(stores, d["id"])
    # Exactly one immutable ledger row exists.
    adjustments = stores.disputes.list_adjustments(tenant="acme")
    assert len(adjustments) == 1 and adjustments[0]["direction"] == "apply"


# -- projection, gate and threshold re-evaluation -----------------------------


def test_applied_open_period_adjustment_moves_gate_immediately(stores):
    # Budget of 2; after 2 served units the next request would be rejected.
    budget(stores.metering, amount=2.0, thresholds=(1.0,))
    serve(stores.metering, "e1")
    serve(stores.metering, "e2")
    decision = stores.metering.check("acme")
    assert decision.allowed is False
    assert decision.raw_used == 2.0 and decision.used == 2.0

    d = create(stores, ["e1"], qty=-1.0)
    approve(stores, d["id"])
    apply(stores, d["id"])

    decision = stores.metering.check("acme")
    assert decision.allowed is True
    assert decision.raw_used == 2.0
    # Post-charge projection against the adjusted usage (1.0 + 1.0 charge).
    assert decision.used == 2.0
    assert decision.public()["normal_adjustment"] == -1.0

    view = stores.disputes.adjusted_budget(
        "acme", PERIOD_DAY, stores.clock.t
    )
    assert view["raw_used"] == 2.0
    assert view["adjusted_used"] == 1.0
    assert view["normal_adjustment"] == -1.0
    assert view["adjustments"][0]["dispute_id"] == d["id"]


def test_applied_credit_fires_missing_threshold_alert(stores):
    # Only the 1.0 threshold is configured, and usage is below it; an
    # upward adjustment that crosses it fires the missing alert on apply.
    budget(stores.metering, amount=10.0, thresholds=(1.0,))
    serve(stores.metering, "e1", quantity=5.0)
    assert stores.metering.list_alerts(tenant="acme") == []
    d = create(stores, ["e1"], qty=6.0)
    approve(stores, d["id"])
    apply(stores, d["id"])
    alerts = stores.metering.list_alerts(tenant="acme")
    assert len(alerts) == 1
    assert alerts[0]["usage"] == 11.0
    fired = [
        r for r in stores.audit.query(type_="budget_alert", limit=10)
        if r["details"].get("action") == "fired"
    ]
    assert fired and fired[0]["details"]["retroactive"] is False


def test_original_events_are_never_modified(stores):
    budget(stores.metering, amount=10.0)
    serve(stores.metering, "e1", quantity=5.0)
    d = create(stores, ["e1"], qty=-5.0)
    approve(stores, d["id"])
    apply(stores, d["id"])
    events = stores.metering.list_events(tenant="acme")
    assert events[0]["quantity"] == 5.0  # immutable


# -- retroactive adjustments for closed periods -------------------------------


def test_retroactive_adjustment_appends_but_does_not_change_projection(stores):
    budget(stores.metering, amount=10.0)
    now = stores.clock.t
    past = now - 2 * 86400
    serve(stores.metering, "e1", quantity=3.0, event_time=past)
    label = period_label(past, PERIOD_DAY)
    d = create(stores, ["e1"], qty=-1.0, retroactive=True, period=label)
    approve(stores, d["id"])
    applied = stores.disputes.apply(d["id"], actor="bob")
    assert applied["status"] == STATUS_APPLIED and applied["retroactive"] is True

    adjustments = stores.disputes.list_adjustments(
        tenant="acme", kind="retroactive"
    )
    assert len(adjustments) == 1
    assert adjustments[0]["kind"] == "retroactive"
    assert adjustments[0]["adjusted_quantity"] == 2.0

    view = stores.disputes.adjusted_budget("acme", PERIOD_DAY, past)
    assert view["raw_used"] == 3.0
    assert view["adjusted_used"] == 3.0  # gate projection untouched
    assert view["normal_adjustment"] == 0.0
    assert view["retroactive_adjustment"] == -1.0
    assert view["adjusted_including_retroactive"] == 2.0

    # No projection row delta was written for the closed period and no
    # retroactive alert is manufactured by the apply.
    proj = stores.db.execute(
        "SELECT adjustment_delta FROM budget_usage_projections"
        " WHERE tenant='acme' AND period_start=?",
        (period_start(past, PERIOD_DAY),),
    ).fetchone()
    assert proj["adjustment_delta"] == 0.0
    # Retroactive disputes cannot be revoked once applied.
    with pytest.raises(DisputeConflict):
        stores.disputes.revoke(d["id"], actor="bob")


def test_normal_dispute_whose_period_closed_cannot_apply(stores):
    budget(stores.metering)
    serve(stores.metering, "e1")
    d = create(stores, ["e1"], qty=-1.0)
    approve(stores, d["id"])
    stores.clock.advance(2 * 86400)
    with pytest.raises(DisputeConflict) as exc:
        stores.disputes.apply(d["id"], actor="bob")
    assert "frozen_period" in str(exc.value)
    assert stores.disputes.get(d["id"])["status"] == STATUS_APPROVED


# -- revocation ----------------------------------------------------------------


def test_revoke_pending_and_reverse_applied_open_period(stores):
    budget(stores.metering, amount=10.0)
    serve(stores.metering, "e1", quantity=5.0)

    pending = create(stores, ["e1"], qty=-1.0)
    out = stores.disputes.revoke(pending["id"], actor="alice",
                                 reason="filed twice")
    assert out["status"] == STATUS_REVOKED
    assert stores.disputes.list_adjustments(tenant="acme") == []

    d2 = create(stores, ["e1"], qty=-2.0)
    approve(stores, d2["id"])
    apply(stores, d2["id"])
    # The uncharged current usage (before the pending one-unit projection) is 3.
    assert stores.disputes.adjusted_budget(
        "acme", PERIOD_DAY, stores.clock.t
    )["adjusted_used"] == 3.0
    assert stores.metering.check("acme").allowed is True
    reversed_ = stores.disputes.revoke(d2["id"], actor="bob")
    assert reversed_["status"] == STATUS_REVOKED
    # The gate projection returns to the raw billed quantity (5 + 1 charge).
    assert stores.disputes.adjusted_budget(
        "acme", PERIOD_DAY, stores.clock.t
    )["adjusted_used"] == 5.0
    decision = stores.metering.check("acme")
    assert decision.raw_used == 5.0 and decision.used == 6.0
    assert decision.public()["normal_adjustment"] == 0.0
    ledger = stores.disputes.list_adjustments(tenant="acme")
    assert {(a["direction"], a["quantity"]) for a in ledger} == {
        ("apply", -2.0), ("reverse", 2.0)
    }
    apply_row = next(a for a in ledger if a["direction"] == "apply")
    reverse_row = next(a for a in ledger if a["direction"] == "reverse")
    assert reverse_row["reverses_id"] == apply_row["id"]


def test_cannot_revoke_rejected(stores):
    budget(stores.metering)
    serve(stores.metering, "e1")
    d = create(stores, ["e1"], qty=-1.0)
    reject(stores, d["id"])
    with pytest.raises(DisputeConflict):
        stores.disputes.revoke(d["id"], actor="bob")


# -- list/history filters ------------------------------------------------------


def test_list_filters_by_tenant_status_and_time(stores):
    budget(stores.metering)
    serve(stores.metering, "e1")
    d = create(stores, ["e1"], qty=-1.0)
    reject(stores, d["id"])
    assert len(stores.disputes.list_disputes(tenant="acme")) == 1
    assert stores.disputes.list_disputes(tenant="acme", status=STATUS_PENDING) == []
    assert len(stores.disputes.list_disputes(
        tenant="acme", status=STATUS_REJECTED
    )) == 1
    assert stores.disputes.list_disputes(
        tenant="acme", since=stores.clock.t + 10
    ) == []
    with pytest.raises(MeteringValidationError):
        stores.disputes.list_disputes(status="bogus")


def test_history_time_window(stores):
    budget(stores.metering)
    serve(stores.metering, "e1")
    d = create(stores, ["e1"], qty=-1.0)
    t0 = stores.clock.t
    stores.clock.advance(5)
    approve(stores, d["id"])
    hist = stores.disputes.history(d["id"], since=t0 + 1)
    assert [h["action"] for h in hist] == ["approved"]


# -- persistence across restart ------------------------------------------------


def test_state_survives_reconnect(stores, tmp_path, clock):
    budget(stores.metering)
    serve(stores.metering, "e1", quantity=5.0)
    d = create(stores, ["e1"], qty=-2.0)
    approve(stores, d["id"])
    apply(stores, d["id"])

    db2 = connect(str(tmp_path / "disp.db"))
    audit2 = AuditLog(db2, clock)
    metering2 = MeteringStore(db2, audit2, clock)
    disputes2 = DisputeStore(db2, metering2, audit2, clock)

    loaded = disputes2.get(d["id"])
    assert loaded["status"] == STATUS_APPLIED
    assert loaded["frozen_events"][0]["event_id"] == "e1"
    assert loaded["created_by"] == "alice" and loaded["decided_by"] == "bob"
    assert metering2.check("acme").raw_used == 5.0
    assert disputes2.adjusted_budget(
        "acme", PERIOD_DAY, clock.t
    )["adjusted_used"] == 3.0
    hist = disputes2.history(d["id"])
    assert [h["action"] for h in hist] == [
        "created", "submitted", "approved", "applied"
    ]
    assert len(disputes2.list_adjustments(tenant="acme")) == 1


# -- validation errors ---------------------------------------------------------


def test_zero_adjustment_rejected():
    with pytest.raises(Exception):
        DisputeSpec(tenant="acme", event_ids=["e1"], reason="x",
                    adjustment_quantity=0)


def test_blank_reason_rejected():
    with pytest.raises(Exception):
        DisputeSpec(tenant="acme", event_ids=["e1"], reason="  ",
                    adjustment_quantity=-1)


def test_missing_dispute_raises_not_found(stores):
    from app.disputes import DisputeNotFound
    with pytest.raises(DisputeNotFound):
        stores.disputes.get("nope")
    with pytest.raises(DisputeNotFound):
        stores.disputes.history("nope")
