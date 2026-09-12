"""Usage metering: events, idempotency, late events, aggregates, budgets."""
from __future__ import annotations

import pytest

from app.metering import (
    BudgetSpec,
    MeteringConflict,
    MeteringStore,
    MeteringValidationError,
    PERIOD_DAY,
    PERIOD_MONTH,
    RESULT_DEGRADED,
    RESULT_REJECTED,
    RESULT_SERVED,
    next_period_start,
    period_label,
    period_start,
)
from app.storage import connect
from app.audit import AuditLog

from tests.conftest import FakeClock


@pytest.fixture
def metering(tmp_path, clock):
    db = connect(str(tmp_path / "meter.db"))
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


# -- event idempotency ---------------------------------------------------------


def test_duplicate_event_is_not_billed_twice(metering):
    first = serve(metering, eid="fixed")
    again = serve(metering, eid="fixed")
    assert first["duplicate"] is False
    assert again["duplicate"] is True
    buckets = metering.aggregates(tenant="acme", period_type=PERIOD_DAY)
    assert len(buckets) == 1
    assert buckets[0]["events"] == 1
    assert buckets[0]["quantity"] == 1.0


def test_server_generates_distinct_ids_for_unspecified_events(metering):
    a = serve(metering)
    b = serve(metering)
    assert a["event_id"] and b["event_id"]
    assert a["event_id"] != b["event_id"]
    assert a["duplicate"] is False and b["duplicate"] is False


def test_duplicate_event_with_different_payload_still_replays(metering):
    # Dedup is by event id only, like a request id; the winner is replayed.
    serve(metering, eid="dup", quantity=1, client="orig")
    again = serve(metering, eid="dup", quantity=5, client="other")
    assert again["duplicate"] is True
    assert again["client_key"] == "orig"
    assert again["quantity"] == 1


# -- late / out-of-order events ------------------------------------------------


def test_late_event_archives_by_event_time_not_ingestion_time(metering, clock):
    past = clock.t - 5 * 86400
    serve(metering, eid="late", event_time=past, client="old")
    rows = metering.list_events(
        tenant="acme", start=past - 10, end=past + 86400
    )
    assert [r["event_id"] for r in rows] == ["late"]
    buckets = metering.aggregates(tenant="acme", period_type=PERIOD_DAY)
    old = [b for b in buckets if b["period_start"] == period_start(past, PERIOD_DAY)]
    assert len(old) == 1 and old[0]["quantity"] == 1.0


def test_out_of_order_events_aggregate_consistently(metering, clock):
    # Insert newest first, then older; both periods and the month row sum up.
    serve(metering, eid="new", event_time=clock.t, client="c")
    serve(metering, eid="older", event_time=clock.t - 3 * 86400, client="c")
    serve(metering, eid="oldest", event_time=clock.t - 33 * 86400, client="c")
    days = metering.aggregates(tenant="acme", period_type=PERIOD_DAY)
    months = metering.aggregates(tenant="acme", period_type=PERIOD_MONTH)
    assert sum(b["quantity"] for b in days) == 3
    # oldest may be in the previous month; regardless every quantity is 1.
    assert sum(b["quantity"] for b in months) == 3


def test_future_live_event_is_rejected(metering, clock):
    with pytest.raises(MeteringValidationError):
        serve(metering, eid="future", event_time=clock.t + 3600)


# -- aggregates ----------------------------------------------------------------


def test_aggregates_split_by_client_and_rule_scope(metering):
    serve(metering, eid="1", client="a", rule_scope="global")
    serve(metering, eid="2", client="a", rule_scope="region")
    serve(metering, eid="3", client="b", rule_scope="global")
    rows = metering.aggregates(
        tenant="acme", period_type=PERIOD_DAY,
        group_by_client=True, group_by_scope=True,
    )
    assert len(rows) == 3
    by = {(r["client_key"], r["rule_scope"]): r for r in rows}
    assert by[("a", "global")]["quantity"] == 1
    assert by[("a", "region")]["quantity"] == 1
    assert by[("b", "global")]["quantity"] == 1


def test_rejected_and_degraded_quantities_tracked_separately(metering):
    serve(metering, eid="ok")
    serve(metering, eid="deg", result=RESULT_DEGRADED, degraded=True)
    serve(metering, eid="rej", result=RESULT_REJECTED, quantity=0)
    rows = metering.aggregates(tenant="acme", period_type=PERIOD_DAY)
    (row,) = rows
    assert row["events"] == 3
    assert row["allowed_quantity"] == 1
    assert row["degraded_quantity"] == 1
    assert row["rejected_quantity"] == 0
    assert row["quantity"] == 2  # rejected requests bill nothing


def test_event_window_query_filters_by_event_time(metering, clock):
    serve(metering, eid="a", event_time=clock.t - 100)
    serve(metering, eid="b", event_time=clock.t)
    in_window = metering.list_events(
        tenant="acme", start=clock.t - 50, end=clock.t + 50
    )
    assert [r["event_id"] for r in in_window] == ["b"]


# -- budgets, thresholds, policies ---------------------------------------------


def test_threshold_alerts_fire_once_each(metering):
    metering.upsert_budget(
        BudgetSpec(tenant="acme", amount=4, alert_thresholds=[0.5, 1.0],
                   over_policy="reject"),
        actor="admin",
    )
    for i in range(4):
        serve(metering, eid=f"e{i}", client="x")
    alerts = metering.list_alerts(tenant="acme")
    assert sorted(a["threshold"] for a in alerts) == [0.5, 1.0]
    assert all(a["status"] == "open" for a in alerts)
    # A rejected over-budget request archives a zero-quantity event and
    # must never create duplicate threshold alerts.
    metering.record_event(
        tenant="acme", client_key="x", name="api", rule_scope="region",
        rule_version=None, group_id=None, config_version=1,
        result=RESULT_REJECTED, quantity=0, event_id="rej",
    )
    alerts = metering.list_alerts(tenant="acme")
    assert sorted(a["threshold"] for a in alerts) == [0.5, 1.0]


def test_reject_policy_gate(metering):
    metering.upsert_budget(
        BudgetSpec(tenant="acme", amount=2, alert_thresholds=[1.0],
                   over_policy="reject"),
        actor="admin",
    )
    serve(metering, eid="1")
    serve(metering, eid="2")
    decision = metering.check("acme")
    assert decision.allowed is False
    assert decision.reason == "budget_exceeded"
    assert decision.remaining == 0.0


def test_degrade_policy_gate(metering):
    metering.upsert_budget(
        BudgetSpec(tenant="acme", amount=1, alert_thresholds=[1.0],
                   over_policy="degrade"),
        actor="admin",
    )
    serve(metering, eid="1")
    d = metering.check("acme")
    assert d.allowed is True and d.degraded is True
    assert d.reason == "over_budget_degraded"


def test_allow_policy_gate(metering):
    metering.upsert_budget(
        BudgetSpec(tenant="acme", amount=1, alert_thresholds=[1.0],
                   over_policy="allow"),
        actor="admin",
    )
    serve(metering, eid="1")
    d = metering.check("acme")
    assert d.allowed is True and d.degraded is False
    assert d.reason == "over_budget_allow"


def test_no_budget_means_unbounded(metering):
    d = metering.check("unknown-tenant")
    assert d.allowed is True and d.amount is None
    assert d.reason == "no_budget"


def test_budget_rolls_over_at_utc_midnight(metering, clock):
    metering.upsert_budget(
        BudgetSpec(tenant="acme", amount=1, alert_thresholds=[1.0],
                   over_policy="reject"),
        actor="admin",
    )
    serve(metering, eid="today")
    assert metering.check("acme").allowed is False
    clock.t = next_period_start(clock.t, PERIOD_DAY) + 1
    d = metering.check("acme")
    # check() projects the pending unit into the new (empty) period.
    assert d.allowed is True and d.used == 1.0
    assert metering.budget_status("acme")["used"] == 0.0


def test_monthly_budget_uses_month_boundary(metering, clock):
    metering.upsert_budget(
        BudgetSpec(tenant="acme", period_type=PERIOD_MONTH, amount=1,
                   alert_thresholds=[1.0], over_policy="reject"),
        actor="admin",
    )
    serve(metering, eid="m")
    assert metering.check("acme").allowed is False
    # Same month, even many days later: still blocked.
    clock.advance(10 * 86400)
    assert metering.check("acme").allowed is False
    # Advance to the first of next month UTC: budget resets.
    clock.t = next_period_start(clock.t, PERIOD_MONTH) + 1
    assert metering.check("acme").allowed is True


# -- optimistic concurrency and lifecycle --------------------------------------


def test_budget_optimistic_concurrency(metering):
    metering.upsert_budget(
        BudgetSpec(tenant="acme", amount=5), actor="admin"
    )
    with pytest.raises(MeteringConflict):
        metering.upsert_budget(
            BudgetSpec(tenant="acme", amount=9, expected_version=99),
            actor="admin",
        )


def test_same_content_budget_put_is_noop(metering):
    spec = BudgetSpec(tenant="acme", amount=5)
    _, created = metering.upsert_budget(spec, actor="admin")
    again, created_again = metering.upsert_budget(spec, actor="admin")
    assert created is True and created_again is False
    assert again["version"] == 1


def test_budget_delete(metering):
    metering.upsert_budget(BudgetSpec(tenant="acme", amount=5), actor="admin")
    metering.delete_budget("acme", actor="admin")
    assert metering.budget_status("acme") is None


def test_acknowledge_alert_is_versioned_and_idempotent(metering):
    metering.upsert_budget(
        BudgetSpec(tenant="acme", amount=1, alert_thresholds=[1.0]),
        actor="admin",
    )
    serve(metering, eid="1")
    (alert,) = metering.list_alerts(tenant="acme")
    acked, changed = metering.acknowledge_alert(
        alert["id"], actor="ops", comment="seen"
    )
    assert changed is True and acked["status"] == "acknowledged"
    assert acked["version"] == 2
    again, changed_again = metering.acknowledge_alert(
        alert["id"], actor="ops"
    )
    assert changed_again is False
    with pytest.raises(MeteringConflict):
        metering.acknowledge_alert(
            alert["id"], actor="ops", expected_version=1
        )


# -- recompute and retroactive alerts ------------------------------------------


def test_recompute_rebuilds_aggregates_and_heals_drift(metering, clock):
    metering.upsert_budget(
        BudgetSpec(tenant="acme", amount=100, alert_thresholds=[1.0]),
        actor="admin",
    )
    for i in range(3):
        serve(metering, eid=f"e{i}", event_time=clock.t - i * 10, client="c")
    # Corrupt an aggregate row, then recompute: detail log is the source of truth.
    db = metering._conn
    db.execute("UPDATE usage_aggregates SET quantity = 0")
    db.commit()
    result = metering.recompute(actor="admin", tenant="acme")
    assert result["events_scanned"] == 3
    total = sum(
        b["quantity"]
        for b in metering.aggregates(tenant="acme", period_type=PERIOD_DAY)
    )
    assert total == 3


def test_backfill_fires_retroactive_alert_on_past_period(metering, clock):
    metering.upsert_budget(
        BudgetSpec(tenant="acme", amount=3, alert_thresholds=[1.0],
                   over_policy="reject"),
        actor="admin",
    )
    past = clock.t - 20 * 86400
    result = metering.backfill(
        [
            dict(
                event_id=f"bf{i}", event_time=past + i, tenant="acme",
                client_key="b", name="api", rule_scope="global",
                config_version=1, result=RESULT_SERVED, quantity=1,
            )
            for i in range(4)
        ],
        actor="ops",
    )
    assert result["accepted"] == 4
    past_start = period_start(past, PERIOD_DAY)
    alerts = [
        a for a in metering.list_alerts(tenant="acme")
        if a["period_start"] == past_start
    ]
    assert alerts and alerts[0]["threshold"] == 1.0
    # Backfilling an old period never moves the current period's usage.
    assert metering.budget_status("acme")["used"] == 0.0


def test_backfill_is_idempotent(metering, clock):
    past = clock.t - 10 * 86400
    payload = [
        dict(event_id="once", event_time=past, tenant="acme", client_key="b",
             name="api", rule_scope="global", config_version=1,
             result=RESULT_SERVED, quantity=1)
    ]
    first = metering.backfill(payload, actor="ops")
    second = metering.backfill(payload, actor="ops")
    assert first["accepted"] == 1
    assert second["accepted"] == 0 and second["duplicates"] == 1
    buckets = metering.aggregates(tenant="acme", period_type=PERIOD_DAY)
    assert sum(b["quantity"] for b in buckets) == 1


def test_recompute_creates_missing_retroactive_alerts(metering, clock):
    # Configure budget only after the usage happened; reconcile via recompute.
    past = clock.t - 20 * 86400
    metering.backfill(
        [
            dict(event_id=f"old{i}", event_time=past + i, tenant="acme",
                 client_key="b", name="api", rule_scope="global",
                 config_version=1, result=RESULT_SERVED, quantity=1)
            for i in range(2)
        ],
        actor="ops",
    )
    metering.upsert_budget(
        BudgetSpec(tenant="acme", amount=1, alert_thresholds=[1.0]),
        actor="admin",
    )
    # No alerts yet (budget did not exist when the events landed)...
    assert metering.list_alerts(tenant="acme") == []
    result = metering.recompute(actor="admin", tenant="acme")
    assert result["alerts_created"] >= 1
    assert metering.list_alerts(tenant="acme")


# -- persistence ----------------------------------------------------------------


def test_concurrent_duplicate_events_bill_once(metering):
    import threading

    metering.upsert_budget(
        BudgetSpec(tenant="t", amount=10_000, alert_thresholds=[1.0]),
        actor="a",
    )
    counts = {"new": 0, "dup": 0}
    lock = threading.Lock()

    def fire(i):
        eid = "shared" if i % 2 == 0 else f"uniq{i}"
        r = metering.record_event(
            tenant="t", client_key="c", name="n", rule_scope="global",
            rule_version=None, group_id=None, config_version=1,
            result=RESULT_SERVED, quantity=1, event_id=eid,
        )
        with lock:
            counts["dup" if r["duplicate"] else "new"] += 1

    threads = [threading.Thread(target=fire, args=(i,)) for i in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # 20 share "shared" -> 1 new, 19 dup; the other 20 are unique.
    assert counts == {"new": 21, "dup": 19}
    total = sum(
        b["quantity"]
        for b in metering.aggregates(tenant="t", period_type=PERIOD_DAY)
    )
    assert total == 21


def test_concurrent_budget_updates_only_one_wins(metering):
    import threading

    metering.upsert_budget(BudgetSpec(tenant="t", amount=1), actor="a")
    outcome = {"ok": 0, "conflict": 0}
    lock = threading.Lock()

    def upd(i):
        try:
            metering.upsert_budget(
                BudgetSpec(tenant="t", amount=10 + i, expected_version=1),
                actor="x",
            )
            with lock:
                outcome["ok"] += 1
        except MeteringConflict:
            with lock:
                outcome["conflict"] += 1

    threads = [threading.Thread(target=upd, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcome == {"ok": 1, "conflict": 9}


def test_state_survives_restart(tmp_path, clock):
    db_path = str(tmp_path / "persist.db")
    db = connect(db_path)
    store = MeteringStore(db, AuditLog(db, clock), clock)
    store.upsert_budget(
        BudgetSpec(tenant="acme", amount=2, alert_thresholds=[1.0]),
        actor="admin",
    )
    serve(store, eid="e1")
    serve(store, eid="e2")
    (alert,) = store.list_alerts(tenant="acme")
    store.acknowledge_alert(alert["id"], actor="ops")
    db.close()

    db2 = connect(db_path)
    reopened = MeteringStore(db2, AuditLog(db2, clock), clock)
    status = reopened.budget_status("acme")
    assert status is not None and status["used"] == 2
    assert len(reopened.list_events(tenant="acme")) == 2
    acked = reopened.list_alerts(tenant="acme", status="acknowledged")
    assert len(acked) == 1
