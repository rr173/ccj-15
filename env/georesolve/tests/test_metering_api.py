"""End-to-end metering/budget API and data-plane integration tests."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import Components, create_app

TOKEN = "root-token"
H = {"Authorization": f"Bearer {TOKEN}"}

RULE = {
    "name": "api", "scope": "global", "rule_version": 1, "ttl": 60,
    "targets": [{"id": "b1", "address": "tcp://10.0.0.1:80", "weight": 1}],
}


@pytest.fixture
def client(tmp_path):
    comp = Components(
        db_path=str(tmp_path / "api.db"),
        admin_token=TOKEN,
        enable_background=False,
    )
    app = create_app(comp)
    with TestClient(app) as c:
        yield c


def put_budget(client, tenant, amount=3, policy="reject", thresholds=None,
               expected=None, version="day"):
    body = {
        "period_type": version,
        "amount": amount,
        "alert_thresholds": [1.0] if thresholds is None else thresholds,
        "over_policy": policy,
    }
    if expected is not None:
        body["expected_version"] = expected
    return client.put(f"/v1/budgets/{tenant}", json=body, headers=H)


def test_resolve_records_metered_event(client):
    client.post("/v1/config", json={"version": 1, "rules": [RULE]}, headers=H)
    r = client.get("/v1/resolve", params={"name": "api", "tenant": "acme",
                                          "client": "c1"})
    assert r.status_code == 200
    body = r.json()
    assert body["event_id"]  # every answer carries its replayable event id
    assert body["budget"]["enabled"] is False  # no budget configured yet

    events = client.get(
        "/v1/metering/events", params={"tenant": "acme"}, headers=H
    ).json()["events"]
    assert len(events) == 1
    ev = events[0]
    assert ev["tenant"] == "acme" and ev["client_key"] == "c1"
    assert ev["rule_scope"] == "global" and ev["quantity"] == 1
    assert ev["result"] == "served"
    # client/scope breakdown queries
    by_scope = client.get(
        "/v1/metering/aggregates",
        params={"tenant": "acme", "period": "day",
                "group_by_scope": "true"},
        headers=H,
    ).json()["buckets"]
    assert by_scope[0]["rule_scope"] == "global"


def test_repeated_request_id_is_billed_once(client):
    client.post("/v1/config", json={"version": 1, "rules": [RULE]}, headers=H)
    headers = {"X-Request-Id": "idempotent-1"}
    for _ in range(3):
        r = client.get(
            "/v1/resolve",
            params={"name": "api", "tenant": "acme", "client": "c1"},
            headers=headers,
        )
        assert r.status_code == 200
        assert r.json()["event_id"] == "idempotent-1"
    events = client.get(
        "/v1/metering/events", params={"tenant": "acme"}, headers=H
    ).json()["events"]
    assert len(events) == 1
    agg = client.get(
        "/v1/metering/aggregates", params={"tenant": "acme", "period": "day"},
        headers=H,
    ).json()["buckets"]
    assert agg[0]["quantity"] == 1 and agg[0]["events"] == 1


def test_reject_policy_returns_402_with_explanation(client):
    client.post("/v1/config", json={"version": 1, "rules": [RULE]}, headers=H)
    assert put_budget(client, "acme", amount=2).status_code == 201
    for i in range(2):
        r = client.get(
            "/v1/resolve",
            params={"name": "api", "tenant": "acme", "client": "c"},
            headers={"X-Request-Id": f"ok{i}"},
        )
        assert r.status_code == 200

    denied = client.get(
        "/v1/resolve",
        params={"name": "api", "tenant": "acme", "client": "c"},
        headers={"X-Request-Id": "denied-1"},
    )
    assert denied.status_code == 402
    body = denied.json()
    assert body["reason"] == "budget_exceeded"
    assert body["event_id"] == "denied-1"
    assert body["budget"]["used"] == 2 and body["budget"]["remaining"] == 0
    assert body["budget"]["policy"] == "reject"

    # Retrying the same denied request id replays, never double-billing.
    again = client.get(
        "/v1/resolve",
        params={"name": "api", "tenant": "acme", "client": "c"},
        headers={"X-Request-Id": "denied-1"},
    )
    assert again.status_code == 402
    assert again.json()["event_id"] == "denied-1"
    agg = client.get(
        "/v1/metering/aggregates", params={"tenant": "acme", "period": "day"},
        headers=H,
    ).json()["buckets"]
    # 2 served units, two zero-quantity denial events, still 2 billed.
    assert agg[0]["quantity"] == 2
    rej_events = client.get(
        "/v1/metering/events",
        params={"tenant": "acme", "rule_scope": "global"},
        headers=H,
    ).json()["events"]
    denials = [e for e in rej_events if e["result"] == "budget_rejected"]
    assert len(denials) == 1  # retried denial was a duplicate


def test_degrade_policy_serves_flagged_answer(client):
    client.post("/v1/config", json={"version": 1, "rules": [RULE]}, headers=H)
    put_budget(client, "acme", amount=1, policy="degrade")
    first = client.get("/v1/resolve", params={
        "name": "api", "tenant": "acme", "client": "c"})
    assert first.status_code == 200 and first.json()["degraded"] is False
    second = client.get("/v1/resolve", params={
        "name": "api", "tenant": "acme", "client": "c"})
    assert second.status_code == 200
    body = second.json()
    assert body["degraded"] is True
    assert "budget_exceeded" in body["degrade_reasons"]
    assert body["budget"]["degraded"] is True
    # degraded answers are still metered as budget_degraded
    events = client.get(
        "/v1/metering/events", params={"tenant": "acme"}, headers=H
    ).json()["events"]
    assert any(e["result"] == "budget_degraded" for e in events)


def test_threshold_alert_is_open_until_acknowledged(client):
    client.post("/v1/config", json={"version": 1, "rules": [RULE]}, headers=H)
    put_budget(client, "acme", amount=2, thresholds=[0.5, 1.0])
    client.get("/v1/resolve", params={"name": "api", "tenant": "acme"})
    alerts = client.get("/v1/budget-alerts", params={"tenant": "acme"},
                        headers=H).json()["alerts"]
    assert [a["threshold"] for a in alerts] == [0.5]
    client.get("/v1/resolve", params={"name": "api", "tenant": "acme"})
    alerts = client.get("/v1/budget-alerts", params={"tenant": "acme"},
                        headers=H).json()["alerts"]
    assert sorted(a["threshold"] for a in alerts) == [0.5, 1.0]

    alert = [a for a in alerts if a["threshold"] == 0.5][0]
    ack = client.post(
        f"/v1/budget-alerts/{alert['id']}/acknowledge",
        json={"comment": "investigating"}, headers=H,
    )
    assert ack.status_code == 200 and ack.json()["alert"]["status"] == "acknowledged"
    # stale expected_version conflicts
    conflict = client.post(
        f"/v1/budget-alerts/{alert['id']}/acknowledge",
        json={"expected_version": 1}, headers=H,
    )
    assert conflict.status_code == 409
    open_alerts = client.get(
        "/v1/budget-alerts",
        params={"tenant": "acme", "status": "open"}, headers=H,
    ).json()["alerts"]
    assert [a["threshold"] for a in open_alerts] == [1.0]


def test_budget_status_and_aggregates_endpoints(client):
    client.post("/v1/config", json={"version": 1, "rules": [RULE]}, headers=H)
    put_budget(client, "acme", amount=10)
    client.get("/v1/resolve", params={"name": "api", "tenant": "acme",
                                      "client": "c1"})
    status = client.get("/v1/budgets/acme", headers=H).json()
    assert status["used"] == 1 and status["remaining"] == 9
    assert status["budget"]["over_policy"] == "reject"
    assert status["period_end"] > status["period_start"]

    missing = client.get("/v1/budgets/nobody", headers=H)
    assert missing.status_code == 404

    agg = client.get(
        "/v1/metering/aggregates",
        params={"period": "day", "group_by_client": "true"}, headers=H,
    ).json()
    assert agg["count"] == 1 and agg["buckets"][0]["client_key"] == "c1"


def test_backfill_and_recompute(client):
    client.post("/v1/config", json={"version": 1, "rules": [RULE]}, headers=H)
    put_budget(client, "acme", amount=5)
    past = 1_700_000_000 - 20 * 86400
    payload = {
        "events": [
            {
                "event_id": f"bf{i}", "event_time": past + i,
                "tenant": "acme", "client_key": "batch", "name": "api",
                "rule_scope": "global", "config_version": 1,
                "result": "served", "quantity": 1,
            }
            for i in range(6)
        ]
    }
    r = client.post("/v1/metering/backfill", json=payload, headers=H)
    assert r.status_code == 201 and r.json()["accepted"] == 6
    # duplicate replay
    again = client.post(
        "/v1/metering/backfill",
        json={"events": payload["events"][:1]}, headers=H,
    )
    assert again.json()["duplicates"] == 1

    # retroactive alert fired for the over-budget past period
    alerts = client.get("/v1/budget-alerts", params={"tenant": "acme"},
                        headers=H).json()["alerts"]
    assert any(a["threshold"] == 1.0 for a in alerts)

    # current period untouched; aggregates show the backfilled day
    assert client.get("/v1/budgets/acme", headers=H).json()["used"] == 0
    rec = client.post("/v1/metering/recompute",
                      json={"tenant": "acme"}, headers=H)
    assert rec.status_code == 200 and rec.json()["events_scanned"] >= 6


def test_backfill_idempotency_key_replay(client):
    client.post("/v1/config", json={"version": 1, "rules": [RULE]}, headers=H)
    body = {"events": [{
        "event_id": "idem-evt", "event_time": 1_700_000_000 - 86400,
        "tenant": "acme", "name": "api", "rule_scope": "global",
        "config_version": 1,
    }]}
    hdr = {**H, "Idempotency-Key": "bf-key-1"}
    first = client.post("/v1/metering/backfill", json=body, headers=hdr)
    replay = client.post("/v1/metering/backfill", json=body, headers=hdr)
    assert replay.json().get("idempotent_replay") is True
    assert first.json()["accepted"] == 1


def test_budget_write_optimistic_concurrency(client):
    assert put_budget(client, "acme", amount=5).status_code == 201
    stale = put_budget(client, "acme", amount=9, expected=1)
    assert stale.status_code == 200  # current version is 1 -> updates to 2
    conflict = put_budget(client, "acme", amount=9, expected=1)
    assert conflict.status_code == 409


def test_explain_reports_budget_projection_without_charging(client):
    client.post("/v1/config", json={"version": 1, "rules": [RULE]}, headers=H)
    put_budget(client, "acme", amount=3, policy="reject")
    info = client.get("/v1/explain", params={
        "name": "api", "tenant": "acme", "client": "c"}).json()
    assert info["budget"]["enabled"] is True
    assert info["budget"]["used"] == 1.0  # projection, no event written
    # explain does not meter: still full budget afterwards
    status = client.get("/v1/budgets/acme", headers=H).json()
    assert status["used"] == 0


def test_unauthenticated_control_plane_is_rejected(client):
    assert client.get("/v1/budgets").status_code == 401
    assert client.get("/v1/metering/events").status_code == 401


def test_tenant_scoped_admin_is_isolated(client):
    # create an identity scoped to tenant "acme" only
    role = client.post("/v1/admin/roles", json={
        "id": "acme-meter",
        "permissions": [
            {"action": "metering:read",
             "scope": {"scope": "tenant", "tenant": "acme"}},
            {"action": "budget:read",
             "scope": {"scope": "tenant", "tenant": "acme"}},
            {"action": "budget:write",
             "scope": {"scope": "tenant", "tenant": "acme"}},
        ],
    }, headers=H)
    assert role.status_code == 201
    ident = client.post("/v1/admin/identities", json={
        "id": "acme-ops", "roles": ["acme-meter"]}, headers=H).json()
    ih = {"Authorization": f"Bearer {ident['token']}"}

    client.post("/v1/config", json={"version": 1, "rules": [RULE]}, headers=H)
    # can read own tenant usage
    r = client.get("/v1/metering/events",
                   params={"tenant": "acme"}, headers=ih)
    assert r.status_code == 200
    # cannot touch another tenant's budget
    denied = client.put("/v1/budgets/other",
                        json={"amount": 1, "alert_thresholds": [1.0],
                              "over_policy": "reject",
                              "period_type": "day"}, headers=ih)
    assert denied.status_code == 403
    # listing is filtered to covered tenants
    put_budget(client, "acme", amount=5)
    put_budget(client, "other", amount=5)
    visible = client.get("/v1/budgets", headers=ih).json()["budgets"]
    assert [b["tenant"] for b in visible] == ["acme"]


def test_audit_trail_records_metering_actions(client):
    client.post("/v1/config", json={"version": 1, "rules": [RULE]}, headers=H)
    put_budget(client, "acme", amount=1)
    client.get("/v1/resolve", params={"name": "api", "tenant": "acme"})
    for type_ in ("budget_change", "budget_alert", "usage_event"):
        recs = client.get("/v1/audit", params={"type": type_}, headers=H)
        assert recs.status_code == 200 and recs.json()["records"]


def test_region_admin_can_manage_tenant_budgets_but_not_global(client):
    role = client.post("/v1/admin/roles", json={
        "id": "eu-admin",
        "permissions": [
            {"action": a, "scope": {"scope": "region", "region": "eu"}}
            for a in ("budget:read", "budget:write", "metering:read")
        ],
    }, headers=H)
    assert role.status_code == 201
    ident = client.post("/v1/admin/identities", json={
        "id": "eu-ops", "roles": ["eu-admin"]}, headers=H).json()
    ih = {"Authorization": f"Bearer {ident['token']}"}

    # Region scope inherits every tenant-level resource (any tenant id).
    ok = client.put("/v1/budgets/acme", json={
        "period_type": "day", "amount": 5,
        "alert_thresholds": [1.0], "over_policy": "reject"}, headers=ih)
    assert ok.status_code in (200, 201)
    # But a tenant budget cannot be widened into global powers: backfill /
    # global recompute require their own actions and are absent here.
    assert client.get("/v1/metering/events", headers=ih).status_code == 200
    recompute = client.post(
        "/v1/metering/recompute", json={}, headers=ih)
    assert recompute.status_code == 403


def test_invalid_backfill_payload_is_rejected(client):
    # empty event list
    assert client.post("/v1/metering/backfill", json={"events": []},
                       headers=H).status_code == 422
    # missing event_time and tenant
    bad = client.post("/v1/metering/backfill", json={
        "events": [{"tenant": "", "event_time": None}]}, headers=H)
    assert bad.status_code == 422
    # bad rule_scope
    bad_scope = client.post("/v1/metering/backfill", json={"events": [{
        "tenant": "acme", "event_time": 1700000000,
        "rule_scope": "galactic"}]}, headers=H)
    assert bad_scope.status_code == 422


def test_invalid_budget_is_rejected(client):
    bad_amount = client.put("/v1/budgets/acme", json={
        "period_type": "day", "amount": 0,
        "alert_thresholds": [1.0], "over_policy": "reject"}, headers=H)
    assert bad_amount.status_code == 422
    bad_policy = client.put("/v1/budgets/acme", json={
        "period_type": "week", "amount": 1,
        "alert_thresholds": [1.0], "over_policy": "reject"}, headers=H)
    assert bad_policy.status_code == 422
