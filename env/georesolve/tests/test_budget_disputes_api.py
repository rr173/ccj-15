"""End-to-end API tests for budget billing disputes."""
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


def make_identity(client, ident_id, scopes):
    role_id = f"role-{ident_id}"
    client.post(
        "/v1/admin/roles",
        json={
            "id": role_id,
            "permissions": [
                {"action": action, "scope": (
                    {"scope": "tenant", "tenant": "acme"}
                    if scope == "tenant"
                    else {"scope": scope}
                )}
                for action, scope in scopes
            ],
        },
        headers=H,
    )
    res = client.post(
        "/v1/admin/identities",
        json={"id": ident_id, "roles": [role_id]},
        headers=H,
    )
    return res.json()["token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def setup(client, amount=3):
    client.post("/v1/config", json={"version": 1, "rules": [RULE]}, headers=H)
    client.put(
        "/v1/budgets/acme",
        json={
            "period_type": "day", "amount": amount,
            "alert_thresholds": [1.0], "over_policy": "reject",
        },
        headers=H,
    )
    ids = []
    for i in range(3):
        r = client.get(
            "/v1/resolve",
            params={"name": "api", "tenant": "acme", "client": "c"},
            headers={"X-Request-Id": f"ev-{i}"},
        )
        assert r.status_code == 200
        ids.append(f"ev-{i}")
    return ids


def create_dispute(client, token, ids, qty=-1.0, **extra):
    body = {
        "tenant": "acme", "event_ids": ids, "reason": "double charge",
        "adjustment_quantity": qty, "submit": True,
    }
    body.update(extra)
    r = client.post("/v1/budget-disputes", json=body, headers=auth(token))
    return r


def test_full_happy_path_api(client):
    ids = setup(client)
    alice = make_identity(
        client, "alice", [("budget:write", "tenant"), ("budget:read", "tenant")]
    )
    bob = make_identity(
        client, "bob", [("budget:write", "tenant"), ("budget:read", "tenant")]
    )

    r = create_dispute(client, alice, [ids[0]])
    assert r.status_code == 201, r.text
    did = r.json()["dispute"]["id"]
    assert r.json()["dispute"]["status"] == "pending_review"
    assert r.json()["dispute"]["frozen_policy"]["policy"]["source"] == "tenant"

    # The creator cannot approve their own dispute.
    r = client.post(
        f"/v1/budget-disputes/{did}/approve", json={}, headers=auth(alice)
    )
    assert r.status_code == 409 and "self_approval" in r.json()["detail"]

    r = client.post(
        f"/v1/budget-disputes/{did}/approve", json={}, headers=auth(bob)
    )
    assert r.status_code == 200
    version = r.json()["dispute"]["version"]

    # expected_version mismatch conflicts.
    r = client.post(
        f"/v1/budget-disputes/{did}/apply",
        json={"expected_version": version + 99},
        headers=auth(bob),
    )
    assert r.status_code == 409

    r = client.post(
        f"/v1/budget-disputes/{did}/apply",
        json={"expected_version": version},
        headers=auth(bob),
    )
    assert r.status_code == 200
    assert r.json()["dispute"]["status"] == "applied"

    detail = client.get(
        f"/v1/budget-disputes/{did}", headers=auth(bob)
    ).json()
    actions = [h["action"] for h in detail["history"]]
    assert actions == ["created", "submitted", "approved", "applied"]

    # The gate immediately uses the adjusted projection: raw 3, adjusted 2,
    # so one more unit fits within the budget of 3.
    adjusted = client.get(
        "/v1/budgets/acme/adjusted", headers=auth(bob)
    ).json()
    assert adjusted["raw_used"] == 3.0
    assert adjusted["adjusted_used"] == 2.0
    assert len(adjusted["adjustments"]) == 1

    gate = client.get(
        "/v1/explain", params={"name": "api", "tenant": "acme", "client": "c"},
    ).json()["budget"]
    assert gate["raw_used"] == 3.0 and gate["used"] == 3.0  # projected
    assert gate["normal_adjustment"] == -1.0
    assert gate["allowed"] is True


def test_idempotency_key_replays_approval(client):
    ids = setup(client)
    alice = make_identity(client, "alice", [("budget:write", "tenant")])
    bob = make_identity(client, "bob", [("budget:write", "tenant")])
    did = create_dispute(client, alice, [ids[0]]).json()["dispute"]["id"]

    headers = {**auth(bob), "Idempotency-Key": "approve-1"}
    first = client.post(
        f"/v1/budget-disputes/{did}/approve", json={}, headers=headers
    )
    assert first.status_code == 200
    replay = client.post(
        f"/v1/budget-disputes/{did}/approve", json={}, headers=headers
    )
    assert replay.status_code == 200
    assert replay.json()["idempotent_replay"] is True
    # A replay does not re-audit.
    audits = client.get(
        "/v1/audit", params={"type": "budget_dispute", "limit": 50}, headers=H
    ).json()["records"]
    approves = [
        a for a in audits
        if a["details"].get("action") == "approved"
    ]
    assert len(approves) == 1


def test_concurrent_apply_only_one_wins(client):
    ids = setup(client)
    alice = make_identity(client, "alice", [("budget:write", "tenant")])
    bob = make_identity(client, "bob", [("budget:write", "tenant")])
    did = create_dispute(client, alice, [ids[0]]).json()["dispute"]["id"]
    version = client.post(
        f"/v1/budget-disputes/{did}/approve", json={}, headers=auth(bob)
    ).json()["dispute"]["version"]

    r1 = client.post(
        f"/v1/budget-disputes/{did}/apply",
        json={"expected_version": version}, headers=auth(bob),
    )
    r2 = client.post(
        f"/v1/budget-disputes/{did}/apply",
        json={"expected_version": version}, headers=auth(bob),
    )
    assert r1.status_code == 200
    assert r2.status_code == 409
    adjustments = client.get(
        "/v1/budgets/acme/adjustments", headers=H
    ).json()["adjustments"]
    assert len(adjustments) == 1


def test_reject_then_apply_conflicts(client):
    ids = setup(client)
    alice = make_identity(client, "alice", [("budget:write", "tenant")])
    bob = make_identity(client, "bob", [("budget:write", "tenant")])
    did = create_dispute(client, alice, [ids[0]]).json()["dispute"]["id"]
    assert client.post(
        f"/v1/budget-disputes/{did}/reject",
        json={"comment": "no evidence"}, headers=auth(bob),
    ).status_code == 200
    assert client.post(
        f"/v1/budget-disputes/{did}/apply", json={}, headers=auth(bob)
    ).status_code == 409


def test_validation_refusals(client):
    ids = setup(client)
    alice = make_identity(client, "alice", [("budget:write", "tenant")])

    # Unknown event.
    r = create_dispute(client, alice, ["ghost"])
    assert r.status_code == 409 and "unknown_event" in r.json()["detail"]
    # Duplicate references.
    r = create_dispute(client, alice, [ids[0], ids[0]])
    assert r.status_code == 409 and "duplicate_event" in r.json()["detail"]
    # Adjusted usage negative.
    r = create_dispute(client, alice, [ids[0]], qty=-100)
    assert r.status_code == 409 and "negative_usage" in r.json()["detail"]
    # Blank reason / zero quantity -> 422.
    r = client.post(
        "/v1/budget-disputes",
        json={"tenant": "acme", "event_ids": [ids[0]],
              "reason": "  ", "adjustment_quantity": -1},
        headers=auth(alice),
    )
    assert r.status_code == 422
    r = client.post(
        "/v1/budget-disputes",
        json={"tenant": "acme", "event_ids": [ids[0]],
              "reason": "x", "adjustment_quantity": 0},
        headers=auth(alice),
    )
    assert r.status_code == 422
    # The refusals are audited.
    denied = client.get(
        "/v1/audit", params={"type": "budget_policy_denied", "limit": 50},
        headers=H,
    ).json()["records"]
    reasons = {r["details"]["reason"] for r in denied}
    assert {"unknown_event", "duplicate_event", "negative_usage"} <= reasons


def test_cross_tenant_event_rejected(client):
    ids = setup(client)
    # The event belongs to acme; create a dispute claiming tenant other.
    alice = make_identity(
        client, "alice-global", [("budget:write", "global")]
    )
    r = client.post(
        "/v1/budget-disputes",
        json={
            "tenant": "other", "event_ids": [ids[0]],
            "reason": "x", "adjustment_quantity": -1, "submit": True,
        },
        headers=auth(alice),
    )
    assert r.status_code == 409 and "cross_tenant_event" in r.json()["detail"]


def test_tenant_scoped_admin_cannot_touch_other_tenant(client):
    ids = setup(client)
    carol = make_identity(
        client, "carol", [("budget:write", "tenant"), ("budget:read", "tenant")]
    )
    # carol's role covers only acme; create for another tenant -> 403.
    r = client.post(
        "/v1/budget-disputes",
        json={
            "tenant": "someoneelse", "event_ids": [ids[0]],
            "reason": "x", "adjustment_quantity": -1,
        },
        headers=auth(carol),
    )
    assert r.status_code == 403


def test_list_is_scope_filtered(client):
    ids = setup(client)
    alice = make_identity(
        client, "alice2", [("budget:write", "tenant"), ("budget:read", "tenant")]
    )
    create_dispute(client, alice, [ids[0]], submit=False)
    # A tenant-scoped reader sees acme disputes...
    rows = client.get("/v1/budget-disputes", headers=auth(alice)).json()
    assert rows["count"] == 1 and rows["disputes"][0]["tenant"] == "acme"
    # ...and global sees all.
    all_rows = client.get("/v1/budget-disputes", headers=H).json()
    assert all_rows["count"] >= 1


def test_draft_submit_and_revoke_flow(client):
    ids = setup(client)
    alice = make_identity(client, "alice", [("budget:write", "tenant")])
    bob = make_identity(client, "bob", [("budget:write", "tenant")])

    r = create_dispute(client, alice, [ids[0]], submit=False)
    assert r.status_code == 201 and r.json()["dispute"]["status"] == "draft"
    did = r.json()["dispute"]["id"]

    # Revoke a draft before it is reviewed.
    assert client.post(
        f"/v1/budget-disputes/{did}/revoke",
        json={"reason": "mistake"}, headers=auth(alice),
    ).status_code == 200
    detail = client.get(
        f"/v1/budget-disputes/{did}", headers=H
    ).json()
    assert detail["dispute"]["status"] == "revoked"
    assert [h["action"] for h in detail["history"]] == ["created", "revoked"]


def test_reverse_applied_open_period_via_api(client):
    ids = setup(client)
    alice = make_identity(client, "alice", [("budget:write", "tenant")])
    bob = make_identity(client, "bob", [("budget:write", "tenant")])
    did = create_dispute(client, alice, [ids[0]]).json()["dispute"]["id"]
    client.post(
        f"/v1/budget-disputes/{did}/approve", json={}, headers=auth(bob)
    )
    client.post(
        f"/v1/budget-disputes/{did}/apply", json={}, headers=auth(bob)
    )
    r = client.post(
        f"/v1/budget-disputes/{did}/revoke",
        json={"reason": "reversed"}, headers=auth(bob),
    )
    assert r.status_code == 200 and r.json()["dispute"]["status"] == "revoked"
    adjustments = client.get(
        "/v1/budgets/acme/adjustments", headers=H
    ).json()["adjustments"]
    assert {a["direction"] for a in adjustments} == {"apply", "reverse"}
    view = client.get("/v1/budgets/acme/adjusted", headers=H).json()
    assert view["adjusted_used"] == 3.0  # back to raw


def test_retroactive_closed_period_flow_api(client):
    ids = setup(client)
    # The events are today; a retroactive dispute must target a closed
    # period. Backfill one event into yesterday and dispute that.
    import time
    yesterday = time.time() - 86400
    client.post(
        "/v1/metering/backfill",
        json={"events": [{
            "event_id": "old-1", "event_time": yesterday, "tenant": "acme",
            "client_key": "c", "name": "api", "config_version": 1,
            "result": "served", "quantity": 2,
        }]},
        headers=H,
    )
    import datetime
    label = datetime.datetime.utcfromtimestamp(yesterday).strftime("%Y-%m-%d")
    alice = make_identity(client, "alice", [("budget:write", "tenant")])
    bob = make_identity(client, "bob", [("budget:write", "tenant")])

    # Non-retroactive dispute for the closed period is refused.
    r = client.post(
        "/v1/budget-disputes",
        json={
            "tenant": "acme", "period_type": "day", "period": label,
            "event_ids": ["old-1"], "reason": "x",
            "adjustment_quantity": -1, "retroactive": False, "submit": True,
        },
        headers=auth(alice),
    )
    assert r.status_code == 409 and "frozen_period" in r.json()["detail"]

    r = client.post(
        "/v1/budget-disputes",
        json={
            "tenant": "acme", "period_type": "day", "period": label,
            "event_ids": ["old-1"], "reason": "x",
            "adjustment_quantity": -1, "retroactive": True, "submit": True,
        },
        headers=auth(alice),
    )
    assert r.status_code == 201
    did = r.json()["dispute"]["id"]
    client.post(
        f"/v1/budget-disputes/{did}/approve", json={}, headers=auth(bob)
    )
    r = client.post(
        f"/v1/budget-disputes/{did}/apply", json={}, headers=auth(bob)
    )
    assert r.status_code == 200

    view = client.get(
        "/v1/budgets/acme/adjusted",
        params={"period_type": "day", "period": label}, headers=H,
    ).json()
    assert view["raw_used"] == 2.0
    assert view["adjusted_used"] == 2.0  # projection untouched
    assert view["retroactive_adjustment"] == -1.0
    assert view["adjusted_including_retroactive"] == 1.0

    # The retroactive adjustment cannot be revoked.
    assert client.post(
        f"/v1/budget-disputes/{did}/revoke", json={}, headers=auth(bob)
    ).status_code == 409


def test_requires_authentication(client):
    r = client.get("/v1/budget-disputes")
    assert r.status_code == 401


def test_unknown_dispute_is_404(client):
    r = client.get("/v1/budget-disputes/nope", headers=H)
    assert r.status_code == 404


def test_applied_credit_reopens_gate_for_following_resolves(client):
    ids = setup(client, amount=3)
    alice = make_identity(client, "alice", [("budget:write", "tenant")])
    bob = make_identity(client, "bob", [("budget:write", "tenant")])
    # Budget exhausted: the next resolve is rejected with 402.
    denied = client.get(
        "/v1/resolve",
        params={"name": "api", "tenant": "acme", "client": "c"},
        headers={"X-Request-Id": "denied-1"},
    )
    assert denied.status_code == 402

    did = create_dispute(client, alice, [ids[0]]).json()["dispute"]["id"]
    client.post(
        f"/v1/budget-disputes/{did}/approve", json={}, headers=auth(bob)
    )
    assert client.post(
        f"/v1/budget-disputes/{did}/apply", json={}, headers=auth(bob)
    ).status_code == 200

    # The adjusted projection (raw 3, adjusted 2) lets the next resolution
    # through immediately, without any modification to the original events.
    allowed = client.get(
        "/v1/resolve",
        params={"name": "api", "tenant": "acme", "client": "c"},
        headers={"X-Request-Id": "after-credit"},
    )
    assert allowed.status_code == 200
    budget = allowed.json()["budget"]
    assert budget["raw_used"] == 3.0
    assert budget["normal_adjustment"] == -1.0

    events = client.get(
        "/v1/metering/events",
        params={"tenant": "acme", "start": 0, "end": 10**11}, headers=H,
    ).json()["events"]
    original = next(e for e in events if e["event_id"] == ids[0])
    assert original["quantity"] == 1  # immutable


def test_history_time_filter_api(client):
    ids = setup(client)
    alice = make_identity(client, "alice", [("budget:write", "tenant")])
    bob = make_identity(client, "bob", [("budget:write", "tenant")])
    did = create_dispute(client, alice, [ids[0]]).json()["dispute"]["id"]
    client.post(
        f"/v1/budget-disputes/{did}/approve", json={}, headers=auth(bob)
    )
    r = client.get(
        f"/v1/budget-disputes/{did}/history",
        params={"since": 10**11}, headers=H,
    )
    assert r.status_code == 200 and r.json()["history"] == []
    r = client.get(
        f"/v1/budget-disputes/{did}/history", headers=H
    )
    assert [h["action"] for h in r.json()["history"]] == [
        "created", "submitted", "approved"
    ]
