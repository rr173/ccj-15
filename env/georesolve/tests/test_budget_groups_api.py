"""End-to-end API tests for budget groups, inheritance and overrides."""
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


def _make_group(client, gid="g1", amount=3.0, policy="reject", parent=None,
                expected=None, thresholds=None):
    body = {}
    if amount is not None:
        body.update(
            period_type="day", amount=amount,
            alert_thresholds=[1.0] if thresholds is None else thresholds,
            over_policy=policy,
        )
    if parent is not None:
        body["parent_id"] = parent
    if expected is not None:
        body["expected_version"] = expected
    return client.post(
        "/v1/budget-groups", params={"group_id": gid}, json=body, headers=H
    )


def test_group_crud_and_inherited_resolution(client):
    client.post("/v1/config", json={"version": 1, "rules": [RULE]}, headers=H)
    r = _make_group(client, amount=2.0)
    assert r.status_code == 201
    assert r.json()["group"]["version"] == 1

    moved = client.post(
        "/v1/budget-groups/g1/members", params={"tenant": "acme"},
        json={}, headers=H,
    )
    assert moved.status_code == 200
    assert moved.json()["membership"]["group_id"] == "g1"

    groups = client.get("/v1/budget-groups", headers=H).json()["groups"]
    assert {g["id"] for g in groups} == {"g1"}
    one = client.get("/v1/budget-groups/g1", headers=H).json()["group"]
    assert {m["tenant"] for m in one["members"]} == {"acme"}
    assert one["member_count"] == 1

    # resolution shows the inherited source and version
    resolved = client.get(
        "/v1/budgets/acme/resolved", headers=H
    ).json()
    assert resolved["enabled"] is True
    assert resolved["origin"]["source"] == "group"
    assert resolved["origin"]["source_id"] == "g1"
    assert resolved["origin"]["source_version"] == 1
    assert resolved["amount"] == 2.0

    status = client.get("/v1/budgets/acme", headers=H).json()
    assert status["budget"]["source"] == "group"
    assert status["policy_origin"]["source_id"] == "g1"

    # two served requests exhaust the inherited budget; third is rejected
    for i in range(2):
        ok = client.get(
            "/v1/resolve",
            params={"name": "api", "tenant": "acme", "client": "c"},
            headers={"X-Request-Id": f"ok{i}"},
        )
        assert ok.status_code == 200
    denied = client.get(
        "/v1/resolve",
        params={"name": "api", "tenant": "acme", "client": "c"},
        headers={"X-Request-Id": "denied"},
    )
    assert denied.status_code == 402
    body = denied.json()
    assert body["budget"]["policy_source"] == "group"
    assert body["budget"]["policy_origin"]["source_id"] == "g1"


def test_group_parent_inheritance_via_api(client):
    assert _make_group(client, gid="base", amount=5.0).status_code == 201
    r = _make_group(client, gid="child", amount=None, parent="base")
    assert r.status_code == 201
    client.post(
        "/v1/budget-groups/child/members", params={"tenant": "t1"},
        json={}, headers=H,
    )
    resolved = client.get("/v1/budgets/t1/resolved", headers=H).json()
    assert resolved["origin"]["source_id"] == "base"
    assert resolved["origin"]["member_group_id"] == "child"


def test_cyclic_inheritance_returns_409(client):
    _make_group(client, gid="a", amount=1.0)
    _make_group(client, gid="b", amount=2.0)
    client.put(
        "/v1/budget-groups/a",
        json={"period_type": "day", "amount": 1.0,
              "alert_thresholds": [1.0], "over_policy": "reject",
              "parent_id": "b"},
        headers=H,
    )
    close = client.put(
        "/v1/budget-groups/b",
        json={"period_type": "day", "amount": 2.0,
              "alert_thresholds": [1.0], "over_policy": "reject",
              "parent_id": "a"},
        headers=H,
    )
    assert close.status_code == 409
    denials = client.get(
        "/v1/audit",
        params={"type": "budget_policy_denied"}, headers=H,
    ).json()["records"]
    assert any(d["details"]["reason"] == "cyclic_inheritance" for d in denials)


def test_override_approval_workflow_end_to_end(client):
    client.post("/v1/config", json={"version": 1, "rules": [RULE]}, headers=H)
    _make_group(client, amount=100.0)
    client.post(
        "/v1/budget-groups/g1/members", params={"tenant": "acme"},
        json={}, headers=H,
    )

    # requester: a tenant-scoped admin
    client.post("/v1/admin/roles", json={
        "id": "acme-budget",
        "permissions": [
            {"action": "budget:read",
             "scope": {"scope": "tenant", "tenant": "acme"}},
            {"action": "budget:write",
             "scope": {"scope": "tenant", "tenant": "acme"}},
            {"action": "metering:read",
             "scope": {"scope": "tenant", "tenant": "acme"}},
        ],
    }, headers=H)
    requester = client.post("/v1/admin/identities", json={
        "id": "acme-ops", "roles": ["acme-budget"]}, headers=H).json()
    rh = {"Authorization": f"Bearer {requester['token']}"}

    import time
    now = time.time()
    create = client.post(
        "/v1/budgets/acme/overrides",
        json={
            "period_type": "day", "amount": 1.0,
            "alert_thresholds": [1.0], "over_policy": "reject",
            "window_start": now - 10, "window_end": now + 3600,
            "reason": "incident cap",
        },
        headers=rh,
    )
    assert create.status_code == 201
    oid = create.json()["override"]["id"]

    # the requester cannot approve its own request
    self_approval = client.post(
        f"/v1/budget-overrides/{oid}/approve", json={}, headers=rh
    )
    assert self_approval.status_code == 409

    # a different authorized admin approves
    approve = client.post(
        f"/v1/budget-overrides/{oid}/approve",
        json={"comment": "ok"}, headers=H,
    )
    assert approve.status_code == 200
    assert approve.json()["override"]["status"] == "approved"

    resolved = client.get("/v1/budgets/acme/resolved", headers=H).json()
    assert resolved["origin"]["source"] == "override"
    assert resolved["origin"]["override_id"] == oid

    # live resolution applies the tight override
    ok = client.get(
        "/v1/resolve", params={"name": "api", "tenant": "acme"},
    )
    assert ok.status_code == 200
    denied = client.get(
        "/v1/resolve", params={"name": "api", "tenant": "acme"},
        headers={"X-Request-Id": "no"},
    )
    assert denied.status_code == 402

    # the requester (tenant admin) may revoke; group policy returns at once
    revoke = client.post(
        f"/v1/budget-overrides/{oid}/revoke", json={}, headers=rh
    )
    assert revoke.status_code == 200
    resolved = client.get("/v1/budgets/acme/resolved", headers=H).json()
    assert resolved["origin"]["source"] == "group"


def test_approver_without_tenant_scope_is_forbidden(client):
    import time
    # requester: tenant-acme budget admin
    client.post("/v1/admin/roles", json={
        "id": "acme-budget",
        "permissions": [
            {"action": "budget:read",
             "scope": {"scope": "tenant", "tenant": "acme"}},
            {"action": "budget:write",
             "scope": {"scope": "tenant", "tenant": "acme"}},
        ],
    }, headers=H)
    req = client.post("/v1/admin/identities", json={
        "id": "acme-ops", "roles": ["acme-budget"]}, headers=H).json()
    rh = {"Authorization": f"Bearer {req['token']}"}
    # approver: only tenant-other budget admin (a *different* person, but
    # lacking coverage of acme) must not be able to approve
    client.post("/v1/admin/roles", json={
        "id": "other-budget",
        "permissions": [
            {"action": "budget:read",
             "scope": {"scope": "tenant", "tenant": "other"}},
            {"action": "budget:write",
             "scope": {"scope": "tenant", "tenant": "other"}},
        ],
    }, headers=H)
    appr = client.post("/v1/admin/identities", json={
        "id": "other-ops", "roles": ["other-budget"]}, headers=H).json()
    ah = {"Authorization": f"Bearer {appr['token']}"}

    now = time.time()
    oid = client.post(
        "/v1/budgets/acme/overrides",
        json={"period_type": "day", "amount": 1.0,
              "alert_thresholds": [1.0], "over_policy": "reject",
              "window_start": now - 5, "window_end": now + 3600},
        headers=rh,
    ).json()["override"]["id"]
    forbidden = client.post(
        f"/v1/budget-overrides/{oid}/approve", json={}, headers=ah
    )
    assert forbidden.status_code == 403
    # still pending, visible to root
    assert client.get(
        f"/v1/budget-overrides/{oid}", headers=H
    ).json()["override"]["status"] == "pending"


def test_tenant_admin_cannot_manage_groups_or_migrate(client):
    client.post("/v1/admin/roles", json={
        "id": "acme-budget",
        "permissions": [
            {"action": "budget:read",
             "scope": {"scope": "tenant", "tenant": "acme"}},
            {"action": "budget:write",
             "scope": {"scope": "tenant", "tenant": "acme"}},
        ],
    }, headers=H)
    ident = client.post("/v1/admin/identities", json={
        "id": "acme-ops", "roles": ["acme-budget"]}, headers=H).json()
    ih = {"Authorization": f"Bearer {ident['token']}"}

    # group CRUD is global-only
    assert _make_group(client, amount=1.0).status_code == 201
    denied_create = client.post(
        "/v1/budget-groups", params={"group_id": "x"},
        json={"period_type": "day", "amount": 1.0,
              "alert_thresholds": [1.0], "over_policy": "reject"},
        headers=ih,
    )
    assert denied_create.status_code == 403
    # a tenant-scoped admin cannot migrate memberships either (cross-scope)
    denied_move = client.post(
        "/v1/budget-groups/g1/members", params={"tenant": "acme"},
        json={}, headers=ih,
    )
    assert denied_move.status_code == 403
    # cannot touch another tenant's override flow
    other = client.post(
        "/v1/budgets/other/overrides",
        json={"period_type": "day", "amount": 1.0,
              "alert_thresholds": [1.0], "over_policy": "reject",
              "window_start": 1, "window_end": 2},
        headers=ih,
    )
    assert other.status_code == 403


def test_member_migration_optimistic_concurrency_conflict(client):
    _make_group(client, gid="a", amount=1.0)
    _make_group(client, gid="b", amount=2.0)
    client.post(
        "/v1/budget-groups/a/members", params={"tenant": "acme"},
        json={}, headers=H,
    )
    # move to b at version 1
    first = client.post(
        "/v1/budget-groups/b/members", params={"tenant": "acme"},
        json={"expected_version": 1}, headers=H,
    )
    assert first.status_code == 200
    # a stale expected_version loses with 409
    stale = client.post(
        "/v1/budget-groups/a/members", params={"tenant": "acme"},
        json={"expected_version": 1}, headers=H,
    )
    assert stale.status_code == 409


def test_idempotency_key_replays_group_and_override_writes(client):
    import time
    now = time.time()
    hdr = {**H, "Idempotency-Key": "grp-key-1"}
    body = {"period_type": "day", "amount": 5.0,
            "alert_thresholds": [1.0], "over_policy": "reject"}
    first = client.post(
        "/v1/budget-groups", params={"group_id": "g1"},
        json=body, headers=hdr,
    )
    replay = client.post(
        "/v1/budget-groups", params={"group_id": "g1"},
        json=body, headers=hdr,
    )
    assert first.status_code == 201
    assert replay.json().get("idempotent_replay") is True
    # one group at version 1, no second revision
    group = client.get("/v1/budget-groups/g1", headers=H).json()["group"]
    assert group["version"] == 1

    ohdr = {**H, "Idempotency-Key": "ovr-key-1"}
    payload = {
        "period_type": "day", "amount": 1.0,
        "alert_thresholds": [1.0], "over_policy": "reject",
        "window_start": now - 5, "window_end": now + 3600,
    }
    r1 = client.post("/v1/budgets/acme/overrides", json=payload, headers=ohdr)
    r2 = client.post("/v1/budgets/acme/overrides", json=payload, headers=ohdr)
    assert r1.status_code == 201
    assert r2.json().get("idempotent_replay") is True
    assert r1.json()["override"]["id"] == r2.json()["override"]["id"]


def test_elapsed_window_cannot_be_requested(client):
    import time
    now = time.time()
    create = client.post(
        "/v1/budgets/acme/overrides",
        json={"period_type": "day", "amount": 1.0,
              "alert_thresholds": [1.0], "over_policy": "reject",
              "window_start": now - 100, "window_end": now - 1},
        headers=H,
    )
    # a window already ended cannot even be requested
    assert create.status_code == 409


def test_audit_records_policy_lifecycle(client):
    import time
    now = time.time()
    _make_group(client, amount=3.0)
    client.post(
        "/v1/budget-groups/g1/members", params={"tenant": "acme"},
        json={}, headers=H,
    )
    create = client.post(
        "/v1/budgets/acme/overrides",
        json={"period_type": "day", "amount": 1.0,
              "alert_thresholds": [1.0], "over_policy": "reject",
              "window_start": now - 5, "window_end": now + 3600},
        headers=H,
    )
    oid = create.json()["override"]["id"]
    client.post(f"/v1/budget-overrides/{oid}/approve", json={}, headers=H)

    types = ("budget_group", "budget_membership", "budget_override")
    for type_ in types:
        recs = client.get(
            "/v1/audit", params={"type": type_}, headers=H
        ).json()["records"]
        assert recs, type_
