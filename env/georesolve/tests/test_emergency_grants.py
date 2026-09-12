"""Temporary emergency grant (break-glass elevation) tests.

Covers the request -> approve/reject -> active -> expire/revoke lifecycle:
approval gating (no effect before approval), separation of duties (no
self-approval), delegable-scope enforcement at approval time, per-request
permission computation (config, cache, health and versions all execute
against the grant's scopes), immediate lapse on expiry/revocation (old
tokens cannot keep using the grant), persistence and auditing of every
transition, idempotent retries, and conflict rejection for writes against
decided/expired states under concurrency.
"""
from __future__ import annotations

import concurrent.futures

import pytest
from fastapi.testclient import TestClient

from app.main import Components, create_app

ROOT_TOKEN = "root-token"
ROOT = {"Authorization": f"Bearer {ROOT_TOKEN}"}


class FakeClock:
    def __init__(self, t: float = 1_700_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def perm(action: str, scope: dict) -> dict:
    return {"action": action, "scope": scope}


GLOBAL = {"scope": "global"}
REGION_EU = {"scope": "region", "region": "eu"}
TENANT_VIP = {"scope": "tenant", "tenant": "vip"}
TENANT_ACME = {"scope": "tenant", "tenant": "acme"}


def base_config(version: int) -> dict:
    return {
        "version": version,
        "defaults": {"negative_ttl": 30},
        "rules": [
            {"name": "api", "scope": "global", "rule_version": 1, "ttl": 60,
             "targets": [{"id": "g1", "address": "tcp://10.0.0.1:80",
                          "weight": 1}]},
            {"name": "api", "scope": "region", "region": "eu",
             "rule_version": 1, "ttl": 60,
             "targets": [{"id": "eu1", "address": "tcp://10.1.0.1:80",
                          "weight": 1}]},
            {"name": "api", "scope": "tenant", "tenant": "vip",
             "rule_version": 1, "ttl": 60,
             "targets": [{"id": "vip1", "address": "tcp://10.2.0.1:80",
                          "weight": 1}]},
        ],
    }


@pytest.fixture
def comp(tmp_path):
    return Components(
        db_path=str(tmp_path / "emergency.db"),
        admin_token=ROOT_TOKEN,
        enable_background=False,
    )


@pytest.fixture
def client(comp):
    with TestClient(create_app(comp)) as c:
        yield c


@pytest.fixture
def clock(comp) -> FakeClock:
    """Drive the authz store (and with it grant expiry) deterministically."""
    fake = FakeClock()
    comp.authz._clock = fake
    return fake


def make_admin(client, role_id: str, identity_id: str, permissions: list) -> str:
    """Create a role and an identity holding it; return the identity token."""
    r = client.post(
        "/v1/admin/roles",
        json={"id": role_id, "permissions": permissions},
        headers=ROOT,
    )
    assert r.status_code == 201, r.text
    r = client.post(
        "/v1/admin/identities",
        json={"id": identity_id, "roles": [role_id]},
        headers=ROOT,
    )
    assert r.status_code == 201, r.text
    return r.json()["token"]


def make_plain_identity(client, identity_id: str) -> str:
    """An identity with no roles at all: every permission must come from a grant."""
    r = client.post(
        "/v1/admin/identities",
        json={"id": identity_id, "roles": []},
        headers=ROOT,
    )
    assert r.status_code == 201, r.text
    return r.json()["token"]


def request_grant(client, token: str, identity_id: str, permissions: list,
                  duration: float = 3600, reason: str = "incident-42",
                  headers: dict | None = None) -> dict:
    r = client.post(
        "/v1/admin/emergency-grants",
        json={"identity_id": identity_id, "reason": reason,
              "permissions": permissions, "duration_seconds": duration},
        headers=headers or bearer(token),
    )
    assert r.status_code == 201, r.text
    return r.json()["grant"]


def approve(client, token: str, grant_id: str, **kwargs) -> "TestClient.response":
    return client.post(
        f"/v1/admin/emergency-grants/{grant_id}/approve",
        json=kwargs or {},
        headers=bearer(token),
    )


def get_grant(client, grant_id: str) -> dict:
    r = client.get(f"/v1/admin/emergency-grants/{grant_id}", headers=ROOT)
    assert r.status_code == 200, r.text
    return r.json()["grant"]


def audit_records(client, type_: str) -> list:
    return client.get("/v1/audit", params={"type": type_}, headers=ROOT).json()[
        "records"
    ]


def grant_events(client, action: str) -> list:
    return [
        rec for rec in audit_records(client, "emergency_grant")
        if rec["details"]["action"] == action
    ]


# -- lifecycle ----------------------------------------------------------------


def test_full_lifecycle_request_approve_use_expire(comp, client, clock):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    alice = make_plain_identity(client, "alice")
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])

    # nothing works before the grant exists
    assert client.get("/v1/config", headers=bearer(alice)).status_code == 403

    grant = request_grant(
        client, alice, "alice",
        [perm("config:read", TENANT_VIP), perm("config:write", TENANT_VIP)],
        duration=600,
    )
    assert grant["status"] == "pending"
    assert grant["requested_by"] == "alice"
    assert grant["active"] is False

    # a pending grant grants nothing
    assert client.get("/v1/config", headers=bearer(alice)).status_code == 403

    r = approve(client, approver, grant["id"])
    assert r.status_code == 200, r.text
    body = r.json()["grant"]
    assert body["status"] == "approved" and body["active"] is True
    # the validity window starts at approval time
    assert body["approved_at"] == clock.t
    assert body["expires_at"] == clock.t + 600
    assert body["decided_by"] == "carol"

    # the grant now participates in permission computation, scoped
    r = client.get("/v1/config", headers=bearer(alice))
    assert r.status_code == 200
    assert all(rule["scope"] == "tenant" for rule in r.json()["rules"])
    scoped = {
        "version": 2,
        "rules": [
            {"name": "api", "scope": "tenant", "tenant": "vip",
             "rule_version": 2, "ttl": 30,
             "targets": [{"id": "vip2", "address": "tcp://10.2.0.2:80",
                          "weight": 1}]},
        ],
    }
    r = client.post("/v1/config", json=scoped, headers=bearer(alice))
    assert r.status_code == 200, r.text
    # ...but the grant's scope is enforced: a global rule is out of reach
    evil = {
        "version": 3,
        "rules": [
            {"name": "api", "scope": "global", "rule_version": 3, "ttl": 60,
             "targets": [{"id": "evil", "address": "tcp://9.9.9.9:80",
                          "weight": 1}]},
        ],
    }
    assert client.post("/v1/config", json=evil,
                       headers=bearer(alice)).status_code == 403

    # expiry lapses the grant immediately: the same old token stops working
    clock.advance(601)
    assert client.get("/v1/config", headers=bearer(alice)).status_code == 403
    grant = get_grant(client, grant["id"])
    assert grant["status"] == "expired" and grant["active"] is False

    # every transition is audited
    for action in ("requested", "approved", "expired"):
        events = grant_events(client, action)
        assert len(events) == 1, action
        assert events[0]["details"]["grant_id"] == grant["id"]
        assert events[0]["details"]["identity"] == "alice"
    assert grant_events(client, "requested")[0]["details"]["reason"] == "incident-42"


def test_request_for_another_identity(comp, client, clock):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    bob = make_plain_identity(client, "bob")
    requester = make_admin(client, "req", "dave", [perm("config:read", GLOBAL)])
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])

    grant = request_grant(client, requester, "bob",
                          [perm("config:read", GLOBAL)])
    assert grant["identity_id"] == "bob"
    assert grant["requested_by"] == "dave"
    assert approve(client, approver, grant["id"]).status_code == 200
    assert client.get("/v1/config", headers=bearer(bob)).status_code == 200


def test_pending_grant_visible_and_queryable(comp, client, clock):
    alice = make_plain_identity(client, "alice")
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])
    grant = request_grant(client, alice, "alice",
                          [perm("config:read", TENANT_VIP)])

    # the requester sees its own request; the approver sees delegable ones
    r = client.get("/v1/admin/emergency-grants", headers=bearer(alice))
    assert [g["id"] for g in r.json()["grants"]] == [grant["id"]]
    r = client.get("/v1/admin/emergency-grants",
                   params={"status": "pending"}, headers=bearer(approver))
    assert [g["id"] for g in r.json()["grants"]] == [grant["id"]]
    r = client.get("/v1/admin/emergency-grants",
                   params={"status": "approved"}, headers=bearer(approver))
    assert r.json()["grants"] == []
    r = client.get("/v1/admin/emergency-grants",
                   params={"status": "bogus"}, headers=ROOT)
    assert r.status_code == 400

    # an unrelated identity sees nothing
    r = client.post("/v1/admin/identities", json={"id": "mallory", "roles": []},
                    headers=ROOT)
    token = r.json()["token"]
    r = client.get("/v1/admin/emergency-grants", headers=bearer(token))
    assert r.json()["grants"] == []
    r = client.get(f"/v1/admin/emergency-grants/{grant['id']}",
                   headers=bearer(token))
    assert r.status_code == 403


# -- approval rules -------------------------------------------------------------


def test_approver_cannot_decide_own_request(comp, client, clock):
    admin = make_admin(client, "self-approver", "alice",
                       [perm("admin:manage", GLOBAL)])
    grant = request_grant(client, admin, "alice",
                          [perm("config:read", GLOBAL)])
    r = approve(client, admin, grant["id"])
    assert r.status_code == 403
    r = client.post(f"/v1/admin/emergency-grants/{grant['id']}/reject",
                    json={}, headers=bearer(admin))
    assert r.status_code == 403
    assert get_grant(client, grant["id"])["status"] == "pending"
    # a different admin can still decide
    other = make_admin(client, "other-approver", "carol",
                       [perm("admin:manage", GLOBAL)])
    assert approve(client, other, grant["id"]).status_code == 200


def test_deciding_requires_admin_manage(comp, client, clock):
    alice = make_plain_identity(client, "alice")
    reader = make_admin(client, "reader", "ted", [perm("config:read", GLOBAL)])
    grant = request_grant(client, alice, "alice",
                          [perm("config:read", GLOBAL)])
    r = approve(client, reader, grant["id"])
    assert r.status_code == 403
    assert get_grant(client, grant["id"])["status"] == "pending"


def test_grant_permissions_must_stay_within_approvers_delegable_scope(
    comp, client, clock
):
    alice = make_plain_identity(client, "alice")
    tenant_approver = make_admin(
        client, "vip-approver", "carol", [perm("admin:manage", TENANT_VIP)]
    )
    # region/global elevations exceed a tenant admin's delegable scope
    for scope in (REGION_EU, GLOBAL, TENANT_ACME):
        grant = request_grant(client, alice, "alice",
                              [perm("config:write", scope)])
        r = approve(client, tenant_approver, grant["id"])
        assert r.status_code == 403, scope
        assert get_grant(client, grant["id"])["status"] == "pending"
    # within scope: allowed
    grant = request_grant(client, alice, "alice",
                          [perm("config:write", TENANT_VIP)])
    assert approve(client, tenant_approver, grant["id"]).status_code == 200


def test_reject_lifecycle(comp, client, clock):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    alice = make_plain_identity(client, "alice")
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])
    grant = request_grant(client, alice, "alice",
                          [perm("config:read", GLOBAL)])
    r = client.post(f"/v1/admin/emergency-grants/{grant['id']}/reject",
                    json={"comment": "not justified"}, headers=bearer(approver))
    assert r.status_code == 200
    body = r.json()["grant"]
    assert body["status"] == "rejected"
    assert body["decision_comment"] == "not justified"

    # a rejected grant never takes effect
    assert client.get("/v1/config", headers=bearer(alice)).status_code == 403
    # and it is terminal: further decisions conflict
    assert approve(client, approver, grant["id"]).status_code == 409
    r = client.post(f"/v1/admin/emergency-grants/{grant['id']}/reject",
                    json={}, headers=bearer(approver))
    assert r.status_code == 409
    assert len(grant_events(client, "rejected")) == 1


# -- revocation and expiry ------------------------------------------------------


def test_revoke_takes_effect_immediately(comp, client, clock):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    alice = make_plain_identity(client, "alice")
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])
    grant = request_grant(client, alice, "alice",
                          [perm("config:read", GLOBAL)])
    approve(client, approver, grant["id"])
    assert client.get("/v1/config", headers=bearer(alice)).status_code == 200

    r = client.post(f"/v1/admin/emergency-grants/{grant['id']}/revoke",
                    json={}, headers=bearer(approver))
    assert r.status_code == 200
    assert r.json()["grant"]["status"] == "revoked"
    assert r.json()["grant"]["revoked_by"] == "carol"
    # the very next request with the same token no longer has the permission
    assert client.get("/v1/config", headers=bearer(alice)).status_code == 403
    # revoke is terminal
    r = client.post(f"/v1/admin/emergency-grants/{grant['id']}/revoke",
                    json={}, headers=bearer(approver))
    assert r.status_code == 409
    assert len(grant_events(client, "revoked")) == 1


def test_grantee_can_revoke_own_grant(comp, client, clock):
    alice = make_plain_identity(client, "alice")
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])
    grant = request_grant(client, alice, "alice",
                          [perm("config:read", GLOBAL)])
    approve(client, approver, grant["id"])
    r = client.post(f"/v1/admin/emergency-grants/{grant['id']}/revoke",
                    json={}, headers=bearer(alice))
    assert r.status_code == 200
    assert r.json()["grant"]["status"] == "revoked"


def test_revoke_requires_authority(comp, client, clock):
    alice = make_plain_identity(client, "alice")
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])
    outsider = make_admin(client, "outsider", "mallory",
                          [perm("admin:manage", TENANT_ACME)])
    grant = request_grant(client, alice, "alice",
                          [perm("config:read", GLOBAL)])
    approve(client, approver, grant["id"])
    # mallory's admin:manage does not cover the grant's global scope
    r = client.post(f"/v1/admin/emergency-grants/{grant['id']}/revoke",
                    json={}, headers=bearer(outsider))
    assert r.status_code == 403
    assert get_grant(client, grant["id"])["status"] == "approved"
    denied = audit_records(client, "authz_denied")
    assert any(rec["details"].get("action") == "emergency:revoke"
               and rec["details"]["identity"] == "mallory" for rec in denied)


def test_revoke_pending_or_decided_grant_conflicts(comp, client, clock):
    alice = make_plain_identity(client, "alice")
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])
    pending = request_grant(client, alice, "alice",
                            [perm("config:read", GLOBAL)])
    r = client.post(f"/v1/admin/emergency-grants/{pending['id']}/revoke",
                    json={}, headers=bearer(approver))
    assert r.status_code == 409  # not active yet

    rejected = request_grant(client, alice, "alice",
                             [perm("config:read", GLOBAL)])
    client.post(f"/v1/admin/emergency-grants/{rejected['id']}/reject",
                json={}, headers=bearer(approver))
    r = client.post(f"/v1/admin/emergency-grants/{rejected['id']}/revoke",
                    json={}, headers=bearer(approver))
    assert r.status_code == 409


def test_writes_against_expired_grant_are_rejected(comp, client, clock):
    alice = make_plain_identity(client, "alice")
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])
    grant = request_grant(client, alice, "alice",
                          [perm("config:read", GLOBAL)], duration=30)
    approve(client, approver, grant["id"])

    clock.advance(31)  # lapses the grant
    assert get_grant(client, grant["id"])["status"] == "expired"
    # approve / reject / revoke against the expired state all conflict
    assert approve(client, approver, grant["id"]).status_code == 409
    r = client.post(f"/v1/admin/emergency-grants/{grant['id']}/reject",
                    json={}, headers=bearer(approver))
    assert r.status_code == 409
    r = client.post(f"/v1/admin/emergency-grants/{grant['id']}/revoke",
                    json={}, headers=bearer(approver))
    assert r.status_code == 409
    # exactly one expiry transition was recorded
    assert len(grant_events(client, "expired")) == 1


def test_concurrent_approval_exactly_one_wins(comp, client, clock):
    alice = make_plain_identity(client, "alice")
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])
    grant = request_grant(client, alice, "alice",
                          [perm("config:read", GLOBAL)])

    def attempt(_):
        return approve(client, approver, grant["id"]).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(attempt, range(8)))
    assert codes.count(200) == 1
    assert codes.count(409) == 7
    assert len(grant_events(client, "approved")) == 1


def test_concurrent_revoke_and_expiry_rejects_late_writes(comp, client, clock):
    alice = make_plain_identity(client, "alice")
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])
    grant = request_grant(client, alice, "alice",
                          [perm("config:read", GLOBAL)], duration=30)
    approve(client, approver, grant["id"])
    clock.advance(31)  # grant is now overdue; first touch lapses it

    def attempt(_):
        return client.post(f"/v1/admin/emergency-grants/{grant['id']}/revoke",
                           json={}, headers=bearer(approver)).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        codes = list(pool.map(attempt, range(6)))
    assert codes == [409] * 6
    assert get_grant(client, grant["id"])["status"] == "expired"
    assert len(grant_events(client, "expired")) == 1
    assert grant_events(client, "revoked") == []


def test_optimistic_concurrency_on_decide_and_revoke(comp, client, clock):
    alice = make_plain_identity(client, "alice")
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])
    grant = request_grant(client, alice, "alice",
                          [perm("config:read", GLOBAL)])
    r = approve(client, approver, grant["id"], expected_version=9)
    assert r.status_code == 409
    r = approve(client, approver, grant["id"], expected_version=1)
    assert r.status_code == 200
    r = client.post(f"/v1/admin/emergency-grants/{grant['id']}/revoke",
                    json={"expected_version": 1}, headers=bearer(approver))
    assert r.status_code == 409
    r = client.post(f"/v1/admin/emergency-grants/{grant['id']}/revoke",
                    json={"expected_version": 2}, headers=bearer(approver))
    assert r.status_code == 200


# -- scoped execution of control-plane operations -------------------------------


def test_grant_scopes_cache_flush_health_and_versions(comp, client, clock):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    v2 = base_config(2)
    v2["rules"][2]["rule_version"] = 2
    v2["rules"][2]["targets"] = [
        {"id": "vip2", "address": "tcp://10.2.0.2:80", "weight": 1}
    ]
    client.post("/v1/config", json=v2, headers=ROOT)
    for tenant, region in (("vip", "eu"), ("acme", "us")):
        client.get("/v1/resolve", params={"name": "api", "region": region,
                                          "tenant": tenant, "client": "c"})
    assert len(client.get("/v1/cache", headers=ROOT).json()["entries"]) == 2

    alice = make_plain_identity(client, "alice")
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])
    grant = request_grant(
        client, alice, "alice",
        [perm("cache:read", TENANT_VIP), perm("cache:flush", TENANT_VIP),
         perm("health:read", TENANT_VIP), perm("health:write", TENANT_VIP),
         perm("versions:read", TENANT_VIP)],
    )
    approve(client, approver, grant["id"])

    # cache view and flush are scoped to the grant
    entries = client.get("/v1/cache", headers=bearer(alice)).json()["entries"]
    assert len(entries) == 1 and entries[0]["tenant"] == "vip"
    r = client.post("/v1/cache/flush", headers=bearer(alice))
    assert r.status_code == 200 and r.json()["flushed"] == 1
    remaining = client.get("/v1/cache", headers=ROOT).json()["entries"]
    assert len(remaining) == 1 and remaining[0]["tenant"] == "acme"

    # health override only inside the granted scope
    r = client.post("/v1/health/targets/vip2", json={"healthy": False},
                    headers=bearer(alice))
    assert r.status_code == 200
    r = client.post("/v1/health/targets/g1", json={"healthy": False},
                    headers=bearer(alice))
    assert r.status_code == 403
    targets = client.get("/v1/health/targets",
                         headers=bearer(alice)).json()["targets"]
    assert set(targets) == {"vip2"}

    # version history diffs are filtered to the granted scope
    r = client.get("/v1/config/versions", headers=bearer(alice))
    assert r.status_code == 200
    summaries = [v["summary"] for v in r.json()["versions"] if v["summary"]]
    assert summaries
    for s in summaries:
        for d in s["rule_diffs"]:
            assert d["scope"] == "tenant" and d["tenant"] == "vip"


def test_grant_permissions_show_up_in_decision_audit(comp, client, clock):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    alice = make_plain_identity(client, "alice")
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])
    grant = request_grant(client, alice, "alice",
                          [perm("config:read", GLOBAL)])
    approve(client, approver, grant["id"])
    client.get("/v1/config", headers=bearer(alice))

    decisions = [
        rec for rec in audit_records(client, "authz_decision")
        if rec["details"]["identity"] == "alice"
        and rec["details"]["action"] == "config:read"
        and rec["details"]["outcome"] == "allow"
    ]
    assert decisions
    assert grant["id"] in decisions[0]["details"]["emergency_grants"]


# -- idempotency ------------------------------------------------------------------


def test_idempotent_request_replay(comp, client, clock):
    alice = make_plain_identity(client, "alice")
    key = {"Idempotency-Key": "grant-create-1"}
    payload = {"identity_id": "alice", "reason": "incident",
               "permissions": [perm("config:read", GLOBAL)],
               "duration_seconds": 60}
    r1 = client.post("/v1/admin/emergency-grants", json=payload,
                     headers={**bearer(alice), **key})
    r2 = client.post("/v1/admin/emergency-grants", json=payload,
                     headers={**bearer(alice), **key})
    assert r1.status_code == 201 and r2.status_code == 201
    assert r2.json()["idempotent_replay"] is True
    assert r1.json()["grant"]["id"] == r2.json()["grant"]["id"]
    # the mutation ran exactly once
    grants = client.get("/v1/admin/emergency-grants", headers=ROOT).json()["grants"]
    assert len(grants) == 1
    assert len(grant_events(client, "requested")) == 1

    # same key, different payload -> conflict
    payload["reason"] = "different"
    r = client.post("/v1/admin/emergency-grants", json=payload,
                    headers={**bearer(alice), **key})
    assert r.status_code == 409


def test_idempotent_approve_and_revoke(comp, client, clock):
    alice = make_plain_identity(client, "alice")
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])
    grant = request_grant(client, alice, "alice",
                          [perm("config:read", GLOBAL)])
    key = {"Idempotency-Key": "grant-approve-1"}
    r1 = client.post(f"/v1/admin/emergency-grants/{grant['id']}/approve",
                     json={}, headers={**bearer(approver), **key})
    r2 = client.post(f"/v1/admin/emergency-grants/{grant['id']}/approve",
                     json={}, headers={**bearer(approver), **key})
    assert r1.status_code == 200 and r2.status_code == 200
    assert r2.json()["idempotent_replay"] is True
    assert len(grant_events(client, "approved")) == 1

    key = {"Idempotency-Key": "grant-revoke-1"}
    r1 = client.post(f"/v1/admin/emergency-grants/{grant['id']}/revoke",
                     json={}, headers={**bearer(approver), **key})
    r2 = client.post(f"/v1/admin/emergency-grants/{grant['id']}/revoke",
                     json={}, headers={**bearer(approver), **key})
    assert r1.status_code == 200 and r2.status_code == 200
    assert r2.json()["idempotent_replay"] is True
    assert len(grant_events(client, "revoked")) == 1


# -- validation -------------------------------------------------------------------


def test_request_validation(comp, client, clock):
    alice = make_plain_identity(client, "alice")
    base = {"identity_id": "alice", "reason": "incident",
            "permissions": [perm("config:read", GLOBAL)],
            "duration_seconds": 60}
    for bad in (
        {**base, "reason": ""},
        {**base, "reason": "   "},
        {**base, "permissions": []},
        {**base, "duration_seconds": 0},
        {**base, "duration_seconds": -5},
        {**base, "permissions": [perm("config:fly", GLOBAL)]},
    ):
        r = client.post("/v1/admin/emergency-grants", json=bad,
                        headers=bearer(alice))
        assert r.status_code == 422, bad
    # non-finite durations are rejected by both the API and the store model
    from pydantic import ValidationError

    from app.authz import EmergencyGrant
    from app.main import EmergencyGrantCreateRequest
    for model in (EmergencyGrantCreateRequest,):
        with pytest.raises(ValidationError):
            model(**{**base, "duration_seconds": float("inf")})
    with pytest.raises(ValidationError):
        EmergencyGrant(id="g", identity_id="alice", reason="r",
                       permissions=[perm("config:read", GLOBAL)],
                       duration_seconds=float("nan"))
    # unknown grantee -> 404
    r = client.post("/v1/admin/emergency-grants",
                    json={**base, "identity_id": "ghost"},
                    headers=bearer(alice))
    assert r.status_code == 404
    # unknown grant id -> 404
    assert client.get("/v1/admin/emergency-grants/nope",
                      headers=ROOT).status_code == 404
    approver = make_admin(client, "approver", "carol",
                          [perm("admin:manage", GLOBAL)])
    assert approve(client, approver, "nope").status_code == 404


def test_unauthenticated_cannot_use_grant_endpoints(comp, client, clock):
    make_plain_identity(client, "alice")  # turns enforcement on
    assert client.post("/v1/admin/emergency-grants", json={}).status_code == 401
    assert client.get("/v1/admin/emergency-grants").status_code == 401


# -- persistence --------------------------------------------------------------------


def test_grants_survive_restart(tmp_path):
    db = str(tmp_path / "persist.db")
    clock = FakeClock()
    comp1 = Components(db_path=db, admin_token=ROOT_TOKEN,
                       enable_background=False)
    comp1.authz._clock = clock
    with TestClient(create_app(comp1)) as c1:
        c1.post("/v1/config", json=base_config(1), headers=ROOT)
        alice = make_plain_identity(c1, "alice")
        approver = make_admin(c1, "approver", "carol",
                              [perm("admin:manage", GLOBAL)])
        active = request_grant(c1, alice, "alice",
                               [perm("config:read", GLOBAL)], duration=1000)
        approve(c1, approver, active["id"])
        pending = request_grant(c1, alice, "alice",
                                [perm("cache:read", GLOBAL)], duration=1000)
        short = request_grant(c1, alice, "alice",
                              [perm("health:read", GLOBAL)], duration=10)
        approve(c1, approver, short["id"])
        clock.advance(20)  # lapse the short grant
        assert get_grant(c1, short["id"])["status"] == "expired"

    comp2 = Components(db_path=db, admin_token=ROOT_TOKEN,
                       enable_background=False)
    comp2.authz._clock = clock
    with TestClient(create_app(comp2)) as c2:
        # states survived: active grant still works, pending still pending,
        # expired stays expired
        assert c2.get("/v1/config", headers=bearer(alice)).status_code == 200
        assert get_grant(c2, pending["id"])["status"] == "pending"
        assert get_grant(c2, short["id"])["status"] == "expired"
        # and the still-active grant expires on schedule after the restart
        clock.advance(1000)
        assert c2.get("/v1/config", headers=bearer(alice)).status_code == 403
        assert get_grant(c2, active["id"])["status"] == "expired"
        # audit history survived too
        actions = {rec["details"]["action"]
                   for rec in audit_records(c2, "emergency_grant")}
        assert {"requested", "approved", "expired"} <= actions
