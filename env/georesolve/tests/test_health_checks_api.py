"""End-to-end API tests for health-check orchestration endpoints."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import Components, create_app

TOKEN = "test-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

CONFIG_V1 = {
    "version": 1,
    "rules": [
        {"name": "api", "scope": "global", "rule_version": 1, "ttl": 60,
         "targets": [
             {"id": "b1", "address": "tcp://10.0.0.1:80", "weight": 3},
             {"id": "b2", "address": "tcp://10.0.0.2:80", "weight": 1},
         ]},
        {"name": "api", "scope": "tenant", "tenant": "vip", "rule_version": 1,
         "ttl": 60,
         "targets": [{"id": "vip1", "address": "tcp://10.2.0.1:80"}]},
    ],
}


@pytest.fixture
def env(tmp_path):
    comp = Components(
        db_path=str(tmp_path / "hc-api.db"),
        admin_token=TOKEN,
        enable_background=False,
    )
    app = create_app(comp)
    with TestClient(app) as c:
        c.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
        yield c, comp


@pytest.fixture
def client(env):
    return env[0]


def policy_body(**over):
    body = {
        "interval_seconds": 2.0,
        "timeout_seconds": 0.5,
        "fail_threshold": 2,
        "recover_threshold": 2,
        "maintenance_windows": [],
        "priority": 10,
    }
    body.update(over)
    return body


# -- CRUD ----------------------------------------------------------------------


def test_policy_create_get_list_and_default_checks(client):
    r = client.put("/v1/health/targets/b1/policy", json=policy_body(),
                   headers=HEADERS)
    assert r.status_code in (200, 201), r.text
    assert r.json()["created"] is True
    assert r.json()["policy"]["policy_version"] == 1
    assert r.json()["policy"]["checks"] == [
        {"type": "tcp", "port": None, "path": None, "timeout_seconds": None,
         "expect_status": None, "expect_json": False, "expect_field": None,
         "content_regex": None}
    ]

    assert client.get("/v1/health/targets/b1", headers=HEADERS).json()[
        "state"]["source"] == "check"
    policies = client.get("/v1/health/policies", headers=HEADERS).json()
    assert policies["count"] == 1

    # Idempotent identical PUT.
    r = client.put("/v1/health/targets/b1/policy", json=policy_body(),
                   headers=HEADERS)
    assert r.json()["created"] is False
    assert r.json()["policy"]["policy_version"] == 1


def test_policy_for_unknown_target_404(client):
    r = client.put("/v1/health/targets/zzz/policy", json=policy_body(),
                   headers=HEADERS)
    assert r.status_code == 404


def test_invalid_policy_is_422(client):
    r = client.put("/v1/health/targets/b1/policy",
                   json=policy_body(interval_seconds=-1), headers=HEADERS)
    assert r.status_code == 422
    r = client.put(
        "/v1/health/targets/b1/policy",
        json=policy_body(checks=[{"type": "tcp", "path": "/nope"}]),
        headers=HEADERS,
    )
    assert r.status_code == 422
    r = client.put(
        "/v1/health/targets/b1/policy",
        json=policy_body(maintenance_windows=[{"start": 20, "end": 10}]),
        headers=HEADERS,
    )
    assert r.status_code == 422


def test_policy_expected_version_conflict_and_update(client):
    client.put("/v1/health/targets/b1/policy", json=policy_body(),
               headers=HEADERS)
    r = client.put("/v1/health/targets/b1/policy",
                   json=policy_body(priority=1, expected_version=99),
                   headers=HEADERS)
    assert r.status_code == 409 and r.json()["code"]

    r = client.put("/v1/health/targets/b1/policy",
                   json=policy_body(priority=1, expected_version=1),
                   headers=HEADERS)
    assert r.status_code == 200 and r.json()["policy"]["policy_version"] == 2


def test_delete_policy_and_revisions(client):
    client.put("/v1/health/targets/b1/policy", json=policy_body(),
               headers=HEADERS)
    r = client.delete("/v1/health/targets/b1/policy?expected_version=1",
                      headers=HEADERS)
    assert r.status_code == 200 and r.json()["deleted"] == "b1"
    st = client.get("/v1/health/targets/b1", headers=HEADERS).json()["state"]
    assert st["source"] == "unmanaged" and st["healthy"] is True
    revs = client.get("/v1/health/policy-revisions?target_id=b1",
                      headers=HEADERS).json()["revisions"]
    assert [x["action"] for x in revs] == ["deleted", "created"]


# -- idempotency ----------------------------------------------------------------


def test_idempotency_key_replays_policy_create(client):
    h = {**HEADERS, "Idempotency-Key": "k1"}
    r1 = client.put("/v1/health/targets/b1/policy", json=policy_body(),
                    headers=h)
    r2 = client.put("/v1/health/targets/b1/policy", json=policy_body(),
                    headers=h)
    assert r1.status_code == 201 and r2.status_code == 201
    assert r2.json()["idempotent_replay"] is True
    assert r1.json()["policy"]["policy_version"] == r2.json()[
        "policy"]["policy_version"]
    revs = client.get("/v1/health/policy-revisions?target_id=b1",
                      headers=HEADERS).json()["revisions"]
    assert len(revs) == 1


def test_idempotency_key_same_key_different_payload_conflicts(client):
    client.put("/v1/health/targets/b1/policy", json=policy_body(),
               headers={**HEADERS, "Idempotency-Key": "k"}, )
    r = client.put("/v1/health/targets/b1/policy",
                   json=policy_body(priority=1),
                   headers={**HEADERS, "Idempotency-Key": "k"})
    assert r.status_code == 409


# -- manual control ---------------------------------------------------------------


def test_pause_resume_override_and_revoke(client):
    client.put("/v1/health/targets/b1/policy", json=policy_body(),
               headers=HEADERS)
    r = client.post("/v1/health/targets/b1/override",
                    json={"healthy": False, "reason": "drain"},
                    headers=HEADERS)
    assert r.status_code == 200 and r.json()["state"]["healthy"] is False
    assert r.json()["state"]["source"] == "manual_override"
    assert r.json()["state"]["override"]["reason"] == "drain"

    assert client.get("/v1/health/targets/b1", headers=HEADERS).json()[
        "state"]["source"] == "manual_override"

    r = client.post("/v1/health/targets/b1/pause", json={}, headers=HEADERS)
    # Override takes precedence over pause.
    assert r.json()["state"]["source"] == "manual_override"

    client.post("/v1/health/targets/b1/override/revoke", json={},
                headers=HEADERS)
    st = client.get("/v1/health/targets/b1", headers=HEADERS).json()["state"]
    assert st["source"] == "paused" and st["paused"] is True

    r = client.post("/v1/health/targets/b1/resume", json={}, headers=HEADERS)
    assert r.json()["state"]["source"] == "check"
    assert r.json()["changed"] is True
    # Idempotent resume.
    assert client.post("/v1/health/targets/b1/resume", json={},
                       headers=HEADERS).json()["changed"] is False


def test_override_expiry_and_expected_version(client):
    client.put("/v1/health/targets/b1/policy", json=policy_body(),
               headers=HEADERS)
    r = client.post("/v1/health/targets/b1/override",
                    json={"healthy": False}, headers=HEADERS)
    sv = r.json()["state"]["state_version"]
    bad = client.post("/v1/health/targets/b1/resume",
                      json={"expected_version": sv + 100}, headers=HEADERS)
    assert bad.status_code == 409


def test_legacy_override_endpoint_backed_by_orchestrator(client):
    r = client.post("/v1/health/targets/b1", json={"healthy": False},
                    headers=HEADERS)
    assert r.status_code == 200 and r.json()["healthy"] is False
    st = client.get("/v1/health/targets/b1", headers=HEADERS).json()["state"]
    assert st["source"] == "manual_override"
    # Resolution selection excludes the forced-down target.
    ans = client.get("/v1/resolve",
                     params={"name": "api", "client": "1.1.1.1"}).json()
    assert ans["chosen"] == "b2"


# -- history -----------------------------------------------------------------------


def test_history_filter_by_policy_version_and_pagination(client, env, monkeypatch):
    comp = env[1]

    async def always_ok(method, address, timeout):
        return {"type": "tcp", "ok": True, "reason": None, "status": None,
                "duration_ms": 0.1, "detail": ""}

    monkeypatch.setattr("app.health_checks.run_probe", always_ok)
    client.put("/v1/health/targets/b1/policy",
               json=policy_body(fail_threshold=3), headers=HEADERS)
    for _ in range(3):
        r = client.post("/v1/health/targets/b1/check", headers=HEADERS)
        assert r.status_code == 200 and r.json()["ran"] is True
    client.put("/v1/health/targets/b1/policy",
               json=policy_body(priority=1), headers=HEADERS)
    client.post("/v1/health/targets/b1/check", headers=HEADERS)

    page = client.get(
        "/v1/health/targets/b1/history?limit=2", headers=HEADERS
    ).json()
    assert [x["seq"] for x in page["items"]] == [1, 2]
    assert page["has_more"] is True and page["order"] == "seq:asc"
    nxt = page["next_cursor"]
    page2 = client.get(
        f"/v1/health/targets/b1/history?limit=2&after_seq={nxt}",
        headers=HEADERS,
    ).json()
    assert [x["seq"] for x in page2["items"]] == [3, 4]

    v1 = client.get(
        "/v1/health/targets/b1/history?policy_version=1", headers=HEADERS
    ).json()
    assert all(x["policy_version"] == 1 for x in v1["items"])
    check = next(x for x in v1["items"] if x["kind"] == "check")
    assert check["started_at"] is not None
    assert check["response_summary"][0]["ok"] is True
    assert check["verdict"] == "success"

    # Policy change never rewrites the earlier rows.
    assert check["detail"]["fail_threshold"] == 3


def test_transition_rows_show_reason_and_before_after(client):
    client.put("/v1/health/targets/b1/policy",
               json=policy_body(), headers=HEADERS)
    client.post("/v1/health/targets/b1/override",
                json={"healthy": False, "reason": "drain"}, headers=HEADERS)
    client.post("/v1/health/targets/b1/override/revoke", json={},
                headers=HEADERS)
    rows = client.get(
        "/v1/health/targets/b1/history?kind=transition", headers=HEADERS
    ).json()["items"]
    reasons = {x["transition"]["reason"] for x in rows}
    assert "manual_override" in reasons
    assert "manual_override_revoked" in reasons
    ov = next(x for x in rows if x["transition"]["reason"] == "manual_override")
    assert ov["transition"]["from_source"] == "check"
    assert ov["transition"]["to_source"] == "manual_override"
    assert ov["transition"]["from_healthy"] is True
    assert ov["transition"]["to_healthy"] is False


# -- maintenance window --------------------------------------------------------------


def test_maintenance_window_holds_target_out(client, monkeypatch):
    # Window covering the whole test period.
    client.put(
        "/v1/health/targets/b1/policy",
        json=policy_body(maintenance_windows=[
            {"start": 0, "end": 2_000_000_000, "note": "rack"}]),
        headers=HEADERS,
    )
    st = client.get("/v1/health/targets/b1", headers=HEADERS).json()["state"]
    assert st["source"] == "maintenance" and st["healthy"] is False
    r = client.post("/v1/health/targets/b1/check", headers=HEADERS)
    assert r.json()["ran"] is False  # probes skipped in maintenance
    ans = client.get("/v1/resolve",
                     params={"name": "api", "client": "9.9.9.9"}).json()
    assert ans["chosen"] == "b2"


# -- selection uses effective health only ---------------------------------------------


def test_thresholded_failure_removes_target_from_selection(env, monkeypatch):
    client, comp = env

    async def flaky(method, address, timeout):
        ok = "10.0.0.2" not in address  # b2 fails
        return {"type": "tcp", "ok": ok,
                "reason": None if ok else "connection_error",
                "status": None, "duration_ms": 0.1,
                "detail": "" if ok else "refused"}

    monkeypatch.setattr("app.health_checks.run_probe", flaky)
    client.put("/v1/health/targets/b2/policy",
               json=policy_body(fail_threshold=2, recover_threshold=1),
               headers=HEADERS)
    client.post("/v1/health/targets/b2/check", headers=HEADERS)
    # One failure does not flip the observed state yet.
    ans = client.get("/v1/resolve",
                     params={"name": "api", "client": "c1"}).json()
    targets = {t["id"]: t["healthy"] for t in ans["targets"]}
    assert targets["b2"] is True
    client.post("/v1/health/targets/b2/check", headers=HEADERS)
    ans = client.get("/v1/resolve",
                     params={"name": "api", "client": "c1"}).json()
    targets = {t["id"]: t["healthy"] for t in ans["targets"]}
    assert targets["b2"] is False and ans["chosen"] == "b1"


# -- restart persistence ---------------------------------------------------------------


def test_state_survives_restart(tmp_path, monkeypatch):
    path = str(tmp_path / "restart.db")

    def build():
        comp = Components(db_path=path, admin_token=TOKEN,
                          enable_background=False)
        return TestClient(create_app(comp)), comp

    with build()[0] as c:
        c.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
        c.put("/v1/health/targets/b1/policy",
             json=policy_body(fail_threshold=3), headers=HEADERS)

        async def fail(method, address, timeout):
            return {"type": "tcp", "ok": False, "reason": "timeout",
                    "status": None, "duration_ms": 500.0, "detail": "x"}

        monkeypatch.setattr("app.health_checks.run_probe", fail)
        c.post("/v1/health/targets/b1/check", headers=HEADERS)
        c.post("/v1/health/targets/b1/check", headers=HEADERS)
        c.post("/v1/health/targets/b1/override",
               json={"healthy": False, "expires_at": 2_000_000_000},
               headers=HEADERS)
        hist_before = c.get(
            "/v1/health/targets/b1/history?limit=100", headers=HEADERS
        ).json()["items"]

    c2, _ = build()
    with c2:
        st = c2.get("/v1/health/targets/b1", headers=HEADERS).json()["state"]
        assert st["consecutive_failures"] == 2  # unfinished ladder
        assert st["override"]["expires_at"] == 2_000_000_000
        assert st["source"] == "manual_override"
        hist = c2.get(
            "/v1/health/targets/b1/history?limit=100", headers=HEADERS
        ).json()["items"]
        assert [x["seq"] for x in hist] == [x["seq"] for x in hist_before]


# -- drill isolation --------------------------------------------------------------------


def test_drills_do_not_write_live_health_history(client):
    body = {
        "config_version": 1,
        "steps": [
            {"name": "api", "client": "10.0.0.0",
             "health_changes": {"b1": False},
             "expected": {"chosen": "b2"}},
        ],
    }
    did = client.post("/v1/drills", json=body, headers=HEADERS).json()[
        "drill"]["id"]
    client.post(f"/v1/drills/{did}/advance", json={}, headers=HEADERS)

    # Live history stays empty and the live view stays healthy.
    r = client.get("/v1/health/targets/b1/history", headers=HEADERS)
    assert r.status_code == 404
    live = client.get("/v1/health/targets", headers=HEADERS).json()["targets"]
    assert all(t["healthy"] for t in live.values())


# -- authorization ----------------------------------------------------------------------


def test_endpoints_require_authentication(client):
    assert client.get("/v1/health/policies").status_code == 401
    assert client.put("/v1/health/targets/b1/policy",
                      json=policy_body()).status_code == 401


def test_scope_filtering_and_tenant_admin(tmp_path):
    comp = Components(db_path=str(tmp_path / "scope.db"), admin_token=TOKEN,
                      enable_background=False)
    with TestClient(create_app(comp)) as c:
        c.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
        c.post("/v1/admin/roles", headers=HEADERS, json={
            "id": "vip-health",
            "permissions": [
                {"action": "health:read",
                 "scope": {"scope": "tenant", "tenant": "vip"}},
                {"action": "health:write",
                 "scope": {"scope": "tenant", "tenant": "vip"}},
            ],
        })
        c.post("/v1/admin/identities", headers=HEADERS, json={
            "id": "tadmin", "roles": ["vip-health"],
        })
        tok = c.post("/v1/admin/identities", headers=HEADERS, json={
            "id": "tadmin2", "roles": ["vip-health"],
        }).json()["token"]
        h = {"Authorization": f"Bearer {tok}"}
        # The tenant admin sees only vip1 in the global health view.
        view = c.get("/v1/health/targets", headers=h).json()["targets"]
        assert set(view) == {"vip1"}
        # Forcing the global b1 down is forbidden (no full coverage).
        r = c.post("/v1/health/targets/b1", json={"healthy": False}, headers=h)
        assert r.status_code == 403
        r = c.post("/v1/health/targets/vip1", json={"healthy": False},
                   headers=h)
        assert r.status_code == 200
        # A policy on vip1 is allowed.
        r = c.put("/v1/health/targets/vip1/policy", json=policy_body(),
                  headers=h)
        assert r.status_code == 201, r.text
