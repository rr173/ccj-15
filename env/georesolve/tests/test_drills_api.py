"""End-to-end API tests for the fault-drill endpoints."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import Components, create_app

TOKEN = "test-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

CONFIG_V1 = {
    "version": 1,
    "defaults": {"negative_ttl": 30},
    "rules": [
        {"name": "api", "scope": "global", "rule_version": 1, "ttl": 60,
         "targets": [
             {"id": "b1", "address": "tcp://10.0.0.1:80", "weight": 3},
             {"id": "b2", "address": "tcp://10.0.0.2:80", "weight": 1},
         ]},
    ],
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
        c.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
        yield c


def drill_body():
    return {
        "config_version": 1,
        "steps": [
            {"name": "api", "client": "10.0.0.0",
             "expected": {"chosen": "b1", "order": ["b1", "b2"]}},
            {"name": "api", "client": "10.0.0.0", "health_changes": {"b1": False},
             "expected": {"chosen": "b2"}},
            {"name": "api", "client": "10.0.0.0", "advance_seconds": 1},
        ],
    }


def test_create_get_list_drill(client):
    r = client.post("/v1/drills", json=drill_body(), headers=HEADERS)
    assert r.status_code == 201, r.text
    did = r.json()["drill"]["id"]
    assert r.json()["drill"]["status"] == "ready"

    r = client.get(f"/v1/drills/{did}", headers=HEADERS)
    assert r.status_code == 200
    body = r.json()["drill"]
    assert set(body["frozen"]["target_manifest"]) == {"b1", "b2"}
    assert body["steps_planned"] == 3

    r = client.get("/v1/drills", headers=HEADERS)
    assert r.status_code == 200 and r.json()["count"] == 1


def test_advance_pause_resume_reset_flow(client):
    did = client.post("/v1/drills", json=drill_body(), headers=HEADERS).json()["drill"]["id"]

    # ready -> advance implicitly starts
    r = client.post(f"/v1/drills/{did}/advance", json={}, headers=HEADERS)
    assert r.status_code == 200, r.text
    step1 = r.json()["step"]
    assert step1["answer"]["chosen"] == "b1"
    assert step1["cache_hit"] is False
    assert r.json()["matched_expected"] is True

    # pause holds; advancing is refused
    r = client.post(f"/v1/drills/{did}/pause", json={}, headers=HEADERS)
    assert r.status_code == 200 and r.json()["status"] == "paused"
    r = client.post(f"/v1/drills/{did}/advance", json={}, headers=HEADERS)
    assert r.status_code == 409 and r.json()["code"] == "status_conflict"
    r = client.post(f"/v1/drills/{did}/resume", json={}, headers=HEADERS)
    assert r.status_code == 200 and r.json()["status"] == "running"

    # step 2 fails b1 over -> deterministic failover to b2
    r = client.post(f"/v1/drills/{did}/advance", json={}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["step"]["answer"]["chosen"] == "b2"
    assert r.json()["step"]["health_after"]["b1"] is False

    # step 3: identical request still within ttl -> simulated cache hit.
    # advance, pause and resume each bumped the drill version (1 -> 5).
    assert r.json()["version"] == 5
    r = client.post(f"/v1/drills/{did}/advance", json={"expected_version": 5},
                    headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["step"]["cache_hit"] is True
    assert r.json()["status"] == "completed"

    # reset wipes the run and lets it start over (step 3 left version at 6)
    r = client.post(f"/v1/drills/{did}/reset", json={"expected_version": 6},
                    headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "ready" and r.json()["current_seq"] == 0
    r = client.get(f"/v1/drills/{did}/steps/1", headers=HEADERS)
    assert r.status_code == 404


def test_step_gap_and_unknown_target_are_rejected(client):
    did = client.post("/v1/drills", json=drill_body(), headers=HEADERS).json()["drill"]["id"]
    r = client.post(f"/v1/drills/{did}/advance", json={"seq": 2}, headers=HEADERS)
    assert r.status_code == 409 and r.json()["code"] == "step_sequence_gap"

    body = drill_body()
    body["steps"][0]["health_changes"] = {"ghost": True}
    r = client.post("/v1/drills", json=body, headers=HEADERS)
    assert r.status_code == 409 and r.json()["code"] == "target_not_in_frozen_manifest"


def test_illegal_health_change_rejected(client):
    did = client.post("/v1/drills", json=drill_body(), headers=HEADERS).json()["drill"]["id"]
    # The sequence is frozen at creation; mutate the manifest via a new drill.
    body = drill_body()
    body["steps"][0]["health_changes"] = {"b1": "down"}
    r = client.post("/v1/drills", json=body, headers=HEADERS)
    assert r.status_code == 409 and r.json()["code"] == "illegal_health_change"
    # The refusal is recorded in the drill-only audit.
    recs = client.get("/v1/drills-audit", params={"action": "drill_create_rejected"},
                      headers=HEADERS).json()["records"]
    assert recs and recs[0]["details"]["code"] == "illegal_health_change"


def test_missing_config_version_is_404(client):
    r = client.post(
        "/v1/drills",
        json={"config_version": 42, "steps": [{"name": "api"}]},
        headers=HEADERS,
    )
    assert r.status_code == 404 and r.json()["code"] == "config_version_not_found"


def test_expected_version_conflict(client):
    did = client.post("/v1/drills", json=drill_body(), headers=HEADERS).json()["drill"]["id"]
    r = client.post(
        f"/v1/drills/{did}/advance", json={"expected_version": 99}, headers=HEADERS
    )
    assert r.status_code == 409 and r.json()["code"] == "expected_version"


def test_idempotent_step_submission(client):
    did = client.post("/v1/drills", json=drill_body(), headers=HEADERS).json()["drill"]["id"]
    h = {**HEADERS, "Idempotency-Key": "step-one"}
    r1 = client.post(f"/v1/drills/{did}/advance", json={}, headers=h)
    r2 = client.post(f"/v1/drills/{did}/advance", json={}, headers=h)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r2.json()["idempotent_replay"] is True
    assert r1.json()["step"]["started_at"] == r2.json()["step"]["started_at"]
    # Same key, different payload conflicts.
    h2 = {**HEADERS, "Idempotency-Key": "step-one"}
    r3 = client.post(f"/v1/drills/{did}/advance", json={"seq": 2}, headers=h2)
    assert r3.status_code == 409 and r3.json()["code"] == "idempotency_conflict"


def test_step_query_endpoint(client):
    did = client.post("/v1/drills", json=drill_body(), headers=HEADERS).json()["drill"]["id"]
    client.post(f"/v1/drills/{did}/advance", json={}, headers=HEADERS)
    r = client.get(f"/v1/drills/{did}/steps/1", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["step"]["seq"] == 1
    assert r.json()["step"]["answer"]["chosen"] == "b1"


def test_report_is_frozen_and_replay_identical(client):
    did = client.post("/v1/drills", json=drill_body(), headers=HEADERS).json()["drill"]["id"]
    for _ in range(3):
        client.post(f"/v1/drills/{did}/advance", json={}, headers=HEADERS)
    r1 = client.post(f"/v1/drills/{did}/report", headers=HEADERS)
    r2 = client.post(f"/v1/drills/{did}/report", headers=HEADERS)
    assert r1.status_code == 200
    assert r2.json()["idempotent_replay"] is True
    assert r1.json()["checksum"] == r2.json()["checksum"]
    report = r1.json()["report"]
    assert report["steps_recorded"] == 3
    assert report["steps_matched"] == 3
    assert report["first_diff"] is None
    assert set(report["frozen_snapshot"]["target_manifest"]) == {"b1", "b2"}


def test_report_points_at_first_diff(client):
    body = drill_body()
    body["steps"][0]["expected"] = {"chosen": "b2"}  # will mismatch
    did = client.post("/v1/drills", json=body, headers=HEADERS).json()["drill"]["id"]
    client.post(f"/v1/drills/{did}/advance", json={}, headers=HEADERS)
    r = client.post(f"/v1/drills/{did}/report", headers=HEADERS)
    assert r.json()["report"]["first_diff"]["seq"] == 1


def test_drills_are_isolated_from_live_state(client):
    did = client.post("/v1/drills", json=drill_body(), headers=HEADERS).json()["drill"]["id"]
    client.post(f"/v1/drills/{did}/advance", json={}, headers=HEADERS)
    client.post(f"/v1/drills/{did}/advance", json={}, headers=HEADERS)

    # The live health view never saw the simulated b1 failure.
    live = client.get("/v1/health/targets", headers=HEADERS).json()["targets"]
    assert all(t["healthy"] for t in live.values())

    # The live resolution cache has no drill-produced entries.
    cache = client.get("/v1/cache", headers=HEADERS).json()["entries"]
    assert cache == []

    # The real audit log contains no drill replay internals.
    audit = client.get("/v1/audit", headers=HEADERS).json()["records"]
    assert all(r["type"] != "release_group_hit" for r in audit)


def test_drill_endpoints_require_authentication(client):
    assert client.get("/v1/drills").status_code == 401
    assert client.post("/v1/drills", json=drill_body()).status_code == 401


def test_scoped_drill_permission_is_forbidden(tmp_path):
    # A drill replays a full global snapshot: tenant/region drill grants
    # must not be sufficient; only a global grant passes.
    comp = Components(
        db_path=str(tmp_path / "scoped.db"),
        admin_token=TOKEN,
        enable_background=False,
    )
    with TestClient(create_app(comp)) as c:
        c.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
        r = c.post("/v1/admin/roles", headers=HEADERS, json={
            "id": "tenant-drill",
            "permissions": [
                {"action": "drill:write",
                 "scope": {"scope": "tenant", "tenant": "acme"}},
                {"action": "drill:read",
                 "scope": {"scope": "tenant", "tenant": "acme"}},
            ],
        })
        assert r.status_code == 201, r.text
        r = c.post("/v1/admin/identities", headers=HEADERS, json={
            "id": "tadmin", "roles": ["tenant-drill"],
        })
        assert r.status_code == 201, r.text
        ttoken = r.json()["token"]
        th = {"Authorization": f"Bearer {ttoken}"}
        assert c.post("/v1/drills", json=drill_body(), headers=th).status_code == 403
        assert c.get("/v1/drills", headers=th).status_code == 403
        # A global drill role works end to end.
        c.post("/v1/admin/roles", headers=HEADERS, json={
            "id": "global-drill",
            "permissions": [
                {"action": "drill:write", "scope": {"scope": "global"}},
                {"action": "drill:read", "scope": {"scope": "global"}},
            ],
        })
        r = c.post("/v1/admin/identities", headers=HEADERS, json={
            "id": "gadmin", "roles": ["global-drill"],
        })
        gh = {"Authorization": f"Bearer {r.json()['token']}"}
        assert c.post("/v1/drills", json=drill_body(), headers=gh).status_code == 201
        assert c.get("/v1/drills", headers=gh).status_code == 200


def test_reset_invalidates_previous_idempotency_key(client):
    did = client.post("/v1/drills", json=drill_body(), headers=HEADERS).json()["drill"]["id"]
    h = {**HEADERS, "Idempotency-Key": "k"}
    client.post(f"/v1/drills/{did}/advance", json={}, headers=h)
    client.post(f"/v1/drills/{did}/reset", json={}, headers=HEADERS)
    r = client.post(f"/v1/drills/{did}/advance", json={"seq": 1}, headers=h)
    assert r.status_code == 200
    assert "idempotent_replay" not in r.json()


def test_state_survives_api_restart(tmp_path):
    path = str(tmp_path / "restart.db")

    def build():
        comp = Components(db_path=path, admin_token=TOKEN, enable_background=False)
        return TestClient(create_app(comp)), comp

    c1, _ = build()
    with c1:
        c1.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
        did = c1.post("/v1/drills", json=drill_body(), headers=HEADERS).json()["drill"]["id"]
        c1.post(f"/v1/drills/{did}/advance", json={}, headers=HEADERS)
        checksum = c1.post(f"/v1/drills/{did}/report", headers=HEADERS).json()["checksum"]

    c2, _ = build()
    with c2:
        d = c2.get(f"/v1/drills/{did}", headers=HEADERS).json()["drill"]
        assert d["current_seq"] == 1 and d["status"] == "running"
        step = c2.get(f"/v1/drills/{did}/steps/1", headers=HEADERS).json()["step"]
        assert step["answer"]["chosen"] == "b1"
        rep = c2.post(f"/v1/drills/{did}/report", headers=HEADERS).json()
        assert rep["idempotent_replay"] is True
        assert rep["checksum"] == checksum
        # Continue to the end on the restarted process.
        c2.post(f"/v1/drills/{did}/advance", json={"expected_version": 2},
                headers=HEADERS)
        r = c2.post(f"/v1/drills/{did}/advance", json={"expected_version": 3},
                    headers=HEADERS)
        assert r.json()["status"] == "completed"
