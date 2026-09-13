"""End-to-end API tests for reusable drill plans, runs and branches."""
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

STEPS = [
    {"name": "api", "client": "10.0.0.0",
     "expected": {"chosen": "b1", "order": ["b1", "b2"]}},
    {"name": "api", "client": "10.0.0.0", "health_changes": {"b1": False},
     "expected": {"chosen": "b2"}},
    {"name": "api", "client": "10.0.0.0", "advance_seconds": 1},
]


def build(path):
    comp = Components(db_path=path, admin_token=TOKEN, enable_background=False)
    return TestClient(create_app(comp)), comp


@pytest.fixture
def client(tmp_path):
    c, _ = build(str(tmp_path / "api.db"))
    with c:
        c.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
        yield c


def completed_drill(client):
    did = client.post("/v1/drills", json={"config_version": 1, "steps": STEPS},
                      headers=HEADERS).json()["drill"]["id"]
    for _ in range(3):
        r = client.post(f"/v1/drills/{did}/advance", json={}, headers=HEADERS)
        assert r.status_code == 200
    return did


def make_plan(client, **over):
    did = over.pop("drill_id", None) or completed_drill(client)
    body = {"name": "nightly", "source_drill_id": did, **over}
    r = client.post("/v1/drill-plans", json=body, headers=HEADERS)
    assert r.status_code == 201, r.text
    return r.json()["plan"]["id"]


def advance_all(client, rid, n=3):
    for _ in range(n):
        r = client.post(f"/v1/drill-runs/{rid}/advance", json={}, headers=HEADERS)
        assert r.status_code == 200, r.text
    return r


# -- plans -------------------------------------------------------------------


def test_plan_lifecycle_list_detail_archive(client):
    pid = make_plan(client)
    r = client.get(f"/v1/drill-plans/{pid}", headers=HEADERS)
    assert r.status_code == 200
    plan = r.json()["plan"]
    assert plan["status"] == "active"
    assert set(plan["frozen"]["target_manifest"]) == {"b1", "b2"}
    assert plan["steps_planned"] == 3
    assert plan["run_count"] == 0
    assert [s["seq"] for s in plan["steps_spec"]] == [1, 2, 3]

    r = client.get("/v1/drill-plans", headers=HEADERS)
    assert r.status_code == 200 and r.json()["count"] == 1

    r = client.post(f"/v1/drill-plans/{pid}/archive", json={}, headers=HEADERS)
    assert r.status_code == 200 and r.json()["plan"]["status"] == "archived"
    # Archived plan cannot spawn runs.
    r = client.post(f"/v1/drill-plans/{pid}/runs", json={}, headers=HEADERS)
    assert r.status_code == 409 and r.json()["code"] == "plan_archived"


def test_plan_from_uncompleted_drill_is_409(client):
    did = client.post(
        "/v1/drills", json={"config_version": 1, "steps": STEPS}, headers=HEADERS
    ).json()["drill"]["id"]
    r = client.post(
        "/v1/drill-plans", json={"name": "x", "source_drill_id": did}, headers=HEADERS
    )
    assert r.status_code == 409 and r.json()["code"] == "drill_not_completed"


def test_plan_unknown_is_404(client):
    assert client.get("/v1/drill-plans/nope", headers=HEADERS).status_code == 404


def test_plan_archive_expected_version_conflict_and_replay(client):
    pid = make_plan(client)
    r = client.post(
        f"/v1/drill-plans/{pid}/archive",
        json={"expected_version": 99},
        headers=HEADERS,
    )
    assert r.status_code == 409 and r.json()["code"] == "expected_version"
    h = {**HEADERS, "Idempotency-Key": "archive-1"}
    r1 = client.post(f"/v1/drill-plans/{pid}/archive", json={}, headers=h)
    r2 = client.post(f"/v1/drill-plans/{pid}/archive", json={}, headers=h)
    assert r1.status_code == 200 and r2.json()["idempotent_replay"] is True
    assert r1.json()["plan"]["version"] == r2.json()["plan"]["version"]


def test_plan_create_idempotency_replays(client):
    did = completed_drill(client)
    body = {"plan_id": "fixed-plan", "name": "p", "source_drill_id": did}
    h = {**HEADERS, "Idempotency-Key": "mk"}
    r1 = client.post("/v1/drill-plans", json=body, headers=h)
    r2 = client.post("/v1/drill-plans", json=body, headers=h)
    assert r1.status_code == 201 and r2.status_code == 201
    assert r2.json()["idempotent_replay"] is True
    assert r1.json()["plan"]["id"] == r2.json()["plan"]["id"]
    # Same key, different payload -> conflict.
    r3 = client.post(
        "/v1/drill-plans", json={**body, "name": "other"}, headers=h
    )
    assert r3.status_code == 409 and r3.json()["code"] == "idempotency_conflict"


# -- independent runs --------------------------------------------------------


def test_independent_runs_share_nothing(client):
    pid = make_plan(client)
    r1 = client.post(f"/v1/drill-plans/{pid}/runs", json={"note": "A"},
                     headers=HEADERS)
    rid1 = r1.json()["run"]["id"]
    r2 = client.post(f"/v1/drill-plans/{pid}/runs", json={"note": "B"},
                     headers=HEADERS)
    rid2 = r2.json()["run"]["id"]
    advance_all(client, rid1)
    # Run 2 is untouched despite run 1 completing.
    run2 = client.get(f"/v1/drill-runs/{rid2}", headers=HEADERS).json()["run"]
    assert run2["status"] == "ready" and run2["current_seq"] == 0
    assert run2["steps"] == []
    assert run2["health"] == {"b1": True, "b2": True}
    # Runs are listed under the plan and globally.
    listed = client.get(f"/v1/drill-plans/{pid}/runs", headers=HEADERS).json()
    assert listed["count"] == 2
    assert len(client.get("/v1/drill-runs", headers=HEADERS).json()["runs"]) == 2


def test_run_expected_version_conflict(client):
    pid = make_plan(client)
    rid = client.post(f"/v1/drill-plans/{pid}/runs", json={},
                      headers=HEADERS).json()["run"]["id"]
    r = client.post(
        f"/v1/drill-runs/{rid}/advance",
        json={"expected_version": 99},
        headers=HEADERS,
    )
    assert r.status_code == 409 and r.json()["code"] == "expected_version"


def test_concurrent_run_creates_one_winner():
    # SQLite + threads: only one of two racing starts with the same
    # expected_version may succeed.
    import threading
    import tempfile

    d = tempfile.mkdtemp()
    c, comp = build(f"{d}/race.db")
    with c:
        c.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
        pid = make_plan(c)
        results = []

        def worker():
            r = c.post(
                f"/v1/drill-plans/{pid}/runs",
                json={"expected_version": 1},
                headers=HEADERS,
            )
            results.append((r.status_code, r.json().get("code")))

        barrier = threading.Barrier(2)

        def synced():
            barrier.wait()
            worker()

        ts = [threading.Thread(target=synced) for _ in range(2)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        oks = [r for r in results if r[0] == 201]
        conflicts = [r for r in results if r[0] == 409]
        assert len(oks) == 1 and len(conflicts) == 1


# -- branching ---------------------------------------------------------------


def test_branch_end_to_end_and_parent_independence(client):
    pid = make_plan(client)
    rid = client.post(f"/v1/drill-plans/{pid}/runs", json={},
                      headers=HEADERS).json()["run"]["id"]
    advance_all(client, rid)

    br = client.post(
        f"/v1/drill-runs/{rid}/branches",
        json={
            "branch_point_seq": 1,
            "steps": [
                {"name": "api", "client": "10.0.0.0",
                 "expected": {"chosen": "b1"}},
                {"name": "api", "client": "10.0.0.0", "advance_seconds": 1},
            ],
            "note": "keep-b1",
        },
        headers=HEADERS,
    )
    assert br.status_code == 201, br.text
    bid = br.json()["run"]["id"]
    detail = client.get(f"/v1/drill-runs/{bid}", headers=HEADERS).json()["run"]
    assert detail["parent_run_id"] == rid and detail["branch_point_seq"] == 1
    assert detail["steps"][0]["inherited"] is True
    assert detail["status"] == "running"

    s2 = client.post(f"/v1/drill-runs/{bid}/advance", json={}, headers=HEADERS)
    assert s2.json()["step"]["answer"]["chosen"] == "b1"
    s3 = client.post(f"/v1/drill-runs/{bid}/advance", json={}, headers=HEADERS)
    assert s3.json()["status"] == "completed"

    # Parent stays its own completed run with its original (b1-failing) steps.
    parent = client.get(f"/v1/drill-runs/{rid}", headers=HEADERS).json()["run"]
    assert parent["status"] == "completed"
    assert parent["steps"][1]["health_after"]["b1"] is False

    # Inherited step is readable through the step endpoint.
    st = client.get(f"/v1/drill-runs/{bid}/steps/1", headers=HEADERS)
    assert st.status_code == 200 and st.json()["step"]["inherited"] is True
    # Advancing an inherited position is refused.
    r = client.post(f"/v1/drill-runs/{bid}/reset", json={}, headers=HEADERS)
    assert r.status_code == 200
    reset_run = client.get(f"/v1/drill-runs/{bid}", headers=HEADERS).json()["run"]
    assert reset_run["current_seq"] == 1
    assert len(reset_run["steps"]) == 1  # inherited prefix survives reset


def test_branch_from_unfinished_step_is_409(client):
    pid = make_plan(client)
    rid = client.post(f"/v1/drill-plans/{pid}/runs", json={},
                      headers=HEADERS).json()["run"]["id"]
    client.post(f"/v1/drill-runs/{rid}/advance", json={}, headers=HEADERS)
    r = client.post(
        f"/v1/drill-runs/{rid}/branches",
        json={"branch_point_seq": 3, "steps": []},
        headers=HEADERS,
    )
    assert r.status_code == 409 and r.json()["code"] == "branch_point_invalid"


def test_branch_wrong_tail_length_is_409(client):
    pid = make_plan(client)
    rid = client.post(f"/v1/drill-plans/{pid}/runs", json={},
                      headers=HEADERS).json()["run"]["id"]
    advance_all(client, rid)
    r = client.post(
        f"/v1/drill-runs/{rid}/branches",
        json={"branch_point_seq": 1, "steps": [{"name": "api"}]},
        headers=HEADERS,
    )
    assert r.status_code == 409 and r.json()["code"] == "branch_tail_length"


def test_branch_idempotency_and_expected_version(client):
    pid = make_plan(client)
    rid = client.post(f"/v1/drill-plans/{pid}/runs", json={},
                      headers=HEADERS).json()["run"]["id"]
    client.post(f"/v1/drill-runs/{rid}/advance", json={}, headers=HEADERS)
    body = {
        "branch_point_seq": 1,
        "steps": [{"name": "api", "client": "10.0.0.0"},
                  {"name": "api", "client": "10.0.0.0"}],
        "expected_version": 99,
    }
    r = client.post(f"/v1/drill-runs/{rid}/branches", json=body, headers=HEADERS)
    assert r.status_code == 409 and r.json()["code"] == "expected_version"
    body["expected_version"] = 2
    h = {**HEADERS, "Idempotency-Key": "brk"}
    r1 = client.post(f"/v1/drill-runs/{rid}/branches", json=body, headers=h)
    r2 = client.post(f"/v1/drill-runs/{rid}/branches", json=body, headers=h)
    assert r1.status_code == 201 and r2.status_code == 201
    assert r2.json()["idempotent_replay"] is True
    assert r1.json()["run"]["id"] == r2.json()["run"]["id"]


# -- owner isolation ---------------------------------------------------------


def _identity_with_drill_perms(client, ident):
    """Create an identity holding global drill:read + drill:write."""
    client.post("/v1/admin/roles", headers=HEADERS, json={
        "id": f"{ident}-drill",
        "permissions": [
            {"action": "drill:read", "scope": {"scope": "global"}},
            {"action": "drill:write", "scope": {"scope": "global"}},
        ],
    })
    r = client.post("/v1/admin/identities", headers=HEADERS, json={
        "id": ident, "roles": [f"{ident}-drill"],
    })
    return r.json()["token"]


def test_owner_isolation_across_identities(tmp_path):
    c, _ = build(str(tmp_path / "owners.db"))
    with c:
        c.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
        at = _identity_with_drill_perms(c, "alice")
        bt = _identity_with_drill_perms(c, "bob")
        ah = {"Authorization": f"Bearer {at}"}
        bh = {"Authorization": f"Bearer {bt}"}

        # Alice makes a completed drill and saves a plan.
        did = c.post("/v1/drills", json={"config_version": 1, "steps": STEPS},
                     headers=ah).json()["drill"]["id"]
        for _ in range(3):
            c.post(f"/v1/drills/{did}/advance", json={}, headers=ah)
        pid = c.post(
            "/v1/drill-plans",
            json={"name": "p", "source_drill_id": did},
            headers=ah,
        ).json()["plan"]["id"]
        rid = c.post(f"/v1/drill-plans/{pid}/runs", json={},
                     headers=ah).json()["run"]["id"]

        # Bob cannot see or operate Alice's run.
        assert c.get(f"/v1/drill-runs/{rid}", headers=bh).status_code == 403
        assert c.post(
            f"/v1/drill-runs/{rid}/advance", json={}, headers=bh
        ).status_code == 403
        assert c.post(
            f"/v1/drill-runs/{rid}/pause", json={}, headers=bh
        ).status_code == 403
        assert c.post(
            f"/v1/drill-runs/{rid}/report", headers=bh
        ).status_code == 403
        assert c.post(
            f"/v1/drill-runs/{rid}/branches",
            json={"branch_point_seq": 1, "steps": [
                {"name": "api"}, {"name": "api"}]},
            headers=bh,
        ).status_code == 403
        # Bob's global listing never leaks Alice's run.
        assert c.get("/v1/drill-runs", headers=bh).json()["runs"] == []
        # Bob can start his own run of the same plan.
        rb = c.post(f"/v1/drill-plans/{pid}/runs", json={}, headers=bh)
        assert rb.status_code == 201
        # He cannot compare across owners.
        assert c.post(
            f"/v1/drill-runs/{rid}/compare",
            json={"other_run_id": rb.json()["run"]["id"]},
            headers=ah,
        ).status_code == 403


# -- reports and comparison --------------------------------------------------


def test_run_report_frozen(client):
    pid = make_plan(client)
    rid = client.post(f"/v1/drill-plans/{pid}/runs", json={},
                      headers=HEADERS).json()["run"]["id"]
    advance_all(client, rid)
    r1 = client.post(f"/v1/drill-runs/{rid}/report", headers=HEADERS)
    r2 = client.post(f"/v1/drill-runs/{rid}/report", headers=HEADERS)
    assert r1.status_code == 200
    assert r2.json()["idempotent_replay"] is True
    assert r1.json()["checksum"] == r2.json()["checksum"]
    rep = r1.json()["report"]
    assert rep["steps_recorded"] == 3 and rep["steps_matched"] == 3
    assert rep["frozen_snapshot"]["config_version"] == 1


def test_compare_report_pins_versions_and_first_difference(client):
    pid = make_plan(client)
    rid_a = client.post(f"/v1/drill-plans/{pid}/runs", json={},
                        headers=HEADERS).json()["run"]["id"]
    rid_b = client.post(f"/v1/drill-plans/{pid}/runs", json={},
                        headers=HEADERS).json()["run"]["id"]
    advance_all(client, rid_a)
    client.post(f"/v1/drill-runs/{rid_b}/advance", json={}, headers=HEADERS)
    r = client.post(
        f"/v1/drill-runs/{rid_a}/compare",
        json={"other_run_id": rid_b},
        headers=HEADERS,
    )
    assert r.status_code == 200
    rep = r.json()["report"]
    assert rep["first_divergence"]["seq"] == 2
    assert rep["first_divergence"]["dimension"] == "step_progress"
    # Both run versions are pinned in the frozen report.
    versions = {x["run_id"]: x["version"] for x in rep["runs"]}
    assert versions[rid_a] == 4 and versions[rid_b] == 2

    # Complete B; repeated comparisons still return the pair's one frozen
    # report (pinned to the versions at first generation).
    client.post(f"/v1/drill-runs/{rid_b}/advance", json={}, headers=HEADERS)
    client.post(f"/v1/drill-runs/{rid_b}/advance", json={}, headers=HEADERS)
    r2 = client.post(
        f"/v1/drill-runs/{rid_a}/compare",
        json={"other_run_id": rid_b},
        headers=HEADERS,
    )
    assert r2.json()["idempotent_replay"] is True
    assert r2.json()["checksum"] == r.json()["checksum"]
    checksum = r2.json()["checksum"]
    # Same stored report regardless of request direction.
    r3 = client.post(
        f"/v1/drill-runs/{rid_b}/compare",
        json={"other_run_id": rid_a},
        headers=HEADERS,
    )
    assert r3.json()["idempotent_replay"] is True
    assert r3.json()["checksum"] == checksum


def test_compare_detects_resolution_order_and_expected_differences(client):
    pid = make_plan(client)
    rid = client.post(f"/v1/drill-plans/{pid}/runs", json={},
                      headers=HEADERS).json()["run"]["id"]
    advance_all(client, rid)
    # Branch keeps b1 healthy: step 2 differs first on the health set.
    bid = client.post(
        f"/v1/drill-runs/{rid}/branches",
        json={
            "branch_point_seq": 1,
            "steps": [
                {"name": "api", "client": "10.0.0.0",
                 "expected": {"chosen": "b1", "order": ["b1", "b2"]}},
                {"name": "api", "client": "10.0.0.0", "advance_seconds": 1,
                 "expected": {"chosen": "b2"}},
            ],
        },
        headers=HEADERS,
    ).json()["run"]["id"]
    client.post(f"/v1/drill-runs/{bid}/advance", json={}, headers=HEADERS)
    client.post(f"/v1/drill-runs/{bid}/advance", json={}, headers=HEADERS)
    rep = client.post(
        f"/v1/drill-runs/{rid}/compare",
        json={"other_run_id": bid},
        headers=HEADERS,
    ).json()["report"]
    assert rep["first_divergence"]["seq"] == 2
    assert rep["first_divergence"]["dimension"] == "health_set"


def test_compare_cross_plan_is_409(client):
    p1 = make_plan(client)
    p2 = make_plan(client)
    r1 = client.post(f"/v1/drill-plans/{p1}/runs", json={},
                     headers=HEADERS).json()["run"]["id"]
    r2 = client.post(f"/v1/drill-plans/{p2}/runs", json={},
                     headers=HEADERS).json()["run"]["id"]
    r = client.post(
        f"/v1/drill-runs/{r1}/compare",
        json={"other_run_id": r2},
        headers=HEADERS,
    )
    assert r.status_code == 409 and r.json()["code"] == "compare_plan_mismatch"


def test_owner_filter_endpoint(client):
    pid = make_plan(client)
    client.post(f"/v1/drill-plans/{pid}/runs", json={"owner_id": "alice"},
                headers=HEADERS)
    client.post(f"/v1/drill-plans/{pid}/runs", json={"owner_id": "bob"},
                headers=HEADERS)
    r = client.get("/v1/drill-runs", params={"owner_id": "alice"},
                   headers=HEADERS)
    runs = r.json()["runs"]
    assert len(runs) == 1 and runs[0]["owner_id"] == "alice"


# -- persistence across restart ----------------------------------------------


def test_state_survives_restart(tmp_path):
    path = str(tmp_path / "restart.db")
    c, _ = build(path)
    with c:
        c.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
        pid = make_plan(c)
        rid = c.post(f"/v1/drill-plans/{pid}/runs",
                     json={"run_id": "run-x", "owner_id": "alice", "note": "n"},
                     headers=HEADERS).json()["run"]["id"]
        c.post(f"/v1/drill-runs/{rid}/advance", json={}, headers=HEADERS)
        bid = c.post(
            f"/v1/drill-runs/{rid}/branches",
            json={"run_id": "br-x", "branch_point_seq": 1,
                  "steps": [{"name": "api", "client": "10.0.0.0"},
                            {"name": "api", "client": "10.0.0.0"}]},
            headers=HEADERS,
        ).json()["run"]["id"]
        checksum = c.post(f"/v1/drill-runs/{rid}/report",
                          headers=HEADERS).json()["checksum"]
        cmp = c.post(
            f"/v1/drill-runs/{rid}/compare",
            json={"other_run_id": bid},
            headers=HEADERS,
        ).json()["checksum"]

    c2, _ = build(path)
    with c2:
        plan = c2.get(f"/v1/drill-plans/{pid}", headers=HEADERS).json()["plan"]
        assert plan["steps_planned"] == 3 and set(
            plan["frozen"]["target_manifest"]
        ) == {"b1", "b2"}
        run = c2.get(f"/v1/drill-runs/{rid}", headers=HEADERS).json()["run"]
        assert run["owner_id"] == "alice" and run["current_seq"] == 1
        assert run["steps"][0]["answer"]["chosen"] == "b1"
        branch = c2.get(f"/v1/drill-runs/{bid}", headers=HEADERS).json()["run"]
        assert branch["parent_run_id"] == rid
        assert branch["steps"][0]["inherited"] is True
        # Version conflict still enforced after restart.
        r = c2.post(f"/v1/drill-runs/{rid}/advance",
                    json={"expected_version": 1}, headers=HEADERS)
        assert r.status_code == 409 and r.json()["code"] == "expected_version"
        # Report checksum stable.
        rep = c2.post(f"/v1/drill-runs/{rid}/report", headers=HEADERS).json()
        assert rep["idempotent_replay"] is True and rep["checksum"] == checksum
        # Comparison report checksum stable.
        cmp2 = c2.post(
            f"/v1/drill-runs/{rid}/compare",
            json={"other_run_id": bid},
            headers=HEADERS,
        ).json()
        assert cmp2["idempotent_replay"] is True and cmp2["checksum"] == cmp


def test_endpoints_require_authentication(client):
    assert client.get("/v1/drill-plans").status_code == 401
    assert client.post(
        "/v1/drill-plans", json={"name": "x", "config_version": 1,
                                 "steps": [{"name": "api"}]}
    ).status_code == 401
    assert client.get("/v1/drill-runs").status_code == 401
