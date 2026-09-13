"""End-to-end API tests for alert-policy drill endpoints."""
from __future__ import annotations

import asyncio

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
def client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "api.db")
    comp = Components(
        db_path=db_path,
        admin_token=TOKEN,
        enable_background=False,
    )
    app = create_app(comp)

    def set_probe(ok: bool):
        import app.health_checks as mod

        async def fake(method, address, timeout):
            return {
                "type": "tcp", "ok": ok,
                "reason": None if ok else "connection_error",
                "status": None, "duration_ms": 0.1, "detail": "",
            }
        # Auto-undone at teardown so the fake cannot leak into other modules.
        monkeypatch.setattr(mod, "run_probe", fake)

    with TestClient(app) as c:
        c.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
        c.put(
            "/v1/health/targets/b1/policy",
            headers=HEADERS,
            json={
                "interval_seconds": 2.0, "timeout_seconds": 1.0,
                "fail_threshold": 1, "recover_threshold": 1,
                "maintenance_windows": [], "priority": 10,
            },
        )
        r = c.post(
            "/v1/health/alert-subscriptions",
            headers=HEADERS,
            json={
                "target_id": "b1",
                "webhook_url": "http://hooks.example/live",
                "max_retries": 2,
                "backoff_base_seconds": 1.0,
                "backoff_max_seconds": 100.0,
            },
        )
        sub = r.json()["subscription"]
        set_probe(False)
        asyncio.run(comp.health.check_target("b1"))
        yield c, sub, db_path


def _create(client, sub_id, **over):
    body = {"subscription_id": sub_id}
    body.update(over)
    return client.post("/v1/health/alert-drills", json=body, headers=HEADERS)


def test_create_list_get_drill(client):
    c, sub, _db = client
    r = _create(c, sub["sub_id"])
    assert r.status_code == 201, r.text
    did = r.json()["drill"]["id"]
    assert r.json()["drill"]["status"] == "ready"
    assert r.json()["drill"]["total_rows"] >= 2
    r = c.get(f"/v1/health/alert-drills/{did}", headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["drill"]["frozen_input"]["subscription"][
        "sub_id"
    ] == sub["sub_id"]
    r = c.get("/v1/health/alert-drills", headers=HEADERS)
    assert r.status_code == 200 and r.json()["count"] == 1
    r = c.get(
        "/v1/health/alert-drills",
        params={"subscription_id": sub["sub_id"]},
        headers=HEADERS,
    )
    assert r.json()["count"] == 1
    r = c.get(
        "/v1/health/alert-drills",
        params={"subscription_id": "other"},
        headers=HEADERS,
    )
    assert r.json()["count"] == 0


def test_advance_pause_resume_reset_flow(client):
    c, sub, _db = client
    did = _create(c, sub["sub_id"]).json()["drill"]["id"]
    # First advance starts the drill and records a step.
    r = c.post(f"/v1/health/alert-drills/{did}/advance", json={}, headers=HEADERS)
    assert r.status_code == 200, r.text
    version = r.json()["version"]
    # Pause holds; advancing is refused.
    r = c.post(f"/v1/health/alert-drills/{did}/pause", json={}, headers=HEADERS)
    assert r.status_code == 200 and r.json()["status"] == "paused"
    r = c.post(f"/v1/health/alert-drills/{did}/advance", json={}, headers=HEADERS)
    assert r.status_code == 409 and r.json()["code"] == "status_conflict"
    r = c.post(f"/v1/health/alert-drills/{did}/resume", json={}, headers=HEADERS)
    assert r.status_code == 200 and r.json()["status"] == "running"
    # Drain the slice with settle so the run completes.
    last = None
    for _ in range(20):
        cur = c.get(f"/v1/health/alert-drills/{did}", headers=HEADERS).json()["drill"]
        if cur["cursor"] >= cur["total_rows"]:
            break
        r = c.post(
            f"/v1/health/alert-drills/{did}/advance",
            json={"settle": True},
            headers=HEADERS,
        )
        assert r.status_code == 200, r.text
        last = r
    assert last is not None and last.json()["status"] == "completed"
    # Reset starts a fresh epoch.
    r = c.post(f"/v1/health/alert-drills/{did}/reset", json={}, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["status"] == "ready" and r.json()["cursor"] == 0
    assert r.json()["run_epoch"] == 2
    # Old epoch's steps are no longer readable in the new run.
    r = c.get(f"/v1/health/alert-drills/{did}/steps/1", headers=HEADERS)
    assert r.status_code == 404


def test_expected_version_conflict_is_409(client):
    c, sub, _db = client
    did = _create(c, sub["sub_id"]).json()["drill"]["id"]
    r = c.post(
        f"/v1/health/alert-drills/{did}/advance",
        json={"expected_version": 99},
        headers=HEADERS,
    )
    assert r.status_code == 409 and r.json()["code"] == "expected_version"


def test_idempotent_advance(client):
    c, sub, _db = client
    did = _create(c, sub["sub_id"]).json()["drill"]["id"]
    h = {**HEADERS, "Idempotency-Key": "adv"}
    r1 = c.post(f"/v1/health/alert-drills/{did}/advance", json={}, headers=h)
    r2 = c.post(f"/v1/health/alert-drills/{did}/advance", json={}, headers=h)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r2.json()["idempotent_replay"] is True
    assert r1.json()["step"]["seq"] == r2.json()["step"]["seq"]
    # Same key, different payload conflicts.
    r3 = c.post(
        f"/v1/health/alert-drills/{did}/advance",
        json={"steps": 2},
        headers=h,
    )
    assert r3.status_code == 409 and r3.json()["code"] == "idempotency_conflict"


def test_simulated_webhook_only_lands_in_the_inbox(client):
    c, sub, _db = client
    did = _create(c, sub["sub_id"]).json()["drill"]["id"]
    for _ in range(20):
        cur = c.get(f"/v1/health/alert-drills/{did}", headers=HEADERS).json()["drill"]
        if cur["cursor"] >= cur["total_rows"]:
            break
        c.post(
            f"/v1/health/alert-drills/{did}/advance",
            json={"settle": True},
            headers=HEADERS,
        )
    inbox = c.get(
        f"/v1/health/alert-drills/{did}/inbox", headers=HEADERS
    ).json()
    assert inbox["count"] == 1
    msg = inbox["messages"][0]
    assert msg["url"] == "http://hooks.example/live"
    assert msg["body"]["type"] == "unhealthy"
    assert msg["headers"]["X-Georesolve-Drill"] == did
    # The live outbox count is whatever the background never sent (no worker
    # in this app); importantly the drill created no extra live deliveries.
    live = c.get("/v1/health/alert-deliveries", headers=HEADERS).json()
    assert all(d["sub_id"] == sub["sub_id"] for d in live["deliveries"])


def test_report_is_frozen(client):
    c, sub, _db = client
    did = _create(c, sub["sub_id"]).json()["drill"]["id"]
    for _ in range(20):
        cur = c.get(f"/v1/health/alert-drills/{did}", headers=HEADERS).json()["drill"]
        if cur["cursor"] >= cur["total_rows"]:
            break
        c.post(
            f"/v1/health/alert-drills/{did}/advance",
            json={"settle": True},
            headers=HEADERS,
        )
    r1 = c.post(f"/v1/health/alert-drills/{did}/report", headers=HEADERS)
    r2 = c.post(f"/v1/health/alert-drills/{did}/report", headers=HEADERS)
    assert r1.status_code == 200
    assert r2.json()["idempotent_replay"] is True
    assert r1.json()["checksum"] == r2.json()["checksum"]
    report = r1.json()["report"]
    assert report["frozen_input"]["subscription"]["sub_id"] == sub["sub_id"]
    assert report["statistics"]["inbox_messages"] == 1
    assert report["decisions"]
    assert "production_diff" in report


def test_drills_are_isolated_from_live_state(client):
    c, sub, _db = client
    before_events = c.get("/v1/health/alert-events", headers=HEADERS).json()["count"]
    before_deliv = c.get("/v1/health/alert-deliveries", headers=HEADERS).json()["count"]
    before_hist = len(c.get(
        "/v1/health/targets/b1/history", headers=HEADERS
    ).json()["items"])
    did = _create(c, sub["sub_id"]).json()["drill"]["id"]
    for _ in range(20):
        cur = c.get(f"/v1/health/alert-drills/{did}", headers=HEADERS).json()["drill"]
        if cur["cursor"] >= cur["total_rows"]:
            break
        c.post(
            f"/v1/health/alert-drills/{did}/advance",
            json={"settle": True},
            headers=HEADERS,
        )
    after_events = c.get("/v1/health/alert-events", headers=HEADERS).json()["count"]
    after_deliv = c.get("/v1/health/alert-deliveries", headers=HEADERS).json()["count"]
    after_hist = len(c.get(
        "/v1/health/targets/b1/history", headers=HEADERS
    ).json()["items"])
    assert after_events == before_events
    assert after_deliv == before_deliv
    assert after_hist == before_hist
    # Drill audit is separate from the real audit log.
    records = c.get("/v1/health/alert-drills-audit", headers=HEADERS).json()["records"]
    assert records and all("alert_drill" in r["action"] for r in records)
    real = c.get("/v1/audit", headers=HEADERS).json()["records"]
    assert all("alert_drill" not in r["type"] for r in real)


def test_requires_authentication(client):
    c, sub, _db = client
    assert c.get("/v1/health/alert-drills").status_code == 401
    assert _create(c, sub["sub_id"])  # authorized works
    assert c.post(
        "/v1/health/alert-drills",
        json={"subscription_id": sub["sub_id"]},
    ).status_code == 401


def test_scoped_drill_permission_forbidden(tmp_path):
    comp = Components(
        db_path=str(tmp_path / "scoped.db"),
        admin_token=TOKEN,
        enable_background=False,
    )
    with TestClient(create_app(comp)) as c:
        c.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
        c.post("/v1/admin/roles", headers=HEADERS, json={
            "id": "tenant-drill",
            "permissions": [
                {"action": "drill:write",
                 "scope": {"scope": "tenant", "tenant": "acme"}},
                {"action": "drill:read",
                 "scope": {"scope": "tenant", "tenant": "acme"}},
            ],
        })
        r = c.post("/v1/admin/identities", headers=HEADERS, json={
            "id": "tadmin", "roles": ["tenant-drill"],
        })
        th = {"Authorization": f"Bearer {r.json()['token']}"}
        r = c.post(
            "/v1/health/alert-drills",
            json={"subscription_id": "x"},
            headers=th,
        )
        assert r.status_code == 403
        assert c.get("/v1/health/alert-drills", headers=th).status_code == 403


def test_unknown_drill_is_404(client):
    c, _sub, _db = client
    assert c.get(
        "/v1/health/alert-drills/nope", headers=HEADERS
    ).status_code == 404
    assert c.post(
        "/v1/health/alert-drills/nope/advance", json={}, headers=HEADERS
    ).status_code == 404
    assert c.get(
        "/v1/health/alert-drills/nope/inbox", headers=HEADERS
    ).status_code == 404


def test_restart_preserves_progress_and_frozen_report(client):
    c, sub, db_path = client
    did = _create(c, sub["sub_id"]).json()["drill"]["id"]
    c.post(
        f"/v1/health/alert-drills/{did}/advance", json={}, headers=HEADERS
    )
    checksum_before = c.post(
        f"/v1/health/alert-drills/{did}/report", headers=HEADERS
    ).json()["checksum"]

    # Restart: a fresh component stack on the same database file.
    comp2 = Components(
        db_path=db_path, admin_token=TOKEN, enable_background=False
    )
    with TestClient(create_app(comp2)) as c2:
        d = c2.get(
            f"/v1/health/alert-drills/{did}", headers=HEADERS
        ).json()["drill"]
        assert d["cursor"] == 1
        step = c2.get(
            f"/v1/health/alert-drills/{did}/steps/1", headers=HEADERS
        ).json()["step"]
        assert step["seq"] == 1
        # Continue the replay to the end.
        for _ in range(20):
            cur = c2.get(
                f"/v1/health/alert-drills/{did}", headers=HEADERS
            ).json()["drill"]
            if cur["cursor"] >= cur["total_rows"]:
                break
            c2.post(
                f"/v1/health/alert-drills/{did}/advance",
                json={"settle": True},
                headers=HEADERS,
            )
        rep = c2.post(
            f"/v1/health/alert-drills/{did}/report", headers=HEADERS
        ).json()
        assert rep["idempotent_replay"] is True
        assert rep["checksum"] == checksum_before
        assert (
            c2.get(
                f"/v1/health/alert-drills/{did}/inbox", headers=HEADERS
            ).json()["count"]
            == 1
        )


def test_clock_only_advance_releases_suppressed_delivery(client):
    c, sub, _db = client
    # Add a silence window by updating the subscription, then freeze the
    # CURRENT (v2) revision over the existing failure history.
    r = c.put(
        f"/v1/health/alert-subscriptions/{sub['sub_id']}",
        headers=HEADERS,
        json={
            "target_id": "b1",
            "webhook_url": "http://hooks.example/live",
            "silence_windows": [{"start": 0.0, "end": 10**12, "note": "all"}],
            "expected_version": 1,
        },
    )
    assert r.status_code == 200, r.text
    did = _create(c, sub["sub_id"]).json()["drill"]["id"]
    c.post(
        f"/v1/health/alert-drills/{did}/advance",
        json={"steps": 100},
        headers=HEADERS,
    )
    detail = c.get(
        f"/v1/health/alert-drills/{did}", headers=HEADERS
    ).json()["drill"]
    assert detail["stats"]["suppressed_now"] == 1
    assert c.get(
        f"/v1/health/alert-drills/{did}/inbox", headers=HEADERS
    ).json()["count"] == 0
    # Move past the frozen window end: released and delivered to inbox.
    r = c.post(
        f"/v1/health/alert-drills/{did}/advance",
        json={"to_time": 10**12},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert r.json()["stats"]["succeeded"] == 1
    assert c.get(
        f"/v1/health/alert-drills/{did}/inbox", headers=HEADERS
    ).json()["count"] == 1
