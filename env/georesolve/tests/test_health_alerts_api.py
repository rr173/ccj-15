"""End-to-end API tests for health alert subscriptions and delivery."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

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
        "fail_threshold": 1,
        "recover_threshold": 1,
        "maintenance_windows": [],
        "priority": 10,
    }
    body.update(over)
    return body


def sub_body(**over):
    body = {"target_id": "b1", "webhook_url": "http://127.0.0.1:9/hook",
            "sources": ["*"], "consecutive_threshold": 1,
            "max_retries": 0}
    body.update(over)
    return body


# -- subscription CRUD --------------------------------------------------------


def test_subscription_crud_and_validation(client):
    r = client.post("/v1/health/alert-subscriptions",
                    json=sub_body(), headers=HEADERS)
    assert r.status_code == 201, r.text
    sid = r.json()["subscription"]["sub_id"]
    assert r.json()["subscription"]["signing_secret_set"] is False
    assert "signing_secret" not in r.json()["subscription"]

    # GET / list
    assert client.get(
        f"/v1/health/alert-subscriptions/{sid}", headers=HEADERS
    ).json()["subscription"]["target_id"] == "b1"
    listed = client.get("/v1/health/alert-subscriptions",
                        headers=HEADERS).json()
    assert listed["count"] == 1

    # Unknown target / bad url / bad source are 422 or 404.
    assert client.post("/v1/health/alert-subscriptions",
                       json=sub_body(target_id="zzz"),
                       headers=HEADERS).status_code == 404
    assert client.post("/v1/health/alert-subscriptions",
                       json=sub_body(webhook_url="ftp://x"),
                       headers=HEADERS).status_code == 422
    assert client.post("/v1/health/alert-subscriptions",
                       json=sub_body(sources=["bogus"]),
                       headers=HEADERS).status_code == 422

    # Update without expected_version -> 422; wrong version -> 409.
    assert client.put(
        f"/v1/health/alert-subscriptions/{sid}",
        json=sub_body(webhook_url="http://127.0.0.1:9/v2"),
        headers=HEADERS,
    ).status_code == 422
    assert client.put(
        f"/v1/health/alert-subscriptions/{sid}",
        json=sub_body(webhook_url="http://127.0.0.1:9/v2",
                      expected_version=99),
        headers=HEADERS,
    ).status_code == 409
    r = client.put(
        f"/v1/health/alert-subscriptions/{sid}",
        json=sub_body(webhook_url="http://127.0.0.1:9/v2",
                      expected_version=1),
        headers=HEADERS,
    )
    assert r.status_code == 200 and r.json()["subscription"][
        "sub_version"] == 2

    # Idempotent re-PUT with the same Idempotency-Key replays.
    key = "idem-sub-update"
    r1 = client.put(
        f"/v1/health/alert-subscriptions/{sid}",
        json=sub_body(webhook_url="http://127.0.0.1:9/v3",
                      expected_version=2),
        headers={**HEADERS, "Idempotency-Key": key},
    )
    assert r1.status_code == 200
    r2 = client.put(
        f"/v1/health/alert-subscriptions/{sid}",
        json=sub_body(webhook_url="http://127.0.0.1:9/v3",
                      expected_version=2),
        headers={**HEADERS, "Idempotency-Key": key},
    )
    assert r2.status_code == 200 and r2.json().get("idempotent_replay") is True
    # The replay did not bump the version a second time.
    assert client.get(
        f"/v1/health/alert-subscriptions/{sid}", headers=HEADERS
    ).json()["subscription"]["sub_version"] == 3

    # Delete requires matching version.
    assert client.delete(
        f"/v1/health/alert-subscriptions/{sid}?expected_version=99",
        headers=HEADERS,
    ).status_code == 409
    assert client.delete(
        f"/v1/health/alert-subscriptions/{sid}?expected_version=3",
        headers=HEADERS,
    ).status_code == 200
    assert client.get(
        "/v1/health/alert-subscriptions", headers=HEADERS
    ).json()["count"] == 0
    assert client.get(
        f"/v1/health/alert-subscriptions/{sid}", headers=HEADERS
    ).status_code == 404


def test_create_requires_idempotency_key_to_be_optional(client):
    # No key is fine; the endpoint works.
    r = client.post("/v1/health/alert-subscriptions",
                    json=sub_body(), headers=HEADERS)
    assert r.status_code == 201


# -- event generation over the real health API + delivery --------------------


class _Handler(BaseHTTPRequestHandler):
    received: list[dict] = []
    fail_times = 0
    log_message = lambda *a: None  # noqa: E731

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        body = json.loads(raw)
        type(self).received.append({
            "headers": dict(self.headers),
            "body": body,
        })
        if len(type(self).received) <= type(self).fail_times:
            self.send_response(503)
            self.end_headers()
            return
        self.send_response(202)
        self.end_headers()


@pytest.fixture
def hook_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    _Handler.received = []
    _Handler.fail_times = 0
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/hook"
    finally:
        server.shutdown()


def _force_failure(client, tid="b1"):
    import app.health_checks as mod

    async def fail(method, address, timeout):
        return {"type": "tcp", "ok": False, "reason": "x",
                "status": None, "duration_ms": 0.1, "detail": ""}

    mod.run_probe = fail
    try:
        return client.post(f"/v1/health/targets/{tid}/check", headers=HEADERS)
    finally:
        from app.health_checks import run_probe
        mod.run_probe = run_probe


def test_end_to_end_event_delivery(client, env, hook_server):
    _, comp = env
    client.put("/v1/health/targets/b1/policy",
               json=policy_body(), headers=HEADERS)
    client.post("/v1/health/alert-subscriptions",
                json=sub_body(webhook_url=hook_server, signing_secret="s3"),
                headers=HEADERS)
    r = _force_failure(client)
    assert r.status_code == 200

    events = client.get("/v1/health/alert-events", headers=HEADERS).json()
    assert events["count"] == 1
    ev = events["events"][0]
    assert ev["event_type"] == "unhealthy" and ev["target_id"] == "b1"
    assert ev["deliveries"][0]["status"] == "pending"

    # Background is disabled; run one dispatch tick to actually POST.
    import asyncio
    res = asyncio.run(comp.alerts.dispatch_once())
    assert res and res[0]["status"] == "succeeded"
    assert len(_Handler.received) == 1
    req = _Handler.received[0]
    assert req["body"]["type"] == "unhealthy"
    assert req["headers"]["X-Georesolve-Signature"].startswith("sha256=")
    assert req["headers"]["Idempotency-Key"]

    # Delivery status is queryable.
    did = ev["deliveries"][0]["id"]
    d = client.get(f"/v1/health/alert-deliveries/{did}",
                   headers=HEADERS).json()["delivery"]
    assert d["status"] == "succeeded" and d["attempts"] == 1
    listed = client.get("/v1/health/alert-deliveries",
                        headers=HEADERS).json()
    assert listed["count"] == 1


def test_replay_endpoint_re_posts(client, env, hook_server):
    _, comp = env
    client.put("/v1/health/targets/b1/policy",
               json=policy_body(), headers=HEADERS)
    client.post("/v1/health/alert-subscriptions",
                json=sub_body(webhook_url=hook_server), headers=HEADERS)
    _force_failure(client)
    import asyncio
    asyncio.run(comp.alerts.dispatch_once())
    assert len(_Handler.received) == 1

    ev_id = client.get("/v1/health/alert-events",
                       headers=HEADERS).json()["events"][0]["id"]
    r = client.post(f"/v1/health/alert-events/{ev_id}/replay",
                    headers={**HEADERS, "Idempotency-Key": "replay-1"})
    assert r.status_code == 200 and r.json()["replayed"] is True
    asyncio.run(comp.alerts.dispatch_once())
    assert len(_Handler.received) == 2
    assert _Handler.received[1]["headers"].get("X-Georesolve-Replay-Count") == "1"

    # Replaying an unknown event 404.
    assert client.post("/v1/health/alert-events/99999/replay",
                       headers=HEADERS).status_code == 404


def test_silence_window_holds_delivery_until_replay(client, env, hook_server):
    _, comp = env
    # Silence for the next hour: the delivery stays suppressed.
    now = comp.alerts._clock()
    client.put("/v1/health/targets/b1/policy",
               json=policy_body(), headers=HEADERS)
    client.post(
        "/v1/health/alert-subscriptions",
        json=sub_body(webhook_url=hook_server, silence_windows=[
            {"start": now - 10, "end": now + 3600, "note": "incident"}
        ]),
        headers=HEADERS,
    )
    _force_failure(client)
    ev = client.get("/v1/health/alert-events",
                    headers=HEADERS).json()["events"][0]
    assert ev["deliveries"][0]["status"] == "suppressed"

    import asyncio
    assert asyncio.run(comp.alerts.dispatch_once()) == []
    assert _Handler.received == []

    # Forced replay ignores the silence window.
    client.post(f"/v1/health/alert-events/{ev['id']}/replay",
                headers=HEADERS)
    asyncio.run(comp.alerts.dispatch_once())
    assert len(_Handler.received) == 1


def test_failed_webhook_retries_and_event_filters(client, env):
    _, comp = env
    client.put("/v1/health/targets/b1/policy",
               json=policy_body(), headers=HEADERS)
    # Nothing listens on this port: connect refused -> failed -> dead after
    # the initial attempt (max_retries=0 means no retries).
    client.post("/v1/health/alert-subscriptions",
                json=sub_body(webhook_url="http://127.0.0.1:9/hook",
                              max_retries=0, backoff_base_seconds=0.01),
                headers=HEADERS)
    _force_failure(client)
    import asyncio
    res = asyncio.run(comp.alerts.dispatch_once())
    assert res and res[0]["status"] == "dead"

    # Filtering helpers.
    r = client.get("/v1/health/alert-events?event_type=recovered",
                   headers=HEADERS)
    assert r.json()["count"] == 0
    r = client.get("/v1/health/alert-events?event_type=unhealthy",
                   headers=HEADERS)
    assert r.json()["count"] == 1
    r = client.get("/v1/health/alert-events?status=bogus", headers=HEADERS)
    assert r.status_code == 422
    r = client.get("/v1/health/alert-deliveries?status=dead", headers=HEADERS)
    assert r.json()["count"] == 1


def test_unknown_event_and_delivery_404(client):
    assert client.get("/v1/health/alert-events/123456",
                      headers=HEADERS).status_code == 404
    assert client.get("/v1/health/alert-deliveries/123456",
                      headers=HEADERS).status_code == 404


def test_old_event_delivers_with_original_snapshot_after_edit(client, env,
                                                              hook_server):
    _, comp = env
    client.put("/v1/health/targets/b1/policy",
               json=policy_body(), headers=HEADERS)
    r = client.post("/v1/health/alert-subscriptions",
                    json=sub_body(webhook_url=hook_server,
                                  silence_windows=[]),
                    headers=HEADERS).json()
    sid = r["subscription"]["sub_id"]
    _force_failure(client)

    # Point the subscription somewhere else AFTER the event fired.
    upd = client.put(
        f"/v1/health/alert-subscriptions/{sid}",
        json=sub_body(webhook_url="http://127.0.0.1:9/elsewhere",
                      expected_version=1),
        headers=HEADERS,
    )
    assert upd.status_code == 200

    import asyncio
    asyncio.run(comp.alerts.dispatch_once())
    # The existing delivery used the frozen v1 snapshot -> original server.
    assert len(_Handler.received) == 1
    assert _Handler.received[0]["body"]["subscription"] == {"id": sid,
                                                            "version": 1}


def test_secret_rotation_keeps_old_event_signed_with_original_secret(
        client, env, hook_server):
    import hashlib
    import hmac as _hmac

    _, comp = env
    client.put("/v1/health/targets/b1/policy",
               json=policy_body(), headers=HEADERS)
    r = client.post(
        "/v1/health/alert-subscriptions",
        json=sub_body(webhook_url=hook_server, signing_secret="old-key",
                      max_retries=3, backoff_base_seconds=0.01),
        headers=HEADERS,
    ).json()
    sid = r["subscription"]["sub_id"]
    _force_failure(client)

    def expected_sig(secret: str, raw: bytes) -> str:
        return "sha256=" + _hmac.new(
            secret.encode(), raw, hashlib.sha256
        ).hexdigest()

    # Rotate the signing secret after the event/delivery were generated,
    # then fail the first attempt and retry: both must verify under the old
    # key frozen on the delivery row, not the rotated subscription key.
    upd = client.put(
        f"/v1/health/alert-subscriptions/{sid}",
        json=sub_body(webhook_url=hook_server, signing_secret="new-key",
                      max_retries=3, backoff_base_seconds=0.01,
                      expected_version=1),
        headers=HEADERS,
    )
    assert upd.status_code == 200

    _Handler.fail_times = 1
    import asyncio
    import time as _time
    asyncio.run(comp.alerts.dispatch_once())  # attempt 1 -> 503
    # Backoff base is 10ms: wait past it so the retry is due on the next tick.
    _time.sleep(0.02)
    asyncio.run(comp.alerts.dispatch_once())  # attempt 2 -> 202
    assert len(_Handler.received) == 2
    for received in _Handler.received:
        raw = json.dumps(received["body"], sort_keys=True).encode()
        sig = received["headers"]["X-Georesolve-Signature"]
        assert sig == expected_sig("old-key", raw)
        assert sig != expected_sig("new-key", raw)

    # The frozen secret is never exposed on delivery read endpoints.
    did = client.get("/v1/health/alert-deliveries",
                     headers=HEADERS).json()["deliveries"][0]["id"]
    d = client.get(f"/v1/health/alert-deliveries/{did}",
                   headers=HEADERS).json()["delivery"]
    assert "signing_secret" not in d and "old-key" not in json.dumps(d)


def test_pending_delivery_survives_process_restart(tmp_path, hook_server):
    import asyncio
    from app.storage import connect as db_connect
    from app.audit import AuditLog as AuditLog2
    from app.config_store import ConfigManager as CM2
    from app.health_checks import HealthCheckStore as HCS2
    from app.health_alerts import AlertStore as AS2

    path = str(tmp_path / "restart-api.db")
    comp = Components(db_path=path, admin_token=TOKEN, enable_background=False)
    app = create_app(comp)
    with TestClient(app) as c:
        c.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
        c.put("/v1/health/targets/b1/policy",
              json=policy_body(), headers=HEADERS)
        c.post("/v1/health/alert-subscriptions",
               json=sub_body(webhook_url=hook_server), headers=HEADERS)
        _force_failure(c)
        assert c.get("/v1/health/alert-deliveries?status=pending",
                     headers=HEADERS).json()["count"] == 1

    # Simulate a restart with brand-new stores over the same SQLite file.
    db2 = db_connect(path)
    audit2 = AuditLog2(db2)
    cfg2 = CM2(db2, audit2)
    cfg2.load_persisted()
    alerts2 = AS2(db2, cfg2, audit2)
    alerts2.ingest_new()  # catch-up must not duplicate
    deliveries = alerts2.list_deliveries()["deliveries"]
    assert len(deliveries) == 1
    assert deliveries[0]["status"] == "pending"
    assert alerts2.list_events()["count"] == 1


def test_drill_runs_never_create_alert_events(client, env, hook_server):
    _, comp = env
    client.put("/v1/health/targets/b1/policy",
               json=policy_body(), headers=HEADERS)
    client.post("/v1/health/alert-subscriptions",
                json=sub_body(webhook_url=hook_server), headers=HEADERS)

    # Create and advance a fault drill that simulates b1 going unhealthy;
    # it uses the private drill registry and must not surface as an event.
    drill = {
        "config_version": 1,
        "steps": [
            {"name": "api", "client": "10.0.0.0",
             "health_changes": {"b1": False}},
            {"name": "api", "client": "10.0.0.0", "advance_seconds": 1},
        ],
    }
    r = client.post("/v1/drills", json=drill, headers=HEADERS)
    assert r.status_code in (200, 201), r.text
    drill_id = r.json()["drill"]["id"]
    client.post(f"/v1/drills/{drill_id}/advance", json={}, headers=HEADERS)
    client.post(f"/v1/drills/{drill_id}/advance", json={}, headers=HEADERS)
    comp.alerts.ingest_new()
    assert client.get("/v1/health/alert-events",
                      headers=HEADERS).json()["count"] == 0
