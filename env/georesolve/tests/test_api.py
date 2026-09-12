"""End-to-end API tests through the FastAPI app."""
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
        {"name": "api", "scope": "region", "region": "eu", "rule_version": 1,
         "ttl": 60,
         "targets": [{"id": "eu1", "address": "tcp://10.1.0.1:80", "weight": 1}]},
        {"name": "api", "scope": "tenant", "tenant": "vip", "rule_version": 1,
         "ttl": 60,
         "targets": [{"id": "vip1", "address": "tcp://10.2.0.1:80", "weight": 1}]},
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
        yield c


def test_full_flow(client):
    assert client.get("/healthz").json()["config_version"] == 0

    r = client.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
    assert r.status_code == 200 and r.json()["version"] == 1

    # data plane: layered answers
    r = client.get("/v1/resolve", params={"name": "api", "region": "us",
                                          "tenant": "acme", "client": "1.2.3.4"})
    body = r.json()
    assert body["status"] == "OK" and body["rule_scope"] == "global"
    assert body["chosen"] in ("b1", "b2")

    r = client.get("/v1/resolve", params={"name": "api", "region": "eu",
                                          "tenant": "acme", "client": "1.2.3.4"})
    assert r.json()["chosen"] == "eu1"

    r = client.get("/v1/resolve", params={"name": "api", "region": "eu",
                                          "tenant": "vip", "client": "1.2.3.4"})
    assert r.json()["chosen"] == "vip1"

    # second identical request is served from cache
    r = client.get("/v1/resolve", params={"name": "api", "region": "eu",
                                          "tenant": "vip", "client": "1.2.3.4"})
    assert r.json()["cached"] is True

    # explain: rule version, targets, effective time
    r = client.get("/v1/explain", params={"name": "api", "region": "eu",
                                          "tenant": "vip", "client": "1.2.3.4"})
    info = r.json()
    rule = info["effective_rule"]
    assert rule["rule_version"] == 1 and rule["scope"] == "tenant"
    assert rule["effective_from"] == 0.0
    assert [t["id"] for t in rule["targets"]] == ["vip1"]
    assert info["selection"]["chosen"] == "vip1"
    assert info["cache"]["state"] == "valid"
    assert info["config_version"] == 1

    # audit: rule changes recorded
    r = client.get("/v1/audit", params={"type": "rule_change"}, headers=HEADERS)
    assert r.status_code == 200
    assert len(r.json()["records"]) == 3


def test_config_version_monotonic_and_invalidation(client):
    client.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
    client.get("/v1/resolve", params={"name": "api", "region": "eu",
                                      "tenant": "acme", "client": "c"})

    stale = dict(CONFIG_V1, version=1)
    r = client.post("/v1/config", json=stale, headers=HEADERS)
    assert r.status_code == 409

    v2 = {
        "version": 2,
        "rules": [
            {"name": "api", "scope": "region", "region": "eu", "rule_version": 2,
             "ttl": 60,
             "targets": [{"id": "eu2", "address": "tcp://10.1.0.2:80",
                          "weight": 1}]},
        ],
    }
    r = client.post("/v1/config", json=v2, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["invalidated"] >= 1

    r = client.get("/v1/resolve", params={"name": "api", "region": "eu",
                                          "tenant": "acme", "client": "c"})
    body = r.json()
    assert body["chosen"] == "eu2" and body["rule_version"] == 2
    assert body["cached"] is False

    r = client.get("/v1/audit", params={"type": "cache_invalidation"},
                   headers=HEADERS)
    names = [rec["details"].get("name") for rec in r.json()["records"]]
    assert "api" in names


def test_admin_endpoints_require_token(client):
    assert client.get("/v1/config").status_code == 401
    assert client.post("/v1/config", json=CONFIG_V1).status_code == 401
    assert client.get("/v1/audit").status_code == 401
    assert client.get("/v1/config", headers=HEADERS).status_code == 200


def test_invalid_config_rejected(client):
    bad = {"version": 1, "rules": [
        {"name": "x", "scope": "region", "rule_version": 1}  # missing region
    ]}
    r = client.post("/v1/config", json=bad, headers=HEADERS)
    assert r.status_code == 422


def test_cache_flush_is_audited(client):
    client.post("/v1/config", json=CONFIG_V1, headers=HEADERS)
    client.get("/v1/resolve", params={"name": "api", "client": "c"})
    r = client.post("/v1/cache/flush", headers=HEADERS)
    assert r.json()["flushed"] >= 1
    r = client.get("/v1/audit", params={"type": "cache_invalidation"},
                   headers=HEADERS)
    reasons = [rec["details"]["reason"] for rec in r.json()["records"]]
    assert "manual_flush" in reasons
