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


GRAY_CONFIG = {
    "version": 1,
    "rules": [
        {"name": "api", "scope": "global", "rule_version": 1, "ttl": 60,
         "targets": [{"id": "b1", "address": "tcp://10.0.0.1:80", "weight": 1}]},
    ],
    "release_groups": [
        {"id": "g1", "name": "api", "scope": "global", "priority": 10,
         "match_labels": {"env": "canary"}, "percent": 100, "ttl": 60,
         "window_start": 1_000_000_000, "window_end": 3_000_000_000,
         "rule_version": 1,
         "targets": [{"id": "c1", "address": "tcp://10.9.0.1:80", "weight": 1}]},
    ],
}


def test_release_groups_end_to_end(client):
    r = client.post("/v1/config", json=GRAY_CONFIG, headers=HEADERS)
    assert r.status_code == 200

    # Config snapshot exposes the groups.
    groups = client.get("/v1/config", headers=HEADERS).json()["release_groups"]
    assert [g["id"] for g in groups] == ["g1"]

    # Labeled request hits the group; unlabeled falls back to the base rule.
    r = client.get("/v1/resolve", params={
        "name": "api", "client": "c", "labels": "env=canary,team=pay"})
    body = r.json()
    assert body["release_group"] == "g1" and body["chosen"] == "c1"

    r = client.get("/v1/resolve", params={"name": "api", "client": "c"})
    body = r.json()
    assert body["release_group"] is None and body["chosen"] == "b1"

    # Explain shows the hit group and the reason.
    r = client.get("/v1/explain", params={
        "name": "api", "client": "c", "labels": "env=canary"})
    release = r.json()["release"]
    assert release["reason"] == "hit" and release["group"]["id"] == "g1"

    # Audit: group change and hit recorded.
    r = client.get("/v1/audit", params={"type": "release_group_change"},
                   headers=HEADERS)
    assert r.json()["records"][0]["details"]["group_id"] == "g1"
    r = client.get("/v1/audit", params={"type": "release_group_hit"},
                   headers=HEADERS)
    assert r.json()["records"][0]["details"]["group_id"] == "g1"


LIMIT_CONFIG = {
    "version": 1,
    "rules": [
        {"name": "api", "scope": "global", "rule_version": 1, "ttl": 60,
         "targets": [{"id": "b1", "address": "tcp://10.0.0.1:80", "weight": 1}]},
    ],
    "rate_limit_tiers": [
        {"id": "tight", "scope": "global", "rate_per_second": 1, "burst": 1,
         "priority": 10},
        {"id": "canary", "scope": "global", "rate_per_second": 1, "burst": 1,
         "priority": 1, "match_labels": {"env": "canary"}},
    ],
}


def test_rate_limited_cache_hit_returns_429_without_cache_write(client):
    assert client.post("/v1/config", json=LIMIT_CONFIG, headers=HEADERS).status_code == 200
    params = {"name": "api", "client": "rate-client"}

    first = client.get("/v1/resolve", params=params)
    assert first.status_code == 200 and first.json()["rate_limit"]["tier_id"] == "tight"
    second = client.get("/v1/resolve", params=params)
    assert second.status_code == 200 and second.json()["cached"] is True
    denied = client.get("/v1/resolve", params=params)
    assert denied.status_code == 429
    assert denied.headers["retry-after"] == "1"
    body = denied.json()
    assert body["detail"] == "rate_limit_exceeded"
    assert body["rate_limit"]["tier_id"] == "tight"
    assert body["rate_limit"]["remaining"] == 0
    assert body["retry_after"] > 0

    cache = client.get("/v1/cache", headers=HEADERS).json()["entries"]
    rate_entries = [e for e in cache if e["client_key"] == "rate-client"]
    assert len(rate_entries) == 1 and rate_entries[0]["kind"] == "positive"
    audit = client.get("/v1/audit", params={"type": "rate_limit_rejected"},
                       headers=HEADERS).json()["records"]
    assert audit[0]["details"]["tier_id"] == "tight"


def test_explain_reports_rate_limit_but_does_not_consume(client):
    client.post("/v1/config", json=LIMIT_CONFIG, headers=HEADERS)
    params = {"name": "api", "client": "explain-client", "labels": "env=canary"}

    for _ in range(2):
        info = client.get("/v1/explain", params=params).json()
        rate = info["rate_limit"]
        assert rate["tier_id"] == "canary"
        assert rate["remaining"] == 1
        assert rate["reason"] == "allowed"

    resolved = client.get("/v1/resolve", params=params)
    assert resolved.status_code == 200
    denied = client.get("/v1/explain", params=params).json()
    assert denied["rate_limit"]["reason"] == "rate_limit_exceeded"
    assert denied["rate_limit"]["retry_after"] > 0


@pytest.mark.parametrize(
    "tier,message",
    [
        ({"id": "bad", "rate_per_second": -1, "burst": 1}, "positive"),
        ({"id": "bad", "rate_per_second": 0, "burst": 1}, "positive"),
        ({"id": "bad", "rate_per_second": 10, "burst": 4}, "burst"),
    ],
)
def test_invalid_rate_limit_config_rejected(client, tier, message):
    bad = {"version": 1, "rate_limit_tiers": [tier]}
    r = client.post("/v1/config", json=bad, headers=HEADERS)
    assert r.status_code == 422
    assert message in str(r.json()["detail"])


def test_duplicate_rate_limit_priority_labels_rejected(client):
    bad = {"version": 1, "rate_limit_tiers": [
        {"id": "a", "rate_per_second": 1, "burst": 1, "priority": 1,
         "match_labels": {"env": "canary"}},
        {"id": "b", "rate_per_second": 1, "burst": 1, "priority": 1,
         "match_labels": {"env": "canary", "team": "pay"}},
    ]}
    r = client.post("/v1/config", json=bad, headers=HEADERS)
    assert r.status_code == 422
    assert "duplicate or otherwise compatible label conditions" in str(r.json()["detail"])


def test_rate_limit_policy_change_audited_and_buckets_reset(client):
    client.post("/v1/config", json=LIMIT_CONFIG, headers=HEADERS)
    client.get("/v1/resolve", params={"name": "api", "client": "reset"})

    v2 = dict(LIMIT_CONFIG, version=2)
    r = client.post("/v1/config", json=v2, headers=HEADERS)
    assert r.status_code == 200
    # The version bump alone reset the exhausted bucket.
    assert client.get("/v1/resolve", params={"name": "api", "client": "reset"}).status_code == 200

    records = client.get("/v1/audit", params={"type": "rate_limit_bucket_reset"},
                         headers=HEADERS).json()["records"]
    assert records[0]["details"]["config_version"] == 2


def test_malformed_labels_rejected(client):
    client.post("/v1/config", json=GRAY_CONFIG, headers=HEADERS)
    r = client.get("/v1/resolve", params={"name": "api", "labels": "envcanary"})
    assert r.status_code == 400


def test_invalid_release_group_config_rejected(client):
    bad_percent = dict(GRAY_CONFIG, release_groups=[
        dict(GRAY_CONFIG["release_groups"][0], percent=150)])
    r = client.post("/v1/config", json=bad_percent, headers=HEADERS)
    assert r.status_code == 422

    overlapping = dict(GRAY_CONFIG, release_groups=[
        GRAY_CONFIG["release_groups"][0],
        dict(GRAY_CONFIG["release_groups"][0], id="g2", priority=20),
    ])
    r = client.post("/v1/config", json=overlapping, headers=HEADERS)
    assert r.status_code == 422

    # Same name and scope layer, overlapping windows, but *different* match
    # labels and priorities must still be rejected with a clear error.
    diff_labels = dict(GRAY_CONFIG, release_groups=[
        dict(GRAY_CONFIG["release_groups"][0], id="g1", priority=10),
        dict(GRAY_CONFIG["release_groups"][0], id="g2", priority=20,
             match_labels={"env": "prod"}),
    ])
    r = client.post("/v1/config", json=diff_labels, headers=HEADERS)
    assert r.status_code == 422
    assert "overlapping windows" in str(r.json()["detail"])
