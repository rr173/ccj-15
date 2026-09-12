"""Config dry-run preview, version history and rollback."""
from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from app.config_store import (
    PreviewConsumed,
    PreviewExpired,
    PreviewMismatch,
    RollbackRejected,
    VersionConflict,
    VersionNotFound,
)
from app.main import Components, create_app
from tests.conftest import bundle, rule, target

TOKEN = "test-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

V1 = {
    "version": 1,
    "defaults": {"negative_ttl": 30},
    "rules": [
        {"name": "api", "scope": "global", "rule_version": 1, "ttl": 60,
         "targets": [{"id": "b1", "address": "tcp://10.0.0.1:80", "weight": 1}]},
        {"name": "web", "scope": "global", "rule_version": 1, "ttl": 60,
         "targets": [{"id": "w1", "address": "tcp://10.0.0.2:80", "weight": 1}]},
    ],
    "rate_limit_tiers": [
        {"id": "global", "scope": "global", "rate_per_second": 100,
         "burst": 200, "priority": 0, "match_labels": {}},
    ],
}

V2 = {
    "version": 2,
    "defaults": {"negative_ttl": 30},
    "rules": [
        # api: targets change (cache must be invalidated); web: removed
        {"name": "api", "scope": "global", "rule_version": 2, "ttl": 60,
         "targets": [{"id": "b2", "address": "tcp://10.0.0.3:80", "weight": 1}]},
    ],
    "release_groups": [
        {"id": "g1", "name": "api", "scope": "global", "priority": 10,
         "match_labels": {"env": "canary"}, "percent": 100, "ttl": 60,
         "window_start": 0, "window_end": 3_000_000_000,
         "rule_version": 2,
         "targets": [{"id": "c1", "address": "tcp://10.9.0.1:80", "weight": 1}]},
    ],
    "rate_limit_tiers": [
        {"id": "global", "scope": "global", "rate_per_second": 50,
         "burst": 100, "priority": 0, "match_labels": {}},
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


@pytest.fixture
def short_ttl_client(tmp_path):
    comp = Components(
        db_path=str(tmp_path / "ttl.db"),
        admin_token=TOKEN,
        enable_background=False,
        preview_ttl=10,
    )
    app = create_app(comp)
    with TestClient(app) as c:
        yield c, comp


def _apply_v1_v2(client):
    assert client.post("/v1/config", json=V1, headers=HEADERS).status_code == 200
    assert client.post("/v1/config", json=V2, headers=HEADERS).status_code == 200


# -- dry-run preview ------------------------------------------------------

def test_preview_changes_nothing(client):
    client.post("/v1/config", json=V1, headers=HEADERS)
    client.get("/v1/resolve", params={"name": "api", "client": "c"})
    client.get("/v1/resolve", params={"name": "web", "client": "c"})

    r = client.post("/v1/config/preview", json=V2, headers=HEADERS)
    assert r.status_code == 200, r.text
    prev = r.json()
    assert prev["dry_run"] is True
    assert prev["base_version"] == 1
    assert prev["proposed_version"] == 2
    assert prev["preview_token"]
    assert prev["expires_at"] > 0

    summary = prev["summary"]
    assert set(summary["affected_names"]) == {"api", "web"}
    actions = {d["name"]: d["action"] for d in summary["rule_diffs"]}
    assert actions == {"api": "updated", "web": "removed"}
    assert summary["release_group_diffs"][0]["action"] == "added"
    tier_diff = summary["rate_limit_tier_diffs"][0]
    assert tier_diff["tier_id"] == "global"
    assert tier_diff["old_rate_per_second"] == 100
    assert tier_diff["new_rate_per_second"] == 50
    assert tier_diff["old_burst"] == 200 and tier_diff["new_burst"] == 100

    # Impact projection: both cached answers would be evicted and the policy
    # fingerprint would change.
    assert prev["impact"]["cache_entries_invalidated"] == 2
    assert prev["impact"]["rate_limit_policy_changed"] == 1

    # The preview changed nothing: still on v1, cache intact, no audit.
    assert client.get("/healthz").json()["config_version"] == 1
    body = client.get("/v1/resolve", params={"name": "api", "client": "c"}).json()
    assert body["cached"] is True and body["chosen"] == "b1"
    audit = client.get("/v1/audit", headers=HEADERS).json()["records"]
    assert not any(rec["type"] == "config_applied" and
                   rec["details"]["version"] == 2 for rec in audit)
    assert not any(rec["type"] == "cache_invalidation" and
                   rec["details"].get("reason") == "config_applied"
                   for rec in audit)


def test_preview_defaults_version_and_validates(client):
    client.post("/v1/config", json=V1, headers=HEADERS)
    # No version supplied -> current + 1.
    payload = {k: v for k, v in V2.items() if k != "version"}
    r = client.post("/v1/config/preview", json=payload, headers=HEADERS)
    assert r.status_code == 200 and r.json()["proposed_version"] == 2

    # Validation errors surface exactly like a real apply (422).
    bad = {"version": 2, "rules": [
        {"name": "x", "scope": "region", "rule_version": 1}]}
    r = client.post("/v1/config/preview", json=bad, headers=HEADERS)
    assert r.status_code == 422

    # Non-monotonic preview version conflicts without touching anything.
    r = client.post("/v1/config/preview", json=V1, headers=HEADERS)
    assert r.status_code == 409


def test_commit_with_valid_preview_token(client):
    client.post("/v1/config", json=V1, headers=HEADERS)
    token = client.post("/v1/config/preview", json=V2,
                        headers=HEADERS).json()["preview_token"]
    payload = dict(V2, preview_token=token)
    r = client.post("/v1/config", json=payload, headers=HEADERS)
    assert r.status_code == 200
    assert r.json()["version"] == 2
    assert set(r.json()["summary"]["affected_names"]) == {"api", "web"}


def test_preview_token_single_use(client):
    client.post("/v1/config", json=V1, headers=HEADERS)
    token = client.post("/v1/config/preview", json=V2,
                        headers=HEADERS).json()["preview_token"]
    r1 = client.post("/v1/config", json=dict(V2, preview_token=token),
                     headers=HEADERS)
    assert r1.status_code == 200

    # The token is burned: a second attempt with a higher version number is
    # refused for reusing it (not silently accepted).
    v3 = dict(V2, version=3)
    r2 = client.post("/v1/config", json=dict(v3, preview_token=token),
                     headers=HEADERS)
    assert r2.status_code == 409 and "already been used" in r2.json()["detail"]
    # ... but a token-less commit is fine.
    assert client.post("/v1/config", json=v3, headers=HEADERS).status_code == 200


def test_preview_token_rejects_stale_base(client):
    client.post("/v1/config", json=V1, headers=HEADERS)
    token = client.post("/v1/config/preview", json=V2,
                        headers=HEADERS).json()["preview_token"]
    # Another commit advances the live version before the preview is used.
    other = dict(V2, version=2, rules=[
        {"name": "api", "scope": "global", "rule_version": 2, "ttl": 60,
         "targets": [{"id": "b9", "address": "tcp://10.0.0.9:80", "weight": 1}]},
    ])
    assert client.post("/v1/config", json=other, headers=HEADERS).status_code == 200
    # Commit the previewed content as v3; the token's base (v1) is stale.
    r = client.post("/v1/config", json=dict(V2, version=3, preview_token=token),
                    headers=HEADERS)
    assert r.status_code == 409 and "stale" in r.json()["detail"]


def test_preview_token_rejects_stale_base(client):
    client.post("/v1/config", json=V1, headers=HEADERS)
    token = client.post("/v1/config/preview", json=V2,
                        headers=HEADERS).json()["preview_token"]
    # Another commit advances the live version before the preview is used.
    other = dict(V2, rules=[
        {"name": "api", "scope": "global", "rule_version": 2, "ttl": 60,
         "targets": [{"id": "b9", "address": "tcp://10.0.0.9:80", "weight": 1}]},
    ])
    assert client.post("/v1/config", json=other, headers=HEADERS).status_code == 200
    # Commit the previewed content as v3; monotonicity passes but the token's
    # base version (v1) is stale.
    r = client.post("/v1/config",
                    json=dict(V2, version=3, preview_token=token),
                    headers=HEADERS)
    assert r.status_code == 409 and "stale" in r.json()["detail"]
    assert client.get("/healthz").json()["config_version"] == 2


def test_preview_token_rejects_changed_payload(client):
    client.post("/v1/config", json=V1, headers=HEADERS)
    token = client.post("/v1/config/preview", json=V2,
                        headers=HEADERS).json()["preview_token"]
    tampered = dict(V2, rate_limit_tiers=[
        {"id": "global", "scope": "global", "rate_per_second": 1,
         "burst": 1, "priority": 0}])
    r = client.post("/v1/config", json=dict(tampered, preview_token=token),
                    headers=HEADERS)
    assert r.status_code == 409 and "no longer matches" in r.json()["detail"]
    # Failed commit changed nothing.
    assert client.get("/healthz").json()["config_version"] == 1


def test_preview_token_expires(stack):
    b1 = bundle(1, [rule("api", targets=[target("b1")], ttl=60)])
    b2 = bundle(2, [rule("api", targets=[target("b2")], ttl=60,
                         rule_version=2)])
    stack.config.apply(b1)
    result = stack.config.preview_bundle(b2)
    stack.clock.advance(301)
    with pytest.raises(PreviewExpired):
        stack.config.apply(b2, preview_token=result.token)
    # Still on v1 after the rejected commit.
    assert stack.config.snapshot().version == 1


def test_expired_preview_token_api_returns_410(short_ttl_client):
    client, comp = short_ttl_client
    client.post("/v1/config", json=V1, headers=HEADERS)
    token = client.post("/v1/config/preview", json=V2,
                        headers=HEADERS).json()["preview_token"]
    # Advance the service clock past the preview TTL.
    base = comp.config._clock()
    comp.config._clock = lambda: base + 11
    comp.config._previews._clock = comp.config._clock
    r = client.post("/v1/config", json=dict(V2, preview_token=token),
                    headers=HEADERS)
    assert r.status_code == 410
    assert "expired" in r.json()["detail"]


def test_preview_token_consumed_once(stack):
    b1 = bundle(1, [rule("api", targets=[target("b1")], ttl=60)])
    b2 = bundle(2, [rule("api", targets=[target("b2")], ttl=60,
                         rule_version=2)])
    stack.config.apply(b1)
    result = stack.config.preview_bundle(b2)
    stack.config.apply(b2, preview_token=result.token)
    # Reusing the burned token with a higher version number is still refused.
    b3 = bundle(3, [rule("api", targets=[target("b2")], ttl=60,
                         rule_version=2)])
    with pytest.raises(PreviewConsumed):
        stack.config.apply(b3, preview_token=result.token)


def test_preview_token_wrong_version_rejected(stack):
    b1 = bundle(1, [rule("api", targets=[target("b1")], ttl=60)])
    b2 = bundle(2, [rule("api", targets=[target("b2")], ttl=60,
                         rule_version=2)])
    b3 = bundle(3, [rule("api", targets=[target("b2")], ttl=60,
                         rule_version=2)])
    stack.config.apply(b1)
    result = stack.config.preview_bundle(b2)
    with pytest.raises(PreviewMismatch):
        stack.config.apply(b3, preview_token=result.token)


# -- history --------------------------------------------------------------

def test_version_history_and_detail(client):
    _apply_v1_v2(client)
    r = client.get("/v1/config/versions", headers=HEADERS)
    versions = r.json()["versions"]
    assert [v["version"] for v in versions] == [2, 1]

    v2_summary = versions[0]["summary"]
    assert set(v2_summary["affected_names"]) == {"api", "web"}
    assert v2_summary["base_version"] == 1
    assert v2_summary["rollback_of"] is None
    assert [d["action"] for d in v2_summary["rate_limit_tier_diffs"]] == ["updated"]
    group = v2_summary["release_group_diffs"][0]
    assert group["group_id"] == "g1" and group["new_percent"] == 100

    detail = client.get("/v1/config/versions/1", headers=HEADERS).json()
    assert detail["version"] == 1
    assert detail["bundle"]["version"] == 1
    assert len(detail["bundle"]["rules"]) == 2
    assert detail["fingerprint"]

    lean = client.get("/v1/config/versions/1?payload=false",
                      headers=HEADERS).json()
    assert "bundle" not in lean

    assert client.get("/v1/config/versions/99", headers=HEADERS).status_code == 404


# -- rollback -------------------------------------------------------------

def test_rollback_creates_new_version_through_normal_pipeline(client):
    _apply_v1_v2(client)
    # v2 is live; labeled canary traffic hits g1.
    hit = client.get("/v1/resolve", params={
        "name": "api", "client": "c", "labels": "env=canary"}).json()
    assert hit["release_group"] == "g1" and hit["chosen"] == "c1"
    # v2's tier is tight.
    tier_v2 = hit["rate_limit"]["rate_per_second"]
    assert tier_v2 == 50

    r = client.post("/v1/config/rollback", json={"version": 1}, headers=HEADERS)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["rolled_back"] is True
    assert body["target_version"] == 1
    assert body["version"] == 3  # strictly higher new version
    summary = body["summary"]
    assert summary["rollback_of"] == 1 and summary["base_version"] == 2

    # Live state is v1's content at version 3.
    assert client.get("/healthz").json()["config_version"] == 3
    answer = client.get("/v1/resolve", params={
        "name": "api", "client": "c2", "labels": "env=canary"}).json()
    assert answer["release_group"] is None and answer["chosen"] == "b1"
    web = client.get("/v1/resolve", params={"name": "web", "client": "c2"}).json()
    assert web["status"] == "OK" and web["chosen"] == "w1"
    assert answer["rate_limit"]["rate_per_second"] == 100

    # Audit: same pipeline as an ordinary apply.
    types = {rec["type"] for rec in
             client.get("/v1/audit", headers=HEADERS).json()["records"]}
    assert {"config_applied", "config_rollback", "rule_change",
            "release_group_change", "rate_limit_change",
            "rate_limit_bucket_reset"} <= types
    rollback_records = [
        rec for rec in client.get(
            "/v1/audit", params={"type": "config_rollback"},
            headers=HEADERS).json()["records"]
    ]
    assert rollback_records[0]["details"]["target_version"] == 1

    # History records the new rollback version.
    versions = client.get("/v1/config/versions",
                          headers=HEADERS).json()["versions"]
    assert versions[0]["version"] == 3
    assert versions[0]["summary"]["rollback_of"] == 1


def test_rollback_to_unknown_version_rejected(client):
    _apply_v1_v2(client)
    r = client.post("/v1/config/rollback", json={"version": 42},
                    headers=HEADERS)
    assert r.status_code == 404 and "does not exist" in r.json()["detail"]


def test_rollback_to_current_version_rejected(client):
    _apply_v1_v2(client)
    r = client.post("/v1/config/rollback", json={"version": 2},
                    headers=HEADERS)
    assert r.status_code == 409 and "already the current version" in r.json()["detail"]


def test_rollback_to_identical_content_rejected(client):
    client.post("/v1/config", json=V1, headers=HEADERS)
    # Re-apply v1's exact content as v2.
    client.post("/v1/config", json=dict(V1, version=2), headers=HEADERS)
    r = client.post("/v1/config/rollback", json={"version": 1},
                    headers=HEADERS)
    assert r.status_code == 409 and "identical content" in r.json()["detail"]
    assert client.get("/healthz").json()["config_version"] == 2


def test_rollback_preview_does_not_change_anything(client):
    _apply_v1_v2(client)
    r = client.post("/v1/config/rollback/preview", json={"version": 1},
                    headers=HEADERS)
    assert r.status_code == 200
    prev = r.json()
    assert prev["kind"] == "rollback"
    assert prev["base_version"] == 2 and prev["proposed_version"] == 3
    assert prev["rollback_of"] == 1
    assert set(prev["summary"]["affected_names"]) == {"api", "web"}
    assert client.get("/healthz").json()["config_version"] == 2

    # The rollback preview token commits through the rollback endpoint.
    r = client.post("/v1/config/rollback", json={
        "version": 1, "preview_token": prev["preview_token"]}, headers=HEADERS)
    assert r.status_code == 200 and r.json()["version"] == 3


def test_rollback_preview_token_stale_rejected(client):
    _apply_v1_v2(client)
    token = client.post("/v1/config/rollback/preview", json={"version": 1},
                        headers=HEADERS).json()["preview_token"]
    # A concurrent v3 lands first.
    client.post("/v1/config", json=dict(V2, version=3), headers=HEADERS)
    r = client.post("/v1/config/rollback", json={
        "version": 1, "preview_token": token}, headers=HEADERS)
    assert r.status_code == 409 and "stale" in r.json()["detail"]


def test_apply_preview_token_cannot_rollback_and_vice_versa(stack):
    b1 = bundle(1, [rule("api", targets=[target("b1")], ttl=60)])
    b2 = bundle(2, [rule("api", targets=[target("b2")], ttl=60,
                         rule_version=2)])
    b3 = bundle(3, [rule("api", targets=[target("b3")], ttl=60,
                         rule_version=3)])
    stack.config.apply(b1)
    # Rollback preview to v1 proposes v3 (current v2 + 1).
    stack.config.apply(b2)
    rollback_preview = stack.config.preview_rollback(1)
    assert rollback_preview.proposed_version == 3
    # Rollback-kind token cannot drive a plain apply.
    with pytest.raises(PreviewMismatch):
        stack.config.apply(b3, preview_token=rollback_preview.token)

    apply_preview = stack.config.preview_bundle(b3)
    with pytest.raises(PreviewMismatch):
        stack.config.rollback(1, preview_token=apply_preview.token)
    # Neither failed commit changed the live version.
    assert stack.config.snapshot().version == 2


def test_rollback_manager_level(stack):
    b1 = bundle(1, [rule("api", targets=[target("b1")], ttl=60)])
    b2 = bundle(2, [rule("api", targets=[target("b2")], ttl=60,
                         rule_version=2)])
    stack.config.apply(b1)
    stack.config.apply(b2)
    assert stack.config.snapshot().version == 2

    with pytest.raises(VersionNotFound):
        stack.config.rollback(9)
    with pytest.raises(RollbackRejected):
        stack.config.rollback(2)

    result = stack.config.rollback(1)
    assert result["version"] == 3
    rule_state = stack.config.snapshot().rules[("api", "global", "", "")]
    assert [t.id for r in rule_state for t in r.targets] == ["b1"]
    # Re-rolling back to v1 content is a no-op-content rejection.
    with pytest.raises(RollbackRejected):
        stack.config.rollback(1)


# -- concurrency ----------------------------------------------------------

def test_expected_version_optimistic_concurrency(client, stack):
    b1 = bundle(1, [rule("api", targets=[target("b1")], ttl=60)])
    b2 = bundle(2, [rule("api", targets=[target("b2")], ttl=60,
                         rule_version=2)])
    b3 = bundle(3, [rule("api", targets=[target("b3")], ttl=60,
                         rule_version=3)])
    stack.config.apply(b1)
    stack.config.apply(b2, expected_version=1)

    # A submitter still believing it is on v1 must be refused.
    with pytest.raises(VersionConflict):
        stack.config.apply(b3, expected_version=1)
    stack.config.apply(b3, expected_version=2)  # fresh base succeeds


def test_concurrent_same_version_commit_loses_once(stack):
    b1 = bundle(1, [rule("api", targets=[target("b1")], ttl=60)])
    b2a = bundle(2, [rule("api", targets=[target("b2a")], ttl=60,
                          rule_version=2)])
    b2b = bundle(2, [rule("api", targets=[target("b2b")], ttl=60,
                          rule_version=2)])
    stack.config.apply(b1)

    # Simulate two managers sharing one database (e.g. two nodes): the
    # second same-number commit must hit the PRIMARY KEY conflict instead of
    # silently overwriting.
    from app.config_store import ConfigManager
    other = ConfigManager(stack.config._conn, stack.audit, stack.clock)
    other.load_persisted()
    assert other.apply(b2a)["version"] == 2
    with pytest.raises(VersionConflict):
        stack.config.apply(b2b)


def test_concurrent_apply_threads_no_overwrite(stack):
    b1 = bundle(1, [rule("api", targets=[target("b1")], ttl=60)])
    stack.config.apply(b1)
    errors = []

    def commit(version, target_id):
        try:
            stack.config.apply(
                bundle(version, [
                    rule("api", targets=[target(target_id)], ttl=60,
                         rule_version=version)
                ])
            )
        except VersionConflict as exc:
            errors.append(str(exc))

    t1 = threading.Thread(target=commit, args=(2, "x1"))
    t2 = threading.Thread(target=commit, args=(2, "x2"))
    t1.start(); t2.start(); t1.join(); t2.join()
    assert len(errors) == 1
    assert stack.config.snapshot().version == 2


# -- preview requires auth ------------------------------------------------

def test_preview_history_rollback_require_token(client):
    assert client.post("/v1/config/preview", json=V2).status_code == 401
    assert client.get("/v1/config/versions").status_code == 401
    assert client.post("/v1/config/rollback", json={"version": 1}).status_code == 401
    assert client.post(
        "/v1/config/rollback/preview", json={"version": 1}).status_code == 401
