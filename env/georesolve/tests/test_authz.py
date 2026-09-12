"""Multi-tenant admin delegation and scoped authorization tests.

Covers the identity lifecycle, the global -> region -> tenant scope
inheritance chain, scoped control-plane authorization (403 without side
effects), immediate revocation, versioned permission changes with
idempotent retries, delegation constraints (no tenant -> region/global
escalation), concurrent modification, audit queries and persistence.
"""
from __future__ import annotations

import concurrent.futures

import pytest
from fastapi.testclient import TestClient

from app.authz import AuthzStore, Permission, Scope
from app.audit import AuditLog
from app.main import Components, create_app
from app.storage import connect

ROOT_TOKEN = "root-token"
ROOT = {"Authorization": f"Bearer {ROOT_TOKEN}"}


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def perm(action: str, scope: dict) -> dict:
    return {"action": action, "scope": scope}


GLOBAL = {"scope": "global"}
REGION_EU = {"scope": "region", "region": "eu"}
REGION_US = {"scope": "region", "region": "us"}
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
def client(tmp_path):
    comp = Components(
        db_path=str(tmp_path / "authz.db"),
        admin_token=ROOT_TOKEN,
        enable_background=False,
    )
    with TestClient(create_app(comp)) as c:
        yield c


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


# -- scope model unit tests ---------------------------------------------------


def test_scope_covering_chain():
    glob = Scope()
    region = Scope(scope="region", region="eu")
    tenant = Scope(scope="tenant", tenant="vip")
    other_region = Scope(scope="region", region="us")
    other_tenant = Scope(scope="tenant", tenant="acme")

    # global inherits everything
    for s in (glob, region, tenant, other_region, other_tenant):
        assert glob.covers(s)
    # a region grant covers its own region and inherits tenant resources
    assert region.covers(region)
    assert region.covers(tenant)
    assert region.covers(other_tenant)
    assert not region.covers(glob)
    assert not region.covers(other_region)
    # a tenant grant covers exactly its tenant and nothing broader
    assert tenant.covers(tenant)
    assert not tenant.covers(other_tenant)
    assert not tenant.covers(region)
    assert not tenant.covers(glob)


def test_scope_validation():
    with pytest.raises(Exception):
        Scope(scope="global", region="eu")
    with pytest.raises(Exception):
        Scope(scope="region")
    with pytest.raises(Exception):
        Scope(scope="tenant", region="eu")
    with pytest.raises(Exception):
        Permission(action="config:fly")


# -- identity lifecycle ---------------------------------------------------------


def test_identity_lifecycle(client):
    token = make_admin(
        client, "cfg-read", "alice", [perm("config:read", GLOBAL)]
    )
    assert client.get("/v1/config", headers=bearer(token)).status_code == 200

    # token is only ever returned at creation time
    r = client.get("/v1/admin/identities/alice", headers=ROOT)
    body = r.json()["identity"]
    assert body["status"] == "active" and body["identity_version"] == 1
    assert "token" not in body and "token_hash" not in body

    # deactivation takes effect immediately
    r = client.post("/v1/admin/identities/alice/deactivate", headers=ROOT)
    assert r.status_code == 200 and r.json()["changed"] is True
    assert r.json()["identity"]["status"] == "deactivated"
    assert r.json()["identity"]["deactivated_at"] is not None
    r = client.get("/v1/config", headers=bearer(token))
    assert r.status_code == 401

    # reactivation restores access with the same token
    r = client.post("/v1/admin/identities/alice/reactivate", headers=ROOT)
    assert r.status_code == 200 and r.json()["changed"] is True
    assert client.get("/v1/config", headers=bearer(token)).status_code == 200


def test_deactivation_denial_is_audited_with_reason(client):
    token = make_admin(
        client, "cfg-read", "alice", [perm("config:read", GLOBAL)]
    )
    client.get("/v1/config", headers=bearer(token))
    client.post("/v1/admin/identities/alice/deactivate", headers=ROOT)
    client.get("/v1/config", headers=bearer(token))

    r = client.get("/v1/audit", params={"type": "authz_denied"}, headers=ROOT)
    denied = [rec for rec in r.json()["records"]
              if rec["details"].get("reason") == "identity_deactivated"]
    assert denied and denied[0]["details"]["identity"] == "alice"


def test_token_rotation_revokes_old_token(client):
    token = make_admin(
        client, "cfg-read", "alice", [perm("config:read", GLOBAL)]
    )
    assert client.get("/v1/config", headers=bearer(token)).status_code == 200

    r = client.put(
        "/v1/admin/identities/alice",
        json={"rotate_token": True},
        headers=ROOT,
    )
    assert r.status_code == 200
    new_token = r.json()["token"]
    assert new_token != token

    # the old token is dead from the very next request
    assert client.get("/v1/config", headers=bearer(token)).status_code == 401
    assert client.get("/v1/config", headers=bearer(new_token)).status_code == 200


def test_unknown_and_missing_tokens_are_401(client):
    make_admin(client, "cfg-read", "alice", [perm("config:read", GLOBAL)])
    assert client.get("/v1/config").status_code == 401
    assert client.get("/v1/config", headers=bearer("nope")).status_code == 401


def test_bootstrap_token_keeps_working_and_is_global(client):
    assert client.get("/v1/config", headers=ROOT).status_code == 200
    assert client.get("/v1/admin/identities", headers=ROOT).status_code == 200
    r = client.post("/v1/config", json=base_config(1), headers=ROOT)
    assert r.status_code == 200


def test_identity_version_and_authz_version_increment(client):
    token = make_admin(client, "r1", "alice", [perm("config:read", GLOBAL)])
    v_after_create = client.get("/v1/admin/identities", headers=ROOT).json()[
        "authz_version"
    ]
    assert v_after_create == 2  # role create + identity create

    r = client.put(
        "/v1/admin/identities/alice", json={"roles": ["r1"]}, headers=ROOT
    )
    assert r.json()["identity"]["identity_version"] == 1  # no-op, no bump
    assert r.json()["authz_version"] == v_after_create

    make_admin(client, "r2", "bob", [perm("cache:read", GLOBAL)])
    r = client.put(
        "/v1/admin/identities/alice", json={"roles": ["r1", "r2"]}, headers=ROOT
    )
    body = r.json()
    assert body["identity"]["identity_version"] == 2
    assert body["authz_version"] > v_after_create
    assert client.get("/v1/config", headers=bearer(token)).status_code == 200


# -- scoped config authorization -----------------------------------------------


def test_scoped_config_merge_preserves_other_scopes(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    token = make_admin(
        client,
        "vip-writer",
        "vip-admin",
        [perm("config:read", TENANT_VIP), perm("config:write", TENANT_VIP)],
    )

    # tenant admin replaces its own rule via a scoped (tenant-only) bundle
    scoped = {
        "version": 2,
        "rules": [
            {"name": "api", "scope": "tenant", "tenant": "vip",
             "rule_version": 2, "ttl": 30,
             "targets": [{"id": "vip2", "address": "tcp://10.2.0.2:80",
                          "weight": 1}]},
        ],
    }
    r = client.post("/v1/config", json=scoped, headers=bearer(token))
    assert r.status_code == 200, r.text
    assert r.json()["version"] == 2

    # the rest of the config survived the scoped apply
    full = client.get("/v1/config", headers=ROOT).json()
    keys = {(r["name"], r["scope"], r.get("region"), r.get("tenant"))
            for r in full["rules"]}
    assert ("api", "global", None, None) in keys
    assert ("api", "region", "eu", None) in keys
    assert ("api", "tenant", None, "vip") in keys

    # resolution reflects the new tenant rule; other scopes untouched
    r = client.get("/v1/resolve", params={"name": "api", "region": "eu",
                                          "tenant": "vip", "client": "c"})
    assert r.json()["chosen"] == "vip2"
    r = client.get("/v1/resolve", params={"name": "api", "region": "us",
                                          "tenant": "acme", "client": "c"})
    assert r.json()["chosen"] == "g1"


def test_region_admin_inherits_tenant_scope(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    token = make_admin(
        client,
        "eu-ops",
        "eu-admin",
        [perm("config:write", REGION_EU), perm("config:read", REGION_EU)],
    )
    # region grant covers the region rule and inherits tenant-level rules
    bundle = {
        "version": 2,
        "rules": [
            {"name": "api", "scope": "region", "region": "eu",
             "rule_version": 2, "ttl": 60,
             "targets": [{"id": "eu2", "address": "tcp://10.1.0.2:80",
                          "weight": 1}]},
            {"name": "api", "scope": "tenant", "tenant": "vip",
             "rule_version": 2, "ttl": 60,
             "targets": [{"id": "vip9", "address": "tcp://10.2.0.9:80",
                          "weight": 1}]},
        ],
    }
    r = client.post("/v1/config", json=bundle, headers=bearer(token))
    assert r.status_code == 200, r.text

    # ...but not another region, and not the global scope
    for rule in (
        {"name": "api", "scope": "region", "region": "us", "rule_version": 2,
         "ttl": 60,
         "targets": [{"id": "us1", "address": "tcp://10.3.0.1:80",
                      "weight": 1}]},
        {"name": "api", "scope": "global", "rule_version": 2, "ttl": 60,
         "targets": [{"id": "g9", "address": "tcp://10.0.0.9:80",
                      "weight": 1}]},
    ):
        r = client.post(
            "/v1/config",
            json={"version": 3, "rules": [rule]},
            headers=bearer(token),
        )
        assert r.status_code == 403, r.text
    assert client.get("/v1/config", headers=ROOT).json()["version"] == 2


def test_tenant_admin_cannot_widen_to_region_or_global(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    token = make_admin(
        client,
        "vip-writer",
        "vip-admin",
        [perm("config:write", TENANT_VIP)],
    )
    for rule in (
        {"name": "api", "scope": "region", "region": "eu", "rule_version": 2,
         "ttl": 60,
         "targets": [{"id": "eu9", "address": "tcp://10.1.0.9:80",
                      "weight": 1}]},
        {"name": "api", "scope": "global", "rule_version": 2, "ttl": 60,
         "targets": [{"id": "g9", "address": "tcp://10.0.0.9:80",
                      "weight": 1}]},
        {"name": "api", "scope": "tenant", "tenant": "acme",
         "rule_version": 2, "ttl": 60,
         "targets": [{"id": "a1", "address": "tcp://10.4.0.1:80",
                      "weight": 1}]},
    ):
        r = client.post(
            "/v1/config",
            json={"version": 2, "rules": [rule]},
            headers=bearer(token),
        )
        assert r.status_code == 403, r.text
    # nothing was applied
    assert client.get("/v1/config", headers=ROOT).json()["version"] == 1


def test_forbidden_config_write_has_no_side_effects(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    token = make_admin(
        client, "vip-writer", "vip-admin", [perm("config:write", TENANT_VIP)]
    )
    # warm the cache
    r = client.get("/v1/resolve", params={"name": "api", "region": "eu",
                                          "tenant": "vip", "client": "c"})
    assert r.status_code == 200
    r = client.get("/v1/resolve", params={"name": "api", "region": "eu",
                                          "tenant": "vip", "client": "c"})
    assert r.json()["cached"] is True
    cache_before = client.get("/v1/cache", headers=ROOT).json()["entries"]
    audit_before = client.get(
        "/v1/audit", params={"type": "rule_change"}, headers=ROOT
    ).json()["records"]

    evil = {
        "version": 2,
        "rules": [
            {"name": "api", "scope": "global", "rule_version": 2, "ttl": 60,
             "targets": [{"id": "evil", "address": "tcp://9.9.9.9:80",
                          "weight": 1}]},
        ],
    }
    r = client.post("/v1/config", json=evil, headers=bearer(token))
    assert r.status_code == 403

    # no config, cache or audit side effects
    assert client.get("/v1/config", headers=ROOT).json()["version"] == 1
    cache_after = client.get("/v1/cache", headers=ROOT).json()["entries"]
    assert len(cache_after) == len(cache_before)
    audit_after = client.get(
        "/v1/audit", params={"type": "rule_change"}, headers=ROOT
    ).json()["records"]
    assert len(audit_after) == len(audit_before)
    # ...but the denial itself is audited
    denied = client.get(
        "/v1/audit", params={"type": "authz_denied"}, headers=ROOT
    ).json()["records"]
    assert any(rec["details"]["identity"] == "vip-admin"
               and rec["details"]["action"] == "config:write"
               for rec in denied)


def test_config_read_is_filtered_by_scope(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    token = make_admin(
        client, "vip-reader", "vip-admin", [perm("config:read", TENANT_VIP)]
    )
    r = client.get("/v1/config", headers=bearer(token))
    assert r.status_code == 200
    rules = r.json()["rules"]
    assert len(rules) == 1 and rules[0]["scope"] == "tenant"
    assert rules[0]["tenant"] == "vip"


def test_scoped_preview_and_commit_roundtrip(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    token = make_admin(
        client,
        "vip-writer",
        "vip-admin",
        [perm("config:write", TENANT_VIP)],
    )
    scoped = {
        "version": 2,
        "rules": [
            {"name": "api", "scope": "tenant", "tenant": "vip",
             "rule_version": 2, "ttl": 30,
             "targets": [{"id": "vip2", "address": "tcp://10.2.0.2:80",
                          "weight": 1}]},
        ],
    }
    r = client.post("/v1/config/preview", json=scoped, headers=bearer(token))
    assert r.status_code == 200, r.text
    preview = r.json()
    assert preview["dry_run"] is True
    # the preview ran against the merged (scoped) bundle
    assert client.get("/v1/config", headers=ROOT).json()["version"] == 1

    scoped["preview_token"] = preview["preview_token"]
    r = client.post("/v1/config", json=scoped, headers=bearer(token))
    assert r.status_code == 200, r.text
    assert client.get("/v1/config", headers=ROOT).json()["version"] == 2


def test_rollback_requires_global_scope(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    v2 = base_config(2)
    v2["rules"][0]["targets"] = [
        {"id": "g2", "address": "tcp://10.0.0.2:80", "weight": 1}
    ]
    client.post("/v1/config", json=v2, headers=ROOT)

    token = make_admin(
        client, "vip-writer", "vip-admin", [perm("config:write", TENANT_VIP)]
    )
    r = client.post("/v1/config/rollback", json={"version": 1},
                    headers=bearer(token))
    assert r.status_code == 403
    r = client.post("/v1/config/rollback/preview", json={"version": 1},
                    headers=bearer(token))
    assert r.status_code == 403
    assert client.get("/v1/config", headers=ROOT).json()["version"] == 2


# -- cache and health scopes ----------------------------------------------------


def test_cache_flush_is_scoped(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    for tenant, region in (("vip", "eu"), ("acme", "us")):
        client.get("/v1/resolve", params={"name": "api", "region": region,
                                          "tenant": tenant, "client": "c"})
    assert len(client.get("/v1/cache", headers=ROOT).json()["entries"]) == 2

    token = make_admin(
        client, "vip-flush", "vip-admin", [perm("cache:flush", TENANT_VIP)]
    )
    r = client.post("/v1/cache/flush", headers=bearer(token))
    assert r.status_code == 200 and r.json()["flushed"] == 1
    entries = client.get("/v1/cache", headers=ROOT).json()["entries"]
    assert len(entries) == 1 and entries[0]["tenant"] == "acme"


def test_cache_flush_denied_without_permission_and_no_side_effects(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    client.get("/v1/resolve", params={"name": "api", "region": "eu",
                                      "tenant": "vip", "client": "c"})
    token = make_admin(
        client, "vip-reader", "vip-admin", [perm("config:read", TENANT_VIP)]
    )
    r = client.post("/v1/cache/flush", headers=bearer(token))
    assert r.status_code == 403
    assert len(client.get("/v1/cache", headers=ROOT).json()["entries"]) == 1


def test_cache_read_is_filtered(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    for tenant, region in (("vip", "eu"), ("acme", "us")):
        client.get("/v1/resolve", params={"name": "api", "region": region,
                                          "tenant": tenant, "client": "c"})
    token = make_admin(
        client, "vip-cache", "vip-admin", [perm("cache:read", TENANT_VIP)]
    )
    entries = client.get("/v1/cache", headers=bearer(token)).json()["entries"]
    assert len(entries) == 1 and entries[0]["tenant"] == "vip"


def test_health_override_requires_full_coverage(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    token = make_admin(
        client,
        "vip-health",
        "vip-admin",
        [perm("health:write", TENANT_VIP), perm("health:read", TENANT_VIP)],
    )
    # vip1 is referenced only by the tenant rule: inside the caller's scope
    r = client.post("/v1/health/targets/vip1", json={"healthy": False},
                    headers=bearer(token))
    assert r.status_code == 200 and r.json()["healthy"] is False

    # g1 belongs to the global rule: out of scope, denied without side effects
    client.post("/v1/health/targets/g1", json={"healthy": False}, headers=ROOT)
    r = client.post("/v1/health/targets/g1", json={"healthy": True},
                    headers=bearer(token))
    assert r.status_code == 403
    assert client.get("/v1/health/targets", headers=ROOT).json()[
        "targets"
    ]["g1"]["healthy"] is False

    # the override is audited with the acting identity
    changes = client.get("/v1/audit", params={"type": "health_change"},
                         headers=ROOT).json()["records"]
    assert any(rec["details"].get("identity") == "vip-admin"
               and rec["details"]["target_id"] == "vip1" for rec in changes)

    # unknown target -> 404
    r = client.post("/v1/health/targets/nope", json={"healthy": False},
                    headers=bearer(token))
    assert r.status_code == 404


def test_health_read_is_filtered(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    client.post("/v1/health/targets/vip1", json={"healthy": False},
                headers=ROOT)
    client.post("/v1/health/targets/g1", json={"healthy": False}, headers=ROOT)
    token = make_admin(
        client, "vip-health", "vip-admin", [perm("health:read", TENANT_VIP)]
    )
    targets = client.get("/v1/health/targets",
                         headers=bearer(token)).json()["targets"]
    assert set(targets) == {"vip1"}


def test_scoped_merge_preserves_scheduled_rules(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    # schedule a future region-eu rule: the manager keeps the current rule
    # alongside the scheduled one within the same config version
    cfg = base_config(2)
    cfg["rules"][1] = {
        "name": "api", "scope": "region", "region": "eu", "rule_version": 2,
        "ttl": 60, "effective_from": 4_000_000_000,
        "targets": [{"id": "eu-future", "address": "tcp://10.1.0.99:80",
                     "weight": 1}],
    }
    r = client.post("/v1/config", json=cfg, headers=ROOT)
    assert r.status_code == 200, r.text
    assert len([x for x in client.get("/v1/config", headers=ROOT)
                .json()["rules"] if x["scope"] == "region"]) == 2

    token = make_admin(
        client, "vip-writer", "vip-admin", [perm("config:write", TENANT_VIP)]
    )
    scoped = {
        "version": 3,
        "rules": [
            {"name": "api", "scope": "tenant", "tenant": "vip",
             "rule_version": 3, "ttl": 30,
             "targets": [{"id": "vip2", "address": "tcp://10.2.0.2:80",
                          "weight": 1}]},
        ],
    }
    r = client.post("/v1/config", json=scoped, headers=bearer(token))
    assert r.status_code == 200, r.text
    # the scheduled region rule (both versions) survived the scoped apply
    rules = client.get("/v1/config", headers=ROOT).json()["rules"]
    eu_rules = [r for r in rules
                if r["scope"] == "region" and r.get("region") == "eu"]
    assert len(eu_rules) == 2
    assert any(r["effective_from"] == 4_000_000_000 for r in eu_rules)


def test_scoped_merge_preserves_tiers_and_groups(client):
    cfg = base_config(1)
    cfg["rate_limit_tiers"] = [
        {"id": "global-default", "scope": "global", "rate_per_second": 100,
         "burst": 200, "priority": 100},
    ]
    cfg["release_groups"] = [
        {"id": "canary", "name": "api", "scope": "global", "priority": 5,
         "match_labels": {"env": "canary"}, "percent": 50, "ttl": 30,
         "window_start": 1, "window_end": 4_000_000_000, "rule_version": 1,
         "targets": [{"id": "gc1", "address": "tcp://10.0.0.11:80",
                      "weight": 1}]},
    ]
    client.post("/v1/config", json=cfg, headers=ROOT)
    token = make_admin(
        client, "vip-writer", "vip-admin", [perm("config:write", TENANT_VIP)]
    )
    scoped = {
        "version": 2,
        "rules": [
            {"name": "api", "scope": "tenant", "tenant": "vip",
             "rule_version": 2, "ttl": 30,
             "targets": [{"id": "vip2", "address": "tcp://10.2.0.2:80",
                          "weight": 1}]},
        ],
        "rate_limit_tiers": [
            {"id": "vip-tier", "scope": "tenant", "tenant": "vip",
             "rate_per_second": 500, "burst": 1000, "priority": 0},
        ],
    }
    r = client.post("/v1/config", json=scoped, headers=bearer(token))
    assert r.status_code == 200, r.text
    full = client.get("/v1/config", headers=ROOT).json()
    tier_ids = {t["id"] for t in full["rate_limit_tiers"]}
    assert tier_ids == {"global-default", "vip-tier"}
    assert len(full["release_groups"]) == 1
    # the tenant tier now governs vip resolutions
    r = client.get("/v1/explain", params={"name": "api", "region": "eu",
                                          "tenant": "vip", "client": "c"})
    assert r.json()["rate_limit"]["tier_id"] == "vip-tier"


def test_health_override_denied_when_target_is_shared(client):
    cfg = base_config(1)
    # the tenant rule references the same target as the global rule
    cfg["rules"][2]["targets"] = [
        {"id": "g1", "address": "tcp://10.0.0.1:80", "weight": 1}
    ]
    client.post("/v1/config", json=cfg, headers=ROOT)
    token = make_admin(
        client, "vip-health", "vip-admin", [perm("health:write", TENANT_VIP)]
    )
    # g1 is referenced by the global rule too: overriding it would leak
    r = client.post("/v1/health/targets/g1", json={"healthy": False},
                    headers=bearer(token))
    assert r.status_code == 403
    # vip1 is exclusive to the tenant rule
    r = client.post("/v1/health/targets/vip1", json={"healthy": False},
                    headers=bearer(token))
    assert r.status_code == 404  # no longer referenced by any rule


def test_identity_update_optimistic_concurrency(client):
    make_admin(client, "r1", "alice", [perm("config:read", GLOBAL)])
    r = client.put(
        "/v1/admin/identities/alice",
        json={"rotate_token": True, "expected_version": 9},
        headers=ROOT,
    )
    assert r.status_code == 409
    r = client.put(
        "/v1/admin/identities/alice",
        json={"rotate_token": True, "expected_version": 1},
        headers=ROOT,
    )
    assert r.status_code == 200
    assert r.json()["identity"]["identity_version"] == 2


# -- version history scoping -----------------------------------------------------


def test_version_history_is_filtered_for_scoped_callers(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    v2 = base_config(2)
    v2["rules"][0]["rule_version"] = 2  # change the global rule
    v2["rules"][0]["targets"] = [
        {"id": "g2", "address": "tcp://10.0.0.2:80", "weight": 1}
    ]
    v2["rules"][2]["rule_version"] = 2  # and the tenant rule
    v2["rules"][2]["targets"] = [
        {"id": "vip2", "address": "tcp://10.2.0.2:80", "weight": 1}
    ]
    client.post("/v1/config", json=v2, headers=ROOT)

    token = make_admin(
        client, "vip-hist", "vip-admin", [perm("versions:read", TENANT_VIP)]
    )
    r = client.get("/v1/config/versions", headers=bearer(token))
    assert r.status_code == 200
    summaries = [v["summary"] for v in r.json()["versions"] if v["summary"]]
    assert summaries
    for s in summaries:
        for d in s["rule_diffs"]:
            assert d["scope"] == "tenant" and d["tenant"] == "vip"

    r = client.get("/v1/config/versions/2", headers=bearer(token))
    assert r.status_code == 200
    bundle = r.json()["bundle"]
    assert all(rule["scope"] == "tenant" for rule in bundle["rules"])

    # the global caller still sees everything
    r = client.get("/v1/config/versions/2", headers=ROOT)
    assert len(r.json()["bundle"]["rules"]) == 3


# -- delegation constraints -------------------------------------------------------


def test_tenant_admin_cannot_delegate_beyond_its_scope(client):
    token = make_admin(
        client,
        "vip-owner",
        "vip-admin",
        [perm("admin:manage", TENANT_VIP), perm("config:read", TENANT_VIP)],
    )
    # cannot mint region or global roles
    for scope in (REGION_EU, GLOBAL, TENANT_ACME):
        r = client.post(
            "/v1/admin/roles",
            json={"id": f"evil-{scope['scope']}",
                  "permissions": [perm("config:write", scope)]},
            headers=bearer(token),
        )
        assert r.status_code == 403, r.text
    # can mint a same-tenant role and identity
    r = client.post(
        "/v1/admin/roles",
        json={"id": "vip-sub",
              "permissions": [perm("config:read", TENANT_VIP)]},
        headers=bearer(token),
    )
    assert r.status_code == 201, r.text
    r = client.post(
        "/v1/admin/identities",
        json={"id": "vip-sub-admin", "roles": ["vip-sub"]},
        headers=bearer(token),
    )
    assert r.status_code == 201, r.text


def test_tenant_admin_cannot_assign_a_broader_role(client):
    client.post(
        "/v1/admin/roles",
        json={"id": "global-role",
              "permissions": [perm("config:write", GLOBAL)]},
        headers=ROOT,
    )
    token = make_admin(
        client, "vip-owner", "vip-admin", [perm("admin:manage", TENANT_VIP)]
    )
    r = client.post(
        "/v1/admin/identities",
        json={"id": "sneaky", "roles": ["global-role"]},
        headers=bearer(token),
    )
    assert r.status_code == 403
    # the broader role is also invisible to the narrower admin
    ids = {r["id"] for r in
           client.get("/v1/admin/roles", headers=bearer(token)).json()["roles"]}
    assert "global-role" not in ids
    r = client.get("/v1/admin/roles/global-role", headers=bearer(token))
    assert r.status_code == 403


def test_identity_visibility_is_scoped(client):
    make_admin(client, "global-role", "root-admin",
               [perm("config:read", GLOBAL)])
    token = make_admin(client, "vip-owner", "vip-admin",
                       [perm("admin:manage", TENANT_VIP)])
    ids = {i["id"] for i in client.get(
        "/v1/admin/identities", headers=bearer(token)).json()["identities"]}
    assert "root-admin" not in ids
    assert "vip-admin" in ids  # an identity always sees itself
    r = client.get("/v1/admin/identities/root-admin", headers=bearer(token))
    assert r.status_code == 403


def test_role_update_requires_delegable_old_and_new_permissions(client):
    client.post(
        "/v1/admin/roles",
        json={"id": "mixed",
              "permissions": [perm("config:read", GLOBAL)]},
        headers=ROOT,
    )
    token = make_admin(client, "vip-owner", "vip-admin",
                       [perm("admin:manage", TENANT_VIP)])
    # the role's existing permissions are outside the caller's scope
    r = client.put(
        "/v1/admin/roles/mixed",
        json={"permissions": [perm("config:read", TENANT_VIP)]},
        headers=bearer(token),
    )
    assert r.status_code == 403


def test_role_in_use_cannot_be_deleted(client):
    make_admin(client, "r1", "alice", [perm("config:read", GLOBAL)])
    r = client.delete("/v1/admin/roles/r1", headers=ROOT)
    assert r.status_code == 409
    r = client.delete("/v1/admin/roles/r1",
                      headers={**ROOT, "Idempotency-Key": "del-r1"})
    assert r.status_code == 409


def test_admin_manage_requires_permission(client):
    token = make_admin(client, "cfg-read", "alice",
                       [perm("config:read", GLOBAL)])
    r = client.get("/v1/admin/roles", headers=bearer(token))
    assert r.status_code == 403
    r = client.post("/v1/admin/identities", json={"id": "x", "roles": []},
                    headers=bearer(token))
    assert r.status_code == 403


# -- optimistic concurrency and concurrent modification ---------------------------


def test_expected_version_optimistic_concurrency(client):
    make_admin(client, "r1", "alice", [perm("config:read", GLOBAL)])
    role = client.get("/v1/admin/roles/r1", headers=ROOT).json()["role"]
    assert role["role_version"] == 1

    r = client.put(
        "/v1/admin/roles/r1",
        json={"permissions": [perm("config:read", GLOBAL),
                              perm("cache:read", GLOBAL)],
              "expected_version": 7},
        headers=ROOT,
    )
    assert r.status_code == 409

    r = client.put(
        "/v1/admin/roles/r1",
        json={"permissions": [perm("config:read", GLOBAL),
                              perm("cache:read", GLOBAL)],
              "expected_version": 1},
        headers=ROOT,
    )
    assert r.status_code == 200
    assert r.json()["role"]["role_version"] == 2


def test_concurrent_role_updates_exactly_one_wins(client):
    make_admin(client, "r1", "alice", [perm("config:read", GLOBAL)])

    def attempt(i):
        return client.put(
            "/v1/admin/roles/r1",
            json={"description": f"attempt-{i}", "expected_version": 1},
            headers=ROOT,
        ).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(attempt, range(8)))
    assert codes.count(200) == 1
    assert codes.count(409) == 7
    role = client.get("/v1/admin/roles/r1", headers=ROOT).json()["role"]
    assert role["role_version"] == 2


def test_concurrent_identity_creation_is_unique(client):
    client.post(
        "/v1/admin/roles",
        json={"id": "r1", "permissions": [perm("config:read", GLOBAL)]},
        headers=ROOT,
    )

    def attempt(_):
        return client.post("/v1/admin/identities",
                           json={"id": "alice", "roles": ["r1"]},
                           headers=ROOT).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        codes = list(pool.map(attempt, range(6)))
    assert codes.count(201) == 1
    assert codes.count(409) == 5


# -- idempotent retries -----------------------------------------------------------


def test_idempotency_key_replays_stored_response(client):
    key = {"Idempotency-Key": "role-create-1"}
    payload = {"id": "r1", "permissions": [perm("config:read", GLOBAL)]}
    r1 = client.post("/v1/admin/roles", json=payload,
                     headers={**ROOT, **key})
    r2 = client.post("/v1/admin/roles", json=payload,
                     headers={**ROOT, **key})
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r2.json()["idempotent_replay"] is True
    assert r2.json()["role"] == r1.json()["role"]
    assert r2.json()["authz_version"] == r1.json()["authz_version"]

    # the mutation ran exactly once: one role, one audit record, one bump
    roles = client.get("/v1/admin/roles", headers=ROOT).json()["roles"]
    assert [r["id"] for r in roles] == ["r1"]
    changes = client.get("/v1/audit", params={"type": "role_change"},
                         headers=ROOT).json()["records"]
    assert len(changes) == 1


def test_idempotency_key_conflict_on_different_payload(client):
    key = {"Idempotency-Key": "role-create-2"}
    client.post("/v1/admin/roles",
                json={"id": "r1",
                      "permissions": [perm("config:read", GLOBAL)]},
                headers={**ROOT, **key})
    r = client.post("/v1/admin/roles",
                    json={"id": "r2",
                          "permissions": [perm("config:read", GLOBAL)]},
                    headers={**ROOT, **key})
    assert r.status_code == 409


def test_idempotent_identity_create_returns_same_token(client):
    client.post(
        "/v1/admin/roles",
        json={"id": "r1", "permissions": [perm("config:read", GLOBAL)]},
        headers=ROOT,
    )
    key = {"Idempotency-Key": "identity-create-1"}
    payload = {"id": "alice", "roles": ["r1"]}
    r1 = client.post("/v1/admin/identities", json=payload,
                     headers={**ROOT, **key})
    r2 = client.post("/v1/admin/identities", json=payload,
                     headers={**ROOT, **key})
    assert r1.status_code == 201 and r2.status_code == 201
    assert r1.json()["token"] == r2.json()["token"]
    assert r2.json()["idempotent_replay"] is True
    idents = client.get("/v1/admin/identities", headers=ROOT).json()[
        "identities"
    ]
    assert [i["id"] for i in idents] == ["alice"]


def test_deactivate_is_naturally_idempotent(client):
    make_admin(client, "r1", "alice", [perm("config:read", GLOBAL)])
    r1 = client.post("/v1/admin/identities/alice/deactivate", headers=ROOT)
    r2 = client.post("/v1/admin/identities/alice/deactivate", headers=ROOT)
    assert r1.json()["changed"] is True
    assert r2.status_code == 200 and r2.json()["changed"] is False
    # no version bump and no duplicate audit record for the no-op
    assert r2.json()["authz_version"] == r1.json()["authz_version"]
    changes = client.get("/v1/audit", params={"type": "identity_change"},
                         headers=ROOT).json()["records"]
    deactivations = [c for c in changes
                     if c["details"]["action"] == "deactivated"]
    assert len(deactivations) == 1


# -- audit ------------------------------------------------------------------------


def test_every_decision_and_change_is_audited(client):
    token = make_admin(client, "vip-writer", "vip-admin",
                       [perm("config:write", TENANT_VIP)])
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    client.post("/v1/config",
                json={"version": 2, "rules": [
                    {"name": "api", "scope": "tenant", "tenant": "vip",
                     "rule_version": 2, "ttl": 30,
                     "targets": [{"id": "v2", "address": "tcp://10.2.0.2:80",
                                  "weight": 1}]}]},
                headers=bearer(token))

    decisions = client.get("/v1/audit", params={"type": "authz_decision"},
                           headers=ROOT).json()["records"]
    assert any(rec["details"]["identity"] == "vip-admin"
               and rec["details"]["action"] == "config:write"
               and rec["details"]["outcome"] == "allow" for rec in decisions)

    role_changes = client.get("/v1/audit", params={"type": "role_change"},
                              headers=ROOT).json()["records"]
    assert role_changes[0]["details"]["actor"] == "bootstrap"
    assert role_changes[0]["details"]["authz_version"] >= 1

    identity_changes = client.get(
        "/v1/audit", params={"type": "identity_change"}, headers=ROOT
    ).json()["records"]
    assert identity_changes[0]["details"]["identity"] == "vip-admin"
    assert identity_changes[0]["details"]["new"]["status"] == "active"


def test_audit_query_is_scoped_for_narrow_callers(client):
    client.post("/v1/config", json=base_config(1), headers=ROOT)
    token = make_admin(
        client,
        "vip-auditor",
        "vip-admin",
        [perm("audit:read", TENANT_VIP)],
    )
    records = client.get("/v1/audit", headers=bearer(token)).json()["records"]
    assert records, "a scoped caller sees at least its own decisions"
    for rec in records:
        d = rec["details"]
        # own records, or records whose scope is covered by tenant:vip
        own = d.get("identity") == "vip-admin" or d.get("actor") == "vip-admin"
        tenant_scoped = d.get("rule_key", "").endswith("|vip") or (
            d.get("scope") == "tenant" and d.get("tenant") == "vip"
        )
        assert own or tenant_scoped, rec
    # bootstrap's global rule_change records are not visible
    assert not any(rec["type"] == "rule_change"
                   and rec["details"].get("rule_key") == "api|global||"
                   for rec in records)


def test_version_history_group_diffs_keep_region_scope(client):
    cfg = base_config(1)
    cfg["release_groups"] = [
        {"id": "canary-eu", "name": "api", "scope": "region", "region": "eu",
         "priority": 5, "match_labels": {"env": "canary"}, "percent": 50,
         "ttl": 30, "window_start": 1, "window_end": 4_000_000_000,
         "rule_version": 1,
         "targets": [{"id": "euc1", "address": "tcp://10.1.0.11:80",
                      "weight": 1}]},
    ]
    client.post("/v1/config", json=cfg, headers=ROOT)
    token = make_admin(
        client, "eu-hist", "eu-admin", [perm("versions:read", REGION_EU)]
    )
    r = client.get("/v1/config/versions/1", headers=bearer(token))
    assert r.status_code == 200
    summary = r.json()["summary"]
    group_diffs = summary["release_group_diffs"]
    assert len(group_diffs) == 1
    assert group_diffs[0]["region"] == "eu"
    # tenant-scoped callers do not see the region group diff
    vip = make_admin(
        client, "vip-hist", "vip-admin", [perm("versions:read", TENANT_VIP)]
    )
    r = client.get("/v1/config/versions/1", headers=bearer(vip))
    assert r.json()["summary"]["release_group_diffs"] == []


def test_open_mode_ignores_unknown_tokens(tmp_path):
    comp = Components(db_path=str(tmp_path / "open2.db"),
                      enable_background=False)
    with TestClient(create_app(comp)) as c:
        assert c.get("/v1/config", headers=bearer("whatever")).status_code == 200


# -- persistence -------------------------------------------------------------------


def test_authz_state_survives_restart(tmp_path):
    db = str(tmp_path / "persist.db")
    comp1 = Components(db_path=db, admin_token=ROOT_TOKEN,
                       enable_background=False)
    with TestClient(create_app(comp1)) as c1:
        token = make_admin(c1, "r1", "alice", [perm("config:read", GLOBAL)])
        c1.post("/v1/admin/roles",
                json={"id": "r2", "permissions": [perm("cache:read", GLOBAL)]},
                headers={**ROOT, "Idempotency-Key": "persist-key"})
        version_before = c1.get("/v1/admin/roles", headers=ROOT).json()[
            "authz_version"
        ]

    comp2 = Components(db_path=db, admin_token=ROOT_TOKEN,
                       enable_background=False)
    with TestClient(create_app(comp2)) as c2:
        # identity token still authenticates
        assert c2.get("/v1/config", headers=bearer(token)).status_code == 200
        # roles and the global authz version survived
        roles = c2.get("/v1/admin/roles", headers=ROOT).json()
        assert {r["id"] for r in roles["roles"]} == {"r1", "r2"}
        assert roles["authz_version"] == version_before
        # the idempotency record survived: replay returns the stored response
        r = c2.post("/v1/admin/roles",
                    json={"id": "r2",
                          "permissions": [perm("cache:read", GLOBAL)]},
                    headers={**ROOT, "Idempotency-Key": "persist-key"})
        assert r.status_code == 201 and r.json()["idempotent_replay"] is True
        # deactivation persists too
        c2.post("/v1/admin/identities/alice/deactivate", headers=ROOT)

    comp3 = Components(db_path=db, admin_token=ROOT_TOKEN,
                       enable_background=False)
    with TestClient(create_app(comp3)) as c3:
        assert c3.get("/v1/config", headers=bearer(token)).status_code == 401


def test_store_rejects_duplicate_tokens(tmp_path):
    from app.authz import AuthzConflict

    db = connect(str(tmp_path / "dup.db"))
    store = AuthzStore(db, AuditLog(db), admin_token=ROOT_TOKEN)
    bootstrap = store.authenticate(ROOT_TOKEN)
    ident, token = store.create_identity(bootstrap, "alice", [], token="tok-1")
    assert ident.id == "alice" and token == "tok-1"
    with pytest.raises(AuthzConflict):
        store.create_identity(bootstrap, "bob", [], token="tok-1")


# -- open / bootstrap modes --------------------------------------------------------


def test_open_mode_without_token_or_identities(tmp_path):
    comp = Components(db_path=str(tmp_path / "open.db"),
                      enable_background=False)
    with TestClient(create_app(comp)) as c:
        assert c.get("/v1/config").status_code == 200
        assert c.post("/v1/config", json=base_config(1)).status_code == 200


def test_creating_first_identity_activates_enforcement(tmp_path):
    comp = Components(db_path=str(tmp_path / "enforce.db"),
                      enable_background=False)
    with TestClient(create_app(comp)) as c:
        assert c.get("/v1/config").status_code == 200  # open mode
        r = c.post("/v1/admin/roles",
                   json={"id": "r1",
                         "permissions": [perm("config:read", GLOBAL)]})
        assert r.status_code == 201
        r = c.post("/v1/admin/identities",
                   json={"id": "alice", "roles": ["r1"]})
        token = r.json()["token"]
        # enforcement is now on: anonymous requests are rejected
        assert c.get("/v1/config").status_code == 401
        assert c.get("/v1/config", headers=bearer(token)).status_code == 200
