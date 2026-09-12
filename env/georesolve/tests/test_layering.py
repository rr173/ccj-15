"""Layered override: tenant > region > global, and isolation between scopes."""
from __future__ import annotations

from tests.conftest import bundle, rule, target


def setup_layers(stack):
    stack.config.apply(
        bundle(
            1,
            [
                rule("api", "global", targets=[target("g1")], ttl=60, rule_version=1),
                rule("api", "region", region="eu", targets=[target("e1")],
                     ttl=60, rule_version=1),
                rule("api", "tenant", tenant="vip", targets=[target("v1")],
                     ttl=60, rule_version=1),
            ],
        )
    )


def test_global_rule_applies_without_overrides(stack):
    setup_layers(stack)
    ans = stack.resolver.resolve("api", region="us", tenant="acme", client_key="c1")
    assert ans["status"] == "OK"
    assert ans["rule_scope"] == "global"
    assert ans["chosen"] == "g1"


def test_region_rule_overrides_global_only_in_that_region(stack):
    setup_layers(stack)
    eu = stack.resolver.resolve("api", region="eu", tenant="acme", client_key="c1")
    us = stack.resolver.resolve("api", region="us", tenant="acme", client_key="c1")
    assert eu["rule_scope"] == "region" and eu["chosen"] == "e1"
    assert us["rule_scope"] == "global" and us["chosen"] == "g1"


def test_tenant_rule_overrides_region_and_global_only_for_that_tenant(stack):
    setup_layers(stack)
    vip_eu = stack.resolver.resolve("api", region="eu", tenant="vip", client_key="c1")
    vip_us = stack.resolver.resolve("api", region="us", tenant="vip", client_key="c1")
    other = stack.resolver.resolve("api", region="eu", tenant="acme", client_key="c1")
    assert vip_eu["rule_scope"] == "tenant" and vip_eu["chosen"] == "v1"
    assert vip_us["rule_scope"] == "tenant" and vip_us["chosen"] == "v1"
    assert other["rule_scope"] == "region" and other["chosen"] == "e1"


def test_no_cross_tenant_answer_leak(stack):
    setup_layers(stack)
    # Prime the cache for tenant vip, then resolve as another tenant.
    stack.resolver.resolve("api", region="eu", tenant="vip", client_key="c1")
    ans = stack.resolver.resolve("api", region="eu", tenant="acme", client_key="c1")
    assert ans["chosen"] != "v1"
    assert ans["chosen"] == "e1"
    # And a tenant with no rule at all falls to region/global, never to vip's.
    entry_vip = stack.cache.peek("api", "eu", "vip", "c1")
    entry_acme = stack.cache.peek("api", "eu", "acme", "c1")
    assert entry_vip is not None and entry_acme is not None
    assert entry_vip is not entry_acme


def test_no_cross_region_answer_leak(stack):
    setup_layers(stack)
    stack.resolver.resolve("api", region="eu", tenant="acme", client_key="c1")
    ans = stack.resolver.resolve("api", region="us", tenant="acme", client_key="c1")
    assert ans["chosen"] == "g1"


def test_unknown_name_is_nxdomain_and_scoped(stack):
    setup_layers(stack)
    ans = stack.resolver.resolve("missing", region="eu", tenant="vip", client_key="c1")
    assert ans["status"] == "NXDOMAIN"
    assert ans["rule_version"] is None
    # negative answer for eu/vip must not leak to another scope
    ans2 = stack.resolver.resolve("missing", region="us", tenant="", client_key="c1")
    assert ans2["status"] == "NXDOMAIN"
    assert ans2["cached"] is False
