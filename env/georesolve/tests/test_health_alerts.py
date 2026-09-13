"""Unit tests for health event subscriptions, suppression and delivery."""
from __future__ import annotations

import asyncio

import pytest

from app.audit import AuditLog
from app.config_store import ConfigManager
from app.health_alerts import (
    AlertConflict,
    AlertNotFound,
    AlertStore,
    AlertValidation,
    SendOutcome,
    SilenceWindowSpec,
    ST_DEAD,
    ST_FAILED,
    ST_PENDING,
    ST_SENDING,
    ST_SUCCEEDED,
    ST_SUPPRESSED,
    ST_SUPERSEDED,
    ST_UNCONFIRMED,
    SubscriptionUpsertIn,
)
from app.health_checks import (
    HealthCheckStore,
    MaintenanceWindowSpec,
    OverrideIn,
    PolicyUpsertIn,
)
from app.storage import connect
from tests.conftest import FakeClock, bundle, rule, target


class AlertFixture:
    def __init__(self, tmp_path, sender=None):
        self.clock = FakeClock()
        db = connect(str(tmp_path / "alerts.db"))
        self.db = db
        self.audit = AuditLog(db, self.clock)
        self.config = ConfigManager(db, self.audit, self.clock)
        self.health = HealthCheckStore(db, self.config, self.audit, self.clock)
        self.alerts = AlertStore(
            db, self.config, self.audit, self.clock, sender=sender
        )
        self.health.set_history_commit_listener(self.alerts.ingest_new)
        self.config.apply(
            bundle(
                1,
                [
                    rule("api", targets=[
                        target("a", address="tcp://10.0.0.1:80"),
                        target("b", address="tcp://10.0.0.2:80"),
                    ], rule_version=1)
                ],
            )
        )


@pytest.fixture
def af(tmp_path):
    return AlertFixture(tmp_path)


def policy(**over):
    base = dict(
        interval_seconds=2.0,
        timeout_seconds=1.0,
        fail_threshold=1,
        recover_threshold=1,
        maintenance_windows=[],
        priority=10,
    )
    base.update(over)
    return PolicyUpsertIn(**base)


def sub(target_id="a", **over):
    base = dict(
        target_id=target_id,
        webhook_url="http://hooks.example/alert",
    )
    base.update(over)
    return SubscriptionUpsertIn(**base)


def set_probe(ok: bool):
    import app.health_checks as mod

    async def fake(method, address, timeout):
        return {"type": "tcp", "ok": ok,
                "reason": None if ok else "connection_error",
                "status": None, "duration_ms": 0.1, "detail": ""}
    mod.run_probe = fake
    return fake


# -- subscription CRUD / validation -------------------------------------------


def test_create_subscription_validates_target_and_url(af):
    with pytest.raises(AlertNotFound):
        af.alerts.create_subscription(sub("zzz"))
    with pytest.raises(Exception):
        SubscriptionUpsertIn(target_id="a", webhook_url="ftp://nope/x")
    with pytest.raises(Exception):
        SubscriptionUpsertIn(target_id="a", webhook_url="http://x", sources=[])
    with pytest.raises(Exception):
        SubscriptionUpsertIn(target_id="a", webhook_url="http://x",
                             sources=["bogus"])
    with pytest.raises(Exception):
        SubscriptionUpsertIn(target_id="a", webhook_url="http://x",
                             consecutive_threshold=0)
    with pytest.raises(Exception):
        SubscriptionUpsertIn(target_id="a", webhook_url="http://x",
                             backoff_base_seconds=99, backoff_max_seconds=1)


def test_subscription_update_needs_expected_version_and_conflicts(af):
    s, _ = af.alerts.create_subscription(sub())
    sid = s["sub_id"]
    with pytest.raises(AlertValidation):
        af.alerts.update_subscription(sid, sub())
    with pytest.raises(AlertConflict):
        af.alerts.update_subscription(sid, sub(expected_version=99))
    updated, changed = af.alerts.update_subscription(
        sid, sub(webhook_url="http://hooks.example/v2", expected_version=1)
    )
    assert changed and updated["sub_version"] == 2
    # Identical re-PUT at the right version is a no-op.
    again, changed = af.alerts.update_subscription(
        sid, SubscriptionUpsertIn(
            target_id="a", webhook_url="http://hooks.example/v2",
            expected_version=2,
        ),
    )
    assert changed is False and again["sub_version"] == 2
    revs = af.alerts.sub_revisions(sid)
    assert [r["action"] for r in revs] == ["updated", "created"]


def test_subscription_delete_is_versioned_and_soft(af):
    s, _ = af.alerts.create_subscription(sub())
    sid = s["sub_id"]
    with pytest.raises(AlertConflict):
        af.alerts.delete_subscription(sid, expected_version=42)
    af.alerts.delete_subscription(sid, expected_version=1)
    with pytest.raises(AlertConflict):
        af.alerts.delete_subscription(sid)
    assert af.alerts.get_subscription(sid)["deleted"] is True
    assert af.alerts.list_subscriptions() == []
    assert af.alerts.list_subscriptions(include_deleted=True)[0]["sub_id"] == sid


def test_secret_is_not_echoed_in_api_view(af):
    s, _ = af.alerts.create_subscription(
        sub(signing_secret="shh")
    )
    assert s["signing_secret"] == "shh"  # store-level dict keeps it


# -- event generation + dedup ------------------------------------------------


def _fail_target(af, tid="a", times=1):
    import app.health_checks as mod
    set_probe(False)
    for _ in range(times):
        asyncio.run(af.health.check_target(tid))
    return mod


def test_unhealthy_and_recovered_events_generated_and_deduped(af):
    af.health.upsert_policy("a", policy())
    af.alerts.create_subscription(sub())
    _fail_target(af)
    events = af.alerts.list_events()["events"]
    assert [e["event_type"] for e in events] == ["unhealthy"]
    ev = events[0]
    assert ev["source"] == "check"
    assert ev["to_healthy"] is False and ev["status"] == ST_PENDING
    assert len(ev["deliveries"]) == 1
    # Re-scanning the same history (restart catch-up / double listener) does
    # not duplicate events or deliveries.
    af.alerts._conn.execute(
        "INSERT OR REPLACE INTO health_alert_meta (key, value) VALUES (?, ?)",
        ("history_cursor", "0"),
    )
    af.alerts._conn.commit()
    af.alerts.ingest_new()
    assert af.alerts.list_events()["count"] == 1

    set_probe(True)
    asyncio.run(af.health.check_target("a"))
    types = [e["event_type"] for e in af.alerts.list_events()["events"]]
    assert types == ["recovered", "unhealthy"]


def test_events_are_not_backfilled_before_first_run(af, tmp_path):
    # A failure that happens before any ingestor has run must not replay once
    # the cursor seeds itself at the newest row.
    af.health.upsert_policy("a", policy())
    _fail_target(af)
    # Brand-new AlertStore on the same DB initializes the cursor now.
    alerts2 = AlertStore(af.db, af.config, af.audit, af.clock)
    alerts2.create_subscription(sub())
    alerts2.ingest_new()
    assert alerts2.list_events()["count"] == 0
    # A later recovery + a fresh failure transition produce events.
    set_probe(True)
    asyncio.run(af.health.check_target("a"))
    set_probe(False)
    asyncio.run(af.health.check_target("a"))
    alerts2.ingest_new()
    types = {e["event_type"] for e in alerts2.list_events()["events"]}
    assert types == {"unhealthy", "recovered"}


def test_target_and_source_filters(af):
    af.health.upsert_policy("a", policy())
    af.health.upsert_policy("b", policy())
    af.alerts.create_subscription(sub(target_id="a"))
    af.alerts.create_subscription(sub(
        target_id="b", sources=["maintenance"]
    ))
    _fail_target(af, "a")
    _fail_target(af, "b")
    events = af.alerts.list_events()["events"]
    assert {e["target_id"] for e in events} == {"a"}
    # The check-sourced event for b did not match the maintenance-only sub.
    af.health.upsert_policy(
        "b",
        policy(maintenance_windows=[
            MaintenanceWindowSpec(start=af.clock.t, end=af.clock.t + 100)
        ]),
    )
    af.health.get_state("b")  # trigger window entry
    types = {
        (e["target_id"], e["event_type"])
        for e in af.alerts.list_events()["events"]
    }
    assert ("b", "maintenance_begin") in types


def test_wildcard_subscription_matches_all_targets(af):
    af.health.upsert_policy("a", policy())
    af.health.upsert_policy("b", policy())
    s, _ = af.alerts.create_subscription(sub(target_id="*"))
    assert s["target_id"] == "*"
    _fail_target(af, "a")
    _fail_target(af, "b")
    assert {e["target_id"] for e in af.alerts.list_events()["events"]} == {
        "a", "b"
    }


# -- consecutive threshold ----------------------------------------------------


def test_consecutive_threshold_delays_event_until_enough_failures(af):
    # Policy flips after 1 failure; the subscription requires 3 in a row.
    af.health.upsert_policy("a", policy(fail_threshold=1, recover_threshold=1))
    af.alerts.create_subscription(sub(consecutive_threshold=3))
    _fail_target(af)
    ev = af.alerts.list_events()["events"][0]
    assert ev["status"] == ST_UNCONFIRMED
    assert ev["deliveries"][0]["status"] == ST_UNCONFIRMED
    _fail_target(af)  # 2nd consecutive failure: still unconfirmed
    assert af.alerts.list_events()["events"][0]["status"] == ST_UNCONFIRMED
    _fail_target(af)  # 3rd -> activates
    ev = af.alerts.list_events()["events"][0]
    assert ev["status"] == ST_PENDING and ev["activated_at"] is not None


def test_threshold_streak_broken_supersedes_unconfirmed(af):
    af.health.upsert_policy(
        "a", policy(fail_threshold=1, recover_threshold=1)
    )
    af.alerts.create_subscription(sub(consecutive_threshold=3))
    _fail_target(af)
    assert af.alerts.list_events()["events"][0]["status"] == ST_UNCONFIRMED
    set_probe(True)
    asyncio.run(af.health.check_target("a"))  # streak broken + recovery
    ev = af.alerts.list_events(status=ST_SUPERSEDED)["events"]
    assert ev and ev[0]["event_type"] == "unhealthy"
    assert ev[0]["deliveries"][0]["status"] == ST_SUPERSEDED
    # A new failure after the streak reset starts confirmation from scratch.
    _fail_target(af)
    assert af.alerts.list_events(status=ST_UNCONFIRMED)["count"] == 1


# -- maintenance / override events -------------------------------------------


def test_maintenance_window_events_fire_immediately_regardless_of_threshold(af):
    af.health.upsert_policy(
        "a",
        policy(maintenance_windows=[
            MaintenanceWindowSpec(start=100.0, end=200.0)
        ]),
    )
    af.alerts.create_subscription(sub(consecutive_threshold=5))
    af.clock.t = 100.0
    af.health.is_healthy("a")
    ev = [e for e in af.alerts.list_events()["events"]
          if e["event_type"] == "maintenance_begin"][0]
    assert ev["status"] == ST_PENDING
    af.clock.t = 200.0
    af.health.is_healthy("a")
    types = {e["event_type"] for e in af.alerts.list_events()["events"]}
    assert {"maintenance_begin", "maintenance_end"} <= types


def test_override_expiry_generates_event(af):
    af.health.upsert_policy("a", policy())
    af.alerts.create_subscription(sub(sources=["manual_override"]))
    af.health.override(
        "a", OverrideIn(healthy=False, expires_at=af.clock.t + 10)
    )
    af.clock.advance(11)
    af.health.get_state("a")  # lazy expiry
    ev = af.alerts.list_events()["events"]
    assert [e["event_type"] for e in ev] == ["override_expired"]
    assert ev[0]["source"] == "manual_override"


# -- silence windows ----------------------------------------------------------


def test_silence_window_suppresses_then_releases(af):
    af.health.upsert_policy("a", policy())
    af.alerts.create_subscription(sub(silence_windows=[
        SilenceWindowSpec(start=af.clock.t, end=af.clock.t + 100)
    ]))
    _fail_target(af)
    ev = af.alerts.list_events()["events"][0]
    assert ev["deliveries"][0]["status"] == ST_SUPPRESSED
    # Still inside the window: nothing released.
    af.clock.advance(50)
    af.alerts.release_suppressed()
    assert af.alerts.list_events()["events"][0]["deliveries"][0][
        "status"] == ST_SUPPRESSED
    af.clock.advance(60)
    released = af.alerts.release_suppressed()
    assert released == 1
    assert af.alerts.list_events()["events"][0]["deliveries"][0][
        "status"] == ST_PENDING


def test_replay_overrides_silence_and_uses_frozen_snapshot(af):
    af.health.upsert_policy("a", policy())
    af.alerts.create_subscription(
        sub(
            silence_windows=[
                SilenceWindowSpec(start=af.clock.t, end=af.clock.t + 10_000)
            ],
            max_retries=2,
        )
    )
    _fail_target(af)
    ev_id = af.alerts.list_events()["events"][0]["id"]
    # Even mid-window, replay forces the delivery onto the outbox.
    result = af.alerts.replay_event(ev_id)
    assert result["deliveries"][0]["status"] == ST_PENDING
    assert result["deliveries"][0]["replayed_count"] == 1
    # The frozen snapshot is the v1 subscription even after later edits.
    af.alerts.update_subscription(
        result["deliveries"][0]["sub_id"],
        sub(
            webhook_url="http://hooks.example/changed",
            max_retries=2,
            silence_windows=[],
            expected_version=1,
        ),
    )
    d = af.alerts.get_delivery(result["deliveries"][0]["id"])
    assert d["snapshot"]["webhook_url"] == "http://hooks.example/alert"
    assert d["sub_version"] == 1


# -- delivery: success / retries / backoff / crash reclaim --------------------


class ScriptedSender:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def __call__(self, *, url, headers, body, timeout):
        self.calls.append({"url": url, "headers": dict(headers), "body": body})
        if self.outcomes:
            out = self.outcomes.pop(0)
            if isinstance(out, Exception):
                raise out
            return out
        return SendOutcome(ok=True, status_code=200)


def test_successful_delivery_sends_signed_payload(af):
    af.health.upsert_policy("a", policy())
    af.alerts.create_subscription(sub(signing_secret="topsecret"))
    _fail_target(af)
    sender = ScriptedSender([SendOutcome(ok=True, status_code=202)])
    af.alerts._sender = sender
    results = asyncio.run(af.alerts.dispatch_once())
    assert results[0]["status"] == ST_SUCCEEDED
    assert results[0]["attempts"] == 1 and results[0]["sent_at"] == af.clock.t
    req = sender.calls[0]
    assert req["url"] == "http://hooks.example/alert"
    assert req["headers"]["X-Georesolve-Signature"].startswith("sha256=")
    assert req["headers"]["Idempotency-Key"] == req["headers"][
        "X-Georesolve-Delivery-Uid"
    ]
    # Idempotent second dispatch: nothing due.
    assert asyncio.run(af.alerts.dispatch_once()) == []


def _valid_hmac(secret: str, call: dict) -> bool:
    import hashlib
    import hmac as _hmac

    expected = "sha256=" + _hmac.new(
        secret.encode(), call["body"], hashlib.sha256
    ).hexdigest()
    return _hmac.compare_digest(
        expected, call["headers"]["X-Georesolve-Signature"]
    )


def _rotate_secret(af, sid: str, new_secret: str) -> None:
    af.alerts.update_subscription(
        sid,
        SubscriptionUpsertIn(
            target_id="a",
            webhook_url="http://hooks.example/alert",
            signing_secret=new_secret,
            expected_version=1,
        ),
    )


def test_retries_after_secret_rotation_keep_signing_with_frozen_secret(af):
    # A delivery generated under the old key must keep HMAC-ing with that key
    # on every later attempt even after the admin rotates the subscription's
    # signing secret; otherwise the receiver cannot verify old events.
    af.health.upsert_policy("a", policy())
    created, _ = af.alerts.create_subscription(
        sub(signing_secret="old-secret", max_retries=3,
            backoff_base_seconds=1.0)
    )
    sid = created["sub_id"]
    _fail_target(af)
    sender = ScriptedSender([
        SendOutcome(ok=False, status_code=503, error="HTTP 503"),  # attempt 1
        SendOutcome(ok=True, status_code=200),                    # attempt 2
    ])
    af.alerts._sender = sender
    asyncio.run(af.alerts.dispatch_once())
    assert _valid_hmac("old-secret", sender.calls[0])
    # Rotate between attempts while the delivery is parked on backoff.
    _rotate_secret(af, sid, "new-secret")
    assert af.alerts.get_subscription(sid)["signing_secret"] == "new-secret"
    af.clock.advance(2)
    asyncio.run(af.alerts.dispatch_once())
    assert af.alerts.list_deliveries()["deliveries"][0]["status"] == ST_SUCCEEDED
    # The retry still carries a signature valid under the original key and
    # not under the rotated one.
    assert _valid_hmac("old-secret", sender.calls[1])
    assert not _valid_hmac("new-secret", sender.calls[1])


def test_replay_after_secret_rotation_uses_original_secret(af):
    af.health.upsert_policy("a", policy())
    created, _ = af.alerts.create_subscription(
        sub(signing_secret="old-secret")
    )
    sid = created["sub_id"]
    _fail_target(af)
    sender = ScriptedSender([SendOutcome(ok=True, status_code=200)])
    af.alerts._sender = sender
    asyncio.run(af.alerts.dispatch_once())
    assert _valid_hmac("old-secret", sender.calls[0])
    _rotate_secret(af, sid, "new-secret")
    # Manual replay reuses the frozen delivery row (payload/uid unchanged);
    # the redelivery must still sign with the original secret.
    ev_id = af.alerts.list_events()["events"][0]["id"]
    af.alerts.replay_event(ev_id)
    asyncio.run(af.alerts.dispatch_once())
    assert len(sender.calls) == 2
    assert _valid_hmac("old-secret", sender.calls[1])
    assert not _valid_hmac("new-secret", sender.calls[1])


def test_secret_added_after_generation_does_not_sign_old_delivery(af):
    # A delivery generated while the subscription had no secret was unsigned;
    # adding one later must not retroactively sign that frozen old event.
    af.health.upsert_policy("a", policy())
    created, _ = af.alerts.create_subscription(sub())
    sid = created["sub_id"]
    _fail_target(af)
    _rotate_secret(af, sid, "added-later")
    sender = ScriptedSender([SendOutcome(ok=True, status_code=200)])
    af.alerts._sender = sender
    asyncio.run(af.alerts.dispatch_once())
    assert "X-Georesolve-Signature" not in sender.calls[0]["headers"]


def test_delivery_api_dict_never_carries_the_frozen_secret(af):
    af.health.upsert_policy("a", policy())
    af.alerts.create_subscription(sub(signing_secret="topsecret"))
    _fail_target(af)
    d = af.alerts.list_deliveries()["deliveries"][0]
    assert "signing_secret" not in d
    full = af.alerts.get_delivery(d["id"])
    assert "signing_secret" not in full
    assert full["snapshot"]["has_signing_secret"] is True


def test_legacy_delivery_backfills_secret_from_frozen_revision(af, tmp_path):
    # Simulate a pre-upgrade database: delivery rows exist without a frozen
    # signing_secret column value. The key is recovered from the immutable
    # revision of the sub_version the delivery was generated against, and a
    # later rotation still yields the original key.
    af.health.upsert_policy("a", policy())
    created, _ = af.alerts.create_subscription(
        sub(signing_secret="old-secret")
    )
    sid = created["sub_id"]
    _fail_target(af)
    # Wipe the frozen column as it would be for a legacy row.
    af.db.execute(
        "UPDATE health_alert_deliveries SET signing_secret = NULL"
    )
    af.db.commit()
    _rotate_secret(af, sid, "new-secret")
    sender = ScriptedSender([SendOutcome(ok=True, status_code=200)])
    af.alerts._sender = sender
    asyncio.run(af.alerts.dispatch_once())
    assert _valid_hmac("old-secret", sender.calls[0])
    assert not _valid_hmac("new-secret", sender.calls[0])
    # The resolution was backfilled onto the row.
    stored = af.db.execute(
        "SELECT signing_secret FROM health_alert_deliveries"
    ).fetchone()
    assert stored["signing_secret"] == "old-secret"


def test_failed_delivery_retries_with_exponential_backoff_then_dies(af):
    af.health.upsert_policy("a", policy())
    af.alerts.create_subscription(sub(
        max_retries=2, backoff_base_seconds=1.0, backoff_max_seconds=100.0
    ))
    _fail_target(af)
    af.alerts._sender = ScriptedSender([
        SendOutcome(ok=False, status_code=503, error="HTTP 503"),
        SendOutcome(ok=False, error="boom"),
        SendOutcome(ok=True, status_code=200),
    ])
    # Attempt 1 fails -> next attempt at t + 1s.
    asyncio.run(af.alerts.dispatch_once())
    d = af.alerts.list_deliveries()["deliveries"][0]
    assert d["status"] == ST_FAILED and d["attempts"] == 1
    assert d["next_attempt_at"] == pytest.approx(af.clock.t + 1.0)
    assert d["last_status_code"] == 503
    # Before the backoff deadline nothing is claimed.
    af.clock.advance(0.5)
    assert af.alerts.claim_due() == []
    af.clock.advance(0.6)
    asyncio.run(af.alerts.dispatch_once())  # attempt 2 -> +2s
    d = af.alerts.list_deliveries()["deliveries"][0]
    assert d["attempts"] == 2
    assert d["next_attempt_at"] == pytest.approx(af.clock.t + 2.0)
    af.clock.advance(3)
    asyncio.run(af.alerts.dispatch_once())  # attempt 3 succeeds
    assert af.alerts.list_deliveries()["deliveries"][0]["status"] == ST_SUCCEEDED


def test_dead_after_max_retries(af):
    af.health.upsert_policy("a", policy())
    af.alerts.create_subscription(sub(max_retries=1, backoff_base_seconds=1.0))
    _fail_target(af)
    af.alerts._sender = ScriptedSender([
        SendOutcome(ok=False, error="x"),
        SendOutcome(ok=False, error="x"),
    ])
    asyncio.run(af.alerts.dispatch_once())
    af.clock.advance(2)
    asyncio.run(af.alerts.dispatch_once())
    d = af.alerts.list_deliveries()["deliveries"][0]
    assert d["status"] == ST_DEAD and d["attempts"] == 2
    # A dead delivery stays dead on later ticks...
    af.clock.advance(100)
    assert af.alerts.claim_due() == []
    # ...until an operator replays it.
    af.alerts.replay_event(af.alerts.list_events()["events"][0]["id"])
    assert af.alerts.list_deliveries()["deliveries"][0]["status"] == ST_PENDING


def test_crashed_inflight_delivery_is_reclaimed(af):
    af.health.upsert_policy("a", policy())
    af.alerts.create_subscription(sub())
    _fail_target(af)
    claimed = af.alerts.claim_due(now=af.clock.t)
    assert len(claimed) == 1 and claimed[0]["status"] == ST_SENDING
    # Simulate a crash: no result recorded. Nothing claimed before deadline.
    assert af.alerts.claim_due(now=af.clock.t + 10) == []
    reclaimed = af.alerts.claim_due(now=af.clock.t + 31)
    assert len(reclaimed) == 1


def test_pending_deliveries_survive_restart(tmp_path):
    path = str(tmp_path / "restart.db")
    clock = FakeClock()
    db = connect(path)
    audit = AuditLog(db, clock)
    config = ConfigManager(db, audit, clock)
    health = HealthCheckStore(db, config, audit, clock)
    alerts = AlertStore(db, config, audit, clock)
    health.set_history_commit_listener(alerts.ingest_new)
    config.apply(bundle(1, [rule("api", targets=[target("a")])]))
    health.upsert_policy("a", policy())
    alerts.create_subscription(sub(max_retries=7))
    import app.health_checks as mod
    set_probe(False)
    asyncio.run(health.check_target("a"))

    db2 = connect(path)
    audit2 = AuditLog(db2, clock)
    config2 = ConfigManager(db2, audit2, clock)
    config2.load_persisted()
    alerts2 = AlertStore(db2, config2, audit2, clock)
    alerts2.ingest_new()  # post-restart catch-up must not duplicate
    deliveries = alerts2.list_deliveries()["deliveries"]
    assert len(deliveries) == 1 and deliveries[0]["status"] == ST_PENDING
    assert alerts2.list_events()["count"] == 1
    assert deliveries[0]["snapshot"]["max_retries"] == 7


# -- drill isolation ----------------------------------------------------------


def test_drill_simulated_failures_never_raise_live_events(af):
    # The alert path only reads health_check_history; a drill's private
    # simulation registry is unrelated to the live store and never writes
    # history, so it can never raise a production alert.
    from app.health import HealthRegistry

    af.health.upsert_policy("a", policy())
    af.alerts.create_subscription(sub())
    sim = HealthRegistry(af.clock)
    sim.set("a", False)
    assert sim.is_healthy("a") is False
    af.alerts.ingest_new()
    assert af.alerts.list_events()["count"] == 0
    # Only a genuine live transition raises the event.
    _fail_target(af)
    assert af.alerts.list_events()["count"] == 1


# -- replay edge cases --------------------------------------------------------


def test_replay_of_unconfirmed_event_conflicts(af):
    af.health.upsert_policy("a", policy())
    af.alerts.create_subscription(sub(consecutive_threshold=3))
    _fail_target(af)
    ev_id = af.alerts.list_events()["events"][0]["id"]
    with pytest.raises(AlertConflict):
        af.alerts.replay_event(ev_id)


def test_event_and_delivery_lookup_404(af):
    with pytest.raises(AlertNotFound):
        af.alerts.get_event(123_456)
    with pytest.raises(AlertNotFound):
        af.alerts.get_delivery(123_456)
    with pytest.raises(AlertNotFound):
        af.alerts.get_subscription("nope")
