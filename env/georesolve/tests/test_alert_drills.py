"""Unit tests for isolated alert-policy drills."""
from __future__ import annotations

import asyncio
import threading

import pytest

from app.alert_drills import (
    AlertDrillConflict,
    AlertDrillCreateIn,
    AlertDrillAdvanceIn,
    AlertDrillNotFound,
    AlertDrillStore,
    AlertDrillValidation,
    SendRuleIn,
    ST_DEAD,
    ST_FAILED,
    ST_SUCCEEDED,
    ST_SUPERSEDED,
    ST_UNCONFIRMED,
)
from app.health_alerts import (
    AlertStore,
    SendOutcome,
    SilenceWindowSpec,
    SubscriptionUpsertIn,
)
from app.health_checks import (
    HealthCheckStore,
    MaintenanceWindowSpec,
    OverrideIn,
    PolicyUpsertIn,
)
from app.storage import connect
from app.audit import AuditLog
from app.config_store import ConfigManager
from tests.conftest import FakeClock, bundle, rule, target


def _ok_sender(**kwargs):
    # Offline stand-in: the live pipeline "succeeds" without network I/O.
    return SendOutcome(ok=True, status_code=200)


class AlertDrillFixture:
    def __init__(self, tmp_path, *, sender=None, clock=None):
        self.clock = clock or FakeClock(1000.0)
        db = connect(str(tmp_path / "alert_drills.db"))
        self.db = db
        self.audit = AuditLog(db, self.clock)
        self.config = ConfigManager(db, self.audit, self.clock)
        self.health = HealthCheckStore(db, self.config, self.audit, self.clock)
        self.alerts = AlertStore(
            db, self.config, self.audit, self.clock,
            sender=sender or _ok_sender,
        )
        self.health.set_history_commit_listener(self.alerts.ingest_new)
        self.drills = AlertDrillStore(db, self.clock)
        self.config.apply(
            bundle(
                1,
                [
                    rule("api", targets=[
                        target("a", address="tcp://10.0.0.1:80"),
                        target("b", address="tcp://10.0.0.2:80"),
                    ])
                ],
            )
        )

    def policy(self, **over):
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

    def sub(self, target_id="a", **over):
        base = dict(target_id=target_id, webhook_url="http://hooks.example/x")
        base.update(over)
        return SubscriptionUpsertIn(**base)

    def probe(self, ok: bool):
        import app.health_checks as mod

        async def fake(method, address, timeout):
            return {
                "type": "tcp", "ok": ok,
                "reason": None if ok else "connection_error",
                "status": None, "duration_ms": 0.1, "detail": "",
            }
        # Auto-undone by pytest at test teardown so the fake never leaks into
        # other test modules sharing the process.
        self.monkeypatch.setattr(mod, "run_probe", fake)

    def fail(self, tid="a"):
        self.probe(False)
        asyncio.run(self.health.check_target(tid))

    def recover(self, tid="a"):
        self.probe(True)
        asyncio.run(self.health.check_target(tid))

    def pump_live(self):
        """Drive the real (offline) outbox once: ingest, release, send."""
        asyncio.run(self.alerts.dispatch_once())


@pytest.fixture
def ad(tmp_path, monkeypatch):
    fixture = AlertDrillFixture(tmp_path)
    fixture.monkeypatch = monkeypatch
    return fixture


def _create(ad, sub_over=None, drill_over=None):
    ad.health.upsert_policy("a", ad.policy())
    s, _ = ad.alerts.create_subscription(ad.sub(**(sub_over or {})))
    spec = AlertDrillCreateIn(subscription_id=s["sub_id"], **(drill_over or {}))
    return ad.drills.create(spec), s


def _advance_all(ads, did, total, *, settle=True):
    last = None
    for i in range(total):
        # Only the final advance asks for settlement/completion.
        last_step_settle = settle and i == total - 1
        _code, last = ads.advance(
            did, AlertDrillAdvanceIn(settle=last_step_settle)
        )
    return last


def _drain(ads, did, *, settle=True):
    """Advance until the frozen cursor is fully consumed."""
    last = None
    guard = 0
    while True:
        got = ads.get(did)
        if got["cursor"] >= got["total_rows"]:
            break
        last_step_settle = settle and (
            got["cursor"] + 1 >= got["total_rows"]
        )
        _code, last = ads.advance(
            did, AlertDrillAdvanceIn(settle=last_step_settle)
        )
        guard += 1
        if guard > 10000:
            raise RuntimeError("drain loop did not terminate")
    return last


# -- creation / snapshot -------------------------------------------------------


def test_create_freezes_subscription_and_history(ad):
    ad.health.upsert_policy("a", ad.policy())
    s, _ = ad.alerts.create_subscription(ad.sub(signing_secret="shh"))
    ad.fail()
    drill = ad.drills.create(AlertDrillCreateIn(subscription_id=s["sub_id"]))
    assert drill["status"] == "ready"
    assert drill["total_rows"] >= 2  # at least a check and a transition
    frozen = drill["frozen_input"]
    assert frozen["subscription"]["sub_id"] == s["sub_id"]
    assert frozen["subscription"]["has_signing_secret"] is True
    # The public view must never carry the secret itself.
    assert "signing_secret" not in frozen["subscription"]
    assert frozen["history_row_ids"]


def test_create_unknown_subscription_is_404(ad):
    with pytest.raises(AlertDrillNotFound):
        ad.drills.create(AlertDrillCreateIn(subscription_id="nope"))


def test_create_without_history_conflicts(ad):
    ad.health.upsert_policy("a", ad.policy())
    s, _ = ad.alerts.create_subscription(ad.sub())
    with pytest.raises(AlertDrillConflict) as ei:
        ad.drills.create(AlertDrillCreateIn(subscription_id=s["sub_id"]))
    assert ei.value.code == "no_history_rows_selected"


def test_create_freezes_a_specific_old_revision(ad):
    ad.health.upsert_policy("a", ad.policy())
    s, _ = ad.alerts.create_subscription(
        ad.sub(webhook_url="http://hooks.example/v1")
    )
    ad.fail()
    ad.alerts.update_subscription(
        s["sub_id"],
        ad.sub(webhook_url="http://hooks.example/v2", expected_version=1),
    )
    drill = ad.drills.create(
        AlertDrillCreateIn(subscription_id=s["sub_id"], sub_version=1)
    )
    assert drill["frozen_input"]["subscription"]["webhook_url"] == (
        "http://hooks.example/v1"
    )
    with pytest.raises(AlertDrillNotFound):
        ad.drills.create(
            AlertDrillCreateIn(subscription_id=s["sub_id"], sub_version=99)
        )


def test_invalid_time_range_and_anchor_rejected(ad):
    ad.health.upsert_policy("a", ad.policy())
    s, _ = ad.alerts.create_subscription(ad.sub())
    # The cross-field check is enforced by the store (model fields alone are
    # finite floats).
    with pytest.raises(AlertDrillValidation):
        ad.drills.create(
            AlertDrillCreateIn(
                subscription_id=s["sub_id"], since=2000.0, until=1000.0
            )
        )
    ad.fail()
    with pytest.raises(AlertDrillValidation):
        ad.drills.create(
            AlertDrillCreateIn(
                subscription_id=s["sub_id"], start_at=10**12
            )
        )


# -- basic replay / isolation --------------------------------------------------


def test_replay_records_event_delivery_and_inbox(ad):
    drill, _rows = _setup_fail_drill(ad)
    # The frozen slice includes the check, the unhealthy transition and may
    # exclude unrelated transitions (e.g. the 'policy_created' row is not an
    # alert event), but it must contain both the check and the transition.
    assert drill["total_rows"] >= 2
    last = _drain(ad.drills, "dd")
    assert last["status"] == "completed"
    assert last["stats"]["succeeded"] == 1
    assert last["stats"]["inbox_messages"] == 1
    inbox = ad.drills.inbox("dd")
    msg = inbox["messages"][0]
    assert msg["url"] == "http://hooks.example/x"
    assert msg["headers"]["X-Georesolve-Drill"] == "dd"
    assert msg["headers"]["Idempotency-Key"] == msg["headers"][
        "X-Georesolve-Delivery-Uid"
    ]
    assert msg["body"]["type"] == "unhealthy"


def _setup_fail_drill(
    ad,
    *,
    sub_over=None,
    send_script=None,
    default_outcome="ok",
    drill_id="dd",
):
    ad.health.upsert_policy("a", ad.policy())
    s, _ = ad.alerts.create_subscription(ad.sub(**(sub_over or {})))
    ad.fail()
    # Drive the real outbox so production ends in the same terminal state the
    # successful drill does (makes the report diff an apples-to-apples check).
    ad.pump_live()
    rows = ad.db.execute(
        "SELECT COUNT(*) c FROM health_check_history"
    ).fetchone()["c"]
    drill = ad.drills.create(
        AlertDrillCreateIn(
            subscription_id=s["sub_id"],
            drill_id=drill_id,
            send_script=send_script or [],
            default_outcome=default_outcome,
        )
    )
    return drill, rows


def test_drill_never_writes_live_tables_or_runs_network(ad):
    sent = []

    def live_sender(**kwargs):  # pragma: no cover - must never be called
        sent.append(kwargs)
        raise AssertionError("live sender invoked by a drill")

    # Build the live history/subscription normally (the live outbox is not
    # pumped here), then arm a failing sender before driving the drill.
    ad.health.upsert_policy("a", ad.policy())
    s, _ = ad.alerts.create_subscription(ad.sub())
    ad.fail()
    ad.alerts._sender = live_sender
    rows = ad.db.execute(
        "SELECT COUNT(*) c FROM health_check_history"
    ).fetchone()["c"]
    ad.drills.create(AlertDrillCreateIn(subscription_id=s["sub_id"], drill_id="dd"))
    before_events = ad.db.execute(
        "SELECT COUNT(*) c FROM health_alert_events"
    ).fetchone()["c"]
    before_deliv = ad.db.execute(
        "SELECT COUNT(*) c FROM health_alert_deliveries"
    ).fetchone()["c"]
    before_hist = rows
    _drain(ad.drills, "dd")
    assert sent == []
    assert ad.db.execute(
        "SELECT COUNT(*) c FROM health_alert_events"
    ).fetchone()["c"] == before_events
    assert ad.db.execute(
        "SELECT COUNT(*) c FROM health_alert_deliveries"
    ).fetchone()["c"] == before_deliv
    assert ad.db.execute(
        "SELECT COUNT(*) c FROM health_check_history"
    ).fetchone()["c"] == before_hist
    # Simulated inbox is the only place webhooks landed.
    assert ad.drills.inbox("dd")["count"] == 1
    # The real audit log has no drill entries.
    assert ad.db.execute(
        "SELECT COUNT(*) c FROM audit WHERE type LIKE '%drill%'"
    ).fetchone()["c"] == 0


# -- consecutive threshold -----------------------------------------------------


def test_consecutive_threshold_confirms_across_check_rows(ad):
    # Policy flips unhealthy at the 2nd failure; subscription needs 3
    # consecutive failures, so the event is seeded unconfirmed (2/3) and only
    # the next failure check activates it.
    ad.health.upsert_policy(
        "a", ad.policy(fail_threshold=2, recover_threshold=1)
    )
    s, _ = ad.alerts.create_subscription(ad.sub(consecutive_threshold=3))
    ad.fail()  # failure check (1), no transition
    ad.fail()  # failure check (2) -> unhealthy transition, seeded 2/3
    ad.fail()  # failure check (3) -> confirms the unconfirmed delivery
    rows = ad.db.execute(
        "SELECT COUNT(*) c FROM health_check_history"
    ).fetchone()["c"]
    ad.drills.create(
        AlertDrillCreateIn(subscription_id=s["sub_id"], drill_id="th")
    )
    # Replay until the slice is consumed; watch the streak grow then activate.
    statuses: list[str] = []
    while True:
        got = ad.drills.get("th")
        if got["cursor"] >= got["total_rows"]:
            break
        ad.drills.advance("th", AlertDrillAdvanceIn())
        deliveries = ad.drills.get("th")["deliveries"]
        if deliveries:
            statuses.append(deliveries[0]["status"])
    assert ST_UNCONFIRMED in statuses
    assert statuses[-1] == ST_SUCCEEDED  # confirmed + delivered to inbox
    assert ad.drills.inbox("th")["count"] == 1
    ev = ad.drills.get("th")["events"][0]
    assert ev["event_type"] == "unhealthy" and ev["confirm_count"] == 3
    assert ev["activated_at"] is not None


def test_threshold_streak_superseded_by_opposite_check(ad):
    # Policy flips at 1 failure; subscription requires 3 consecutive failures,
    # so the unhealthy event is seeded unconfirmed (1/3) and a quick recovery
    # check supersedes it before confirmation.
    ad.health.upsert_policy(
        "a", ad.policy(fail_threshold=1, recover_threshold=1)
    )
    s, _ = ad.alerts.create_subscription(ad.sub(consecutive_threshold=3))
    ad.fail()    # transition unhealthy, seeded 1/3
    ad.recover()  # opposite verdict breaks the streak + recovery transition
    rows = ad.db.execute(
        "SELECT COUNT(*) c FROM health_check_history"
    ).fetchone()["c"]
    ad.drills.create(
        AlertDrillCreateIn(subscription_id=s["sub_id"], drill_id="sup")
    )
    _drain(ad.drills, "sup")
    deliveries = ad.drills.get("sup")["deliveries"]
    # The unhealthy delivery (threshold 3) is superseded; the recovered
    # transition is only seeded 1/3 by the single success check, so it stays
    # unconfirmed and neither event reaches the inbox.
    by_event = {}
    for d in deliveries:
        import json as _json
        payload = ad.db.execute(
            "SELECT event_payload FROM alert_drill_deliveries WHERE id=?",
            (d["id"],),
        ).fetchone()
        by_event[_json.loads(payload["event_payload"])["type"]] = d
    assert by_event["unhealthy"]["status"] == ST_SUPERSEDED
    assert by_event["recovered"]["status"] == ST_UNCONFIRMED
    assert ad.drills.inbox("sup")["count"] == 0


# -- suppression / retries ------------------------------------------------------


def test_clock_only_advance_cannot_consume_rows(ad):
    drill, _ = _setup_fail_drill(
        ad,
        sub_over={
            "silence_windows": [SilenceWindowSpec(start=1000.0, end=1010.0)]
        },
    )
    # to_time is clock-only: combining it with steps > 1 is a client error.
    with pytest.raises(AlertDrillValidation):
        ad.drills.advance(
            "dd", AlertDrillAdvanceIn(to_time=1005.0, steps=2)
        )


def test_silence_window_suppresses_then_clock_releases(ad):
    drill, rows = _setup_fail_drill(
        ad,
        sub_over={
            "silence_windows": [SilenceWindowSpec(start=1000.0, end=1010.0)]
        },
    )
    code, p = ad.drills.advance("dd", AlertDrillAdvanceIn(steps=100))
    # Everything consumed, but the delivery is parked inside the window.
    assert p["cursor"] == p["total_rows"]
    assert p["stats"]["suppressed_now"] == 1
    assert ad.drills.inbox("dd")["count"] == 0
    # A clock-only advance to the window end releases and sends.
    code, p = ad.drills.advance(
        "dd", AlertDrillAdvanceIn(to_time=1010.0)
    )
    assert p["stats"]["suppressed_now"] == 0
    assert p["stats"]["succeeded"] == 1
    assert ad.drills.inbox("dd")["count"] == 1


def test_clock_only_advance_refuses_to_go_backwards(ad):
    drill, rows = _setup_fail_drill(
        ad,
        sub_over={
            "silence_windows": [SilenceWindowSpec(start=1000.0, end=1010.0)]
        },
    )
    ad.drills.advance("dd", AlertDrillAdvanceIn(steps=100))
    with pytest.raises(AlertDrillConflict):
        ad.drills.advance("dd", AlertDrillAdvanceIn(to_time=999.0))


def test_failed_send_retries_with_backoff_then_succeeds(ad):
    drill, rows = _setup_fail_drill(
        ad,
        sub_over={
            "max_retries": 3,
            "backoff_base_seconds": 1.0,
            "backoff_max_seconds": 100.0,
        },
        send_script=[SendRuleIn(result="fail", status_code=503, attempt=1)],
        default_outcome="ok",
    )
    code, p = ad.drills.advance("dd", AlertDrillAdvanceIn(steps=100))
    delivery = ad.drills.get("dd")["deliveries"][0]
    assert delivery["status"] == ST_FAILED
    assert delivery["attempts"] == 1
    assert delivery["next_attempt_at"] == pytest.approx(1001.0)
    # Not due yet.
    code, p = ad.drills.advance("dd", AlertDrillAdvanceIn(to_time=1000.5))
    assert ad.drills.get("dd")["deliveries"][0]["status"] == ST_FAILED
    # At the backoff deadline the retry succeeds.
    code, p = ad.drills.advance("dd", AlertDrillAdvanceIn(to_time=1001.0))
    delivery = ad.drills.get("dd")["deliveries"][0]
    assert delivery["status"] == ST_SUCCEEDED
    assert delivery["attempts"] == 2
    inbox = ad.drills.inbox("dd")
    assert [m["attempt"] for m in inbox["messages"]] == [1, 2]


def test_dead_after_max_retries(ad):
    drill, rows = _setup_fail_drill(
        ad,
        sub_over={"max_retries": 1, "backoff_base_seconds": 1.0},
        default_outcome="fail",
    )
    ad.drills.advance("dd", AlertDrillAdvanceIn(steps=100, settle=True))
    delivery = ad.drills.get("dd")["deliveries"][0]
    assert delivery["status"] == ST_DEAD
    assert delivery["attempts"] == 2  # initial + 1 retry
    # settle left the clock far enough ahead; future clock advances cannot
    # resurrect a dead delivery.
    before = ad.drills.inbox("dd")["count"]
    ad.drills.advance("dd", AlertDrillAdvanceIn(to_time=10**9))
    assert ad.drills.inbox("dd")["count"] == before


def test_settle_pumps_through_all_retries(ad):
    drill, rows = _setup_fail_drill(
        ad,
        sub_over={
            "max_retries": 5,
            "backoff_base_seconds": 1.0,
            "backoff_max_seconds": 4.0,
        },
        default_outcome="fail",
    )
    code, p = ad.drills.advance(
        "dd", AlertDrillAdvanceIn(steps=100, settle=True)
    )
    assert p["stats"]["dead"] == 1
    # 1 initial + 5 retries = 6 inbox messages.
    assert ad.drills.inbox("dd")["count"] == 6


def test_webhook_signature_uses_frozen_secret(ad):
    import hashlib
    import hmac as _hmac

    ad.health.upsert_policy("a", ad.policy())
    s, _ = ad.alerts.create_subscription(
        ad.sub(signing_secret="old-secret")
    )
    ad.fail()
    rows = ad.db.execute(
        "SELECT COUNT(*) c FROM health_check_history"
    ).fetchone()["c"]
    ad.drills.create(
        AlertDrillCreateIn(subscription_id=s["sub_id"], drill_id="sig")
    )
    _drain(ad.drills, "sig")
    msg = ad.drills.inbox("sig")["messages"][0]
    body = msg["body"]
    raw = (
        __import__("json").dumps(body, sort_keys=True).encode()
    )
    expected = "sha256=" + _hmac.new(
        b"old-secret", raw, hashlib.sha256
    ).hexdigest()
    assert msg["headers"]["X-Georesolve-Signature"] == expected


# -- lifecycle ------------------------------------------------------------------


def test_pause_blocks_advance_resume_continues(ad):
    drill, rows = _setup_fail_drill(ad)
    ad.drills.advance("dd", AlertDrillAdvanceIn())
    code, p = ad.drills.pause("dd")
    assert p["status"] == "paused"
    with pytest.raises(AlertDrillConflict) as ei:
        ad.drills.advance("dd", AlertDrillAdvanceIn())
    assert ei.value.code == "status_conflict"
    code, p = ad.drills.resume("dd")
    assert p["status"] == "running"


def test_expected_version_conflict_is_409(ad):
    drill, rows = _setup_fail_drill(ad)
    with pytest.raises(AlertDrillConflict) as ei:
        ad.drills.advance("dd", AlertDrillAdvanceIn(expected_version=99))
    assert ei.value.code == "expected_version"
    with pytest.raises(AlertDrillConflict) as ei:
        ad.drills.pause("dd", expected_version=99)
    assert ei.value.code == "expected_version"


def test_idempotent_advance_replays_same_step(ad):
    drill, rows = _setup_fail_drill(ad)
    fp = "fixed-fingerprint"
    code, p1 = ad.drills.advance(
        "dd", AlertDrillAdvanceIn(), idem_key="k1", fingerprint=fp
    )
    seq = p1["step"]["seq"]
    code, p2 = ad.drills.advance(
        "dd", AlertDrillAdvanceIn(), idem_key="k1", fingerprint=fp
    )
    assert p2["idempotent_replay"] is True
    assert p2["step"]["seq"] == seq
    # Same key, different fingerprint conflicts.
    with pytest.raises(AlertDrillConflict) as ei:
        ad.drills.advance(
            "dd", AlertDrillAdvanceIn(steps=2),
            idem_key="k1", fingerprint="other",
        )
    assert ei.value.code == "idempotency_conflict"


def test_concurrent_advances_are_serialized(ad):
    drill, rows = _setup_fail_drill(ad)
    errors = []
    results = []

    def worker():
        try:
            for _ in range(rows):
                code, p = ad.drills.advance("dd", AlertDrillAdvanceIn())
                results.append(p["step"]["seq"])
        except AlertDrillConflict as exc:
            errors.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Exactly one thread consumed each seq; losers got status/version
    # conflicts (all attempted at version 1) rather than double-applying.
    winning = [s for s in results]
    assert sorted(winning) == list(range(1, len(winning) + 1))
    assert len(winning) <= rows
    stored = ad.db.execute(
        "SELECT COUNT(*) c FROM alert_drill_steps"
        " WHERE drill_id='dd' AND run_epoch=1"
    ).fetchone()["c"]
    assert stored == len(winning)


def test_reset_starts_new_epoch_and_invalidates_keys(ad):
    drill, rows = _setup_fail_drill(ad)
    fingerprint = "fp"
    _drain(ad.drills, "dd", settle=False)
    assert ad.drills.inbox("dd")["count"] >= 1
    code, p = ad.drills.reset(
        "dd", idem_key="reset-k", fingerprint=fingerprint
    )
    assert p["run_epoch"] == 2 and p["status"] == "ready"
    assert p["cursor"] == 0 and p["sim_clock"] == 1000.0
    # Current run has no steps / inbox.
    assert ad.drills.get("dd")["inbox_count"] == 0
    with pytest.raises(AlertDrillNotFound):
        ad.drills.get_step("dd", 1)
    # Old idempotency key cannot replay the prior epoch's response.
    code, p = ad.drills.advance(
        "dd", AlertDrillAdvanceIn(), idem_key="k", fingerprint=fingerprint
    )
    assert "idempotent_replay" not in p
    # Prior-epoch rows remain in the tables for the audit trail (a reset
    # starts a fresh epoch rather than deleting history).
    assert ad.db.execute(
        "SELECT run_epoch, COUNT(*) FROM alert_drill_inbox"
        " WHERE drill_id='dd' GROUP BY run_epoch"
    ).fetchall()
    assert ad.db.execute(
        "SELECT COUNT(*) c FROM alert_drill_inbox"
        " WHERE drill_id='dd' AND run_epoch=2"
    ).fetchone()["c"] == 0
    assert ad.db.execute(
        "SELECT COUNT(*) c FROM alert_drill_audit"
        " WHERE drill_id='dd' AND action='alert_drill_reset'"
    ).fetchone()["c"] == 1


def test_progress_survives_restart(ad):
    drill, _ = _setup_fail_drill(ad)
    total = drill["total_rows"]
    # Advance exactly one frozen row, leaving progress mid-run.
    code, first = ad.drills.advance("dd", AlertDrillAdvanceIn())
    assert first["cursor"] == 1

    # A brand-new store over the same database is a process restart.
    restarted = AlertDrillStore(ad.db, FakeClock(5001.0))
    got = restarted.get("dd")
    assert got["cursor"] == 1 and got["status"] == "running"
    step = restarted.get_step("dd", 1)
    assert step["seq"] == 1
    # Continue to completion.
    last = _drain(restarted, "dd")
    assert last["status"] == "completed"
    rep = restarted.report("dd")
    assert rep["report"]["progress"]["cursor"] == total
    # The inbox survives too and is still queryable.
    assert restarted.inbox("dd")["count"] >= 1


# -- report / diff ---------------------------------------------------------------


def test_report_is_frozen_and_captures_input_decisions_and_diff(ad):
    drill, rows = _setup_fail_drill(ad)
    _drain(ad.drills, "dd")
    r1 = ad.drills.report("dd")
    r2 = ad.drills.report("dd")
    assert r2["idempotent_replay"] is True
    assert r1["checksum"] == r2["checksum"]
    report = r1["report"]
    assert report["frozen_input"]["subscription"]["webhook_url"] == (
        "http://hooks.example/x"
    )
    assert report["statistics"]["succeeded"] == 1
    assert report["decisions"], "per-step suppression/retry decisions kept"
    sends = [s for d in report["decisions"] for s in d.get("sends", [])]
    assert sends and sends[0]["outcome"]["ok"] is True
    diff = report["production_diff"]
    # Live pipeline saw the same unhealthy transition and delivered it.
    assert diff["counts"]["compared"] == 1
    item = diff["deliveries"][0]
    assert item["difference"] == "same"
    assert item["simulated"]["status"] == item["production"]["status"]


def test_report_flags_sim_only_event_when_live_had_no_subscription(ad):
    # Live failure happens with NO matching subscription, so production never
    # creates an event/delivery. A subscription created afterwards still sees
    # the past rows in a drill (drills select history directly), so the diff
    # must report a simulated-only delivery.
    ad.health.upsert_policy("a", ad.policy())
    ad.fail()
    sub, _ = ad.alerts.create_subscription(ad.sub(sources=["check"]))
    rows = ad.db.execute(
        "SELECT COUNT(*) c FROM health_check_history"
    ).fetchone()["c"]
    # Production ingestor seeded its cursor before the sub existed: no event.
    assert ad.alerts.list_events()["count"] == 0
    ad.drills.create(
        AlertDrillCreateIn(subscription_id=sub["sub_id"], drill_id="so")
    )
    _drain(ad.drills, "so")
    diff = ad.drills.report("so")["report"]["production_diff"]
    assert diff["counts"]["no_production_event"] >= 1
    assert any(
        i["difference"] == "no_production_event" for i in diff["deliveries"]
    )


# -- maintenance / override events ----------------------------------------------


def test_maintenance_events_fire_immediately(ad):
    ad.health.upsert_policy(
        "a",
        ad.policy(maintenance_windows=[
            MaintenanceWindowSpec(start=1000.0, end=1100.0)
        ]),
    )
    s, _ = ad.alerts.create_subscription(ad.sub())
    ad.health.is_healthy("a")  # triggers maintenance_begin at 1000
    rows = ad.db.execute(
        "SELECT COUNT(*) c FROM health_check_history"
    ).fetchone()["c"]
    drill = ad.drills.create(
        AlertDrillCreateIn(subscription_id=s["sub_id"], drill_id="mnt")
    )
    _drain(ad.drills, "mnt")
    types = {e["event_type"] for e in ad.drills.get("mnt")["events"]}
    assert "maintenance_begin" in types
    # Maintenance events ignore consecutive thresholds and deliver at once.
    assert ad.drills.inbox("mnt")["count"] >= 1


def test_override_expiry_event_replays(ad):
    ad.health.upsert_policy("a", ad.policy())
    s, _ = ad.alerts.create_subscription(ad.sub(sources=["manual_override"]))
    ad.health.override(
        "a", OverrideIn(healthy=False, expires_at=ad.clock.t + 10)
    )
    ad.clock.advance(11)
    ad.health.get_state("a")  # lazy expiry -> override_expired transition
    rows = ad.db.execute(
        "SELECT COUNT(*) c FROM health_check_history"
    ).fetchone()["c"]
    drill = ad.drills.create(
        AlertDrillCreateIn(subscription_id=s["sub_id"], drill_id="ovr")
    )
    _drain(ad.drills, "ovr")
    types = {e["event_type"] for e in ad.drills.get("ovr")["events"]}
    assert types == {"override_expired"}


# -- audit / validation ----------------------------------------------------------


def test_lifecycle_and_refusals_go_to_drill_only_audit(ad):
    drill, rows = _setup_fail_drill(ad)
    with pytest.raises(AlertDrillConflict):
        ad.drills.advance("dd", AlertDrillAdvanceIn(expected_version=42))
    records = ad.drills.drill_audit("dd")
    actions = {r["action"] for r in records}
    assert "alert_drill_created" in actions
    assert "alert_drill_advance_rejected" in actions


def test_inbox_status_filter(ad):
    drill, rows = _setup_fail_drill(
        ad, sub_over={"max_retries": 0}, default_outcome="fail"
    )
    ad.drills.advance("dd", AlertDrillAdvanceIn(steps=100, settle=True))
    # Even a dead delivery produced an inbox row; filter by its final status.
    dead = ad.drills.inbox("dd", status=ST_DEAD)
    assert dead["count"] == 1
    assert ad.drills.inbox("dd", status=ST_SUCCEEDED)["count"] == 0
