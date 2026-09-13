"""Store-level tests for isolated fault drills and resolution replay."""
from __future__ import annotations

import threading

import pytest

from app.audit import AuditLog
from app.config_store import ConfigManager
from app.drills import (
    CODE_ILLEGAL_HEALTH,
    CODE_STEP_GAP,
    CODE_STATUS_CONFLICT,
    CODE_TARGET_NOT_FROZEN,
    CODE_UNKNOWN_VERSION,
    CODE_VERSION_CONFLICT,
    DrillConflict,
    DrillCreateIn,
    DrillNotFound,
    DrillStepIn,
    DrillStore,
    AdvanceIn,
)
from app.health import HealthRegistry
from app.models import ConfigBundle, Defaults, ReleaseGroup, Rule, Target
from app.storage import connect


BUNDLE = ConfigBundle(
    version=1,
    defaults=Defaults(negative_ttl=5),
    rules=[
        Rule(
            name="api",
            scope="global",
            ttl=60,
            targets=[
                Target(id="a", address="tcp://10.0.0.1:80", weight=3),
                Target(id="b", address="tcp://10.0.0.2:80", weight=1),
            ],
        )
    ],
)


@pytest.fixture
def store(tmp_path):
    db = connect(str(tmp_path / "drills.db"))
    audit = AuditLog(db)
    cfg = ConfigManager(db, audit)
    health = HealthRegistry()
    cfg.apply(BUNDLE)
    return DrillStore(db, cfg, health), cfg, health, audit


def make_step(**kw):
    kw.setdefault("name", "api")
    kw.setdefault("client", "c1")
    return DrillStepIn(**kw)


def create(store_, steps, version=1, **kw):
    return store_.create(DrillCreateIn(config_version=version, steps=steps, **kw))


def advance(store_, did, **kw):
    return store_.advance(did, AdvanceIn(**kw))[1]


# -- creation and freezing ---------------------------------------------------


def test_create_freezes_manifest_and_rules(store):
    s, cfg, health, _audit = store
    drill = create(s, [make_step()])
    assert drill["status"] == "ready"
    assert set(drill["frozen"]["target_manifest"]) == {"a", "b"}
    summary = drill["frozen"]["rule_summary"][0]
    assert summary["name"] == "api" and summary["target_ids"] == ["a", "b"]
    assert drill["current_seq"] == 0


def test_create_rejects_missing_config_version_and_audits(store):
    s, cfg, health, _audit = store
    with pytest.raises(DrillNotFound) as exc:
        create(s, [make_step()], version=99)
    assert exc.value.code == CODE_UNKNOWN_VERSION
    records = s.drill_audit(action="drill_create_rejected")
    assert records and records[0]["details"]["code"] == CODE_UNKNOWN_VERSION


def test_create_rejects_target_not_in_manifest(store):
    s, *_ = store
    with pytest.raises(DrillConflict) as exc:
        create(s, [make_step(health_changes={"ghost": True})])
    assert exc.value.code == CODE_TARGET_NOT_FROZEN
    assert s.drill_audit(action="drill_create_rejected")


def test_create_rejects_illegal_health_value_and_audits(store):
    s, *_ = store
    with pytest.raises(DrillConflict) as exc:
        create(s, [make_step(health_changes={"a": "yes"})])
    assert exc.value.code == CODE_ILLEGAL_HEALTH
    rec = s.drill_audit(action="drill_create_rejected")[0]
    assert rec["details"]["code"] == CODE_ILLEGAL_HEALTH


def test_create_requires_steps(store):
    s, *_ = store
    # min_length on the request model rejects an empty sequence at the edge.
    with pytest.raises(Exception):
        DrillCreateIn(config_version=1, steps=[])


def test_initial_health_must_be_frozen(store):
    s, *_ = store
    with pytest.raises(DrillConflict) as exc:
        create(s, [make_step()], initial_health={"ghost": False})
    assert exc.value.code == CODE_TARGET_NOT_FROZEN


# -- step progression --------------------------------------------------------


def test_advance_replays_resolution_and_records_step(store):
    s, *_ = store
    did = create(s, [make_step(expected={"chosen": "a"}), make_step()])["id"]
    out = advance(s, did)
    step = out["step"]
    assert out["status"] == "running"
    assert step["answer"]["chosen"] == "a"
    assert step["order"] == ["a", "b"]
    assert step["cache_hit"] is False
    assert step["matched_expected"] is True
    assert step["started_at"] > 0
    assert step["input"]["health_before"] == {"a": True, "b": True}
    assert step["health_after"] == {"a": True, "b": True}


def test_simulated_failover_walks_the_deterministic_order(store):
    s, *_ = store
    did = create(
        s,
        [
            make_step(),
            make_step(health_changes={"a": False}, expected={"chosen": "b"}),
        ],
    )["id"]
    advance(s, did)
    out = advance(s, did)
    step = out["step"]
    assert step["answer"]["chosen"] == "b"
    assert step["health_after"] == {"a": False, "b": True}
    # Health changed during this request, so the cached answer was re-computed.
    assert step["cache_hit"] is False
    assert step["matched_expected"] is True
    assert out["status"] == "completed"


def test_third_identical_request_is_a_simulated_cache_hit(store):
    s, *_ = store
    did = create(s, [make_step(), make_step(), make_step(advance_seconds=1)])["id"]
    advance(s, did)
    advance(s, did)
    out = advance(s, did)
    assert out["step"]["cache_hit"] is True
    assert out["status"] == "completed"


def test_simulated_cache_expiry_is_driven_by_simulated_time(store):
    s, *_ = store
    # ttl=60; jumping past it forces a re-computation (cache miss).
    did = create(
        s, [make_step(), make_step(advance_seconds=61, expected={"chosen": "a"})]
    )["id"]
    advance(s, did)
    out = advance(s, did)
    assert out["step"]["cache_hit"] is False
    assert out["step"]["matched_expected"] is True


def test_expected_mismatch_is_recorded_with_diff_reason(store):
    s, *_ = store
    did = create(s, [make_step(expected={"chosen": "b"})])["id"]
    out = advance(s, did)
    assert out["matched_expected"] is False
    diffs = out["step"]["diffs"]
    assert [d["field"] for d in diffs] == ["chosen"]
    assert diffs[0] == {"field": "chosen", "expected": "b", "actual": "a"}


def test_advance_rejects_step_gap_and_audits(store):
    s, *_ = store
    did = create(s, [make_step(), make_step()])["id"]
    with pytest.raises(DrillConflict) as exc:
        advance(s, did, seq=2)
    assert exc.value.code == CODE_STEP_GAP
    rec = s.drill_audit(did, action="drill_step_rejected")[0]
    assert rec["details"]["code"] == CODE_STEP_GAP
    # The gap did not consume a step number: step 1 still advances normally.
    assert advance(s, did, seq=1)["current_seq"] == 1


def test_advance_beyond_frozen_sequence_is_refused(store):
    s, *_ = store
    did = create(s, [make_step()])["id"]
    advance(s, did)
    # The single planned step is done: the drill is completed, so a further
    # advance is a state-machine refusal rather than a gap.
    with pytest.raises(DrillConflict) as exc:
        advance(s, did, seq=2)
    assert exc.value.code == CODE_STATUS_CONFLICT


def test_explicit_gap_inside_the_sequence_is_refused(store):
    s, *_ = store
    did = create(s, [make_step(), make_step()])["id"]
    with pytest.raises(DrillConflict) as exc:
        advance(s, did, seq=2)
    assert exc.value.code == CODE_STEP_GAP


def test_expected_version_conflict(store):
    s, *_ = store
    did = create(s, [make_step(), make_step()])["id"]
    advance(s, did)  # version now 2
    with pytest.raises(DrillConflict) as exc:
        advance(s, did, expected_version=1)
    assert exc.value.code == CODE_VERSION_CONFLICT
    rec = s.drill_audit(did, action="drill_step_rejected")[0]
    assert rec["details"]["code"] == CODE_VERSION_CONFLICT
    # The losing attempt changed nothing; retrying with the right version wins.
    assert advance(s, did, expected_version=2)["current_seq"] == 2


def test_concurrent_advances_only_one_wins(store):
    s, *_ = store
    did = create(s, [make_step(), make_step()])["id"]
    s.resume(did)  # running: both threads race to record the SAME next step
    results = []

    def worker():
        try:
            # Both submit step 1 concurrently; the loser sees the gap.
            results.append(("ok", advance(s, did, seq=1)["current_seq"]))
        except DrillConflict as exc:
            results.append(("conflict", exc.code))

    barrier = threading.Barrier(2)

    def synced():
        barrier.wait()
        worker()

    threads = [threading.Thread(target=synced) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    oks = [r for r in results if r[0] == "ok"]
    assert len(oks) == 1 and oks[0][1] == 1
    assert any(r[1] == CODE_STEP_GAP for r in results)


# -- idempotency -------------------------------------------------------------


def test_idempotent_step_submission_replays_same_result(store):
    s, *_ = store
    did = create(s, [make_step(), make_step()])["id"]
    _, first = s.advance(did, AdvanceIn(), idem_key="k", fingerprint="f")
    _, replay = s.advance(did, AdvanceIn(), idem_key="k", fingerprint="f")
    assert replay["idempotent_replay"] is True
    assert replay["step"]["started_at"] == first["step"]["started_at"]
    assert replay["version"] == first["version"]
    # Only one step row was recorded.
    assert len(s.get(did)["steps"]) == 1


def test_same_idempotency_key_different_payload_conflicts(store):
    s, *_ = store
    did = create(s, [make_step()])["id"]
    s.advance(did, AdvanceIn(), idem_key="k", fingerprint="f")
    with pytest.raises(DrillConflict) as exc:
        s.advance(did, AdvanceIn(), idem_key="k", fingerprint="other")
    assert exc.value.code == "idempotency_conflict"


def test_idempotency_keys_do_not_cross_drills(store):
    s, *_ = store
    d1 = create(s, [make_step()])["id"]
    d2 = create(s, [make_step()])["id"]
    _, r1 = s.advance(d1, AdvanceIn(), idem_key="shared", fingerprint="f")
    _, r2 = s.advance(d2, AdvanceIn(), idem_key="shared", fingerprint="f")
    assert r1.get("idempotent_replay") is None
    assert r2.get("idempotent_replay") is None


# -- pause / resume / reset --------------------------------------------------


def test_pause_blocks_advance_and_resume_continues(store):
    s, *_ = store
    did = create(s, [make_step(), make_step()])["id"]
    s.resume(did)
    advance(s, did)
    s.pause(did, expected_version=3)
    with pytest.raises(DrillConflict) as exc:
        advance(s, did)
    assert exc.value.code == CODE_STATUS_CONFLICT
    s.resume(did, expected_version=4)
    assert advance(s, did)["status"] == "completed"


def test_pause_only_valid_while_running(store):
    s, *_ = store
    did = create(s, [make_step()])["id"]
    with pytest.raises(DrillConflict) as exc:
        s.pause(did)
    assert exc.value.code == CODE_STATUS_CONFLICT


def test_reset_clears_steps_cache_report_and_bumps_epoch(store):
    s, *_ = store
    did = create(s, [make_step(expected={"chosen": "a"}), make_step()])["id"]
    advance(s, did)
    advance(s, did)
    rep_before = s.report(did)["checksum"]
    out = s.reset(did)[1]
    assert out["status"] == "ready" and out["current_seq"] == 0
    assert out["run_epoch"] == 2
    with pytest.raises(DrillNotFound):
        s.step(did, 1)
    fresh = s.get(did)
    assert fresh["steps"] == []
    assert fresh["cache_state"] == []
    assert fresh["health"] == {"a": True, "b": True}
    # A new report is regenerated for the empty run with a different checksum.
    assert s.report(did)["checksum"] != rep_before


def test_reset_invalidates_previous_epoch_idempotency_key(store):
    s, *_ = store
    did = create(s, [make_step(), make_step()])["id"]
    s.advance(did, AdvanceIn(), idem_key="k", fingerprint="f")
    s.reset(did, idem_key="r", fingerprint="x")
    _, out = s.advance(did, AdvanceIn(seq=1), idem_key="k", fingerprint="f")
    assert out.get("idempotent_replay") is None
    assert out["step"]["seq"] == 1


def test_reset_is_itself_idempotent(store):
    s, *_ = store
    did = create(s, [make_step()])["id"]
    _, r1 = s.reset(did, idem_key="r", fingerprint="x")
    _, r2 = s.reset(did, idem_key="r", fingerprint="x")
    assert r2["idempotent_replay"] is True
    assert r2["run_epoch"] == r1["run_epoch"]


# -- report ------------------------------------------------------------------


def test_report_freezes_snapshot_and_points_at_first_diff(store):
    s, *_ = store
    did = create(
        s,
        [
            make_step(expected={"chosen": "a"}),  # matches
            make_step(health_changes={"a": False}, expected={"chosen": "a"}),  # diffs
            make_step(health_changes={"a": False}, expected={"chosen": "nope"}),
        ],
    )["id"]
    advance(s, did)
    advance(s, did)
    advance(s, did)
    rep = s.report(did)["report"]
    assert rep["steps_recorded"] == 3
    assert rep["steps_matched"] == 1
    assert rep["first_diff"]["seq"] == 2
    assert "chosen" in rep["first_diff"]["diff_reasons"]
    # The frozen snapshot is fixed at creation and carried in the report.
    assert rep["frozen_snapshot"]["config_version"] == 1
    assert set(rep["frozen_snapshot"]["target_manifest"]) == {"a", "b"}
    step2 = rep["steps"][1]
    assert step2["actual"]["chosen"] == "b"
    assert step2["expected"]["chosen"] == "a"


def test_report_is_generated_once_and_identical_afterwards(store):
    s, *_ = store
    did = create(s, [make_step()])["id"]
    advance(s, did)
    first = s.report(did)
    second = s.report(did)
    assert second["idempotent_replay"] is True
    assert first["checksum"] == second["checksum"]


def test_report_before_any_steps_is_empty_but_stable(store):
    s, *_ = store
    did = create(s, [make_step()])["id"]
    r1 = s.report(did)
    r2 = s.report(did)
    assert r1["checksum"] == r2["checksum"]
    assert r1["report"]["steps_recorded"] == 0
    assert r1["report"]["first_diff"] is None


# -- isolation ---------------------------------------------------------------


def test_replay_does_not_touch_live_state(store):
    s, cfg, live_health, audit = store
    did = create(
        s,
        [
            make_step(health_changes={"a": False}),
            make_step(health_changes={"a": False, "b": False}),
        ],
    )["id"]
    advance(s, did)
    advance(s, did)
    # Live health view untouched (unknown -> fail open True).
    assert live_health.is_healthy("a") is True
    assert live_health.is_healthy("b") is True
    # The production Resolver used by the data plane is never constructed in
    # these tests, but the real audit log only holds the config apply: the
    # replay's internal release_group_hit audits were discarded.
    real_types = {r["type"] for r in audit.query(limit=1000)}
    assert "release_group_hit" not in real_types
    # Drill audit lives in its own table.
    assert s.drill_audit(did, action="drill_step")


def test_distinct_drills_keep_distinct_simulated_state(store):
    s, *_ = store
    d1 = create(s, [make_step(health_changes={"a": False})])["id"]
    d2 = create(s, [make_step()])["id"]
    advance(s, d1)
    out2 = advance(s, d2)
    # Drill 2 does not see drill 1's health change.
    assert out2["step"]["health_after"] == {"a": True, "b": True}
    assert out2["step"]["answer"]["chosen"] == "a"


def test_release_groups_are_replayed_in_isolation(store, tmp_path):
    db = connect(str(tmp_path / "g.db"))
    audit = AuditLog(db)
    cfg = ConfigManager(db, audit)
    bundle = ConfigBundle(
        version=3,
        rules=[
            Rule(
                name="svc",
                scope="global",
                ttl=60,
                targets=[Target(id="base", address="tcp://1:80")],
            )
        ],
        release_groups=[
            ReleaseGroup(
                id="canary",
                name="svc",
                scope="global",
                priority=0,
                match_labels={"env": "canary"},
                percent=100,
                window_start=0,
                window_end=10_000_000_000,
                targets=[Target(id="can", address="tcp://2:80")],
            )
        ],
    )
    cfg.apply(bundle)
    s = DrillStore(db, cfg, HealthRegistry())
    did = s.create(
        DrillCreateIn(
            config_version=3,
            steps=[
                DrillStepIn(name="svc", client="c", labels={"env": "canary"}),
            ],
        )
    )["id"]
    out = advance(s, did)
    assert out["step"]["answer"]["chosen"] == "can"
    assert out["step"]["answer"]["release_group"] == "canary"


# -- persistence across restart ----------------------------------------------


def test_state_survives_restart(tmp_path):
    path = str(tmp_path / "persist.db")

    def build():
        db = connect(path)
        cfg = ConfigManager(db, AuditLog(db))
        cfg.load_persisted()  # mirrors Components.start()
        health = HealthRegistry()
        return DrillStore(db, cfg, health), cfg

    s1, cfg = build()
    cfg.apply(BUNDLE)  # seed the saved version the drill will freeze
    did = s1.create(
        DrillCreateIn(
            drill_id="persist-drill",
            config_version=1,
            steps=[make_step(expected={"chosen": "a"}), make_step()],
        )
    )["id"]
    advance(s1, did)
    checksum = s1.report(did)["checksum"]

    s2, _ = build()  # new store/connection over the same database
    drill = s2.get(did)
    assert drill["status"] == "running"
    assert drill["current_seq"] == 1
    assert drill["steps"][0]["answer"]["chosen"] == "a"
    # Continuing the sequence and the report checksum are stable.
    out = advance(s2, did, expected_version=2)
    assert out["status"] == "completed"
    assert s2.report(did)["checksum"] == checksum
    # Audit order is preserved and append-only.
    actions = [r["action"] for r in reversed(s2.drill_audit(did))]
    assert actions.index("drill_created") < actions.index("drill_step") < actions.index(
        "drill_completed"
    )


def test_step_query_by_number(store):
    s, *_ = store
    did = create(s, [make_step(), make_step(health_changes={"a": False})])["id"]
    advance(s, did)
    advance(s, did)
    step = s.step(did, 2)
    assert step["seq"] == 2 and step["answer"]["chosen"] == "b"
    with pytest.raises(DrillNotFound):
        s.step(did, 9)
