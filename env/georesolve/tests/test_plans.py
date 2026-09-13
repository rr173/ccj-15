"""Store-level tests for reusable plans, independent runs and branches."""
from __future__ import annotations

import threading

import pytest

from app.audit import AuditLog
from app.config_store import ConfigManager
from app.drills import (
    AdvanceIn,
    DrillCreateIn,
    DrillStepIn,
    DrillStore,
)
from app.health import HealthRegistry
from app.models import ConfigBundle, Defaults, Rule, Target
from app.plans import (
    BranchCreateIn,
    CODE_BRANCH_POINT_INVALID,
    CODE_BRANCH_TAIL_LENGTH,
    CODE_DRILL_NOT_COMPLETED,
    CODE_OWNER_MISMATCH,
    CODE_PLAN_ARCHIVED,
    CODE_STEP_GAP,
    CODE_VERSION_CONFLICT,
    PlanArchiveIn,
    PlanConflict,
    PlanCreateIn,
    PlanForbidden,
    PlanNotFound,
    PlanStore,
    RunAdvanceIn,
    RunCreateIn,
    RunNotFound,
)
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


def step(**kw):
    kw.setdefault("name", "api")
    kw.setdefault("client", "c1")
    return kw


@pytest.fixture
def stores(tmp_path):
    db = connect(str(tmp_path / "plans.db"))
    audit = AuditLog(db)
    cfg = ConfigManager(db, audit)
    health = HealthRegistry()
    cfg.apply(BUNDLE)
    drills = DrillStore(db, cfg, health)
    plans = PlanStore(db, cfg, drills)
    return plans, drills, cfg, db


def completed_drill(drills, steps):
    did = drills.create(DrillCreateIn(config_version=1, steps=steps))["id"]
    for _ in steps:
        drills.advance(did, AdvanceIn())
    return did


def make_plan(plans, drills, steps=None):
    steps = steps or [
        DrillStepIn(**step(expected={"chosen": "a"})),
        DrillStepIn(**step(health_changes={"a": False}, expected={"chosen": "b"})),
        DrillStepIn(**step(advance_seconds=1)),
    ]
    did = completed_drill(drills, steps)
    _, payload = plans.create_plan(
        PlanCreateIn(name="p", source_drill_id=did), actor="bootstrap"
    )
    return payload["plan"]["id"]


# -- plan creation / freezing ------------------------------------------------


def test_plan_freezes_completed_drill_snapshot(stores):
    plans, drills, cfg, _ = stores
    did = completed_drill(drills, [DrillStepIn(**step())])
    _, payload = plans.create_plan(
        PlanCreateIn(name="nightly", source_drill_id=did, description="d"),
        actor="bootstrap",
    )
    plan = payload["plan"]
    assert payload["plan"]["status"] == "active"
    assert plan["config_version"] == 1
    assert set(plan["frozen"]["target_manifest"]) == {"a", "b"}
    assert plan["steps_planned"] == 1
    assert plan["steps_spec"][0]["name"] == "api"
    assert plan["initial_health"] == {"a": True, "b": True}
    assert plan["source_drill_id"] == did


def test_plan_from_uncompleted_drill_is_rejected(stores):
    plans, drills, _, _ = stores
    did = drills.create(
        DrillCreateIn(config_version=1, steps=[DrillStepIn(**step())])
    )["id"]
    with pytest.raises(PlanConflict) as exc:
        plans.create_plan(PlanCreateIn(name="p", source_drill_id=did), actor="x")
    assert exc.value.code == CODE_DRILL_NOT_COMPLETED


def test_plan_from_version_and_steps(stores):
    plans, *_ = stores
    _, payload = plans.create_plan(
        PlanCreateIn(
            name="p",
            config_version=1,
            steps=[step(), step(health_changes={"a": False})],
        ),
        actor="bootstrap",
    )
    assert payload["plan"]["steps_planned"] == 2


def test_plan_from_unknown_version_is_404(stores):
    plans, *_ = stores
    with pytest.raises(PlanNotFound):
        plans.create_plan(
            PlanCreateIn(name="p", config_version=99, steps=[step()]), actor="x"
        )


def test_plan_id_uniqueness(stores):
    plans, drills, _, _ = stores
    pid = make_plan(plans, drills)
    with pytest.raises(PlanConflict) as exc:
        plans.create_plan(
            PlanCreateIn(plan_id=pid, name="p2", config_version=1, steps=[step()]),
            actor="x",
        )
    assert exc.value.code == "plan_id_conflict"


# -- independent runs --------------------------------------------------------


def test_two_runs_are_independent(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, r1 = plans.create_run(
        pid, RunCreateIn(note="one", owner_id="alice"), actor="bootstrap"
    )
    _, r2 = plans.create_run(
        pid, RunCreateIn(note="two", owner_id="bob"), actor="bootstrap"
    )
    rid1, rid2 = r1["run"]["id"], r2["run"]["id"]
    assert rid1 != rid2
    for _ in range(3):
        plans.advance(rid1, RunAdvanceIn(), actor="alice")
    # Run 2 sees none of run 1's health/cache/steps/lifecycle.
    run2 = plans.get_run(rid2, actor="bob")
    assert run2["status"] == "ready" and run2["current_seq"] == 0
    assert run2["health"] == {"a": True, "b": True}
    assert run2["steps"] == [] and run2["cache_state"] == []
    # Plan creation + two run creates bumped the plan version three times.
    assert plans.get_plan(pid)["version"] == 3


def test_run_advances_replay_identically_to_the_drill(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, r = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = r["run"]["id"]
    _, s1 = plans.advance(rid, RunAdvanceIn(), actor="alice")
    assert s1["step"]["answer"]["chosen"] == "a"
    assert s1["step"]["cache_hit"] is False
    _, s2 = plans.advance(rid, RunAdvanceIn(), actor="alice")
    assert s2["step"]["answer"]["chosen"] == "b"
    assert s2["step"]["health_after"]["a"] is False
    _, s3 = plans.advance(rid, RunAdvanceIn(), actor="alice")
    assert s3["status"] == "completed"
    # Step 3 is the same request one simulated second later: its answer is
    # still served from the simulated cache (no health change at step 3).
    assert s3["step"]["cache_hit"] is True


def test_run_lifecycle_pause_resume_reset(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, r = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = r["run"]["id"]
    plans.advance(rid, RunAdvanceIn(), actor="alice")
    _, paused = plans.pause_run(rid, actor="alice")
    assert paused["status"] == "paused"
    with pytest.raises(PlanConflict) as exc:
        plans.advance(rid, RunAdvanceIn(), actor="alice")
    assert exc.value.code == "status_conflict"
    plans.resume_run(rid, actor="alice")
    plans.advance(rid, RunAdvanceIn(), actor="alice")
    _, reset = plans.reset_run(rid, actor="alice")
    assert reset["status"] == "ready" and reset["current_seq"] == 0
    assert reset["run_epoch"] == 2
    assert plans.get_run(rid, actor="alice")["steps"] == []
    with pytest.raises(RunNotFound):
        plans.run_step(rid, 1, actor="alice")


def test_archived_plan_rejects_new_runs(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    plans.archive_plan(pid, PlanArchiveIn(), actor="bootstrap")
    with pytest.raises(PlanConflict) as exc:
        plans.create_run(pid, RunCreateIn(), actor="bootstrap")
    assert exc.value.code == CODE_PLAN_ARCHIVED


def test_expected_version_conflict_on_run_create(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    # Plan version is 1 after creation.
    plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")  # -> 2
    with pytest.raises(PlanConflict) as exc:
        plans.create_run(
            pid, RunCreateIn(owner_id="bob", expected_version=1), actor="bootstrap"
        )
    assert exc.value.code == CODE_VERSION_CONFLICT


def test_concurrent_run_creates_only_one_version_bump_wins(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    # Both racers expect plan version 1; only one can bump it to 2.
    results = []

    def worker(owner):
        try:
            plans.create_run(
                pid, RunCreateIn(owner_id=owner, expected_version=1), actor="bootstrap"
            )
            results.append(("ok", owner))
        except PlanConflict as exc:
            results.append(("conflict", exc.code))

    barrier = threading.Barrier(2)
    threads = []
    for owner in ("alice", "bob"):
        def synced(o=owner):
            barrier.wait()
            worker(o)
        threads.append(threading.Thread(target=synced))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len([r for r in results if r[0] == "ok"]) == 1
    assert any(r[1] == CODE_VERSION_CONFLICT for r in results)


# -- owner isolation ---------------------------------------------------------


def test_other_owner_cannot_read_or_operate(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, r = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = r["run"]["id"]
    # Bob cannot read...
    with pytest.raises(PlanForbidden) as exc:
        plans.get_run(rid, actor="bob")
    assert exc.value.code == CODE_OWNER_MISMATCH
    # ...nor advance, pause, reset, report or compare.
    with pytest.raises(PlanForbidden):
        plans.advance(rid, RunAdvanceIn(), actor="bob")
    with pytest.raises(PlanForbidden):
        plans.pause_run(rid, actor="bob")
    with pytest.raises(PlanForbidden):
        plans.reset_run(rid, actor="bob")
    with pytest.raises(PlanForbidden):
        plans.run_report(rid, actor="bob")
    with pytest.raises(PlanForbidden):
        plans.create_branch(
            rid,
            BranchCreateIn(
                branch_point_seq=1,
                steps=[step(), step()],
            ),
            actor="bob",
        )
    # Bob's list never includes Alice's run.
    assert plans.list_runs(actor="bob") == []
    assert [x["id"] for x in plans.list_runs(actor="alice")] == [rid]
    # A privileged (bootstrap) caller sees and operates everything.
    run = plans.get_run(rid, actor="bootstrap")
    assert run["owner_id"] == "alice"


def test_owner_filter(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    plans.create_run(pid, RunCreateIn(owner_id="bob"), actor="bootstrap")
    alice = plans.list_runs(owner_id="alice", actor="bootstrap")
    assert len(alice) == 1 and alice[0]["owner_id"] == "alice"


# -- branching ---------------------------------------------------------------


def test_branch_inherits_prefix_and_replaces_tail(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, r = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = r["run"]["id"]
    for _ in range(3):
        plans.advance(rid, RunAdvanceIn(), actor="alice")

    # Branch after step 1: the run keeps a healthy (instead of failing at
    # step 2). Replacement steps are numbered 1..2 from the branch point.
    _, br = plans.create_branch(
        rid,
        BranchCreateIn(
            branch_point_seq=1,
            steps=[
                step(expected={"chosen": "a"}),
                step(advance_seconds=1),
            ],
            owner_id="alice",
            note="keep-a-healthy",
        ),
        actor="alice",
    )
    bid = br["run"]["id"]
    branch = plans.get_run(bid, actor="alice")
    assert branch["parent_run_id"] == rid
    assert branch["branch_point_seq"] == 1
    assert branch["status"] == "running"
    assert branch["current_seq"] == 1
    inherited = branch["steps"][0]
    assert inherited["inherited"] is True
    assert inherited["inherited_from"] == {"run_id": rid, "run_epoch": 1, "seq": 1}
    assert inherited["answer"]["chosen"] == "a"

    # Advance the branch's own first step: a stays healthy -> chosen a.
    _, s2 = plans.advance(bid, RunAdvanceIn(), actor="alice")
    assert s2["step"]["answer"]["chosen"] == "a"
    assert s2["step"]["matched_expected"] is True
    _, s3 = plans.advance(bid, RunAdvanceIn(), actor="alice")
    assert s3["status"] == "completed"


def test_branch_health_and_cache_are_independent_from_parent(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, r = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = r["run"]["id"]
    for _ in range(3):
        plans.advance(rid, RunAdvanceIn(), actor="alice")
    _, br = plans.create_branch(
        rid,
        BranchCreateIn(
            branch_point_seq=2,
            steps=[step(health_changes={"b": False})],
        ),
        actor="alice",
    )
    bid = br["run"]["id"]
    # The parent continues to exist and stays completed; the branch's reset
    # and advance do not alter it.
    _, reset = plans.reset_run(bid, actor="alice")
    assert reset["current_seq"] == 2  # rewinds to the branch point
    branch = plans.get_run(bid, actor="alice")
    # Inherited steps survive a reset; health/cache restored to step 2's state.
    assert len(branch["steps"]) == 2
    assert branch["health"] == {"a": False, "b": True}
    assert all(s["inherited"] for s in branch["steps"])
    parent = plans.get_run(rid, actor="alice")
    assert parent["status"] == "completed" and parent["current_seq"] == 3
    # The branch's cache inherits step-2 entries; its own new step executes.
    _, s3 = plans.advance(bid, RunAdvanceIn(), actor="alice")
    # Both targets unhealthy: production fail-open still returns a target but
    # flags the answer degraded.
    assert s3["step"]["answer"]["degraded"] is True
    assert s3["step"]["answer"]["chosen"] in ("a", "b")
    # A branch reset that already happened never rewound the parent epoch.
    parent = plans.get_run(rid, actor="alice")
    assert parent["run_epoch"] == 1


def test_branch_from_unknown_or_unfinished_step_rejected(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, r = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = r["run"]["id"]
    plans.advance(rid, RunAdvanceIn(), actor="alice")  # only step 1 exists
    with pytest.raises(PlanConflict) as exc:
        plans.create_branch(
            rid,
            BranchCreateIn(branch_point_seq=2, steps=[step(), step()]),
            actor="alice",
        )
    assert exc.value.code == CODE_BRANCH_POINT_INVALID
    # Branching from the final step has no tail to replace.
    for _ in range(2):
        plans.advance(rid, RunAdvanceIn(), actor="alice")
    with pytest.raises(PlanConflict) as exc:
        plans.create_branch(
            rid, BranchCreateIn(branch_point_seq=3, steps=[]), actor="alice"
        )
    assert exc.value.code == CODE_BRANCH_TAIL_LENGTH


def test_branch_tail_length_must_match(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, r = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = r["run"]["id"]
    for _ in range(3):
        plans.advance(rid, RunAdvanceIn(), actor="alice")
    with pytest.raises(PlanConflict) as exc:
        plans.create_branch(
            rid,
            BranchCreateIn(
                branch_point_seq=1,
                steps=[step()],  # needs 2
            ),
            actor="alice",
        )
    assert exc.value.code == CODE_BRANCH_TAIL_LENGTH


def test_branch_expected_version_conflict(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, r = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = r["run"]["id"]
    plans.advance(rid, RunAdvanceIn(), actor="alice")  # run version -> 2
    with pytest.raises(PlanConflict) as exc:
        plans.create_branch(
            rid,
            BranchCreateIn(
                branch_point_seq=1, steps=[step(), step()], expected_version=99
            ),
            actor="alice",
        )
    assert exc.value.code == CODE_VERSION_CONFLICT


def test_inherited_steps_cannot_be_advanced(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, r = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = r["run"]["id"]
    for _ in range(3):
        plans.advance(rid, RunAdvanceIn(), actor="alice")
    _, br = plans.create_branch(
        rid,
        BranchCreateIn(branch_point_seq=1, steps=[step(), step()]),
        actor="alice",
    )
    bid = br["run"]["id"]
    with pytest.raises(PlanConflict) as exc:
        plans.advance(bid, RunAdvanceIn(seq=1), actor="alice")
    assert exc.value.code in (CODE_STEP_GAP, "status_conflict")


def test_parent_advance_after_branch_does_not_touch_branch(stores):
    plans, drills, *_ = stores
    # Parent branches while still running, then finishes; branch is untouched.
    steps = [DrillStepIn(**step()), DrillStepIn(**step()),
             DrillStepIn(**step())]
    did = completed_drill(drills, steps)
    _, p = plans.create_plan(
        PlanCreateIn(name="p", source_drill_id=did), actor="bootstrap"
    )
    pid = p["plan"]["id"]
    _, r = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = r["run"]["id"]
    plans.advance(rid, RunAdvanceIn(), actor="alice")
    plans.advance(rid, RunAdvanceIn(), actor="alice")  # current_seq = 2
    _, br = plans.create_branch(
        rid, BranchCreateIn(branch_point_seq=1, steps=[step(), step()]),
        actor="alice",
    )
    bid = br["run"]["id"]
    # Parent finishes its own step 3.
    _, s = plans.advance(rid, RunAdvanceIn(), actor="alice")
    assert s["status"] == "completed"
    branch = plans.get_run(bid, actor="alice")
    assert branch["current_seq"] == 1  # unaffected by parent completion


# -- idempotency -------------------------------------------------------------


def test_plan_create_idempotency_replays(stores):
    plans, *_ = stores
    req = PlanCreateIn(plan_id="p1", name="p", config_version=1, steps=[step()])
    _, r1 = plans.create_plan(req, actor="bootstrap", idem_key="k", fingerprint="f")
    _, r2 = plans.create_plan(req, actor="bootstrap", idem_key="k", fingerprint="f")
    assert r2["idempotent_replay"] is True
    assert r1["plan"]["id"] == r2["plan"]["id"]
    with pytest.raises(PlanConflict):
        plans.create_plan(req, actor="bootstrap", idem_key="k", fingerprint="other")


def test_run_advance_idempotency_scoped_per_epoch(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, r = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = r["run"]["id"]
    _, a1 = plans.advance(
        rid, RunAdvanceIn(), actor="alice", idem_key="k", fingerprint="f"
    )
    _, a2 = plans.advance(
        rid, RunAdvanceIn(), actor="alice", idem_key="k", fingerprint="f"
    )
    assert a2["idempotent_replay"] is True
    assert a1["step"]["started_at"] == a2["step"]["started_at"]
    # After a reset (new epoch) the key cannot resurrect the old result.
    plans.reset_run(rid, actor="alice")
    _, a3 = plans.advance(
        rid, RunAdvanceIn(seq=1), actor="alice", idem_key="k", fingerprint="f"
    )
    assert a3.get("idempotent_replay") is None


# -- reports & comparisons ---------------------------------------------------


def test_creating_run_for_another_owner_succeeds_but_cannot_be_read(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    # An admin assigns the run to alice; the creating identity does not own
    # it afterwards, but the creation response still returns the new run.
    _, payload = plans.create_run(
        pid, RunCreateIn(owner_id="alice", note="assigned"), actor="bootstrap"
    )
    rid = payload["run"]["id"]
    assert payload["run"]["owner_id"] == "alice"
    with pytest.raises(PlanForbidden):
        plans.get_run(rid, actor="carol")
    assert plans.get_run(rid, actor="alice")["note"] == "assigned"


def test_branch_replacement_health_changes_and_expected_are_used(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, r = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = r["run"]["id"]
    for _ in range(3):
        plans.advance(rid, RunAdvanceIn(), actor="alice")
    # Branch from step 2: fail b instead of a; a stays chosen.
    _, br = plans.create_branch(
        rid,
        BranchCreateIn(
            branch_point_seq=2,
            steps=[step(health_changes={"a": False, "b": False},
                         expected={"chosen": "a", "degraded": True})],
        ),
        actor="alice",
    )
    bid = br["run"]["id"]
    _, s3 = plans.advance(bid, RunAdvanceIn(), actor="alice")
    # Both targets unhealthy -> fail-open picks rank 1 (a), degraded.
    assert s3["step"]["answer"]["degraded"] is True
    assert s3["step"]["answer"]["chosen"] == "a"
    assert s3["matched_expected"] is True


def test_plan_list_filters(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    active = plans.list_plans(status="active")
    assert [p["id"] for p in active] == [pid]
    assert active[0]["run_count"] == 2
    plans.archive_plan(pid, PlanArchiveIn(), actor="bootstrap")
    assert plans.list_plans(status="active") == []
    assert [p["id"] for p in plans.list_plans(status="archived")] == [pid]


def test_run_reset_inherits_plan_anchor_for_deterministic_cache(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, r1 = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    _, r2 = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    # Two runs created at distinct wall-clock moments share the plan's frozen
    # simulated anchor, so step 1 answers and timestamps are identical.
    _, a1 = plans.advance(r1["run"]["id"], RunAdvanceIn(), actor="alice")
    _, a2 = plans.advance(r2["run"]["id"], RunAdvanceIn(), actor="alice")
    assert a1["step"]["sim_time"] == a2["step"]["sim_time"]
    assert a1["step"]["answer"]["chosen"] == a2["step"]["answer"]["chosen"]


def test_run_report_is_frozen(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, r = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = r["run"]["id"]
    for _ in range(3):
        plans.advance(rid, RunAdvanceIn(), actor="alice")
    rep1 = plans.run_report(rid, actor="alice")
    rep2 = plans.run_report(rid, actor="alice")
    assert rep2["idempotent_replay"] is True
    assert rep1["checksum"] == rep2["checksum"]
    assert rep1["report"]["steps_recorded"] == 3
    assert rep1["report"]["steps_matched"] == 3  # steps 1,2 match; step 3 has no expectation


def test_compare_pins_versions_and_names_first_divergence(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, ra = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    _, rb = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    aid, bid = ra["run"]["id"], rb["run"]["id"]
    for _ in range(3):
        plans.advance(aid, RunAdvanceIn(), actor="alice")
    # Run B is one step behind: first divergence is recorded-step progress.
    plans.advance(bid, RunAdvanceIn(), actor="alice")
    rep_wrapper = plans.compare(aid, bid, actor="alice")
    rep = rep_wrapper["report"]
    assert rep["runs"][0]["version"] == 4 and rep["runs"][1]["version"] == 2
    dv = rep["first_divergence"]
    assert dv["seq"] == 2 and dv["dimension"] == "step_progress"

    # Advance B identically up to 3 -> at the moment of that later
    # comparison the pair's stored report is still the first-generated
    # step_progress report: one pair has exactly one frozen report, pinned to
    # the versions seen when the pair was first compared.
    plans.advance(bid, RunAdvanceIn(), actor="alice")
    plans.advance(bid, RunAdvanceIn(), actor="alice")
    again = plans.compare(aid, bid, actor="alice")
    assert again["idempotent_replay"] is True
    # Same stored report/checksum regardless of later run progress.
    assert again["checksum"] == rep_wrapper["checksum"]
    assert again["report"]["first_divergence"]["dimension"] == "step_progress"


def test_compare_branch_detects_health_and_input_diffs(stores):
    plans, drills, *_ = stores
    pid = make_plan(plans, drills)
    _, ra = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = ra["run"]["id"]
    for _ in range(3):
        plans.advance(rid, RunAdvanceIn(), actor="alice")
    _, br = plans.create_branch(
        rid,
        BranchCreateIn(
            branch_point_seq=1,
            steps=[step(expected={"chosen": "a"}), step(advance_seconds=1)],
        ),
        actor="alice",
    )
    bid = br["run"]["id"]
    plans.advance(bid, RunAdvanceIn(), actor="alice")
    plans.advance(bid, RunAdvanceIn(), actor="alice")
    rep = plans.compare(rid, bid, actor="alice")["report"]
    dv = rep["first_divergence"]
    assert dv["seq"] == 2 and dv["dimension"] == "health_set"
    # Reversed pair gives the same stored report and checksum.
    rev = plans.compare(bid, rid, actor="alice")
    assert rev["checksum"] == plans.compare(rid, bid, actor="alice")["checksum"]


def test_compare_detects_step_input_diff(stores):
    plans, drills, *_ = stores
    # Two plans' runs can't compare; within one plan, branch with a changed
    # request at step 2 must surface as step_input first.
    custom = [
        DrillStepIn(**step(name="api")),
        DrillStepIn(**step(name="api")),
        DrillStepIn(**step(name="api")),
    ]
    pid = make_plan(plans, drills, custom)
    _, ra = plans.create_run(pid, RunCreateIn(owner_id="alice"), actor="bootstrap")
    rid = ra["run"]["id"]
    for _ in range(3):
        plans.advance(rid, RunAdvanceIn(), actor="alice")
    _, br = plans.create_branch(
        rid,
        BranchCreateIn(
            branch_point_seq=1,
            steps=[
                step(name="api", client="different-client"),
                step(name="api"),
            ],
        ),
        actor="alice",
    )
    bid = br["run"]["id"]
    plans.advance(bid, RunAdvanceIn(), actor="alice")
    plans.advance(bid, RunAdvanceIn(), actor="alice")
    dv = plans.compare(rid, bid, actor="alice")["report"]["first_divergence"]
    assert dv["dimension"] == "step_input"


def test_compare_cross_plan_is_rejected(stores):
    plans, drills, *_ = stores
    p1 = make_plan(plans, drills)
    p2 = make_plan(plans, drills)
    _, ra = plans.create_run(p1, RunCreateIn(owner_id="alice"), actor="bootstrap")
    _, rb = plans.create_run(p2, RunCreateIn(owner_id="alice"), actor="bootstrap")
    with pytest.raises(PlanConflict) as exc:
        plans.compare(ra["run"]["id"], rb["run"]["id"], actor="alice")
    assert exc.value.code == "compare_plan_mismatch"


# -- persistence across restart ----------------------------------------------


def test_everything_survives_restart(tmp_path):
    path = str(tmp_path / "persist.db")

    def build():
        db = connect(path)
        cfg = ConfigManager(db, AuditLog(db))
        cfg.load_persisted()
        health = HealthRegistry()
        drills = DrillStore(db, cfg, health)
        return PlanStore(db, cfg, drills), cfg

    s1, cfg = build()
    cfg.apply(BUNDLE)
    did = s1._drills.create(
        DrillCreateIn(
            config_version=1,
            steps=[
                DrillStepIn(**step(expected={"chosen": "a"})),
                DrillStepIn(**step()),
            ],
        )
    )["id"]
    s1._drills.advance(did, AdvanceIn())
    s1._drills.advance(did, AdvanceIn())
    _, p = s1.create_plan(
        PlanCreateIn(plan_id="plan-x", name="p", source_drill_id=did), actor="bootstrap"
    )
    pid = p["plan"]["id"]
    _, r = s1.create_run(
        pid, RunCreateIn(run_id="run-x", owner_id="alice"), actor="bootstrap"
    )
    rid = r["run"]["id"]
    s1.advance(rid, RunAdvanceIn(), actor="alice")
    _, br = s1.create_branch(
        rid,
        BranchCreateIn(run_id="br-x", branch_point_seq=1, steps=[step()]),
        actor="alice",
    )
    bid = br["run"]["id"]
    checksum = s1.run_report(rid, actor="alice")["checksum"]

    s2, _ = build()
    plan = s2.get_plan(pid)
    assert plan["status"] == "active" and plan["steps_planned"] == 2
    run = s2.get_run(rid, actor="alice")
    assert run["current_seq"] == 1 and run["status"] == "running"
    assert run["steps"][0]["answer"]["chosen"] == "a"
    # Owner permission enforced after restart.
    with pytest.raises(PlanForbidden):
        s2.get_run(rid, actor="bob")
    branch = s2.get_run(bid, actor="alice")
    assert branch["parent_run_id"] == rid
    assert branch["steps"][0]["inherited"] is True
    # Optimistic version survives.
    with pytest.raises(PlanConflict) as exc:
        s2.advance(rid, RunAdvanceIn(expected_version=1), actor="alice")
    assert exc.value.code == CODE_VERSION_CONFLICT
    # Report checksum is stable.
    assert s2.run_report(rid, actor="alice")["checksum"] == checksum
    # Comparison checksum is stable across restart.
    cmp1 = s2.compare(rid, bid, actor="alice")
    s3, _ = build()
    cmp2 = s3.compare(rid, bid, actor="alice")
    assert cmp2["idempotent_replay"] is True
    assert cmp2["checksum"] == cmp1["checksum"]
