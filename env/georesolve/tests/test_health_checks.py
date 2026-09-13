"""Unit tests for the health-check orchestration store/state machine."""
from __future__ import annotations

import asyncio
import time

import pytest

from app.audit import AuditLog
from app.config_store import ConfigManager
from app.health_checks import (
    HealthCheckConflict,
    HealthCheckNotFound,
    HealthCheckStore,
    MaintenanceWindowSpec,
    OverrideIn,
    PolicyUpsertIn,
    REASON_FORMAT,
    REASON_TIMEOUT,
    CheckMethodSpec,
)
from app.health_checks import run_probe
from app.storage import connect
from tests.conftest import FakeClock, bundle, rule, target


class HStoreFixture:
    def __init__(self, tmp_path):
        self.clock = FakeClock()
        db = connect(str(tmp_path / "hc.db"))
        self.audit = AuditLog(db, self.clock)
        self.config = ConfigManager(db, self.audit, self.clock)
        self.store = HealthCheckStore(db, self.config, self.audit, self.clock)
        self.config.apply(
            bundle(
                1,
                [
                    rule("api", targets=[
                        target("a", address="tcp://10.0.0.1:80"),
                        target("b", address="http://10.0.0.2/health"),
                    ], rule_version=1)
                ],
            )
        )


@pytest.fixture
def hc(tmp_path):
    return HStoreFixture(tmp_path)


def policy(clock=None, **over):
    base = dict(
        interval_seconds=2.0,
        timeout_seconds=1.0,
        fail_threshold=2,
        recover_threshold=2,
        maintenance_windows=[],
        priority=10,
    )
    base.update(over)
    return PolicyUpsertIn(**base)


def probe_failing(address, timeout, *, error="connection refused"):
    async def p(address, timeout):
        return {"type": "tcp", "ok": False, "reason": "connection_error",
                "status": None, "duration_ms": 1.0, "detail": error}
    return p


# -- policy CRUD / versioning -------------------------------------------------


def test_create_policy_defaults_checks_from_address(hc):
    pol, created = hc.store.upsert_policy("b", policy())
    assert created is True and pol["policy_version"] == 1
    assert pol["checks"] == [{"type": "http", "port": None, "path": "/health",
                             "timeout_seconds": None, "expect_status": None,
                             "expect_json": False, "expect_field": None,
                             "content_regex": None}]
    state = hc.store.get_state("b")
    assert state["effective_source"] == "check"
    assert state["effective_healthy"] is True  # fail open initially


def test_create_policy_for_unknown_target_is_404(hc):
    with pytest.raises(HealthCheckNotFound):
        hc.store.upsert_policy("zzz", policy())


def test_invalid_policy_rejected(tmp_path):
    hc = HStoreFixture(tmp_path)
    with pytest.raises(Exception):
        hc.store.upsert_policy(
            "a", policy(interval_seconds=0.0)
        )
    with pytest.raises(Exception):
        hc.store.upsert_policy("a", policy(fail_threshold=0))
    with pytest.raises(Exception):
        hc.store.upsert_policy(
            "a",
            policy(maintenance_windows=[
                MaintenanceWindowSpec(start=100.0, end=50.0)
            ]),
        )
    with pytest.raises(Exception):
        CheckMethodSpec(type="tcp", path="/x")


def test_expected_version_conflict_on_policy(hc):
    hc.store.upsert_policy("a", policy())
    with pytest.raises(HealthCheckConflict):
        hc.store.upsert_policy("a", policy(priority=5, expected_version=99))


def test_identical_policy_put_is_noop(hc):
    hc.store.upsert_policy("a", policy())
    pol, created = hc.store.upsert_policy("a", policy())
    assert created is False and pol["policy_version"] == 1


def test_policy_update_appends_revision_and_keeps_history(hc):
    hc.store.upsert_policy("a", policy(fail_threshold=3))
    asyncio.run(hc.store.check_target("a"))  # one check row at v1
    h = hc.store.history("a")["items"]
    assert {r["policy_version"] for r in h} == {1}
    assert [r for r in h if r["kind"] == "check"][0]["detail"][
        "fail_threshold"
    ] == 3

    pol, _ = hc.store.upsert_policy("a", policy(fail_threshold=1))
    assert pol["policy_version"] == 2
    revisions = hc.store.revisions("a")
    actions = [(r["policy_version"], r["action"]) for r in reversed(revisions)]
    assert actions == [(1, "created"), (2, "updated")]

    # The v1 check history row is immutable and still shows v1 thresholds.
    h = hc.store.history("a")["items"]
    check_row = next(r for r in h if r["kind"] == "check")
    assert check_row["policy_version"] == 1
    assert check_row["detail"]["fail_threshold"] == 3
    v2 = hc.store.history("a", policy_version=2)
    assert v2["items"] == []


def test_policy_delete_returns_target_to_unmanaged(hc):
    hc.store.upsert_policy("a", policy())
    hc.store.delete_policy("a", expected_version=1)
    assert hc.store.is_healthy("a") is True
    st = hc.store.get_state("a")
    assert st["effective_source"] == "unmanaged" and st["policy_version"] == 0
    revs = hc.store.revisions("a")
    assert revs[0]["action"] == "deleted"
    # History remains queryable after deletion.
    assert hc.store.history("a")["items"]


def test_delete_missing_policy_404(hc):
    with pytest.raises(HealthCheckNotFound):
        hc.store.delete_policy("a")


# -- threshold state machine ---------------------------------------------------


def _force_probe(monkeypatch_target, ok, reason="connection_error"):
    async def fake(method, address, timeout):
        return {"type": method.type, "ok": ok, "reason": None if ok else reason,
                "status": 200 if ok else None, "duration_ms": 0.1, "detail": ""}
    return fake


def test_consecutive_failures_then_recovery(hc, monkeypatch):
    hc.store.upsert_policy("a", policy(fail_threshold=2, recover_threshold=2))
    import app.health_checks as mod
    results = iter([False, False, True, True])

    async def fake(method, address, timeout):
        ok = next(results)
        return {"type": "tcp", "ok": ok, "reason": None if ok else "x",
                "status": None, "duration_ms": 0.1, "detail": ""}

    monkeypatch.setattr(mod, "run_probe", fake)

    r1 = asyncio.run(hc.store.check_target("a"))
    assert r1["verdict"] == "failure" and r1["transition_seq"] is None
    assert hc.store.is_healthy("a") is True  # threshold not reached

    r2 = asyncio.run(hc.store.check_target("a"))
    assert r2["transition_seq"] is not None
    assert hc.store.is_healthy("a") is False
    assert hc.store.get_state("a")["observed_healthy"] is False

    r3 = asyncio.run(hc.store.check_target("a"))
    assert r3["transition_seq"] is None  # need 2 successes
    assert hc.store.is_healthy("a") is False
    r4 = asyncio.run(hc.store.check_target("a"))
    assert r4["transition_seq"] is not None
    assert hc.store.is_healthy("a") is True

    hist = hc.store.history("a")["items"]
    transitions = [r for r in hist if r["kind"] == "transition"]
    reasons = [r["transition"]["reason"] for r in transitions]
    assert "check_fail_threshold" in reasons
    assert "check_recover_threshold" in reasons
    # Each transition carries before/after versions.
    tr = next(r for r in transitions
              if r["transition"]["reason"] == "check_fail_threshold")
    assert tr["transition"]["from_healthy"] is True
    assert tr["transition"]["to_healthy"] is False


def test_success_resets_failure_ladder(hc, monkeypatch):
    import app.health_checks as mod
    hc.store.upsert_policy("a", policy(fail_threshold=2))
    seq = iter([False, True, False])

    async def fake(method, address, timeout):
        ok = next(seq)
        return {"type": "tcp", "ok": ok, "reason": None if ok else "x",
                "status": None, "duration_ms": 0.1, "detail": ""}

    monkeypatch.setattr(mod, "run_probe", fake)
    for _ in range(3):
        asyncio.run(hc.store.check_target("a"))
    assert hc.store.get_state("a")["consecutive_failures"] == 1
    assert hc.store.is_healthy("a") is True


def test_check_history_has_start_time_summary_verdict_and_policy(hc, monkeypatch):
    import app.health_checks as mod

    async def fake(method, address, timeout):
        return {"type": "tcp", "ok": True, "reason": None, "status": None,
                "duration_ms": 0.42, "detail": ""}

    monkeypatch.setattr(mod, "run_probe", fake)
    hc.store.upsert_policy("a", policy())
    asyncio.run(hc.store.check_target("a"))
    row = next(
        r for r in hc.store.history("a")["items"] if r["kind"] == "check"
    )
    assert row["kind"] == "check"
    assert row["started_at"] == hc.clock.t
    assert row["verdict"] == "success"
    assert row["response_summary"][0]["ok"] is True
    assert row["policy_version"] == 1


def test_stale_probe_after_policy_change_is_discarded(hc, monkeypatch):
    import app.health_checks as mod
    hc.store.upsert_policy("a", policy())

    async def slow(method, address, timeout):
        # Policy is changed to v2 while the probe is "in flight".
        hc.store.upsert_policy("a", policy(priority=1))
        return {"type": "tcp", "ok": False, "reason": "x", "status": None,
                "duration_ms": 0.1, "detail": ""}

    monkeypatch.setattr(mod, "run_probe", slow)
    res = asyncio.run(hc.store.check_target("a"))
    assert res is None  # stale result never recorded against v2
    checks = [r for r in hc.store.history("a")["items"] if r["kind"] == "check"]
    assert checks == []


# -- maintenance windows -------------------------------------------------------


def test_maintenance_window_parks_target_and_resumes(hc, monkeypatch):
    import app.health_checks as mod
    hc.store.upsert_policy(
        "a",
        policy(maintenance_windows=[
            MaintenanceWindowSpec(start=100.0, end=200.0, note="rack work")
        ]),
    )
    hc.clock.t = 100.0
    hc.store.is_healthy("a")  # trigger lazy entry
    st = hc.store.get_state("a")
    assert st["effective_source"] == "maintenance"
    assert st["effective_healthy"] is False
    # Checks do not run during the window.
    assert asyncio.run(hc.store.check_target("a")) is None

    hc.clock.t = 200.0
    assert hc.store.is_healthy("a") is True
    st = hc.store.get_state("a")
    assert st["effective_source"] == "check" and st["in_maintenance"] is False
    reasons = [r["transition"]["reason"]
               for r in hc.store.history("a")["items"]
               if r["kind"] == "transition"]
    assert "maintenance_begin" in reasons and "maintenance_end" in reasons


# -- pause / resume -------------------------------------------------------------


def test_pause_freezes_and_resume_returns_to_check(hc, monkeypatch):
    import app.health_checks as mod
    hc.store.upsert_policy("a", policy(fail_threshold=1))

    async def fail(method, address, timeout):
        return {"type": "tcp", "ok": False, "reason": "x", "status": None,
                "duration_ms": 0.1, "detail": ""}

    monkeypatch.setattr(mod, "run_probe", fail)
    asyncio.run(hc.store.check_target("a"))
    assert hc.store.is_healthy("a") is False

    res = hc.store.pause("a", reason="investigating")
    assert res["changed"] is True
    st = hc.store.get_state("a")
    assert st["paused"] is True
    assert st["effective_source"] == "paused"
    assert st["effective_healthy"] is False  # frozen answer
    assert asyncio.run(hc.store.check_target("a")) is None

    # Repeated pause is a natural no-op.
    assert hc.store.pause("a")["changed"] is False

    res = hc.store.resume("a")
    assert res["changed"] is True
    st = hc.store.get_state("a")
    assert st["paused"] is False and st["effective_source"] == "check"


def test_pause_expected_version_conflict(hc):
    hc.store.upsert_policy("a", policy())
    with pytest.raises(HealthCheckConflict):
        hc.store.pause("a", expected_version=999)


# -- manual override and expiry -------------------------------------------------


def test_override_takes_precedence_and_revoke_returns_to_check(hc):
    hc.store.upsert_policy("a", policy())
    res = hc.store.override("a", OverrideIn(healthy=False, reason="drain"))
    assert res["changed"] is True
    assert hc.store.is_healthy("a") is False
    st = hc.store.get_state("a")
    assert st["effective_source"] == "manual_override"
    assert st["observed_healthy"] is True  # check verdict untouched

    # Repeating the same override is a no-op.
    assert hc.store.override(
        "a", OverrideIn(healthy=False, reason="drain")
    )["changed"] is False

    hc.store.revoke_override("a")
    st = hc.store.get_state("a")
    assert st["effective_source"] == "check" and st["effective_healthy"] is True


def test_override_expires_lazily_and_falls_back_to_check(hc, monkeypatch):
    import app.health_checks as mod
    hc.store.upsert_policy("a", policy())
    hc.store.override("a", OverrideIn(healthy=False, expires_at=hc.clock.t + 10))
    assert hc.store.is_healthy("a") is False
    hc.clock.advance(11)
    # Probes keep running under the override; make one fail so the observed
    # verdict is unhealthy by the time the override expires.

    async def fail(method, address, timeout):
        return {"type": "tcp", "ok": False, "reason": "x", "status": None,
                "duration_ms": 0.1, "detail": ""}

    monkeypatch.setattr(mod, "run_probe", fail)
    hc.store.upsert_policy("a", policy(fail_threshold=1),
                          )  # bump to v2 (counters reset)
    asyncio.run(hc.store.check_target("a"))
    assert hc.store.is_healthy("a") is False  # override still wins
    hc.clock.advance(1)  # now past expiry
    assert hc.store.is_healthy("a") is False  # expired -> observed unhealthy
    st = hc.store.get_state("a")
    assert st["effective_source"] == "check"
    assert st["override_healthy"] is None
    reasons = [r["transition"]["reason"]
               for r in hc.store.history("a")["items"]
               if r["kind"] == "transition"]
    assert "manual_override_expired" in reasons


def test_override_in_the_past_rejected(hc):
    hc.store.upsert_policy("a", policy())
    with pytest.raises(HealthCheckConflict):
        hc.store.override("a", OverrideIn(healthy=True, expires_at=hc.clock.t - 1))


def test_revoke_without_override_conflicts(hc):
    hc.store.upsert_policy("a", policy())
    with pytest.raises(HealthCheckConflict):
        hc.store.revoke_override("a")


# -- persistence / restart ------------------------------------------------------


def test_state_and_history_persist_across_restart(tmp_path):
    clock = FakeClock()
    db = connect(str(tmp_path / "p.db"))
    audit = AuditLog(db, clock)
    config = ConfigManager(db, audit, clock)
    store = HealthCheckStore(db, config, audit, clock)
    config.apply(bundle(1, [rule("api", targets=[target("a")], rule_version=1)]))
    store.upsert_policy("a", policy(fail_threshold=1))

    import app.health_checks as mod

    async def fail(method, address, timeout):
        return {"type": "tcp", "ok": False, "reason": "x", "status": None,
                "duration_ms": 0.1, "detail": ""}

    orig = mod.run_probe
    mod.run_probe = fail
    try:
        asyncio.run(store.check_target("a"))
    finally:
        mod.run_probe = orig
    store.override("a", OverrideIn(healthy=True, expires_at=clock.t + 100))

    db2 = connect(str(tmp_path / "p.db"))
    audit2 = AuditLog(db2, clock)
    config2 = ConfigManager(db2, audit2, clock)
    config2.load_persisted()
    store2 = HealthCheckStore(db2, config2, audit2, clock)
    st = store2.get_state("a")
    assert st["observed_healthy"] is False
    assert st["consecutive_failures"] == 1
    assert st["effective_source"] == "manual_override"
    assert st["override_expires_at"] == clock.t + 100
    assert store2.is_healthy("a") is True
    hist = store2.history("a")["items"]
    assert [r["seq"] for r in hist] == list(range(1, len(hist) + 1))
    # Fixed pagination order.
    assert hist == sorted(hist, key=lambda r: r["seq"])


def test_unfinished_counters_survive_restart(tmp_path):
    clock = FakeClock()
    path = str(tmp_path / "c.db")
    db = connect(path)
    audit = AuditLog(db, clock)
    config = ConfigManager(db, audit, clock)
    store = HealthCheckStore(db, config, audit, clock)
    config.apply(bundle(1, [rule("api", targets=[target("a")], rule_version=1)]))
    store.upsert_policy("a", policy(fail_threshold=3))
    import app.health_checks as mod

    async def fail(method, address, timeout):
        return {"type": "tcp", "ok": False, "reason": "x", "status": None,
                "duration_ms": 0.1, "detail": ""}

    mod.run_probe = fail
    asyncio.run(store.check_target("a"))
    asyncio.run(store.check_target("a"))
    mod.run_probe = run_probe

    db2 = connect(path)
    a2 = AuditLog(db2, clock)
    c2 = ConfigManager(db2, a2, clock)
    c2.load_persisted()
    s2 = HealthCheckStore(db2, c2, a2, clock)
    assert s2.get_state("a")["consecutive_failures"] == 2


# -- history pagination / filtering ---------------------------------------------


def test_history_pagination_fixed_order_and_version_filter(hc, monkeypatch):
    import app.health_checks as mod

    async def ok(method, address, timeout):
        return {"type": "tcp", "ok": True, "reason": None, "status": None,
                "duration_ms": 0.1, "detail": ""}

    monkeypatch.setattr(mod, "run_probe", ok)
    hc.store.upsert_policy("a", policy())
    for _ in range(3):
        asyncio.run(hc.store.check_target("a"))
    hc.store.upsert_policy("a", policy(priority=1))
    for _ in range(2):
        asyncio.run(hc.store.check_target("a"))

    page1 = hc.store.history("a", limit=2)
    assert [r["seq"] for r in page1["items"]] == [1, 2]
    assert page1["has_more"] is True
    page2 = hc.store.history("a", limit=2, after_seq=page1["next_cursor"])
    assert [r["seq"] for r in page2["items"]] == [3, 4]

    v2 = hc.store.history("a", policy_version=2, limit=50)
    assert {r["seq"] for r in v2["items"]} == {
        r["seq"] for r in hc.store.history("a", limit=50)["items"]
        if r["policy_version"] == 2
    }
    transitions = hc.store.history("a", kind="transition", limit=50)
    assert all(r["kind"] == "transition" for r in transitions["items"])


def test_history_unknown_target_404(hc):
    with pytest.raises(HealthCheckNotFound):
        hc.store.history("nope")


# -- probe-level behavior --------------------------------------------------------


def test_scheduler_uses_priority_order(hc, monkeypatch):
    hc.store.upsert_policy("a", policy(priority=100))
    hc.store.upsert_policy("b", policy(priority=1))
    due = hc.store.due_targets()
    assert [d["target_id"] for d in due] == ["b", "a"]


def test_http_probe_reasons_against_local_server():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            bodies = {
                "/json": b'{"a": {"b": 1}}',
                "/badjson": b"not-json{",
                "/ok": b"hello world",
            }
            body = bodies.get(self.path, b"")
            code = 503 if self.path == "/down" else 200
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        cases = [
            (CheckMethodSpec(type="http"), base + "/down", False, "bad_status"),
            (CheckMethodSpec(type="http"), base + "/ok", True, None),
            (CheckMethodSpec(type="http", expect_json=True),
             base + "/badjson", False, REASON_FORMAT),
            (CheckMethodSpec(type="http",
                             expect_field={"path": "a.b", "equals": 1}),
             base + "/json", True, None),
            (CheckMethodSpec(type="http",
                             expect_field={"path": "a.b", "equals": 2}),
             base + "/json", False, REASON_FORMAT),
            (CheckMethodSpec(type="http", expect_status=[503]),
             base + "/down", True, None),
            # Method path overrides the address path.
            (CheckMethodSpec(type="http", path="/json"),
             base + "/down", True, None),
        ]
        for method, address, want_ok, want_reason in cases:
            res = asyncio.run(run_probe(method, address, 2.0))
            assert res["ok"] is want_ok, (address, res)
            assert res["reason"] == want_reason, (address, res)
    finally:
        server.shutdown()


def test_tcp_probe_timeout_reason():
    # An unroutable address with a short timeout yields timeout or a
    # connection error; both are explicit failure reasons (never silent OK).
    res = asyncio.run(
        run_probe(CheckMethodSpec(type="tcp"), "tcp://10.255.255.1:9", 0.05)
    )
    assert res["ok"] is False
    assert res["reason"] in (REASON_TIMEOUT, "connection_error")
    assert res["duration_ms"] >= 0
