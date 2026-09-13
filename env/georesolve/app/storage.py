"""SQLite persistence for config versions, the audit log and admin authz."""
from __future__ import annotations

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS config_versions (
    version    INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL,
    source     TEXT NOT NULL,
    payload    TEXT NOT NULL,
    summary    TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    type    TEXT NOT NULL,
    details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit(type, id);
CREATE TABLE IF NOT EXISTS authz_roles (
    id           TEXT PRIMARY KEY,
    role_version INTEGER NOT NULL,
    payload      TEXT NOT NULL,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS authz_identities (
    id               TEXT PRIMARY KEY,
    identity_version INTEGER NOT NULL,
    token_hash       TEXT NOT NULL UNIQUE,
    status           TEXT NOT NULL,
    roles            TEXT NOT NULL,
    payload          TEXT NOT NULL,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL,
    deactivated_at   REAL
);
CREATE TABLE IF NOT EXISTS authz_idempotency (
    key                 TEXT PRIMARY KEY,
    request_fingerprint TEXT NOT NULL,
    status_code         INTEGER NOT NULL,
    response            TEXT NOT NULL,
    created_at          REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS authz_meta (
    k TEXT PRIMARY KEY,
    v INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS authz_emergency_grants (
    id           TEXT PRIMARY KEY,
    identity_id  TEXT NOT NULL,
    status       TEXT NOT NULL,
    payload      TEXT NOT NULL,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL,
    expires_at   REAL
);
CREATE INDEX IF NOT EXISTS idx_emergency_identity
    ON authz_emergency_grants(identity_id, status);
CREATE TABLE IF NOT EXISTS usage_events (
    event_id      TEXT PRIMARY KEY,
    event_time    REAL NOT NULL,
    recorded_at   REAL NOT NULL,
    tenant        TEXT NOT NULL,
    client_key    TEXT NOT NULL,
    name          TEXT NOT NULL,
    region        TEXT NOT NULL DEFAULT '',
    labels_sig    TEXT NOT NULL DEFAULT '',
    rule_scope    TEXT NOT NULL,
    rule_version  INTEGER,
    group_id      TEXT,
    config_version INTEGER NOT NULL,
    result        TEXT NOT NULL,
    quantity      REAL NOT NULL,
    degraded      INTEGER NOT NULL DEFAULT 0,
    source        TEXT NOT NULL DEFAULT 'live',
    backfilled_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_usage_time ON usage_events(event_time);
CREATE INDEX IF NOT EXISTS idx_usage_tenant_time ON usage_events(tenant, event_time);
CREATE INDEX IF NOT EXISTS idx_usage_client_time ON usage_events(tenant, client_key, event_time);
CREATE INDEX IF NOT EXISTS idx_usage_scope_time
    ON usage_events(tenant, rule_scope, event_time);
CREATE TABLE IF NOT EXISTS usage_aggregates (
    period_type  TEXT NOT NULL,
    period_start REAL NOT NULL,
    tenant       TEXT NOT NULL,
    client_key   TEXT NOT NULL DEFAULT '',
    rule_scope   TEXT NOT NULL DEFAULT '',
    events       INTEGER NOT NULL,
    quantity     REAL NOT NULL,
    allowed_qty  REAL NOT NULL,
    rejected_qty REAL NOT NULL,
    degraded_qty REAL NOT NULL,
    updated_at   REAL NOT NULL,
    PRIMARY KEY (period_type, period_start, tenant, client_key, rule_scope)
);
CREATE INDEX IF NOT EXISTS idx_agg_tenant
    ON usage_aggregates(period_type, period_start, tenant);
CREATE TABLE IF NOT EXISTS budgets (
    tenant           TEXT PRIMARY KEY,
    period_type      TEXT NOT NULL,
    amount           REAL NOT NULL,
    alert_thresholds TEXT NOT NULL,
    over_policy      TEXT NOT NULL,
    version          INTEGER NOT NULL,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL,
    created_by       TEXT,
    updated_by       TEXT
);
CREATE TABLE IF NOT EXISTS budget_alerts (
    id           TEXT PRIMARY KEY,
    tenant       TEXT NOT NULL,
    period_type  TEXT NOT NULL,
    period_start REAL NOT NULL,
    threshold    REAL NOT NULL,
    usage        REAL NOT NULL,
    budget_amount REAL NOT NULL,
    event_id     TEXT,
    fired_at     REAL NOT NULL,
    status       TEXT NOT NULL DEFAULT 'open',
    acknowledged_by TEXT,
    acknowledged_at REAL,
    comment      TEXT,
    version      INTEGER NOT NULL DEFAULT 1,
    policy_origin TEXT,
    UNIQUE(tenant, period_type, period_start, threshold)
);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON budget_alerts(tenant, status);

-- Tenant budget groups: a group carries an optional default budget policy
-- (period/amount/thresholds/over-policy). A group without its own policy
-- inherits from parent_id; the chain is validated to be acyclic. Every
-- policy/parent/description change bumps ``version``; each version is also
-- archived in budget_group_revisions so historical periods can resolve the
-- policy that was in effect at an arbitrary past time.
CREATE TABLE IF NOT EXISTS budget_groups (
    id               TEXT PRIMARY KEY,
    description      TEXT NOT NULL DEFAULT '',
    parent_id        TEXT,
    period_type      TEXT,
    amount           REAL,
    alert_thresholds TEXT,
    over_policy      TEXT,
    version          INTEGER NOT NULL DEFAULT 1,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL,
    created_by       TEXT,
    updated_by       TEXT
);
CREATE TABLE IF NOT EXISTS budget_group_revisions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id   TEXT NOT NULL,
    version    INTEGER NOT NULL,
    action     TEXT NOT NULL,
    payload    TEXT NOT NULL,
    actor      TEXT,
    ts         REAL NOT NULL,
    UNIQUE(group_id, version)
);
CREATE INDEX IF NOT EXISTS idx_group_rev_time
    ON budget_group_revisions(group_id, ts);
-- A tenant belongs to at most one group at a time. The per-row version is
-- the optimistic-concurrency token for member migrations: a concurrent move
-- of the same tenant loses with a conflict instead of silently overwriting.
CREATE TABLE IF NOT EXISTS budget_group_members (
    tenant     TEXT PRIMARY KEY,
    group_id   TEXT NOT NULL,
    version    INTEGER NOT NULL DEFAULT 1,
    added_at   REAL NOT NULL,
    added_by   TEXT,
    FOREIGN KEY(group_id) REFERENCES budget_groups(id)
);
CREATE INDEX IF NOT EXISTS idx_group_members_group
    ON budget_group_members(group_id);
-- Append-only membership intervals; the open interval (end_at IS NULL) is
-- the tenant's current group. Closed intervals let policy resolution for a
-- past event time see which group the tenant belonged to back then.
CREATE TABLE IF NOT EXISTS budget_group_membership_history (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant    TEXT NOT NULL,
    group_id  TEXT NOT NULL,
    start_at  REAL NOT NULL,
    end_at    REAL,
    moved_by  TEXT
);
CREATE INDEX IF NOT EXISTS idx_membership_history
    ON budget_group_membership_history(tenant, start_at);
-- Approval-gated temporary budget overrides with an explicit validity
-- window. Only an approved override whose window contains the resolution
-- time is in effect; windows of two non-terminal overrides for one tenant
-- may never overlap.
CREATE TABLE IF NOT EXISTS budget_overrides (
    id               TEXT PRIMARY KEY,
    tenant           TEXT NOT NULL,
    period_type      TEXT NOT NULL,
    amount           REAL NOT NULL,
    alert_thresholds TEXT NOT NULL,
    over_policy      TEXT NOT NULL,
    window_start     REAL NOT NULL,
    window_end       REAL NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    requested_by     TEXT NOT NULL,
    requested_at     REAL NOT NULL,
    decided_by       TEXT,
    decided_at       REAL,
    decision_comment TEXT,
    approved_at      REAL,
    revoked_by       TEXT,
    revoked_at       REAL,
    version          INTEGER NOT NULL DEFAULT 1,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_overrides_tenant
    ON budget_overrides(tenant, status, window_start);
-- Frozen policy actually applied per (tenant, period). The open period's
-- row tracks the live resolved policy (frozen=0) and is refreshed on every
-- event; the first observation after the period closes re-resolves the
-- policy as of the period boundary and flips the row to frozen=1, after
-- which it never changes again.
CREATE TABLE IF NOT EXISTS budget_policy_snapshots (
    period_type      TEXT NOT NULL,
    period_start     REAL NOT NULL,
    tenant           TEXT NOT NULL,
    source           TEXT NOT NULL,
    source_id        TEXT NOT NULL,
    source_version   INTEGER NOT NULL,
    amount           REAL NOT NULL,
    alert_thresholds TEXT NOT NULL,
    over_policy      TEXT NOT NULL,
    frozen           INTEGER NOT NULL DEFAULT 0,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL,
    PRIMARY KEY (period_type, period_start, tenant)
);
CREATE INDEX IF NOT EXISTS idx_policy_snapshots_tenant
    ON budget_policy_snapshots(tenant, period_start);

-- Budget billing disputes. A dispute cites one or more immutable usage
-- events in one tenant period and proposes a signed billing adjustment.
-- At submission (draft -> pending_review) the cited event list, the raw
-- period aggregates and the resolved budget policy (source + version) are
-- frozen into this row; later event backfills, group edits, migrations or
-- override changes never rewrite the freeze. Lifecycle:
--   draft -> pending_review -> approved -> applied
--                           \-> rejected
--   draft/pending_review/approved -> revoked
--   applied (open period, normal) -> revoked (append-only reverse)
CREATE TABLE IF NOT EXISTS budget_disputes (
    id                  TEXT PRIMARY KEY,
    tenant              TEXT NOT NULL,
    period_type         TEXT NOT NULL,
    period_start        REAL NOT NULL,
    reason              TEXT NOT NULL DEFAULT '',
    adjustment_quantity REAL NOT NULL,
    retroactive         INTEGER NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'draft',
    event_count         INTEGER NOT NULL DEFAULT 0,
    frozen_events       TEXT,
    frozen_aggregates   TEXT,
    frozen_policy       TEXT,
    frozen_at           REAL,
    created_by          TEXT NOT NULL,
    created_at          REAL NOT NULL,
    submitted_by        TEXT,
    submitted_at        REAL,
    decided_by          TEXT,
    decided_at          REAL,
    decision_comment    TEXT,
    applied_by          TEXT,
    applied_at          REAL,
    revoked_by          TEXT,
    revoked_at          REAL,
    revoke_reason       TEXT,
    version             INTEGER NOT NULL DEFAULT 1,
    updated_at          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_disputes_tenant
    ON budget_disputes(tenant, period_type, period_start);
CREATE INDEX IF NOT EXISTS idx_disputes_status ON budget_disputes(status);
CREATE INDEX IF NOT EXISTS idx_disputes_created ON budget_disputes(created_at, id);

-- Cited usage events of a dispute, frozen in the exact submission order.
-- References are only validated at submission time (a draft may cite an
-- event id before it is verified); the immutable usage_events rows
-- themselves are never modified.
CREATE TABLE IF NOT EXISTS budget_dispute_refs (
    dispute_id TEXT NOT NULL,
    event_id   TEXT NOT NULL,
    position   INTEGER NOT NULL,
    PRIMARY KEY (dispute_id, position)
);
CREATE INDEX IF NOT EXISTS idx_dispute_refs_event
    ON budget_dispute_refs(event_id);

-- Append-only lifecycle timeline of a dispute. Every transition appends
-- exactly one row, never updated or deleted, so the approval chain and
-- audit ordering survive restarts.
CREATE TABLE IF NOT EXISTS budget_dispute_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dispute_id  TEXT NOT NULL,
    ts          REAL NOT NULL,
    actor       TEXT,
    action      TEXT NOT NULL,
    from_status TEXT,
    to_status   TEXT,
    version     INTEGER NOT NULL,
    details     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_dispute_events_dispute
    ON budget_dispute_events(dispute_id, id);
CREATE INDEX IF NOT EXISTS idx_dispute_events_ts
    ON budget_dispute_events(ts, id);

-- Immutable adjustment ledger. Applying an approved dispute appends one
-- 'apply' row (signed quantity); revoking an open-period applied dispute
-- appends a 'reverse' row. Rows are never updated or deleted. ``kind`` is
-- 'normal' for open-period projections (read by the budget gate) and
-- 'retroactive' for closed periods (traceable only; they never alter the
-- period's gate projection or the alerts the period actually fired).
CREATE TABLE IF NOT EXISTS budget_adjustments (
    id                TEXT PRIMARY KEY,
    dispute_id        TEXT NOT NULL,
    tenant            TEXT NOT NULL,
    period_type       TEXT NOT NULL,
    period_start      REAL NOT NULL,
    kind              TEXT NOT NULL,
    direction         TEXT NOT NULL,
    quantity          REAL NOT NULL,
    reverses_id       TEXT,
    raw_quantity      REAL NOT NULL,
    adjusted_quantity REAL NOT NULL,
    policy_origin     TEXT,
    actor             TEXT NOT NULL,
    created_at        REAL NOT NULL,
    UNIQUE(dispute_id, direction)
);
CREATE INDEX IF NOT EXISTS idx_adjustments_period
    ON budget_adjustments(tenant, period_type, period_start, kind);

-- Materialized per-period budget projection: raw billed quantity (the
-- immutable aggregates) plus the net normal adjustment delta. The gate
-- and the "adjusted budget" view read this projection; it is updated in
-- the same transaction as the immutable adjustment row. Retroactive
-- adjustments deliberately never touch a closed period's projection.
CREATE TABLE IF NOT EXISTS budget_usage_projections (
    period_type      TEXT NOT NULL,
    period_start     REAL NOT NULL,
    tenant           TEXT NOT NULL,
    raw_quantity     REAL NOT NULL,
    adjustment_delta REAL NOT NULL DEFAULT 0,
    updated_at       REAL NOT NULL,
    PRIMARY KEY (period_type, period_start, tenant)
);
CREATE INDEX IF NOT EXISTS idx_projections_tenant
    ON budget_usage_projections(tenant, period_start);

-- ======================================================================
-- Fault drills (resolution replay)
--
-- A drill freezes one saved config version (target manifest + rule summary
-- + full bundle payload) and a client request sequence, then replays the
-- resolver step by step inside a private space: every step uses its own
-- health registry, resolution cache and clock. The live health view,
-- resolution cache, rate-limit buckets and the real audit log are never
-- touched. All drill state lives here and therefore survives restarts.
-- ======================================================================
CREATE TABLE IF NOT EXISTS drills (
    id             TEXT PRIMARY KEY,
    status         TEXT NOT NULL,          -- ready|running|paused|completed|rejected
    config_version INTEGER NOT NULL,       -- frozen saved config version
    base_sim_time  REAL NOT NULL,          -- simulated clock anchor at creation
    spec           TEXT NOT NULL,          -- frozen creation spec (steps, ...)
    frozen         TEXT NOT NULL,          -- frozen manifest/rule summary/bundle
    health         TEXT NOT NULL,          -- current simulated health set {id: bool}
    cache_state    TEXT NOT NULL,          -- serialized simulated cache entries
    current_seq    INTEGER NOT NULL DEFAULT 0,  -- last recorded step number
    last_sim_time  REAL,                          -- simulated clock of the last step
    run_epoch      INTEGER NOT NULL DEFAULT 1,  -- bumps on reset (invalidates old keys)
    version        INTEGER NOT NULL DEFAULT 1,  -- optimistic-concurrency token
    created_by     TEXT,
    created_at     REAL NOT NULL,
    started_at     REAL,
    paused_at      REAL,
    completed_at   REAL,
    rejection      TEXT,                   -- {code,detail} when status='rejected'
    updated_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_drills_created ON drills(created_at, id);
CREATE INDEX IF NOT EXISTS idx_drills_status ON drills(status);

-- One row per *recorded* (committed) step, in step order. Refused attempts
-- do not consume a step number; they are kept in drill_audit instead, so
-- the same seq can be retried after the caller fixes the payload.
CREATE TABLE IF NOT EXISTS drill_steps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    drill_id    TEXT NOT NULL,
    run_epoch   INTEGER NOT NULL,
    seq         INTEGER NOT NULL,
    spec        TEXT NOT NULL,             -- the committed step spec
    result      TEXT NOT NULL,             -- full recorded step result
    started_at  REAL NOT NULL,             -- wall-clock step start
    recorded_at REAL NOT NULL,
    actor       TEXT,
    UNIQUE(drill_id, run_epoch, seq)
);
CREATE INDEX IF NOT EXISTS idx_drill_steps_drill
    ON drill_steps(drill_id, run_epoch, seq);

-- Append-only drill audit, fully separate from the real ``audit`` table.
-- Covers lifecycle transitions and every explicit refusal.
CREATE TABLE IF NOT EXISTS drill_audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    drill_id TEXT,
    ts      REAL NOT NULL,
    actor   TEXT,
    action  TEXT NOT NULL,
    version INTEGER,
    details TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_drill_audit_drill ON drill_audit(drill_id, id);
CREATE INDEX IF NOT EXISTS idx_drill_audit_ts ON drill_audit(ts, id);

-- Idempotency keys scoped per (drill, run_epoch). A reset starts a new
-- epoch, so a key retried after restart/replay cannot resurrect a result
-- from a previous run; keys also never cross between drills.
CREATE TABLE IF NOT EXISTS drill_idempotency (
    drill_id    TEXT NOT NULL,
    run_epoch   INTEGER NOT NULL,
    idem_key    TEXT NOT NULL,
    action      TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response    TEXT NOT NULL,
    created_at  REAL NOT NULL,
    PRIMARY KEY (drill_id, run_epoch, idem_key)
);

-- At most one report per (drill, run_epoch). The content is frozen when
-- first generated and addressed by its checksum; reset clears the row so a
-- replayed drill produces a fresh report.
CREATE TABLE IF NOT EXISTS drill_reports (
    drill_id   TEXT PRIMARY KEY,
    run_epoch  INTEGER NOT NULL,
    created_at REAL NOT NULL,
    content    TEXT NOT NULL,
    checksum   TEXT NOT NULL
);

-- ======================================================================
-- Reusable drill plans, independent runs and branches
--
-- A plan freezes a completed drill (or a saved config version plus a step
-- sequence) into an immutable, named artefact: config bundle, target
-- manifest, rule summaries, normalized step inputs/expected results and the
-- initial health set. Runs are fully independent replays of one plan;
-- branches are runs that inherit a frozen prefix of another run's recorded
-- steps and replace the tail. All state is persisted and survives restarts.
-- ======================================================================
CREATE TABLE IF NOT EXISTS drill_plans (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'active',  -- active|archived
    config_version   INTEGER NOT NULL,
    source_drill_id  TEXT,
    spec             TEXT NOT NULL,     -- frozen normalized step sequence
    frozen           TEXT NOT NULL,     -- frozen bundle/manifest/summaries
    initial_health   TEXT NOT NULL,     -- deterministic {target_id: bool}
    version          INTEGER NOT NULL DEFAULT 1,  -- optimistic token; bumps
                                                  -- on archive and run create
    created_by       TEXT,
    created_at       REAL NOT NULL,
    archived_at      REAL,
    updated_at       REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_drill_plans_created ON drill_plans(created_at, id);
CREATE INDEX IF NOT EXISTS idx_drill_plans_status ON drill_plans(status);

CREATE TABLE IF NOT EXISTS plan_runs (
    id               TEXT PRIMARY KEY,
    plan_id          TEXT NOT NULL,
    status           TEXT NOT NULL,     -- ready|running|paused|completed
    owner_id         TEXT NOT NULL,     -- identity allowed to read/operate
    note             TEXT NOT NULL DEFAULT '',
    base_sim_time    REAL NOT NULL,     -- per-run simulated clock anchor
    branch_point_seq INTEGER NOT NULL DEFAULT 0,  -- >0 for branches
    parent_run_id    TEXT,
    parent_run_epoch INTEGER,
    spec             TEXT NOT NULL,     -- this run's (possibly replaced) steps
    health           TEXT NOT NULL,     -- private simulated health set
    cache_state      TEXT NOT NULL,     -- private serialized simulated cache
    current_seq      INTEGER NOT NULL DEFAULT 0,
    last_sim_time    REAL,
    run_epoch        INTEGER NOT NULL DEFAULT 1,  -- bumps on reset
    version          INTEGER NOT NULL DEFAULT 1,  -- optimistic token
    created_by       TEXT,
    created_at       REAL NOT NULL,
    started_at       REAL,
    paused_at        REAL,
    completed_at     REAL,
    updated_at       REAL NOT NULL,
    FOREIGN KEY(plan_id) REFERENCES drill_plans(id)
);
CREATE INDEX IF NOT EXISTS idx_plan_runs_plan ON plan_runs(plan_id, created_at);
CREATE INDEX IF NOT EXISTS idx_plan_runs_owner ON plan_runs(owner_id);
CREATE INDEX IF NOT EXISTS idx_plan_runs_status ON plan_runs(status);
CREATE INDEX IF NOT EXISTS idx_plan_runs_parent ON plan_runs(parent_run_id);

-- Recorded steps of a run. 'inherited' rows are the branch's read-only
-- prefix, frozen copies of the parent's results (including the full private
-- cache state needed to continue replay after the branch point); 'recorded'
-- rows are the run's own executed steps.
CREATE TABLE IF NOT EXISTS plan_run_steps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL,
    run_epoch   INTEGER NOT NULL,
    seq         INTEGER NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'recorded',  -- recorded|inherited
    spec        TEXT NOT NULL,
    result      TEXT NOT NULL,
    started_at  REAL NOT NULL,
    recorded_at REAL NOT NULL,
    actor       TEXT,
    UNIQUE(run_id, run_epoch, seq)
);
CREATE INDEX IF NOT EXISTS idx_plan_run_steps_run
    ON plan_run_steps(run_id, run_epoch, seq);

-- Append-only audit trail for plans and runs, fully separate from both the
-- real audit table and the drill-only audit table.
CREATE TABLE IF NOT EXISTS plan_audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id TEXT,
    run_id  TEXT,
    ts      REAL NOT NULL,
    actor   TEXT,
    action  TEXT NOT NULL,
    version INTEGER,
    details TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_plan_audit_plan ON plan_audit(plan_id, id);
CREATE INDEX IF NOT EXISTS idx_plan_audit_run ON plan_audit(run_id, id);
CREATE INDEX IF NOT EXISTS idx_plan_audit_ts ON plan_audit(ts, id);

-- Identity-scoped idempotency keys for plan/run creation, archival and
-- branching (operations with no run epoch of their own).
CREATE TABLE IF NOT EXISTS plan_idempotency (
    idem_key    TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL,
    action      TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response    TEXT NOT NULL,
    created_at  REAL NOT NULL
);

-- Idempotency keys scoped per (run, run_epoch): reset starts a new epoch so
-- a retried key can never resurrect a prior run's response.
CREATE TABLE IF NOT EXISTS plan_run_idempotency (
    run_id      TEXT NOT NULL,
    run_epoch   INTEGER NOT NULL,
    idem_key    TEXT NOT NULL,
    action      TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response    TEXT NOT NULL,
    created_at  REAL NOT NULL,
    PRIMARY KEY (run_id, run_epoch, idem_key)
);

-- One frozen report per (run, run_epoch); reset removes the row.
CREATE TABLE IF NOT EXISTS plan_run_reports (
    run_id     TEXT PRIMARY KEY,
    run_epoch  INTEGER NOT NULL,
    created_at REAL NOT NULL,
    content    TEXT NOT NULL,
    checksum   TEXT NOT NULL
);

-- Frozen pair-wise comparison reports. The natural key is the unordered run
-- pair: the first comparison of a pair pins both runs to the versions they
-- held at that moment, and every repeat for the same pair replays that one
-- stored report (regardless of request direction or later progress).
CREATE TABLE IF NOT EXISTS plan_run_comparisons (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id_low       TEXT NOT NULL,
    run_id_high      TEXT NOT NULL,
    run_low_version  INTEGER NOT NULL,
    run_high_version INTEGER NOT NULL,
    created_at       REAL NOT NULL,
    content          TEXT NOT NULL,
    checksum         TEXT NOT NULL,
    UNIQUE(run_id_low, run_id_high)
);
CREATE INDEX IF NOT EXISTS idx_plan_comparisons_pair
    ON plan_run_comparisons(run_id_low, run_id_high);

-- ======================================================================
-- Target health-check orchestration
--
-- Each resolution target can have an independent check policy: several
-- probe methods, interval/timeout, failure and recovery thresholds,
-- maintenance windows and a priority for the checker. Policies are
-- versioned (monotonic ``policy_version``, optimistic-concurrency token);
-- every create/update/delete appends an immutable revision row, and
-- recorded check history is never rewritten when a policy changes.
--
-- The per-target state machine lives in health_target_states: observed
-- check verdict with unfinished threshold counters, current effective
-- status plus its explicit source (check/manual_override/maintenance/
-- paused/unmanaged), pause and override (with expiry) bookkeeping, next
-- scheduled probe time and a separate state_version. Everything needed to
-- continue after a restart is here; health_check_history is append-only.
-- ======================================================================
CREATE TABLE IF NOT EXISTS health_policies (
    target_id      TEXT PRIMARY KEY,
    policy_version INTEGER NOT NULL,
    checks         TEXT NOT NULL,          -- ordered list of probe method specs
    interval_seconds REAL NOT NULL,
    timeout_seconds  REAL NOT NULL,
    fail_threshold  INTEGER NOT NULL,
    recover_threshold INTEGER NOT NULL,
    maintenance_windows TEXT NOT NULL,     -- list of [start, end, note]
    priority       INTEGER NOT NULL DEFAULT 100,
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     REAL NOT NULL,
    updated_at     REAL NOT NULL,
    created_by     TEXT,
    updated_by     TEXT
);
CREATE INDEX IF NOT EXISTS idx_health_policies_priority
    ON health_policies(enabled, priority);

-- Append-only policy revisions: history of policy content. The frozen
-- payload of a revision is what check history rows refer to via
-- policy_version; later edits only append a new revision.
CREATE TABLE IF NOT EXISTS health_policy_revisions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id      TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    action         TEXT NOT NULL,          -- created|updated|deleted
    payload        TEXT NOT NULL,
    actor          TEXT,
    ts             REAL NOT NULL,
    UNIQUE(target_id, policy_version)
);
CREATE INDEX IF NOT EXISTS idx_health_policy_rev_target
    ON health_policy_revisions(target_id, policy_version);
CREATE INDEX IF NOT EXISTS idx_health_policy_rev_version
    ON health_policy_revisions(policy_version);

-- Per-target live state machine row, persisted after every change so the
-- observed verdict, unfinished threshold counters, maintenance/override
-- timing and scheduling all survive a restart.
CREATE TABLE IF NOT EXISTS health_target_states (
    target_id        TEXT PRIMARY KEY,
    observed_healthy INTEGER NOT NULL DEFAULT 1,  -- verdict from checks
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    consecutive_successes INTEGER NOT NULL DEFAULT 0,
    effective_source TEXT NOT NULL DEFAULT 'unmanaged',
    effective_healthy INTEGER NOT NULL DEFAULT 1,
    paused           INTEGER NOT NULL DEFAULT 0,
    paused_at        REAL,
    paused_reason    TEXT,
    pause_resets_counters INTEGER NOT NULL DEFAULT 1,
    override_healthy INTEGER,
    override_reason  TEXT,
    override_by      TEXT,
    override_at      REAL,
    override_expires_at REAL,
    policy_version   INTEGER NOT NULL DEFAULT 0,  -- policy at last check
    last_check_seq   INTEGER NOT NULL DEFAULT 0,
    last_checked_at  REAL,
    next_check_at    REAL NOT NULL,
    state_version    INTEGER NOT NULL DEFAULT 1,
    in_maintenance   INTEGER NOT NULL DEFAULT 0,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_health_states_due
    ON health_target_states(next_check_at);

-- Append-only check/transition history in a fixed global order. Each row
-- records either a probe evaluation (kind='check': start time, per-method
-- response summaries, verdict, reason, policy version) or an effective
-- status transition (kind='transition': reason, old/new status and source,
-- and policy/state versions before and after). Rows are immutable; a policy
-- update never rewrites them.
CREATE TABLE IF NOT EXISTS health_check_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,  -- global fixed order
    target_id      TEXT NOT NULL,
    seq            INTEGER NOT NULL,          -- per-target 1-based order
    kind           TEXT NOT NULL,             -- check|transition
    ts             REAL NOT NULL,             -- record time
    started_at     REAL,                      -- check: probe start time
    policy_version INTEGER NOT NULL,          -- governing policy version
    state_version  INTEGER,                   -- state version after the event
    verdict        TEXT,                      -- check: success|failure|skipped
    failure_reason TEXT,                      -- timeout|response_format_error|...
    response_summary TEXT,                    -- per-method compact summaries
    duration_ms    REAL,
    effective_healthy INTEGER,
    effective_source TEXT,
    transition_reason TEXT,                  -- transition: check_fail_threshold|...
    from_healthy   INTEGER,
    to_healthy     INTEGER,
    from_source    TEXT,
    to_source      TEXT,
    from_policy_version INTEGER,
    to_policy_version INTEGER,
    actor          TEXT,
    detail         TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_health_hist_target
    ON health_check_history(target_id, seq);
CREATE INDEX IF NOT EXISTS idx_health_hist_version
    ON health_check_history(policy_version);
CREATE INDEX IF NOT EXISTS idx_health_hist_ts
    ON health_check_history(ts, id);

-- ======================================================================
-- Health event subscriptions and alert delivery
--
-- Subscriptions select transitions by target ('*' = every target) and
-- status source (check / manual_override / maintenance / '*') and carry
-- their own consecutive-threshold confirmation, silence windows, retry
-- policy and webhook endpoint. A subscription is versioned; every update
-- appends an immutable revision, and each generated event freezes the
-- matching subscription revision so later edits never change what an old
-- event is delivered as.
--
-- health_alert_events is the deduplicated, persisted event stream: one row
-- per (target_id, transition history id). Thresholded check-sourced
-- transitions start 'unconfirmed' and only become active (and create a
-- delivery row) after enough consecutive same-verdict checks, or are
-- superseded by an opposite transition. health_alert_deliveries is the
-- outbox: a row exists exactly when an event must be (or has been) sent to
-- one subscription, with next_attempt_at/attempts/last_error persisted
-- after every attempt so a crashed/retrying webhook is never lost.
-- ======================================================================
CREATE TABLE IF NOT EXISTS health_alert_subscriptions (
    sub_id        TEXT PRIMARY KEY,
    sub_version   INTEGER NOT NULL DEFAULT 1,
    target_id     TEXT NOT NULL,             -- '*' matches every target
    sources       TEXT NOT NULL,             -- JSON list of status sources
    consecutive_threshold INTEGER NOT NULL DEFAULT 1,
    webhook_url   TEXT NOT NULL,
    headers       TEXT NOT NULL DEFAULT '{}',
    signing_secret TEXT,
    silence_windows TEXT NOT NULL DEFAULT '[]',  -- JSON list of [start,end,note)
    max_retries   INTEGER NOT NULL DEFAULT 5,
    backoff_base_seconds REAL NOT NULL DEFAULT 1.0,
    backoff_max_seconds REAL NOT NULL DEFAULT 300.0,
    enabled       INTEGER NOT NULL DEFAULT 1,
    deleted       INTEGER NOT NULL DEFAULT 0,
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL,
    created_by    TEXT,
    updated_by    TEXT
);
CREATE INDEX IF NOT EXISTS idx_health_alert_subs_target
    ON health_alert_subscriptions(target_id, enabled, deleted);

CREATE TABLE IF NOT EXISTS health_alert_sub_revisions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sub_id      TEXT NOT NULL,
    sub_version INTEGER NOT NULL,
    action      TEXT NOT NULL,               -- created|updated|deleted
    payload     TEXT NOT NULL,
    actor       TEXT,
    ts          REAL NOT NULL,
    UNIQUE(sub_id, sub_version)
);
CREATE INDEX IF NOT EXISTS idx_health_alert_sub_rev
    ON health_alert_sub_revisions(sub_id, sub_version);

CREATE TABLE IF NOT EXISTS health_alert_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uid     TEXT NOT NULL UNIQUE,      -- stable id sent in the webhook
    target_id     TEXT NOT NULL,
    transition_id INTEGER NOT NULL,          -- health_check_history.id
    transition_seq INTEGER NOT NULL,         -- per-target seq at the transition
    event_type    TEXT NOT NULL,             -- unhealthy|recovered|maintenance_begin|maintenance_end|override_expired
    source        TEXT NOT NULL,             -- effective status source
    from_healthy  INTEGER,
    to_healthy    INTEGER,
    state_version INTEGER,
    policy_version INTEGER,
    detail        TEXT NOT NULL DEFAULT '{}',
    ts            REAL NOT NULL,
    status        TEXT NOT NULL,             -- unconfirmed|active|superseded|suppressed
    confirm_count INTEGER NOT NULL DEFAULT 0,
    threshold     INTEGER NOT NULL DEFAULT 1,
    activated_at  REAL,
    UNIQUE(target_id, transition_id)
);
CREATE INDEX IF NOT EXISTS idx_health_alert_ev_status
    ON health_alert_events(status, id);
CREATE INDEX IF NOT EXISTS idx_health_alert_ev_target
    ON health_alert_events(target_id, ts);

CREATE TABLE IF NOT EXISTS health_alert_deliveries (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_uid   TEXT NOT NULL UNIQUE,     -- Idempotency-Key sent to the webhook
    event_id       INTEGER NOT NULL
                   REFERENCES health_alert_events(id),
    sub_id         TEXT NOT NULL,
    sub_version    INTEGER NOT NULL,         -- frozen subscription snapshot
    snapshot       TEXT NOT NULL,            -- full subscription payload at fire
    event_payload  TEXT NOT NULL,            -- frozen webhook body
    status         TEXT NOT NULL,            -- pending|sending|succeeded|failed|dead|suppressed
    attempts       INTEGER NOT NULL DEFAULT 0,
    max_retries    INTEGER NOT NULL,
    next_attempt_at REAL,
    last_error     TEXT,
    last_status_code INTEGER,
    sent_at        REAL,
    created_at     REAL NOT NULL,
    updated_at     REAL NOT NULL,
    replayed_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_health_alert_del_due
    ON health_alert_deliveries(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_health_alert_del_event
    ON health_alert_deliveries(event_id);
CREATE INDEX IF NOT EXISTS idx_health_alert_del_sub
    ON health_alert_deliveries(sub_id, id);

-- Cursor of the alert ingestor into health_check_history (global id order).
-- A missing row means "start from the newest history id" so creating a
-- subscription never replays the pre-existing past; after a restart every
-- unprocessed row is scanned and UNIQUE(target_id, transition_id) makes
-- catch-up idempotent.
CREATE TABLE IF NOT EXISTS health_alert_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    # Migration for databases created before version summaries existed.
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(config_versions)")}
    if "summary" not in cols:
        conn.execute("ALTER TABLE config_versions ADD COLUMN summary TEXT")
    alert_cols = {r["name"] for r in conn.execute("PRAGMA table_info(budget_alerts)")}
    if "policy_origin" not in alert_cols:
        conn.execute("ALTER TABLE budget_alerts ADD COLUMN policy_origin TEXT")
    return conn
