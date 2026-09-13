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
