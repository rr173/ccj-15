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
