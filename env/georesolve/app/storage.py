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
    return conn
