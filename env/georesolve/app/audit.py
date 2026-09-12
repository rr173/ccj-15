"""Append-only audit log: rule changes, cache invalidations, health changes."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Callable, Optional


class AuditLog:
    def __init__(self, conn: sqlite3.Connection, clock: Callable[[], float] = time.time):
        self._conn = conn
        self._clock = clock
        self._lock = threading.Lock()

    def record(self, type_: str, details: dict, ts: Optional[float] = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit (ts, type, details) VALUES (?, ?, ?)",
                (self._clock() if ts is None else ts, type_, json.dumps(details, sort_keys=True)),
            )
            self._conn.commit()

    def query(
        self,
        type_: Optional[str] = None,
        limit: int = 200,
        since: Optional[float] = None,
    ) -> list[dict]:
        sql = "SELECT id, ts, type, details FROM audit WHERE 1=1"
        args: list = []
        if type_:
            sql += " AND type = ?"
            args.append(type_)
        if since is not None:
            sql += " AND ts >= ?"
            args.append(since)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [
            {"id": r["id"], "ts": r["ts"], "type": r["type"], "details": json.loads(r["details"])}
            for r in rows
        ]
