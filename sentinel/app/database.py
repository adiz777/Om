"""SQLite persistence for Om Sentinel run history. No database driver beyond stdlib is required."""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DB = Path(__file__).resolve().parents[1] / "data" / "sentinel.db"


def db_path() -> Path:
    configured = os.getenv("OM_SENTINEL_DB_PATH", "").strip()
    path = Path(configured).expanduser() if configured else DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def connect() -> sqlite3.Connection:
    connection = sqlite3.connect(db_path(), timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=5000")
    return connection


def init_db() -> None:
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                payload TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_created_at ON runs(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_domain ON runs(domain)")


def save_run(domain: str, payload: dict[str, Any], risk_score: int = 0) -> dict[str, Any]:
    init_db()
    run_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    with connect() as conn:
        conn.execute(
            "INSERT INTO runs (id, domain, status, created_at, risk_score, payload) VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, domain, "completed", created_at, max(0, min(100, int(risk_score))), json.dumps(payload, separators=(",", ":"), ensure_ascii=False)),
        )
    return {"id": run_id, "domain": domain, "status": "completed", "created_at": created_at, "risk_score": max(0, min(100, int(risk_score)))}


def list_runs(limit: int = 50, offset: int = 0) -> dict[str, Any]:
    init_db()
    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    with connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        rows = conn.execute(
            "SELECT id, domain, status, created_at, risk_score FROM runs ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return {"total": total, "limit": limit, "offset": offset, "items": [dict(row) for row in rows]}


def get_run(run_id: str) -> dict[str, Any] | None:
    init_db()
    with connect() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        return None
    item = dict(row)
    try:
        item["payload"] = json.loads(item["payload"])
    except (ValueError, TypeError):
        item["payload"] = {}
    return item
