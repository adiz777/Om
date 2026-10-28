"""SQLite WAL persistence and JSON file fallback for Om 2.0 scan history.

Provides:
- Safe database initialisation and schema migration tracking (`schema_migrations`)
- Session history persistence and lookup
- Filtering and search by target, profile, or status
- Configurable retention cleanup (days & max sessions)
- Graceful fallback so basic CLI runs succeed even if SQLite is disabled or read-only
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from om.reporting.generator import validate_report_schema

DEFAULT_DB_PATH = Path("om_reports") / "om_history.db"
CURRENT_DB_VERSION = 2


def _resolve_db_path(db_path: str | Path | None = None) -> Path:
    path = Path(db_path).expanduser() if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(_resolve_db_path(db_path), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str | Path | None = None) -> None:
    """Initialise SQLite schema and apply migrations safely."""
    with _connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_sessions (
                session_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                profile TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                duration_seconds REAL NOT NULL DEFAULT 0.0,
                total_findings INTEGER NOT NULL DEFAULT 0,
                confirmed_findings INTEGER NOT NULL DEFAULT 0,
                error_count INTEGER NOT NULL DEFAULT 0,
                session_dir TEXT NOT NULL DEFAULT '',
                report_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_sessions_started ON scan_sessions(started_at DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_sessions_target ON scan_sessions(target)"
        )
        row = conn.execute(
            "SELECT MAX(version) AS v FROM schema_migrations"
        ).fetchone()
        if not row or not row["v"] or int(row["v"]) < CURRENT_DB_VERSION:
            conn.execute(
                "INSERT OR REPLACE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (CURRENT_DB_VERSION, datetime.now(timezone.utc).isoformat()),
            )


def save_session(
    report_doc: dict[str, Any],
    session_dir: str | Path = "",
    *,
    db_path: str | Path | None = None,
    retention_days: int = 90,
    max_sessions: int = 250,
) -> dict[str, Any]:
    """Persist a completed, partial, failed, or cancelled scan session to SQLite."""
    validate_report_schema(report_doc)
    init_db(db_path)
    summary = report_doc.get("summary", {})
    session_id = str(report_doc["session_id"])
    target = str(report_doc["target"])
    target_type = str(report_doc.get("target_type", "domain"))
    profile = str(report_doc.get("profile", "low"))
    status = str(report_doc.get("status", "completed"))
    started_at = str(report_doc["started_at"])
    completed_at = str(report_doc["completed_at"])
    duration = float(report_doc.get("duration_seconds", 0.0) or 0.0)
    total_f = int(summary.get("total_findings", 0))
    conf_f = int(summary.get("confirmed_findings", 0))
    err_c = int(summary.get("error_count", 0))
    dir_str = str(Path(session_dir).resolve()) if session_dir else ""

    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO scan_sessions (
                session_id, target, target_type, profile, status,
                started_at, completed_at, duration_seconds,
                total_findings, confirmed_findings, error_count,
                session_dir, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                target,
                target_type,
                profile,
                status,
                started_at,
                completed_at,
                duration,
                total_f,
                conf_f,
                err_c,
                dir_str,
                json.dumps(report_doc, ensure_ascii=False),
            ),
        )

    cleanup_retention(db_path=db_path, retention_days=retention_days, max_sessions=max_sessions)
    return {
        "session_id": session_id,
        "target": target,
        "target_type": target_type,
        "profile": profile,
        "status": status,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": duration,
        "total_findings": total_f,
        "confirmed_findings": conf_f,
        "error_count": err_c,
        "session_dir": dir_str,
    }


def list_sessions(
    *,
    db_path: str | Path | None = None,
    target_filter: str | None = None,
    profile_filter: str | None = None,
    status_filter: str | None = None,
    search_query: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Query scan sessions with optional filtering and pagination."""
    init_db(db_path)
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))

    target_p = target_filter.strip().lower() if (target_filter and target_filter.strip()) else None
    profile_p = profile_filter.strip().lower() if (profile_filter and profile_filter.strip()) else None
    status_p = status_filter.strip().lower() if (status_filter and status_filter.strip()) else None
    q_p = f"%{search_query.strip().lower()}%" if (search_query and search_query.strip()) else None

    params = (target_p, target_p, profile_p, profile_p, status_p, status_p, q_p, q_p, q_p, q_p)

    with _connect(db_path) as conn:
        total = conn.execute(
            """
            SELECT COUNT(*) FROM scan_sessions
            WHERE (? IS NULL OR LOWER(target) = ?)
              AND (? IS NULL OR LOWER(profile) = ?)
              AND (? IS NULL OR LOWER(status) = ?)
              AND (? IS NULL OR LOWER(target) LIKE ? OR LOWER(session_id) LIKE ? OR LOWER(report_json) LIKE ?)
            """,
            params,
        ).fetchone()[0]
        rows = conn.execute(
            """
            SELECT session_id, target, target_type, profile, status,
                   started_at, completed_at, duration_seconds,
                   total_findings, confirmed_findings, error_count, session_dir
            FROM scan_sessions
            WHERE (? IS NULL OR LOWER(target) = ?)
              AND (? IS NULL OR LOWER(profile) = ?)
              AND (? IS NULL OR LOWER(status) = ?)
              AND (? IS NULL OR LOWER(target) LIKE ? OR LOWER(session_id) LIKE ? OR LOWER(report_json) LIKE ?)
            ORDER BY started_at DESC
            LIMIT ? OFFSET ?
            """,
            (*params, limit, offset),
        ).fetchall()

    return {
        "total": int(total),
        "limit": limit,
        "offset": offset,
        "sessions": [dict(r) for r in rows],
    }


def get_session(
    session_id: str, *, db_path: str | Path | None = None
) -> dict[str, Any] | None:
    """Retrieve a full scan session document by `session_id`."""
    init_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM scan_sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
    if row is None:
        return None
    doc = json.loads(row["report_json"])
    doc["session_dir"] = row["session_dir"]
    return doc


def delete_session(session_id: str, *, db_path: str | Path | None = None) -> bool:
    """Delete a session entry from SQLite."""
    init_db(db_path)
    with _connect(db_path) as conn:
        cur = conn.execute(
            "DELETE FROM scan_sessions WHERE session_id = ?", (session_id,)
        )
        return cur.rowcount > 0


def cleanup_retention(
    *,
    db_path: str | Path | None = None,
    retention_days: int = 90,
    max_sessions: int = 250,
) -> int:
    """Prune sessions older than `retention_days` or exceeding `max_sessions`."""
    init_db(db_path)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, retention_days))).isoformat()
    with _connect(db_path) as conn:
        c1 = conn.execute(
            "DELETE FROM scan_sessions WHERE started_at < ?", (cutoff,)
        ).rowcount
        c2 = conn.execute(
            """
            DELETE FROM scan_sessions
            WHERE session_id NOT IN (
                SELECT session_id FROM scan_sessions
                ORDER BY started_at DESC
                LIMIT ?
            )
            """,
            (max(10, max_sessions),),
        ).rowcount
    return int(c1 + c2)


def load_report_file(path_or_dir: str | Path) -> dict[str, Any]:
    """Load an Om JSON report from a file path or a session directory."""
    candidate = Path(path_or_dir).expanduser()
    if candidate.is_dir():
        candidate = candidate / "report.json"
    if not candidate.is_file():
        raise FileNotFoundError(f"Report file not found: {candidate}")
    doc = json.loads(candidate.read_text(encoding="utf-8"))
    validate_report_schema(doc)
    return doc
