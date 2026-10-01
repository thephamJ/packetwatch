"""SQLite storage for alerts.

All queries use parameter binding (``?`` placeholders); user-supplied values
are never concatenated into SQL strings.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, Iterable, List, Optional

from packetwatch.models import Alert

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    detector    TEXT    NOT NULL,
    severity    TEXT    NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    src         TEXT    NOT NULL,
    dst         TEXT,
    description TEXT    NOT NULL,
    details     TEXT    NOT NULL,
    source      TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts (ts);
CREATE INDEX IF NOT EXISTS idx_alerts_src      ON alerts (src);
CREATE INDEX IF NOT EXISTS idx_alerts_detector ON alerts (detector);
"""


def connect(path: str = "packetwatch.db") -> sqlite3.Connection:
    """Open (and initialise) the alert database."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def insert_alerts(
    conn: sqlite3.Connection, alerts: Iterable[Alert], source: Optional[str] = None
) -> int:
    """Insert alerts and return how many rows were written."""
    rows = [
        (a.timestamp, a.detector, a.severity, a.src, a.dst, a.description,
         json.dumps(a.details), source)
        for a in alerts
    ]
    with conn:
        conn.executemany(
            "INSERT INTO alerts (ts, detector, severity, src, dst, description, details, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    return len(rows)


def query_alerts(
    conn: sqlite3.Connection,
    detector: Optional[str] = None,
    severity: Optional[str] = None,
    src: Optional[str] = None,
    since: Optional[float] = None,
    until: Optional[float] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Return alerts matching the filters, newest first."""
    clauses, params = [], []
    if detector:
        clauses.append("detector = ?")
        params.append(detector)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if src:
        clauses.append("src = ?")
        params.append(src)
    if since is not None:
        clauses.append("ts >= ?")
        params.append(since)
    if until is not None:
        clauses.append("ts <= ?")
        params.append(until)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT * FROM alerts {where} ORDER BY ts DESC, id DESC LIMIT ?"
    params.append(limit)
    return [dict(row) for row in conn.execute(sql, params)]


def top_sources(conn: sqlite3.Connection, limit: int = 10) -> List[Dict[str, Any]]:
    """Sources ranked by number of alerts (ties broken by worst severity seen)."""
    sql = """
        SELECT src,
               COUNT(*) AS alert_count,
               MAX(CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) AS worst
        FROM alerts
        GROUP BY src
        ORDER BY alert_count DESC, worst DESC, src
        LIMIT ?
    """
    names = {3: "high", 2: "medium", 1: "low"}
    out = []
    for row in conn.execute(sql, (limit,)):
        out.append({"src": row["src"], "alert_count": row["alert_count"],
                    "worst_severity": names[row["worst"]]})
    return out


def counts_by_detector(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    sql = "SELECT detector, COUNT(*) AS alert_count FROM alerts GROUP BY detector ORDER BY alert_count DESC"
    return [dict(row) for row in conn.execute(sql)]
