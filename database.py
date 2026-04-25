"""
database.py
-----------
Handles SQLite storage for scan history, analytics, and dashboard data.
Uses Python's built-in sqlite3 — no external DB dependency required.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "phishing_logs.db"


def get_connection() -> sqlite3.Connection:
    """Returns a connection to the SQLite database."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row  # Enable dict-like row access
    return conn


def init_db():
    """Creates the database tables if they don't exist yet."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                url         TEXT    NOT NULL,
                risk_score  REAL    NOT NULL,
                classification TEXT NOT NULL,
                details     TEXT,           -- JSON blob of full analysis
                scanned_at  TEXT    NOT NULL
            )
        """)
        conn.commit()


def save_scan(url: str, risk_score: float, classification: str, details: dict):
    """Persists a scan result to the database."""
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO scans (url, risk_score, classification, details, scanned_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                url,
                risk_score,
                classification,
                json.dumps(details),
                datetime.utcnow().isoformat()
            )
        )
        conn.commit()


def get_recent_scans(limit: int = 50) -> list:
    """Returns the most recent scan results."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    """
    Returns aggregate statistics for the dashboard:
      - total scans
      - phishing count
      - suspicious count
      - safe count
    """
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        phishing = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE classification = 'Phishing'"
        ).fetchone()[0]
        suspicious = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE classification = 'Suspicious'"
        ).fetchone()[0]
        safe = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE classification = 'Safe'"
        ).fetchone()[0]

    return {
        "total": total,
        "phishing": phishing,
        "suspicious": suspicious,
        "safe": safe,
    }


def get_daily_counts(days: int = 14) -> list:
    """
    Returns daily scan counts broken down by classification
    for charting purposes.
    """
    with get_connection() as conn:
        rows = conn.execute(f"""
            SELECT
                DATE(scanned_at) as date,
                classification,
                COUNT(*) as count
            FROM scans
            WHERE scanned_at >= DATE('now', '-{days} days')
            GROUP BY DATE(scanned_at), classification
            ORDER BY date ASC
        """).fetchall()
    return [dict(r) for r in rows]
