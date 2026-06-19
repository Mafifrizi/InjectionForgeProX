import sqlite3
from datetime import datetime
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_NAME = str(PROJECT_ROOT / "injectionforge_results.db")


def _connect():
    conn = sqlite3.connect(DB_NAME, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            target TEXT,
            payload TEXT,
            response TEXT,
            success BOOLEAN,
            confidence REAL,
            method TEXT,
            leak_category TEXT,
            severity TEXT,
            leaked_data TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_result(target, result):
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        INSERT INTO results (timestamp, target, payload, response, success, confidence, method, leak_category, severity, leaked_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        target,
        result.get("payload", ""),
        result.get("response", ""),
        result.get("success", False),
        result.get("confidence", 0),
        result.get("method", ""),
        result.get("leak_category", ""),
        result.get("severity", "Info"),
        json.dumps(result.get("leaked_data", []))
    ))
    conn.commit()
    conn.close()
