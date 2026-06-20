import sqlite3
from datetime import datetime
import json
from pathlib import Path

from .redaction import redact_result, redact_text
from .paths import default_runtime_file

DB_NAME = str(default_runtime_file("injectionforge_results.db"))


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


def save_result(target, result, redact: bool = True):
    """Persist a result safely.

    Runtime storage uses the same redaction policy as generated reports by
    default. This avoids silently retaining raw credentials in SQLite before a
    report is generated. Pass ``redact=False`` only for restricted local
    evidence handling.
    """
    stored = redact_result(result, enabled=redact)
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        INSERT INTO results (timestamp, target, payload, response, success, confidence, method, leak_category, severity, leaked_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        redact_text(str(target or "")),
        stored.get("payload", ""),
        stored.get("response", ""),
        stored.get("success", False),
        stored.get("confidence", 0),
        stored.get("method", ""),
        stored.get("leak_category", ""),
        stored.get("severity", "Info"),
        json.dumps(stored.get("leaked_data", []))
    ))
    conn.commit()
    conn.close()
