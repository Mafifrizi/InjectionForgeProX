import sqlite3
from datetime import datetime
import json

DB_NAME = "injectionforge_results.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
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
    conn = sqlite3.connect(DB_NAME)
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