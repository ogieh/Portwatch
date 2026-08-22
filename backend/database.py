import sqlite3
import json
from datetime import datetime

DB_PATH = "scans.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            summary TEXT NOT NULL,
            full_data TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_scan(scan_data):
    """
    scan_data is the full dict returned by scanner.run_scan(), i.e.
    {"target": ..., "ports": [...], "summary": ...}
    We stamp a timestamp and id, store the whole thing as JSON so it can be
    reloaded exactly as-is later via GET /api/history/<id>.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    timestamp = datetime.utcnow().isoformat()
    record = dict(scan_data)
    record["timestamp"] = timestamp

    cursor.execute(
        "INSERT INTO scans (target, timestamp, summary, full_data) VALUES (?, ?, ?, ?)",
        (scan_data["target"], timestamp, scan_data.get("summary", ""), json.dumps(record)),
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()

    record["id"] = scan_id
    return record


def get_history():
    """Lightweight list for the history table: id, target, timestamp, summary."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, target, timestamp, summary FROM scans ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()

    return [
        {"id": r["id"], "target": r["target"], "timestamp": r["timestamp"], "summary": r["summary"]}
        for r in rows
    ]


def get_scan_by_id(scan_id):
    """Full scan data for reloading into the results view via 'Load'."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT full_data FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return None

    data = json.loads(row["full_data"])
    data["id"] = scan_id
    return data
