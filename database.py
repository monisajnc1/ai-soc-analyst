import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path

# ---- Cloud-Proof Database Path ----
# Detects if running on Streamlit Cloud or local
if os.path.exists("/mount/src/ai-soc-analyst"):
    # Streamlit Cloud environment: use /tmp (always writable)
    DB_FILE = "/tmp/soc_triage.db"
else:
    # Local environment: use project folder
    DB_FILE = str(Path(__file__).parent / "soc_triage.db")


def init_db():
    """Create the alerts table if it doesn't exist."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT,
            source_ip     TEXT,
            dest_ip       TEXT,
            event_type    TEXT,
            severity      TEXT,
            message       TEXT,
            raw_log       TEXT,
            vt_result     TEXT,
            mitre_tag     TEXT,
            ai_summary    TEXT,
            response_plan TEXT,
            status        TEXT DEFAULT 'New'
        )
    """)
    conn.commit()
    conn.close()


def insert_alert(alert_dict):
    """Insert a new alert row and return its row id."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO alerts
            (timestamp, source_ip, dest_ip, event_type, severity, message, raw_log)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        alert_dict.get("timestamp", datetime.now().isoformat()),
        alert_dict.get("source_ip") or alert_dict.get("src_ip"),
        alert_dict.get("dest_ip") or alert_dict.get("destination"),
        alert_dict.get("event_type") or alert_dict.get("type"),
        alert_dict.get("severity", "Medium"),
        alert_dict.get("message") or alert_dict.get("msg"),
        json.dumps(alert_dict),
    ))
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    return row_id


def update_alert(row_id, fields: dict):
    """Update specific columns for a given alert id."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    set_expr = ", ".join(f"{col} = ?" for col in fields)
    values = list(fields.values()) + [row_id]
    cur.execute(f"UPDATE alerts SET {set_expr} WHERE id = ?", values)
    conn.commit()
    conn.close()


def get_all_alerts():
    """Return every alert as a list of dicts, newest first."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM alerts ORDER BY id DESC")
        rows = [dict(r) for r in cur.fetchall()]
    except sqlite3.OperationalError:
        # Table might not exist yet if no alerts triaged
        rows = []
    finally:
        conn.close()
    return rows


def clear_all_alerts():
    """Drop all rows from the alerts table."""
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
