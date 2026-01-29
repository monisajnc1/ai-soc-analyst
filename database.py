import sqlite3
import json
from datetime import datetime

# Path to our local sqlite db
DB_PATH = "soc_triage.db"

def init_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    # Initial table setup
    cur.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            event_type TEXT,
            severity TEXT,
            message TEXT,
            raw_data TEXT,
            ai_analysis TEXT,
            vt_report TEXT,
            mitre_mapping TEXT,
            response_recommendation TEXT,
            status TEXT DEFAULT 'New',
            assigned_to TEXT DEFAULT 'Unassigned',
            comments TEXT DEFAULT '[]'
        )
    ''')
    db.commit()
    db.close()

def insert_alert(data):
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.execute('''
        INSERT INTO alerts (
            timestamp, source_ip, destination_ip, event_type, severity, message, raw_data
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('timestamp', datetime.now().isoformat()),
        data.get('source_ip'),
        data.get('destination_ip'),
        data.get('event_type'),
        data.get('severity', 'Medium'),
        data.get('message'),
        json.dumps(data.get('raw_data', {}))
    ))
    new_id = cur.lastrowid
    db.commit()
    db.close()
    return new_id

def update_alert(alert_id, fields):
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    
    # Dynamic update query based on passed dict
    clause = ", ".join([f"{k} = ?" for k in fields.keys()])
    vals = list(fields.values())
    vals.append(alert_id)
    
    cur.execute(f"UPDATE alerts SET {clause} WHERE id = ?", vals)
    db.commit()
    db.close()

def get_alerts():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    cur = db.cursor()
    cur.execute("SELECT * FROM alerts ORDER BY id DESC")
    rows = cur.fetchall()
    db.close()
    return [dict(r) for r in rows]

if __name__ == "__main__":
    init_db()
    print("Database ready.")
