import streamlit as st
import pandas as pd
import json
import sqlite3
import requests
import os
from datetime import datetime
from dotenv import load_dotenv
from openai import OpenAI

# --- INITIALIZE ENVIRONMENT ---
load_dotenv()
VT_KEY = os.getenv("VT_API_KEY")
PROV_KEY = os.getenv("OPENAI_API_KEY")
DB_PATH = "soc_triage.db"

# Set up AI client
cloud_client = None
if PROV_KEY and PROV_KEY.startswith("sk-") and "demo-key" not in PROV_KEY:
    cloud_client = OpenAI(api_key=PROV_KEY)

# --- DATABASE LOGIC ---
def init_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, source_ip TEXT, destination_ip TEXT,
            event_type TEXT, severity TEXT, message TEXT,
            raw_data TEXT, triage_summary TEXT, vt_report TEXT,
            mitre_mapping TEXT, response_recommendation TEXT,
            status TEXT DEFAULT 'New', assigned_to TEXT DEFAULT 'Unassigned',
            comments TEXT DEFAULT '[]'
        )
    ''')
    db.commit()
    db.close()

def insert_alert(data):
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.execute('''
        INSERT INTO alerts (timestamp, source_ip, destination_ip, event_type, severity, message, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (data.get('timestamp', datetime.now().isoformat()), data.get('source_ip'), data.get('destination_ip'),
          data.get('event_type'), data.get('severity', 'Medium'), data.get('message'), json.dumps(data.get('raw_data', {}))))
    new_id = cur.lastrowid
    db.commit()
    db.close()
    return new_id

def update_alert(alert_id, fields):
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
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

# --- ENRICHMENT & ANALYSIS LOGIC ---
def get_vt_report(indicator):
    if not VT_KEY or "simulation-hub" in VT_KEY:
        return {"status": "local_heuristic", "indicator": indicator, "reputation": "Clean", "malicious_count": 0}
    api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    try:
        resp = requests.get(api_url, headers={"x-apikey": VT_KEY})
        stats = resp.json()['data']['attributes']['last_analysis_stats']
        return {"status": "success", "reputation": "Malicious" if stats['malicious'] > 0 else "Clean", "malicious_count": stats['malicious']}
    except:
        return {"status": "error", "reputation": "Unknown"}

def preprocess_alert(raw):
    return {"timestamp": raw.get("timestamp") or datetime.now().isoformat(), "source_ip": raw.get("src_ip"), 
            "destination_ip": raw.get("dest_ip"), "event_type": raw.get("type"), 
            "severity": raw.get("severity", "Medium"), "message": raw.get("msg"), "raw_data": raw}

def get_triage_summary(details):
    if not cloud_client: return "Local analysis: Review logs for suspicious patterns."
    try:
        res = cloud_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": f"Summarize this security alert: {details}"}]
        )
        return res.choices[0].message.content
    except: return "AI Triage unavailable."

def get_mitre_mapping(details):
    return "T1595 - Active Scanning"

def get_response_recommendation(details, vt):
    if vt.get('reputation') == "Malicious": return "Isolate Host immediately."
    return "Monitor activity."

def classify_severity(details, vt):
    return "High" if vt.get('malicious_count', 0) > 0 else details.get('severity', 'Medium')

# --- UI & THEME ---
st.set_page_config(page_title="Sentinel Triage Platform", layout="wide", page_icon="🛡️")

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap');
    [data-theme="dark"], [data-theme="light"], .stApp { background-color: #ffffff !important; color: #0f172a !important; }
    .main-title { font-family: 'Inter', sans-serif; font-weight: 800; background: linear-gradient(135deg, #1e293b 0%, #2563eb 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-size: 3rem; }
    p, span, label, div, h1, h2, h3, h4 { color: #0f172a !important; }
    section[data-testid="stSidebar"] { background-color: #f8fafc !important; }
    .stExpander { border-radius: 12px; border: 1px solid #e2e8f0; background-color: #ffffff; }
</style>
""", unsafe_allow_html=True)

init_db()

# --- SIDEBAR ---
with st.sidebar:
    st.markdown("<h1 style='color:#2563eb;'>🛡️ SENTINEL</h1>", unsafe_allow_html=True)
    st.caption("Strategic Triage Engine v1.2.0-ULTIMATE-LIGHT")
    view = st.radio("NAVIGATION", ["📊 Dashboard", "📥 Ingestion"])
    st.info("Operational Status: ONLINE")

# --- DASHBOARD ---
if view == "📊 Dashboard":
    st.markdown("<h1 class='main-title'>Operational Dashboard</h1>", unsafe_allow_html=True)
    rows = get_alerts()
    if not rows:
        st.warning("No incidents detected.")
    else:
        for r in rows:
            with st.expander(f"{r['event_type']} @ {r['source_ip']}"):
                st.write(f"**Message:** {r['message']}")
                st.info(f"**Analysis:** {r['triage_summary']}")

# --- INGESTION ---
elif view == "📥 Ingestion":
    st.markdown("<h1 class='main-title'>Ingestion Hub</h1>", unsafe_allow_html=True)
    if st.button("Simulate Attack"):
        a = {"src_ip": "10.0.0.1", "dest_ip": "Server-01", "type": "SQL Injection", "msg": "Malicious payload detected"}
        proc = preprocess_alert(a)
        aid = insert_alert(proc)
        vt = get_vt_report(proc['source_ip'])
        update_alert(aid, {"vt_report": json.dumps(vt), "triage_summary": get_triage_summary(proc)})
        st.success("Alert ingested! Check dashboard.")
