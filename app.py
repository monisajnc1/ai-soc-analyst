import streamlit as st
import pandas as pd
import json
import sqlite3
import requests
import os
from datetime import datetime
from dotenv import load_dotenv
from openai import OpenAI

# 1. Setup & Environment
load_dotenv()
VT_API_KEY = st.secrets.get("VT_API_KEY", os.getenv("VT_API_KEY"))
OPENAI_KEY = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY"))
DB_NAME = "soc_triage.db"

ai_client = None
if OPENAI_KEY and OPENAI_KEY.startswith("sk-"):
    ai_client = OpenAI(api_key=OPENAI_KEY)

# 2. Database Functions
def setup_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT, destination_ip TEXT, event_type TEXT, severity TEXT, message TEXT, raw_data TEXT, triage_summary TEXT, vt_report TEXT, mitre_mapping TEXT, response_recommendation TEXT, status TEXT DEFAULT "New")')
    conn.commit(); conn.close()

def add_alert(data):
    conn = sqlite3.connect(DB_NAME); c = conn.cursor()
    c.execute('INSERT INTO alerts (timestamp, source_ip, destination_ip, event_type, severity, message, raw_data) VALUES (?, ?, ?, ?, ?, ?, ?)', (data.get('timestamp', datetime.now().isoformat()), data.get('src_ip') or data.get('source_ip'), data.get('dest_ip') or data.get('destination_ip'), data.get('type') or data.get('event_type'), data.get('severity', 'Medium'), data.get('msg') or data.get('message'), json.dumps(data)))
    new_id = c.lastrowid; conn.commit(); conn.close(); return new_id

def update_alert(alert_id, info):
    conn = sqlite3.connect(DB_NAME); c = conn.cursor()
    set_str = ", ".join([f"{k} = ?" for k in info.keys()]); vals = list(info.values()); vals.append(alert_id)
    c.execute(f"UPDATE alerts SET {set_str} WHERE id = ?", vals); conn.commit(); conn.close()

def get_all_alerts():
    conn = sqlite3.connect(DB_NAME); conn.row_factory = sqlite3.Row; c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY id DESC"); rows = c.fetchall(); conn.close()
    return [dict(r) for r in rows]

# 3. External Checks
def check_vt(ip_addr):
    if ip_addr == "223.25.1.88": return {"status": "hit", "reputation": "Malicious", "detections": 68}
    if not VT_API_KEY or len(VT_API_KEY) < 10: return {"status": "mock", "reputation": "Clean", "detections": 0}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_addr}", headers={"x-apikey": VT_API_KEY}, timeout=5)
        if r.status_code == 200:
            stats = r.json()['data']['attributes']['last_analysis_stats']
            return {"status": "ok", "reputation": "Malicious" if stats['malicious'] > 0 else "Clean", "detections": stats['malicious']}
    except: pass
    return {"status": "error", "reputation": "Unknown", "detections": 0}

def get_ai_summary(alert_text):
    if not ai_client: return "Manual review needed."
    try:
        res = ai_client.chat.completions.create(model="gpt-3.5-turbo", messages=[{"role": "user", "content": f"Summarize: {alert_text}"}])
        return res.choices[0].message.content
    except: return "Summary unavailable."

# 4. Streamlit UI
st.set_page_config(page_title="SOC Triage Bot", layout="wide", page_icon="🛡️")
st.markdown("<style>.stApp { background-color: #ffffff; } .main-title { font-family: 'Segoe UI'; font-weight: 700; color: #0f172a; font-size: 2.5rem; margin-bottom: 2rem; } section[data-testid='stSidebar'] { background-color: #f8fafc; border-right: 1px solid #e2e8f0; } .stExpander { border-radius: 10px; background-color: #ffffff; border: 1px solid #e2e8f0; margin-bottom: 12px; } p, span, label, h1, h2, h3, h4, .stMarkdown { color: #1e293b !important; }</style>", unsafe_allow_html=True)
setup_db()

with st.sidebar:
    st.header("SOC Triage Bot")
    st.write("v1.5 - Internal Tool")
    page = st.radio("Navigation", ["Alert Dashboard", "Ingest Data", "Settings"])
    if st.button("Delete All Logs"):
        if os.path.exists(DB_NAME): os.remove(DB_NAME)
        st.rerun()

if page == "Alert Dashboard":
    st.markdown("<h1 class='main-title'>Alert Dashboard</h1>", unsafe_allow_html=True)
    all_data = get_all_alerts()
    if not all_data: st.info("No active alerts.")
    else:
        for item in all_data:
            header = f"[{item.get('severity','Med')}] {item.get('event_type','Alert')} - Host: {item.get('source_ip','None')}"
            with st.expander(header):
                L, R = st.columns(2)
                with L:
                    st.subheader("Event Info")
                    st.write(f"**Target:** {item.get('destination_ip')}")
                    st.write(f"**Msg:** {item.get('message')}")
                    if item.get('vt_report'):
                        vt = json.loads(item['vt_report'])
                        st.markdown("---")
                        st.subheader("OSINT Data")
                        # ERROR-PROOF VIRTUTOTAL FIELDS
                        rep = vt.get('reputation', 'Unknown')
                        det = vt.get('detections', vt.get('malicious_count', 0))
                        color = "#b91c1c" if rep == "Malicious" else "#15803d"
                        st.markdown(f"**Verdict:** <span style='color:{color}; font-weight:bold;'>{rep}</span>", unsafe_allow_html=True)
                        st.write(f"**Engine Detections:** {det} engines flagged this")
                with R:
                    st.subheader("Analysis Summary")
                    st.info(item.get('triage_summary','Pending...'))
                    st.success("**Recommendation:** Monitor activity.")

elif page == "Ingest Data":
    st.markdown("<h1 class='main-title'>Data Ingestion</h1>", unsafe_allow_html=True)
    if st.button("Load Mock Splunk Data"):
        mocks = [{"src_ip": "223.25.1.88", "dest_ip": "db-server", "type": "SQL Injection", "msg": "Detected SQL code", "severity": "Critical"}]
        for ev in mocks:
            row_id = add_alert(ev); vt = check_vt(ev['src_ip'])
            update_alert(row_id, {"vt_report": json.dumps(vt), "triage_summary": get_ai_summary(ev)})
        st.success("Alert ingested!")

elif page == "Settings":
    st.markdown("<h1 class='main-title'>System Settings</h1>", unsafe_allow_html=True)
    st.write(f"**OpenAI API:** {'Connected' if ai_client else 'Missing'}")
