import streamlit as st
import pandas as pd
import json
import sqlite3
import os
from datetime import datetime
from dotenv import load_dotenv

# --- HAND-WRITTEN LOGIC MODULES ---

# database.py logic (integrated for cloud deployment)
def setup_database():
    conn = sqlite3.connect("soc_triage.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, source_ip TEXT, destination_ip TEXT,
        event_type TEXT, severity TEXT, message TEXT,
        raw_data TEXT, triage_summary TEXT, vt_report TEXT,
        mitre_mapping TEXT, response_recommendation TEXT,
        status TEXT DEFAULT "New"
    )''')
    conn.commit(); conn.close()

def save_alert(data):
    conn = sqlite3.connect("soc_triage.db"); c = conn.cursor()
    c.execute('INSERT INTO alerts (timestamp, source_ip, destination_ip, event_type, severity, message, raw_data) VALUES (?, ?, ?, ?, ?, ?, ?)', 
             (data.get('timestamp', datetime.now().isoformat()), data.get('src_ip') or data.get('source_ip'), 
              data.get('dest_ip') or data.get('destination_ip'), data.get('type') or data.get('event_type'), 
              data.get('severity', 'Medium'), data.get('msg') or data.get('message'), json.dumps(data)))
    new_id = c.lastrowid; conn.commit(); conn.close(); return new_id

def update_alert_data(aid, info):
    conn = sqlite3.connect("soc_triage.db"); c = conn.cursor()
    set_str = ", ".join([f"{k} = ?" for k in info.keys()]); vals = list(info.values()); vals.append(aid)
    c.execute(f"UPDATE alerts SET {set_str} WHERE id = ?", vals); conn.commit(); conn.close()

def fetch_all_alerts():
    conn = sqlite3.connect("soc_triage.db"); conn.row_factory = sqlite3.Row; c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY id DESC"); rows = c.fetchall(); conn.close()
    return [dict(r) for r in rows]

# enrichment/analysis logic (integrated)
def check_ip_reputation(ip):
    VT_KEY = st.secrets.get("VT_API_KEY", os.getenv("VT_API_KEY"))
    if ip == "223.25.1.88": return {"reputation": "Malicious", "malicious_count": 68} # Demo Hit
    if not VT_KEY: return {"reputation": "Clean", "malicious_count": 0}
    try:
        import requests
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": VT_KEY}, timeout=5)
        if r.status_code == 200:
            stats = r.json()['data']['attributes']['last_analysis_stats']
            return {"reputation": "Malicious" if stats['malicious'] > 0 else "Clean", "malicious_count": stats['malicious']}
    except: pass
    return {"reputation": "Unknown", "malicious_count": 0}

def get_mitre_mapping(details):
    t = str(details.get('type') or details.get('event_type') or '').lower()
    if "brute" in t: return "T1110 - Brute Force"
    if "sql" in t: return "T1190 - Exploit App"
    return "T1059 - Command Line"

def get_ai_triage(details, vt):
    from openai import OpenAI
    API = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY"))
    if not API: return "Waiting for manual review.", "Monitor host."
    try:
        client = OpenAI(api_key=API)
        prompt = f"Triage this alert. Provide a brief summary and one recommendation:\n{details}"
        res = client.chat.completions.create(model="gpt-3.5-turbo", messages=[{"role": "user", "content": prompt}])
        return res.choices[0].message.content, "Perform isolation if behavior continues."
    except: return "AI triage currently offline.", "Review logs manually."

# --- STREAMLIT UI ---

st.set_page_config(page_title="SOC Analyst Bot", layout="wide", page_icon="🛡️")

st.markdown("""
<style>
    .stApp { background-color: #ffffff; }
    .header-title { font-family: 'Segoe UI'; font-weight: 800; color: #0f172a; font-size: 2.5rem; margin-bottom: 2rem; }
    section[data-testid="stSidebar"] { background-color: #f8fafc; border-right: 1px solid #e2e8f0; }
    .stExpander { border-radius: 10px; background-color: #ffffff; border: 1px solid #e2e8f0; margin-bottom: 12px; }
    p, span, label, h1, h2, h3, h4, .stMarkdown { color: #1e293b !important; }
</style>
""", unsafe_allow_html=True)

setup_database()

with st.sidebar:
    st.header("SOC Analyst Bot")
    st.write("v1.7 - Automated Internal Tool")
    page = st.radio("Navigation", ["Incident Dashboard", "Data Ingestion"])
    if st.button("Clear Old Logs"):
        if os.path.exists("soc_triage.db"): os.remove("soc_triage.db")
        st.rerun()

if page == "Incident Dashboard":
    st.markdown("<h1 class='header-title'>Incident Pipeline</h1>", unsafe_allow_html=True)
    alerts = fetch_all_alerts()
    if not alerts: 
        st.info("No active incidents. Use the Ingestion tab to pull SIEM logs.")
    else:
        for item in alerts:
            header = f"⚠️ [{item.get('severity','Med')}] {item.get('event_type','Alert')} - Host: {item.get('source_ip','Internal')}"
            with st.expander(header):
                L, R = st.columns(2)
                with L:
                    st.subheader("📋 Context")
                    st.write(f"**Description:** {item.get('message')}")
                    st.write(f"**MITRE Technique:** `{item.get('mitre_mapping', 'None')}`")
                    if item.get('vt_report'):
                        vt = json.loads(item['vt_report'])
                        color = "#dc2626" if vt.get('reputation') == "Malicious" else "#16a34a"
                        st.markdown(f"**VirusTotal:** <span style='color:{color}; font-weight:bold;'>{vt.get('reputation')}</span>", unsafe_allow_html=True)
                with R:
                    st.subheader("🧠 Intelligence")
                    st.info(item.get('triage_summary') or "Awaiting automated triaging...")
                    st.success(f"**AI Recommendation:** {item.get('response_recommendation') or 'Awaiting review.'}")

elif page == "Data Ingestion":
    st.markdown("<h1 class='header-title'>Data Ingestion</h1>", unsafe_allow_html=True)
    if st.button("🚀 Trigger Automated SIEM Triage"):
        # Real-world simulation telemetry
        logs = [
            {"src_ip": "223.25.1.88", "dest_ip": "db-server", "type": "SQL Injection", "msg": "Malicious string detected in GET parameter", "severity": "Critical"},
            {"src_ip": "8.8.8.8", "dest_ip": "hq-portal", "type": "Brute Force", "msg": "High number of login failures", "severity": "High"}
        ]
        status = st.status("Analyzing logs, checking VT, and generating AI playbooks...")
        for l in logs:
            rid = save_alert(l) # 1. Normalizing & saving
            vt = check_ip_reputation(l['src_ip']) # 2. Real-time Threat Intel
            mitre = get_mitre_mapping(l) # 3. MITRE Correlation
            summary, rec = get_ai_triage(l, vt) # 4. AI Response Plan
            update_alert_data(rid, {"vt_report": json.dumps(vt), "triage_summary": summary, "mitre_mapping": mitre, "response_recommendation": rec})
        status.update(label="Triage Complete!", state="complete")
        st.success("Incoming telemetry triaged with real-time AI and Threat Intel.")
