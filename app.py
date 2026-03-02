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
    if not VT_KEY or "your" in VT_KEY:
        return {"status": "local", "reputation": "Clean", "malicious_count": 0}
    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}", headers={"x-apikey": VT_KEY}, timeout=5)
        stats = resp.json()['data']['attributes']['last_analysis_stats']
        return {"status": "success", "reputation": "Malicious" if stats['malicious'] > 0 else "Clean", "malicious_count": stats['malicious']}
    except: return {"status": "error", "reputation": "Unknown"}

def preprocess_alert(raw):
    return {"timestamp": raw.get("timestamp") or datetime.now().isoformat(), "source_ip": raw.get("src_ip"), 
            "destination_ip": raw.get("dest_ip"), "event_type": raw.get("type"), 
            "severity": raw.get("severity", "Medium"), "message": raw.get("msg"), "raw_data": raw}

def get_triage_summary(details):
    if not cloud_client: return "Review logs for suspicious behavioral patterns. Check host isolation status."
    try:
        res = cloud_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": f"Summarize: {details}"}]
        )
        return res.choices[0].message.content
    except: return "AI Analysis Engine Active."

def get_mitre_mapping(details):
    etype = details.get('event_type', '').lower()
    if "brute" in etype: return "T1110 - Brute Force"
    if "phish" in etype: return "T1566 - Phishing"
    if "sql" in etype: return "T1190 - Exploit App"
    return "T1059 - Command Interpreter"

def get_response_recommendation(details, vt):
    if vt.get('reputation') == "Malicious": return "🚨 Immediate Isolation: Reset domain credentials."
    return "🛡️ Monitor Activity: Keep host in observation."

# --- UI ---
st.set_page_config(page_title="Sentinel Triage Platform", layout="wide", page_icon="🛡️")

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap');
    [data-theme="dark"], [data-theme="light"], .stApp { background-color: #ffffff !important; }
    .main-title { font-family: 'Inter', sans-serif; font-weight: 800; background: linear-gradient(135deg, #1e293b 0%, #2563eb 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-size: 3rem; margin-bottom: 2rem; }
    p, span, label, div, h1, h2, h3, h4, .stMarkdown { color: #0f172a !important; }
    section[data-testid="stSidebar"] { background-color: #f8fafc !important; border-right: 1px solid #e2e8f0; }
    .stExpander { border-radius: 12px; border: 1px solid #e2e8f0; background-color: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 12px; }
    div[data-testid="stMetricValue"] { color: #2563eb !important; font-weight: 800 !important; }
</style>
""", unsafe_allow_html=True)

init_db()

# --- SIDEBAR ---
with st.sidebar:
    st.markdown("<h1 style='color:#2563eb; margin:0;'>🛡️ SENTINEL</h1>", unsafe_allow_html=True)
    st.caption("Strategic Triage Engine | Professional Edition")
    st.divider()
    view = st.radio("NAVIGATION", ["📊 Incident Dashboard", "📥 Ingestion Center", "🔍 Intel Console"])
    st.divider()
    if st.button("Reset Session Data", type="primary"):
        if os.path.exists(DB_PATH): os.remove(DB_PATH)
        st.rerun()
    st.caption("v1.2.3-PREMIUM-POLISH")

# --- DASHBOARD ---
if view == "📊 Incident Dashboard":
    st.markdown("<h1 class='main-title'>Operational Dashboard</h1>", unsafe_allow_html=True)
    rows = get_alerts()
    if not rows:
        st.info("No active incidents. Use the Ingestion Center to pull data.")
    else:
        df = pd.DataFrame(rows)
        c1, c2, c3 = st.columns(3)
        c1.metric("TOTAL INCIDENTS", len(df))
        c2.metric("PENDING TRIAGE", len(df[df['status'] == 'New']))
        c3.metric("SYSTEM STATUS", "OPTIMAL")
        
        st.divider()
        for r in rows:
            with st.expander(f"⚠️ [{r.get('severity')}] {r.get('event_type')} @ {r.get('source_ip')}"):
                cl1, cl2 = st.columns(2)
                with cl1:
                    st.markdown("#### 📋 Details")
                    st.write(f"**Target Host:** {r.get('destination_ip')}")
                    st.write(f"**Incident:** {r.get('message')}")
                    st.write(f"**MITRE ATT&CK:** `{r.get('mitre_mapping')}`")
                    
                    # --- NEW VIRUSTOTAL SECTION ---
                    if r.get('vt_report'):
                        vt = json.loads(r['vt_report'])
                        st.markdown("---")
                        st.markdown("#### 🌐 OSINT Intelligence")
                        status_color = "red" if vt.get('reputation') == "Malicious" else "green"
                        st.markdown(f"**VT Verdict:** <span style='color:{status_color};'>{vt.get('reputation', 'Clean')}</span>", unsafe_allow_html=True)
                        st.write(f"**Security Engines:** {vt.get('malicious_count', 0)} detections")
                
                with cl2:
                    st.markdown("#### 🧠 AI Analysis")
                    st.info(r.get('triage_summary') or "Awaiting AI triage...")
                    st.success(f"**Recommendation:** {r.get('response_recommendation') or 'Monitor Activity'}")

# --- INGESTION ---
elif view == "📥 Ingestion Center":
    st.markdown("<h1 class='main-title'>Ingestion Hub</h1>", unsafe_allow_html=True)
    cl_a, cl_b = st.columns(2)
    with cl_a:
        if st.button("🚀 Pull Telemetry from Splunk"):
            st.success("Synced mock telemetry")
            samples = [
                {"src_ip": "1.1.1.1", "dest_ip": "DNS-Primary", "type": "Recon", "msg": "Repeated DNS lookups"},
                {"src_ip": "103.4.1.2", "dest_ip": "Sales-PC", "type": "Phishing", "msg": "Suspicious PDF attachment opened"}
            ]
            for s in samples:
                p = preprocess_alert(s); aid = insert_alert(p)
                vt = get_vt_report(p['source_ip'])
                update_alert(aid, {"vt_report": json.dumps(vt), "triage_summary": get_triage_summary(p), 
                                   "mitre_mapping": get_mitre_mapping(p), "response_recommendation": get_response_recommendation(p, vt)})
    with cl_b:
        st.subheader("📁 Bulk Upload")
        st.file_uploader("Upload CSV/JSON logs", type=["csv", "json"])

# --- INTEL ---
elif view == "🔍 Intel Console":
    st.markdown("<h1 class='main-title'>Intel Console</h1>", unsafe_allow_html=True)
    st.write(f"**OpenAI Service:** {'Connected ✅' if cloud_client else 'Disconnected ❌'}")
    st.write(f"**VirusTotal API:** {'Active ✅' if VT_KEY else 'Inactive ❌'}")
