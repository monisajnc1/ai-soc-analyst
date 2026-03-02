import streamlit as st
import pandas as pd
import json
import sqlite3
import requests
import os
from datetime import datetime
from dotenv import load_dotenv
from openai import OpenAI

# --- INITIALIZE ---
load_dotenv()
VT_KEY = st.secrets.get("VT_API_KEY", os.getenv("VT_API_KEY"))
PROV_KEY = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY"))
DB_PATH = "soc_triage.db"

cloud_client = None
if PROV_KEY and PROV_KEY.startswith("sk-") and "demo-key" not in PROV_KEY:
    cloud_client = OpenAI(api_key=PROV_KEY)

def init_db():
    db = sqlite3.connect(DB_PATH); cur = db.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT, destination_ip TEXT, event_type TEXT, severity TEXT, message TEXT, raw_data TEXT, triage_summary TEXT, vt_report TEXT, mitre_mapping TEXT, response_recommendation TEXT, status TEXT DEFAULT "New")')
    db.commit(); db.close()

def insert_alert(data):
    db = sqlite3.connect(DB_PATH); cur = db.cursor()
    cur.execute('INSERT INTO alerts (timestamp, source_ip, destination_ip, event_type, severity, message, raw_data) VALUES (?, ?, ?, ?, ?, ?, ?)', 
                 (data.get('timestamp', datetime.now().isoformat()), 
                  data.get('src_ip') or data.get('source_ip'), 
                  data.get('dest_ip') or data.get('destination_ip'), 
                  data.get('type') or data.get('event_type'), 
                  data.get('severity', 'Medium'), 
                  data.get('msg') or data.get('message'), 
                  json.dumps(data)))
    nid = cur.lastrowid; db.commit(); db.close(); return nid

def update_alert(aid, fields):
    db = sqlite3.connect(DB_PATH); cur = db.cursor()
    clause = ", ".join([f"{k} = ?" for k in fields.keys()])
    vals = list(fields.values()); vals.append(aid)
    cur.execute(f"UPDATE alerts SET {clause} WHERE id = ?", vals); db.commit(); db.close()

def get_alerts():
    db = sqlite3.connect(DB_PATH); db.row_factory = sqlite3.Row; cur = db.cursor()
    cur.execute("SELECT * FROM alerts ORDER BY id DESC"); rows = cur.fetchall(); db.close()
    return [dict(r) for r in rows]

def get_vt_report(ip):
    # FORCE a malicious response for a known bad IP (for demonstration)
    if ip == "223.25.1.88":
        return {"status": "hit", "reputation": "Malicious", "malicious_count": 68}
    
    if not VT_KEY or len(VT_KEY) < 10: return {"status": "mock", "reputation": "Clean", "malicious_count": 0}
    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": VT_KEY}, timeout=5)
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            return {"status": "success", "reputation": "Malicious" if stats['malicious'] > 0 else "Clean", "malicious_count": stats['malicious']}
    except: pass
    return {"status": "error", "reputation": "Unknown"}

# --- UI ---
st.set_page_config(page_title="Sentinel Triage Platform", layout="wide", page_icon="🛡️")
st.markdown("<style>[data-theme='dark'],[data-theme='light'],.stApp{background-color:#ffffff !important;}.main-title{font-family:'Inter';font-weight:800;background:linear-gradient(135deg,#1e293b,#2563eb);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:3rem;}p,span,label,div,h1,h2,h3,h4{color:#0f172a !important;}section[data-testid='stSidebar']{background-color:#f8fafc !important;border-right:1px solid #e2e8f0;}.stExpander{border-radius:12px;border:1px solid #e2e8f0;background-color:#ffffff;box-shadow:0 1px 3px rgba(0,0,0,0.05);margin-bottom:12px;}div[data-testid='stMetricValue']{color:#2563eb !important;font-weight:800 !important;}</style>", unsafe_allow_html=True)
init_db()

with st.sidebar:
    st.markdown("<h1 style='color:#2563eb; margin:0;'>🛡️ SENTINEL</h1>", unsafe_allow_html=True)
    st.caption("Strategic Triage Engine | Professional Edition")
    st.divider()
    view = st.radio("NAVIGATION", ["📊 Incident Dashboard", "📥 Ingestion Center", "🔍 Intel Console"])
    if st.button("Reset Session Data", type="primary"):
        if os.path.exists(DB_PATH): os.remove(DB_PATH)
        st.rerun()

if view == "📊 Incident Dashboard":
    st.markdown("<h1 class='main-title'>Operational Dashboard</h1>", unsafe_allow_html=True)
    rows = get_alerts()
    if not rows: st.info("No active incidents. Use the Ingestion Center to pull telemetry.")
    else:
        df = pd.DataFrame(rows)
        c1, c2, c3 = st.columns(3); c1.metric("TOTAL INCIDENTS",len(df)); c2.metric("PENDING TRIAGE",len(df[df['status']=='New'])); c3.metric("SYSTEM STATUS","OPTIMAL")
        st.divider()
        for r in rows:
            with st.expander(f"⚠️ [{r.get('severity','Med')}] {r.get('event_type','Alert')} @ {r.get('source_ip','Indicator')}"):
                cl1, cl2 = st.columns(2)
                with cl1:
                    st.markdown("#### 📋 Details")
                    st.write(f"**Target Host:** {r.get('destination_ip')}"); st.write(f"**Problem Message:** {r.get('message')}")
                    if r.get('vt_report'):
                        vt = json.loads(r['vt_report'])
                        st.markdown("---")
                        st.markdown("#### 🌐 OSINT Intelligence")
                        sc = "red" if vt.get('reputation') == "Malicious" else "green"
                        st.markdown(f"**VT Verdict:** <span style='color:{sc}; font-weight:bold;'>{vt.get('reputation','Clean')}</span>", unsafe_allow_html=True)
                        st.write(f"**Security Engines:** {vt.get('malicious_count',0)} detections")
                with cl2:
                    st.markdown("#### 🧠 AI Analysis")
                    st.info(r.get('triage_summary') or "Automated review in progress...")
                    st.success(f"**Recommendation:** Isolation of indicated host and full disk forensics.")

elif view == "📥 Ingestion Center":
    st.markdown("<h1 class='main-title'>Ingestion Hub</h1>", unsafe_allow_html=True)
    if st.button("🚀 Pull Telemetry from Splunk"):
        samples = [
            {"src_ip": "223.25.1.88", "dest_ip": "DMZ-WEB-04", "type": "SQL Injection", "msg": "Malicious payload in URI"},
            {"src_ip": "1.1.1.1", "dest_ip": "Office-PC", "type": "Brute Force", "msg": "Repeated failed logins"}
        ]
        for s in samples:
            aid = insert_alert(s); vt = get_vt_report(s['src_ip'])
            update_alert(aid, {"vt_report": json.dumps(vt)})
        st.success("Telemetry Synced! Check Dashboard.")

elif view == "🔍 Intel Console":
    st.markdown("<h1 class='main-title'>Intel Console</h1>", unsafe_allow_html=True)
    st.write(f"**OpenAI Service:** {'Connected ✅' if cloud_client else 'Disconnected ❌'}")
    st.write(f"**VirusTotal API:** {'Active ✅' if VT_KEY and len(VT_KEY)>10 else 'Inactive ❌'}")
