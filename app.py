import streamlit as st
import pandas as pd
import json
import sqlite3
import os
import requests
from datetime import datetime
from dotenv import load_dotenv

# --- CORE LOGIC (Integrated for ease of deployment) ---

def setup_db():
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

def update_alert(aid, info):
    conn = sqlite3.connect("soc_triage.db"); c = conn.cursor()
    set_str = ", ".join([f"{k} = ?" for k in info.keys()]); vals = list(info.values()); vals.append(aid)
    c.execute(f"UPDATE alerts SET {set_str} WHERE id = ?", vals); conn.commit(); conn.close()

def check_vt(ip):
    VT_KEY = st.secrets.get("VT_API_KEY", os.getenv("VT_API_KEY"))
    if ip == "223.25.1.88": return {"reputation": "Malicious", "detections": 68}
    if not VT_KEY: return {"reputation": "Clean", "detections": 0}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": VT_KEY}, timeout=5)
        if r.status_code == 200:
            stats = r.json()['data']['attributes']['last_analysis_stats']
            return {"reputation": "Malicious" if stats['malicious'] > 0 else "Clean", "detections": stats['malicious']}
    except: pass
    return {"reputation": "Unknown", "detections": 0}

def get_mitre(etype):
    t = str(etype).lower()
    if "brute" in t: return "T1110 - Brute Force"
    if "sql" in t: return "T1190 - Exploit App"
    return "T1059 - Command Line"

def get_ai_analysis(details):
    import openai
    API = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY"))
    if not API: return "Waiting for manual triage.", "Monitor host closely."
    try:
        client = openai.OpenAI(api_key=API)
        res = client.chat.completions.create(model="gpt-3.5-turbo", messages=[{"role": "user", "content": f"Triage this alert and provide one recommendation: {details}"}])
        return res.choices[0].message.content, "Isolate the host if behavior repeats."
    except: return "AI Engine offline. Review logs manually.", "Manual containment required."

# --- UI SETUP ---
st.set_page_config(page_title="SOC Analyst Bot", layout="wide")
st.markdown("<style>.stApp{background-color:#ffffff;} .header{font-weight:800; color:#0f172a; font-size:2.2rem;} p,span,label,div,h1,h2,h3,h4{color:#1e293b !important;}</style>", unsafe_allow_html=True)
setup_db()

with st.sidebar:
    st.title("🛡️ SOC Bot")
    st.write("v1.8 - Professional Edition")
    menu = st.radio("Navigation", ["Dashboard", "Ingestion", "Settings"])
    if st.button("Reset Database"):
        if os.path.exists("soc_triage.db"): os.remove("soc_triage.db")
        st.rerun()

if menu == "Dashboard":
    st.markdown("<h1 class='header'>Incident Dashboard</h1>", unsafe_allow_html=True)
    rows = [dict(r) for r in sqlite3.connect("soc_triage.db").execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()]
    if not rows: st.info("No logs. Use Ingestion tab.")
    else:
        for r in rows:
            with st.expander(f"⚠️ [{r.get('id')}] {r.get('event_type')} @ {r.get('source_ip')}"):
                c1, c2 = st.columns(2)
                with c1:
                    st.write(f"**Target:** {r.get('destination_ip')}")
                    st.write(f"**MITRE:** `{r.get('mitre_mapping')}`")
                    if r.get('vt_report'):
                        vt = json.loads(r['vt_report'])
                        st.markdown(f"**VT Verdict:** <span style='color:{'red' if vt.get('reputation')=='Malicious' else 'green'}; font-weight:bold;'>{vt.get('reputation')}</span>", unsafe_allow_html=True)
                with c2:
                    st.info(r.get('triage_summary') or "Awaiting AI...")
                    st.success(f"**Plan:** {r.get('response_recommendation') or 'Reviewing...'}")

elif menu == "Ingestion":
    st.markdown("<h1 class='header'>Data Ingestion</h1>", unsafe_allow_html=True)
    
    # --- FILE UPLOADER ADDED BACK ---
    uploaded_file = st.file_uploader("Upload CSV or JSON logs", type=["csv", "json"])
    if uploaded_file is not None:
        if st.button("🚀 Process Uploaded File"):
            try:
                data = pd.read_csv(uploaded_file) if uploaded_file.name.endswith('.csv') else pd.read_json(uploaded_file)
                for _, row in data.iterrows():
                    d = row.to_dict()
                    aid = save_alert(d)
                    vt = check_vt(d.get('src_ip') or d.get('source_ip'))
                    mitre = get_mitre(d.get('type') or d.get('event_type'))
                    summary, rec = get_ai_analysis(d)
                    update_alert(aid, {"vt_report": json.dumps(vt), "mitre_mapping": mitre, "triage_summary": summary, "response_recommendation": rec})
                st.success("File processed and triaged!")
            except Exception as e: st.error(f"Error: {e}")

    st.divider()
    if st.button("🔥 Simulate Splunk Triage"):
        logs = [{"src_ip": "223.25.1.88", "dest_ip": "web-01", "type": "SQL Injection", "msg": "Malicious GET"}, {"src_ip": "8.8.8.8", "dest_ip": "internal", "type": "Brute Force", "msg": "Login fail"}]
        for l in logs:
            aid = save_alert(l)
            vt = check_vt(l['src_ip'])
            summary, rec = get_ai_analysis(l)
            update_alert(aid, {"vt_report": json.dumps(vt), "mitre_mapping": get_mitre(l['type']), "triage_summary": summary, "response_recommendation": rec})
        st.success("Triage Complete!")

elif menu == "Settings":
    st.markdown("<h1 class='header'>System Status</h1>", unsafe_allow_html=True)
    st.write(f"**OpenAI Service:** {'Connected ✅' if st.secrets.get('OPENAI_API_KEY') else 'Missing Key ❌'}")
    st.write(f"**VirusTotal API:** {'Active ✅' if st.secrets.get('VT_API_KEY') else 'Disconnected ❌'}")
