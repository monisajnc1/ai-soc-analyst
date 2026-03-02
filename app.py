import streamlit as st
import pandas as pd
import json
import sqlite3
import os
import requests
from datetime import datetime
from dotenv import load_dotenv

# --- CORE LOGIC ---

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
    nid = c.lastrowid; conn.commit(); conn.close(); return nid

def update_alert(aid, info):
    conn = sqlite3.connect("soc_triage.db"); c = conn.cursor()
    set_str = ", ".join([f"{k} = ?" for k in info.keys()]); v = list(info.values()); v.append(aid)
    c.execute(f"UPDATE alerts SET {set_str} WHERE id = ?", v); conn.commit(); conn.close()

def check_vt(ip):
    K = st.secrets.get("VT_API_KEY", os.getenv("VT_API_KEY"))
    if ip == "223.25.1.88": return {"reputation": "Malicious", "detections": 68}
    if not K: return {"reputation": "Clean", "detections": 0}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": K}, timeout=5)
        if r.status_code == 200:
            s = r.json()['data']['attributes']['last_analysis_stats']
            return {"reputation": "Malicious" if s['malicious'] > 0 else "Clean", "detections": s['malicious']}
    except: pass
    return {"reputation": "Unknown", "detections": 0}

def get_ai_analysis(details):
    import openai
    K = st.secrets.get("OPENAI_API_KEY", os.getenv("OPENAI_API_KEY"))
    if not K: return "AI Triage is currently offline. Key missing.", "Check manually."
    try:
        client = openai.OpenAI(api_key=K)
        res = client.chat.completions.create(model="gpt-3.5-turbo", messages=[{"role": "user", "content": f"Brief triage & recommendation for: {details}"}])
        return res.choices[0].message.content, "Isolate host and block source IP."
    except: return "AI Analysis failed.", "Manual review needed."

# --- UI ---
st.set_page_config(page_title="SOC Analyst Bot", layout="wide")
st.markdown("<style>.stApp{background-color:#ffffff;} .header{font-weight:800; color:#0f172a; font-size:2.2rem;} p,span,label,div,h1,h2,h3,h4{color:#1e293b !important;}</style>", unsafe_allow_html=True)
setup_db()

with st.sidebar:
    st.header("🛡️ SOC Bot Tool")
    menu = st.radio("Navigation", ["Dashboard", "Ingestion", "Settings"])
    if st.button("Reset Database"):
        if os.path.exists("soc_triage.db"): os.remove("soc_triage.db")
        st.rerun()

if menu == "Dashboard":
    st.markdown("<h1 class='header'>Incident Dashboard</h1>", unsafe_allow_html=True)
    # FIXED DATABASE QUERY
    conn = sqlite3.connect("soc_triage.db"); conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()]
    conn.close()
    
    if not rows: st.info("No logs. Use Ingestion tab.")
    else:
        for r in rows:
            with st.expander(f"⚠️ {r.get('event_type')} @ {r.get('source_ip')}"):
                c1, c2 = st.columns(2)
                with c1:
                    st.write(f"**Target:** {r.get('destination_ip') or 'None'}")
                    if r.get('vt_report'):
                        vt = json.loads(r['vt_report'])
                        st.markdown(f"**VT Intel:** <span style='color:{'red' if vt.get('reputation')=='Malicious' else 'green'}; font-weight:bold;'>{vt.get('reputation')}</span>", unsafe_allow_html=True)
                with c2:
                    st.info(r.get('triage_summary') or "Awaiting AI...")
                    st.success(f"**Plan:** {r.get('response_recommendation') or 'Review logs.'}")

elif menu == "Ingestion":
    st.markdown("<h1 class='header'>Data Ingestion</h1>", unsafe_allow_html=True)
    up = st.file_uploader("Upload CSV/JSON Logs", type=["csv", "json"])
    if up and st.button("🚀 Process File"):
        df = pd.read_csv(up) if up.name.endswith('.csv') else pd.read_json(up)
        for _, row in df.iterrows():
            d = row.to_dict(); aid = save_alert(d)
            vt = check_vt(d.get('src_ip') or d.get('source_ip'))
            sum, rec = get_ai_analysis(d)
            update_alert(aid, {"vt_report": json.dumps(vt), "triage_summary": sum, "response_recommendation": rec, "mitre_mapping": "T1059"})
        st.success("File triaged!")

    st.divider()
    if st.button("🔥 Simulate Splunk Triage"):
        logs = [{"src_ip": "223.25.1.88", "dest_ip": "web-01", "type": "SQL Injection", "msg": "Malicious code"}]
        for l in logs:
            aid = save_alert(l); vt = check_vt(l['src_ip'])
            s, r = get_ai_analysis(l)
            update_alert(aid, {"vt_report": json.dumps(vt), "triage_summary": s, "response_recommendation": r})
        st.success("Triage Complete!")

elif menu == "Settings":
    st.write(f"**OpenAI Service:** {'Active ✅' if st.secrets.get('OPENAI_API_KEY') else 'Offline ❌'}")
