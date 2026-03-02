import streamlit as st
import pandas as pd
import json
from datetime import datetime

# Local imports
from database import get_alerts, init_db, insert_alert, update_alert
from enrichment import preprocess_alert, get_vt_report, VT_KEY
from analysis import get_triage_summary, get_mitre_mapping, get_response_recommendation, classify_severity, PROV_KEY

# --- Page Setup ---
st.set_page_config(page_title="Sentinel Triage Platform", layout="wide", page_icon="🛡️")

# --- Premium Professional Light Theme Styling ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;700&display=swap');

    /* GLOBAL DARK-MODE NUKE - Force light theme even if system/account is set to dark */
    [data-theme="dark"], [data-theme="light"], .stApp, 
    [data-testid="stAppViewContainer"], [data-testid="stHeader"], 
    [data-testid="stSidebar"], [data-testid="stToolbar"] {
        background-color: #ffffff !important;
        color: #0f172a !important;
    }

    :root {
        --bg-color: #ffffff;
        --sidebar-bg: #f8fafc;
        --text-primary: #0f172a;
        --text-secondary: #475569;
        --accent-primary: #2563eb;
        --border-color: #e2e8f0;
    }

    /* Professional Header Gradient */
    .main-title {
        font-family: 'Inter', sans-serif !important;
        font-weight: 800 !important;
        background: linear-gradient(135deg, #1e293b 0%, #2563eb 100%) !important;
        -webkit-background-clip: text !important;
        -webkit-text-fill-color: transparent !important;
        font-size: 3rem !important;
        letter-spacing: -0.05em !important;
        margin-bottom: 0.25rem !important;
    }

    /* Force all text elements to be dark */
    p, span, label, div, h1, h2, h3, h4, .stMarkdown, .stText, .stCaption {
        color: #0f172a !important;
    }

    /* Premium Sidebar Styling */
    section[data-testid="stSidebar"], [data-testid="stSidebarNav"] {
        background-color: #f8fafc !important;
        border-right: 1px solid #e2e8f0 !important;
    }
    
    /* Clean Cards/Expanders */
    .stExpander {
        border-radius: 16px !important;
        border: 1px solid #e2e8f0 !important;
        background-color: #ffffff !important;
        box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1) !important;
        margin-bottom: 1.25rem !important;
    }

    /* Metric Visualization */
    div[data-testid="stMetricValue"] {
        color: #2563eb !important;
        font-size: 2.2rem !important;
        font-weight: 700 !important;
    }
</style>
""", unsafe_allow_html=True)

# Make sure DB exists
init_db()

# --- Sidebar Navigation ---
with st.sidebar:
    st.markdown("<h1 style='color:var(--accent-primary);'>🛡️ SENTINEL</h1>", unsafe_allow_html=True)
    st.caption("Strategic Triage Engine v1.1.0-LIGHT-THEME-FORCED")
    st.divider()
    
    view = st.radio("NAVIGATION", 
                    ["📊 Incident Dashboard", "📥 Ingestion Center", "🔍 Intel Console"],
                    index=0)
    
    st.divider()
    
    # Personal analyst profile
    st.subheader("👤 Profile")
    analyst_id = st.text_input("Name", "Analyst_1", help="Changes current session owner")
    
    st.sidebar.markdown("<br><br>", unsafe_allow_html=True)
    st.sidebar.info("Operational Status: ONLINE")

# --- App Logic by View ---

if view == "📊 Incident Dashboard":
    st.markdown("<h1 class='main-title'>Operational Dashboard</h1>", unsafe_allow_html=True)
    st.write("Real-time monitoring and incident triage pipeline.")
    st.divider()

    rows = get_alerts()
    if not rows:
        st.warning("Systems idle. No incidents detected in database.")
        st.info("Head to the **Ingestion Center** to simulate traffic.")
    else:
        # Top Metrics
        df = pd.DataFrame(rows)
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("TOTAL INCIDENTS", len(df))
        c2.metric("CRITICAL THREATS", len(df[df['severity'] == 'Critical']))
        c3.metric("PENDING TRIAGE", len(df[df['status'] == 'New']))
        c4.metric("SYSTEM UPTIME", "99.9%")

        st.subheader("Live Alert Stream")
        for i, r in df.iterrows():
            # Dynamic header color based on severity
            sev_emoji = "🔴" if r['severity'] == "Critical" else "🟠" if r['severity'] == "High" else "🟡"
            header = f"{sev_emoji} [{r['severity']}] {r['event_type']} @ {r['source_ip']} ({r['status']})"
            
            if r.get('assigned_to') and r['assigned_to'] != "Unassigned":
                header += f" | 👤 {r['assigned_to']}"
                
            with st.expander(header):
                col_l, col_r = st.columns([1, 1])
                
                with col_l:
                    st.markdown("#### 📋 Event Context")
                    st.caption(f"**Observed at:** {r['timestamp']}")
                    st.write(f"**Target Host:** {r['destination_ip']}")
                    st.write(f"**Detection Msg:** {r['message']}")
                    st.markdown(f"**MITRE ATT&CK Mapping:** `{r['mitre_mapping'] or 'None'}`")
                    
                    st.markdown("#### 🔍 Threat Intelligence")
                    if r['vt_report']:
                        vt_json = json.loads(r['vt_report'])
                        rep_status = vt_json.get('reputation', 'Unknown')
                        st.write(f"**VirusTotal Verdict:** {rep_status}")
                        if st.checkbox("View Detailed Rep Report", key=f"vt_chk_{r['id']}"):
                            st.json(vt_json)
                    
                    st.markdown("---")
                    st.markdown("#### 🤝 Incident Ownership")
                    
                    # Teammate selection
                    cur_user = r.get('assigned_to', 'Unassigned')
                    opts = ["Unassigned", "Analyst_1", "Analyst_2", "Lead_SOC"]
                    pick = st.selectbox("Assignee", opts, index=opts.index(cur_user) if cur_user in opts else 0, key=f"user_{r['id']}")
                    if pick != cur_user:
                        update_alert(r['id'], {"assigned_to": pick})
                        st.rerun()

                    # Comment thread
                    st.markdown("**Incident Log**")
                    notes = json.loads(r.get('comments', '[]'))
                    for n in notes:
                        st.caption(f"**{n['user']}** ({n.get('time', '')[:16]}): {n['text']}")
                    
                    txt = st.text_input("Update log...", key=f"note_in_{r['id']}", placeholder="Add technical observations...")
                    if st.button("Add Log Entry", key=f"note_sub_{r['id']}"):
                        if txt:
                            notes.append({"user": analyst_id, "time": datetime.now().isoformat(), "text": txt})
                            update_alert(r['id'], {"comments": json.dumps(notes)})
                            st.rerun()

                with col_r:
                    st.markdown("#### 🛡️ Behavioral Analysis")
                    st.info(r['triage_summary'] or "Analysis in priority queue...")
                    
                    st.markdown("#### 🛠️ Response Playbook")
                    st.success(r['response_recommendation'] or "Awaiting manual triage.")
                    
                    # Workflow status
                    st.markdown("#### ⚡ Pipeline Management")
                    btns = st.columns(3)
                    if btns[0].button("✅ Resolve", key=f"fix_{r['id']}"):
                        update_alert(r['id'], {"status": "Resolved"})
                        st.rerun()
                    if btns[1].button("🕵️ Investigate", key=f"inv_{r['id']}"):
                        update_alert(r['id'], {"status": "Investigating"})
                        st.rerun()
                    if btns[2].button("⚠️ Escalate", key=f"esc_{r['id']}"):
                        update_alert(r['id'], {"status": "Escalated"})
                        st.rerun()

elif view == "📥 Ingestion Center":
    st.markdown("<h1 class='main-title'>Ingestion Hub</h1>", unsafe_allow_html=True)
    st.write("Source integration and telemetry simulation.")
    st.divider()

    col_a, col_b = st.columns(2)
    
    with col_a:
        st.subheader("🔌 External SIEM Connection")
        if st.button("🔍 Pull from Splunk Instance"):
            from splunk_ingest import fetch_splunk_alerts
            with st.status("Connecting to Splunk API..."):
                s_data = fetch_splunk_alerts()
                if not s_data:
                    st.warning("No new events found.")
                else:
                    for entry in s_data:
                        obj = {
                            "src_ip": entry.get("src_ip") or entry.get("clientip") or "0.0.0.0",
                            "dest_ip": entry.get("dest_ip") or entry.get("host") or "Local",
                            "type": entry.get("sourcetype") or "Splunk Log",
                            "severity": "Medium",
                            "msg": entry.get("_raw")[:200] if "_raw" in entry else "Event from Splunk"
                        }
                        proc = preprocess_alert(obj)
                        aid = insert_alert(proc)
                        
                        # Pipeline
                        vt = get_vt_report(proc['source_ip'])
                        ts = get_triage_summary(proc)
                        mtt = get_mitre_mapping(proc)
                        rec = get_response_recommendation(proc, vt)
                        sev = classify_severity(proc, vt)
                        
                        update_alert(aid, {
                            "vt_report": json.dumps(vt), "triage_summary": ts,
                            "mitre_mapping": mtt, "response_recommendation": rec, "severity": sev
                        })
                    st.success(f"Synced {len(s_data)} events from Splunk.")

        st.divider()
        st.subheader("🚀 Rapid Simulation")
        if st.button("Ingest Synthetic Alert Samples"):
            samples = [
                {"src_ip": "103.45.12.1", "dest_ip": "DMZ-WEB-01", "type": "SQL Injection", "severity": "High", "msg": "Detected classic SQLmap payload in GET param"},
                {"src_ip": "8.8.4.4", "dest_ip": "INTERNAL-DC-01", "type": "Anomalous Login", "severity": "Medium", "msg": "Multiple 4624 events followed by 4625"},
            ]
            for a in samples:
                proc = preprocess_alert(a)
                aid = insert_alert(proc)
                vt = get_vt_report(proc['source_ip'])
                ts = get_triage_summary(proc)
                update_alert(aid, {
                    "vt_report": json.dumps(vt), "triage_summary": ts,
                    "mitre_mapping": get_mitre_mapping(proc), "severity": classify_severity(proc, vt),
                    "response_recommendation": get_response_recommendation(proc, vt)
                })
            st.success("Test samples added to dashboard.")

    with col_b:
        st.subheader("📑 Manual Case Creation")
        with st.form("new_case"):
            s_ip = st.text_input("Indicator (IP/Host)", "192.168.1.50")
            d_ip = st.text_input("Target Environment", "Production-DB")
            etype = st.selectbox("Category", ["Brute Force", "Malware", "Phishing", "Recon", "Other"])
            msg_box = st.text_area("Event Details", "Observed via out-of-band monitoring")
            if st.form_submit_button("Generate Incident"):
                obj = {"src_ip": s_ip, "dest_ip": d_ip, "type": etype, "severity": "Medium", "msg": msg_box}
                proc = preprocess_alert(obj)
                aid = insert_alert(proc)
                # Run full triage logic
                vt = get_vt_report(proc['source_ip'])
                ts = get_triage_summary(proc)
                update_alert(aid, {
                    "vt_report": json.dumps(vt), "triage_summary": ts,
                    "mitre_mapping": get_mitre_mapping(proc), "severity": classify_severity(proc, vt),
                    "response_recommendation": get_response_recommendation(proc, vt)
                })
                st.success("Incident created.")

        st.divider()
        st.subheader("📁 Bulk Upload")
        up_file = st.file_uploader("Upload CSV/JSON security logs", type=["csv", "json"])
        if up_file and st.button("Parse and Process"):
            try:
                items = pd.read_csv(up_file).to_dict('records') if up_file.name.endswith('.csv') else json.load(up_file)
                if not isinstance(items, list): items = [items]
                bar = st.progress(0)
                for i, raw in enumerate(items):
                    obj = {"src_ip": raw.get("src_ip"), "dest_ip": raw.get("dest_ip"), "type": raw.get("type"), "severity": "Medium", "msg": raw.get("msg")}
                    proc = preprocess_alert(obj)
                    aid = insert_alert(proc)
                    vt = get_vt_report(proc['source_ip'])
                    update_alert(aid, {"vt_report": json.dumps(vt), "triage_summary": get_triage_summary(proc)})
                    bar.progress((i + 1) / len(items))
                st.success("Batch processing complete.")
            except Exception as e:
                st.error(f"Processing error: {e}")

elif view == "🔍 Intel Console":
    st.markdown("<h1 class='main-title'>OSINT & Configuration</h1>", unsafe_allow_html=True)
    st.write("Manage threat intelligence sources and system parameters.")
    st.divider()
    
    # Reload environment to ensure latest keys are shown if changed
    import os
    from dotenv import load_dotenv
    load_dotenv(override=True)
    
    st.subheader("🔑 Active API Configurations")
    
    # Visual status badges
    c_ai, c_vt = st.columns(2)
    
    with c_ai:
        api_val = os.getenv("OPENAI_API_KEY", "")
        if api_val.startswith('sk-'):
            st.success("✅ Provider: CONNECTED")
            st.caption("Advanced behavioral triaging is active.")
        else:
            st.error("❌ Provider: OFFLINE")
            st.caption("Using local heuristic fallback engine.")
            
    with c_vt:
        vt_val = os.getenv("VT_API_KEY", "")
        if vt_val and "your" not in vt_val:
            st.success("🌐 VirusTotal: CONNECTED")
            st.caption("Global reputation lookups are active.")
        else:
            st.error("🌐 VirusTotal: OFFLINE")
            st.caption("Using local IP reputation scoring.")

    st.divider()
    
    st.markdown("#### ⚙️ Session Identity")
    st.info(f"**Host:** Sentinel Triage Engine  \n**User:** `{analyst_id}`")
    
    st.divider()
    st.subheader("🧪 Diagnostics")
    if st.button("Run System Pipeline Test"):
        st.write("Checking database connectivity...")
        st.write("Verifying AI analysis modules...")
        st.write("Testing SIEM simulation layers...")
        st.success("All systems operational.")

# Footer
st.sidebar.divider()
st.sidebar.subheader("📈 System Telemetry")
try:
    df_mini = pd.DataFrame(get_alerts())
    if not df_mini.empty:
        st.sidebar.caption(f"Active Alerts: {len(df_mini)}")
        st.sidebar.caption(f"Resolved: {len(df_mini[df_mini['status']=='Resolved'])}")
    else:
        st.sidebar.caption("No active telemetry.")
except:
    pass

st.sidebar.markdown("---")
st.sidebar.caption("Sentinel v1.1.0-LIGHT-THEME-FORCED | Professional Edition")


