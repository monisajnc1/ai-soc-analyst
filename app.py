import streamlit as st
import pandas as pd
import json
import time
from database import init_db, insert_alert, update_alert, get_all_alerts, clear_all_alerts
from enrichment import lookup_ip
from analysis import triage_alert, map_mitre, recommend_response

# ── Page config ──────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI SOC Analyst",
    layout="centered",
    page_icon="📋",
)

# ── Light document-style CSS ─────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Merriweather:wght@400;700;900&family=Inter:wght@400;500;600;700&display=swap');

    /* ---- base ---- */
    html, body, .stApp,
    [data-testid="stAppViewContainer"],
    [data-testid="stMain"] {
        background-color: #ffffff !important;
    }

    /* hide streamlit chrome */
    header[data-testid="stHeader"],
    #MainMenu, footer { display: none !important; }

    /* ---- typography ---- */
    .doc-title {
        font-family: 'Merriweather', Georgia, serif;
        font-weight: 900;
        font-size: 2rem;
        color: #111;
        margin: 2rem 0 0.2rem 0;
    }
    .doc-subtitle {
        font-family: 'Inter', sans-serif;
        font-size: 0.95rem;
        color: #666;
        margin-bottom: 1.8rem;
    }
    .section-head {
        font-family: 'Merriweather', Georgia, serif;
        font-weight: 700;
        font-size: 1.35rem;
        color: #111;
        margin: 1.6rem 0 0.8rem 0;
    }

    /* ---- alert cards ---- */
    .alert-card {
        border-left: 4px solid #111;
        background: #fafafa;
        padding: 14px 18px;
        margin-bottom: 12px;
        font-family: 'Inter', sans-serif;
    }
    .alert-card .title {
        font-weight: 700;
        font-size: 1.05rem;
        color: #111;
    }
    .alert-card .meta {
        font-size: 0.88rem;
        color: #555;
        margin-top: 4px;
    }
    .alert-card.critical { border-left-color: #dc2626; }
    .alert-card.high { border-left-color: #ea580c; }
    .alert-card.medium { border-left-color: #ca8a04; }
    .alert-card.low { border-left-color: #16a34a; }

    /* ---- severity badges ---- */
    .sev-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 3px;
        font-size: 0.78rem;
        font-weight: 700;
        font-family: 'Inter', sans-serif;
    }
    .sev-critical { background: #fef2f2; color: #dc2626; }
    .sev-high     { background: #fff7ed; color: #ea580c; }
    .sev-medium   { background: #fefce8; color: #ca8a04; }
    .sev-low      { background: #f0fdf4; color: #16a34a; }

    /* ---- VT verdict ---- */
    .vt-clean     { color: #16a34a; font-weight: 700; }
    .vt-malicious { color: #dc2626; font-weight: 700; }
    .vt-unknown   { color: #6b7280; font-weight: 700; }

    /* ---- analysis box ---- */
    .analysis-box {
        background: #f9fafb;
        border: 1px solid #e5e7eb;
        border-radius: 6px;
        padding: 14px;
        font-family: 'Inter', sans-serif;
        font-size: 0.92rem;
        line-height: 1.6;
        color: #333;
        margin-bottom: 10px;
    }

    /* ---- button ---- */
    .stButton>button {
        background-color: #111 !important;
        color: #fff !important;
        border: none !important;
        border-radius: 4px;
        font-weight: 600;
        padding: 0.55rem 1.4rem;
    }
    .stButton>button:hover {
        background-color: #333 !important;
    }

    /* ---- divider ---- */
    hr { border-top: 1px solid #ddd !important; }
</style>
""", unsafe_allow_html=True)

# ── Database setup ───────────────────────────────────────────────────
init_db()


# ═══════════════════════════════════════════════════════════════════════
#  HELPER — run triage pipeline on a list of raw alert dicts
# ═══════════════════════════════════════════════════════════════════════
def run_pipeline(raw_alerts: list):
    """Triage a list of alert dicts: save → enrich → analyze → update."""
    with st.status("Running triage pipeline …", expanded=True) as status:
        for i, log in enumerate(raw_alerts, 1):
            etype = log.get("event_type") or log.get("type") or "Unknown"
            src = log.get("source_ip") or log.get("src_ip") or "—"
            st.write(f"**[{i}/{len(raw_alerts)}]** Processing *{etype}* from `{src}`")

            rid = insert_alert(log)
            vt = lookup_ip(src)
            mitre = map_mitre(log)
            summary = triage_alert(log)
            resp = recommend_response(log, vt)

            update_alert(rid, {
                "vt_result": json.dumps(vt),
                "mitre_tag": mitre,
                "ai_summary": summary,
                "response_plan": resp,
                "status": "Triaged",
            })
            time.sleep(0.25)

        status.update(label="Pipeline complete", state="complete")

    st.success(f"Successfully triaged {len(raw_alerts)} alerts.")
    time.sleep(0.5)
    st.rerun()


# ═══════════════════════════════════════════════════════════════════════
#  HEADER
# ═══════════════════════════════════════════════════════════════════════
st.markdown("<div class='doc-title'>AI SOC Analyst</div>", unsafe_allow_html=True)
st.markdown(
    "<div class='doc-subtitle'>Automated SIEM Triage &amp; Threat Intelligence Platform</div>",
    unsafe_allow_html=True,
)
st.markdown("---")

# ═══════════════════════════════════════════════════════════════════════
#  TABS
# ═══════════════════════════════════════════════════════════════════════
tab_dash, tab_ingest = st.tabs(["Dashboard", "Ingest & Triage"])


# ─────────────────────────────────────────────────────────────────────
#  TAB 1 — DASHBOARD
# ─────────────────────────────────────────────────────────────────────
with tab_dash:
    st.markdown("<div class='section-head'>Processed Alerts</div>", unsafe_allow_html=True)
    alerts = get_all_alerts()

    if not alerts:
        st.info("No alerts in the database yet. Switch to the **Ingest & Triage** tab to run the pipeline.")
    else:
        # ── Metrics row ──
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Alerts", len(alerts))
        col2.metric("Critical / High",
                     sum(1 for a in alerts if a.get("severity") in ("Critical", "High")))
        clean_count = 0
        for a in alerts:
            if a.get("vt_result"):
                try:
                    if json.loads(a["vt_result"]).get("verdict") == "Clean":
                        clean_count += 1
                except Exception:
                    pass
        col3.metric("Clean Verdicts", clean_count)

        st.markdown("---")

        # ── Alert cards ──
        for alert in alerts:
            sev = (alert.get("severity") or "medium").lower()
            sev_class = sev if sev in ("critical", "high", "medium", "low") else "medium"

            st.markdown(f"""
            <div class='alert-card {sev_class}'>
                <div class='title'>
                    {alert.get("event_type") or "Unknown Event"}
                    &nbsp; <span class='sev-badge sev-{sev_class}'>{(alert.get("severity") or "Medium").upper()}</span>
                </div>
                <div class='meta'>
                    Source: {alert.get("source_ip") or "—"}
                    &nbsp;→&nbsp; {alert.get("dest_ip") or "—"}
                    &nbsp;&nbsp;|&nbsp;&nbsp; {alert.get("timestamp") or ""}
                </div>
            </div>
            """, unsafe_allow_html=True)

            with st.expander("View full analysis"):
                c1, c2 = st.columns(2)

                with c1:
                    # ── AI Summary ──
                    st.markdown("**AI Triage Summary**")
                    ai_text = alert.get("ai_summary") or "Pending analysis …"
                    st.markdown(f"<div class='analysis-box'>{ai_text}</div>", unsafe_allow_html=True)

                    # ── MITRE ──
                    st.markdown("**MITRE ATT&CK Mapping**")
                    st.code(alert.get("mitre_tag") or "—")

                with c2:
                    # ── VT Intelligence ──
                    st.markdown("**VirusTotal Intelligence**")
                    if alert.get("vt_result"):
                        try:
                            vt = json.loads(alert["vt_result"])
                            verdict = vt.get("verdict", "Unknown")
                            vt_class = {
                                "Clean": "vt-clean",
                                "Malicious": "vt-malicious",
                            }.get(verdict, "vt-unknown")

                            st.markdown(f"""
                            <div class='analysis-box'>
                                <div>Verdict: <span class='{vt_class}'>{verdict}</span></div>
                                <div>Detections: <b>{vt.get('detections', 0)}</b> engines flagged</div>
                                <div>Country: <b>{vt.get('country', 'Unknown')}</b></div>
                                <div>Owner: {vt.get('owner', 'Unknown')}</div>
                                <div>IP: <code>{vt.get('ip', '—')}</code></div>
                            </div>
                            """, unsafe_allow_html=True)
                        except Exception:
                            st.write("_Error parsing VT data_")
                    else:
                        st.markdown("<div class='analysis-box'>No intelligence data available.</div>",
                                    unsafe_allow_html=True)

                    # ── Response ──
                    st.markdown("**Recommended Response**")
                    resp_text = alert.get("response_plan") or "Pending evaluation."
                    st.info(resp_text)

        st.markdown("---")
        if st.button("Clear all alerts"):
            clear_all_alerts()
            st.rerun()


# ─────────────────────────────────────────────────────────────────────
#  TAB 2 — INGEST & TRIAGE
# ─────────────────────────────────────────────────────────────────────
with tab_ingest:
    st.markdown("<div class='section-head'>Ingest Alerts</div>", unsafe_allow_html=True)
    st.write("Choose an ingestion method below. Each alert will be processed through the full "
             "triage pipeline: **VirusTotal → MITRE Mapping → AI Analysis → Response Plan**.")

    method = st.radio(
        "Ingestion Method",
        ["Sample Alerts", "Upload CSV", "Upload JSON"],
        horizontal=True,
    )

    # ── Method 1: Sample Alerts ──────────────────────────────────────
    if method == "Sample Alerts":
        st.markdown("---")
        st.write("Process a built-in set of sample SIEM alerts to test the pipeline.")

        sample_logs = [
            {
                "source_ip": "185.220.101.34",
                "dest_ip": "web-prod-01",
                "event_type": "SQL Injection",
                "severity": "Critical",
                "message": "Malicious SQL payload detected in POST /api/login",
            },
            {
                "source_ip": "45.33.32.156",
                "dest_ip": "dc-internal-02",
                "event_type": "Brute Force",
                "severity": "High",
                "message": "120 failed SSH logins for root in 60 seconds",
            },
            {
                "source_ip": "8.8.8.8",
                "dest_ip": "workstation-114",
                "event_type": "Reconnaissance",
                "severity": "Medium",
                "message": "Nmap SYN scan detected across 1024 ports",
            },
        ]

        # Preview table
        preview_df = pd.DataFrame(sample_logs)
        st.dataframe(preview_df, use_container_width=True)

        if st.button("Triage Sample Alerts"):
            run_pipeline(sample_logs)

    # ── Method 2: CSV Upload ─────────────────────────────────────────
    elif method == "Upload CSV":
        st.markdown("---")
        st.write("Upload a CSV file with columns: `source_ip`, `dest_ip`, `event_type`, `severity`, `message`.")
        st.caption("Optional columns: `timestamp`")

        uploaded = st.file_uploader("Choose a CSV file", type=["csv"], key="csv_upload")

        if uploaded is not None:
            try:
                df = pd.read_csv(uploaded)
                st.write(f"**{len(df)} alerts found in file.**")
                st.dataframe(df, use_container_width=True)

                if st.button("Triage CSV Alerts"):
                    records = df.to_dict(orient="records")
                    run_pipeline(records)
            except Exception as e:
                st.error(f"Failed to parse CSV: {e}")

    # ── Method 3: JSON Upload ────────────────────────────────────────
    elif method == "Upload JSON":
        st.markdown("---")
        st.write("Upload a JSON file containing an array of alert objects with fields: "
                 "`source_ip`, `dest_ip`, `event_type`, `severity`, `message`.")

        uploaded = st.file_uploader("Choose a JSON file", type=["json"], key="json_upload")

        if uploaded is not None:
            try:
                raw = json.load(uploaded)
                if isinstance(raw, dict):
                    raw = [raw]
                st.write(f"**{len(raw)} alerts found in file.**")
                st.dataframe(pd.DataFrame(raw), use_container_width=True)

                if st.button("Triage JSON Alerts"):
                    run_pipeline(raw)
            except Exception as e:
                st.error(f"Failed to parse JSON: {e}")


# ── Footer ───────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<p style='text-align:center; color:#999; font-size:0.8rem;'>"
    "Internal Tool — Confidential</p>",
    unsafe_allow_html=True,
)
