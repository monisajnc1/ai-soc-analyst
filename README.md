# Sentinel: Strategic Triage Platform 🛡️

Sentinel is a professional-grade, AI-powered SOC analyst triage platform designed to automate the initial analysis of security alerts. By integrating Large Language Models (LLMs) with global threat intelligence and SIEM telemetry, Sentinel drastically reduces MTTR (Mean Time to Respond).

## 🚀 Key Features

*   **Multi-View Navigation**: Integrated Dashboard, Ingestion Center, and Intel Console.
*   **AI Behavioral Triage**: Autonomous technical summaries and attack pattern recognition via GPT-4/3.5 models.
*   **Threat Intel Fusion**: Automated VirusTotal reputation scanning for suspicious indicators.
*   **MITRE ATT&CK Mapping**: Instant correlation of events to specific tactics and techniques.
*   **Multi-Analyst Collaboration**: Incident assignment system with persistent technical log threads.
*   **SIEM Integration**: Native support for Splunk (including a high-fidelity simulation mode).
*   **Bulk Telemetry Ingestion**: Seamless import of security logs via CSV and JSON.

## 🛠️ Deployment & Setup

### 1. Environment Preparation
Ensure you have Python 3.9+ installed. Clone the repository and install the standard dependency stack:
```bash
pip install -r requirements.txt
```

### 2. Configuration
Sentinel relies on a `.env` file for API orchestration. Use the provided template or create one:
```env
OPENAI_API_KEY=sk-your-key
VT_API_KEY=vt-your-key
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
```
> [!TIP]
> Use the built-in **Demo Mode** keys to test the platform's visual indicators without a live API subscription.

### 3. Execution
Launch the production-ready dashboard:
```bash
streamlit run app.py
```

## 🏗️ Architecture
Sentinel's modular design ensures scalability and ease of integration:
- **`app.py`**: Presentation layer and session management.
- **`analysis.py`**: Core logic engine for AI and Scoring.
- **`enrichment.py`**: Telemetry normalization and OSINT lookups.
- **`database.py`**: Persistent storage using SQLite.
- **`splunk_ingest.py`**: SIEM connector logic.

---
*Sentinel: Strategic Triage Platform | v1.0.2*
