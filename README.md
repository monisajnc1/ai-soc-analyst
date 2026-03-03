# AI SOC Analyst

An automated SIEM alert triage platform built with Python and Streamlit.

## Objectives

- Design and develop an **AI-powered automated triage system** for SIEM alerts.
- Reduce **manual effort and alert fatigue** faced by SOC analysts.
- Automatically **analyze and classify alerts** based on potential risk and severity.
- Enrich alerts using **threat intelligence from VirusTotal**.
- Map alerts to the **MITRE ATT&CK framework** for better understanding of attacker behaviour.
- Generate **contextual explanations and response suggestions** using AI.
- Present alert analysis through an **interactive Streamlit dashboard**.
- Store alert data and analysis results in a **SQLite database** for tracking and historical analysis.

## Tech Stack

| Component   | Technology            |
|-------------|-----------------------|
| Frontend    | Streamlit (light theme) |
| Database    | SQLite3               |
| AI Engine   | OpenAI GPT-3.5        |
| Threat Intel| VirusTotal API        |
| Language    | Python 3.9+           |

## Project Structure

```
ai-soc-analyst/
├── app.py            # Main dashboard and triage pipeline
├── database.py       # SQLite CRUD helpers
├── enrichment.py     # VirusTotal IP reputation lookup
├── analysis.py       # AI triage, MITRE mapping, response engine
├── requirements.txt  # Python dependencies
├── .env              # API keys (not committed)
└── .streamlit/
    └── config.toml   # Light theme configuration
```

## Quick Start

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Add your API keys to `.env`:
   ```
   OPENAI_API_KEY=sk-...
   VT_API_KEY=...
   ```

3. Run the app:
   ```
   streamlit run app.py
   ```

4. Open `http://localhost:8501` in your browser.
