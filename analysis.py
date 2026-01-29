import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

OPENAI_KEY = os.getenv("OPENAI_API_KEY")

# Set up client only if key looks valid and isn't the demo placeholder
gpt_client = None
if OPENAI_KEY and OPENAI_KEY.startswith("sk-") and "demo-key" not in OPENAI_KEY:
    gpt_client = OpenAI(api_key=OPENAI_KEY)

def get_ai_analysis(details):
    event = details.get('event_type') or 'Unknown'
    msg = details.get('message') or ''
    
    # Fallback to simple rules if no AI connected
    if not gpt_client:
        analysis = f"**[Local Engine]** Potential {event} activity detected. "
        msg_lower = msg.lower()
        if any(x in msg_lower for x in ["login", "brute", "password"]):
            analysis += "Likely brute-force or credential spray. Verify account lockouts."
        elif any(x in msg_lower for x in ["malware", "virus", "trojan"]):
            analysis += "Malicious file signature detected. Isolate host immediately."
        elif "phishing" in msg_lower:
            analysis += "Suspicious URL/Domain. Check for email delivery logs."
        else:
            analysis += "Heuristic match. Review raw logs for suspicious patterns."
        return analysis

    # GPT analysis request
    prompt = f"""
    You are a Senior SOC Analyst. Triage this alert:
    {details}
    
    Give me a short summary, why it's suspicious, and the attack pattern.
    """

    try:
        res = gpt_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "system", "content": "Security Analyst Assistant."},
                      {"role": "user", "content": prompt}]
        )
        return res.choices[0].message.content
    except Exception as e:
        return f"AI Analysis failed: {str(e)}"

def get_mitre_mapping(details):
    # Quick lookup for common tactics
    etype = details.get('event_type', '').lower()
    
    mappings = {
        "brute_force": "T1110 - Brute Force",
        "phishing": "T1566 - Phishing",
        "malware": "T1204 - User Execution",
        "sql_injection": "T1190 - Exploit Public-Facing App",
        "enumeration": "T1046 - Network Service Scanning"
    }
    
    for k, v in mappings.items():
        if k in etype:
            return v
    
    return "T1595 - Active Scanning"

def get_response_recommendation(details, vt):
    # Basic logic for generated steps
    if vt.get('reputation') == "Malicious" or details.get('severity') == "High":
        return "1. Isolate Host\n2. Reset Credentials\n3. Flush DNS/Malware Scan\n4. Escalate to SIRT"
    
    return "1. Monitor for 1hr\n2. Check IP reputation manually\n3. Close if no further hits"

def classify_severity(details, vt):
    # Re-calculate severity based on intel
    if vt.get('reputation') == "Malicious":
        return "Critical"
    if vt.get('malicious_count', 0) > 0:
        return "High"
    
    return details.get('severity', 'Medium')
