import requests
import os
from dotenv import load_dotenv

load_dotenv()

VT_KEY = os.getenv("VT_API_KEY")

def get_vt_report(indicator):
    # If no key or demo key, we just return a fake score so the app still works for testing
    if not VT_KEY or "simulation-hub" in VT_KEY:
        return {
            "status": "local_heuristic",
            "indicator": indicator,
            "reputation": "Suspicious" if hash(indicator) % 2 == 0 else "Clean",
            "malicious_count": 5 if hash(indicator) % 2 == 0 else 0,
            "total_engines": 70
        }

    # Hit the VT IP lookup endpoint
    api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    headers = {"x-apikey": VT_KEY}
    
    try:
        resp = requests.get(api_url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            # Grab the last analysis stats
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                "status": "success",
                "indicator": indicator,
                "reputation": "Malicious" if stats['malicious'] > 0 else "Clean",
                "malicious_count": stats['malicious'],
                "total_engines": sum(stats.values())
            }
        else:
            return {"status": "error", "message": f"VT API Error Code: {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def preprocess_alert(raw):
    # Normalize different SIEM formats into our internal schema
    return {
        "timestamp": raw.get("timestamp") or raw.get("time"),
        "source_ip": raw.get("src_ip") or raw.get("source"),
        "destination_ip": raw.get("dest_ip") or raw.get("destination"),
        "event_type": raw.get("type") or raw.get("category"),
        "severity": raw.get("severity", "Medium"),
        "message": raw.get("msg") or raw.get("description"),
        "raw_data": raw
    }
