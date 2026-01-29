import os
import splunklib.client as client
import splunklib.results as results
from dotenv import load_dotenv

load_dotenv()

def get_splunk_conn():
    try:
        # Connect to localized splunk instance
        service = client.connect(
            host=os.getenv("SPLUNK_HOST"),
            port=os.getenv("SPLUNK_PORT"),
            username=os.getenv("SPLUNK_USER"),
            password=os.getenv("SPLUNK_PWD")
        )
        return service
    except Exception as e:
        print(f"Splunk connection failed: {e}")
        return None

def fetch_splunk_alerts(query='search index=main sourcetype="*security*" | head 5'):
    host = os.getenv("SPLUNK_HOST")
    pwd = os.getenv("SPLUNK_PWD")
    
    # Simple simulation if creds are still placeholders
    if host == "localhost" and (not pwd or "password" in pwd):
        print("Dev Mode: Simulating Splunk results...")
        return [
            {
                "src_ip": "10.1.1.50",
                "clientip": "10.1.1.50",
                "host": "Web-Server-01",
                "sourcetype": "access_combined",
                "_raw": "10.1.1.50 - - [29/Jan/2026:10:00:01] \"POST /login.php HTTP/1.1\" 401 532 \"-\" \"Mozilla/5.0\""
            },
            {
                "src_ip": "192.168.50.12",
                "clientip": "192.168.50.12",
                "host": "HR-PC-04",
                "sourcetype": "WinEventLog:Security",
                "_raw": "EventCode=4625 Message=An account failed to log on. Account Name: HR_User"
            },
            {
                "src_ip": "45.33.22.11",
                "clientip": "45.33.22.11",
                "host": "Firewall-Main",
                "sourcetype": "cisco:asa",
                "_raw": "%ASA-4-106023: Deny tcp src outside:45.33.22.11/56721 dst inside:10.0.0.5/445"
            }
        ]

    conn = get_splunk_conn()
    if not conn:
        return []

    try:
        job = conn.jobs.create(query, exec_mode="blocking")
        res_stream = job.results(output_mode='json')
        reader = results.JSONResultsReader(res_stream)
        
        results_list = []
        for r in reader:
            if isinstance(r, dict):
                results_list.append(r)
        return results_list
    except Exception as e:
        print(f"Query error: {e}")
        return []

if __name__ == "__main__":
    print("Testing Splunk connection...")
    data = fetch_splunk_alerts()
    print(f"Found {len(data)} results.")
