import requests
from core.config import VT_API_KEY, ABUSEIPDB_API_KEY

class OnlineIntel:
    def __init__(self):
        self.vt_key = VT_API_KEY
        self.abuseipdb_key = ABUSEIPDB_API_KEY

    def check_vt_hash(self, file_hash: str) -> dict:
        if not self.vt_key:
            return {"error": "API Key missing in .env"}
            
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "accept": "application/json",
            "x-apikey": self.vt_key
        }
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                return {
                    "malicious": stats.get("malicious", 0), 
                    "suspicious": stats.get("suspicious", 0), 
                    "undetected": stats.get("undetected", 0)
                }
            elif response.status_code == 404:
                return {"error": "Hash not found in VirusTotal"}
            return {"error": f"VT API Error {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def check_abuseipdb(self, ip: str) -> dict:
        if not self.abuseipdb_key:
            return {"error": "API Key missing in .env"}
            
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {
            "Accept": "application/json",
            "Key": self.abuseipdb_key
        }
        try:
            response = requests.get(url, headers=headers, params=querystring)
            if response.status_code == 200:
                data = response.json()
                score = data["data"]["abuseConfidenceScore"]
                return {"abuse_confidence": score}
            return {"error": f"AbuseIPDB Error {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
