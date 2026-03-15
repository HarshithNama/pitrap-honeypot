import requests
import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

PRIVATE_RANGES = [
    "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.", "::1"
]

def is_private_ip(ip: str) -> bool:
    return any(ip.startswith(r) for r in PRIVATE_RANGES)

def enrich(ip: str) -> dict:
    result = {
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "latitude": 0.0,
        "longitude": 0.0,
        "abuse_score": 0
    }

    if is_private_ip(ip):
        result["country"] = "Local"
        result["city"] = "Local"
        result["isp"] = "Local Network"
        return result

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                result["country"] = data.get("country", "Unknown")
                result["city"] = data.get("city", "Unknown")
                result["isp"] = data.get("isp", "Unknown")
                result["latitude"] = data.get("lat", 0.0)
                result["longitude"] = data.get("lon", 0.0)
    except Exception as e:
        print(f"[ENRICHER] GeoIP error for {ip}: {e}")

    if ABUSEIPDB_KEY:
        try:
            headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers, params=params, timeout=5
            )
            if r.status_code == 200:
                data = r.json()
                result["abuse_score"] = data.get(
                    "data", {}).get("abuseConfidenceScore", 0)
        except Exception as e:
            print(f"[ENRICHER] AbuseIPDB error for {ip}: {e}")

    return result
