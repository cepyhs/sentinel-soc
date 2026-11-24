import json
import os
import urllib.parse
import urllib.request


def check_ip_reputation(ip: str) -> dict:
    """Mengecek skor reputasi IP melalui API AbuseIPDB atau fallback intelijen lokal."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if api_key:
        url = f"https://api.abuseipdb.com/api/v2/check?{urllib.parse.urlencode({'ipAddress': ip, 'maxAgeInDays': 90})}"
        req = urllib.request.Request(
            url,
            headers={"Key": api_key, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))["data"]
                return {
                    "source": "AbuseIPDB Live API",
                    "abuse_score": payload.get("abuseConfidenceScore", 0),
                    "country": payload.get("countryCode", "UNKNOWN"),
                    "isp": payload.get("isp", "Unknown ISP"),
                    "total_reports": payload.get("totalReports", 0),
                }
        except Exception as exc:
            return {"source": f"API Error ({exc})", "abuse_score": 0, "country": "N/A", "isp": "N/A", "total_reports": 0}

    # Simulasi intelijen ancaman jika API Key belum dikonfigurasi
    known_threat_feeds = {
        "185.220.101.45": {
            "source": "Local Threat Feed (Simulated AbuseIPDB)",
            "abuse_score": 100,
            "country": "DE (Tor Exit Node)",
            "isp": "Zwiebelfreunde e.V.",
            "total_reports": 1420,
        }
    }
    return known_threat_feeds.get(
        ip,
        {"source": "Local Threat Feed", "abuse_score": 50, "country": "UNKNOWN", "isp": "Unclassified", "total_reports": 1},
    )
