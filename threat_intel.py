import json
import os
import urllib.parse
import urllib.request


def check_ip_reputation(ip: str, db=None) -> dict:
    """Mengecek reputasi IP via SQLite cache lalu AbuseIPDB v2 API."""
    if db is not None:
        cached = db.get_cached_ip(ip)
        if cached:
            return cached

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {
            "source": "Skipped (ABUSEIPDB_API_KEY not set)",
            "abuse_score": None,
            "country": "N/A",
            "isp": "N/A",
            "total_reports": 0,
        }

    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    url = f"https://api.abuseipdb.com/api/v2/check?{query}"
    req = urllib.request.Request(
        url,
        headers={"Key": api_key, "Accept": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))["data"]
            result = {
                "source": "AbuseIPDB Live API",
                "abuse_score": payload.get("abuseConfidenceScore", 0),
                "country": payload.get("countryCode", "UNKNOWN"),
                "isp": payload.get("isp", "Unknown ISP"),
                "total_reports": payload.get("totalReports", 0),
            }
            if db is not None:
                db.save_ip_cache(ip, result)
            return result
    except Exception as exc:
        return {
            "source": f"API Lookup Failed ({exc})",
            "abuse_score": None,
            "country": "N/A",
            "isp": "N/A",
            "total_reports": 0,
        }
