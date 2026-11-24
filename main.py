import re
from collections import Counter
from anomaly_engine import detect_brute_force_zscore, detect_dns_tunneling
from database import SentinelDB
from responder import execute_containment, generate_incident_report
from threat_intel import check_ip_reputation

SSH_FAILED_PATTERN = re.compile(
    r"^(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)
DNS_QUERY_PATTERN = re.compile(
    r"^(\w+\s+\d+\s+\d+:\d+:\d+).*DNS_QUERY:\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)"
)


def run_sentinel(log_file_path: str):
    db = SentinelDB()
    failed_ip_counter = Counter()
    confirmed_incidents = []

    print(f"[*] Memulai analisis log: {log_file_path}\n")

    with open(log_file_path, "r", encoding="utf-8") as file:
        for line in file:
            ssh_match = SSH_FAILED_PATTERN.search(line)
            if ssh_match:
                timestamp, user, ip = ssh_match.groups()
                db.log_auth_event(timestamp, user, ip, "FAILED")
                failed_ip_counter[ip] += 1
                continue

            dns_match = DNS_QUERY_PATTERN.search(line)
            if dns_match:
                timestamp, domain, src_ip = dns_match.groups()
                result = detect_dns_tunneling(domain)
                if result["is_anomalous"]:
                    action = execute_containment(domain, "DNS Tunneling", dry_run=True)
                    print(f"[ALERT][MITRE T1071.004] Potensi DNS Tunneling dari {src_ip}")
                    print(f"   -> Domain   : {domain} | Entropy: {result['entropy']} bits")
                    print(f"   -> Response : {action}\n")

                    db.save_alert("T1071.004", "DNS Tunneling / High Entropy", domain, result["entropy"], "HIGH")
                    confirmed_incidents.append({
                        "mitre_id": "T1071.004",
                        "alert_type": "DNS Tunneling / Data Exfiltration",
                        "severity": "HIGH",
                        "indicator": domain,
                        "metric_desc": f"Shannon Entropy = {result['entropy']} bits (Host sumber: {src_ip})",
                        "intel_summary": "High-entropy randomized subdomain pattern",
                        "action_taken": action,
                    })

    brute_force_outliers = detect_brute_force_zscore(dict(failed_ip_counter))
    for item in brute_force_outliers:
        ip = item["ip"]
        intel = check_ip_reputation(ip)
        action = execute_containment(ip, "SSH Brute-Force", dry_run=True)

        print(f"[ALERT][MITRE T1110] SSH Brute-Force Outlier dari {ip}")
        print(f"   -> Statistik: {item['attempts']} percobaan gagal (Z-Score: {item['z_score']} | Baseline Mean: {item['baseline_mean']})")
        print(f"   -> Intel    : Abuse Score {intel['abuse_score']}% | {intel['country']} | ISP: {intel['isp']}")
        print(f"   -> Response : {action}\n")

        db.save_alert("T1110", "SSH Brute-Force (Z-Score Outlier)", ip, item["z_score"], "CRITICAL")
        confirmed_incidents.append({
            "mitre_id": "T1110",
            "alert_type": "SSH Brute-Force Attack",
            "severity": "CRITICAL",
            "indicator": ip,
            "metric_desc": f"{item['attempts']} failed logins (Z-Score = {item['z_score']}, Mean = {item['baseline_mean']})",
            "intel_summary": f"Abuse Score {intel['abuse_score']}% ({intel['country']} - {intel['isp']}, {intel['total_reports']} reports via {intel['source']})",
            "action_taken": action,
        })

    if confirmed_incidents:
        report_file = generate_incident_report(confirmed_incidents)
        print(f"[+] Laporan investigasi otomatis berhasil dibuat: {report_file}")


if __name__ == "__main__":
    run_sentinel("logs/sample_soc.log")
