import argparse
import os
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


def run_sentinel(log_file_path: str, entropy_threshold: float, z_threshold: float, min_attempts: int, live_block: bool):
    if not os.path.exists(log_file_path):
        print(f"[!] File log tidak ditemukan: {log_file_path}")
        return

    db = SentinelDB()
    failed_ip_counter = Counter()
    confirmed_incidents = []
    dry_run = not live_block

    print(f"[*] Menganalisis log : {log_file_path}")
    print(f"[*] Parameter        : Entropy >= {entropy_threshold} | Z-Score >= {z_threshold} | Dry-Run = {dry_run}\n")

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
                result = detect_dns_tunneling(domain, threshold=entropy_threshold)
                if result["is_anomalous"]:
                    action = execute_containment(domain, "DNS Tunneling", dry_run=dry_run)
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
                        "intel_summary": result["note"],
                        "action_taken": action,
                    })

    brute_force_outliers = detect_brute_force_zscore(
        dict(failed_ip_counter),
        z_threshold=z_threshold,
        min_attempts=min_attempts,
    )
    for item in brute_force_outliers:
        ip = item["ip"]
        intel = check_ip_reputation(ip, db=db)
        action = execute_containment(ip, "SSH Brute-Force", dry_run=dry_run)

        score_label = f"{intel['abuse_score']}%" if intel["abuse_score"] is not None else "N/A"
        intel_line = f"Abuse Score {score_label} | {intel['country']} | ISP: {intel['isp']} ({intel['source']})"

        print(f"[ALERT][MITRE T1110] SSH Brute-Force Outlier dari {ip}")
        print(f"   -> Statistik: {item['attempts']} percobaan gagal (Z-Score: {item['z_score']} | Baseline Mean: {item['baseline_mean']})")
        print(f"   -> Intel    : {intel_line}")
        print(f"   -> Response : {action}\n")

        db.save_alert("T1110", "SSH Brute-Force (Z-Score Outlier)", ip, item["z_score"], "CRITICAL")
        confirmed_incidents.append({
            "mitre_id": "T1110",
            "alert_type": "SSH Brute-Force Attack",
            "severity": "CRITICAL",
            "indicator": ip,
            "metric_desc": f"{item['attempts']} failed logins (Z-Score = {item['z_score']}, Mean = {item['baseline_mean']})",
            "intel_summary": intel_line,
            "action_taken": action,
        })

    if confirmed_incidents:
        report_file = generate_incident_report(confirmed_incidents)
        print(f"[+] Laporan investigasi otomatis dibuat: {report_file}")
    else:
        print("[+] Tidak ditemukan anomali yang melewati ambang batas.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL — CLI Log Triage & Anomaly Detection Engine")
    parser.add_argument("--log", default="logs/sample_soc.log", help="Path ke file log target (mis. /var/log/auth.log)")
    parser.add_argument("--entropy", type=float, default=3.8, help="Ambang batas Shannon Entropy DNS (default: 3.8)")
    parser.add_argument("--z-threshold", type=float, default=1.5, help="Ambang batas Z-Score brute-force (default: 1.5)")
    parser.add_argument("--min-attempts", type=int, default=5, help="Minimal percobaan gagal sebelum evaluasi Z-Score")
    parser.add_argument("--live-block", action="store_true", help="Eksekusi pemblokiran UFW secara nyata (nonaktifkan dry-run)")
    args = parser.parse_args()

    run_sentinel(args.log, args.entropy, args.z_threshold, args.min_attempts, args.live_block)
