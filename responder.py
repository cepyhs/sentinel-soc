import ipaddress
import os
from datetime import datetime


def execute_containment(indicator: str, alert_type: str, dry_run: bool = True) -> str:
    """Menentukan tindakan respons aman (Whitelist check untuk IP lokal, UFW block untuk IP publik)."""
    try:
        ip_obj = ipaddress.ip_address(indicator)
        if ip_obj.is_private or ip_obj.is_loopback:
            return f"INTERNAL HOST ({indicator}): Whitelisted dari blokir UFW -> Tandai untuk isolasi endpoint & forensik."

        ufw_cmd = f"sudo ufw insert 1 deny from {indicator} to any"
        if dry_run:
            return f"ACTIVE CONTAINMENT [DRY-RUN]: Siap mengeksekusi `{ufw_cmd}`"
        os.system(ufw_cmd)
        return f"ACTIVE CONTAINMENT [EXECUTED]: IP {indicator} diblokir via UFW."
    except ValueError:
        return f"DNS SINKHOLE RECOMMENDED: Blokir resolusi domain `{indicator}` pada DNS resolver lokal."


def generate_incident_report(incidents: list, output_dir: str = "reports") -> str:
    """Menghasilkan laporan investigasi insiden SOC terstruktur dalam format Markdown."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp_slug = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(output_dir, f"incident_report_{timestamp_slug}.md")

    lines = [
        "# SENTINEL SOC — Automated Incident Investigation Report",
        f"- **Generated At:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S WIB')}",
        f"- **Total Confirmed Alerts:** {len(incidents)}",
        "- **Containment Mode:** Safe Dry-Run (Whitelist Protected)\n",
        "## Executive Summary & Findings\n",
    ]

    for idx, item in enumerate(incidents, start=1):
        lines.extend([
            f"### {idx}. [{item['mitre_id']}] {item['alert_type']} ({item['severity']})",
            f"- **Indicator (IoC):** `{item['indicator']}`",
            f"- **Detection Metric:** {item['metric_desc']}",
            f"- **Threat Intelligence:** {item['intel_summary']}",
            f"- **Automated Response:** {item['action_taken']}\n",
        ])

    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write("\n".join(lines))

    return report_path
