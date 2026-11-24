# SENTINEL — Autonomous SOC Triage & Behavioral Anomaly Engine

**SENTINEL** is a lightweight, modular SIEM/SOAR prototype built in Python and SQLite3 for Linux environments. Designed to combat SOC alert fatigue, it combines statistical anomaly detection, threat intelligence enrichment, MITRE ATT&CK mapping, and whitelist-protected automated containment.

## System Architecture

~~~mermaid
flowchart LR
    A[Raw Linux & DNS Logs] --> B[Regex Log Parser]
    B --> C[(SQLite3 Storage)]
    B --> D[Behavioral Anomaly Engine]
    D -->|Shannon Entropy >= 3.8| E[DNS Tunneling Alert<br/>MITRE T1071.004]
    D -->|Z-Score Outlier >= 1.5| F[Brute-Force Alert<br/>MITRE T1110]
    F --> G[Threat Intel Enrichment<br/>AbuseIPDB API]
    E & G --> H[SOAR Safe Responder<br/>Whitelist Check + UFW]
    H --> I[Automated Markdown<br/>Incident Report]
~~~

## Detection Capabilities & MITRE ATT&CK Mapping

| Technique ID | Attack Vector | Detection Method | Automated Response |
| :--- | :--- | :--- | :--- |
| **T1071.004** | DNS Tunneling / Data Exfiltration | **Shannon Entropy** ($H(X) = -\sum P(x_i)\log_2 P(x_i)$) on subdomains | Internal host whitelisted from firewall block; DNS sinkhole recommended |
| **T1110** | SSH Credential Brute-Force | **Z-Score Outlier Analysis** ($Z = \frac{x - \mu}{\sigma}$) + Threat Intel scoring | Active containment via `ufw` (Safe Dry-Run supported) |

## Quick Start

~~~bash
git clone https://github.com/<USERNAME_GITHUB>/sentinel-soc.git
cd sentinel-soc

# (Optional) Set AbuseIPDB API key for live threat intelligence
export ABUSEIPDB_API_KEY="your_api_key_here"

# Run detection engine on sample telemetry
python3 main.py
~~~

## Sample Output
- **Database Telemetry:** Persists structured authentication events and confirmed alerts in `sentinel.db`.
- **Incident Reports:** Automatically generates timestamped Markdown investigation reports inside `reports/`.
