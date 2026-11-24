import math
import statistics
from collections import Counter


def calculate_shannon_entropy(text: str) -> float:
    """Menghitung entropi Shannon (bit per karakter) untuk mendeteksi string acak/terenkripsi."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )
    return round(entropy, 4)


def detect_dns_tunneling(domain: str, threshold: float = 3.8) -> dict:
    """Menganalisis subdomain untuk mendeteksi potensi penyelundupan data via DNS."""
    subdomain = domain.split(".")[0]
    entropy = calculate_shannon_entropy(subdomain)
    is_anomalous = entropy >= threshold and len(subdomain) >= 12
    return {
        "domain": domain,
        "subdomain": subdomain,
        "entropy": entropy,
        "is_anomalous": is_anomalous,
    }


def detect_brute_force_zscore(ip_counts: dict, z_threshold: float = 1.5, min_attempts: int = 5) -> list:
    """Mendeteksi IP penyerang brute-force menggunakan analisis outlier Z-Score."""
    if not ip_counts:
        return []

    values = list(ip_counts.values())
    mean_val = statistics.mean(values)
    stdev_val = statistics.pstdev(values)

    anomalies = []
    for ip, count in ip_counts.items():
        z_score = (count - mean_val) / stdev_val if stdev_val > 0 else float(count)
        if count >= min_attempts and z_score >= z_threshold:
            anomalies.append({
                "ip": ip,
                "attempts": count,
                "z_score": round(z_score, 2),
                "baseline_mean": round(mean_val, 2),
            })
    return anomalies
