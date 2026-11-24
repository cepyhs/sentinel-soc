import sqlite3
from datetime import datetime, timedelta


class SentinelDB:
    def __init__(self, db_path="sentinel.db"):
        self.conn = sqlite3.connect(db_path)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                username TEXT,
                source_ip TEXT,
                status TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detected_at TEXT,
                mitre_id TEXT,
                alert_type TEXT,
                indicator TEXT,
                metric_value REAL,
                severity TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_cache (
                ip TEXT PRIMARY KEY,
                abuse_score INTEGER,
                country TEXT,
                isp TEXT,
                total_reports INTEGER,
                cached_at TEXT
            )
        """)
        self.conn.commit()

    def log_auth_event(self, timestamp, username, source_ip, status):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO auth_events (timestamp, username, source_ip, status) VALUES (?, ?, ?, ?)",
            (timestamp, username, source_ip, status),
        )
        self.conn.commit()

    def save_alert(self, mitre_id, alert_type, indicator, metric_value, severity):
        cursor = self.conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO alerts (detected_at, mitre_id, alert_type, indicator, metric_value, severity) VALUES (?, ?, ?, ?, ?, ?)",
            (now, mitre_id, alert_type, indicator, metric_value, severity),
        )
        self.conn.commit()

    def get_cached_ip(self, ip: str, ttl_hours: int = 24):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT abuse_score, country, isp, total_reports, cached_at FROM ip_cache WHERE ip = ?",
            (ip,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        cached_time = datetime.strptime(row[4], "%Y-%m-%d %H:%M:%S")
        if datetime.now() - cached_time > timedelta(hours=ttl_hours):
            return None

        return {
            "source": "SQLite Cache (24h TTL)",
            "abuse_score": row[0],
            "country": row[1],
            "isp": row[2],
            "total_reports": row[3],
        }

    def save_ip_cache(self, ip: str, intel: dict):
        cursor = self.conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT OR REPLACE INTO ip_cache (ip, abuse_score, country, isp, total_reports, cached_at) VALUES (?, ?, ?, ?, ?, ?)",
            (ip, intel["abuse_score"], intel["country"], intel["isp"], intel["total_reports"], now),
        )
        self.conn.commit()
