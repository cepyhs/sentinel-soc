import sqlite3
from datetime import datetime


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
