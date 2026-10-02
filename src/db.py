import sqlite3
from datetime import datetime, timezone

class AlertDB:
    def __init__(self, db_path="alerts.db"):
        self.conn = sqlite3.connect(db_path)
        self.create_table()

    def create_table(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    source_ip TEXT,
                    attack_type TEXT,
                    severity TEXT,
                    details TEXT
                );
            """)

    def insert_alert(self, src_ip: str, attack_type: str, severity: str, details: str):
        with self.conn:
            self.conn.execute("""
                INSERT INTO alerts (timestamp, source_ip, attack_type, severity, details)
                VALUES (?, ?, ?, ?, ?)
            """, (datetime.now(timezone.utc).isoformat(), src_ip, attack_type, severity, details))

    def get_summary(self):
        cur = self.conn.cursor()
        cur.execute("""
            SELECT source_ip, attack_type, severity, COUNT(*) as detections
            FROM alerts
            GROUP BY source_ip, attack_type, severity
            ORDER BY detections DESC;
        """)
        return cur.fetchall()
