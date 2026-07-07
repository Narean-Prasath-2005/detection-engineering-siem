"""
storage.py

SQLite-based persistent storage for alerts, events, and metrics.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any


class AlertStorage:
    """
    Manages persistent storage of detection alerts and events.
    """

    def __init__(self, db_path: str = "siem.db"):
        self.db_path = db_path
        self.conn = None
        self._initialize_db()

    def _initialize_db(self):
        """Create database schema if it doesn't exist."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Enable column access by name

        cursor = self.conn.cursor()

        # Alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                mitre_tactic TEXT,
                mitre_technique TEXT,
                mitre_attack_id TEXT,
                hostname TEXT,
                username TEXT,
                process_name TEXT,
                command_line TEXT,
                event_data TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Events table (raw events for investigation)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT,
                source TEXT,
                hostname TEXT,
                raw_data TEXT NOT NULL,
                processed BOOLEAN DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Rule execution metrics
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rule_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                execution_count INTEGER DEFAULT 0,
                match_count INTEGER DEFAULT 0,
                last_match TEXT,
                last_execution TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes for performance
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
            ON alerts(timestamp)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_rule_id
            ON alerts(rule_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_severity
            ON alerts(severity)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON events(timestamp)
        """)

        self.conn.commit()

    def store_alert(self, alert: Dict) -> int:
        """
        Store an alert in the database.

        Args:
            alert: Alert dictionary from detector

        Returns:
            Alert ID
        """
        cursor = self.conn.cursor()

        cursor.execute("""
            INSERT INTO alerts (
                timestamp, rule_id, title, severity,
                mitre_tactic, mitre_technique, mitre_attack_id,
                hostname, username, process_name, command_line,
                event_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert.get("timestamp", datetime.utcnow().isoformat()),
            alert.get("rule_id"),
            alert.get("title"),
            alert.get("severity"),
            alert.get("mitre_tactic"),
            alert.get("mitre_technique"),
            alert.get("mitre_attack_id"),
            alert.get("hostname"),
            alert.get("user"),
            alert.get("process_name"),
            alert.get("command_line"),
            json.dumps(alert)  # Store full alert as JSON
        ))

        self.conn.commit()
        return cursor.lastrowid

    def store_event(self, event: Dict, source: str = "unknown") -> int:
        """
        Store a raw event in the database.

        Args:
            event: Event dictionary
            source: Event source (auditd, windows, etc.)

        Returns:
            Event ID
        """
        cursor = self.conn.cursor()

        cursor.execute("""
            INSERT INTO events (
                timestamp, event_type, source, hostname, raw_data
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            event.get("timestamp", datetime.utcnow().isoformat()),
            event.get("event_type"),
            source,
            event.get("hostname"),
            json.dumps(event)
        ))

        self.conn.commit()
        return cursor.lastrowid

    def update_rule_metrics(self, rule_id: str, matched: bool = False):
        """
        Update execution metrics for a rule.

        Args:
            rule_id: Rule identifier
            matched: Whether the rule matched an event
        """
        cursor = self.conn.cursor()

        # Check if metrics exist
        cursor.execute("""
            SELECT id, execution_count, match_count
            FROM rule_metrics
            WHERE rule_id = ?
        """, (rule_id,))

        row = cursor.fetchone()

        if row:
            # Update existing metrics
            new_exec_count = row["execution_count"] + 1
            new_match_count = row["match_count"] + (1 if matched else 0)

            cursor.execute("""
                UPDATE rule_metrics
                SET execution_count = ?,
                    match_count = ?,
                    last_match = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE last_match END,
                    last_execution = CURRENT_TIMESTAMP
                WHERE rule_id = ?
            """, (new_exec_count, new_match_count, matched, rule_id))
        else:
            # Create new metrics entry
            cursor.execute("""
                INSERT INTO rule_metrics (rule_id, execution_count, match_count, last_match)
                VALUES (?, 1, ?, ?)
            """, (rule_id, 1 if matched else 0, datetime.utcnow().isoformat() if matched else None))

        self.conn.commit()

    def query_alerts(
        self,
        severity: Optional[str] = None,
        rule_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """
        Query alerts with optional filters.

        Args:
            severity: Filter by severity level
            rule_id: Filter by rule ID
            start_time: Filter by start timestamp (ISO format)
            end_time: Filter by end timestamp (ISO format)
            limit: Maximum number of results

        Returns:
            List of alert dictionaries
        """
        cursor = self.conn.cursor()

        query = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if rule_id:
            query += " AND rule_id = ?"
            params.append(rule_id)

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)

        results = []
        for row in cursor.fetchall():
            results.append(dict(row))

        return results

    def get_alert_statistics(self) -> Dict[str, Any]:
        """
        Get aggregate statistics about alerts.

        Returns:
            Dictionary with statistics
        """
        cursor = self.conn.cursor()

        # Total alerts
        cursor.execute("SELECT COUNT(*) as count FROM alerts")
        total_alerts = cursor.fetchone()["count"]

        # Alerts by severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM alerts
            GROUP BY severity
        """)
        by_severity = {row["severity"]: row["count"] for row in cursor.fetchall()}

        # Top 5 rules by alert count
        cursor.execute("""
            SELECT rule_id, title, COUNT(*) as count
            FROM alerts
            GROUP BY rule_id
            ORDER BY count DESC
            LIMIT 5
        """)
        top_rules = [dict(row) for row in cursor.fetchall()]

        # Alerts by MITRE tactic
        cursor.execute("""
            SELECT mitre_tactic, COUNT(*) as count
            FROM alerts
            WHERE mitre_tactic IS NOT NULL
            GROUP BY mitre_tactic
        """)
        by_tactic = {row["mitre_tactic"]: row["count"] for row in cursor.fetchall()}

        return {
            "total_alerts": total_alerts,
            "by_severity": by_severity,
            "top_rules": top_rules,
            "by_tactic": by_tactic
        }

    def get_rule_metrics(self, rule_id: Optional[str] = None) -> List[Dict]:
        """
        Get rule execution metrics.

        Args:
            rule_id: Optional specific rule ID

        Returns:
            List of metric dictionaries
        """
        cursor = self.conn.cursor()

        if rule_id:
            cursor.execute("""
                SELECT * FROM rule_metrics WHERE rule_id = ?
            """, (rule_id,))
        else:
            cursor.execute("""
                SELECT * FROM rule_metrics ORDER BY match_count DESC
            """)

        return [dict(row) for row in cursor.fetchall()]

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
