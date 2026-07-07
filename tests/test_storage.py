"""
test_storage.py

Test suite for alert storage functionality.
"""

import pytest
import sys
import os
from pathlib import Path
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.storage import AlertStorage


@pytest.fixture
def storage():
    """Create a temporary test database."""
    db_path = "test_siem.db"

    # Remove existing test db
    if os.path.exists(db_path):
        os.remove(db_path)

    storage = AlertStorage(db_path)
    yield storage

    # Cleanup
    storage.close()
    if os.path.exists(db_path):
        os.remove(db_path)


class TestAlertStorage:
    """Test alert storage operations."""

    def test_store_alert(self, storage):
        alert = {
            "rule_id": "DET-0001",
            "title": "Test Alert",
            "severity": "high",
            "mitre_tactic": "Execution",
            "mitre_technique": "PowerShell",
            "mitre_attack_id": "T1059.001",
            "hostname": "WORKSTATION01",
            "user": "alice",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc ABCD",
            "timestamp": datetime.utcnow().isoformat()
        }

        alert_id = storage.store_alert(alert)
        assert alert_id > 0

    def test_query_alerts_all(self, storage):
        # Store multiple alerts
        for i in range(5):
            alert = {
                "rule_id": f"DET-000{i}",
                "title": f"Test Alert {i}",
                "severity": "medium",
                "timestamp": datetime.utcnow().isoformat()
            }
            storage.store_alert(alert)

        alerts = storage.query_alerts(limit=10)
        assert len(alerts) == 5

    def test_query_alerts_by_severity(self, storage):
        # Store alerts with different severities
        storage.store_alert({
            "rule_id": "DET-001",
            "title": "Critical Alert",
            "severity": "critical",
            "timestamp": datetime.utcnow().isoformat()
        })

        storage.store_alert({
            "rule_id": "DET-002",
            "title": "Medium Alert",
            "severity": "medium",
            "timestamp": datetime.utcnow().isoformat()
        })

        critical_alerts = storage.query_alerts(severity="critical")
        assert len(critical_alerts) == 1
        assert critical_alerts[0]["severity"] == "critical"

    def test_query_alerts_by_rule(self, storage):
        rule_id = "DET-0001"

        storage.store_alert({
            "rule_id": rule_id,
            "title": "Alert 1",
            "severity": "high",
            "timestamp": datetime.utcnow().isoformat()
        })

        storage.store_alert({
            "rule_id": "DET-0002",
            "title": "Alert 2",
            "severity": "high",
            "timestamp": datetime.utcnow().isoformat()
        })

        alerts = storage.query_alerts(rule_id=rule_id)
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == rule_id

    def test_query_alerts_by_time_range(self, storage):
        now = datetime.utcnow()
        yesterday = now - timedelta(days=1)

        # Store old alert
        storage.store_alert({
            "rule_id": "DET-001",
            "title": "Old Alert",
            "severity": "low",
            "timestamp": (now - timedelta(days=2)).isoformat()
        })

        # Store recent alert
        storage.store_alert({
            "rule_id": "DET-002",
            "title": "Recent Alert",
            "severity": "high",
            "timestamp": now.isoformat()
        })

        recent_alerts = storage.query_alerts(start_time=yesterday.isoformat())
        assert len(recent_alerts) == 1
        assert recent_alerts[0]["title"] == "Recent Alert"


class TestEventStorage:
    """Test event storage operations."""

    def test_store_event(self, storage):
        event = {
            "event_id": "4688",
            "timestamp": datetime.utcnow().isoformat(),
            "hostname": "SERVER01",
            "process_name": "cmd.exe"
        }

        event_id = storage.store_event(event, source="windows")
        assert event_id > 0


class TestRuleMetrics:
    """Test rule execution metrics."""

    def test_update_rule_metrics(self, storage):
        rule_id = "DET-0001"

        # First execution with match
        storage.update_rule_metrics(rule_id, matched=True)

        metrics = storage.get_rule_metrics(rule_id)
        assert len(metrics) == 1
        assert metrics[0]["execution_count"] == 1
        assert metrics[0]["match_count"] == 1

    def test_update_rule_metrics_multiple(self, storage):
        rule_id = "DET-0001"

        # Multiple executions
        storage.update_rule_metrics(rule_id, matched=True)
        storage.update_rule_metrics(rule_id, matched=False)
        storage.update_rule_metrics(rule_id, matched=True)

        metrics = storage.get_rule_metrics(rule_id)
        assert metrics[0]["execution_count"] == 3
        assert metrics[0]["match_count"] == 2


class TestStatistics:
    """Test alert statistics."""

    def test_get_statistics(self, storage):
        # Store various alerts
        storage.store_alert({
            "rule_id": "DET-001",
            "title": "Alert 1",
            "severity": "critical",
            "mitre_tactic": "Execution",
            "timestamp": datetime.utcnow().isoformat()
        })

        storage.store_alert({
            "rule_id": "DET-002",
            "title": "Alert 2",
            "severity": "high",
            "mitre_tactic": "Credential Access",
            "timestamp": datetime.utcnow().isoformat()
        })

        storage.store_alert({
            "rule_id": "DET-001",
            "title": "Alert 3",
            "severity": "critical",
            "mitre_tactic": "Execution",
            "timestamp": datetime.utcnow().isoformat()
        })

        stats = storage.get_alert_statistics()

        assert stats["total_alerts"] == 3
        assert stats["by_severity"]["critical"] == 2
        assert stats["by_severity"]["high"] == 1
        assert stats["by_tactic"]["Execution"] == 2
        assert stats["by_tactic"]["Credential Access"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
