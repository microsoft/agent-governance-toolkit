# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for PersistentAlertManager."""

import sqlite3

import pytest

from agent_sre.alerts import (
    Alert,
    AlertChannel,
    AlertSeverity,
    ChannelConfig,
    PersistentAlertManager,
)


class TestPersistentAlertManager:
    @pytest.fixture
    def manager(self, tmp_path):
        db_path = str(tmp_path / "test_alerts.db")
        m = PersistentAlertManager(db_path=db_path)
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
            callback=lambda a: None,
        ))
        return m

    def test_persist_alert(self, manager):
        manager.send(Alert(title="Test", message="msg"))
        assert manager.alert_count() == 1

    def test_query_alerts(self, manager):
        manager.send(Alert(title="A", message="1", agent_id="a1"))
        manager.send(Alert(title="B", message="2", agent_id="a2"))
        all_alerts = manager.query_alerts()
        assert len(all_alerts) == 2
        a1_alerts = manager.query_alerts(agent_id="a1")
        assert len(a1_alerts) == 1

    def test_query_by_severity(self, manager):
        manager.send(Alert(title="Warn", message="w", severity=AlertSeverity.WARNING))
        manager.send(Alert(title="Crit", message="c", severity=AlertSeverity.CRITICAL))
        critical = manager.query_alerts(severity="critical")
        assert len(critical) == 1
        assert critical[0]["severity"] == "critical"

    def test_delivery_results_persisted(self, manager):
        manager.send(Alert(title="Test", message="msg"))
        conn = sqlite3.connect(manager._db_path)
        results = conn.execute("SELECT * FROM delivery_results").fetchall()
        conn.close()
        assert len(results) >= 1

    def test_inherits_dedup(self, manager):
        manager.send(Alert(title="A", message="1", dedup_key="k1"))
        manager.send(Alert(title="A", message="1", dedup_key="k1"))
        # Dedup should suppress 2nd, but 1st should be persisted
        assert manager.alert_count() == 1
        assert manager.suppressed_count == 1

    def test_query_limit(self, manager):
        for i in range(20):
            manager.send(Alert(title=f"Alert-{i}", message=f"msg-{i}"))
        limited = manager.query_alerts(limit=5)
        assert len(limited) == 5
