# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for alert deduplication and storm protection (issue #52).

Covers: AlertDeduplicator, AlertBatcher, alert_fingerprint, and
integration with the existing AlertManager.
"""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

from agent_sre.alerts import (
    Alert,
    AlertBatcher,
    AlertChannel,
    AlertDeduplicator,
    AlertManager,
    AlertSeverity,
    ChannelConfig,
    alert_fingerprint,
)

# =============================================================================
# alert_fingerprint
# =============================================================================


class TestAlertFingerprint:
    def test_same_fields_produce_same_fingerprint(self):
        a1 = Alert(title="SLO Breach", message="x", agent_id="agent-1")
        a2 = Alert(title="SLO Breach", message="y", agent_id="agent-1")
        assert alert_fingerprint(a1) == alert_fingerprint(a2)

    def test_different_fields_produce_different_fingerprint(self):
        a1 = Alert(title="SLO Breach", message="x", agent_id="agent-1")
        a2 = Alert(title="SLO Breach", message="x", agent_id="agent-2")
        assert alert_fingerprint(a1) != alert_fingerprint(a2)

    def test_custom_group_by(self):
        a1 = Alert(title="A", message="x", agent_id="agent-1", slo_name="s1")
        a2 = Alert(title="B", message="y", agent_id="agent-1", slo_name="s1")
        fp1 = alert_fingerprint(a1, fields=("agent_id", "slo_name"))
        fp2 = alert_fingerprint(a2, fields=("agent_id", "slo_name"))
        assert fp1 == fp2

    def test_fingerprint_is_hex_string(self):
        a = Alert(title="Test", message="msg")
        fp = alert_fingerprint(a)
        assert isinstance(fp, str)
        assert len(fp) == 64  # SHA-256

    def test_missing_field_uses_empty_string(self):
        a = Alert(title="Test", message="msg")
        fp = alert_fingerprint(a, fields=("agent_id", "nonexistent_field"))
        assert isinstance(fp, str)


# =============================================================================
# AlertDeduplicator
# =============================================================================


class TestAlertDeduplicator:
    def test_first_alert_passes(self):
        d = AlertDeduplicator(window_seconds=60)
        a = Alert(title="Breach", message="x", agent_id="a1")
        assert d.should_send(a) is True

    def test_duplicate_within_window_suppressed(self):
        d = AlertDeduplicator(window_seconds=60)
        a = Alert(title="Breach", message="x", agent_id="a1")
        assert d.should_send(a) is True
        d.record(a)
        assert d.should_send(a) is False

    def test_duplicate_after_window_passes(self):
        d = AlertDeduplicator(window_seconds=1)
        a = Alert(title="Breach", message="x", agent_id="a1")
        assert d.should_send(a) is True
        d.record(a)
        # Patch time to simulate window expiry
        with patch("agent_sre.alerts.dedup.time") as mock_time:
            mock_time.time.return_value = time.time() + 2
            assert d.should_send(a) is True

    def test_different_alerts_not_deduplicated(self):
        d = AlertDeduplicator(window_seconds=60)
        a1 = Alert(title="Breach", message="x", agent_id="a1")
        a2 = Alert(title="Breach", message="x", agent_id="a2")
        assert d.should_send(a1) is True
        d.record(a1)
        assert d.should_send(a2) is True

    def test_resolved_always_passes(self):
        d = AlertDeduplicator(window_seconds=60)
        a = Alert(title="Breach", message="x", agent_id="a1")
        assert d.should_send(a) is True
        d.record(a)
        resolved = Alert(
            title="Breach", message="ok", agent_id="a1",
            severity=AlertSeverity.RESOLVED,
        )
        assert d.should_send(resolved) is True

    def test_resolved_clears_window(self):
        d = AlertDeduplicator(window_seconds=60)
        a = Alert(title="Breach", message="x", agent_id="a1")
        d.record(a)
        resolved = Alert(
            title="Breach", message="ok", agent_id="a1",
            severity=AlertSeverity.RESOLVED,
        )
        d.should_send(resolved)
        # After resolved, same alert should pass again
        assert d.should_send(a) is True

    def test_record_updates_timestamp(self):
        d = AlertDeduplicator(window_seconds=60)
        a = Alert(title="Breach", message="x", agent_id="a1")
        d.record(a)
        stats = d.get_stats()
        assert stats["unique_alerts"] == 1

    def test_get_stats(self):
        d = AlertDeduplicator(window_seconds=60)
        a = Alert(title="Breach", message="x", agent_id="a1")
        d.should_send(a)
        d.record(a)
        d.should_send(a)  # duplicate
        stats = d.get_stats()
        assert stats["total_received"] == 2
        assert stats["total_deduplicated"] == 1
        assert stats["unique_alerts"] == 1

    def test_clear(self):
        d = AlertDeduplicator(window_seconds=60)
        a = Alert(title="Breach", message="x", agent_id="a1")
        d.should_send(a)
        d.record(a)
        d.should_send(a)
        d.clear()
        stats = d.get_stats()
        assert stats["total_received"] == 0
        assert stats["total_deduplicated"] == 0
        assert stats["unique_alerts"] == 0
        # After clear, same alert should pass
        assert d.should_send(a) is True

    def test_custom_group_by(self):
        d = AlertDeduplicator(window_seconds=60, group_by=("slo_name",))
        a1 = Alert(title="A", message="x", agent_id="a1", slo_name="s1")
        a2 = Alert(title="B", message="y", agent_id="a2", slo_name="s1")
        assert d.should_send(a1) is True
        d.record(a1)
        # Different agent_id but same slo_name should be suppressed
        assert d.should_send(a2) is False

    def test_thread_safety(self):
        d = AlertDeduplicator(window_seconds=60)
        results = []

        def check_and_record(agent_id: str):
            a = Alert(title="Breach", message="x", agent_id=agent_id)
            if d.should_send(a):
                d.record(a)
                results.append(agent_id)

        threads = [
            threading.Thread(target=check_and_record, args=(f"agent-{i}",))
            for i in range(20)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Each unique agent should appear exactly once
        assert len(results) == 20
        assert len(set(results)) == 20


# =============================================================================
# AlertBatcher
# =============================================================================


class TestAlertBatcher:
    def test_add_and_flush(self):
        b = AlertBatcher(batch_window_seconds=60)
        a1 = Alert(title="A", message="1")
        a2 = Alert(title="B", message="2")
        b.add(a1)
        b.add(a2)
        assert b.size == 2
        flushed = b.flush()
        assert len(flushed) == 2
        assert b.size == 0

    def test_flush_empty(self):
        b = AlertBatcher()
        flushed = b.flush()
        assert flushed == []

    def test_is_ready_max_batch_size(self):
        b = AlertBatcher(max_batch_size=3)
        assert b.is_ready() is False
        b.add(Alert(title="A", message="1"))
        b.add(Alert(title="B", message="2"))
        assert b.is_ready() is False
        b.add(Alert(title="C", message="3"))
        assert b.is_ready() is True

    def test_is_ready_window_expiry(self):
        b = AlertBatcher(batch_window_seconds=1)
        b.add(Alert(title="A", message="1"))
        assert b.is_ready() is False
        with patch("agent_sre.alerts.dedup.time") as mock_time:
            mock_time.time.return_value = time.time() + 2
            assert b.is_ready() is True

    def test_is_ready_empty_batch(self):
        b = AlertBatcher(batch_window_seconds=0)
        assert b.is_ready() is False

    def test_digest_empty(self):
        b = AlertBatcher()
        assert b.get_digest() == "No alerts in batch."

    def test_digest_with_alerts(self):
        b = AlertBatcher()
        b.add(Alert(title="SLO Breach", message="x", severity=AlertSeverity.CRITICAL))
        b.add(Alert(title="Budget Low", message="y", severity=AlertSeverity.WARNING))
        b.add(Alert(title="All Clear", message="z", severity=AlertSeverity.INFO))
        digest = b.get_digest()
        assert "3 alerts" in digest
        assert "critical: 1" in digest
        assert "warning: 1" in digest
        assert "info: 1" in digest
        assert "[CRITICAL] SLO Breach" in digest

    def test_digest_truncates_at_10(self):
        b = AlertBatcher()
        for i in range(15):
            b.add(Alert(title=f"Alert-{i}", message="x"))
        digest = b.get_digest()
        assert "15 alerts" in digest
        assert "... and 5 more" in digest

    def test_digest_single_alert(self):
        b = AlertBatcher()
        b.add(Alert(title="Only One", message="x"))
        digest = b.get_digest()
        assert "1 alert)" in digest

    def test_flush_resets_window(self):
        b = AlertBatcher(batch_window_seconds=60)
        b.add(Alert(title="A", message="1"))
        b.flush()
        # After flush, adding a new alert should start a new window
        b.add(Alert(title="B", message="2"))
        assert b.size == 1

    def test_thread_safety(self):
        b = AlertBatcher(max_batch_size=100)
        threads = [
            threading.Thread(
                target=lambda i=i: b.add(Alert(title=f"T-{i}", message="x")),
            )
            for i in range(50)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert b.size == 50


# =============================================================================
# Integration: AlertDeduplicator + AlertManager
# =============================================================================


class TestDeduplicatorWithManager:
    """Verify AlertDeduplicator works as middleware around AlertManager."""

    def test_dedup_wraps_manager(self):
        received = []
        dedup = AlertDeduplicator(window_seconds=60)
        manager = AlertManager()
        manager.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
            callback=lambda a: received.append(a),
        ))

        alert = Alert(title="Breach", message="x", agent_id="a1")
        # First send
        if dedup.should_send(alert):
            dedup.record(alert)
            manager.send(alert)
        # Duplicate
        if dedup.should_send(alert):
            dedup.record(alert)
            manager.send(alert)

        assert len(received) == 1
        stats = dedup.get_stats()
        assert stats["total_deduplicated"] == 1

    def test_batcher_with_manager(self):
        received = []
        batcher = AlertBatcher(max_batch_size=3)
        manager = AlertManager()
        manager.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
            callback=lambda a: received.append(a),
        ))

        for i in range(3):
            batcher.add(Alert(title=f"Alert-{i}", message="x"))

        assert batcher.is_ready()
        for alert in batcher.flush():
            manager.send(alert)
        assert len(received) == 3

    def test_dedup_and_batcher_combined(self):
        """Full pipeline: dedup -> batch -> send."""
        received = []
        dedup = AlertDeduplicator(window_seconds=60)
        batcher = AlertBatcher(max_batch_size=10)
        manager = AlertManager()
        manager.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
            callback=lambda a: received.append(a),
        ))

        alerts = [
            Alert(title="Breach", message="x", agent_id="a1"),
            Alert(title="Breach", message="x", agent_id="a1"),  # dup
            Alert(title="Breach", message="x", agent_id="a2"),  # different
            Alert(title="Budget", message="y", agent_id="a1"),  # different title
        ]

        for alert in alerts:
            if dedup.should_send(alert):
                dedup.record(alert)
                batcher.add(alert)

        # 3 unique alerts should be batched
        assert batcher.size == 3
        for alert in batcher.flush():
            manager.send(alert)
        assert len(received) == 3
