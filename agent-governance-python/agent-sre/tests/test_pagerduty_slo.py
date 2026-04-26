# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for PagerDuty SLO integration."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agent_sre.alerts import (
    Alert,
    AlertChannel,
    AlertManager,
    AlertSeverity,
    ChannelConfig,
)
from agent_sre.integrations.pagerduty import PagerDutyAlertConfig
from agent_sre.slo.objectives import ErrorBudget, SLO, SLOStatus


def _make_slo(
    name: str = "latency-p99",
    agent_id: str = "agent-1",
    budget_total: float = 0.01,
) -> SLO:
    """Create a minimal SLO for testing (no SLIs needed for status forcing)."""
    budget = ErrorBudget(total=budget_total, consumed=0.0)
    sli_mock = MagicMock()
    sli_mock.target = 0.99
    sli_mock.current_value.return_value = 0.999
    sli_mock.to_dict.return_value = {"name": "mock-sli", "target": 0.99}
    return SLO(
        name=name,
        indicators=[sli_mock],
        error_budget=budget,
        agent_id=agent_id,
    )


class TestPagerDutyAlertConfig:
    def test_registers_pagerduty_channel(self):
        """PagerDutyAlertConfig registers a PagerDuty channel with AlertManager."""
        manager = AlertManager()
        pd = PagerDutyAlertConfig(
            alert_manager=manager,
            routing_key="test-key",
        )

        assert pd.channel_name in manager.list_channels()

    def test_slo_breach_triggers_alert(self):
        """SLO transitioning to CRITICAL fires a PagerDuty alert."""
        sent_alerts: list[Alert] = []
        manager = AlertManager()

        # Use a callback channel to capture alerts
        manager.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test-capture",
            callback=lambda a: sent_alerts.append(a),
            min_severity=AlertSeverity.WARNING,
        ))

        pd = PagerDutyAlertConfig(
            alert_manager=manager,
            routing_key="test-key",
        )

        slo = _make_slo()

        # Exhaust the error budget to force CRITICAL/EXHAUSTED
        for _ in range(100):
            slo.error_budget.record_event(good=False)

        status = pd.watch_slo(slo, agent_id="agent-1")
        assert status in (SLOStatus.CRITICAL, SLOStatus.EXHAUSTED)

        # Should have fired at least one alert
        breach_alerts = [a for a in sent_alerts if "Breach" in a.title]
        assert len(breach_alerts) >= 1
        assert breach_alerts[0].severity in (AlertSeverity.CRITICAL, AlertSeverity.WARNING)

    def test_slo_recovery_resolves(self):
        """SLO recovering to HEALTHY sends a resolve event."""
        sent_alerts: list[Alert] = []
        manager = AlertManager()
        manager.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test-capture",
            callback=lambda a: sent_alerts.append(a),
            min_severity=AlertSeverity.INFO,
        ))

        pd = PagerDutyAlertConfig(
            alert_manager=manager,
            routing_key="test-key",
        )

        slo = _make_slo(budget_total=0.01)

        # Force into EXHAUSTED state
        for _ in range(100):
            slo.error_budget.record_event(good=False)
        pd.watch_slo(slo, agent_id="agent-1")

        # Now "recover" — reset budget
        slo.error_budget.consumed = 0.0
        slo.error_budget._events.clear()
        slo._last_status = None  # reset SLO's own status tracking

        status = pd.watch_slo(slo, agent_id="agent-1")
        assert status == SLOStatus.HEALTHY

        # Should have a RESOLVED alert
        resolved = [a for a in sent_alerts if a.severity == AlertSeverity.RESOLVED]
        assert len(resolved) >= 1
        assert "Recovered" in resolved[0].title

    def test_dedup_key_prevents_duplicates(self):
        """Same SLO breach doesn't re-fire alerts within dedup window."""
        sent_alerts: list[Alert] = []
        manager = AlertManager(dedup_window_seconds=300.0)
        manager.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test-capture",
            callback=lambda a: sent_alerts.append(a),
            min_severity=AlertSeverity.WARNING,
        ))

        pd = PagerDutyAlertConfig(
            alert_manager=manager,
            routing_key="test-key",
        )

        slo = _make_slo(budget_total=0.01)
        for _ in range(100):
            slo.error_budget.record_event(good=False)

        # First watch fires
        pd.watch_slo(slo, agent_id="agent-1")
        first_count = len(sent_alerts)
        assert first_count >= 1

        # Force status change tracking to pretend we haven't seen this status
        # but the AlertManager dedup should suppress the re-send
        pd._last_statuses.pop(slo.name, None)
        pd.watch_slo(slo, agent_id="agent-1")

        # The alert manager's dedup should suppress the duplicate
        assert manager.suppressed_count >= 1

    def test_resolve_event_format(self):
        """Verify the resolve payload uses event_action: 'resolve'."""
        from agent_sre.alerts import format_pagerduty

        resolve_alert = Alert(
            title="SLO Recovered: test-slo",
            message="SLO recovered to healthy",
            severity=AlertSeverity.RESOLVED,
            agent_id="agent-1",
            slo_name="test-slo",
            dedup_key="test-slo:agent-1",
        )

        payload = format_pagerduty(resolve_alert)
        assert payload["event_action"] == "resolve"
        assert payload["dedup_key"] == "test-slo:agent-1"

    def test_watch_slo_returns_healthy_for_good_slo(self):
        """A healthy SLO returns HEALTHY and doesn't fire."""
        sent_alerts: list[Alert] = []
        manager = AlertManager()
        manager.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test-capture",
            callback=lambda a: sent_alerts.append(a),
            min_severity=AlertSeverity.WARNING,
        ))

        pd = PagerDutyAlertConfig(
            alert_manager=manager,
            routing_key="test-key",
        )

        slo = _make_slo()
        # Record good events only
        for _ in range(10):
            slo.error_budget.record_event(good=True)

        status = pd.watch_slo(slo, agent_id="agent-1")
        assert status == SLOStatus.HEALTHY
        # No breach alerts should have fired
        breach_alerts = [a for a in sent_alerts if "Breach" in a.title]
        assert len(breach_alerts) == 0

    def test_remove_channel(self):
        """remove() unregisters the PagerDuty channel."""
        manager = AlertManager()
        pd = PagerDutyAlertConfig(
            alert_manager=manager,
            routing_key="test-key",
        )
        assert pd.channel_name in manager.list_channels()

        pd.remove()
        assert pd.channel_name not in manager.list_channels()
