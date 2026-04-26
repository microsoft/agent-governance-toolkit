# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Webhook Alerting.

Covers: Alert, AlertManager, ChannelConfig, formatters, delivery.
Uses CALLBACK channels for zero-network testing.
"""


from agent_sre.alerts import (
    Alert,
    AlertChannel,
    AlertManager,
    AlertSeverity,
    ChannelConfig,
    format_generic,
    format_opsgenie,
    format_pagerduty,
    format_slack,
    format_teams,
)

# =============================================================================
# Alert
# =============================================================================


class TestAlert:
    def test_basic(self):
        a = Alert(title="Test", message="Something happened")
        assert a.title == "Test"
        assert a.severity == AlertSeverity.WARNING

    def test_to_dict(self):
        a = Alert(title="SLO Breach", message="Budget exhausted", severity=AlertSeverity.CRITICAL)
        d = a.to_dict()
        assert d["title"] == "SLO Breach"
        assert d["severity"] == "critical"


# =============================================================================
# Formatters
# =============================================================================


class TestFormatters:
    def test_slack_format(self):
        a = Alert(
            title="SLO Breach",
            message="Error budget exhausted",
            severity=AlertSeverity.CRITICAL,
            agent_id="agent-1",
            slo_name="my-slo",
        )
        payload = format_slack(a)
        assert "blocks" in payload
        assert len(payload["blocks"]) >= 2

    def test_pagerduty_format(self):
        a = Alert(
            title="SLO Breach",
            message="Error budget exhausted",
            severity=AlertSeverity.CRITICAL,
            dedup_key="slo-breach-agent-1",
        )
        payload = format_pagerduty(a)
        assert payload["event_action"] == "trigger"
        assert payload["payload"]["severity"] == "critical"
        assert payload["dedup_key"] == "slo-breach-agent-1"

    def test_pagerduty_resolve(self):
        a = Alert(title="Resolved", message="OK", severity=AlertSeverity.RESOLVED)
        payload = format_pagerduty(a)
        assert payload["event_action"] == "resolve"

    def test_generic_format(self):
        a = Alert(title="Test", message="msg")
        payload = format_generic(a)
        assert payload["title"] == "Test"

    def test_slack_emoji(self):
        for sev, emoji in [
            (AlertSeverity.INFO, "ℹ️"),
            (AlertSeverity.WARNING, "⚠️"),
            (AlertSeverity.CRITICAL, "🚨"),
            (AlertSeverity.RESOLVED, "✅"),
        ]:
            a = Alert(title="Test", message="msg", severity=sev)
            payload = format_slack(a)
            header = payload["blocks"][0]["text"]["text"]
            assert emoji in header


# =============================================================================
# AlertManager
# =============================================================================


class TestAlertManager:
    def test_add_channel(self):
        m = AlertManager()
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
        ))
        assert "test" in m.list_channels()

    def test_remove_channel(self):
        m = AlertManager()
        m.add_channel(ChannelConfig(channel_type=AlertChannel.CALLBACK, name="test"))
        m.remove_channel("test")
        assert "test" not in m.list_channels()

    def test_callback_delivery(self):
        received = []
        m = AlertManager()
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
            callback=lambda a: received.append(a),
        ))
        alert = Alert(title="Test", message="Hello")
        results = m.send(alert)
        assert len(results) == 1
        assert results[0].success
        assert len(received) == 1
        assert received[0].title == "Test"

    def test_severity_filtering(self):
        received = []
        m = AlertManager()
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="critical-only",
            callback=lambda a: received.append(a),
            min_severity=AlertSeverity.CRITICAL,
        ))
        # Send WARNING — should be filtered out
        m.send(Alert(title="Warn", message="minor", severity=AlertSeverity.WARNING))
        assert len(received) == 0

        # Send CRITICAL — should go through
        m.send(Alert(title="Critical", message="major", severity=AlertSeverity.CRITICAL))
        assert len(received) == 1

    def test_disabled_channel(self):
        received = []
        m = AlertManager()
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="disabled",
            callback=lambda a: received.append(a),
            enabled=False,
        ))
        m.send(Alert(title="Test", message="msg"))
        assert len(received) == 0

    def test_multiple_channels(self):
        received_a = []
        received_b = []
        m = AlertManager()
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="channel-a",
            callback=lambda a: received_a.append(a),
        ))
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="channel-b",
            callback=lambda a: received_b.append(a),
        ))
        m.send(Alert(title="Test", message="msg", severity=AlertSeverity.CRITICAL))
        assert len(received_a) == 1
        assert len(received_b) == 1

    def test_callback_error_handled(self):
        def bad_callback(alert):
            raise RuntimeError("fail")

        m = AlertManager()
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="bad",
            callback=bad_callback,
        ))
        results = m.send(Alert(title="Test", message="msg"))
        assert len(results) == 1
        assert not results[0].success

    def test_history(self):
        m = AlertManager()
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
            callback=lambda a: None,
        ))
        m.send(Alert(title="A", message="1"))
        m.send(Alert(title="B", message="2"))
        assert len(m.history) == 2

    def test_stats(self):
        m = AlertManager()
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
            callback=lambda a: None,
        ))
        m.send(Alert(title="A", message="1"))
        stats = m.get_stats()
        assert stats["channels"] == 1
        assert stats["total_sent"] == 1
        assert stats["successful"] == 1

    def test_clear_history(self):
        m = AlertManager()
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
            callback=lambda a: None,
        ))
        m.send(Alert(title="A", message="1"))
        m.clear_history()
        assert len(m.history) == 0

    def test_no_url_webhook_fails(self):
        m = AlertManager()
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.SLACK,
            name="no-url",
            url="",
        ))
        results = m.send(Alert(title="Test", message="msg"))
        assert len(results) == 1
        assert not results[0].success

    def test_info_severity_filtered_by_default(self):
        received = []
        m = AlertManager()
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="warn-and-up",
            callback=lambda a: received.append(a),
            min_severity=AlertSeverity.WARNING,
        ))
        m.send(Alert(title="Info", message="msg", severity=AlertSeverity.INFO))
        assert len(received) == 0


# =============================================================================
# Integration: Alerts from MCP Drift
# =============================================================================


class TestMCPDriftAlerts:
    def test_drift_triggers_alert(self):
        from agent_sre.integrations.mcp import DriftDetector, ToolSchema, ToolSnapshot

        received = []
        manager = AlertManager()
        manager.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="drift-alerts",
            callback=lambda a: received.append(a),
        ))

        detector = DriftDetector()
        detector.set_baseline(ToolSnapshot(
            server_id="mcp-1",
            tools=[ToolSchema(name="search"), ToolSchema(name="calc")],
        ))
        report = detector.compare(ToolSnapshot(
            server_id="mcp-1",
            tools=[ToolSchema(name="search")],  # calc removed
        ))

        if report.has_drift:
            for drift_alert in report.alerts:
                manager.send(Alert(
                    title=f"MCP Drift: {drift_alert.drift_type.value}",
                    message=drift_alert.message,
                    severity=(
                        AlertSeverity.CRITICAL
                        if drift_alert.severity.value == "critical"
                        else AlertSeverity.WARNING
                    ),
                ))

        assert len(received) >= 1
        assert "calc" in received[0].message


class TestAlertDeduplication:
    def test_dedup_suppresses_repeat(self):
        received = []
        m = AlertManager(dedup_window_seconds=60)
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
            callback=lambda a: received.append(a),
        ))
        alert = Alert(title="Breach", message="Budget low", dedup_key="agent-1:slo-1")
        m.send(alert)
        m.send(alert)  # should be suppressed
        assert len(received) == 1
        assert m.suppressed_count == 1

    def test_dedup_allows_different_keys(self):
        received = []
        m = AlertManager(dedup_window_seconds=60)
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
            callback=lambda a: received.append(a),
        ))
        m.send(Alert(title="A", message="1", dedup_key="key-1"))
        m.send(Alert(title="B", message="2", dedup_key="key-2"))
        assert len(received) == 2

    def test_dedup_allows_no_key(self):
        received = []
        m = AlertManager(dedup_window_seconds=60)
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
            callback=lambda a: received.append(a),
        ))
        m.send(Alert(title="A", message="1"))
        m.send(Alert(title="A", message="1"))
        assert len(received) == 2

    def test_resolved_always_passes(self):
        received = []
        m = AlertManager(dedup_window_seconds=60)
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
            callback=lambda a: received.append(a),
        ))
        m.send(Alert(title="Breach", message="x", dedup_key="k1"))
        m.send(Alert(title="Resolved", message="ok", dedup_key="k1", severity=AlertSeverity.RESOLVED))
        assert len(received) == 2

    def test_suppressed_in_stats(self):
        m = AlertManager(dedup_window_seconds=60)
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
            callback=lambda a: None,
        ))
        m.send(Alert(title="A", message="1", dedup_key="k1"))
        m.send(Alert(title="A", message="1", dedup_key="k1"))
        stats = m.get_stats()
        assert stats["suppressed"] == 1


class TestSLOAlertAutoFire:
    def test_slo_fires_alert_on_breach(self):
        from agent_sre.slo.indicators import TaskSuccessRate
        from agent_sre.slo.objectives import SLO, ErrorBudget

        received = []
        manager = AlertManager()
        manager.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test",
            callback=lambda a: received.append(a),
            min_severity=AlertSeverity.INFO,
        ))

        slo = SLO(
            name="test-slo",
            indicators=[TaskSuccessRate(target=0.99)],
            error_budget=ErrorBudget(total=0.01),
            alert_manager=manager,
            agent_id="agent-1",
        )

        # Exhaust error budget
        slo.record_event(False)

        # Should have fired alert
        assert len(received) >= 1
        assert received[-1].severity in (AlertSeverity.CRITICAL, AlertSeverity.WARNING)
        assert received[-1].agent_id == "agent-1"
        assert received[-1].slo_name == "test-slo"

    def test_slo_no_alert_without_manager(self):
        from agent_sre.slo.indicators import TaskSuccessRate
        from agent_sre.slo.objectives import SLO, ErrorBudget

        slo = SLO(
            name="test-slo",
            indicators=[TaskSuccessRate(target=0.99)],
            error_budget=ErrorBudget(total=0.01),
        )
        # Should not raise
        slo.record_event(False)
        status = slo.evaluate()
        assert status is not None


# =============================================================================
# OpsGenie Formatter
# =============================================================================


class TestOpsGenieFormatter:
    def test_basic_format(self):
        a = Alert(title="SLO Breach", message="Budget low", severity=AlertSeverity.CRITICAL,
                  agent_id="agent-1", slo_name="my-slo")
        payload = format_opsgenie(a)
        assert payload["message"] == "SLO Breach"
        assert payload["priority"] == "P1"
        assert "agent:agent-1" in payload["tags"]
        assert payload["alias"] == "agent-1:my-slo"

    def test_info_priority(self):
        a = Alert(title="Info", message="ok", severity=AlertSeverity.INFO)
        payload = format_opsgenie(a)
        assert payload["priority"] == "P5"


# =============================================================================
# Teams Formatter
# =============================================================================


class TestTeamsFormatter:
    def test_basic_format(self):
        a = Alert(title="SLO Breach", message="Budget low", severity=AlertSeverity.CRITICAL,
                  agent_id="agent-1", slo_name="my-slo")
        payload = format_teams(a)
        assert payload["type"] == "message"
        card = payload["attachments"][0]["content"]
        assert card["type"] == "AdaptiveCard"
        body = card["body"]
        assert body[0]["text"] == "SLO Breach"

    def test_facts(self):
        a = Alert(title="Test", message="msg", agent_id="a1", slo_name="s1")
        payload = format_teams(a)
        facts = payload["attachments"][0]["content"]["body"][2]["facts"]
        fact_titles = [f["title"] for f in facts]
        assert "Agent" in fact_titles
        assert "SLO" in fact_titles


# =============================================================================
# OpsGenie & Teams Channel Registration
# =============================================================================


class TestOpsGenieChannel:
    def test_callback_delivery(self):
        received = []
        m = AlertManager()
        m.add_channel(ChannelConfig(
            channel_type=AlertChannel.OPSGENIE,
            name="opsgenie",
            callback=lambda a: received.append(a),
        ))
        assert AlertChannel.OPSGENIE in m._formatters

    def test_teams_formatter_registered(self):
        m = AlertManager()
        assert AlertChannel.TEAMS in m._formatters
