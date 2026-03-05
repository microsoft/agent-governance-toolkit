# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Webhook Alerting for Agent-SRE.

Send alerts to external systems when SLO breaches, incidents,
or cost anomalies are detected. Supports multiple channels.

No external dependencies — uses urllib for HTTP calls.
Includes formatters for Slack, PagerDuty, and generic webhooks.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from collections.abc import Callable


class AlertChannel(Enum):
    """Supported alert channel types."""

    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    GENERIC_WEBHOOK = "generic_webhook"
    CALLBACK = "callback"  # In-process callback (for testing)
    OPSGENIE = "opsgenie"
    TEAMS = "teams"


class AlertSeverity(Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    RESOLVED = "resolved"


@dataclass
class Alert:
    """An alert to be sent to external systems."""

    title: str
    message: str
    severity: AlertSeverity = AlertSeverity.WARNING
    source: str = "agent-sre"
    agent_id: str = ""
    slo_name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    dedup_key: str = ""  # For PagerDuty deduplication

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "message": self.message,
            "severity": self.severity.value,
            "source": self.source,
            "agent_id": self.agent_id,
            "slo_name": self.slo_name,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class ChannelConfig:
    """Configuration for an alert channel."""

    channel_type: AlertChannel
    name: str
    url: str = ""  # Webhook URL
    token: str = ""  # Auth token (for PagerDuty routing key, etc.)
    callback: Callable[[Alert], None] | None = None  # For CALLBACK type
    min_severity: AlertSeverity = AlertSeverity.WARNING
    enabled: bool = True


@dataclass
class DeliveryResult:
    """Result of attempting to deliver an alert."""

    channel_name: str
    success: bool
    status_code: int = 0
    error: str = ""
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


def format_slack(alert: Alert) -> dict[str, Any]:
    """Format alert as Slack incoming webhook payload."""
    severity_emoji = {
        AlertSeverity.INFO: "ℹ️",
        AlertSeverity.WARNING: "⚠️",
        AlertSeverity.CRITICAL: "🚨",
        AlertSeverity.RESOLVED: "✅",
    }
    emoji = severity_emoji.get(alert.severity, "📋")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{emoji} {alert.title}"},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": alert.message},
        },
    ]

    fields = []
    if alert.agent_id:
        fields.append({"type": "mrkdwn", "text": f"*Agent:* {alert.agent_id}"})
    if alert.slo_name:
        fields.append({"type": "mrkdwn", "text": f"*SLO:* {alert.slo_name}"})
    fields.append({"type": "mrkdwn", "text": f"*Severity:* {alert.severity.value}"})

    if fields:
        blocks.append({"type": "section", "fields": fields})

    return {"blocks": blocks}


def format_pagerduty(alert: Alert) -> dict[str, Any]:
    """Format alert as PagerDuty Events API v2 payload."""
    pd_severity = {
        AlertSeverity.INFO: "info",
        AlertSeverity.WARNING: "warning",
        AlertSeverity.CRITICAL: "critical",
        AlertSeverity.RESOLVED: "info",
    }

    event_action = "resolve" if alert.severity == AlertSeverity.RESOLVED else "trigger"

    payload: dict[str, Any] = {
        "event_action": event_action,
        "payload": {
            "summary": f"{alert.title}: {alert.message}",
            "severity": pd_severity.get(alert.severity, "warning"),
            "source": alert.source,
            "component": alert.agent_id or "agent-sre",
            "group": alert.slo_name or "default",
            "custom_details": alert.metadata,
        },
    }

    if alert.dedup_key:
        payload["dedup_key"] = alert.dedup_key

    return payload


def format_generic(alert: Alert) -> dict[str, Any]:
    """Format alert as generic JSON webhook payload."""
    return alert.to_dict()


def format_opsgenie(alert: Alert) -> dict[str, Any]:
    """Format alert as OpsGenie Alert API payload."""
    priority_map = {
        AlertSeverity.INFO: "P5",
        AlertSeverity.WARNING: "P3",
        AlertSeverity.CRITICAL: "P1",
        AlertSeverity.RESOLVED: "P5",
    }
    payload: dict[str, Any] = {
        "message": alert.title,
        "description": alert.message,
        "priority": priority_map.get(alert.severity, "P3"),
        "source": alert.source,
        "tags": [f"agent:{alert.agent_id}"] if alert.agent_id else [],
        "details": alert.metadata,
    }
    if alert.slo_name:
        payload["alias"] = f"{alert.agent_id}:{alert.slo_name}"
        payload["tags"].append(f"slo:{alert.slo_name}")
    return payload


def format_teams(alert: Alert) -> dict[str, Any]:
    """Format alert as Microsoft Teams incoming webhook payload (Adaptive Card)."""
    severity_color = {
        AlertSeverity.INFO: "default",
        AlertSeverity.WARNING: "warning",
        AlertSeverity.CRITICAL: "attention",
        AlertSeverity.RESOLVED: "good",
    }
    facts = []
    if alert.agent_id:
        facts.append({"title": "Agent", "value": alert.agent_id})
    if alert.slo_name:
        facts.append({"title": "SLO", "value": alert.slo_name})
    facts.append({"title": "Severity", "value": alert.severity.value})

    card = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": alert.title,
                        "weight": "bolder",
                        "size": "large",
                        "color": severity_color.get(alert.severity, "default"),
                    },
                    {
                        "type": "TextBlock",
                        "text": alert.message,
                        "wrap": True,
                    },
                    {
                        "type": "FactSet",
                        "facts": facts,
                    },
                ],
            },
        }],
    }
    return card


# ---------------------------------------------------------------------------
# AlertManager
# ---------------------------------------------------------------------------


class AlertManager:
    """
    Manages alert channels and dispatches alerts.

    Usage:
        manager = AlertManager()
        manager.add_channel(ChannelConfig(
            channel_type=AlertChannel.SLACK,
            name="ops-slack",
            url="https://hooks.slack.com/services/...",
        ))

        manager.send(Alert(
            title="SLO Breach",
            message="Error budget exhausted for agent-1",
            severity=AlertSeverity.CRITICAL,
        ))
    """

    def __init__(self, dedup_window_seconds: float = 300.0) -> None:
        self._channels: dict[str, ChannelConfig] = {}
        self._history: list[DeliveryResult] = []
        self._dedup_window_seconds = dedup_window_seconds
        self._dedup_cache: dict[str, float] = {}
        self._suppressed_count: int = 0
        self._formatters = {
            AlertChannel.SLACK: format_slack,
            AlertChannel.PAGERDUTY: format_pagerduty,
            AlertChannel.GENERIC_WEBHOOK: format_generic,
            AlertChannel.CALLBACK: format_generic,
            AlertChannel.OPSGENIE: format_opsgenie,
            AlertChannel.TEAMS: format_teams,
        }

    def add_channel(self, config: ChannelConfig) -> None:
        self._channels[config.name] = config

    def remove_channel(self, name: str) -> None:
        self._channels.pop(name, None)

    def list_channels(self) -> list[str]:
        return list(self._channels.keys())

    @property
    def suppressed_count(self) -> int:
        return self._suppressed_count

    def send(self, alert: Alert) -> list[DeliveryResult]:
        """Send alert to all matching channels."""
        # Deduplication check
        if alert.dedup_key:
            if alert.severity == AlertSeverity.RESOLVED:
                self._dedup_cache.pop(alert.dedup_key, None)
            else:
                now = time.time()
                last_sent = self._dedup_cache.get(alert.dedup_key)
                if last_sent is not None and (now - last_sent) < self._dedup_window_seconds:
                    self._suppressed_count += 1
                    return []
                self._dedup_cache[alert.dedup_key] = now

        results: list[DeliveryResult] = []
        severity_order = [AlertSeverity.INFO, AlertSeverity.WARNING,
                          AlertSeverity.CRITICAL, AlertSeverity.RESOLVED]

        for _name, config in self._channels.items():
            if not config.enabled:
                continue

            # Check minimum severity
            alert_idx = severity_order.index(alert.severity) if alert.severity in severity_order else 0
            min_idx = severity_order.index(config.min_severity) if config.min_severity in severity_order else 0
            if alert_idx < min_idx:
                continue

            result = self._deliver(config, alert)
            results.append(result)
            self._history.append(result)

        return results

    def _deliver(self, config: ChannelConfig, alert: Alert) -> DeliveryResult:
        """Deliver alert to a single channel."""
        try:
            if config.channel_type == AlertChannel.CALLBACK:
                if config.callback:
                    config.callback(alert)
                return DeliveryResult(channel_name=config.name, success=True)

            formatter = self._formatters.get(config.channel_type, format_generic)
            payload = formatter(alert)

            # Add auth token for PagerDuty
            if config.channel_type == AlertChannel.PAGERDUTY and config.token:
                payload["routing_key"] = config.token

            headers: dict[str, str] | None = None
            if config.channel_type == AlertChannel.OPSGENIE and config.token:
                headers = {"Authorization": f"GenieKey {config.token}"}

            return self._http_post(config.name, config.url, payload, headers=headers)

        except Exception as e:
            return DeliveryResult(
                channel_name=config.name,
                success=False,
                error=str(e),
            )

    def _http_post(self, channel_name: str, url: str, payload: dict,
                   headers: dict[str, str] | None = None) -> DeliveryResult:
        """Send HTTP POST. Isolated for testability."""
        if not url:
            return DeliveryResult(
                channel_name=channel_name,
                success=False,
                error="No URL configured",
            )

        try:
            data = json.dumps(payload).encode("utf-8")
            req_headers = {"Content-Type": "application/json"}
            if headers:
                req_headers.update(headers)
            req = urllib.request.Request(
                url,
                data=data,
                headers=req_headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return DeliveryResult(
                    channel_name=channel_name,
                    success=True,
                    status_code=resp.status,
                )
        except urllib.error.HTTPError as e:
            return DeliveryResult(
                channel_name=channel_name,
                success=False,
                status_code=e.code,
                error=str(e),
            )
        except Exception as e:
            return DeliveryResult(
                channel_name=channel_name,
                success=False,
                error=str(e),
            )

    @property
    def history(self) -> list[DeliveryResult]:
        return list(self._history)

    def get_stats(self) -> dict[str, Any]:
        return {
            "channels": len(self._channels),
            "total_sent": len(self._history),
            "successful": sum(1 for r in self._history if r.success),
            "failed": sum(1 for r in self._history if not r.success),
            "suppressed": self._suppressed_count,
        }

    def clear_history(self) -> None:
        self._history.clear()


class PersistentAlertManager(AlertManager):
    """AlertManager with SQLite-backed alert history.

    Persists all alerts and delivery results to a SQLite database
    for audit trail and post-incident analysis.
    """

    def __init__(self, db_path: str = "agent_sre_alerts.db",
                 dedup_window_seconds: float = 300.0) -> None:
        super().__init__(dedup_window_seconds=dedup_window_seconds)
        self._db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        import sqlite3
        conn = sqlite3.connect(self._db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                message TEXT,
                severity TEXT,
                source TEXT,
                agent_id TEXT,
                slo_name TEXT,
                dedup_key TEXT,
                metadata TEXT,
                timestamp REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS delivery_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER,
                channel_name TEXT,
                success INTEGER,
                status_code INTEGER,
                error TEXT,
                timestamp REAL
            )
        """)
        conn.commit()
        conn.close()

    def send(self, alert: Alert) -> list[DeliveryResult]:
        results = super().send(alert)
        if results or not alert.dedup_key:
            self._persist_alert(alert, results)
        return results

    def _persist_alert(self, alert: Alert, results: list[DeliveryResult]) -> None:
        import json as _json
        import sqlite3
        conn = sqlite3.connect(self._db_path)
        cursor = conn.execute(
            "INSERT INTO alerts (title, message, severity, source, agent_id, "
            "slo_name, dedup_key, metadata, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (alert.title, alert.message, alert.severity.value, alert.source,
             alert.agent_id, alert.slo_name, alert.dedup_key,
             _json.dumps(alert.metadata), alert.timestamp),
        )
        alert_id = cursor.lastrowid
        for r in results:
            conn.execute(
                "INSERT INTO delivery_results (alert_id, channel_name, success, "
                "status_code, error, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (alert_id, r.channel_name, int(r.success), r.status_code,
                 r.error, r.timestamp),
            )
        conn.commit()
        conn.close()

    def query_alerts(self, agent_id: str = "", severity: str = "",
                     limit: int = 100) -> list[dict[str, Any]]:
        """Query persisted alerts."""
        import sqlite3
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list = []
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def alert_count(self) -> int:
        """Get total persisted alert count."""
        import sqlite3
        conn = sqlite3.connect(self._db_path)
        count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        conn.close()
        return count


# Re-export dedup module classes for convenience
from agent_sre.alerts.dedup import AlertBatcher, AlertDeduplicator, alert_fingerprint  # noqa: E402
