# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Dashboard API backend for AgentMesh.

Provides route handlers for live traffic, leaderboard, trust trends,
audit logs, compliance reports, and overview statistics. Uses dataclasses
and the event bus — no external web framework dependency required.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from ..events import AnalyticsPlane, Event, EventBus
from .models import (
    AuditLogEntry,
    ComplianceReportData,
    DashboardOverview,
    LeaderboardEntry,
    TrafficEntry,
    TrustTrend,
)


class DashboardAPI:
    """Dashboard API providing route handlers for the AgentMesh dashboard.

    Args:
        bus: The event bus to subscribe to for live data.
        analytics: The analytics plane for aggregated stats.
    """

    def __init__(self, bus: EventBus, analytics: AnalyticsPlane) -> None:
        self._bus = bus
        self._analytics = analytics

        # In-memory stores populated via event subscriptions
        self._traffic: list[TrafficEntry] = []
        self._trust_history: dict[str, list[TrustTrend]] = {}
        self._audit_entries: list[AuditLogEntry] = []
        self._agents: dict[str, dict[str, Any]] = {}
        self._max_traffic = 10000
        self._max_audit = 50000

        # Subscribe to relevant events
        self._bus.subscribe("*", self._on_event)

    def _on_event(self, event: Event) -> None:
        """Internal handler that populates dashboard data stores."""
        # Track traffic
        entry = TrafficEntry(
            source_did=event.source,
            target_did=event.payload.get("target_did", ""),
            event_type=event.event_type,
            timestamp=event.timestamp,
            trust_score=event.payload.get("trust_score"),
            outcome=event.payload.get("outcome", "success"),
        )
        self._traffic.append(entry)
        if len(self._traffic) > self._max_traffic:
            self._traffic = self._traffic[-self._max_traffic:]

        # Track agent info
        agent_did = event.source
        if agent_did not in self._agents:
            self._agents[agent_did] = {
                "did": agent_did,
                "trust_score": 0.0,
                "handshake_count": 0,
                "violation_count": 0,
                "last_active": event.timestamp,
            }
        agent = self._agents[agent_did]
        agent["last_active"] = event.timestamp

        if event.event_type == "handshake.completed":
            agent["handshake_count"] = agent.get("handshake_count", 0) + 1

        if event.event_type in ("trust.verified", "handshake.completed"):
            score = event.payload.get("trust_score")
            if score is not None:
                agent["trust_score"] = float(score)
                trends = self._trust_history.setdefault(agent_did, [])
                trends.append(
                    TrustTrend(
                        agent_did=agent_did,
                        timestamp=event.timestamp,
                        trust_score=float(score),
                        event_type=event.event_type,
                    )
                )

        if event.event_type in ("policy.violated", "trust.failed"):
            agent["violation_count"] = agent.get("violation_count", 0) + 1

        # Track audit log
        if event.event_type == "audit.entry":
            audit = AuditLogEntry(
                entry_id=event.event_id,
                timestamp=event.timestamp,
                agent_did=event.source,
                action=event.payload.get("action", event.event_type),
                outcome=event.payload.get("outcome", "success"),
                resource=event.payload.get("resource"),
                target_did=event.payload.get("target_did"),
                policy_decision=event.payload.get("policy_decision"),
                details=event.payload,
            )
            self._audit_entries.append(audit)
            if len(self._audit_entries) > self._max_audit:
                self._audit_entries = self._audit_entries[-self._max_audit:]

    def get_live_traffic(self, limit: int = 100) -> list[TrafficEntry]:
        """Returns the most recent agent communications.

        Args:
            limit: Maximum number of traffic entries to return.
        """
        return list(reversed(self._traffic[-limit:]))

    def get_leaderboard(self, limit: int = 20) -> list[LeaderboardEntry]:
        """Returns agents ranked by trust score (descending).

        Args:
            limit: Maximum number of leaderboard entries.
        """
        sorted_agents = sorted(
            self._agents.values(),
            key=lambda a: a.get("trust_score", 0.0),
            reverse=True,
        )
        result: list[LeaderboardEntry] = []
        for rank, agent in enumerate(sorted_agents[:limit], start=1):
            result.append(
                LeaderboardEntry(
                    agent_did=agent["did"],
                    trust_score=agent.get("trust_score", 0.0),
                    rank=rank,
                    handshake_count=agent.get("handshake_count", 0),
                    violation_count=agent.get("violation_count", 0),
                    last_active=agent.get("last_active"),
                )
            )
        return result

    def get_trust_trends(
        self, agent_id: str, days: int = 7
    ) -> list[TrustTrend]:
        """Returns trust score history for an agent over a time period.

        Args:
            agent_id: The agent DID to query.
            days: Number of days of history to return.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        trends = self._trust_history.get(agent_id, [])
        return [t for t in trends if t.timestamp >= cutoff]

    def get_audit_log(
        self,
        filters: dict[str, Any] | None = None,
        limit: int = 100,
    ) -> list[AuditLogEntry]:
        """Returns audit log entries with optional filtering.

        Args:
            filters: Optional dict with keys ``agent``, ``action``,
                ``date_from``, ``date_to`` for filtering.
            limit: Maximum number of entries to return.
        """
        entries = list(self._audit_entries)

        if filters:
            if "agent" in filters:
                entries = [e for e in entries if e.agent_did == filters["agent"]]
            if "action" in filters:
                entries = [e for e in entries if e.action == filters["action"]]
            if "date_from" in filters:
                date_from = filters["date_from"]
                if isinstance(date_from, str):
                    date_from = datetime.fromisoformat(date_from)
                entries = [e for e in entries if e.timestamp >= date_from]
            if "date_to" in filters:
                date_to = filters["date_to"]
                if isinstance(date_to, str):
                    date_to = datetime.fromisoformat(date_to)
                entries = [e for e in entries if e.timestamp <= date_to]

        return list(reversed(entries[-limit:]))

    def get_compliance_report(self, framework: str) -> ComplianceReportData:
        """Generates a compliance report summary for the given framework.

        Args:
            framework: Compliance framework identifier (e.g., ``soc2``, ``hipaa``).
        """
        agent_list = list(self._agents.keys())
        violations = [
            e for e in self._audit_entries if e.outcome in ("failure", "denied")
        ]

        total_controls = _framework_control_count(framework)
        controls_failed = min(len(violations), total_controls)
        controls_met = max(total_controls - controls_failed, 0)
        score = (controls_met / total_controls * 100) if total_controls > 0 else 0.0

        return ComplianceReportData(
            framework=framework,
            generated_at=datetime.now(timezone.utc),
            compliance_score=round(score, 2),
            total_controls=total_controls,
            controls_met=controls_met,
            controls_partial=0,
            controls_failed=controls_failed,
            agents_covered=agent_list,
            violations=[
                {"entry_id": v.entry_id, "action": v.action, "outcome": v.outcome}
                for v in violations
            ],
            recommendations=_framework_recommendations(framework),
        )

    def get_overview(self) -> DashboardOverview:
        """Returns a summary overview for the main dashboard."""
        self._analytics.get_stats()
        now = datetime.now(timezone.utc)
        one_hour_ago = now - timedelta(hours=1)

        recent_handshakes = sum(
            1
            for t in self._traffic
            if t.event_type == "handshake.completed" and t.timestamp >= one_hour_ago
        )
        recent_violations = sum(
            1
            for t in self._traffic
            if t.event_type in ("policy.violated", "trust.failed")
            and t.timestamp >= one_hour_ago
        )

        scores = [a.get("trust_score", 0.0) for a in self._agents.values()]
        avg_score = sum(scores) / len(scores) if scores else 0.0

        active_cutoff = now - timedelta(minutes=15)
        active_count = sum(
            1
            for a in self._agents.values()
            if a.get("last_active") and a["last_active"] >= active_cutoff
        )

        return DashboardOverview(
            total_agents=len(self._agents),
            active_agents=active_count,
            handshakes_last_hour=recent_handshakes,
            violations_last_hour=recent_violations,
            avg_trust_score=round(avg_score, 2),
            top_agents=self.get_leaderboard(limit=5),
            recent_events=self.get_live_traffic(limit=10),
            generated_at=now,
        )


def _framework_control_count(framework: str) -> int:
    """Returns the approximate number of controls for a compliance framework."""
    counts: dict[str, int] = {
        "soc2": 64,
        "hipaa": 54,
        "gdpr": 39,
        "eu_ai_act": 42,
    }
    return counts.get(framework, 30)


def _framework_recommendations(framework: str) -> list[str]:
    """Returns standard recommendations for a compliance framework."""
    base = ["Review and update agent access policies regularly"]
    recs: dict[str, list[str]] = {
        "soc2": [
            "Enable continuous monitoring for all production agents",
            "Ensure audit logs are retained for at least 1 year",
        ],
        "hipaa": [
            "Encrypt all agent-to-agent communications containing PHI",
            "Implement minimum necessary access controls",
        ],
        "gdpr": [
            "Implement data subject access request handling for agent data",
            "Ensure cross-border agent communications comply with transfer rules",
        ],
        "eu_ai_act": [
            "Classify all agents by risk tier and apply appropriate controls",
            "Maintain transparency logs for high-risk agent decisions",
        ],
    }
    return base + recs.get(framework, [])
