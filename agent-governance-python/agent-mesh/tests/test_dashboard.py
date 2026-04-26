# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the dashboard API backend and data models."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agentmesh.dashboard import (
    AuditLogEntry,
    ComplianceReportData,
    DashboardAPI,
    DashboardOverview,
    LeaderboardEntry,
    TrafficEntry,
    TrustTrend,
)
from agentmesh.events import AnalyticsPlane, Event, InMemoryEventBus


# ---------------------------------------------------------------------------
# Data model tests
# ---------------------------------------------------------------------------


class TestDashboardModels:
    """Tests for dashboard data models."""

    def test_traffic_entry(self) -> None:
        """TrafficEntry stores communication metadata."""
        entry = TrafficEntry(
            source_did="did:mesh:a",
            target_did="did:mesh:b",
            event_type="handshake.completed",
            timestamp=datetime.now(timezone.utc),
            trust_score=850.0,
        )
        assert entry.source_did == "did:mesh:a"
        assert entry.outcome == "success"

    def test_leaderboard_entry(self) -> None:
        """LeaderboardEntry stores ranking data."""
        entry = LeaderboardEntry(
            agent_did="did:mesh:a",
            trust_score=950.0,
            rank=1,
            handshake_count=42,
        )
        assert entry.rank == 1
        assert entry.violation_count == 0

    def test_trust_trend(self) -> None:
        """TrustTrend stores a time-series data point."""
        trend = TrustTrend(
            agent_did="did:mesh:a",
            timestamp=datetime.now(timezone.utc),
            trust_score=800.0,
            event_type="trust.verified",
        )
        assert trend.trust_score == 800.0

    def test_audit_log_entry(self) -> None:
        """AuditLogEntry stores audit data."""
        entry = AuditLogEntry(
            entry_id="aud-1",
            timestamp=datetime.now(timezone.utc),
            agent_did="did:mesh:a",
            action="handshake",
            outcome="success",
        )
        assert entry.resource is None
        assert entry.details == {}

    def test_compliance_report_data(self) -> None:
        """ComplianceReportData stores compliance summary."""
        report = ComplianceReportData(
            framework="soc2",
            generated_at=datetime.now(timezone.utc),
            compliance_score=95.5,
            total_controls=64,
            controls_met=61,
            controls_partial=2,
            controls_failed=1,
        )
        assert report.framework == "soc2"
        assert report.agents_covered == []

    def test_dashboard_overview(self) -> None:
        """DashboardOverview provides summary with defaults."""
        overview = DashboardOverview()
        assert overview.total_agents == 0
        assert overview.avg_trust_score == 0.0
        assert overview.generated_at is not None


# ---------------------------------------------------------------------------
# Helper to build a wired-up DashboardAPI
# ---------------------------------------------------------------------------


def _make_api() -> tuple[InMemoryEventBus, AnalyticsPlane, DashboardAPI]:
    bus = InMemoryEventBus()
    analytics = AnalyticsPlane(bus)
    api = DashboardAPI(bus, analytics)
    return bus, analytics, api


# ---------------------------------------------------------------------------
# API handler tests
# ---------------------------------------------------------------------------


class TestDashboardAPI:
    """Tests for the DashboardAPI route handlers."""

    def test_get_live_traffic(self) -> None:
        """get_live_traffic returns recent agent communications."""
        bus, _, api = _make_api()

        bus.emit(Event(event_type="handshake.completed", source="did:mesh:a",
                        payload={"target_did": "did:mesh:b", "trust_score": 800}))
        bus.emit(Event(event_type="trust.verified", source="did:mesh:c",
                        payload={"trust_score": 700}))

        traffic = api.get_live_traffic()
        assert len(traffic) == 2
        # Most recent first
        assert traffic[0].source_did == "did:mesh:c"

    def test_get_live_traffic_limit(self) -> None:
        """get_live_traffic respects limit parameter."""
        bus, _, api = _make_api()

        for i in range(10):
            bus.emit(Event(event_type="trust.verified", source=f"did:mesh:{i}"))

        traffic = api.get_live_traffic(limit=3)
        assert len(traffic) == 3

    def test_get_leaderboard(self) -> None:
        """get_leaderboard ranks agents by trust score descending."""
        bus, _, api = _make_api()

        bus.emit(Event(event_type="trust.verified", source="did:mesh:low",
                        payload={"trust_score": 300}))
        bus.emit(Event(event_type="trust.verified", source="did:mesh:high",
                        payload={"trust_score": 900}))
        bus.emit(Event(event_type="trust.verified", source="did:mesh:mid",
                        payload={"trust_score": 600}))

        board = api.get_leaderboard()
        assert len(board) == 3
        assert board[0].agent_did == "did:mesh:high"
        assert board[0].rank == 1
        assert board[1].agent_did == "did:mesh:mid"
        assert board[2].agent_did == "did:mesh:low"

    def test_get_trust_trends(self) -> None:
        """get_trust_trends returns score history for an agent."""
        bus, _, api = _make_api()

        bus.emit(Event(event_type="trust.verified", source="did:mesh:a",
                        payload={"trust_score": 700}))
        bus.emit(Event(event_type="trust.verified", source="did:mesh:a",
                        payload={"trust_score": 750}))
        bus.emit(Event(event_type="trust.verified", source="did:mesh:b",
                        payload={"trust_score": 500}))

        trends = api.get_trust_trends("did:mesh:a")
        assert len(trends) == 2
        assert trends[0].trust_score == 700
        assert trends[1].trust_score == 750

    def test_get_trust_trends_empty(self) -> None:
        """get_trust_trends returns empty for unknown agent."""
        _, _, api = _make_api()
        assert api.get_trust_trends("did:mesh:unknown") == []

    def test_get_audit_log(self) -> None:
        """get_audit_log returns audit entries."""
        bus, _, api = _make_api()

        bus.emit(Event(event_type="audit.entry", source="did:mesh:a",
                        payload={"action": "login", "outcome": "success"}))
        bus.emit(Event(event_type="audit.entry", source="did:mesh:b",
                        payload={"action": "access", "outcome": "denied"}))

        log = api.get_audit_log()
        assert len(log) == 2

    def test_get_audit_log_filter_by_agent(self) -> None:
        """get_audit_log filters by agent DID."""
        bus, _, api = _make_api()

        bus.emit(Event(event_type="audit.entry", source="did:mesh:a",
                        payload={"action": "login"}))
        bus.emit(Event(event_type="audit.entry", source="did:mesh:b",
                        payload={"action": "login"}))

        log = api.get_audit_log(filters={"agent": "did:mesh:a"})
        assert len(log) == 1
        assert log[0].agent_did == "did:mesh:a"

    def test_get_audit_log_filter_by_action(self) -> None:
        """get_audit_log filters by action type."""
        bus, _, api = _make_api()

        bus.emit(Event(event_type="audit.entry", source="did:mesh:a",
                        payload={"action": "login"}))
        bus.emit(Event(event_type="audit.entry", source="did:mesh:a",
                        payload={"action": "access"}))

        log = api.get_audit_log(filters={"action": "access"})
        assert len(log) == 1
        assert log[0].action == "access"

    def test_get_audit_log_filter_by_date_range(self) -> None:
        """get_audit_log filters by date range."""
        bus, _, api = _make_api()

        now = datetime.now(timezone.utc)
        old_event = Event(event_type="audit.entry", source="did:mesh:a",
                          payload={"action": "old"})
        old_event.timestamp = now - timedelta(days=10)

        new_event = Event(event_type="audit.entry", source="did:mesh:a",
                          payload={"action": "new"})

        bus.emit(old_event)
        bus.emit(new_event)

        log = api.get_audit_log(
            filters={"date_from": now - timedelta(days=1)}
        )
        assert len(log) == 1
        assert log[0].action == "new"

    def test_get_compliance_report(self) -> None:
        """get_compliance_report generates framework-specific report."""
        bus, _, api = _make_api()

        # Register some agents
        bus.emit(Event(event_type="agent.registered", source="did:mesh:a"))
        bus.emit(Event(event_type="agent.registered", source="did:mesh:b"))

        report = api.get_compliance_report("soc2")
        assert report.framework == "soc2"
        assert report.total_controls == 64
        assert report.compliance_score >= 0
        assert "did:mesh:a" in report.agents_covered
        assert len(report.recommendations) > 0

    def test_get_compliance_report_with_violations(self) -> None:
        """Compliance score decreases with audit violations."""
        bus, _, api = _make_api()

        bus.emit(Event(event_type="agent.registered", source="did:mesh:a"))
        bus.emit(Event(event_type="audit.entry", source="did:mesh:a",
                        payload={"action": "access", "outcome": "denied"}))

        report = api.get_compliance_report("hipaa")
        assert report.controls_failed >= 1
        assert report.compliance_score < 100

    def test_get_overview(self) -> None:
        """get_overview returns a complete dashboard summary."""
        bus, _, api = _make_api()

        bus.emit(Event(event_type="handshake.completed", source="did:mesh:a",
                        payload={"trust_score": 800, "target_did": "did:mesh:b"}))
        bus.emit(Event(event_type="trust.verified", source="did:mesh:c",
                        payload={"trust_score": 600}))
        bus.emit(Event(event_type="policy.violated", source="did:mesh:d"))

        overview = api.get_overview()
        assert isinstance(overview, DashboardOverview)
        assert overview.total_agents == 3
        assert overview.handshakes_last_hour >= 1
        assert overview.violations_last_hour >= 1
        assert overview.generated_at is not None

    def test_overview_active_agents(self) -> None:
        """Overview counts recently active agents."""
        bus, _, api = _make_api()

        bus.emit(Event(event_type="agent.registered", source="did:mesh:a"))
        bus.emit(Event(event_type="agent.registered", source="did:mesh:b"))

        overview = api.get_overview()
        assert overview.active_agents == 2

    def test_leaderboard_tracks_handshakes(self) -> None:
        """Leaderboard entries reflect handshake counts."""
        bus, _, api = _make_api()

        for _ in range(3):
            bus.emit(Event(event_type="handshake.completed", source="did:mesh:a",
                            payload={"trust_score": 800}))

        board = api.get_leaderboard()
        assert board[0].handshake_count == 3

    def test_leaderboard_tracks_violations(self) -> None:
        """Leaderboard entries reflect violation counts."""
        bus, _, api = _make_api()

        bus.emit(Event(event_type="trust.verified", source="did:mesh:a",
                        payload={"trust_score": 500}))
        bus.emit(Event(event_type="policy.violated", source="did:mesh:a"))
        bus.emit(Event(event_type="trust.failed", source="did:mesh:a"))

        board = api.get_leaderboard()
        assert board[0].violation_count == 2
