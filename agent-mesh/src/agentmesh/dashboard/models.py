# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Dashboard data models for the AgentMesh dashboard API."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class TrafficEntry:
    """Represents a single agent-to-agent communication."""

    source_did: str
    target_did: str
    event_type: str
    timestamp: datetime
    trust_score: float | None = None
    outcome: str = "success"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class LeaderboardEntry:
    """Agent ranking entry on the trust leaderboard."""

    agent_did: str
    trust_score: float
    rank: int
    handshake_count: int = 0
    violation_count: int = 0
    last_active: datetime | None = None


@dataclass
class TrustTrend:
    """Trust score data point for a time series trend."""

    agent_did: str
    timestamp: datetime
    trust_score: float
    event_type: str | None = None


@dataclass
class AuditLogEntry:
    """A single entry in the dashboard audit log view."""

    entry_id: str
    timestamp: datetime
    agent_did: str
    action: str
    outcome: str
    resource: str | None = None
    target_did: str | None = None
    policy_decision: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceReportData:
    """Compliance report summary for dashboard display."""

    framework: str
    generated_at: datetime
    compliance_score: float
    total_controls: int
    controls_met: int
    controls_partial: int
    controls_failed: int
    agents_covered: list[str] = field(default_factory=list)
    violations: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class DashboardOverview:
    """Summary overview for the main dashboard view."""

    total_agents: int = 0
    active_agents: int = 0
    handshakes_last_hour: int = 0
    violations_last_hour: int = 0
    avg_trust_score: float = 0.0
    top_agents: list[LeaderboardEntry] = field(default_factory=list)
    recent_events: list[TrafficEntry] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
