# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Fleet Management for Agent-SRE.

Monitor and manage multiple AI agents as a fleet. Tracks per-agent
health, aggregates SLO compliance across the fleet, detects anomalies,
and provides fleet-wide operational views.

Components:
- AgentRegistration: Per-agent metadata and configuration
- FleetManager: Central registry and health aggregator
- FleetStatus: Aggregate fleet health snapshot
- AgentHealth: Per-agent health report

Usage:
    fleet = FleetManager()

    fleet.register("agent-a", tags={"team": "search"}, slo=my_slo)
    fleet.register("agent-b", tags={"team": "support"}, slo=other_slo)

    fleet.heartbeat("agent-a")
    fleet.record_event("agent-a", success=True, latency_ms=120, cost_usd=0.01)

    status = fleet.status()          # Fleet-wide health
    health = fleet.agent_health("agent-a")  # Per-agent drill-down
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AgentState(Enum):
    """Operational state of an agent in the fleet."""

    ACTIVE = "active"          # Running and reporting
    DEGRADED = "degraded"      # Running but SLO violations
    UNRESPONSIVE = "unresponsive"  # No heartbeat within threshold
    DRAINING = "draining"      # Scheduled for removal
    REMOVED = "removed"        # No longer in fleet


class FleetHealth(Enum):
    """Aggregate fleet health level."""

    HEALTHY = "healthy"      # All agents healthy
    DEGRADED = "degraded"    # Some agents have issues
    CRITICAL = "critical"    # Majority of agents unhealthy
    UNKNOWN = "unknown"      # No agents registered


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AgentEvent:
    """A recorded event for an agent."""

    timestamp: float = field(default_factory=time.time)
    success: bool = True
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentRegistration:
    """Registration record for a single agent."""

    agent_id: str
    tags: dict[str, str] = field(default_factory=dict)
    registered_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    state: AgentState = AgentState.ACTIVE
    slo: Any = None  # Optional SLO object
    events: list[AgentEvent] = field(default_factory=list)
    heartbeat_timeout_seconds: float = 300.0  # 5 minutes

    @property
    def is_responsive(self) -> bool:
        """True if heartbeat is within the timeout."""
        return (time.time() - self.last_heartbeat) < self.heartbeat_timeout_seconds

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self.registered_at

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def success_rate(self) -> float | None:
        """Success rate over all recorded events."""
        if not self.events:
            return None
        good = sum(1 for e in self.events if e.success)
        return good / len(self.events)

    @property
    def avg_latency_ms(self) -> float | None:
        """Average latency across all events."""
        if not self.events:
            return None
        return sum(e.latency_ms for e in self.events) / len(self.events)

    @property
    def total_cost_usd(self) -> float:
        return sum(e.cost_usd for e in self.events)

    def recent_events(self, window_seconds: float = 3600) -> list[AgentEvent]:
        """Events within the last N seconds."""
        cutoff = time.time() - window_seconds
        return [e for e in self.events if e.timestamp >= cutoff]


@dataclass
class AgentHealth:
    """Health report for a single agent."""

    agent_id: str
    state: AgentState
    is_responsive: bool
    success_rate: float | None
    avg_latency_ms: float | None
    total_cost_usd: float
    event_count: int
    uptime_seconds: float
    tags: dict[str, str]
    slo_status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "state": self.state.value,
            "is_responsive": self.is_responsive,
            "success_rate": self.success_rate,
            "avg_latency_ms": self.avg_latency_ms,
            "total_cost_usd": self.total_cost_usd,
            "event_count": self.event_count,
            "uptime_seconds": round(self.uptime_seconds, 1),
            "tags": self.tags,
            "slo_status": self.slo_status,
        }


@dataclass
class FleetStatus:
    """Aggregate fleet health snapshot."""

    health: FleetHealth
    total_agents: int
    active_agents: int
    degraded_agents: int
    unresponsive_agents: int
    fleet_success_rate: float | None
    fleet_avg_latency_ms: float | None
    fleet_total_cost_usd: float
    total_events: int
    agents: list[AgentHealth] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "health": self.health.value,
            "total_agents": self.total_agents,
            "active_agents": self.active_agents,
            "degraded_agents": self.degraded_agents,
            "unresponsive_agents": self.unresponsive_agents,
            "fleet_success_rate": self.fleet_success_rate,
            "fleet_avg_latency_ms": self.fleet_avg_latency_ms,
            "fleet_total_cost_usd": self.fleet_total_cost_usd,
            "total_events": self.total_events,
            "agents": [a.to_dict() for a in self.agents],
        }


# ---------------------------------------------------------------------------
# Fleet manager
# ---------------------------------------------------------------------------

class FleetManager:
    """Central registry and health aggregator for an agent fleet.

    Tracks agent registrations, heartbeats, events, and provides
    fleet-wide and per-agent health views.
    """

    def __init__(
        self,
        heartbeat_timeout: float = 300.0,
        success_rate_threshold: float = 0.9,
    ) -> None:
        self._agents: dict[str, AgentRegistration] = {}
        self._heartbeat_timeout = heartbeat_timeout
        self._success_rate_threshold = success_rate_threshold

    # -- Registration --

    def register(
        self,
        agent_id: str,
        tags: dict[str, str] | None = None,
        slo: Any = None,
        heartbeat_timeout: float | None = None,
    ) -> AgentRegistration:
        """Register an agent in the fleet."""
        reg = AgentRegistration(
            agent_id=agent_id,
            tags=tags or {},
            slo=slo,
            heartbeat_timeout_seconds=heartbeat_timeout or self._heartbeat_timeout,
        )
        self._agents[agent_id] = reg
        return reg

    def deregister(self, agent_id: str) -> bool:
        """Remove an agent from the fleet."""
        if agent_id in self._agents:
            self._agents[agent_id].state = AgentState.REMOVED
            del self._agents[agent_id]
            return True
        return False

    def get_agent(self, agent_id: str) -> AgentRegistration | None:
        return self._agents.get(agent_id)

    @property
    def agent_ids(self) -> list[str]:
        return list(self._agents.keys())

    @property
    def agent_count(self) -> int:
        return len(self._agents)

    # -- Heartbeat --

    def heartbeat(self, agent_id: str) -> bool:
        """Record a heartbeat from an agent. Returns False if agent not found."""
        reg = self._agents.get(agent_id)
        if reg is None:
            return False
        reg.last_heartbeat = time.time()
        if reg.state == AgentState.UNRESPONSIVE:
            reg.state = AgentState.ACTIVE
        return True

    # -- Events --

    def record_event(
        self,
        agent_id: str,
        success: bool = True,
        latency_ms: float = 0.0,
        cost_usd: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Record a task event for an agent. Returns False if agent not found."""
        reg = self._agents.get(agent_id)
        if reg is None:
            return False
        event = AgentEvent(
            success=success,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
            metadata=metadata or {},
        )
        reg.events.append(event)

        # Auto-SLO recording
        if reg.slo and hasattr(reg.slo, "record_event"):
            reg.slo.record_event(success)

        return True

    # -- State management --

    def refresh_states(self) -> None:
        """Update agent states based on heartbeats and success rates."""
        for reg in self._agents.values():
            if reg.state == AgentState.DRAINING:
                continue

            if not reg.is_responsive:
                reg.state = AgentState.UNRESPONSIVE
            elif reg.success_rate is not None and reg.success_rate < self._success_rate_threshold:
                reg.state = AgentState.DEGRADED
            elif reg.state in (AgentState.UNRESPONSIVE, AgentState.DEGRADED):
                reg.state = AgentState.ACTIVE

    def drain(self, agent_id: str) -> bool:
        """Mark an agent as draining (no new work)."""
        reg = self._agents.get(agent_id)
        if reg is None:
            return False
        reg.state = AgentState.DRAINING
        return True

    # -- Health queries --

    def agent_health(self, agent_id: str) -> AgentHealth | None:
        """Get health report for a single agent."""
        reg = self._agents.get(agent_id)
        if reg is None:
            return None

        slo_status = None
        if reg.slo and hasattr(reg.slo, "evaluate"):
            slo_status = reg.slo.evaluate().value

        return AgentHealth(
            agent_id=reg.agent_id,
            state=reg.state,
            is_responsive=reg.is_responsive,
            success_rate=reg.success_rate,
            avg_latency_ms=reg.avg_latency_ms,
            total_cost_usd=reg.total_cost_usd,
            event_count=reg.event_count,
            uptime_seconds=reg.uptime_seconds,
            tags=reg.tags,
            slo_status=slo_status,
        )

    def status(self) -> FleetStatus:
        """Get aggregate fleet health status."""
        self.refresh_states()

        if not self._agents:
            return FleetStatus(
                health=FleetHealth.UNKNOWN,
                total_agents=0,
                active_agents=0,
                degraded_agents=0,
                unresponsive_agents=0,
                fleet_success_rate=None,
                fleet_avg_latency_ms=None,
                fleet_total_cost_usd=0.0,
                total_events=0,
            )

        agents_health: list[AgentHealth] = []
        active = degraded = unresponsive = 0
        all_events: list[AgentEvent] = []

        for reg in self._agents.values():
            health = self.agent_health(reg.agent_id)
            if health:
                agents_health.append(health)
            if reg.state == AgentState.ACTIVE:
                active += 1
            elif reg.state == AgentState.DEGRADED:
                degraded += 1
            elif reg.state == AgentState.UNRESPONSIVE:
                unresponsive += 1
            all_events.extend(reg.events)

        total = len(self._agents)

        # Fleet-wide metrics
        fleet_success = None
        if all_events:
            good = sum(1 for e in all_events if e.success)
            fleet_success = good / len(all_events)

        fleet_latency = None
        if all_events:
            fleet_latency = sum(e.latency_ms for e in all_events) / len(all_events)

        fleet_cost = sum(e.cost_usd for e in all_events)

        # Determine fleet health
        if unresponsive > total / 2:
            health = FleetHealth.CRITICAL
        elif degraded > 0 or unresponsive > 0:
            health = FleetHealth.DEGRADED
        else:
            health = FleetHealth.HEALTHY

        return FleetStatus(
            health=health,
            total_agents=total,
            active_agents=active,
            degraded_agents=degraded,
            unresponsive_agents=unresponsive,
            fleet_success_rate=fleet_success,
            fleet_avg_latency_ms=fleet_latency,
            fleet_total_cost_usd=fleet_cost,
            total_events=len(all_events),
            agents=agents_health,
        )

    # -- Filtering --

    def agents_by_tag(self, key: str, value: str) -> list[str]:
        """Find agent IDs matching a tag key-value pair."""
        return [
            aid for aid, reg in self._agents.items()
            if reg.tags.get(key) == value
        ]

    def agents_by_state(self, state: AgentState) -> list[str]:
        """Find agent IDs in a given state."""
        return [aid for aid, reg in self._agents.items() if reg.state == state]

    def top_cost_agents(self, n: int = 5) -> list[tuple[str, float]]:
        """Get top-N agents by total cost."""
        costs = [(aid, reg.total_cost_usd) for aid, reg in self._agents.items()]
        costs.sort(key=lambda x: x[1], reverse=True)
        return costs[:n]

    def to_dict(self) -> dict[str, Any]:
        """Full fleet state as dictionary."""
        return self.status().to_dict()
