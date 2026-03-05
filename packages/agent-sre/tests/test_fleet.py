# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for agent fleet management."""

from __future__ import annotations

import time

from agent_sre.fleet import (
    AgentEvent,
    AgentHealth,
    AgentRegistration,
    AgentState,
    FleetHealth,
    FleetManager,
)

# ---------------------------------------------------------------------------
# AgentRegistration
# ---------------------------------------------------------------------------

class TestAgentRegistration:
    def test_defaults(self):
        reg = AgentRegistration(agent_id="a1")
        assert reg.agent_id == "a1"
        assert reg.state == AgentState.ACTIVE
        assert reg.is_responsive is True
        assert reg.event_count == 0
        assert reg.success_rate is None
        assert reg.avg_latency_ms is None
        assert reg.total_cost_usd == 0.0

    def test_success_rate(self):
        reg = AgentRegistration(agent_id="a1")
        reg.events = [
            AgentEvent(success=True),
            AgentEvent(success=True),
            AgentEvent(success=False),
        ]
        assert abs(reg.success_rate - 2 / 3) < 1e-10

    def test_avg_latency(self):
        reg = AgentRegistration(agent_id="a1")
        reg.events = [
            AgentEvent(latency_ms=100),
            AgentEvent(latency_ms=200),
        ]
        assert reg.avg_latency_ms == 150.0

    def test_total_cost(self):
        reg = AgentRegistration(agent_id="a1")
        reg.events = [
            AgentEvent(cost_usd=0.01),
            AgentEvent(cost_usd=0.02),
        ]
        assert abs(reg.total_cost_usd - 0.03) < 1e-10

    def test_recent_events(self):
        reg = AgentRegistration(agent_id="a1")
        old = AgentEvent(timestamp=time.time() - 7200)  # 2h ago
        recent = AgentEvent(timestamp=time.time() - 60)  # 1m ago
        reg.events = [old, recent]
        assert len(reg.recent_events(window_seconds=3600)) == 1

    def test_heartbeat_timeout(self):
        reg = AgentRegistration(agent_id="a1", heartbeat_timeout_seconds=1.0)
        reg.last_heartbeat = time.time() - 2.0
        assert reg.is_responsive is False


# ---------------------------------------------------------------------------
# FleetManager — registration
# ---------------------------------------------------------------------------

class TestFleetRegistration:
    def test_register(self):
        fm = FleetManager()
        reg = fm.register("agent-a", tags={"team": "search"})
        assert reg.agent_id == "agent-a"
        assert fm.agent_count == 1
        assert "agent-a" in fm.agent_ids

    def test_register_with_slo(self):
        fm = FleetManager()
        mock_slo = type("MockSLO", (), {"name": "test"})()
        fm.register("agent-a", slo=mock_slo)
        reg = fm.get_agent("agent-a")
        assert reg.slo is mock_slo

    def test_deregister(self):
        fm = FleetManager()
        fm.register("agent-a")
        assert fm.deregister("agent-a") is True
        assert fm.agent_count == 0
        assert fm.deregister("nonexistent") is False

    def test_get_agent(self):
        fm = FleetManager()
        fm.register("agent-a")
        assert fm.get_agent("agent-a") is not None
        assert fm.get_agent("nonexistent") is None


# ---------------------------------------------------------------------------
# FleetManager — heartbeats
# ---------------------------------------------------------------------------

class TestFleetHeartbeat:
    def test_heartbeat(self):
        fm = FleetManager()
        fm.register("agent-a")
        assert fm.heartbeat("agent-a") is True
        assert fm.heartbeat("nonexistent") is False

    def test_heartbeat_recovers_state(self):
        fm = FleetManager()
        reg = fm.register("agent-a")
        reg.state = AgentState.UNRESPONSIVE
        fm.heartbeat("agent-a")
        assert reg.state == AgentState.ACTIVE


# ---------------------------------------------------------------------------
# FleetManager — events
# ---------------------------------------------------------------------------

class TestFleetEvents:
    def test_record_event(self):
        fm = FleetManager()
        fm.register("agent-a")
        assert fm.record_event("agent-a", success=True, latency_ms=50, cost_usd=0.01) is True
        reg = fm.get_agent("agent-a")
        assert reg.event_count == 1
        assert reg.events[0].latency_ms == 50

    def test_record_event_unknown_agent(self):
        fm = FleetManager()
        assert fm.record_event("nonexistent") is False

    def test_auto_slo_recording(self):
        fm = FleetManager()
        recorded = []

        class MockSLO:
            def record_event(self, good):
                recorded.append(good)

        fm.register("agent-a", slo=MockSLO())
        fm.record_event("agent-a", success=True)
        fm.record_event("agent-a", success=False)
        assert recorded == [True, False]


# ---------------------------------------------------------------------------
# FleetManager — state management
# ---------------------------------------------------------------------------

class TestFleetStates:
    def test_refresh_detects_unresponsive(self):
        fm = FleetManager(heartbeat_timeout=1.0)
        reg = fm.register("agent-a", heartbeat_timeout=1.0)
        reg.last_heartbeat = time.time() - 2.0
        fm.refresh_states()
        assert reg.state == AgentState.UNRESPONSIVE

    def test_refresh_detects_degraded(self):
        fm = FleetManager(success_rate_threshold=0.9)
        fm.register("agent-a")
        # Record lots of failures
        for _ in range(10):
            fm.record_event("agent-a", success=False)
        fm.refresh_states()
        assert fm.get_agent("agent-a").state == AgentState.DEGRADED

    def test_drain(self):
        fm = FleetManager()
        fm.register("agent-a")
        assert fm.drain("agent-a") is True
        assert fm.get_agent("agent-a").state == AgentState.DRAINING
        assert fm.drain("nonexistent") is False

    def test_drain_survives_refresh(self):
        fm = FleetManager()
        fm.register("agent-a")
        fm.drain("agent-a")
        fm.refresh_states()
        assert fm.get_agent("agent-a").state == AgentState.DRAINING


# ---------------------------------------------------------------------------
# FleetManager — health queries
# ---------------------------------------------------------------------------

class TestFleetHealth:
    def test_agent_health(self):
        fm = FleetManager()
        fm.register("agent-a", tags={"team": "search"})
        fm.record_event("agent-a", success=True, latency_ms=100, cost_usd=0.05)
        health = fm.agent_health("agent-a")
        assert health.agent_id == "agent-a"
        assert health.success_rate == 1.0
        assert health.avg_latency_ms == 100.0
        assert health.total_cost_usd == 0.05
        assert health.tags["team"] == "search"

    def test_agent_health_not_found(self):
        fm = FleetManager()
        assert fm.agent_health("nonexistent") is None

    def test_agent_health_with_slo(self):
        fm = FleetManager()

        class MockSLO:
            def evaluate(self):
                return type("Status", (), {"value": "healthy"})()
            def record_event(self, good):
                pass

        fm.register("agent-a", slo=MockSLO())
        fm.record_event("agent-a", success=True)
        health = fm.agent_health("agent-a")
        assert health.slo_status == "healthy"

    def test_agent_health_to_dict(self):
        health = AgentHealth(
            agent_id="a1", state=AgentState.ACTIVE,
            is_responsive=True, success_rate=0.95,
            avg_latency_ms=120.0, total_cost_usd=1.5,
            event_count=100, uptime_seconds=3600.0,
            tags={"env": "prod"}, slo_status="healthy",
        )
        d = health.to_dict()
        assert d["agent_id"] == "a1"
        assert d["state"] == "active"
        assert d["success_rate"] == 0.95

    def test_fleet_status_empty(self):
        fm = FleetManager()
        status = fm.status()
        assert status.health == FleetHealth.UNKNOWN
        assert status.total_agents == 0

    def test_fleet_status_healthy(self):
        fm = FleetManager()
        fm.register("a1")
        fm.register("a2")
        fm.record_event("a1", success=True, latency_ms=100, cost_usd=0.01)
        fm.record_event("a2", success=True, latency_ms=200, cost_usd=0.02)
        status = fm.status()
        assert status.health == FleetHealth.HEALTHY
        assert status.total_agents == 2
        assert status.active_agents == 2
        assert status.fleet_success_rate == 1.0
        assert status.fleet_avg_latency_ms == 150.0
        assert abs(status.fleet_total_cost_usd - 0.03) < 1e-10

    def test_fleet_status_degraded(self):
        fm = FleetManager(heartbeat_timeout=1.0)
        reg = fm.register("a1", heartbeat_timeout=1.0)
        fm.register("a2")
        reg.last_heartbeat = time.time() - 2.0
        status = fm.status()
        assert status.health == FleetHealth.DEGRADED
        assert status.unresponsive_agents == 1

    def test_fleet_status_critical(self):
        fm = FleetManager(heartbeat_timeout=1.0)
        r1 = fm.register("a1", heartbeat_timeout=1.0)
        r2 = fm.register("a2", heartbeat_timeout=1.0)
        fm.register("a3", heartbeat_timeout=1.0)
        r1.last_heartbeat = time.time() - 2.0
        r2.last_heartbeat = time.time() - 2.0
        status = fm.status()
        assert status.health == FleetHealth.CRITICAL

    def test_fleet_status_to_dict(self):
        fm = FleetManager()
        fm.register("a1")
        fm.record_event("a1", success=True)
        d = fm.status().to_dict()
        assert "health" in d
        assert "agents" in d
        assert len(d["agents"]) == 1


# ---------------------------------------------------------------------------
# FleetManager — filtering
# ---------------------------------------------------------------------------

class TestFleetFiltering:
    def test_agents_by_tag(self):
        fm = FleetManager()
        fm.register("a1", tags={"team": "search"})
        fm.register("a2", tags={"team": "support"})
        fm.register("a3", tags={"team": "search"})
        assert sorted(fm.agents_by_tag("team", "search")) == ["a1", "a3"]

    def test_agents_by_state(self):
        fm = FleetManager()
        fm.register("a1")
        fm.register("a2")
        fm.drain("a2")
        assert fm.agents_by_state(AgentState.ACTIVE) == ["a1"]
        assert fm.agents_by_state(AgentState.DRAINING) == ["a2"]

    def test_top_cost_agents(self):
        fm = FleetManager()
        fm.register("cheap")
        fm.register("expensive")
        fm.record_event("cheap", cost_usd=0.01)
        fm.record_event("expensive", cost_usd=1.0)
        top = fm.top_cost_agents(n=1)
        assert top[0] == ("expensive", 1.0)

    def test_to_dict(self):
        fm = FleetManager()
        fm.register("a1")
        d = fm.to_dict()
        assert "health" in d
        assert d["total_agents"] == 1
