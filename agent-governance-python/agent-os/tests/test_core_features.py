# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for execution tracking, serialization, audit query, and health CLI.

Covers issues #177, #213, #225, #226.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from agent_os.base_agent import AgentConfig, AuditEntry, BaseAgent, PolicyDecision
from agent_os.integrations.base import GovernancePolicy, PatternType
from agent_os.stateless import ExecutionResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class DummyAgent(BaseAgent):
    """Minimal agent for testing."""

    async def run(self, *args: Any, **kwargs: Any) -> ExecutionResult:
        return await self._execute("test-action", {"key": "value"})


# ---------------------------------------------------------------------------
# Issue #177 — Execution time tracking
# ---------------------------------------------------------------------------


class TestExecutionTimeTracking:
    @pytest.mark.asyncio
    async def test_audit_entry_has_execution_time(self) -> None:
        agent = DummyAgent(AgentConfig(agent_id="time-agent"))
        await agent.run()
        log = agent.get_audit_log()
        assert len(log) == 1
        assert log[0]["execution_time_ms"] is not None
        assert log[0]["execution_time_ms"] >= 0.0

    @pytest.mark.asyncio
    async def test_execution_stats_basic(self) -> None:
        agent = DummyAgent(AgentConfig(agent_id="stats-agent"))
        for _ in range(5):
            await agent.run()
        stats = agent.get_execution_stats()
        assert stats["count"] == 5
        assert stats["avg_ms"] >= 0.0
        assert stats["min_ms"] <= stats["avg_ms"] <= stats["max_ms"]
        assert stats["p99_ms"] >= stats["avg_ms"]

    def test_execution_stats_empty(self) -> None:
        agent = DummyAgent(AgentConfig(agent_id="empty-agent"))
        stats = agent.get_execution_stats()
        assert stats["count"] == 0
        assert stats["avg_ms"] == 0.0


# ---------------------------------------------------------------------------
# Issue #213 — to_dict / from_dict serialization
# ---------------------------------------------------------------------------


class TestAgentConfigSerialization:
    def test_round_trip(self) -> None:
        config = AgentConfig(
            agent_id="ser-agent",
            policies=["read_only"],
            metadata={"team": "core"},
            max_audit_log_size=500,
        )
        d = config.to_dict()
        restored = AgentConfig.from_dict(d)
        assert restored.agent_id == config.agent_id
        assert restored.policies == config.policies
        assert restored.metadata == config.metadata
        assert restored.max_audit_log_size == config.max_audit_log_size

    def test_from_dict_defaults(self) -> None:
        restored = AgentConfig.from_dict({"agent_id": "min-agent"})
        assert restored.policies == []
        assert restored.metadata == {}


class TestAuditEntrySerialization:
    def test_round_trip(self) -> None:
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            agent_id="audit-agent",
            request_id="req-1",
            action="read",
            params={"file": "a.txt"},
            decision=PolicyDecision.ALLOW,
            result_success=True,
            execution_time_ms=12.5,
        )
        d = entry.to_dict()
        restored = AuditEntry.from_dict(d)
        assert restored.agent_id == entry.agent_id
        assert restored.action == entry.action
        assert restored.decision == entry.decision
        assert restored.execution_time_ms == entry.execution_time_ms

    def test_from_dict_with_none_fields(self) -> None:
        d = {
            "timestamp": "2025-01-01T00:00:00+00:00",
            "agent_id": "a1",
            "request_id": "r1",
            "action": "write",
            "params_keys": ["x"],
            "decision": "deny",
        }
        entry = AuditEntry.from_dict(d)
        assert entry.result_success is None
        assert entry.error is None
        assert entry.execution_time_ms is None


class TestGovernancePolicySerialization:
    def test_round_trip(self) -> None:
        policy = GovernancePolicy(
            name="test-policy",
            max_tokens=2048,
            blocked_patterns=["password", ("rm\\s+-rf", PatternType.REGEX)],
        )
        d = policy.to_dict()
        restored = GovernancePolicy.from_dict(d)
        assert restored.name == policy.name
        assert restored.max_tokens == policy.max_tokens
        assert len(restored.blocked_patterns) == 2

    def test_to_dict_includes_name(self) -> None:
        policy = GovernancePolicy(name="my-policy")
        assert policy.to_dict()["name"] == "my-policy"


# ---------------------------------------------------------------------------
# Issue #225 — Audit log query API
# ---------------------------------------------------------------------------


class TestAuditLogQuery:
    @pytest.mark.asyncio
    async def test_filter_by_action(self) -> None:
        agent = DummyAgent(AgentConfig(agent_id="query-agent"))
        await agent.run()
        results = agent.query_audit_log(action="test-action")
        assert len(results) == 1
        assert results[0]["action"] == "test-action"

    @pytest.mark.asyncio
    async def test_filter_by_action_no_match(self) -> None:
        agent = DummyAgent(AgentConfig(agent_id="query-agent"))
        await agent.run()
        results = agent.query_audit_log(action="nonexistent")
        assert results == []

    @pytest.mark.asyncio
    async def test_filter_by_decision(self) -> None:
        agent = DummyAgent(AgentConfig(agent_id="query-agent"))
        await agent.run()
        results = agent.query_audit_log(decision="allow")
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_filter_by_since(self) -> None:
        agent = DummyAgent(AgentConfig(agent_id="query-agent"))
        await agent.run()
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        results = agent.query_audit_log(since=future)
        assert results == []

    @pytest.mark.asyncio
    async def test_limit_and_offset(self) -> None:
        agent = DummyAgent(AgentConfig(agent_id="query-agent"))
        for _ in range(5):
            await agent.run()
        results = agent.query_audit_log(limit=2, offset=1)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_no_filters_returns_all(self) -> None:
        agent = DummyAgent(AgentConfig(agent_id="query-agent"))
        for _ in range(3):
            await agent.run()
        results = agent.query_audit_log()
        assert len(results) == 3


# ---------------------------------------------------------------------------
# Issue #226 — Health check (re-export + CLI)
# ---------------------------------------------------------------------------


class TestHealthReExport:
    def test_import_from_health_module(self) -> None:
        from agent_os.health import HealthChecker, HealthStatus
        checker = HealthChecker(version="test")
        report = checker.check_health()
        assert report.status == HealthStatus.HEALTHY


class TestHealthCLI:
    def test_cmd_health_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        import argparse
        import json as _json
        from agent_os.cli import cmd_health

        ns = argparse.Namespace(format="json")
        rc = cmd_health(ns)
        assert rc == 0
        out = capsys.readouterr().out
        data = _json.loads(out)
        assert data["status"] in ("healthy", "degraded", "unhealthy")
        assert "policy_engine" in data["components"]

    def test_cmd_health_text(self, capsys: pytest.CaptureFixture[str]) -> None:
        import argparse
        from agent_os.cli import cmd_health

        ns = argparse.Namespace(format="text")
        rc = cmd_health(ns)
        assert rc == 0
        out = capsys.readouterr().out
        assert "System Health" in out or "healthy" in out.lower()
