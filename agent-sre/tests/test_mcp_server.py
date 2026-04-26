# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MCP Server."""

import pytest

from agent_sre.mcp.server import AgentSREServer
from agent_sre.slo.indicators import TaskSuccessRate
from agent_sre.slo.objectives import SLO, ErrorBudget


def _make_slo(name: str = "test-slo") -> SLO:
    return SLO(
        name=name,
        indicators=[TaskSuccessRate(target=0.99)],
        error_budget=ErrorBudget(total=0.01),
    )


class TestAgentSREServer:
    def test_list_tools(self):
        server = AgentSREServer()
        tools = server.list_tools()
        assert len(tools) == 5
        names = [t.name for t in tools]
        assert "sre_check_slo" in names
        assert "sre_report_cost" in names
        assert "sre_request_budget" in names
        assert "sre_check_rollout_status" in names
        assert "sre_list_slos" in names

    def test_check_slo(self):
        server = AgentSREServer()
        slo = _make_slo()
        server.register_slo("test-slo", slo)
        result = server.handle_tool_call("sre_check_slo", {"slo_name": "test-slo"})
        assert result.success
        assert result.data["slo_name"] == "test-slo"
        assert "status" in result.data

    def test_check_slo_not_found(self):
        server = AgentSREServer()
        result = server.handle_tool_call("sre_check_slo", {"slo_name": "nonexistent"})
        assert result.success  # returns data with error key, not a tool failure
        assert "error" in result.data

    def test_report_cost(self):
        server = AgentSREServer()
        result = server.handle_tool_call("sre_report_cost", {
            "agent_id": "a1", "cost_usd": 0.05,
        })
        assert result.success
        assert result.data["cost_recorded"] == 0.05
        assert result.data["total_spent"] == 0.05

        # Report more cost
        result2 = server.handle_tool_call("sre_report_cost", {
            "agent_id": "a1", "cost_usd": 0.10,
        })
        assert result2.data["total_spent"] == pytest.approx(0.15)

    def test_request_budget_approved(self):
        server = AgentSREServer()
        server.set_cost_budget("a1", 1.0)
        result = server.handle_tool_call("sre_request_budget", {
            "agent_id": "a1", "requested_usd": 0.50,
        })
        assert result.success
        assert result.data["approved"] is True

    def test_request_budget_denied(self):
        server = AgentSREServer()
        server.set_cost_budget("a1", 0.10)
        # Spend some first
        server.handle_tool_call("sre_report_cost", {"agent_id": "a1", "cost_usd": 0.08})
        result = server.handle_tool_call("sre_request_budget", {
            "agent_id": "a1", "requested_usd": 0.05,
        })
        assert result.success
        assert result.data["approved"] is False

    def test_request_budget_no_limit(self):
        server = AgentSREServer()
        result = server.handle_tool_call("sre_request_budget", {
            "agent_id": "a1", "requested_usd": 1000.0,
        })
        assert result.success
        assert result.data["approved"] is True
        assert result.data["reason"] == "No budget limit set"

    def test_check_rollout_stable(self):
        server = AgentSREServer()
        result = server.handle_tool_call("sre_check_rollout_status", {"agent_id": "a1"})
        assert result.success
        assert result.data["rollout_status"] == "stable"
        assert result.data["is_canary"] is False

    def test_check_rollout_canary(self):
        server = AgentSREServer()
        server.set_rollout_status("a1", "canary")
        result = server.handle_tool_call("sre_check_rollout_status", {"agent_id": "a1"})
        assert result.success
        assert result.data["rollout_status"] == "canary"
        assert result.data["is_canary"] is True

    def test_list_slos(self):
        server = AgentSREServer()
        server.register_slo("slo-1", _make_slo("slo-1"))
        server.register_slo("slo-2", _make_slo("slo-2"))
        result = server.handle_tool_call("sre_list_slos")
        assert result.success
        assert result.data["count"] == 2

    def test_unknown_tool(self):
        server = AgentSREServer()
        result = server.handle_tool_call("nonexistent_tool")
        assert not result.success
        assert "Unknown tool" in result.error

    def test_call_history(self):
        server = AgentSREServer()
        server.handle_tool_call("sre_list_slos")
        server.handle_tool_call("sre_check_rollout_status", {"agent_id": "a1"})
        assert len(server.call_history) == 2

    def test_stats(self):
        server = AgentSREServer()
        server.handle_tool_call("sre_list_slos")
        server.handle_tool_call("nonexistent")
        stats = server.get_stats()
        assert stats["total_calls"] == 2
        assert stats["successful"] == 1
        assert stats["failed"] == 1
        assert stats["tools_available"] == 5

    def test_clear_history(self):
        server = AgentSREServer()
        server.handle_tool_call("sre_list_slos")
        server.clear_history()
        assert len(server.call_history) == 0
