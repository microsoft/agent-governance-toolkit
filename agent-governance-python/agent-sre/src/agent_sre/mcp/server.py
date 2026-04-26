# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP Server for Agent-SRE.

Exposes Agent-SRE capabilities as MCP tools so agents can self-monitor:
- sre_check_slo: agent queries its own SLO status
- sre_report_cost: agent reports task cost
- sre_request_budget: agent requests cost budget for expensive operation
- sre_check_rollout_status: agent checks if it is in canary mode

No external MCP SDK dependency — implements the MCP tool interface via duck typing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass
class MCPToolDefinition:
    """Definition of an MCP tool."""
    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPToolResult:
    """Result of an MCP tool call."""
    tool_name: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    timestamp: float = field(default_factory=time.time)


class AgentSREServer:
    """MCP Server exposing Agent-SRE capabilities as tools.

    Registers SLO engine, cost guard, and delivery components and
    exposes them as callable MCP tools.

    Usage:
        server = AgentSREServer()
        server.register_slo("my-slo", slo_instance)

        # Handle MCP tool call
        result = server.handle_tool_call("sre_check_slo", {"slo_name": "my-slo"})
    """

    def __init__(self) -> None:
        self._slos: dict[str, Any] = {}
        self._cost_budgets: dict[str, float] = {}
        self._cost_spent: dict[str, float] = {}
        self._rollout_status: dict[str, str] = {}
        self._call_history: list[MCPToolResult] = []
        self._tools: dict[str, Callable] = {
            "sre_check_slo": self._check_slo,
            "sre_report_cost": self._report_cost,
            "sre_request_budget": self._request_budget,
            "sre_check_rollout_status": self._check_rollout,
            "sre_list_slos": self._list_slos,
        }

    def register_slo(self, name: str, slo: Any) -> None:
        """Register an SLO for monitoring."""
        self._slos[name] = slo

    def set_cost_budget(self, agent_id: str, budget_usd: float) -> None:
        """Set cost budget for an agent."""
        self._cost_budgets[agent_id] = budget_usd
        self._cost_spent.setdefault(agent_id, 0.0)

    def set_rollout_status(self, agent_id: str, status: str) -> None:
        """Set rollout status for an agent (canary, stable, rolling-back)."""
        self._rollout_status[agent_id] = status

    def list_tools(self) -> list[MCPToolDefinition]:
        """List available MCP tools."""
        return [
            MCPToolDefinition(
                name="sre_check_slo",
                description="Check SLO status for an agent",
                parameters={"type": "object", "properties": {
                    "slo_name": {"type": "string", "description": "Name of the SLO to check"},
                }, "required": ["slo_name"]},
            ),
            MCPToolDefinition(
                name="sre_report_cost",
                description="Report task cost to Agent-SRE cost guard",
                parameters={"type": "object", "properties": {
                    "agent_id": {"type": "string"},
                    "cost_usd": {"type": "number"},
                    "task_id": {"type": "string"},
                }, "required": ["agent_id", "cost_usd"]},
            ),
            MCPToolDefinition(
                name="sre_request_budget",
                description="Request cost budget approval for an expensive operation",
                parameters={"type": "object", "properties": {
                    "agent_id": {"type": "string"},
                    "requested_usd": {"type": "number"},
                }, "required": ["agent_id", "requested_usd"]},
            ),
            MCPToolDefinition(
                name="sre_check_rollout_status",
                description="Check if agent is in canary deployment mode",
                parameters={"type": "object", "properties": {
                    "agent_id": {"type": "string"},
                }, "required": ["agent_id"]},
            ),
            MCPToolDefinition(
                name="sre_list_slos",
                description="List all registered SLOs",
                parameters={"type": "object", "properties": {}},
            ),
        ]

    def handle_tool_call(self, tool_name: str, arguments: dict[str, Any] | None = None) -> MCPToolResult:
        """Handle an MCP tool call."""
        arguments = arguments or {}
        handler = self._tools.get(tool_name)
        if not handler:
            result = MCPToolResult(
                tool_name=tool_name, success=False,
                error=f"Unknown tool: {tool_name}",
            )
        else:
            try:
                data = handler(arguments)
                result = MCPToolResult(tool_name=tool_name, success=True, data=data)
            except Exception as e:
                result = MCPToolResult(tool_name=tool_name, success=False, error=str(e))

        self._call_history.append(result)
        return result

    def _check_slo(self, args: dict[str, Any]) -> dict[str, Any]:
        slo_name = args.get("slo_name", "")
        slo = self._slos.get(slo_name)
        if not slo:
            return {"error": f"SLO '{slo_name}' not found", "available": list(self._slos.keys())}
        status = slo.evaluate()
        return {
            "slo_name": slo_name,
            "status": status.value,
            "budget_remaining_percent": slo.error_budget.remaining_percent,
            "is_exhausted": slo.error_budget.is_exhausted,
        }

    def _report_cost(self, args: dict[str, Any]) -> dict[str, Any]:
        agent_id = args.get("agent_id", "")
        cost_usd = float(args.get("cost_usd", 0))
        self._cost_spent[agent_id] = self._cost_spent.get(agent_id, 0.0) + cost_usd
        budget = self._cost_budgets.get(agent_id)
        return {
            "agent_id": agent_id,
            "cost_recorded": cost_usd,
            "total_spent": self._cost_spent[agent_id],
            "budget_remaining": (budget - self._cost_spent[agent_id]) if budget else None,
        }

    def _request_budget(self, args: dict[str, Any]) -> dict[str, Any]:
        agent_id = args.get("agent_id", "")
        requested = float(args.get("requested_usd", 0))
        budget = self._cost_budgets.get(agent_id)
        spent = self._cost_spent.get(agent_id, 0.0)
        if budget is None:
            return {"approved": True, "reason": "No budget limit set"}
        remaining = budget - spent
        approved = requested <= remaining
        return {
            "approved": approved,
            "requested_usd": requested,
            "remaining_usd": remaining,
            "reason": "Within budget" if approved else f"Exceeds budget by ${requested - remaining:.4f}",
        }

    def _check_rollout(self, args: dict[str, Any]) -> dict[str, Any]:
        agent_id = args.get("agent_id", "")
        status = self._rollout_status.get(agent_id, "stable")
        return {"agent_id": agent_id, "rollout_status": status, "is_canary": status == "canary"}

    def _list_slos(self, args: dict[str, Any]) -> dict[str, Any]:
        slos = []
        for name, slo in self._slos.items():
            status = slo.evaluate()
            slos.append({"name": name, "status": status.value})
        return {"slos": slos, "count": len(slos)}

    @property
    def call_history(self) -> list[MCPToolResult]:
        return list(self._call_history)

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_calls": len(self._call_history),
            "successful": sum(1 for r in self._call_history if r.success),
            "failed": sum(1 for r in self._call_history if not r.success),
            "registered_slos": len(self._slos),
            "tools_available": len(self._tools),
        }

    def clear_history(self) -> None:
        self._call_history.clear()
