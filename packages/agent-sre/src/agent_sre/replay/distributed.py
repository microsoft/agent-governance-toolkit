# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Trace replay — not available in Community Edition.

Classes are retained for API compatibility. Use the local ReplayEngine instead.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_sre.replay.capture import Trace
    from agent_sre.replay.engine import ReplayResult, TraceDiff


class MeshReplayState(Enum):
    """State of a trace replay session."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass
class AgentTraceRef:
    """Reference to a trace belonging to a specific agent in the mesh."""
    agent_id: str
    trace_id: str
    trace: Trace | None = None
    role: str = ""  # initiator, responder, delegate

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "trace_id": self.trace_id,
            "role": self.role,
            "span_count": len(self.trace.spans) if self.trace else 0,
        }


@dataclass
class DelegationLink:
    """A delegation link between two agents in a distributed trace."""
    from_agent: str
    to_agent: str
    from_span_id: str
    to_trace_id: str
    task_description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "from_span_id": self.from_span_id,
            "to_trace_id": self.to_trace_id,
            "task_description": self.task_description,
        }


@dataclass
class DistributedReplayResult:
    """Result of replaying a distributed multi-agent trace."""
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    state: MeshReplayState = MeshReplayState.PENDING
    agent_results: dict[str, ReplayResult] = field(default_factory=dict)
    cross_agent_diffs: list[TraceDiff] = field(default_factory=list)
    agents_completed: int = 0
    agents_total: int = 0

    @property
    def all_diffs(self) -> list[TraceDiff]:
        """All diffs across all agents."""
        diffs = list(self.cross_agent_diffs)
        for result in self.agent_results.values():
            diffs.extend(result.diffs)
        return diffs

    @property
    def success(self) -> bool:
        return self.state == MeshReplayState.COMPLETED and not self.all_diffs

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "state": self.state.value,
            "success": self.success,
            "agents_completed": self.agents_completed,
            "agents_total": self.agents_total,
            "total_diffs": len(self.all_diffs),
            "cross_agent_diffs": [d.to_dict() for d in self.cross_agent_diffs],
            "agent_results": {
                aid: r.to_dict() for aid, r in self.agent_results.items()
            },
        }


class DistributedReplayEngine:
    """Replays multi-agent traces across mesh boundaries.

    Reconstructs the full execution flow across agents by following
    delegation spans and correlating traces from different agents.
    """

    def __init__(self) -> None:
        self._agent_traces: dict[str, AgentTraceRef] = {}
        self._delegation_links: list[DelegationLink] = []

    def add_agent_trace(self, agent_id: str, trace: Trace, role: str = "") -> None:
        """Register a trace for an agent."""
        self._agent_traces[agent_id] = AgentTraceRef(
            agent_id=agent_id,
            trace_id=trace.trace_id,
            trace=trace,
            role=role,
        )

    def link_delegation(
        self,
        from_agent: str,
        to_agent: str,
        from_span_id: str,
        to_trace_id: str,
        task_description: str = "",
    ) -> None:
        """Link a delegation span to the delegated agent's trace."""
        self._delegation_links.append(DelegationLink(
            from_agent=from_agent,
            to_agent=to_agent,
            from_span_id=from_span_id,
            to_trace_id=to_trace_id,
            task_description=task_description,
        ))

    def discover_links(self) -> list[DelegationLink]:
        """Auto-discover delegation links — not available in Community Edition."""
        raise NotImplementedError(
            "Not available in Community Edition"
        )

    def replay(self) -> DistributedReplayResult:
        """Replay all agent traces — not available in Community Edition."""
        raise NotImplementedError(
            "Not available in Community Edition"
        )

    def _check_cross_agent(self, result: DistributedReplayResult) -> list[TraceDiff]:
        """Check consistency across delegation boundaries — not available in Community Edition."""
        raise NotImplementedError(
            "Not available in Community Edition"
        )

    def execution_order(self) -> list[str]:
        """Get the execution order of agents based on delegation links."""
        order: list[str] = []
        visited: set[str] = set()

        initiators = set(self._agent_traces.keys())
        for link in self._delegation_links:
            initiators.discard(link.to_agent)

        def _visit(agent_id: str) -> None:
            if agent_id in visited:
                return
            visited.add(agent_id)
            order.append(agent_id)
            for link in self._delegation_links:
                if link.from_agent == agent_id:
                    _visit(link.to_agent)

        for init in initiators:
            _visit(init)

        # Add any unvisited
        for aid in self._agent_traces:
            if aid not in visited:
                order.append(aid)

        return order

    def to_dict(self) -> dict[str, Any]:
        return {
            "agents": {aid: ref.to_dict() for aid, ref in self._agent_traces.items()},
            "delegation_links": [l.to_dict() for l in self._delegation_links],
            "execution_order": self.execution_order(),
        }
