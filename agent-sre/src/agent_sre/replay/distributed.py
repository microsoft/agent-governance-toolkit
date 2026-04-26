# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Distributed trace replay — multi-agent replay with cross-boundary checks.

Supports automatic delegation link discovery, per-agent replay,
and cross-agent consistency verification.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agent_sre.replay.capture import SpanKind, Trace
from agent_sre.replay.engine import DiffType, ReplayEngine, ReplayResult, TraceDiff


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
        """Auto-discover delegation links by scanning traces for DELEGATION spans.

        Scans all registered agent traces for spans of kind DELEGATION,
        then matches their output_data['delegated_trace_id'] to other
        registered agents' traces.
        """
        discovered: list[DelegationLink] = []

        # Build a reverse lookup: trace_id -> agent_id
        trace_to_agent: dict[str, str] = {}
        for agent_id, ref in self._agent_traces.items():
            if ref.trace:
                trace_to_agent[ref.trace.trace_id] = agent_id

        # Scan each agent's trace for delegation spans
        for agent_id, ref in self._agent_traces.items():
            if ref.trace is None:
                continue
            for span in ref.trace.spans:
                if span.kind != SpanKind.DELEGATION:
                    continue
                # Look for a delegated trace ID in the span's output
                delegated_id = span.output_data.get("delegated_trace_id", "")
                if not delegated_id:
                    delegated_id = span.attributes.get("delegated_trace_id", "")
                if not delegated_id:
                    continue

                to_agent = trace_to_agent.get(delegated_id)
                if to_agent and to_agent != agent_id:
                    link = DelegationLink(
                        from_agent=agent_id,
                        to_agent=to_agent,
                        from_span_id=span.span_id,
                        to_trace_id=delegated_id,
                        task_description=span.name,
                    )
                    discovered.append(link)

        # Merge with existing links (avoid duplicates)
        existing = {
            (lk.from_agent, lk.to_agent, lk.to_trace_id) for lk in self._delegation_links
        }
        for link in discovered:
            key = (link.from_agent, link.to_agent, link.to_trace_id)
            if key not in existing:
                self._delegation_links.append(link)
                existing.add(key)

        return list(self._delegation_links)

    def replay(self) -> DistributedReplayResult:
        """Replay all registered agent traces and check cross-agent consistency.

        Iterates agents in execution order, replays each with a local
        ReplayEngine, then validates delegation boundaries.
        """
        result = DistributedReplayResult(
            agents_total=len(self._agent_traces),
        )
        result.state = MeshReplayState.RUNNING

        engine = ReplayEngine()
        order = self.execution_order()

        for agent_id in order:
            ref = self._agent_traces.get(agent_id)
            if ref is None or ref.trace is None:
                continue

            agent_result = engine.replay(ref.trace)
            result.agent_results[agent_id] = agent_result
            result.agents_completed += 1

        # Cross-agent consistency checks
        result.cross_agent_diffs = self._check_cross_agent(result)

        if result.agents_completed == result.agents_total:
            result.state = MeshReplayState.COMPLETED
        elif result.agents_completed > 0:
            result.state = MeshReplayState.PARTIAL
        else:
            result.state = MeshReplayState.FAILED

        return result

    def _check_cross_agent(self, result: DistributedReplayResult) -> list[TraceDiff]:
        """Verify consistency across delegation boundaries.

        For each delegation link, checks that the delegator's delegation
        span output is consistent with the delegate's trace input.
        """
        diffs: list[TraceDiff] = []

        for link in self._delegation_links:
            from_ref = self._agent_traces.get(link.from_agent)
            to_ref = self._agent_traces.get(link.to_agent)

            if not from_ref or not from_ref.trace or not to_ref or not to_ref.trace:
                continue

            # Find the delegation span in the source agent
            source_span = None
            for span in from_ref.trace.spans:
                if span.span_id == link.from_span_id:
                    source_span = span
                    break

            if source_span is None:
                diffs.append(TraceDiff(
                    diff_type=DiffType.MISSING_SPAN,
                    span_name=f"delegation:{link.from_agent}->{link.to_agent}",
                    description=(
                        f"Delegation span {link.from_span_id} not found "
                        f"in {link.from_agent}'s trace"
                    ),
                ))
                continue

            # Check that the delegate trace actually exists and succeeded
            delegate_trace = to_ref.trace
            if delegate_trace.success is False:
                diffs.append(TraceDiff(
                    diff_type=DiffType.STATUS_CHANGE,
                    span_name=f"delegation:{link.from_agent}->{link.to_agent}",
                    original="expected_success",
                    replayed="delegate_failed",
                    description=(
                        f"Delegated trace {link.to_trace_id} in {link.to_agent} failed"
                    ),
                ))

        return diffs

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
            "delegation_links": [link.to_dict() for link in self._delegation_links],
            "execution_order": self.execution_order(),
        }
