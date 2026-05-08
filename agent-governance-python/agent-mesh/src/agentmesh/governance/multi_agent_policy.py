# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Multi-Agent Policy Evaluator.

A separate evaluation pass that watches all agents collectively, evaluating
policies that span multiple agents. This runs at the AgentMesh router level,
not inside individual agent pipelines.

Design decisions:
    - Separate evaluation pass from per-agent PolicyEngine (does not extend it).
    - Evaluates collective constraints (aggregate behavior across all agents).
    - Relationship constraints tracked on roadmap (not implemented here).
    - Uses a sliding window for time-based aggregate conditions.
    - Non-invasive: agents don't report to this evaluator. It observes
      action records pushed by the governance pipeline.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class MultiAgentPolicyScope(str, Enum):
    """Scope of a multi-agent policy."""

    MULTI_AGENT = "multi-agent"
    # AGENT_PAIR = "agent-pair"  # Roadmap: relationship constraints


class AggregateFunction(str, Enum):
    """Aggregate functions for collective constraints."""

    COUNT = "count"
    SUM = "sum"
    MAX = "max"
    DISTINCT_AGENTS = "distinct_agents"


class MultiAgentAction(str, Enum):
    """Actions taken when a multi-agent policy is violated."""

    DENY = "deny"
    ALERT = "alert"
    THROTTLE = "throttle"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class ActionRecord:
    """A record of an agent action observed by the multi-agent evaluator.

    These are pushed by the governance pipeline after each action.
    """

    agent_id: str
    action: str
    tool_name: str = ""
    params: dict[str, Any] | None = None
    timestamp: float = field(default_factory=time.monotonic)
    wall_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectiveCondition:
    """A condition evaluated across all agents in a time window.

    Attributes:
        aggregate: The aggregate function to apply.
        filter_action: If set, only count actions matching this name.
        filter_tool: If set, only count actions using this tool.
        across: Which agents to aggregate across ("all_agents" or a pattern).
        window_seconds: Sliding window size in seconds.
        threshold: The value that triggers the condition.
    """

    aggregate: AggregateFunction
    filter_action: str | None = None
    filter_tool: str | None = None
    across: str = "all_agents"
    window_seconds: float = 60.0
    threshold: float = 1.0


@dataclass
class MultiAgentPolicy:
    """A policy that evaluates collective agent behavior.

    Example YAML representation:
        name: no-parallel-financial-ops
        scope: multi-agent
        condition:
          aggregate: count
          filter_tool: transfer_funds
          across: all_agents
          window_seconds: 60
          threshold: 3
        action: deny
    """

    name: str
    scope: MultiAgentPolicyScope = MultiAgentPolicyScope.MULTI_AGENT
    condition: CollectiveCondition = field(default_factory=CollectiveCondition)
    action: MultiAgentAction = MultiAgentAction.DENY
    description: str = ""
    enabled: bool = True

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MultiAgentPolicy:
        cond_data = d.get("condition", {})
        condition = CollectiveCondition(
            aggregate=AggregateFunction(cond_data.get("aggregate", "count")),
            filter_action=cond_data.get("filter_action"),
            filter_tool=cond_data.get("filter_tool"),
            across=cond_data.get("across", "all_agents"),
            window_seconds=float(cond_data.get("window_seconds", cond_data.get("window", 60))),
            threshold=float(cond_data.get("threshold", 1)),
        )
        return cls(
            name=d["name"],
            scope=MultiAgentPolicyScope(d.get("scope", "multi-agent")),
            condition=condition,
            action=MultiAgentAction(d.get("action", "deny")),
            description=d.get("description", ""),
            enabled=d.get("enabled", True),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "scope": self.scope.value,
            "condition": {
                "aggregate": self.condition.aggregate.value,
                "filter_action": self.condition.filter_action,
                "filter_tool": self.condition.filter_tool,
                "across": self.condition.across,
                "window_seconds": self.condition.window_seconds,
                "threshold": self.condition.threshold,
            },
            "action": self.action.value,
            "description": self.description,
            "enabled": self.enabled,
        }


@dataclass
class MultiAgentDecision:
    """Result of evaluating a multi-agent policy."""

    policy_name: str
    allowed: bool
    action: MultiAgentAction
    current_value: float
    threshold: float
    reason: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_name": self.policy_name,
            "allowed": self.allowed,
            "action": self.action.value,
            "current_value": self.current_value,
            "threshold": self.threshold,
            "reason": self.reason,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class MultiAgentEvaluationResult:
    """Aggregate result of evaluating all multi-agent policies."""

    allowed: bool
    decisions: list[MultiAgentDecision] = field(default_factory=list)
    violated_policies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "decisions": [d.to_dict() for d in self.decisions],
            "violated_policies": self.violated_policies,
        }


# ---------------------------------------------------------------------------
# Multi-Agent Policy Evaluator
# ---------------------------------------------------------------------------

class MultiAgentPolicyEvaluator:
    """Evaluates collective agent behavior against multi-agent policies.

    This is a separate evaluation pass that runs at a higher level than
    per-agent policy evaluation. It maintains a sliding window of recent
    action records and evaluates aggregate conditions across all agents.

    Usage:
        >>> evaluator = MultiAgentPolicyEvaluator()
        >>> evaluator.add_policy(MultiAgentPolicy(
        ...     name="rate-limit-transfers",
        ...     condition=CollectiveCondition(
        ...         aggregate=AggregateFunction.COUNT,
        ...         filter_tool="transfer_funds",
        ...         window_seconds=60,
        ...         threshold=3,
        ...     ),
        ...     action=MultiAgentAction.DENY,
        ... ))
        >>> evaluator.record_action(ActionRecord(
        ...     agent_id="agent-1", action="transfer", tool_name="transfer_funds"
        ... ))
        >>> result = evaluator.evaluate("agent-2", "transfer", "transfer_funds")
        >>> print(result.allowed)
    """

    def __init__(self, max_history: int = 10000) -> None:
        """Initialize the evaluator.

        Args:
            max_history: Maximum number of action records to retain.
                Older records are evicted when this limit is reached.
        """
        self._policies: dict[str, MultiAgentPolicy] = {}
        self._action_history: list[ActionRecord] = []
        self._max_history = max_history

    # ----- Policy management -----

    def add_policy(self, policy: MultiAgentPolicy) -> None:
        """Add or update a multi-agent policy."""
        self._policies[policy.name] = policy

    def remove_policy(self, name: str) -> bool:
        """Remove a policy by name. Returns True if found."""
        return self._policies.pop(name, None) is not None

    def list_policies(self) -> list[MultiAgentPolicy]:
        """List all registered policies."""
        return list(self._policies.values())

    def load_policies_from_dicts(self, policies: list[dict[str, Any]]) -> int:
        """Load multiple policies from dictionary representations.

        Returns the number of policies loaded.
        """
        count = 0
        for p in policies:
            try:
                policy = MultiAgentPolicy.from_dict(p)
                self.add_policy(policy)
                count += 1
            except (KeyError, ValueError) as e:
                logger.warning("Failed to load policy: %s", e)
        return count

    # ----- Action recording -----

    def record_action(self, record: ActionRecord) -> None:
        """Record an agent action for collective evaluation.

        This should be called by the governance pipeline after each action.
        """
        self._action_history.append(record)
        # Evict oldest records if over limit
        if len(self._action_history) > self._max_history:
            self._action_history = self._action_history[-self._max_history:]

    # ----- Evaluation -----

    def evaluate(
        self,
        agent_id: str,
        action: str,
        tool_name: str = "",
        params: dict[str, Any] | None = None,
    ) -> MultiAgentEvaluationResult:
        """Evaluate all multi-agent policies for a proposed action.

        This is the main entry point, called before an action is executed
        to check whether collective constraints would be violated.

        Args:
            agent_id: The agent proposing the action.
            action: The action being attempted.
            tool_name: The tool being invoked (if applicable).
            params: Action parameters.

        Returns:
            MultiAgentEvaluationResult with allow/deny and per-policy decisions.
        """
        now = time.monotonic()
        decisions: list[MultiAgentDecision] = []
        violated: list[str] = []
        overall_allowed = True

        for policy in self._policies.values():
            if not policy.enabled:
                continue

            decision = self._evaluate_policy(policy, agent_id, action, tool_name, now)
            decisions.append(decision)

            if not decision.allowed:
                violated.append(policy.name)
                if policy.action == MultiAgentAction.DENY:
                    overall_allowed = False

        return MultiAgentEvaluationResult(
            allowed=overall_allowed,
            decisions=decisions,
            violated_policies=violated,
        )

    def _evaluate_policy(
        self,
        policy: MultiAgentPolicy,
        agent_id: str,
        action: str,
        tool_name: str,
        now: float,
    ) -> MultiAgentDecision:
        """Evaluate a single multi-agent policy."""
        cond = policy.condition
        cutoff = now - cond.window_seconds

        # Filter action history to the window
        window_records = [
            r for r in self._action_history
            if r.timestamp >= cutoff
        ]

        # Apply filters
        filtered = self._apply_filters(window_records, cond)

        # Compute aggregate
        value = self._compute_aggregate(filtered, cond.aggregate)

        # Check if adding the proposed action would exceed threshold
        # (count the proposed action as +1 if it matches the filter)
        proposed_matches = self._matches_filter(
            action, tool_name, cond
        )
        projected_value = value + (1.0 if proposed_matches and cond.aggregate == AggregateFunction.COUNT else 0.0)

        if cond.aggregate == AggregateFunction.DISTINCT_AGENTS and proposed_matches:
            existing_agents = {r.agent_id for r in filtered}
            if agent_id not in existing_agents:
                projected_value = value + 1.0
            else:
                projected_value = value

        violated = projected_value >= cond.threshold

        return MultiAgentDecision(
            policy_name=policy.name,
            allowed=not violated,
            action=policy.action,
            current_value=projected_value,
            threshold=cond.threshold,
            reason=(
                f"Collective constraint '{policy.name}' violated: "
                f"{cond.aggregate.value}={projected_value} >= threshold={cond.threshold} "
                f"in {cond.window_seconds}s window"
                if violated else ""
            ),
        )

    def _apply_filters(
        self,
        records: list[ActionRecord],
        condition: CollectiveCondition,
    ) -> list[ActionRecord]:
        """Filter records based on condition criteria."""
        result = records
        if condition.filter_action:
            result = [r for r in result if r.action == condition.filter_action]
        if condition.filter_tool:
            result = [r for r in result if r.tool_name == condition.filter_tool]
        return result

    def _matches_filter(
        self,
        action: str,
        tool_name: str,
        condition: CollectiveCondition,
    ) -> bool:
        """Check if a proposed action matches the condition filters."""
        if condition.filter_action and condition.filter_action != action:
            return False
        if condition.filter_tool and condition.filter_tool != tool_name:
            return False
        return True

    def _compute_aggregate(
        self,
        records: list[ActionRecord],
        aggregate: AggregateFunction,
    ) -> float:
        """Compute an aggregate value over filtered records."""
        if aggregate == AggregateFunction.COUNT:
            return float(len(records))
        elif aggregate == AggregateFunction.DISTINCT_AGENTS:
            return float(len({r.agent_id for r in records}))
        elif aggregate == AggregateFunction.SUM:
            return sum(
                r.metadata.get("cost", 0.0) for r in records
            )
        elif aggregate == AggregateFunction.MAX:
            if not records:
                return 0.0
            return max(
                r.metadata.get("value", 0.0) for r in records
            )
        return 0.0

    # ----- Utilities -----

    def get_window_stats(self, window_seconds: float = 60.0) -> dict[str, Any]:
        """Get statistics about recent agent activity.

        Useful for monitoring and dashboards.
        """
        now = time.monotonic()
        cutoff = now - window_seconds
        window = [r for r in self._action_history if r.timestamp >= cutoff]

        agents = {r.agent_id for r in window}
        actions = {}
        tools = {}
        for r in window:
            actions[r.action] = actions.get(r.action, 0) + 1
            if r.tool_name:
                tools[r.tool_name] = tools.get(r.tool_name, 0) + 1

        return {
            "window_seconds": window_seconds,
            "total_actions": len(window),
            "unique_agents": len(agents),
            "agent_ids": sorted(agents),
            "action_counts": actions,
            "tool_counts": tools,
        }

    def clear_history(self) -> None:
        """Clear all action history."""
        self._action_history.clear()

    @property
    def action_count(self) -> int:
        """Total number of recorded actions."""
        return len(self._action_history)

    @property
    def policy_count(self) -> int:
        """Total number of registered policies."""
        return len(self._policies)
