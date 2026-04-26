# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy Conflict Resolution.

When multiple policies apply to the same agent action, the conflict
resolution strategy determines which decision wins.

Strategies
----------
- **DENY_OVERRIDES** (safest): If ANY matching rule denies, the action
  is denied regardless of what other rules say. Standard in XACML and
  most enterprise policy systems.
- **ALLOW_OVERRIDES**: If ANY matching rule allows, the action is
  allowed. Useful for exception-based governance where you want
  explicit allow-rules to punch through default-deny policies.
- **PRIORITY_FIRST_MATCH** (current default): Rules are sorted by
  priority (highest first), and the first matching rule wins. This
  preserves backward compatibility with the existing PolicyEngine.
- **MOST_SPECIFIC_WINS**: Agent-scoped rules override tenant-scoped,
  which override global-scoped. Within the same scope, priority breaks
  ties. Models the intuition that "closer policies override distant ones."

Scopes
------
Each ``Policy`` can declare a ``scope`` that indicates its breadth:

- ``global``: Organization-wide default policies
- ``tenant``: Applied to a specific tenant or team
- ``agent``: Applied to a specific agent instance

When ``MOST_SPECIFIC_WINS`` is active, scope determines precedence.
When other strategies are active, scope is informational metadata.

Usage::

    from agentmesh.governance.conflict_resolution import (
        ConflictResolutionStrategy,
        PolicyScope,
        PolicyConflictResolver,
    )

    resolver = PolicyConflictResolver(ConflictResolutionStrategy.DENY_OVERRIDES)
    final = resolver.resolve(candidate_decisions)
"""

from __future__ import annotations

import logging
from enum import Enum

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ConflictResolutionStrategy(str, Enum):
    """Strategy for resolving conflicts between competing policy decisions."""

    DENY_OVERRIDES = "deny_overrides"
    ALLOW_OVERRIDES = "allow_overrides"
    PRIORITY_FIRST_MATCH = "priority_first_match"
    MOST_SPECIFIC_WINS = "most_specific_wins"


class PolicyScope(str, Enum):
    """Breadth of a policy's applicability.

    Specificity order (most → least): AGENT > ORGANIZATION > TENANT > GLOBAL.
    """

    GLOBAL = "global"
    TENANT = "tenant"
    ORGANIZATION = "organization"
    AGENT = "agent"


# Specificity rank: higher = more specific
_SCOPE_SPECIFICITY: dict[PolicyScope, int] = {
    PolicyScope.GLOBAL: 0,
    PolicyScope.TENANT: 1,
    PolicyScope.ORGANIZATION: 2,
    PolicyScope.AGENT: 3,
}


class CandidateDecision(BaseModel):
    """A single policy decision candidate awaiting conflict resolution.

    Groups a decision with its originating policy metadata so the
    resolver can apply scope- and priority-aware strategies.

    Attributes:
        action: The action the rule dictates (allow, deny, warn, etc.).
        priority: Numeric priority from the matched rule.
        scope: Scope of the policy that produced this decision.
        policy_name: Name of the originating policy.
        rule_name: Name of the matched rule.
        reason: Human-readable explanation.
        approvers: Required approvers for ``require_approval`` actions.
    """

    action: str
    priority: int = 0
    scope: PolicyScope = PolicyScope.GLOBAL
    policy_name: str = ""
    rule_name: str = ""
    reason: str = ""
    approvers: list[str] = Field(default_factory=list)

    @property
    def is_deny(self) -> bool:
        return self.action == "deny"

    @property
    def is_allow(self) -> bool:
        return self.action == "allow"

    @property
    def specificity(self) -> int:
        return _SCOPE_SPECIFICITY.get(self.scope, 0)


class ResolutionResult(BaseModel):
    """Outcome of conflict resolution.

    Attributes:
        winning_decision: The decision that prevailed.
        strategy_used: Which strategy resolved the conflict.
        candidates_evaluated: How many candidates were considered.
        conflict_detected: Whether genuinely conflicting decisions existed.
        resolution_trace: Human-readable trace of the resolution logic.
    """

    winning_decision: CandidateDecision
    strategy_used: ConflictResolutionStrategy
    candidates_evaluated: int = 0
    conflict_detected: bool = False
    resolution_trace: list[str] = Field(default_factory=list)


class PolicyConflictResolver:
    """Resolves conflicts between competing policy decisions.

    Args:
        strategy: The conflict resolution strategy to apply.
    """

    def __init__(
        self,
        strategy: ConflictResolutionStrategy = ConflictResolutionStrategy.PRIORITY_FIRST_MATCH,
    ) -> None:
        self.strategy = strategy

    def resolve(self, candidates: list[CandidateDecision]) -> ResolutionResult:
        """Resolve a list of candidate decisions into a single winner.

        Args:
            candidates: One or more candidate decisions from matching rules.

        Returns:
            A ``ResolutionResult`` containing the winning decision and
            a trace of the resolution logic.

        Raises:
            ValueError: If ``candidates`` is empty.
        """
        if not candidates:
            raise ValueError("Cannot resolve conflict with zero candidates")

        if len(candidates) == 1:
            return ResolutionResult(
                winning_decision=candidates[0],
                strategy_used=self.strategy,
                candidates_evaluated=1,
                conflict_detected=False,
                resolution_trace=[f"Single candidate: {candidates[0].rule_name} → {candidates[0].action}"],
            )

        # Detect genuine conflict (mix of allow and deny)
        actions = {c.action for c in candidates}
        conflict_detected = "allow" in actions and "deny" in actions

        dispatch = {
            ConflictResolutionStrategy.DENY_OVERRIDES: self._deny_overrides,
            ConflictResolutionStrategy.ALLOW_OVERRIDES: self._allow_overrides,
            ConflictResolutionStrategy.PRIORITY_FIRST_MATCH: self._priority_first_match,
            ConflictResolutionStrategy.MOST_SPECIFIC_WINS: self._most_specific_wins,
        }

        winner, trace = dispatch[self.strategy](candidates)

        return ResolutionResult(
            winning_decision=winner,
            strategy_used=self.strategy,
            candidates_evaluated=len(candidates),
            conflict_detected=conflict_detected,
            resolution_trace=trace,
        )

    # ── Strategy implementations ────────────────────────────

    def _deny_overrides(
        self, candidates: list[CandidateDecision]
    ) -> tuple[CandidateDecision, list[str]]:
        """DENY_OVERRIDES: any deny wins. Among denies, highest priority wins."""
        trace = []
        denies = [c for c in candidates if c.is_deny]
        if denies:
            denies.sort(key=lambda c: c.priority, reverse=True)
            winner = denies[0]
            trace.append(f"DENY_OVERRIDES: {len(denies)} deny rule(s) found")
            trace.append(f"Winner: {winner.rule_name} (priority={winner.priority}, scope={winner.scope.value})")
            return winner, trace

        # No denies — pick highest-priority allow
        candidates_sorted = sorted(candidates, key=lambda c: c.priority, reverse=True)
        winner = candidates_sorted[0]
        trace.append("DENY_OVERRIDES: no deny rules, selecting highest-priority allow")
        trace.append(f"Winner: {winner.rule_name} (priority={winner.priority})")
        return winner, trace

    def _allow_overrides(
        self, candidates: list[CandidateDecision]
    ) -> tuple[CandidateDecision, list[str]]:
        """ALLOW_OVERRIDES: any allow wins. Among allows, highest priority wins."""
        trace = []
        allows = [c for c in candidates if c.is_allow]
        if allows:
            allows.sort(key=lambda c: c.priority, reverse=True)
            winner = allows[0]
            trace.append(f"ALLOW_OVERRIDES: {len(allows)} allow rule(s) found")
            trace.append(f"Winner: {winner.rule_name} (priority={winner.priority}, scope={winner.scope.value})")
            return winner, trace

        # No allows — pick highest-priority deny
        candidates_sorted = sorted(candidates, key=lambda c: c.priority, reverse=True)
        winner = candidates_sorted[0]
        trace.append("ALLOW_OVERRIDES: no allow rules, selecting highest-priority deny")
        trace.append(f"Winner: {winner.rule_name} (priority={winner.priority})")
        return winner, trace

    def _priority_first_match(
        self, candidates: list[CandidateDecision]
    ) -> tuple[CandidateDecision, list[str]]:
        """PRIORITY_FIRST_MATCH: highest priority wins regardless of action."""
        sorted_candidates = sorted(candidates, key=lambda c: c.priority, reverse=True)
        winner = sorted_candidates[0]
        trace = [
            f"PRIORITY_FIRST_MATCH: {len(candidates)} candidates",
            f"Winner: {winner.rule_name} (priority={winner.priority}, action={winner.action})",
        ]
        return winner, trace

    def _most_specific_wins(
        self, candidates: list[CandidateDecision]
    ) -> tuple[CandidateDecision, list[str]]:
        """MOST_SPECIFIC_WINS: agent > tenant > global. Priority breaks ties."""
        sorted_candidates = sorted(
            candidates,
            key=lambda c: (c.specificity, c.priority),
            reverse=True,
        )
        winner = sorted_candidates[0]
        trace = [
            f"MOST_SPECIFIC_WINS: {len(candidates)} candidates",
            f"Specificity ranking: {[(c.rule_name, c.scope.value, c.specificity) for c in sorted_candidates]}",
            f"Winner: {winner.rule_name} (scope={winner.scope.value}, priority={winner.priority}, action={winner.action})",
        ]
        return winner, trace
