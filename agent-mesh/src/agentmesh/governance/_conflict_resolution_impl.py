# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Standalone policy conflict resolution implementation.

This module provides a self-contained implementation that requires no
packages beyond ``pydantic`` (already a core ``agentmesh`` dependency).
It is used as a fallback by ``agentmesh.governance.conflict_resolution``
when ``agent_os`` is not installed.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


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
_SCOPE_SPECIFICITY: dict[Any, int] = {
    PolicyScope.GLOBAL: 0,
    PolicyScope.TENANT: 1,
    PolicyScope.ORGANIZATION: 2,
    PolicyScope.AGENT: 3,
}


class CandidateDecision(BaseModel):
    """A single policy decision candidate awaiting conflict resolution."""

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
    """Outcome of conflict resolution."""

    winning_decision: CandidateDecision
    strategy_used: ConflictResolutionStrategy
    candidates_evaluated: int = 0
    conflict_detected: bool = False
    resolution_trace: list[str] = Field(default_factory=list)


class PolicyConflictResolver:
    """Resolves conflicts between competing policy decisions."""

    def __init__(
        self,
        strategy: ConflictResolutionStrategy = ConflictResolutionStrategy.PRIORITY_FIRST_MATCH,
    ) -> None:
        self.strategy = strategy

    def resolve(self, candidates: list[CandidateDecision]) -> ResolutionResult:
        """Resolve a list of candidate decisions into a single winner."""
        if not candidates:
            raise ValueError("Cannot resolve conflict with zero candidates")
        if len(candidates) == 1:
            return ResolutionResult(
                winning_decision=candidates[0],
                strategy_used=self.strategy,
                candidates_evaluated=1,
                conflict_detected=False,
                resolution_trace=[
                    f"Single candidate: {candidates[0].rule_name} → {candidates[0].action}"
                ],
            )
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

    def _deny_overrides(
        self, candidates: list[CandidateDecision]
    ) -> tuple[CandidateDecision, list[str]]:
        trace: list[str] = []
        denies = [c for c in candidates if c.is_deny]
        if denies:
            denies.sort(key=lambda c: c.priority, reverse=True)
            winner = denies[0]
            trace.append(f"DENY_OVERRIDES: {len(denies)} deny rule(s) found")
            trace.append(
                f"Winner: {winner.rule_name} "
                f"(priority={winner.priority}, scope={winner.scope.value})"
            )
            return winner, trace
        candidates_sorted = sorted(candidates, key=lambda c: c.priority, reverse=True)
        winner = candidates_sorted[0]
        trace.append("DENY_OVERRIDES: no deny rules, selecting highest-priority allow")
        trace.append(f"Winner: {winner.rule_name} (priority={winner.priority})")
        return winner, trace

    def _allow_overrides(
        self, candidates: list[CandidateDecision]
    ) -> tuple[CandidateDecision, list[str]]:
        trace: list[str] = []
        allows = [c for c in candidates if c.is_allow]
        if allows:
            allows.sort(key=lambda c: c.priority, reverse=True)
            winner = allows[0]
            trace.append(f"ALLOW_OVERRIDES: {len(allows)} allow rule(s) found")
            trace.append(
                f"Winner: {winner.rule_name} "
                f"(priority={winner.priority}, scope={winner.scope.value})"
            )
            return winner, trace
        candidates_sorted = sorted(candidates, key=lambda c: c.priority, reverse=True)
        winner = candidates_sorted[0]
        trace.append("ALLOW_OVERRIDES: no allow rules, selecting highest-priority deny")
        trace.append(f"Winner: {winner.rule_name} (priority={winner.priority})")
        return winner, trace

    def _priority_first_match(
        self, candidates: list[CandidateDecision]
    ) -> tuple[CandidateDecision, list[str]]:
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
        sorted_candidates = sorted(
            candidates,
            key=lambda c: (c.specificity, c.priority),
            reverse=True,
        )
        winner = sorted_candidates[0]
        trace = [
            f"MOST_SPECIFIC_WINS: {len(candidates)} candidates",
            f"Specificity ranking: "
            f"{[(c.rule_name, c.scope.value, c.specificity) for c in sorted_candidates]}",
            f"Winner: {winner.rule_name} "
            f"(scope={winner.scope.value}, priority={winner.priority}, action={winner.action})",
        ]
        return winner, trace


__all__ = [
    "ConflictResolutionStrategy",
    "PolicyScope",
    "CandidateDecision",
    "ResolutionResult",
    "PolicyConflictResolver",
]
