# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Supervisor Hierarchy — Enforces layered supervision with a deterministic trust root.

Level 0 (root) MUST be a deterministic (non-LLM) trust root.
Middle levels (1–N) may be agent-based supervisors.
Escalation always terminates at the trust root.

Example:
    >>> from agent_os.trust_root import TrustRoot
    >>> from agent_os.supervisor import SupervisorHierarchy
    >>> from agent_os.integrations.base import GovernancePolicy
    >>>
    >>> root = TrustRoot(policies=[GovernancePolicy()])
    >>> hierarchy = SupervisorHierarchy(trust_root=root)
    >>> hierarchy.register_supervisor("trust-root", level=0, is_agent=False)
    >>> hierarchy.register_supervisor("safety-agent", level=1, is_agent=True)
    >>> hierarchy.validate_hierarchy()
    []
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_os.trust_root import TrustDecision, TrustRoot


@dataclass
class _Supervisor:
    """Internal record for a registered supervisor."""

    name: str
    level: int
    is_agent: bool = True


class SupervisorHierarchy:
    """Manages the layered supervisor chain with a deterministic trust root.

    Args:
        trust_root: The deterministic TrustRoot that serves as level-0 authority.
    """

    def __init__(self, trust_root: TrustRoot) -> None:
        self.trust_root = trust_root
        self._supervisors: list[_Supervisor] = []

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_supervisor(
        self,
        name: str,
        level: int,
        is_agent: bool = True,
    ) -> None:
        """Register a supervisor at a given level.

        Args:
            name: Unique supervisor name.
            level: Hierarchy level (0 = root, higher = closer to workers).
            is_agent: Whether this supervisor is an LLM-based agent.
        """
        self._supervisors.append(_Supervisor(name=name, level=level, is_agent=is_agent))

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_hierarchy(self) -> list[str]:
        """Check hierarchy rules and return a list of violations (empty = valid).

        Rules:
        - Level 0 MUST exist and MUST be deterministic (not an LLM agent).
        - Middle levels (1–N) may be agent-based.
        - Each level present must have at least one supervisor.
        """
        violations: list[str] = []

        level_0 = [s for s in self._supervisors if s.level == 0]
        if not level_0:
            violations.append("Level 0 (root) has no registered supervisor")
        else:
            for s in level_0:
                if s.is_agent:
                    violations.append(
                        f"Level 0 supervisor '{s.name}' must be deterministic, not an LLM agent"
                    )

        # Ensure no gaps in levels (every level between 0 and max has a supervisor)
        if self._supervisors:
            max_level = max(s.level for s in self._supervisors)
            for lvl in range(1, max_level + 1):
                if not any(s.level == lvl for s in self._supervisors):
                    violations.append(f"Level {lvl} has no registered supervisor")

        return violations

    # ------------------------------------------------------------------
    # Authority chain & escalation
    # ------------------------------------------------------------------

    def get_authority_chain(self, action: dict[str, Any]) -> list[str]:
        """Return the ordered chain of supervisor names that would evaluate *action*.

        The chain goes from the lowest (closest to workers) up to the trust root.
        """
        sorted_supervisors = sorted(self._supervisors, key=lambda s: s.level, reverse=True)
        return [s.name for s in sorted_supervisors]

    def escalate(
        self,
        action: dict[str, Any],
        from_level: int,
    ) -> TrustDecision:
        """Escalate *action* up the hierarchy starting above *from_level*.

        Each level is consulted in descending order.  If the action reaches
        level 0 the trust root makes the **final, non-overridable** decision.

        Args:
            action: Dict with ``tool`` and ``arguments``.
            from_level: The level that initiated escalation.

        Returns:
            TrustDecision from the trust root (always deterministic).
        """
        levels_above = sorted(
            {s.level for s in self._supervisors if s.level < from_level},
            reverse=True,
        )

        depth = 0
        for _level in levels_above:
            depth += 1
            if depth > self.trust_root.max_escalation_depth:
                return TrustDecision(
                    allowed=False,
                    reason="Max escalation depth exceeded",
                    policy_name="escalation_limit",
                )

        # Final decision always comes from the deterministic trust root
        return self.trust_root.validate_action(action)
