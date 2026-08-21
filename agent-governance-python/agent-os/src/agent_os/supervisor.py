# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Layered supervision with a deterministic trust root.

Level zero must be deterministic. Higher levels may use agent supervisors, and
escalation always terminates at the trust root.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_os.trust_root import TrustDecision, TrustRoot

# An integer level exceeding this bound is rejected at registration.
# Real supervision hierarchies rarely exceed single digits; 1 000 is generous
# enough to never constrain legitimate use. Without this, Python's unbounded
# integers allow a pathologically large level (e.g. ``10**100``) that makes
# ``validate_hierarchy`` hang if it ever tries to iterate the numeric range.
MAX_SUPERVISOR_LEVEL = 1_000


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

        Raises:
            ValueError: If *level* exceeds ``MAX_SUPERVISOR_LEVEL``.  Python
                ints are unbounded, so without a check a pathologically large
                level (e.g. ``10**100``) makes ``validate_hierarchy`` hang —
                even after the gap scan itself is safe, the sorted set of
                levels is meaningless when the level is not a realistic
                hierarchy position.
        """
        if level > MAX_SUPERVISOR_LEVEL:
            raise ValueError(
                f"Supervisor '{name}' has level {level}, which exceeds the "
                f"maximum allowed level ({MAX_SUPERVISOR_LEVEL})"
            )
        self._supervisors.append(_Supervisor(name=name, level=level, is_agent=is_agent))

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_hierarchy(self) -> list[str]:
        """Check hierarchy rules and return a list of violations (empty = valid).

        Rules:
        - No supervisor may sit above the root: levels MUST NOT be negative.
        - Level 0 MUST exist and MUST be deterministic (not an LLM agent).
        - Middle levels (1–N) may be agent-based.
        - Each level present must have at least one supervisor.
        """
        violations: list[str] = []

        # Checked before anything else: level 0 is the root, so a negative level
        # places a supervisor *above* the deterministic authority. The
        # determinism rule below only inspects supervisors whose level is exactly
        # 0, and the gap scan only walks ``range(1, max_level + 1)``, so a
        # negative level was invisible to both — an agent registered at level -1
        # produced no violations at all while ranking ahead of the trust root in
        # ``get_authority_chain``.
        for s in self._supervisors:
            if s.level < 0:
                violations.append(
                    f"Supervisor '{s.name}' has negative level {s.level}; level 0 is the "
                    "root and nothing may sit above it"
                )

        level_0 = [s for s in self._supervisors if s.level == 0]
        if not level_0:
            violations.append("Level 0 (root) has no registered supervisor")
        else:
            for s in level_0:
                if s.is_agent:
                    violations.append(
                        f"Level 0 supervisor '{s.name}' must be deterministic, not an LLM agent"
                    )

        # Ensure no gaps in levels (every level between 0 and max has a supervisor).
        #
        # The previous implementation iterated ``range(1, max_level + 1)``, which is
        # O(max_level) — proportional to the *numeric value* of the highest level, not
        # to the number of supervisors. A pathologically large level (e.g. ``10**100``,
        # legal since Python ints are unbounded) made this loop hang. The sorted-set
        # approach below is O(n log n) in the number of registered supervisors: it
        # sorts the unique non-negative levels and walks adjacent pairs to find gaps,
        # regardless of how large the numeric values are.
        if self._supervisors:
            occupied = sorted({s.level for s in self._supervisors if s.level >= 0})
            for i in range(1, len(occupied)):
                gap_start = occupied[i - 1] + 1
                gap_end = occupied[i]
                for lvl in range(gap_start, gap_end):
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
