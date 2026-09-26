# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Layered supervision with a deterministic trust root.

Level zero must be deterministic. Higher levels may use agent supervisors, and
escalation always terminates at the trust root.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_os._supervisor_constants import MAX_SUPERVISOR_LEVEL
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

        Raises:
            TypeError: If ``level`` is not an integer or is a boolean.
            ValueError: If ``level`` is negative, exceeds ``MAX_SUPERVISOR_LEVEL``,
                or an agent is registered at level 0.
        """
        if isinstance(level, bool) or not isinstance(level, int):
            raise TypeError(f"Supervisor level must be an int, got {level!r}")
        if level < 0:
            raise ValueError("Supervisor level must be non-negative; level 0 is the root")
        if level == 0 and is_agent:
            raise ValueError("Level 0 supervisor must be deterministic, not an LLM agent")
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
        - Supervisor levels must be integers (``bool`` is not accepted as a level).
        - No supervisor may sit above the root: levels MUST NOT be negative.
        - Level 0 MUST exist and MUST be deterministic (not an LLM agent).
        - Middle levels (1–N) may be agent-based.
        - Each level present must have at least one supervisor.
        """
        violations: list[str] = []

        valid_supervisors: list[_Supervisor] = []
        for s in self._supervisors:
            if not isinstance(s.level, int) or isinstance(s.level, bool):
                violations.append(
                    f"Supervisor '{s.name}' has non-integer level {s.level!r}; "
                    "levels must be integers"
                )
                continue
            valid_supervisors.append(s)

        # Checked before anything else: level 0 is the root, so a negative level
        # places a supervisor *above* the deterministic authority. The
        # determinism rule below only inspects supervisors whose level is exactly
        # 0, and the gap scan only walks ``range(1, max_level + 1)``, so a
        # negative level was invisible to both — an agent registered at level -1
        # produced no violations at all while ranking ahead of the trust root in
        # ``get_authority_chain``.
        for s in valid_supervisors:
            if s.level < 0:
                violations.append(
                    f"Supervisor '{s.name}' has negative level {s.level}; level 0 is the "
                    "root and nothing may sit above it"
                )

        level_0 = [s for s in valid_supervisors if s.level == 0]
        if not level_0:
            violations.append("Level 0 (root) has no registered supervisor")
        else:
            for s in level_0:
                if s.is_agent:
                    violations.append(
                        f"Level 0 supervisor '{s.name}' must be deterministic, not an LLM agent"
                    )

        # Sorting costs O(n log n); reporting each missing level also costs O(g),
        # where g is the number of gaps. Registration bounds the highest level.
        if valid_supervisors:
            occupied = sorted({s.level for s in valid_supervisors if s.level >= 0})
            # Anchor at 0 so gaps below the minimum occupied level are reported
            # (e.g. levels=[3] must report 1 and 2 missing, not nothing).
            anchored = [0, *occupied] if occupied and occupied[0] != 0 else occupied
            for i in range(1, len(anchored)):
                gap_start = anchored[i - 1] + 1
                gap_end = anchored[i]
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
                    authority="supervisor",
                )

        # Below the escalation-depth cap, the final decision comes from the
        # deterministic trust root
        return self.trust_root.validate_action(action)
