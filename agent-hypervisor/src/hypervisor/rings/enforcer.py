# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Ring Enforcer — simple 2-tier access control.

Public Preview: agents get RING_1 (trust > 0.7) or RING_2 (default).
Ring 0 is reserved for kernel-only operations and always denied.
"""

from __future__ import annotations

from dataclasses import dataclass

from hypervisor.constants import RING_1_ENFORCER_THRESHOLD
from hypervisor.models import ActionDescriptor, ExecutionRing


@dataclass
class RingCheckResult:
    """Result of a ring enforcement check."""

    allowed: bool
    required_ring: ExecutionRing
    agent_ring: ExecutionRing
    eff_score: float
    reason: str
    requires_consensus: bool = False
    requires_sre_witness: bool = False


class RingEnforcer:
    """
    Simple 2-tier ring enforcer.

    Ring 0 (Root): Always denied (kernel-only).
    Ring 1 (Privileged): Requires trust > 0.7.
    Ring 2 (Standard): Default for all agents.
    Ring 3 (Sandbox): Read-only / research.
    """

    RING_1_THRESHOLD = RING_1_ENFORCER_THRESHOLD

    def __init__(self) -> None:
        pass

    def check(
        self,
        agent_ring: ExecutionRing,
        action: ActionDescriptor,
        eff_score: float,
        has_consensus: bool = False,
        has_sre_witness: bool = False,
    ) -> RingCheckResult:
        """Check if an agent can perform an action given their ring level."""
        required = action.required_ring

        # Ring 0: always denied in Public Preview
        if required == ExecutionRing.RING_0_ROOT:
            return RingCheckResult(
                allowed=False,
                required_ring=required,
                agent_ring=agent_ring,
                eff_score=eff_score,
                reason="Ring 0 actions are not available in Public Preview",
                requires_sre_witness=True,
            )

        # Agent's ring must be <= required ring (lower number = more privileged)
        if agent_ring.value > required.value:
            return RingCheckResult(
                allowed=False,
                required_ring=required,
                agent_ring=agent_ring,
                eff_score=eff_score,
                reason=(
                    f"Agent ring {agent_ring.value} insufficient for "
                    f"required ring {required.value}"
                ),
            )

        return RingCheckResult(
            allowed=True,
            required_ring=required,
            agent_ring=agent_ring,
            eff_score=eff_score,
            reason="Access granted",
        )

    def compute_ring(self, eff_score: float, has_consensus: bool = False) -> ExecutionRing:
        """Compute ring assignment from trust score."""
        return ExecutionRing.from_eff_score(eff_score, has_consensus)

    def should_demote(self, current_ring: ExecutionRing, eff_score: float) -> bool:
        """Check if an agent should be demoted based on trust drop."""
        appropriate = self.compute_ring(eff_score)
        return appropriate.value > current_ring.value
