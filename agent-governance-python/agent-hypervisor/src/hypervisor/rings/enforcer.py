# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Ring Enforcer — resource-constrained ring-based access control.

Maps execution rings to concrete resource constraints (network, filesystem,
subprocess) and enforces both ring-level access and resource-level restrictions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from hypervisor.constants import RING_1_ENFORCER_THRESHOLD
from hypervisor.models import ActionDescriptor, ExecutionRing


class ResourceType(str, Enum):
    """Types of resources that rings constrain."""

    NETWORK = "network"
    FILESYSTEM = "filesystem"
    SUBPROCESS = "subprocess"
    TOOL_EXECUTION = "tool_execution"


@dataclass
class ResourceConstraints:
    """Resource constraints for an execution ring.

    Defines what an agent at a given ring level is allowed to do.
    """

    network_allowed: bool = False
    network_allowlist: list[str] = field(default_factory=list)
    filesystem_writable: bool = False
    filesystem_scope: str = "none"  # none, session, scoped, full
    subprocess_allowed: bool = False
    max_concurrent_tools: int = 1

    def allows_resource(self, resource_type: ResourceType) -> bool:
        """Check if this constraint set allows the given resource type."""
        if resource_type == ResourceType.NETWORK:
            return self.network_allowed
        elif resource_type == ResourceType.FILESYSTEM:
            return self.filesystem_scope != "none"
        elif resource_type == ResourceType.SUBPROCESS:
            return self.subprocess_allowed
        elif resource_type == ResourceType.TOOL_EXECUTION:
            return True
        return False


# Ring-to-resource constraint mapping
RING_CONSTRAINTS: dict[ExecutionRing, ResourceConstraints] = {
    ExecutionRing.RING_0_ROOT: ResourceConstraints(
        network_allowed=True,
        filesystem_writable=True,
        filesystem_scope="full",
        subprocess_allowed=True,
        max_concurrent_tools=32,
    ),
    ExecutionRing.RING_1_PRIVILEGED: ResourceConstraints(
        network_allowed=True,
        filesystem_writable=True,
        filesystem_scope="full",
        subprocess_allowed=True,
        max_concurrent_tools=16,
    ),
    ExecutionRing.RING_2_STANDARD: ResourceConstraints(
        network_allowed=True,
        network_allowlist=[],  # empty = all allowed at this ring
        filesystem_writable=True,
        filesystem_scope="scoped",
        subprocess_allowed=True,
        max_concurrent_tools=8,
    ),
    ExecutionRing.RING_3_SANDBOX: ResourceConstraints(
        network_allowed=False,
        filesystem_writable=False,
        filesystem_scope="none",
        subprocess_allowed=False,
        max_concurrent_tools=2,
    ),
}


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
    denied_resources: list[ResourceType] = field(default_factory=list)


class RingEnforcer:
    """Ring enforcer with resource constraint validation.

    Ring 0 (Root): Always denied for agents (system-only).
    Ring 1 (Privileged): Full network, full filesystem, subprocess allowed.
    Ring 2 (Standard): Allowlisted network, scoped filesystem, subprocess allowed.
    Ring 3 (Sandbox): No network, read-only filesystem, no subprocess.
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
        """Check if an agent can perform an action given their ring level.

        Validates both ring-level access and resource constraints.
        """
        required = action.required_ring

        # Ring 0: always denied for agents
        if required == ExecutionRing.RING_0_ROOT:
            return RingCheckResult(
                allowed=False,
                required_ring=required,
                agent_ring=agent_ring,
                eff_score=eff_score,
                reason="Ring 0 actions require SRE Witness attestation",
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

    def check_resource(
        self,
        agent_ring: ExecutionRing,
        resource_type: ResourceType,
    ) -> RingCheckResult:
        """Check if an agent's ring allows access to a specific resource type.

        Args:
            agent_ring: The agent's current execution ring.
            resource_type: The resource type being requested.

        Returns:
            RingCheckResult indicating whether access is allowed.
        """
        constraints = self.get_constraints(agent_ring)

        if constraints.allows_resource(resource_type):
            return RingCheckResult(
                allowed=True,
                required_ring=agent_ring,
                agent_ring=agent_ring,
                eff_score=0.0,
                reason=f"{resource_type.value} access granted for ring {agent_ring.value}",
            )

        return RingCheckResult(
            allowed=False,
            required_ring=agent_ring,
            agent_ring=agent_ring,
            eff_score=0.0,
            reason=f"{resource_type.value} access denied at ring {agent_ring.value}",
            denied_resources=[resource_type],
        )

    def get_constraints(self, ring: ExecutionRing) -> ResourceConstraints:
        """Get the resource constraints for a given ring.

        Args:
            ring: The execution ring.

        Returns:
            ResourceConstraints for the ring.
        """
        return RING_CONSTRAINTS.get(ring, RING_CONSTRAINTS[ExecutionRing.RING_3_SANDBOX])

    def compute_ring(self, eff_score: float, has_consensus: bool = False) -> ExecutionRing:
        """Compute ring assignment from trust score."""
        return ExecutionRing.from_eff_score(eff_score, has_consensus)

    def should_demote(self, current_ring: ExecutionRing, eff_score: float) -> bool:
        """Check if an agent should be demoted based on trust drop."""
        appropriate = self.compute_ring(eff_score)
        return appropriate.value > current_ring.value
