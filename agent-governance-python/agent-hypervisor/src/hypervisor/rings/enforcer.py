# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Ring Enforcer — resource-constrained ring-based access control.

Maps execution rings to concrete resource constraints (network, filesystem,
subprocess) and enforces both ring-level access and resource-level restrictions.

Also provides command denylist enforcement for subprocess execution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from hypervisor.constants import RING_1_ENFORCER_THRESHOLD
from hypervisor.models import ActionDescriptor, ExecutionRing
from hypervisor.sandbox import DENIED_COMMANDS


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

# A redirection operator (with an optional fd number at the start of a word, "&>",
# ">&", ">|" or "<<<") and the shell word that is its target. The target keeps
# quoted parts ("...", '...', $'...', $"...") and backslash escapes together with
# the plain characters around them, so a quoted or escaped space stays inside it.
# An unterminated quote runs to the end of the command.
_REDIRECTION = re.compile(
    r"(?:(?<![^\s;&|()`])\d+|&)?[<>]+[&|]?\s*"
    r"(?P<target>(?:"
    r"\$'(?:[^'\\]|\\.)*'?"
    r'|\$?"(?:[^"\\]|\\.)*"?'
    r"|'[^']*'?"
    r"|\\.?"
    r"|[^\s;&|<>()`'\"\\]"
    r")*)",
    re.DOTALL,
)


def _remove_quoting(text: str) -> str:
    """Remove the quotes and backslashes the shell drops before running a command.

    e.g., "'curl'" -> "curl", "c\\url" -> "curl", "$'curl'" -> "curl"
    """
    return re.sub(r"[\"'\\]", "", re.sub(r"\$(?=[\"'])", "", text))


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


@dataclass
class CommandCheckResult:
    """Result of a command denylist check.

    Attributes:
        allowed: Whether the command is allowed (not in denylist).
        reason: Human-readable explanation of the decision.
        command: The command that was checked (base command name, without args).
        matched_denylist_entry: The denylist entry that matched, if denied.
    """

    allowed: bool
    reason: str
    command: str
    matched_denylist_entry: str | None = None


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
                    f"Agent ring {agent_ring.value} insufficient for required ring {required.value}"
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

    def check_command(self, command: str | None) -> CommandCheckResult:
        """Check if a command is allowed by the denylist.

        This method validates whether a command (or command string with arguments)
        is present in the global DENIED_COMMANDS list. The check is performed
        against the base command name (the first command the shell would run).
        Matching is case-insensitive to prevent bypasses via case variation.

        Args:
            command: The command to check (e.g., "curl", "curl -X POST", "python3").
                     Can be None or empty string.

        Returns:
            CommandCheckResult with allowed status, reason, and the base command name.
        """
        if not command:
            return CommandCheckResult(
                allowed=False,
                reason="Empty or None command is not allowed",
                command="",
                matched_denylist_entry=None,
            )

        stripped = command.strip()
        if not stripped:
            return CommandCheckResult(
                allowed=False,
                reason="Command contains no executable name",
                command="",
                matched_denylist_entry=None,
            )

        # Drop redirections with their targets, which the shell applies before running
        # the command, so a target is never taken for the executable. This runs before
        # the quotes are removed, so a quoted or escaped space stays in the target
        # e.g., ">out curl" -> "curl", "2>&1 curl" -> "curl", '>"my file" curl' -> "curl"
        targets = [match.group("target") for match in _REDIRECTION.finditer(stripped)]
        normalized = _REDIRECTION.sub(" ", stripped)

        # Remove shell quoting and escapes, which the shell drops before running
        # the command, e.g., "'curl'" -> "curl", "c\url" -> "curl", "$'curl'" -> "curl"
        normalized = _remove_quoting(normalized)

        # Split at whitespace, control operators, redirections, subshells and command
        # substitution so the first command the shell runs is checked
        # e.g., "curl;" -> "curl", "|curl" -> "curl", "curl>out" -> "curl", "$(curl x)" -> "curl"
        tokens = [token for token in re.split(r"[\s;&|<>()`]+", normalized) if token]

        # A redirection to an empty file name ('>"" curl') fails in the shell and
        # the command never runs, so treat it as having no executable name
        if any(target and not _remove_quoting(target) for target in targets):
            tokens = []

        # Skip words that open a group or negate the command that follows them,
        # and the "$" left over from "$(", e.g., "{ curl; }" -> "curl", "! curl" -> "curl"
        while tokens and tokens[0] in ("{", "!", "$"):
            tokens.pop(0)
        base_command = tokens[0] if tokens else ""

        # Match the executable name rather than the path used to invoke it
        # e.g., "/usr/bin/curl" -> "curl", "./bash" -> "bash"
        base_command = base_command.rsplit("/", 1)[-1]

        if not base_command:
            return CommandCheckResult(
                allowed=False,
                reason="Command contains no executable name",
                command="",
                matched_denylist_entry=None,
            )

        base_command_lower = base_command.lower()

        # Check against denylist (case-insensitive match)
        for denied_cmd in DENIED_COMMANDS:
            if base_command_lower == denied_cmd.lower():
                return CommandCheckResult(
                    allowed=False,
                    reason=f"Command '{base_command}' is denied by sandbox policy",
                    command=base_command,
                    matched_denylist_entry=denied_cmd,
                )

        return CommandCheckResult(
            allowed=True,
            reason=f"Command '{base_command}' is allowed",
            command=base_command,
            matched_denylist_entry=None,
        )
