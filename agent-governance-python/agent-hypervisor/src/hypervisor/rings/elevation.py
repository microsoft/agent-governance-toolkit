# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Ring Elevation — time-bounded privilege escalation with policy enforcement.

Agents can request temporary elevation to a higher-privilege ring.
Elevations are granted based on trust score thresholds, require attestation
for sensitive rings, and automatically expire via tick().
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Callable, Optional

from hypervisor.models import ExecutionRing


class RingElevationError(Exception):
    """Raised for invalid ring elevation requests."""

    def __init__(
        self,
        message: str,
        *,
        current_ring: ExecutionRing | None = None,
        target_ring: ExecutionRing | None = None,
        reason: str | None = None,
        agent_did: str = "",
    ) -> None:
        super().__init__(message)
        self.current_ring = current_ring
        self.target_ring = target_ring
        self.denial_reason = reason
        self.agent_did = agent_did


class ElevationDenialReason:
    """Standard denial reasons for ring elevation failures."""

    COMMUNITY_EDITION = "community_edition"
    INVALID_TARGET = "invalid_target"
    RING_0_FORBIDDEN = "ring_0_forbidden"
    INSUFFICIENT_TRUST = "insufficient_trust"
    NO_SPONSORSHIP = "no_sponsorship"
    EXPIRED_TTL = "expired_ttl"
    DUPLICATE = "duplicate_elevation"


_RING_LABELS: dict[ExecutionRing, str] = {
    ExecutionRing.RING_0_ROOT: "Ring 0 (Root)",
    ExecutionRing.RING_1_PRIVILEGED: "Ring 1 (Privileged)",
    ExecutionRing.RING_2_STANDARD: "Ring 2 (Standard)",
    ExecutionRing.RING_3_SANDBOX: "Ring 3 (Sandbox)",
}

_DOCS_URL = "https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/rings.md"

# Trust score thresholds for elevation approval
ELEVATION_TRUST_THRESHOLDS: dict[ExecutionRing, float] = {
    ExecutionRing.RING_1_PRIVILEGED: 0.85,
    ExecutionRing.RING_2_STANDARD: 0.50,
}


@dataclass
class RingElevation:
    """A time-bounded ring elevation grant."""

    elevation_id: str = field(default_factory=lambda: f"elev:{uuid.uuid4().hex[:8]}")
    agent_did: str = ""
    session_id: str = ""
    original_ring: ExecutionRing = ExecutionRing.RING_3_SANDBOX
    elevated_ring: ExecutionRing = ExecutionRing.RING_2_STANDARD
    granted_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    attestation: str | None = None
    reason: str = ""
    is_active: bool = True

    @property
    def is_expired(self) -> bool:
        return datetime.now(UTC) >= self.expires_at

    @property
    def remaining_seconds(self) -> float:
        remaining = (self.expires_at - datetime.now(UTC)).total_seconds()
        return max(0.0, remaining)


@dataclass
class ChildRegistration:
    """Tracks a parent-child ring relationship."""

    parent_did: str
    child_did: str
    parent_ring: ExecutionRing
    child_ring: ExecutionRing
    registered_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class RingElevationManager:
    """Manages time-bounded ring elevations with policy enforcement.

    Elevation requests are evaluated against trust score thresholds.
    Ring 1 requires attestation. Ring 0 is always forbidden via standard API.
    Active elevations expire based on TTL and are cleaned up by tick().
    """

    MAX_ELEVATION_TTL = 3600
    DEFAULT_TTL = 300

    def __init__(
        self,
        trust_provider: Optional[Callable[[str], float]] = None,
    ) -> None:
        """Initialize the elevation manager.

        Args:
            trust_provider: Callable that returns trust score (0.0-1.0)
                for a given agent DID. If None, elevation requires explicit
                trust_score parameter.
        """
        self._elevations: dict[str, RingElevation] = {}
        self._children: dict[str, ChildRegistration] = {}
        self._trust_provider = trust_provider

    def request_elevation(
        self,
        agent_did: str,
        session_id: str,
        current_ring: ExecutionRing,
        target_ring: ExecutionRing,
        ttl_seconds: int = 0,
        attestation: str | None = None,
        reason: str = "",
        trust_score: Optional[float] = None,
    ) -> RingElevation:
        """Request temporary ring elevation.

        Elevation is granted if the agent's trust score meets the threshold
        for the target ring. Ring 1 additionally requires an attestation string.

        Args:
            agent_did: DID of the requesting agent.
            session_id: Current session identifier.
            current_ring: Agent's current execution ring.
            target_ring: Requested elevated ring.
            ttl_seconds: Duration in seconds (0 = DEFAULT_TTL, capped at MAX).
            attestation: Required for Ring 1 elevation.
            reason: Human-readable justification.
            trust_score: Agent's trust score (0.0-1.0). If None, uses trust_provider.

        Returns:
            RingElevation grant if approved.

        Raises:
            RingElevationError: If elevation is denied.
        """
        # Validate: target must be a higher privilege (lower numeric value)
        if target_ring.value >= current_ring.value:
            denial = ElevationDenialReason.INVALID_TARGET
            raise RingElevationError(
                _build_elevation_error_message(
                    current_ring=current_ring,
                    target_ring=target_ring,
                    reason=denial,
                    agent_did=agent_did,
                ),
                current_ring=current_ring,
                target_ring=target_ring,
                reason=denial,
                agent_did=agent_did,
            )

        # Validate: Ring 0 cannot be requested via standard API
        if target_ring == ExecutionRing.RING_0_ROOT:
            denial = ElevationDenialReason.RING_0_FORBIDDEN
            raise RingElevationError(
                _build_elevation_error_message(
                    current_ring=current_ring,
                    target_ring=target_ring,
                    reason=denial,
                    agent_did=agent_did,
                ),
                current_ring=current_ring,
                target_ring=target_ring,
                reason=denial,
                agent_did=agent_did,
            )

        # Check for duplicate active elevation
        existing = self._find_active(agent_did, session_id)
        if existing is not None:
            denial = ElevationDenialReason.DUPLICATE
            raise RingElevationError(
                _build_elevation_error_message(
                    current_ring=current_ring,
                    target_ring=target_ring,
                    reason=denial,
                    agent_did=agent_did,
                ),
                current_ring=current_ring,
                target_ring=target_ring,
                reason=denial,
                agent_did=agent_did,
            )

        # Resolve trust score
        score = trust_score
        if score is None and self._trust_provider:
            score = self._trust_provider(agent_did)

        if score is None:
            denial = ElevationDenialReason.INSUFFICIENT_TRUST
            raise RingElevationError(
                _build_elevation_error_message(
                    current_ring=current_ring,
                    target_ring=target_ring,
                    reason=denial,
                    agent_did=agent_did,
                ),
                current_ring=current_ring,
                target_ring=target_ring,
                reason=denial,
                agent_did=agent_did,
            )

        # Check trust threshold
        threshold = ELEVATION_TRUST_THRESHOLDS.get(target_ring, 1.0)
        if score < threshold:
            denial = ElevationDenialReason.INSUFFICIENT_TRUST
            raise RingElevationError(
                _build_elevation_error_message(
                    current_ring=current_ring,
                    target_ring=target_ring,
                    reason=denial,
                    agent_did=agent_did,
                ),
                current_ring=current_ring,
                target_ring=target_ring,
                reason=denial,
                agent_did=agent_did,
            )

        # Ring 1 requires attestation
        if target_ring == ExecutionRing.RING_1_PRIVILEGED and not attestation:
            denial = ElevationDenialReason.NO_SPONSORSHIP
            raise RingElevationError(
                _build_elevation_error_message(
                    current_ring=current_ring,
                    target_ring=target_ring,
                    reason=denial,
                    agent_did=agent_did,
                ),
                current_ring=current_ring,
                target_ring=target_ring,
                reason=denial,
                agent_did=agent_did,
            )

        # Compute TTL
        ttl = ttl_seconds if ttl_seconds > 0 else self.DEFAULT_TTL
        ttl = min(ttl, self.MAX_ELEVATION_TTL)

        # Grant elevation
        now = datetime.now(UTC)
        elevation = RingElevation(
            agent_did=agent_did,
            session_id=session_id,
            original_ring=current_ring,
            elevated_ring=target_ring,
            granted_at=now,
            expires_at=now + timedelta(seconds=ttl),
            attestation=attestation,
            reason=reason,
            is_active=True,
        )
        self._elevations[elevation.elevation_id] = elevation
        return elevation

    def get_active_elevation(self, agent_did: str, session_id: str) -> RingElevation | None:
        """Get the active (non-expired) elevation for an agent in a session."""
        elev = self._find_active(agent_did, session_id)
        if elev and not elev.is_expired:
            return elev
        return None

    def get_effective_ring(
        self, agent_did: str, session_id: str, base_ring: ExecutionRing
    ) -> ExecutionRing:
        """Get the effective ring considering active elevations."""
        elev = self.get_active_elevation(agent_did, session_id)
        if elev:
            return elev.elevated_ring
        return base_ring

    def revoke_elevation(self, elevation_id: str) -> None:
        """Revoke an active elevation by ID.

        Raises:
            RingElevationError: If elevation not found or already inactive.
        """
        elev = self._elevations.get(elevation_id)
        if elev is None:
            raise RingElevationError(
                f"Elevation {elevation_id} not found",
                reason="not_found",
            )
        elev.is_active = False

    def tick(self) -> list[RingElevation]:
        """Expire all elevations past their TTL.

        Returns:
            List of elevations that were expired by this tick.
        """
        expired: list[RingElevation] = []
        for elev in self._elevations.values():
            if elev.is_active and elev.is_expired:
                elev.is_active = False
                expired.append(elev)
        return expired

    def register_child(
        self, parent_did: str, child_did: str, parent_ring: ExecutionRing
    ) -> ExecutionRing:
        """Register a child agent with ring <= parent ring.

        Child agents are assigned one ring level lower privilege than parent
        (higher numeric value), capped at Ring 3.

        Args:
            parent_did: DID of the parent agent.
            child_did: DID of the child agent.
            parent_ring: Parent's current execution ring.

        Returns:
            The assigned ring for the child.
        """
        child_ring_value = min(parent_ring.value + 1, ExecutionRing.RING_3_SANDBOX.value)
        child_ring = ExecutionRing(child_ring_value)

        self._children[child_did] = ChildRegistration(
            parent_did=parent_did,
            child_did=child_did,
            parent_ring=parent_ring,
            child_ring=child_ring,
        )
        return child_ring

    def get_child_registration(self, child_did: str) -> ChildRegistration | None:
        """Get the registration for a child agent."""
        return self._children.get(child_did)

    @property
    def active_elevations(self) -> list[RingElevation]:
        """All currently active (non-expired) elevations."""
        return [e for e in self._elevations.values() if e.is_active and not e.is_expired]

    def _find_active(self, agent_did: str, session_id: str) -> RingElevation | None:
        """Find an active elevation for an agent/session pair."""
        for elev in self._elevations.values():
            if (
                elev.agent_did == agent_did
                and elev.session_id == session_id
                and elev.is_active
                and not elev.is_expired
            ):
                return elev
        return None


_REMEDIATION: dict[str, str] = {
    ElevationDenialReason.COMMUNITY_EDITION: (
        "Upgrade to the Enterprise edition to enable ring elevation, "
        "or request access from your organization admin."
    ),
    ElevationDenialReason.INVALID_TARGET: (
        "Request a target ring with a lower numeric value (higher privilege) "
        "than the agent's current ring."
    ),
    ElevationDenialReason.RING_0_FORBIDDEN: (
        "Ring 0 requires SRE Witness attestation and cannot be requested "
        "via the standard elevation API. Contact your platform team."
    ),
    ElevationDenialReason.INSUFFICIENT_TRUST: (
        "Increase the agent's effective trust score above the required "
        "threshold by completing successful operations in the current ring."
    ),
    ElevationDenialReason.NO_SPONSORSHIP: (
        "Obtain a sponsorship from a Ring 1 or Ring 0 agent to vouch "
        "for this elevation request."
    ),
    ElevationDenialReason.EXPIRED_TTL: (
        "Submit a new elevation request with a valid TTL "
        f"(max {RingElevationManager.MAX_ELEVATION_TTL}s)."
    ),
}


def _build_elevation_error_message(
    *,
    current_ring: ExecutionRing,
    target_ring: ExecutionRing,
    reason: str,
    agent_did: str = "",
) -> str:
    """Build a structured, actionable error message for elevation failures."""
    current_label = _RING_LABELS.get(current_ring, str(current_ring))
    target_label = _RING_LABELS.get(target_ring, str(target_ring))
    remediation = _REMEDIATION.get(reason, "Review the elevation requirements.")

    parts = [
        f"Ring elevation denied: {current_label} -> {target_label}",
    ]
    if agent_did:
        parts.append(f"  Agent: {agent_did}")
    parts.append(f"  Reason: {reason}")
    parts.append(f"  Remediation: {remediation}")
    parts.append(f"  Docs: {_DOCS_URL}")
    return "\n".join(parts)
