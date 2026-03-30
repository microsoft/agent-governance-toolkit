# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Ring Elevation — privilege escalation stubs.

Public Preview: elevation is not supported. All requests are denied.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

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


_RING_LABELS: dict[ExecutionRing, str] = {
    ExecutionRing.RING_0_ROOT: "Ring 0 (Root)",
    ExecutionRing.RING_1_PRIVILEGED: "Ring 1 (Privileged)",
    ExecutionRing.RING_2_STANDARD: "Ring 2 (Standard)",
    ExecutionRing.RING_3_SANDBOX: "Ring 3 (Sandbox)",
}

_DOCS_URL = "https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/rings.md"


@dataclass
class RingElevation:
    """A ring elevation grant (stub in Public Preview)."""

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
        return True

    @property
    def remaining_seconds(self) -> float:
        return 0.0


class RingElevationManager:
    """Manages ring elevations (Public Preview: always denies)."""

    MAX_ELEVATION_TTL = 3600
    DEFAULT_TTL = 300

    def __init__(self) -> None:
        self._elevations: dict[str, RingElevation] = {}

    def request_elevation(
        self,
        agent_did: str,
        session_id: str,
        current_ring: ExecutionRing,
        target_ring: ExecutionRing,
        ttl_seconds: int = 0,
        attestation: str | None = None,
        reason: str = "",
    ) -> RingElevation:
        """Request temporary ring elevation (Public Preview: always denied)."""
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

        # Public Preview: all valid requests are denied
        denial = ElevationDenialReason.COMMUNITY_EDITION
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

    def get_active_elevation(self, agent_did: str, session_id: str) -> RingElevation | None:
        return None

    def get_effective_ring(self, agent_did: str, session_id: str, base_ring: ExecutionRing) -> ExecutionRing:
        return base_ring

    def revoke_elevation(self, elevation_id: str) -> None:
        raise RingElevationError(f"Elevation {elevation_id} not found")

    def tick(self) -> list[RingElevation]:
        return []

    def register_child(self, parent_did: str, child_did: str, parent_ring: ExecutionRing) -> ExecutionRing:
        child_ring_value = min(parent_ring.value + 1, ExecutionRing.RING_3_SANDBOX.value)
        return ExecutionRing(child_ring_value)

    @property
    def active_elevations(self) -> list[RingElevation]:
        return []


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
