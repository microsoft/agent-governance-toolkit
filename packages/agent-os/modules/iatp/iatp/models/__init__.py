# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Core data models for the Inter-Agent Trust Protocol (IATP).

This module defines the Pydantic models used for capability manifests,
trust negotiation, and policy enforcement. These models form the
foundation of the IATP protocol.

Classes:
    TrustLevel: Enumeration of agent trust levels.
    ReversibilityLevel: Enumeration of transaction reversibility support.
    RetentionPolicy: Enumeration of data retention policies.
    PrivacyContract: Privacy and data handling policies.
    AgentCapabilities: Capabilities advertised by an agent.
    CapabilityManifest: The complete manifest exchanged during handshake.
    QuarantineSession: Session info for quarantined requests.
    TracingContext: Distributed tracing context.

Example:
    Creating a capability manifest::

        from iatp.models import (
            CapabilityManifest,
            AgentCapabilities,
            PrivacyContract,
            TrustLevel,
            ReversibilityLevel,
            RetentionPolicy,
        )

        manifest = CapabilityManifest(
            agent_id="my-agent",
            trust_level=TrustLevel.TRUSTED,
            capabilities=AgentCapabilities(
                reversibility=ReversibilityLevel.FULL,
                idempotency=True,
            ),
            privacy_contract=PrivacyContract(
                retention=RetentionPolicy.EPHEMERAL,
            ),
        )

        print(f"Trust Score: {manifest.calculate_trust_score()}/10")
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

__all__ = [
    "TrustLevel",
    "ReversibilityLevel",
    "RetentionPolicy",
    "PrivacyContract",
    "AgentCapabilities",
    "CapabilityManifest",
    "QuarantineSession",
    "TracingContext",
    "AttestationRecord",
    "ReputationScore",
    "ReputationEvent",
]


class TrustLevel(str, Enum):
    """Trust levels for agents."""
    VERIFIED_PARTNER = "verified_partner"
    TRUSTED = "trusted"
    STANDARD = "standard"
    UNKNOWN = "unknown"
    UNTRUSTED = "untrusted"


class ReversibilityLevel(str, Enum):
    """Reversibility support levels."""
    FULL = "full"  # Full rollback support
    PARTIAL = "partial"  # Limited rollback (e.g., with fees)
    NONE = "none"  # No rollback support


class RetentionPolicy(str, Enum):
    """Data retention policies."""
    EPHEMERAL = "ephemeral"  # Data deleted after session
    TEMPORARY = "temporary"  # Data stored temporarily (e.g., 30 days)
    PERMANENT = "permanent"  # Data stored indefinitely
    FOREVER = "forever"  # Alias for permanent (for compatibility)


class PrivacyContract(BaseModel):
    """Privacy contract specifying data handling policies."""
    retention: RetentionPolicy = Field(
        ...,
        description="How long the agent stores data"
    )
    storage_location: Optional[str] = Field(
        None,
        description="Geographic location of data storage (e.g., 'us-west')"
    )
    human_review: bool = Field(
        False,
        description="Whether humans may review the data"
    )
    encryption_at_rest: bool = Field(
        True,
        description="Whether data is encrypted at rest"
    )
    encryption_in_transit: bool = Field(
        True,
        description="Whether data is encrypted in transit"
    )


class AgentCapabilities(BaseModel):
    """Capabilities advertised by an agent."""
    idempotency: bool = Field(
        False,
        description="Whether duplicate requests are handled safely"
    )
    reversibility: ReversibilityLevel = Field(
        ReversibilityLevel.NONE,
        description="Level of transaction reversibility support"
    )
    undo_window: Optional[str] = Field(
        None,
        description="Time window for undo operations (e.g., '24h', '7d')"
    )
    sla_latency: Optional[str] = Field(
        None,
        description="Promised response latency (e.g., '2000ms', '5s')"
    )
    rate_limit: Optional[int] = Field(
        None,
        description="Maximum requests per minute"
    )


class CapabilityManifest(BaseModel):
    """
    Capability manifest exchanged during handshake.
    This is the core metadata that agents exchange.
    """
    agent_id: str = Field(
        ...,
        description="Unique identifier for the agent"
    )
    agent_version: Optional[str] = Field(
        None,
        description="Version of the agent"
    )
    trust_level: TrustLevel = Field(
        TrustLevel.STANDARD,
        description="Trust level of the agent"
    )
    capabilities: AgentCapabilities = Field(
        ...,
        description="Capabilities supported by the agent"
    )
    privacy_contract: PrivacyContract = Field(
        ...,
        description="Privacy policies of the agent"
    )
    scopes: List[str] = Field(
        default_factory=list,
        description="RBAC scopes defining agent permissions (e.g., 'repo:read', 'repo:write')"
    )

    def calculate_trust_score(self) -> int:
        """
        Calculate a trust score (0-10) based on capabilities and privacy.

        The trust score helps clients make informed decisions about agent reliability.
        Higher scores indicate more trustworthy agents with better security practices.

        Scoring Criteria:
        ----------------
        Base Score: 5 (neutral)

        Trust Level Adjustments:
        - VERIFIED_PARTNER: +3 (well-known, vetted partner)
        - TRUSTED: +2 (established trust relationship)
        - STANDARD: 0 (no prior relationship)
        - UNKNOWN: -2 (minimal information)
        - UNTRUSTED: -5 (known issues or red flags)

        Capability Bonuses:
        - Idempotency support: +1 (safe retry behavior)
        - Reversibility (full or partial): +1 (can undo actions)

        Privacy Adjustments:
        - Ephemeral retention: +2 (best privacy, data deleted after session)
        - Permanent/forever retention: -2 (worst privacy, data kept indefinitely)
        - No human review: +1 (automated processing only)

        Score Ranges:
        - 8-10: Highly trustworthy (verified partners with strong privacy)
        - 5-7: Moderately trustworthy (standard agents with decent practices)
        - 3-4: Low trust (some concerns, user should be cautious)
        - 0-2: Very low trust (significant concerns, strong warnings needed)

        Returns:
            int: Trust score clamped to range [0, 10]
        """
        score = 5  # Start with neutral score

        # Trust level adjustments
        trust_scores = {
            TrustLevel.VERIFIED_PARTNER: 3,
            TrustLevel.TRUSTED: 2,
            TrustLevel.STANDARD: 0,
            TrustLevel.UNKNOWN: -2,
            TrustLevel.UNTRUSTED: -5
        }
        score += trust_scores.get(self.trust_level, 0)

        # Capability bonuses
        if self.capabilities.idempotency:
            score += 1
        if self.capabilities.reversibility in [ReversibilityLevel.FULL, ReversibilityLevel.PARTIAL]:
            score += 1

        # Privacy bonuses
        if self.privacy_contract.retention == RetentionPolicy.EPHEMERAL:
            score += 2
        elif self.privacy_contract.retention in [RetentionPolicy.PERMANENT, RetentionPolicy.FOREVER]:
            score -= 2

        if not self.privacy_contract.human_review:
            score += 1

        # Clamp to 0-10 range
        return max(0, min(10, score))


class QuarantineSession(BaseModel):
    """Session information for quarantined/untrusted requests."""
    session_id: str
    trace_id: str
    warning_message: str
    user_override: bool = False
    timestamp: str
    manifest: Optional[CapabilityManifest] = None


class TracingContext(BaseModel):
    """Distributed tracing context."""
    trace_id: str = Field(
        ...,
        description="Unique trace ID for the request"
    )
    parent_trace_id: Optional[str] = Field(
        None,
        description="Parent trace ID if this is part of a chain"
    )
    timestamp: str = Field(
        ...,
        description="ISO 8601 timestamp"
    )
    agent_id: str = Field(
        ...,
        description="ID of the agent processing this request"
    )


class AttestationRecord(BaseModel):
    """
    Attestation record for agent codebase verification.

    This provides verifiable proof that an agent is running the expected
    codebase and configuration, signed by a trusted Control Plane.
    """
    agent_id: str = Field(
        ...,
        description="Unique identifier for the agent"
    )
    codebase_hash: str = Field(
        ...,
        description="SHA-256 hash of the agent's codebase"
    )
    config_hash: str = Field(
        ...,
        description="SHA-256 hash of the agent's configuration"
    )
    signature: str = Field(
        ...,
        description="Digital signature from Control Plane (base64 encoded)"
    )
    signing_key_id: str = Field(
        ...,
        description="Identifier for the public key used to verify signature"
    )
    timestamp: str = Field(
        ...,
        description="ISO 8601 timestamp when attestation was created"
    )
    expires_at: Optional[str] = Field(
        None,
        description="ISO 8601 timestamp when attestation expires"
    )

    def is_expired(self, current_time: str) -> bool:
        """
        Check if the attestation has expired.

        Args:
            current_time: Current time in ISO 8601 format

        Returns:
            True if expired, False otherwise
        """
        if not self.expires_at:
            return False
        return current_time > self.expires_at


class ReputationEvent(BaseModel):
    """
    Event that affects an agent's reputation score.

    This tracks individual events that caused reputation changes,
    such as hallucinations detected by cmvk or successful transactions.
    """
    event_id: str = Field(
        ...,
        description="Unique identifier for this event"
    )
    agent_id: str = Field(
        ...,
        description="Agent whose reputation is affected"
    )
    event_type: str = Field(
        ...,
        description="Type of event (e.g., 'hallucination', 'timeout', 'success')"
    )
    severity: str = Field(
        ...,
        description="Severity level: 'critical', 'high', 'medium', 'low'"
    )
    score_delta: float = Field(
        ...,
        description="Change in reputation score (negative for bad events)"
    )
    timestamp: str = Field(
        ...,
        description="ISO 8601 timestamp when event occurred"
    )
    trace_id: Optional[str] = Field(
        None,
        description="Associated trace ID if event was part of a request"
    )
    details: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional context about the event"
    )
    detected_by: Optional[str] = Field(
        None,
        description="Component that detected the event (e.g., 'cmvk', 'iatp')"
    )


class ReputationScore(BaseModel):
    """
    Network-wide reputation score for an agent.

    This tracks an agent's reputation based on its behavior across
    the network. Reputation can be slashed when misbehavior is detected.
    """
    agent_id: str = Field(
        ...,
        description="Agent identifier"
    )
    score: float = Field(
        5.0,
        ge=0.0,
        le=10.0,
        description="Current reputation score (0.0 to 10.0)"
    )
    initial_score: float = Field(
        5.0,
        description="Starting reputation score"
    )
    total_events: int = Field(
        0,
        description="Total number of reputation events"
    )
    positive_events: int = Field(
        0,
        description="Number of positive reputation events"
    )
    negative_events: int = Field(
        0,
        description="Number of negative reputation events"
    )
    last_updated: str = Field(
        ...,
        description="ISO 8601 timestamp of last update"
    )
    recent_events: List[ReputationEvent] = Field(
        default_factory=list,
        description="Recent reputation events (up to 100)"
    )

    def apply_event(self, event: ReputationEvent) -> None:
        """
        Apply a reputation event to update the score.

        Args:
            event: The reputation event to apply
        """
        # Update score with clamping
        self.score = max(0.0, min(10.0, self.score + event.score_delta))

        # Update counters
        self.total_events += 1
        if event.score_delta > 0:
            self.positive_events += 1
        elif event.score_delta < 0:
            self.negative_events += 1

        # Add to recent events (keep last 100)
        self.recent_events.append(event)
        if len(self.recent_events) > 100:
            self.recent_events = self.recent_events[-100:]

        # Update timestamp
        self.last_updated = event.timestamp

    def get_trust_level(self) -> TrustLevel:
        """
        Convert reputation score to trust level.

        Returns:
            Appropriate TrustLevel based on current score
        """
        if self.score >= 8.0:
            return TrustLevel.VERIFIED_PARTNER
        elif self.score >= 6.0:
            return TrustLevel.TRUSTED
        elif self.score >= 4.0:
            return TrustLevel.STANDARD
        elif self.score >= 2.0:
            return TrustLevel.UNKNOWN
        else:
            return TrustLevel.UNTRUSTED
