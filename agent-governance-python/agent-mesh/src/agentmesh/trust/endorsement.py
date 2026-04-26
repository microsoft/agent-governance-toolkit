# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Endorsement Registry — RFC 9334 Endorser Role
===============================================

Implements the Endorser concept from RFC 9334 (RATS Architecture):
an entity that vouches for the integrity, capability, or compliance
of an Attester (agent). Endorsements are first-class metadata
artifacts that inform trust decisions without modifying the
existing handshake or trust-scoring APIs.

Current scope: **unsigned metadata endorsements.** Cryptographic
signature verification is deferred to a future iteration (see
ADR-0009 gap analysis). Consumers should treat endorsements as
informational signals, not as proof of claims, until signature
verification is implemented.

Usage::

    from agentmesh.trust.endorsement import Endorsement, EndorsementRegistry

    registry = EndorsementRegistry()
    endorsement = Endorsement(
        endorser_did="did:mesh:compliance-authority",
        target_did="did:mesh:agent-alpha",
        endorsement_type="compliance",
        claims={"framework": "EU AI Act", "risk_level": "limited"},
    )
    registry.add(endorsement)

    # Query endorsements for an agent
    endorsements = registry.get_endorsements("did:mesh:agent-alpha")

References:
    - RFC 9334, Section 2.1 (Endorser role)
    - RFC 9334, Section 3.1 (Endorsements as artifacts)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class EndorsementType(str, Enum):
    """Categories of endorsement per RFC 9334 semantics.

    - ``CAPABILITY``: vouches that the agent possesses specific capabilities.
    - ``INTEGRITY``: vouches for the agent's code/runtime integrity.
    - ``COMPLIANCE``: vouches for regulatory or policy compliance.
    - ``IDENTITY``: vouches for the agent's identity binding.
    - ``REFERENCE_VALUE``: provides known-good reference values for appraisal.
    """

    CAPABILITY = "capability"
    INTEGRITY = "integrity"
    COMPLIANCE = "compliance"
    IDENTITY = "identity"
    REFERENCE_VALUE = "reference_value"


@dataclass
class Endorsement:
    """A single endorsement from an Endorser about a target agent.

    Attributes:
        endorser_did: DID of the endorsing entity.
        target_did: DID of the agent being endorsed.
        endorsement_type: Category of endorsement.
        claims: Key-value pairs describing what is endorsed.
        issued_at: When the endorsement was issued.
        expires_at: When the endorsement expires (None = no expiry).
        metadata: Additional context (audit trail, source system, etc.).
    """

    endorser_did: str
    target_did: str
    endorsement_type: EndorsementType
    claims: dict[str, Any] = field(default_factory=dict)
    issued_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    expires_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check whether this endorsement has passed its expiry time."""
        if self.expires_at is None:
            return False
        try:
            expiry = datetime.fromisoformat(self.expires_at)
            if expiry.tzinfo is None:
                now = datetime.utcnow()
            else:
                now = datetime.now(UTC)
            return now > expiry
        except (ValueError, TypeError):
            return True

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "endorser_did": self.endorser_did,
            "target_did": self.target_did,
            "endorsement_type": self.endorsement_type.value,
            "claims": dict(self.claims),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Endorsement:
        """Deserialize from a plain dictionary."""
        return cls(
            endorser_did=data["endorser_did"],
            target_did=data["target_did"],
            endorsement_type=EndorsementType(data["endorsement_type"]),
            claims=data.get("claims", {}),
            issued_at=data.get("issued_at", ""),
            expires_at=data.get("expires_at"),
            metadata=data.get("metadata", {}),
        )


class EndorsementRegistry:
    """In-memory registry of endorsements for agents.

    Stores endorsements keyed by target agent DID and provides
    query methods for retrieving valid (non-expired) endorsements.

    This registry does **not** perform cryptographic verification
    of endorsement signatures. That responsibility belongs to a
    future ``EndorsementVerifier`` component (see ADR-0009).
    """

    def __init__(self) -> None:
        self._endorsements: dict[str, list[Endorsement]] = {}

    def add(self, endorsement: Endorsement) -> None:
        """Register an endorsement for a target agent."""
        if endorsement.is_expired():
            logger.warning(
                "Rejecting expired endorsement from %s for %s",
                endorsement.endorser_did,
                endorsement.target_did,
            )
            return
        target = endorsement.target_did
        if target not in self._endorsements:
            self._endorsements[target] = []
        self._endorsements[target].append(endorsement)

    def get_endorsements(
        self,
        target_did: str,
        endorsement_type: EndorsementType | None = None,
    ) -> list[Endorsement]:
        """Get all valid (non-expired) endorsements for an agent.

        Args:
            target_did: The agent DID to query endorsements for.
            endorsement_type: Optional filter by endorsement category.

        Returns:
            List of non-expired endorsements, newest first.
        """
        all_endorsements = self._endorsements.get(target_did, [])
        valid = [e for e in all_endorsements if not e.is_expired()]

        if endorsement_type is not None:
            valid = [e for e in valid if e.endorsement_type == endorsement_type]

        # Purge expired entries while we are here
        if len(valid) < len(all_endorsements):
            self._endorsements[target_did] = [
                e for e in all_endorsements if not e.is_expired()
            ]

        return sorted(valid, key=lambda e: e.issued_at, reverse=True)

    def get_endorsers(self, target_did: str) -> list[str]:
        """Get distinct endorser DIDs for a target agent."""
        endorsements = self.get_endorsements(target_did)
        seen: set[str] = set()
        result: list[str] = []
        for e in endorsements:
            if e.endorser_did not in seen:
                seen.add(e.endorser_did)
                result.append(e.endorser_did)
        return result

    def has_endorsement(
        self,
        target_did: str,
        endorsement_type: EndorsementType,
        endorser_did: str | None = None,
    ) -> bool:
        """Check whether a valid endorsement of the given type exists."""
        endorsements = self.get_endorsements(target_did, endorsement_type)
        if endorser_did is not None:
            endorsements = [e for e in endorsements if e.endorser_did == endorser_did]
        return len(endorsements) > 0

    def revoke(self, target_did: str, endorser_did: str) -> int:
        """Remove all endorsements from a specific endorser for a target.

        Returns:
            Number of endorsements removed.
        """
        if target_did not in self._endorsements:
            return 0
        before = len(self._endorsements[target_did])
        self._endorsements[target_did] = [
            e for e in self._endorsements[target_did]
            if e.endorser_did != endorser_did
        ]
        after = len(self._endorsements[target_did])
        removed = before - after
        if removed > 0:
            logger.info(
                "Revoked %d endorsement(s) from %s for %s",
                removed,
                endorser_did,
                target_did,
            )
        return removed

    def clear(self, target_did: str | None = None) -> None:
        """Clear endorsements. If target_did is None, clear all."""
        if target_did is None:
            self._endorsements.clear()
        else:
            self._endorsements.pop(target_did, None)

    @property
    def total_count(self) -> int:
        """Total number of stored endorsements (including expired)."""
        return sum(len(v) for v in self._endorsements.values())
