# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Registry Service

The "Yellow Pages" of agents. Stores:
- Agent DIDs and identities
- Reputation scores
- Current status (active, suspended, revoked)
- Capabilities and protocols
"""

import asyncio
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

from agentmesh.constants import TIER_TRUSTED_THRESHOLD, TIER_VERIFIED_PARTNER_THRESHOLD, TRUST_SCORE_DEFAULT


class AgentRegistryEntry(BaseModel):
    """Entry in the agent registry."""

    # Identity
    did: str
    name: str
    description: str | None = None
    organization: str | None = None

    # Sponsor
    sponsor_email: str
    sponsor_verified: bool = False

    # Status
    status: Literal["active", "suspended", "revoked"] = "active"
    revocation_reason: str | None = None

    # Capabilities
    capabilities: list[str] = Field(default_factory=list)
    supported_protocols: list[str] = Field(default_factory=list)

    # Trust
    trust_score: int = Field(default=TRUST_SCORE_DEFAULT, ge=0, le=1000)
    trust_tier: Literal[
        "verified_partner",
        "trusted",
        "standard",
        "probationary",
        "untrusted"
    ] = "standard"

    # Credentials
    public_key_fingerprint: str
    svid_serial_number: str
    current_credential_expires_at: datetime

    # Timestamps
    registered_at: datetime = Field(default_factory=datetime.utcnow)
    last_seen_at: datetime | None = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # Delegation
    parent_did: str | None = None
    delegation_depth: int = 0

    # Metadata
    metadata: dict[str, str] = Field(default_factory=dict)


class AgentRegistry:
    """
    Agent Registry Service.

    Maintains a registry of all agents in the mesh with their:
    - Identity and credentials
    - Trust scores and reputation
    - Status and capabilities
    """

    def __init__(self):
        """Initialize the agent registry."""
        self._agents: dict[str, AgentRegistryEntry] = {}
        self._lock = asyncio.Lock()

    async def register(self, entry: AgentRegistryEntry) -> None:
        """
        Register a new agent.

        Args:
            entry: Agent registry entry

        Raises:
            ValueError: If agent is already registered
        """
        async with self._lock:
            if entry.did in self._agents:
                raise ValueError(f"Agent {entry.did} is already registered")

            self._agents[entry.did] = entry

    async def get(self, did: str) -> AgentRegistryEntry | None:
        """
        Get an agent by DID.

        Args:
            did: Agent's DID

        Returns:
            Agent entry or None if not found
        """
        return self._agents.get(did)

    async def update_trust_score(self, did: str, new_score: int) -> None:
        """
        Update an agent's trust score.

        Args:
            did: Agent's DID
            new_score: New trust score (0-1000)

        Raises:
            ValueError: If agent not found
        """
        async with self._lock:
            entry = self._agents.get(did)
            if entry is None:
                raise ValueError(f"Agent {did} not found")

            entry.trust_score = new_score
            entry.updated_at = datetime.now(timezone.utc)

            # Update trust tier based on score
            if new_score >= TIER_VERIFIED_PARTNER_THRESHOLD:
                entry.trust_tier = "verified_partner"
            elif new_score >= TIER_TRUSTED_THRESHOLD:
                entry.trust_tier = "trusted"
            elif new_score >= 400:
                entry.trust_tier = "standard"
            elif new_score >= 200:
                entry.trust_tier = "probationary"
            else:
                entry.trust_tier = "untrusted"

    async def update_status(
        self,
        did: str,
        status: Literal["active", "suspended", "revoked"],
        reason: str | None = None,
    ) -> None:
        """
        Update an agent's status.

        Args:
            did: Agent's DID
            status: New status
            reason: Optional reason for status change

        Raises:
            ValueError: If agent not found
        """
        async with self._lock:
            entry = self._agents.get(did)
            if entry is None:
                raise ValueError(f"Agent {did} not found")

            entry.status = status
            entry.revocation_reason = reason
            entry.updated_at = datetime.now(timezone.utc)

    async def record_activity(self, did: str) -> None:
        """
        Record that an agent was seen (heartbeat).

        Args:
            did: Agent's DID
        """
        async with self._lock:
            entry = self._agents.get(did)
            if entry:
                entry.last_seen_at = datetime.now(timezone.utc)

    async def list_agents(
        self,
        status: Literal["active", "suspended", "revoked"] | None = None,
        min_trust_score: int | None = None,
    ) -> list[AgentRegistryEntry]:
        """
        List agents with optional filters.

        Args:
            status: Filter by status
            min_trust_score: Filter by minimum trust score

        Returns:
            List of matching agent entries
        """
        agents = list(self._agents.values())

        if status:
            agents = [a for a in agents if a.status == status]

        if min_trust_score is not None:
            agents = [a for a in agents if a.trust_score >= min_trust_score]

        return agents

    async def count_agents(
        self,
        status: Literal["active", "suspended", "revoked"] | None = None,
    ) -> int:
        """
        Count agents with optional status filter.

        Args:
            status: Filter by status

        Returns:
            Number of matching agents
        """
        if status is None:
            return len(self._agents)

        return sum(1 for a in self._agents.values() if a.status == status)

    async def get_trust_statistics(self) -> dict:
        """
        Get aggregate trust statistics.

        Returns:
            Dictionary of trust statistics
        """
        if not self._agents:
            return {
                "total_agents": 0,
                "average_trust_score": 0,
                "tier_distribution": {},
            }

        scores = [a.trust_score for a in self._agents.values()]
        tiers = {}

        for agent in self._agents.values():
            tier = agent.trust_tier
            tiers[tier] = tiers.get(tier, 0) + 1

        return {
            "total_agents": len(self._agents),
            "average_trust_score": sum(scores) / len(scores),
            "min_trust_score": min(scores),
            "max_trust_score": max(scores),
            "tier_distribution": tiers,
        }
