# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Human Sponsor

Every agent identity is linked to a human sponsor who is accountable.
The sponsor's credentials are cryptographically linked to the scope chain.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, EmailStr
import uuid


class HumanSponsor(BaseModel):
    """
    Human sponsor responsible for an agent's actions.

    The sponsor is the accountability anchor - when an agent causes
    damage, the sponsor is responsible.
    """

    sponsor_id: str = Field(..., description="Unique sponsor identifier")

    # Identity
    email: EmailStr = Field(..., description="Verified email address")
    name: Optional[str] = Field(None, description="Human name")

    # Organization
    organization_id: Optional[str] = Field(None)
    organization_name: Optional[str] = Field(None)
    department: Optional[str] = Field(None)

    # Verification
    verified: bool = Field(default=False)
    verified_at: Optional[datetime] = Field(None)
    verification_method: Optional[str] = Field(None)  # "email", "sso", "manual"

    # Permissions
    max_agents: int = Field(default=10, description="Max agents this sponsor can create")
    max_delegation_depth: int = Field(default=3, description="Max scope chain depth")
    allowed_capabilities: list[str] = Field(default_factory=list)

    # Status
    status: str = Field(default="active")  # active, suspended, revoked

    # Agents
    agent_dids: list[str] = Field(default_factory=list, description="DIDs of sponsored agents")

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity_at: Optional[datetime] = Field(None)

    @classmethod
    def create(
        cls,
        email: str,
        name: Optional[str] = None,
        organization: Optional[str] = None,
        allowed_capabilities: Optional[list[str]] = None,
    ) -> "HumanSponsor":
        """Create a new human sponsor.

        Args:
            email: Verified email address of the sponsor.
            name: Human-readable name.
            organization: Organization name.
            allowed_capabilities: Capabilities the sponsor may grant.
                Defaults to ``["*"]`` (all capabilities).

        Returns:
            A new unverified HumanSponsor instance.
        """
        sponsor_id = f"sponsor_{uuid.uuid4().hex[:16]}"

        return cls(
            sponsor_id=sponsor_id,
            email=email,
            name=name,
            organization_name=organization,
            allowed_capabilities=allowed_capabilities or ["*"],  # Default: all capabilities
        )

    def verify(self, method: str = "email") -> None:
        """Mark sponsor as verified.

        Args:
            method: Verification method used (e.g. "email", "sso", "manual").
        """
        self.verified = True
        self.verified_at = datetime.utcnow()
        self.verification_method = method

    def can_sponsor_agent(self) -> bool:
        """Check if sponsor can create more agents.

        Returns:
            True if the sponsor is active, verified, and under the agent limit.
        """
        if self.status != "active":
            return False
        if not self.verified:
            return False
        return len(self.agent_dids) < self.max_agents

    def can_grant_capability(self, capability: str) -> bool:
        """Check if sponsor can grant a specific capability.

        Supports exact match, wildcard (``*``), and prefix wildcard matching.

        Args:
            capability: The capability string to check.

        Returns:
            True if the sponsor is allowed to grant the capability.
        """
        if "*" in self.allowed_capabilities:
            return True

        if capability in self.allowed_capabilities:
            return True

        # Check prefix matching
        for allowed in self.allowed_capabilities:
            if allowed.endswith(":*"):
                prefix = allowed[:-2]
                if capability.startswith(prefix + ":"):
                    return True

        return False

    def add_agent(self, agent_did: str) -> None:
        """Track a new agent sponsored by this human.

        Args:
            agent_did: DID of the agent to add.
        """
        if agent_did not in self.agent_dids:
            self.agent_dids.append(agent_did)
            self.last_activity_at = datetime.utcnow()

    def remove_agent(self, agent_did: str) -> None:
        """Remove an agent from sponsorship.

        Args:
            agent_did: DID of the agent to remove.
        """
        if agent_did in self.agent_dids:
            self.agent_dids.remove(agent_did)

    def suspend(self, reason: Optional[str] = None) -> None:
        """Suspend this sponsor (and all their agents should be suspended too).

        Args:
            reason: Optional human-readable reason for suspension.
        """
        self.status = "suspended"

    def reactivate(self) -> None:
        """Reactivate a suspended sponsor.

        Raises:
            ValueError: If the sponsor has been permanently revoked.
        """
        if self.status == "revoked":
            raise ValueError("Cannot reactivate a revoked sponsor")
        self.status = "active"


class SponsorRegistry:
    """
    Registry for human sponsors.

    Tracks who is accountable for which agents.
    """

    def __init__(self):
        self._sponsors: dict[str, HumanSponsor] = {}
        self._by_email: dict[str, str] = {}  # email -> sponsor_id

    def register(self, sponsor: HumanSponsor) -> None:
        """Register a new sponsor.

        Args:
            sponsor: The HumanSponsor to register.

        Raises:
            ValueError: If a sponsor with the same email is already registered.
        """
        if sponsor.email in self._by_email:
            raise ValueError(f"Sponsor already registered: {sponsor.email}")

        self._sponsors[sponsor.sponsor_id] = sponsor
        self._by_email[sponsor.email] = sponsor.sponsor_id

    def get(self, sponsor_id: str) -> Optional[HumanSponsor]:
        """Get sponsor by ID.

        Args:
            sponsor_id: Unique sponsor identifier.

        Returns:
            The HumanSponsor, or None if not found.
        """
        return self._sponsors.get(sponsor_id)

    def get_by_email(self, email: str) -> Optional[HumanSponsor]:
        """Get sponsor by email.

        Args:
            email: The sponsor's email address.

        Returns:
            The HumanSponsor, or None if not found.
        """
        sponsor_id = self._by_email.get(email)
        if sponsor_id:
            return self._sponsors.get(sponsor_id)
        return None

    def get_or_create(
        self,
        email: str,
        name: Optional[str] = None,
        organization: Optional[str] = None,
    ) -> HumanSponsor:
        """Get existing sponsor or create new one.

        Args:
            email: The sponsor's email address.
            name: Human-readable name (used only on creation).
            organization: Organization name (used only on creation).

        Returns:
            The existing or newly created HumanSponsor.
        """
        existing = self.get_by_email(email)
        if existing:
            return existing

        sponsor = HumanSponsor.create(email, name, organization)
        self.register(sponsor)
        return sponsor

    def suspend_all_for_org(self, organization_id: str) -> int:
        """Suspend all sponsors in an organization.

        Args:
            organization_id: The organization identifier.

        Returns:
            The number of sponsors suspended.
        """
        count = 0
        for sponsor in self._sponsors.values():
            if sponsor.organization_id == organization_id:
                sponsor.suspend()
                count += 1
        return count
