# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Capability Scoping

Simple string-based capability scope checking.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
import uuid


class CapabilityGrant(BaseModel):
    """
    A specific capability grant to an agent.

    Capabilities follow the format: action:resource[:qualifier]
    Examples:
    - read:data
    - write:reports
    - execute:tools:calculator
    - admin:*
    """

    grant_id: str = Field(default_factory=lambda: f"grant_{uuid.uuid4().hex[:12]}")

    # Capability specification
    capability: str = Field(..., description="Capability string (e.g., 'read:data')")
    action: str = Field(..., description="Action part (e.g., 'read')")
    resource: str = Field(..., description="Resource part (e.g., 'data')")
    qualifier: Optional[str] = Field(None, description="Optional qualifier")

    # Grant metadata
    granted_to: str = Field(..., description="DID of grantee")
    granted_by: str = Field(..., description="DID of grantor")

    # Scope restrictions
    resource_ids: list[str] = Field(
        default_factory=list,
        description="Specific resource IDs this grant applies to"
    )
    conditions: dict = Field(
        default_factory=dict,
        description="Additional conditions for this grant"
    )

    # Timing
    granted_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = Field(None)

    # Status
    active: bool = Field(default=True)
    revoked_at: Optional[datetime] = Field(None)

    @classmethod
    def parse_capability(cls, capability: str) -> tuple[str, str, Optional[str]]:
        """Parse a capability string into (action, resource, qualifier)."""
        parts = capability.split(":")
        if len(parts) < 2:
            raise ValueError(f"Invalid capability format: {capability}")

        action = parts[0]
        resource = parts[1]
        qualifier = parts[2] if len(parts) > 2 else None

        return action, resource, qualifier

    @classmethod
    def create(
        cls,
        capability: str,
        granted_to: str,
        granted_by: str,
        resource_ids: Optional[list[str]] = None,
        expires_at: Optional[datetime] = None,
    ) -> "CapabilityGrant":
        """Create a new capability grant from a capability string."""
        action, resource, qualifier = cls.parse_capability(capability)

        return cls(
            capability=capability,
            action=action,
            resource=resource,
            qualifier=qualifier,
            granted_to=granted_to,
            granted_by=granted_by,
            resource_ids=resource_ids or [],
            expires_at=expires_at,
        )

    def is_valid(self) -> bool:
        """Check if the grant is currently active and not expired."""
        if not self.active:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True

    def matches(self, requested: str, resource_id: Optional[str] = None) -> bool:
        """Check if this grant satisfies a requested capability.

        Uses simple startswith matching for scope checking.
        """
        if not self.is_valid():
            return False

        # Simple string-based scope check
        if self.capability == "*" or self.capability == requested:
            pass  # exact match or wildcard
        elif self.capability.endswith(":*"):
            prefix = self.capability[:-1]  # e.g. "read:" from "read:*"
            if not requested.startswith(prefix):
                return False
        elif requested.startswith(self.capability):
            pass  # granted is a prefix of requested
        else:
            # Fall back to component matching
            req_action, req_resource, req_qualifier = self.parse_capability(requested)
            if self.action != "*" and self.action != req_action:
                return False
            if self.resource != "*" and self.resource != req_resource:
                return False
            if req_qualifier and self.qualifier:
                if self.qualifier != "*" and self.qualifier != req_qualifier:
                    return False

        # Check resource ID if scoped
        if self.resource_ids and resource_id:
            if resource_id not in self.resource_ids:
                return False

        return True

    def revoke(self) -> None:
        """Revoke this grant immediately."""
        self.active = False
        self.revoked_at = datetime.utcnow()


class CapabilityScope(BaseModel):
    """
    Complete capability scope for an agent.

    Aggregates all grants and provides capability checking.
    """

    agent_did: str
    grants: list[CapabilityGrant] = Field(default_factory=list)

    # Denied capabilities (blocklist)
    denied: list[str] = Field(default_factory=list)

    def add_grant(self, grant: CapabilityGrant) -> None:
        """Add a capability grant to this scope.

        Args:
            grant: The ``CapabilityGrant`` to add.

        Raises:
            ValueError: If the grant's ``granted_to`` does not match
                this scope's ``agent_did``.
        """
        if grant.granted_to != self.agent_did:
            raise ValueError("Grant is for different agent")
        self.grants.append(grant)

    def has_capability(
        self,
        capability: str,
        resource_id: Optional[str] = None,
    ) -> bool:
        """Check if the agent has a specific capability.

        Checks the deny list first, then searches for a valid,
        matching grant.

        Args:
            capability: Capability string to check (e.g.
                ``"read:data"``).
            resource_id: Optional resource ID for scoped checks.

        Returns:
            ``True`` if the capability is not denied and a matching
            valid grant exists.
        """
        # Check denied first
        if capability in self.denied:
            return False

        # Check for matching grant
        for grant in self.grants:
            if grant.matches(capability, resource_id):
                return True

        return False

    def get_capabilities(self) -> list[str]:
        """Get all active capability strings for this agent.

        Returns:
            De-duplicated list of capability strings from grants that
            are currently valid.
        """
        capabilities = set()
        for grant in self.grants:
            if grant.is_valid():
                capabilities.add(grant.capability)
        return list(capabilities)

    def filter_capabilities(self, requested: list[str]) -> list[str]:
        """Filter a list of requested capabilities to only those allowed.

        Args:
            requested: Capability strings the caller wants to use.

        Returns:
            Subset of *requested* that this scope permits.
        """
        return [cap for cap in requested if self.has_capability(cap)]

    def deny(self, capability: str) -> None:
        """Add a capability to the deny list.

        Denied capabilities take precedence over any matching grants.

        Args:
            capability: Capability string to deny (e.g.
                ``"write:data"``).
        """
        if capability not in self.denied:
            self.denied.append(capability)

    def revoke_all(self) -> int:
        """Revoke all active grants in this scope.

        Returns:
            Number of grants that were revoked.
        """
        count = 0
        for grant in self.grants:
            if grant.active:
                grant.revoke()
                count += 1
        return count

    def revoke_from(self, grantor_did: str) -> int:
        """Revoke all active grants issued by a specific grantor.

        Args:
            grantor_did: DID of the grantor whose grants should be
                revoked.

        Returns:
            Number of grants that were revoked.
        """
        count = 0
        for grant in self.grants:
            if grant.active and grant.granted_by == grantor_did:
                grant.revoke()
                count += 1
        return count

    def cleanup_expired(self) -> int:
        """Remove expired and revoked grants from the scope.

        Returns:
            Number of grants that were removed.
        """
        before = len(self.grants)
        self.grants = [g for g in self.grants if g.is_valid()]
        return before - len(self.grants)


class CapabilityRegistry:
    """
    Central registry for capability grants.

    Tracks who has what capabilities across the mesh.
    """

    def __init__(self):
        """Initialise an empty capability registry."""
        self._scopes: dict[str, CapabilityScope] = {}
        self._grants_by_grantor: dict[str, list[str]] = {}  # grantor -> [grant_ids]

    def get_scope(self, agent_did: str) -> CapabilityScope:
        """Get or create the capability scope for an agent.

        Args:
            agent_did: The agent's decentralized identifier.

        Returns:
            The existing ``CapabilityScope``, or a new empty one if
            the agent was not previously registered.
        """
        if agent_did not in self._scopes:
            self._scopes[agent_did] = CapabilityScope(agent_did=agent_did)
        return self._scopes[agent_did]

    def grant(
        self,
        capability: str,
        to_agent: str,
        from_agent: str,
        resource_ids: Optional[list[str]] = None,
    ) -> CapabilityGrant:
        """Grant a capability to an agent.

        Creates a ``CapabilityGrant``, adds it to the agent's scope,
        and tracks it by grantor for bulk revocation.

        Args:
            capability: Capability string (e.g. ``"read:data"``).
            to_agent: DID of the agent receiving the grant.
            from_agent: DID of the agent issuing the grant.
            resource_ids: Optional specific resource IDs to scope the
                grant to.

        Returns:
            The newly created ``CapabilityGrant``.
        """
        grant = CapabilityGrant.create(
            capability=capability,
            granted_to=to_agent,
            granted_by=from_agent,
            resource_ids=resource_ids,
        )

        scope = self.get_scope(to_agent)
        scope.add_grant(grant)

        # Track by grantor
        if from_agent not in self._grants_by_grantor:
            self._grants_by_grantor[from_agent] = []
        self._grants_by_grantor[from_agent].append(grant.grant_id)

        return grant

    def check(
        self,
        agent_did: str,
        capability: str,
        resource_id: Optional[str] = None,
    ) -> bool:
        """Check if an agent has a specific capability.

        Args:
            agent_did: The agent's decentralized identifier.
            capability: Capability string to check.
            resource_id: Optional resource ID for scoped checks.

        Returns:
            ``True`` if a valid matching grant exists for the agent.
        """
        scope = self._scopes.get(agent_did)
        if not scope:
            return False
        return scope.has_capability(capability, resource_id)

    def revoke_all_from(self, grantor_did: str) -> int:
        """Revoke all grants issued by a specific grantor.

        Useful when a grantor agent is compromised and all grants it
        issued must be invalidated immediately.

        Args:
            grantor_did: DID of the grantor whose grants should be
                revoked across all agent scopes.

        Returns:
            Total number of grants that were revoked.
        """
        count = 0
        for scope in self._scopes.values():
            count += scope.revoke_from(grantor_did)
        return count

    def get_agents_with_capability(self, capability: str) -> list[str]:
        """Get all agent DIDs that currently hold a capability.

        Args:
            capability: Capability string to search for.

        Returns:
            List of agent DIDs that have a valid grant matching the
            requested capability.
        """
        result = []
        for agent_did, scope in self._scopes.items():
            if scope.has_capability(capability):
                result.append(agent_did)
        return result
