# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Microsoft Entra Agent ID adapter for AgentMesh.

Bridges AgentMesh DID-based identity with Microsoft Entra Agent ID,
enabling enterprise Zero Trust governance for AI agents via Entra's
identity lifecycle, Conditional Access, and sponsor accountability.

Requires: azure-identity (optional dependency)
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class EntraAgentStatus(str, Enum):
    """Entra Agent ID lifecycle states."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"
    DELETED = "deleted"


class EntraAgentBlueprint(BaseModel):
    """Template for creating Entra agent identities."""

    display_name: str = Field(..., description="Human-readable agent name")
    description: str = Field(default="", description="Agent purpose description")
    default_capabilities: list[str] = Field(default_factory=list)
    require_sponsor: bool = Field(default=True)
    max_delegation_depth: int = Field(default=2)
    conditional_access_policy: Optional[str] = Field(
        default=None, description="Conditional Access policy ID to apply"
    )


class EntraAgentIdentity(BaseModel):
    """
    Microsoft Entra Agent ID binding for an AgentMesh agent.

    Maps an AgentMesh DID identity to an Entra Agent ID, enabling:
    - Enterprise identity lifecycle management
    - Sponsor accountability (human owner per agent)
    - Conditional Access policies for agents
    - Unified audit trail across Entra + AgentMesh
    """

    # AgentMesh identity
    agent_did: str = Field(..., description="AgentMesh DID (did:mesh:...)")
    agent_name: str = Field(..., description="Agent display name")

    # Entra identity
    entra_object_id: str = Field(..., description="Entra Agent ID object ID")
    entra_app_id: str = Field(default="", description="Entra application/client ID")
    tenant_id: str = Field(..., description="Azure AD tenant ID")

    # Sponsor (human accountability)
    sponsor_email: str = Field(..., description="Human sponsor email (Entra UPN)")
    sponsor_object_id: str = Field(
        default="", description="Sponsor's Entra object ID"
    )

    # Lifecycle
    status: EntraAgentStatus = Field(default=EntraAgentStatus.ACTIVE)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: Optional[datetime] = Field(default=None)

    # Capabilities & access
    capabilities: list[str] = Field(default_factory=list)
    conditional_access_policy: Optional[str] = Field(default=None)
    scopes: list[str] = Field(
        default_factory=list,
        description="Entra API permissions/scopes granted to this agent",
    )

    # Blueprint reference
    blueprint_name: Optional[str] = Field(default=None)

    @classmethod
    def create(
        cls,
        agent_did: str,
        agent_name: str,
        entra_object_id: str,
        tenant_id: str,
        sponsor_email: str,
        capabilities: Optional[list[str]] = None,
        scopes: Optional[list[str]] = None,
        blueprint: Optional[EntraAgentBlueprint] = None,
    ) -> EntraAgentIdentity:
        """Create an Entra Agent ID binding for an AgentMesh agent."""
        caps = capabilities or (blueprint.default_capabilities if blueprint else [])
        ca_policy = blueprint.conditional_access_policy if blueprint else None

        return cls(
            agent_did=agent_did,
            agent_name=agent_name,
            entra_object_id=entra_object_id,
            tenant_id=tenant_id,
            sponsor_email=sponsor_email,
            capabilities=caps,
            scopes=scopes or [],
            conditional_access_policy=ca_policy,
            blueprint_name=blueprint.display_name if blueprint else None,
        )

    def record_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)

    def suspend(self, reason: str = "") -> None:
        """Suspend agent identity (reversible)."""
        self.status = EntraAgentStatus.SUSPENDED

    def reactivate(self) -> None:
        """Reactivate a suspended agent."""
        if self.status == EntraAgentStatus.SUSPENDED:
            self.status = EntraAgentStatus.ACTIVE

    def disable(self) -> None:
        """Disable agent identity (requires admin to re-enable)."""
        self.status = EntraAgentStatus.DISABLED

    def is_active(self) -> bool:
        """Check if the agent identity is active."""
        return self.status == EntraAgentStatus.ACTIVE

    def has_scope(self, scope: str) -> bool:
        """Check if agent has a specific Entra API scope."""
        return scope in self.scopes or f"{scope}/*" in self.scopes

    def to_audit_record(self) -> dict[str, Any]:
        """Export identity state for audit logging."""
        return {
            "agent_did": self.agent_did,
            "entra_object_id": self.entra_object_id,
            "tenant_id": self.tenant_id,
            "sponsor_email": self.sponsor_email,
            "status": self.status.value,
            "capabilities": self.capabilities,
            "scopes": self.scopes,
            "last_activity": (
                self.last_activity.isoformat() if self.last_activity else None
            ),
        }


class EntraAgentRegistry:
    """
    Registry mapping AgentMesh DIDs to Microsoft Entra Agent IDs.

    Provides enterprise identity management for AI agents, bridging
    AgentMesh's cryptographic DID identity with Entra's lifecycle
    governance, Conditional Access, and sponsor accountability.
    """

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self._agents: dict[str, EntraAgentIdentity] = {}  # keyed by agent_did
        self._by_entra_id: dict[str, str] = {}  # entra_object_id -> agent_did
        self._blueprints: dict[str, EntraAgentBlueprint] = {}
        self._audit_log: list[dict[str, Any]] = []

    def register_blueprint(self, blueprint: EntraAgentBlueprint) -> None:
        """Register an agent blueprint for consistent identity creation."""
        self._blueprints[blueprint.display_name] = blueprint

    def register(
        self,
        agent_did: str,
        agent_name: str,
        entra_object_id: str,
        sponsor_email: str,
        capabilities: Optional[list[str]] = None,
        scopes: Optional[list[str]] = None,
        blueprint_name: Optional[str] = None,
    ) -> EntraAgentIdentity:
        """Register an agent with both AgentMesh DID and Entra Agent ID."""
        blueprint = self._blueprints.get(blueprint_name) if blueprint_name else None

        if blueprint and blueprint.require_sponsor and not sponsor_email:
            raise ValueError(
                f"Blueprint '{blueprint_name}' requires a sponsor email"
            )

        identity = EntraAgentIdentity.create(
            agent_did=agent_did,
            agent_name=agent_name,
            entra_object_id=entra_object_id,
            tenant_id=self.tenant_id,
            sponsor_email=sponsor_email,
            capabilities=capabilities,
            scopes=scopes,
            blueprint=blueprint,
        )

        self._agents[agent_did] = identity
        self._by_entra_id[entra_object_id] = agent_did
        self._log_event("register", identity)
        return identity

    def get_by_did(self, agent_did: str) -> Optional[EntraAgentIdentity]:
        """Look up agent by AgentMesh DID."""
        return self._agents.get(agent_did)

    def get_by_entra_id(self, entra_object_id: str) -> Optional[EntraAgentIdentity]:
        """Look up agent by Entra object ID."""
        did = self._by_entra_id.get(entra_object_id)
        return self._agents.get(did) if did else None

    def suspend_agent(self, agent_did: str, reason: str = "") -> bool:
        """Suspend an agent (e.g., on anomaly detection)."""
        identity = self._agents.get(agent_did)
        if identity and identity.is_active():
            identity.suspend(reason)
            self._log_event("suspend", identity, {"reason": reason})
            return True
        return False

    def reactivate_agent(self, agent_did: str) -> bool:
        """Reactivate a suspended agent."""
        identity = self._agents.get(agent_did)
        if identity and identity.status == EntraAgentStatus.SUSPENDED:
            identity.reactivate()
            self._log_event("reactivate", identity)
            return True
        return False

    def disable_agent(self, agent_did: str) -> bool:
        """Disable an agent (admin action)."""
        identity = self._agents.get(agent_did)
        if identity:
            identity.disable()
            self._log_event("disable", identity)
            return True
        return False

    def verify_access(
        self, agent_did: str, required_scope: str
    ) -> tuple[bool, str]:
        """
        Verify an agent has the required Entra scope and is active.

        Returns (allowed, reason) tuple.
        """
        identity = self._agents.get(agent_did)
        if not identity:
            return False, "Agent not registered in Entra registry"
        if not identity.is_active():
            return False, f"Agent status: {identity.status.value}"
        if required_scope and not identity.has_scope(required_scope):
            return False, f"Agent lacks scope: {required_scope}"

        identity.record_activity()
        return True, "Access granted"

    def list_agents(
        self, status: Optional[EntraAgentStatus] = None
    ) -> list[EntraAgentIdentity]:
        """List all registered agents, optionally filtered by status."""
        agents = list(self._agents.values())
        if status:
            agents = [a for a in agents if a.status == status]
        return agents

    def get_sponsor_agents(self, sponsor_email: str) -> list[EntraAgentIdentity]:
        """Get all agents owned by a specific sponsor."""
        return [
            a for a in self._agents.values() if a.sponsor_email == sponsor_email
        ]

    def get_audit_log(self) -> list[dict[str, Any]]:
        """Return the full audit log."""
        return list(self._audit_log)

    def _log_event(
        self,
        event_type: str,
        identity: EntraAgentIdentity,
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        """Log an identity lifecycle event."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "agent_did": identity.agent_did,
            "entra_object_id": identity.entra_object_id,
            "sponsor_email": identity.sponsor_email,
            "status": identity.status.value,
        }
        if extra:
            entry.update(extra)
        self._audit_log.append(entry)
