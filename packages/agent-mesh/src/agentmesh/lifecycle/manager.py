# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Lifecycle Manager — orchestrates the agent lifecycle state machine.

Manages provisioning, activation, suspension, and decommissioning
of agents with full audit trail and policy enforcement.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import (
    AgentLifecycleState,
    LifecycleEvent,
    LifecycleEventType,
    LifecyclePolicy,
    ManagedAgent,
)


# Valid state transitions
VALID_TRANSITIONS: dict[AgentLifecycleState, set[AgentLifecycleState]] = {
    AgentLifecycleState.PENDING_APPROVAL: {
        AgentLifecycleState.PROVISIONED,
        AgentLifecycleState.DECOMMISSIONED,  # rejected
    },
    AgentLifecycleState.PROVISIONED: {
        AgentLifecycleState.ACTIVE,
        AgentLifecycleState.DECOMMISSIONING,
    },
    AgentLifecycleState.ACTIVE: {
        AgentLifecycleState.SUSPENDED,
        AgentLifecycleState.ROTATING_CREDENTIALS,
        AgentLifecycleState.DECOMMISSIONING,
        AgentLifecycleState.ORPHANED,
    },
    AgentLifecycleState.SUSPENDED: {
        AgentLifecycleState.ACTIVE,
        AgentLifecycleState.DECOMMISSIONING,
    },
    AgentLifecycleState.ROTATING_CREDENTIALS: {
        AgentLifecycleState.ACTIVE,
        AgentLifecycleState.SUSPENDED,
    },
    AgentLifecycleState.ORPHANED: {
        AgentLifecycleState.ACTIVE,  # reclaimed
        AgentLifecycleState.DECOMMISSIONING,
    },
    AgentLifecycleState.DECOMMISSIONING: {
        AgentLifecycleState.DECOMMISSIONED,
    },
    AgentLifecycleState.DECOMMISSIONED: set(),  # terminal
}


class LifecycleError(Exception):
    """Error in lifecycle management."""


class LifecycleManager:
    """Manages the lifecycle of agents from provisioning to decommission.

    The manager enforces:
    - State machine transitions (invalid transitions are rejected)
    - Policy compliance (owner required, approval workflows)
    - Credential lifecycle (rotation, expiry, revocation)
    - Full audit trail (every state change is recorded)
    """

    def __init__(
        self,
        policy: LifecyclePolicy | None = None,
        storage_path: str | Path | None = None,
    ) -> None:
        self.policy = policy or LifecyclePolicy()
        self._agents: dict[str, ManagedAgent] = {}
        self._storage_path = Path(storage_path) if storage_path else None
        if self._storage_path and self._storage_path.exists():
            self._load()

    @property
    def agents(self) -> list[ManagedAgent]:
        return list(self._agents.values())

    def request_provisioning(
        self,
        name: str,
        owner: str,
        purpose: str = "",
        agent_type: str = "autonomous",
        actor: str = "system",
        tags: dict[str, str] | None = None,
    ) -> ManagedAgent:
        """Request provisioning of a new agent.

        If policy requires approval, agent starts in PENDING_APPROVAL.
        Otherwise, goes directly to PROVISIONED.
        """
        if self.policy.require_owner and not owner:
            raise LifecycleError("Owner is required by policy")

        agent_id = f"agent:{uuid.uuid4().hex[:12]}"
        initial_state = (
            AgentLifecycleState.PENDING_APPROVAL
            if self.policy.require_approval
            else AgentLifecycleState.PROVISIONED
        )

        agent = ManagedAgent(
            agent_id=agent_id,
            name=name,
            owner=owner,
            purpose=purpose,
            agent_type=agent_type,
            state=initial_state,
            tags=tags or {},
        )

        event = LifecycleEvent(
            event_type=LifecycleEventType.REQUESTED,
            agent_id=agent_id,
            actor=actor,
            details={"name": name, "owner": owner, "purpose": purpose},
            new_state=initial_state,
        )
        agent.record_event(event)

        self._agents[agent_id] = agent
        self._save()
        return agent

    def approve(self, agent_id: str, actor: str = "admin") -> ManagedAgent:
        """Approve a pending agent request."""
        agent = self._get_agent(agent_id)
        self._transition(
            agent,
            AgentLifecycleState.PROVISIONED,
            LifecycleEventType.APPROVED,
            actor=actor,
        )
        return agent

    def reject(self, agent_id: str, reason: str = "", actor: str = "admin") -> ManagedAgent:
        """Reject a pending agent request."""
        agent = self._get_agent(agent_id)
        self._transition(
            agent,
            AgentLifecycleState.DECOMMISSIONED,
            LifecycleEventType.REJECTED,
            actor=actor,
            details={"reason": reason},
        )
        agent.decommissioned_at = datetime.now(timezone.utc)
        return agent

    def activate(self, agent_id: str, actor: str = "system") -> ManagedAgent:
        """Activate a provisioned agent and issue initial credentials."""
        agent = self._get_agent(agent_id)
        self._transition(
            agent,
            AgentLifecycleState.ACTIVE,
            LifecycleEventType.ACTIVATED,
            actor=actor,
        )
        # Issue initial credential
        self._issue_credential(agent)
        return agent

    def heartbeat(self, agent_id: str) -> ManagedAgent:
        """Record a heartbeat from an active agent."""
        agent = self._get_agent(agent_id)
        now = datetime.now(timezone.utc)
        agent.last_heartbeat = now
        agent.heartbeat_count += 1
        agent.updated_at = now

        agent.record_event(LifecycleEvent(
            event_type=LifecycleEventType.HEARTBEAT,
            agent_id=agent_id,
            details={"count": agent.heartbeat_count},
        ))
        self._save()
        return agent

    def suspend(self, agent_id: str, reason: str = "", actor: str = "admin") -> ManagedAgent:
        """Suspend an active agent."""
        agent = self._get_agent(agent_id)
        self._transition(
            agent,
            AgentLifecycleState.SUSPENDED,
            LifecycleEventType.SUSPENDED,
            actor=actor,
            details={"reason": reason},
        )
        return agent

    def resume(self, agent_id: str, actor: str = "admin") -> ManagedAgent:
        """Resume a suspended agent."""
        agent = self._get_agent(agent_id)
        self._transition(
            agent,
            AgentLifecycleState.ACTIVE,
            LifecycleEventType.RESUMED,
            actor=actor,
        )
        return agent

    def decommission(self, agent_id: str, reason: str = "", actor: str = "admin") -> ManagedAgent:
        """Start decommissioning an agent."""
        agent = self._get_agent(agent_id)

        # Transition to decommissioning
        self._transition(
            agent,
            AgentLifecycleState.DECOMMISSIONING,
            LifecycleEventType.DECOMMISSION_STARTED,
            actor=actor,
            details={"reason": reason},
        )

        # Revoke credentials if policy requires
        if self.policy.credential_policy.revoke_on_decommission:
            agent.credential_id = None
            agent.credential_expires_at = None

        # Complete decommission
        self._transition(
            agent,
            AgentLifecycleState.DECOMMISSIONED,
            LifecycleEventType.DECOMMISSIONED,
            actor=actor,
        )
        agent.decommissioned_at = datetime.now(timezone.utc)
        return agent

    def change_owner(self, agent_id: str, new_owner: str, actor: str = "admin") -> ManagedAgent:
        """Transfer ownership of an agent."""
        agent = self._get_agent(agent_id)
        old_owner = agent.owner
        agent.owner = new_owner
        agent.record_event(LifecycleEvent(
            event_type=LifecycleEventType.OWNER_CHANGED,
            agent_id=agent_id,
            actor=actor,
            details={"old_owner": old_owner, "new_owner": new_owner},
        ))
        agent.updated_at = datetime.now(timezone.utc)
        self._save()
        return agent

    def rotate_credentials(self, agent_id: str) -> ManagedAgent:
        """Rotate credentials for an active agent."""
        agent = self._get_agent(agent_id)
        if not agent.is_active:
            raise LifecycleError(f"Cannot rotate credentials for agent in state {agent.state}")

        old_cred = agent.credential_id
        self._issue_credential(agent)

        agent.record_event(LifecycleEvent(
            event_type=LifecycleEventType.CREDENTIAL_ROTATED,
            agent_id=agent_id,
            details={"old_credential": old_cred, "new_credential": agent.credential_id},
        ))
        self._save()
        return agent

    def get(self, agent_id: str) -> ManagedAgent | None:
        """Get an agent by ID."""
        return self._agents.get(agent_id)

    def list_by_state(self, state: AgentLifecycleState) -> list[ManagedAgent]:
        """List agents in a specific lifecycle state."""
        return [a for a in self._agents.values() if a.state == state]

    def list_by_owner(self, owner: str) -> list[ManagedAgent]:
        """List agents owned by a specific person/team."""
        return [a for a in self._agents.values() if a.owner == owner]

    def get_audit_trail(self, agent_id: str) -> list[LifecycleEvent]:
        """Get the full audit trail for an agent."""
        agent = self._get_agent(agent_id)
        return agent.events

    def summary(self) -> dict[str, Any]:
        """Generate lifecycle summary statistics."""
        by_state: dict[str, int] = {}
        by_owner: dict[str, int] = {}
        for agent in self._agents.values():
            by_state[agent.state.value] = by_state.get(agent.state.value, 0) + 1
            by_owner[agent.owner] = by_owner.get(agent.owner, 0) + 1

        return {
            "total_agents": len(self._agents),
            "by_state": by_state,
            "by_owner": by_owner,
        }

    # --- Internal helpers ---

    def _get_agent(self, agent_id: str) -> ManagedAgent:
        agent = self._agents.get(agent_id)
        if not agent:
            raise LifecycleError(f"Agent not found: {agent_id}")
        return agent

    def _transition(
        self,
        agent: ManagedAgent,
        new_state: AgentLifecycleState,
        event_type: LifecycleEventType,
        actor: str = "system",
        details: dict[str, Any] | None = None,
    ) -> None:
        """Execute a validated state transition."""
        valid = VALID_TRANSITIONS.get(agent.state, set())
        if new_state not in valid:
            raise LifecycleError(
                f"Invalid transition: {agent.state.value} → {new_state.value}. "
                f"Valid: {[s.value for s in valid]}"
            )

        event = LifecycleEvent(
            event_type=event_type,
            agent_id=agent.agent_id,
            actor=actor,
            details=details or {},
            previous_state=agent.state,
            new_state=new_state,
        )
        agent.record_event(event)
        self._save()

    def _issue_credential(self, agent: ManagedAgent) -> None:
        """Issue a new short-lived credential."""
        now = datetime.now(timezone.utc)
        agent.credential_id = f"cred:{uuid.uuid4().hex[:16]}"
        agent.credential_issued_at = now
        agent.credential_expires_at = now + self.policy.credential_policy.max_credential_ttl

    def _save(self) -> None:
        if not self._storage_path:
            return
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        data = [a.model_dump(mode="json") for a in self._agents.values()]
        self._storage_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def _load(self) -> None:
        if not self._storage_path or not self._storage_path.exists():
            return
        try:
            data = json.loads(self._storage_path.read_text(encoding="utf-8"))
            for item in data:
                agent = ManagedAgent.model_validate(item)
                self._agents[agent.agent_id] = agent
        except Exception:  # noqa: S110 — intentional silent catch for state file load
            pass
