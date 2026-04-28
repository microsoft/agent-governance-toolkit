# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Orphan agent detection.

Identifies agents that have gone silent (missed heartbeats),
have no owner, or have been inactive beyond policy thresholds.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .models import (
    AgentLifecycleState,
    LifecycleEventType,
    ManagedAgent,
)
from .manager import LifecycleManager


class OrphanCandidate:
    """An agent identified as potentially orphaned."""

    def __init__(self, agent: ManagedAgent, reason: str, days_silent: float | None = None):
        self.agent = agent
        self.reason = reason
        self.days_silent = days_silent


class OrphanDetector:
    """Detect orphaned and ghost agents in the fleet.

    An agent is considered orphaned if:
    - It has missed heartbeats beyond the policy threshold
    - It has no assigned owner
    - It has been inactive (no events) beyond max_inactive_days
    """

    def __init__(self, manager: LifecycleManager) -> None:
        self._manager = manager

    def detect(self) -> list[OrphanCandidate]:
        """Scan for orphan candidates across the fleet."""
        candidates: list[OrphanCandidate] = []
        policy = self._manager.policy
        now = datetime.now(timezone.utc)

        for agent in self._manager.agents:
            # Skip already decommissioned or orphaned
            if agent.state in (
                AgentLifecycleState.DECOMMISSIONED,
                AgentLifecycleState.ORPHANED,
            ):
                continue

            # Check heartbeat for active agents
            if agent.is_active:
                if agent.last_heartbeat:
                    silent_time = now - agent.last_heartbeat
                    if silent_time > policy.orphan_threshold:
                        days = silent_time.total_seconds() / 86400
                        candidates.append(OrphanCandidate(
                            agent=agent,
                            reason=f"No heartbeat for {days:.1f} days "
                                   f"(threshold: {policy.orphan_threshold})",
                            days_silent=days,
                        ))
                elif agent.heartbeat_count == 0:
                    # Active but never sent a heartbeat
                    age = now - agent.created_at
                    if age > policy.orphan_threshold:
                        candidates.append(OrphanCandidate(
                            agent=agent,
                            reason="Active but never sent a heartbeat",
                            days_silent=age.total_seconds() / 86400,
                        ))

            # Check for no owner
            if not agent.owner and agent.state != AgentLifecycleState.PENDING_APPROVAL:
                candidates.append(OrphanCandidate(
                    agent=agent,
                    reason="No owner assigned",
                ))

            # Check for long inactivity
            days_since_update = (now - agent.updated_at).total_seconds() / 86400
            if days_since_update > policy.max_inactive_days:
                candidates.append(OrphanCandidate(
                    agent=agent,
                    reason=f"Inactive for {days_since_update:.0f} days "
                           f"(max: {policy.max_inactive_days})",
                    days_silent=days_since_update,
                ))

        return candidates

    def mark_orphaned(self, agent_id: str, actor: str = "orphan-detector") -> ManagedAgent:
        """Mark an agent as orphaned."""
        agent = self._manager._get_agent(agent_id)

        # Only active agents can be marked orphaned
        if agent.state == AgentLifecycleState.ACTIVE:
            self._manager._transition(
                agent,
                AgentLifecycleState.ORPHANED,
                LifecycleEventType.ORPHAN_DETECTED,
                actor=actor,
                details={"detected_at": datetime.now(timezone.utc).isoformat()},
            )
        return agent

    def reclaim(self, agent_id: str, new_owner: str, actor: str = "admin") -> ManagedAgent:
        """Reclaim an orphaned agent by assigning a new owner and reactivating."""
        agent = self._manager._get_agent(agent_id)
        if agent.state != AgentLifecycleState.ORPHANED:
            from .manager import LifecycleError
            raise LifecycleError(f"Agent is not orphaned (state: {agent.state})")

        agent.owner = new_owner
        self._manager._transition(
            agent,
            AgentLifecycleState.ACTIVE,
            LifecycleEventType.RESUMED,
            actor=actor,
            details={"new_owner": new_owner, "reclaimed": True},
        )
        return agent
