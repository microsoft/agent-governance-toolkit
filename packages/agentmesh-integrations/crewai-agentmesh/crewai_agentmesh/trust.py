"""
Trust layer for CrewAI — trust-verified crew selection and task assignment.

Provides:
- AgentProfile: Agent identity with DID, capabilities, and trust score
- TrustedCrew: Select crew members by trust score and capability match
- CapabilityGate: Validate agent-to-task capability requirements
- TrustTracker: Track and update trust scores across crew runs
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class AgentProfile:
    """Agent identity within a CrewAI crew (AgentMesh-aware)."""

    did: str
    name: str
    capabilities: List[str] = field(default_factory=list)
    trust_score: int = 500  # 0-1000
    role: str = ""
    status: str = "active"  # active, suspended, revoked
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities

    def has_all_capabilities(self, required: List[str]) -> bool:
        return all(c in self.capabilities for c in required)

    def has_any_capability(self, required: List[str]) -> bool:
        return any(c in self.capabilities for c in required)

    @property
    def is_active(self) -> bool:
        return self.status == "active"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "did": self.did,
            "name": self.name,
            "capabilities": self.capabilities,
            "trust_score": self.trust_score,
            "role": self.role,
            "status": self.status,
        }


@dataclass
class TaskAssignment:
    """Result of assigning an agent to a task."""

    agent: AgentProfile
    task_description: str
    required_capabilities: List[str]
    trust_sufficient: bool
    capability_match: bool
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.trust_sufficient and self.capability_match


class CapabilityGate:
    """
    Validates that agents have the required capabilities for task assignment.

    In CrewAI, agents are assigned to tasks. CapabilityGate ensures the
    agent's verified capabilities match what the task requires.
    """

    def __init__(self, require_all: bool = True):
        self.require_all = require_all

    def check(
        self,
        agent: AgentProfile,
        required_capabilities: List[str],
    ) -> tuple[bool, str]:
        """Check if agent has required capabilities."""
        if not required_capabilities:
            return True, "No capabilities required"

        if not agent.is_active:
            return False, f"Agent '{agent.name}' is {agent.status}"

        if self.require_all:
            missing = [c for c in required_capabilities if not agent.has_capability(c)]
            if missing:
                return False, f"Missing capabilities: {missing}"
            return True, "All capabilities matched"
        else:
            if agent.has_any_capability(required_capabilities):
                return True, "At least one capability matched"
            return False, f"No matching capabilities"


class TrustTracker:
    """
    Tracks and updates agent trust scores across crew runs.

    Supports:
    - Recording task success/failure
    - Trust decay over time
    - Trust rewards for successful completion
    - Minimum trust threshold enforcement
    """

    def __init__(
        self,
        success_reward: int = 10,
        failure_penalty: int = 50,
        min_score: int = 0,
        max_score: int = 1000,
    ):
        self.success_reward = success_reward
        self.failure_penalty = failure_penalty
        self.min_score = min_score
        self.max_score = max_score
        self._history: List[Dict[str, Any]] = []

    def record_success(self, agent: AgentProfile, task_description: str = "") -> int:
        """Record a successful task completion. Returns new trust score."""
        old_score = agent.trust_score
        agent.trust_score = min(agent.trust_score + self.success_reward, self.max_score)
        self._history.append({
            "did": agent.did,
            "event": "success",
            "old_score": old_score,
            "new_score": agent.trust_score,
            "task": task_description,
            "timestamp": time.time(),
        })
        return agent.trust_score

    def record_failure(self, agent: AgentProfile, task_description: str = "", reason: str = "") -> int:
        """Record a task failure. Returns new trust score."""
        old_score = agent.trust_score
        agent.trust_score = max(agent.trust_score - self.failure_penalty, self.min_score)
        self._history.append({
            "did": agent.did,
            "event": "failure",
            "old_score": old_score,
            "new_score": agent.trust_score,
            "task": task_description,
            "reason": reason,
            "timestamp": time.time(),
        })
        return agent.trust_score

    def get_history(self, did: Optional[str] = None) -> List[Dict[str, Any]]:
        if did:
            return [h for h in self._history if h["did"] == did]
        return list(self._history)


class TrustedCrew:
    """
    Trust-verified crew for CrewAI workflows.

    Wraps a set of AgentProfiles and provides trust-gated selection:
    - Select agents by required capabilities
    - Filter by minimum trust score
    - Sort by trust score (highest first)
    - Track trust across crew runs
    """

    def __init__(
        self,
        agents: Optional[List[AgentProfile]] = None,
        min_trust_score: int = 100,
        capability_gate: Optional[CapabilityGate] = None,
        trust_tracker: Optional[TrustTracker] = None,
    ):
        self._agents: List[AgentProfile] = list(agents) if agents else []
        self.min_trust_score = min_trust_score
        self.capability_gate = capability_gate or CapabilityGate()
        self.trust_tracker = trust_tracker or TrustTracker()
        self._assignments: List[TaskAssignment] = []

    def add_agent(self, agent: AgentProfile) -> None:
        self._agents.append(agent)

    def remove_agent(self, did: str) -> bool:
        before = len(self._agents)
        self._agents = [a for a in self._agents if a.did != did]
        return len(self._agents) < before

    def get_agent(self, did: str) -> Optional[AgentProfile]:
        for a in self._agents:
            if a.did == did:
                return a
        return None

    @property
    def agents(self) -> List[AgentProfile]:
        return list(self._agents)

    @property
    def active_agents(self) -> List[AgentProfile]:
        return [a for a in self._agents if a.is_active]

    @property
    def trusted_agents(self) -> List[AgentProfile]:
        return [
            a for a in self._agents
            if a.is_active and a.trust_score >= self.min_trust_score
        ]

    def select_for_task(
        self,
        required_capabilities: Optional[List[str]] = None,
        min_trust: Optional[int] = None,
    ) -> List[AgentProfile]:
        """
        Select agents capable and trusted enough for a task.

        Returns agents sorted by trust score (highest first).
        """
        threshold = min_trust if min_trust is not None else self.min_trust_score
        candidates = []

        for agent in self._agents:
            if not agent.is_active:
                continue
            if agent.trust_score < threshold:
                continue
            if required_capabilities:
                ok, _ = self.capability_gate.check(agent, required_capabilities)
                if not ok:
                    continue
            candidates.append(agent)

        # Sort by trust score (highest first)
        candidates.sort(key=lambda a: a.trust_score, reverse=True)
        return candidates

    def assign_task(
        self,
        agent_did: str,
        task_description: str,
        required_capabilities: Optional[List[str]] = None,
    ) -> TaskAssignment:
        """
        Attempt to assign a task to a specific agent.

        Validates trust score and capability match.
        """
        agent = self.get_agent(agent_did)
        if agent is None:
            return TaskAssignment(
                agent=AgentProfile(did=agent_did, name="unknown"),
                task_description=task_description,
                required_capabilities=required_capabilities or [],
                trust_sufficient=False,
                capability_match=False,
                reason=f"Agent {agent_did} not found",
            )

        trust_ok = agent.is_active and agent.trust_score >= self.min_trust_score
        cap_ok = True
        cap_reason = ""
        if required_capabilities:
            cap_ok, cap_reason = self.capability_gate.check(agent, required_capabilities)

        reason = ""
        if not trust_ok:
            reason = f"Trust score {agent.trust_score} below minimum {self.min_trust_score}"
        elif not cap_ok:
            reason = cap_reason

        assignment = TaskAssignment(
            agent=agent,
            task_description=task_description,
            required_capabilities=required_capabilities or [],
            trust_sufficient=trust_ok,
            capability_match=cap_ok,
            reason=reason,
        )
        self._assignments.append(assignment)
        return assignment

    def record_task_result(
        self,
        agent_did: str,
        success: bool,
        task_description: str = "",
        reason: str = "",
    ) -> Optional[int]:
        """Record task success/failure and update trust score."""
        agent = self.get_agent(agent_did)
        if agent is None:
            return None
        if success:
            return self.trust_tracker.record_success(agent, task_description)
        return self.trust_tracker.record_failure(agent, task_description, reason)

    def get_assignments(self) -> List[TaskAssignment]:
        return list(self._assignments)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_agents": len(self._agents),
            "active_agents": len(self.active_agents),
            "trusted_agents": len(self.trusted_agents),
            "total_assignments": len(self._assignments),
            "allowed_assignments": sum(1 for a in self._assignments if a.allowed),
            "denied_assignments": sum(1 for a in self._assignments if not a.allowed),
        }
