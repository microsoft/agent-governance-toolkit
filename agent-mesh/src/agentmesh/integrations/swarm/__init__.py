# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""OpenAI Swarm integration with Agent-Mesh trust layer.

Provides trust-verified handoffs between Swarm agents using CMVK identity.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set


from agentmesh.exceptions import TrustViolationError  # noqa: E402


# Backward compatibility: TrustViolationError is re-exported from agentmesh.exceptions


@dataclass
class AgentIdentity:
    """Cryptographic identity for a Swarm agent."""

    agent_name: str
    did: str
    public_key: str
    trust_score: float = 0.5
    capabilities: List[str] = field(default_factory=list)

    @classmethod
    def from_agent(cls, agent: Any) -> "AgentIdentity":
        """Create identity from a Swarm Agent."""
        agent_name = getattr(agent, "name", "unnamed_agent")
        seed = f"{agent_name}:{time.time_ns()}"
        did_hash = hashlib.sha256(seed.encode()).hexdigest()[:32]

        capabilities = []
        functions = getattr(agent, "functions", [])
        for func in functions:
            func_name = getattr(func, "__name__", str(func))
            capabilities.append(func_name)

        return cls(
            agent_name=agent_name,
            did=f"did:swarm:{did_hash}",
            public_key=hashlib.sha256(f"pub:{seed}".encode()).hexdigest(),
            capabilities=capabilities,
        )


@dataclass
class HandoffRecord:
    """Record of a handoff between agents."""

    from_agent: str
    to_agent: str
    timestamp: datetime
    trust_score: float
    verified: bool
    reason: str = ""
    context_keys: List[str] = field(default_factory=list)


@dataclass
class TrustPolicy:
    """Policy for trusted handoffs."""

    min_trust_score: float = 0.5
    allowed_targets: Set[str] = field(default_factory=set)
    blocked_targets: Set[str] = field(default_factory=set)
    sensitive_context_keys: Set[str] = field(default_factory=lambda: {
        "password", "api_key", "secret", "token", "credential",
        "ssn", "credit_card", "bank_account",
    })
    sensitive_trust_score: float = 0.8
    audit_logging: bool = True
    on_violation: Optional[Callable[[str, str, str], None]] = None


class HandoffVerifier:
    """Verifies trust for Swarm handoffs."""

    def __init__(self, policy: TrustPolicy):
        self.policy = policy
        self._identities: Dict[str, AgentIdentity] = {}
        self._handoff_log: List[HandoffRecord] = []

    def register_agent(self, agent: Any, trust_score: float = 0.5) -> AgentIdentity:
        """Register an agent with the trust system."""
        identity = AgentIdentity.from_agent(agent)
        identity.trust_score = trust_score
        self._identities[identity.agent_name] = identity
        return identity

    def verify_handoff(
        self,
        from_agent: str,
        to_agent: str,
        context_variables: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Verify if a handoff is allowed."""
        verified = True
        reason = "Handoff verified"
        context_keys = list(context_variables.keys()) if context_variables else []

        if to_agent not in self._identities:
            verified = False
            reason = f"Target agent '{to_agent}' not registered"
        elif to_agent in self.policy.blocked_targets:
            verified = False
            reason = f"Target agent '{to_agent}' is blocked"
        elif self.policy.allowed_targets and to_agent not in self.policy.allowed_targets:
            verified = False
            reason = f"Target agent '{to_agent}' not in allowed list"
        else:
            target_identity = self._identities[to_agent]
            required_score = self.policy.min_trust_score

            if context_variables:
                for key in context_variables.keys():
                    key_lower = key.lower()
                    if any(s in key_lower for s in self.policy.sensitive_context_keys):
                        required_score = self.policy.sensitive_trust_score
                        break

            if target_identity.trust_score < required_score:
                verified = False
                reason = f"Trust score {target_identity.trust_score} below required {required_score}"

        if self.policy.audit_logging:
            record = HandoffRecord(
                from_agent=from_agent,
                to_agent=to_agent,
                timestamp=datetime.now(timezone.utc),
                trust_score=self._identities.get(to_agent, AgentIdentity("", "", "")).trust_score,
                verified=verified,
                reason=reason,
                context_keys=context_keys,
            )
            self._handoff_log.append(record)

        if not verified:
            if self.policy.on_violation:
                self.policy.on_violation(from_agent, to_agent, reason)
            raise TrustViolationError(reason)

        return True

    def update_trust(self, agent_name: str, delta: float) -> None:
        """Update an agent's trust score."""
        if agent_name in self._identities:
            identity = self._identities[agent_name]
            identity.trust_score = max(0.0, min(1.0, identity.trust_score + delta))

    def get_handoff_log(self) -> List[HandoffRecord]:
        """Get the handoff audit log."""
        return self._handoff_log.copy()


class TrustedAgent:
    """Wrapper that adds trust to a Swarm Agent."""

    def __init__(
        self,
        agent: Any,
        verifier: HandoffVerifier,
        trust_score: float = 0.5,
    ):
        self.agent = agent
        self.verifier = verifier
        self.identity = verifier.register_agent(agent, trust_score)
        self._wrap_handoffs()

    def _wrap_handoffs(self) -> None:
        """Wrap agent functions that return agents (handoffs)."""
        functions = getattr(self.agent, "functions", [])
        wrapped_functions = []

        for func in functions:
            wrapped = self._create_trusted_function(func)
            wrapped_functions.append(wrapped)

        self.agent.functions = wrapped_functions

    def _create_trusted_function(self, func: Callable) -> Callable:
        """Create a trust-verified wrapper for a function."""
        verifier = self.verifier
        from_agent = self.identity.agent_name

        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            if hasattr(result, "name") and hasattr(result, "functions"):
                to_agent = getattr(result, "name", "unknown")
                context = kwargs.get("context_variables", {})
                verifier.verify_handoff(from_agent, to_agent, context)

            return result

        wrapper.__name__ = getattr(func, "__name__", "wrapped")
        wrapper.__doc__ = getattr(func, "__doc__", "")

        return wrapper

    @property
    def name(self) -> str:
        return self.identity.agent_name

    def __getattr__(self, name: str) -> Any:
        return getattr(self.agent, name)


class TrustedSwarm:
    """Swarm client with trust-verified handoffs."""

    def __init__(self, policy: Optional[TrustPolicy] = None):
        self.policy = policy or TrustPolicy()
        self.verifier = HandoffVerifier(self.policy)
        self._agents: Dict[str, TrustedAgent] = {}

    def register_agent(
        self,
        agent: Any,
        trust_score: float = 0.5,
    ) -> TrustedAgent:
        """Register an agent with trust verification."""
        trusted = TrustedAgent(agent, self.verifier, trust_score)
        self._agents[trusted.name] = trusted
        return trusted

    def run(
        self,
        agent: Any,
        messages: List[Dict[str, str]],
        context_variables: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Any:
        """Run swarm with trust verification."""
        try:
            from swarm import Swarm
        except ImportError:
            raise ImportError("OpenAI Swarm not installed. Run: pip install openai-swarm")

        agent_name = getattr(agent, "name", "unknown")
        if agent_name not in self._agents:
            self.register_agent(agent)

        client = Swarm()
        return client.run(agent, messages, context_variables, **kwargs)

    def get_trust_report(self) -> Dict[str, Any]:
        """Get trust status report."""
        return {
            "agents": {
                name: {
                    "trust_score": agent.identity.trust_score,
                    "capabilities": agent.identity.capabilities,
                }
                for name, agent in self._agents.items()
            },
            "handoff_count": len(self.verifier.get_handoff_log()),
            "violations": sum(
                1 for r in self.verifier.get_handoff_log() if not r.verified
            ),
        }


__all__ = [
    "TrustedAgent",
    "TrustPolicy",
    "TrustedSwarm",
    "HandoffVerifier",
    "TrustViolationError",
    "AgentIdentity",
    "HandoffRecord",
]
