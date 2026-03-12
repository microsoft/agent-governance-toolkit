# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
LangGraph Integration for AgentMesh
====================================

Provides trust checkpoints and verified graph nodes for LangGraph workflows.
Enables dual integration of Agent-OS (governance) and Agent-Mesh (trust).

Features:
- Trust verification at graph node boundaries
- Capability-gated node execution
- State persistence with trust metadata
- Integration with Agent-OS policies

Example:
    >>> from agentmesh.integrations.langgraph import TrustedGraphNode, TrustCheckpoint
    >>> from langgraph.graph import StateGraph
    >>>
    >>> # Create trust-enabled nodes
    >>> research_node = TrustedGraphNode(
    ...     name="research",
    ...     handler=research_agent,
    ...     required_capabilities=["access:web", "read:documents"],
    ...     min_trust_score=400,
    ... )
    >>>
    >>> # Add checkpoint for trust state
    >>> checkpoint = TrustCheckpoint(identity)
    >>>
    >>> # Build graph with trust gates
    >>> graph = StateGraph(State)
    >>> graph.add_node("research", research_node)
    >>> graph.add_node("trust_gate", checkpoint.create_gate())
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, TypeVar, Generic
from enum import Enum

logger = logging.getLogger(__name__)

StateType = TypeVar("StateType")


class TrustLevel(Enum):
    """Trust levels for graph execution."""
    VERIFIED_PARTNER = "verified_partner"
    TRUSTED = "trusted"
    STANDARD = "standard"
    UNTRUSTED = "untrusted"
    BLOCKED = "blocked"


@dataclass
class NodeTrustContext:
    """Trust context passed through graph state."""
    agent_did: str
    trust_score: int
    trust_level: TrustLevel
    capabilities: List[str]
    verified_at: datetime
    sponsor_id: str = ""

    # Audit trail
    nodes_visited: List[str] = field(default_factory=list)
    trust_checks_passed: int = 0
    trust_checks_failed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_did": self.agent_did,
            "trust_score": self.trust_score,
            "trust_level": self.trust_level.value,
            "capabilities": self.capabilities,
            "verified_at": self.verified_at.isoformat(),
            "sponsor_id": self.sponsor_id,
            "nodes_visited": self.nodes_visited,
            "trust_checks_passed": self.trust_checks_passed,
            "trust_checks_failed": self.trust_checks_failed,
        }


class TrustedGraphNode(Generic[StateType]):
    """
    LangGraph node with trust verification.

    Wraps a node handler with capability and trust score checks.
    """

    def __init__(
        self,
        name: str,
        handler: Callable[[StateType], StateType],
        required_capabilities: Optional[List[str]] = None,
        min_trust_score: int = 300,
        min_trust_level: TrustLevel = TrustLevel.STANDARD,
        fail_action: str = "block",  # "block" | "warn" | "audit"
    ):
        self.name = name
        self.handler = handler
        self.required_capabilities = required_capabilities or []
        self.min_trust_score = min_trust_score
        self.min_trust_level = min_trust_level
        self.fail_action = fail_action

        # Metrics
        self.total_executions = 0
        self.blocked_executions = 0

    def _get_trust_context(self, state: StateType) -> Optional[NodeTrustContext]:
        """Extract trust context from state."""
        if isinstance(state, dict):
            ctx_data = state.get("_trust_context")
            if ctx_data and isinstance(ctx_data, NodeTrustContext):
                return ctx_data
        return None

    def _check_capabilities(self, context: NodeTrustContext) -> tuple[bool, str]:
        """Check if context has required capabilities."""
        for required in self.required_capabilities:
            found = False
            for cap in context.capabilities:
                # Exact match
                if cap == required:
                    found = True
                    break
                # Wildcard match
                if cap.endswith(":*"):
                    prefix = cap[:-1]
                    if required.startswith(prefix):
                        found = True
                        break
            if not found:
                return False, f"Missing capability: {required}"
        return True, ""

    def _check_trust_level(self, context: NodeTrustContext) -> tuple[bool, str]:
        """Check if trust level is sufficient."""
        level_order = [
            TrustLevel.BLOCKED,
            TrustLevel.UNTRUSTED,
            TrustLevel.STANDARD,
            TrustLevel.TRUSTED,
            TrustLevel.VERIFIED_PARTNER,
        ]
        context_level_idx = level_order.index(context.trust_level)
        required_level_idx = level_order.index(self.min_trust_level)

        if context_level_idx < required_level_idx:
            return False, f"Trust level {context.trust_level.value} < {self.min_trust_level.value}"
        return True, ""

    async def __call__(self, state: StateType) -> StateType:
        """Execute node with trust verification."""
        context = self._get_trust_context(state)

        # If no trust context, behavior depends on fail_action
        if not context:
            if self.fail_action == "block":
                logger.error(f"Node {self.name}: No trust context, blocking execution")
                self.blocked_executions += 1
                raise TrustVerificationError(f"No trust context for node {self.name}")
            elif self.fail_action == "warn":
                logger.warning(f"Node {self.name}: No trust context, proceeding with warning")
            # audit mode: just log and proceed
        else:
            # Check trust score
            if context.trust_score < self.min_trust_score:
                context.trust_checks_failed += 1
                if self.fail_action == "block":
                    self.blocked_executions += 1
                    raise TrustVerificationError(
                        f"Trust score {context.trust_score} < {self.min_trust_score}"
                    )
                logger.warning(f"Node {self.name}: Low trust score {context.trust_score}")

            # Check trust level
            ok, reason = self._check_trust_level(context)
            if not ok:
                context.trust_checks_failed += 1
                if self.fail_action == "block":
                    self.blocked_executions += 1
                    raise TrustVerificationError(reason)
                logger.warning(f"Node {self.name}: {reason}")

            # Check capabilities
            ok, reason = self._check_capabilities(context)
            if not ok:
                context.trust_checks_failed += 1
                if self.fail_action == "block":
                    self.blocked_executions += 1
                    raise TrustVerificationError(reason)
                logger.warning(f"Node {self.name}: {reason}")

            # All checks passed
            context.trust_checks_passed += 1
            context.nodes_visited.append(self.name)

        # Execute handler
        self.total_executions += 1
        logger.info(f"Executing trusted node: {self.name}")

        # Handle both sync and async handlers
        import asyncio
        if asyncio.iscoroutinefunction(self.handler):
            result = await self.handler(state)
        else:
            result = self.handler(state)

        return result

    def get_stats(self) -> Dict[str, Any]:
        """Get node execution statistics."""
        return {
            "name": self.name,
            "total_executions": self.total_executions,
            "blocked_executions": self.blocked_executions,
            "block_rate": self.blocked_executions / max(self.total_executions, 1),
            "required_capabilities": self.required_capabilities,
            "min_trust_score": self.min_trust_score,
        }


class TrustCheckpoint:
    """
    Trust-aware checkpoint for LangGraph state persistence.

    Stores trust metadata alongside graph state.
    """

    def __init__(
        self,
        identity: Any,  # AgentIdentity
        trust_bridge: Any = None,  # TrustBridge
    ):
        self.identity = identity
        self.trust_bridge = trust_bridge
        self._checkpoints: Dict[str, Dict[str, Any]] = {}

    def create_initial_context(self) -> NodeTrustContext:
        """Create initial trust context from identity."""
        return NodeTrustContext(
            agent_did=str(self.identity.did) if hasattr(self.identity, "did") else "",
            trust_score=self.identity.trust_score if hasattr(self.identity, "trust_score") else 500,
            trust_level=TrustLevel.STANDARD,
            capabilities=list(self.identity.capabilities) if hasattr(self.identity, "capabilities") else [],
            verified_at=datetime.utcnow(),
            sponsor_id=self.identity.sponsor_id if hasattr(self.identity, "sponsor_id") else "",
        )

    def inject_context(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Inject trust context into state."""
        if "_trust_context" not in state:
            state["_trust_context"] = self.create_initial_context()
        return state

    def save(self, checkpoint_id: str, state: Dict[str, Any]) -> None:
        """Save checkpoint with trust metadata."""
        context = state.get("_trust_context")
        self._checkpoints[checkpoint_id] = {
            "state": state,
            "trust_context": context.to_dict() if context else None,
            "saved_at": datetime.utcnow().isoformat(),
        }
        logger.info(f"Saved trust checkpoint: {checkpoint_id}")

    def load(self, checkpoint_id: str) -> Optional[Dict[str, Any]]:
        """Load checkpoint."""
        checkpoint = self._checkpoints.get(checkpoint_id)
        if checkpoint:
            logger.info(f"Loaded trust checkpoint: {checkpoint_id}")
            return checkpoint["state"]
        return None

    def create_gate(self) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
        """
        Create a trust gate node for the graph.

        Use as: graph.add_node("trust_gate", checkpoint.create_gate())
        """
        def gate(state: Dict[str, Any]) -> Dict[str, Any]:
            return self.inject_context(state)
        return gate

    def create_verifier(
        self,
        min_score: int = 300,
        required_level: TrustLevel = TrustLevel.STANDARD,
    ) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
        """
        Create a trust verification node.

        Raises TrustVerificationError if trust requirements not met.
        """
        def verify(state: Dict[str, Any]) -> Dict[str, Any]:
            context = state.get("_trust_context")
            if not context:
                raise TrustVerificationError("No trust context in state")

            if isinstance(context, NodeTrustContext):
                if context.trust_score < min_score:
                    raise TrustVerificationError(
                        f"Trust score {context.trust_score} < {min_score}"
                    )

            return state
        return verify


from agentmesh.exceptions import TrustVerificationError  # noqa: E402


# Backward compatibility: TrustVerificationError is re-exported from agentmesh.exceptions


def create_trusted_graph(
    identity: Any,
    nodes: Dict[str, Callable],
    trust_requirements: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, TrustedGraphNode]:
    """
    Convenience function to wrap multiple nodes with trust verification.

    Args:
        identity: AgentIdentity for trust context
        nodes: Dict of node_name -> handler
        trust_requirements: Dict of node_name -> {min_trust_score, required_capabilities}

    Returns:
        Dict of node_name -> TrustedGraphNode
    """
    trust_requirements = trust_requirements or {}
    trusted_nodes = {}

    for name, handler in nodes.items():
        reqs = trust_requirements.get(name, {})
        trusted_nodes[name] = TrustedGraphNode(
            name=name,
            handler=handler,
            required_capabilities=reqs.get("required_capabilities", []),
            min_trust_score=reqs.get("min_trust_score", 300),
        )

    return trusted_nodes


# Convenience exports
__all__ = [
    "TrustedGraphNode",
    "TrustCheckpoint",
    "NodeTrustContext",
    "TrustLevel",
    "TrustVerificationError",
    "create_trusted_graph",
]
