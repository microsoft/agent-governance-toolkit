# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""Langflow integration with Agent-Mesh trust layer.

Provides custom Langflow components for trust verification, identity
management, and trust-gated agent connections in visual workflows.

Langflow is a visual framework for building multi-agent AI applications
built on the LangChain ecosystem. This integration adds governance
primitives as drag-and-drop components.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


from agentmesh.exceptions import TrustVerificationError  # noqa: E402


# Backward compatibility: TrustVerificationError is re-exported from agentmesh.exceptions


@dataclass
class ComponentIdentity:
    """Cryptographic identity for a Langflow component/agent."""

    component_name: str
    did: str
    public_key: str
    trust_score: float = 0.5
    capabilities: List[str] = field(default_factory=list)
    component_type: str = "custom"

    @classmethod
    def generate(
        cls,
        component_name: str,
        capabilities: Optional[List[str]] = None,
        trust_score: float = 0.5,
    ) -> "ComponentIdentity":
        """Generate a new identity for a Langflow component."""
        seed = f"langflow:{component_name}:{time.time_ns()}"
        did_hash = hashlib.sha256(seed.encode()).hexdigest()[:32]
        return cls(
            component_name=component_name,
            did=f"did:langflow:{did_hash}",
            public_key=hashlib.sha256(f"pub:{seed}".encode()).hexdigest(),
            trust_score=trust_score,
            capabilities=capabilities or [],
        )


@dataclass
class ConnectionRecord:
    """Audit record for a trust-verified connection between components."""

    source_component: str
    target_component: str
    timestamp: datetime
    trust_score: float
    verified: bool
    reason: str = ""
    data_keys: List[str] = field(default_factory=list)


class TrustVerificationComponent:
    """Langflow custom component for trust verification.

    Drop this into a Langflow flow to gate connections between agents
    with trust score requirements and capability checks.

    Usage in Langflow custom component::

        from agentmesh.integrations.langflow import TrustVerificationComponent

        component = TrustVerificationComponent(
            min_trust_score=0.6,
            required_capabilities=["search", "summarize"],
        )
        verified = component.verify(source_identity, target_identity, data)
    """

    display_name: str = "AgentMesh Trust Gate"
    description: str = "Verifies trust between connected agents in a flow"

    def __init__(
        self,
        min_trust_score: float = 0.5,
        required_capabilities: Optional[List[str]] = None,
        sensitive_data_keys: Optional[set] = None,
        sensitive_trust_score: float = 0.8,
        on_failure: str = "block",
        audit_logging: bool = True,
    ):
        self.min_trust_score = min_trust_score
        self.required_capabilities = required_capabilities or []
        self.sensitive_data_keys = sensitive_data_keys or {
            "password", "api_key", "secret", "token", "credential",
        }
        self.sensitive_trust_score = sensitive_trust_score
        self.on_failure = on_failure  # "block" | "warn" | "audit"
        self.audit_logging = audit_logging
        self._audit_log: List[ConnectionRecord] = []

    def verify(
        self,
        source: ComponentIdentity,
        target: ComponentIdentity,
        data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Verify trust for a connection between two components."""
        verified = True
        reason = "Connection verified"
        data_keys = list(data.keys()) if data else []

        # Check capabilities
        for cap in self.required_capabilities:
            if cap not in target.capabilities:
                verified = False
                reason = f"Missing required capability: {cap}"
                break

        # Check trust score
        if verified:
            required_score = self.min_trust_score
            if data:
                for key in data.keys():
                    if key.lower() in self.sensitive_data_keys:
                        required_score = self.sensitive_trust_score
                        break

            if target.trust_score < required_score:
                verified = False
                reason = (
                    f"Trust score {target.trust_score:.2f} "
                    f"below required {required_score:.2f}"
                )

        # Audit log
        if self.audit_logging:
            record = ConnectionRecord(
                source_component=source.component_name,
                target_component=target.component_name,
                timestamp=datetime.now(timezone.utc),
                trust_score=target.trust_score,
                verified=verified,
                reason=reason,
                data_keys=data_keys,
            )
            self._audit_log.append(record)

        if not verified and self.on_failure == "block":
            raise TrustVerificationError(reason)

        return verified

    def get_audit_log(self) -> List[ConnectionRecord]:
        """Return the connection audit log."""
        return self._audit_log.copy()


class IdentityComponent:
    """Langflow custom component for CMVK identity setup.

    Provides a visual node for creating and managing agent identities
    within a Langflow flow. Place this at the start of any agent chain.
    """

    display_name: str = "AgentMesh Identity"
    description: str = "Creates a cryptographic identity for an agent in the flow"

    def __init__(self):
        self._identities: Dict[str, ComponentIdentity] = {}

    def build(
        self,
        agent_name: str,
        capabilities: Optional[List[str]] = None,
        trust_score: float = 0.5,
    ) -> ComponentIdentity:
        """Build/retrieve an identity for the given agent name."""
        if agent_name in self._identities:
            return self._identities[agent_name]

        identity = ComponentIdentity.generate(
            component_name=agent_name,
            capabilities=capabilities,
            trust_score=trust_score,
        )
        self._identities[agent_name] = identity
        return identity

    def get_identity(self, agent_name: str) -> Optional[ComponentIdentity]:
        """Retrieve an existing identity."""
        return self._identities.get(agent_name)

    def list_identities(self) -> Dict[str, ComponentIdentity]:
        """List all registered identities."""
        return dict(self._identities)


class TrustGatedFlow:
    """Manages a Langflow flow with trust verification at connections.

    Wraps an entire flow so every component-to-component data transfer
    passes through trust verification automatically.
    """

    def __init__(
        self,
        min_trust_score: float = 0.5,
        required_capabilities: Optional[List[str]] = None,
        audit_logging: bool = True,
    ):
        self.identity_manager = IdentityComponent()
        self.verifier = TrustVerificationComponent(
            min_trust_score=min_trust_score,
            required_capabilities=required_capabilities or [],
            audit_logging=audit_logging,
        )
        self._flow_nodes: Dict[str, ComponentIdentity] = {}

    def register_node(
        self,
        node_name: str,
        capabilities: Optional[List[str]] = None,
        trust_score: float = 0.5,
    ) -> ComponentIdentity:
        """Register a flow node with trust identity."""
        identity = self.identity_manager.build(
            agent_name=node_name,
            capabilities=capabilities,
            trust_score=trust_score,
        )
        self._flow_nodes[node_name] = identity
        return identity

    def verify_connection(
        self,
        from_node: str,
        to_node: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Verify a connection between two flow nodes."""
        source = self._flow_nodes.get(from_node)
        target = self._flow_nodes.get(to_node)

        if source is None:
            raise TrustVerificationError(f"Source node '{from_node}' not registered")
        if target is None:
            raise TrustVerificationError(f"Target node '{to_node}' not registered")

        return self.verifier.verify(source, target, data)

    def get_flow_report(self) -> Dict[str, Any]:
        """Get trust status for the entire flow."""
        audit = self.verifier.get_audit_log()
        return {
            "nodes": {
                name: {
                    "did": identity.did,
                    "trust_score": identity.trust_score,
                    "capabilities": identity.capabilities,
                }
                for name, identity in self._flow_nodes.items()
            },
            "total_connections": len(audit),
            "verified": sum(1 for r in audit if r.verified),
            "blocked": sum(1 for r in audit if not r.verified),
        }

    def to_langflow_config(self) -> Dict[str, Any]:
        """Export trust configuration as Langflow-compatible JSON."""
        return {
            "type": "agentmesh_trust_flow",
            "version": "1.0.0",
            "min_trust_score": self.verifier.min_trust_score,
            "required_capabilities": self.verifier.required_capabilities,
            "nodes": {
                name: {
                    "did": identity.did,
                    "trust_score": identity.trust_score,
                    "capabilities": identity.capabilities,
                }
                for name, identity in self._flow_nodes.items()
            },
        }


__all__ = [
    "ComponentIdentity",
    "ConnectionRecord",
    "IdentityComponent",
    "TrustGatedFlow",
    "TrustVerificationComponent",
    "TrustVerificationError",
]
