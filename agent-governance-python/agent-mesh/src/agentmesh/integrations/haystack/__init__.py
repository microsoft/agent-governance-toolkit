# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""Haystack integration with Agent-Mesh trust layer.

Provides pipeline components for trust verification, identity management,
and trust-gated tool access in Haystack pipelines. Haystack uses a
component-based architecture with typed inputs and outputs, making it
a natural fit for injecting trust gates between pipeline stages.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


from agentmesh.exceptions import TrustError  # noqa: E402


class HaystackTrustError(TrustError):
    """Raised when a Haystack pipeline trust check fails."""


@dataclass
class PipelineIdentity:
    """Cryptographic identity for a Haystack pipeline component."""

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
        component_type: str = "custom",
        capabilities: Optional[List[str]] = None,
        trust_score: float = 0.5,
    ) -> "PipelineIdentity":
        """Generate identity for a Haystack component."""
        seed = f"haystack:{component_name}:{component_type}:{time.time_ns()}"
        did_hash = hashlib.sha256(seed.encode()).hexdigest()[:32]
        return cls(
            component_name=component_name,
            component_type=component_type,
            did=f"did:haystack:{did_hash}",
            public_key=hashlib.sha256(f"pub:{seed}".encode()).hexdigest(),
            trust_score=trust_score,
            capabilities=capabilities or [],
        )


@dataclass
class PipelineAuditEntry:
    """Audit entry for a pipeline stage execution."""

    component_name: str
    stage: str
    timestamp: datetime
    trust_score: float
    verified: bool
    input_keys: List[str] = field(default_factory=list)
    output_keys: List[str] = field(default_factory=list)
    reason: str = ""
    duration_ms: float = 0.0


class TrustGateComponent:
    """Haystack pipeline component for trust verification.

    Insert this between pipeline stages to enforce trust requirements
    on data flowing through the pipeline.

    Follows Haystack's component contract: has a ``run()`` method
    with typed inputs and outputs.

    Usage::

        from agentmesh.integrations.haystack import (
            TrustGateComponent, PipelineIdentity
        )

        identity = PipelineIdentity.generate("rag-retriever", capabilities=["search"])
        gate = TrustGateComponent(min_trust_score=0.6)
        gate.register_component("retriever", identity)

        result = gate.run(
            component_name="retriever",
            data={"query": "example"},
        )
    """

    def __init__(
        self,
        min_trust_score: float = 0.5,
        required_capabilities: Optional[List[str]] = None,
        on_failure: str = "block",
        audit_logging: bool = True,
    ):
        self.min_trust_score = min_trust_score
        self.required_capabilities = required_capabilities or []
        self.on_failure = on_failure
        self.audit_logging = audit_logging
        self._identities: Dict[str, PipelineIdentity] = {}
        self._audit_log: List[PipelineAuditEntry] = []

    def register_component(
        self,
        name: str,
        identity: PipelineIdentity,
    ) -> None:
        """Register a pipeline component with its identity."""
        self._identities[name] = identity

    def run(
        self,
        component_name: str,
        data: Dict[str, Any],
        stage: str = "default",
    ) -> Dict[str, Any]:
        """Run trust verification for a pipeline stage.

        Args:
            component_name: Name of the component to verify.
            data: Data being passed through the pipeline.
            stage: Pipeline stage name for audit purposes.

        Returns:
            Dict with "verified" (bool), "data" (pass-through), and
            "trust_metadata" containing verification details.
        """
        identity = self._identities.get(component_name)
        if identity is None:
            raise HaystackTrustError(
                f"Component '{component_name}' not registered"
            )

        verified = True
        reason = "Verified"

        # Capability check
        for cap in self.required_capabilities:
            if cap not in identity.capabilities:
                verified = False
                reason = f"Missing capability: {cap}"
                break

        # Trust score check
        if verified and identity.trust_score < self.min_trust_score:
            verified = False
            reason = (
                f"Trust score {identity.trust_score:.2f} "
                f"below required {self.min_trust_score:.2f}"
            )

        if self.audit_logging:
            self._audit_log.append(PipelineAuditEntry(
                component_name=component_name,
                stage=stage,
                timestamp=datetime.now(timezone.utc),
                trust_score=identity.trust_score,
                verified=verified,
                input_keys=list(data.keys()),
                reason=reason,
            ))

        if not verified and self.on_failure == "block":
            raise HaystackTrustError(reason)

        return {
            "verified": verified,
            "data": data,
            "trust_metadata": {
                "did": identity.did,
                "trust_score": identity.trust_score,
                "capabilities": identity.capabilities,
                "verified": verified,
                "reason": reason,
            },
        }

    def get_audit_log(self) -> List[PipelineAuditEntry]:
        """Return the pipeline audit log."""
        return self._audit_log.copy()


class TrustAgentComponent:
    """Haystack component wrapping an agent with trust identity.

    Provides a trust-aware wrapper for Haystack agent tools and
    components. Executes the wrapped component only if trust
    verification passes.

    Usage::

        from agentmesh.integrations.haystack import (
            TrustAgentComponent, PipelineIdentity
        )

        identity = PipelineIdentity.generate(
            "code-agent",
            capabilities=["execute_code"],
            trust_score=0.9,
        )
        agent = TrustAgentComponent(
            identity=identity,
            min_trust_score=0.7,
        )

        result = agent.run(
            query="Summarize this document",
            handler=my_handler_function,
        )
    """

    def __init__(
        self,
        identity: PipelineIdentity,
        min_trust_score: float = 0.5,
        required_capabilities: Optional[List[str]] = None,
        audit_logging: bool = True,
    ):
        self.identity = identity
        self.min_trust_score = min_trust_score
        self.required_capabilities = required_capabilities or []
        self.audit_logging = audit_logging
        self._audit_log: List[PipelineAuditEntry] = []

    def run(
        self,
        query: str,
        handler: Any = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Execute the agent with trust verification.

        Args:
            query: The input query.
            handler: Callable that processes the query. If None,
                     returns the query with trust metadata only.
            **kwargs: Additional arguments for the handler.

        Returns:
            Dict with "result", "trust_metadata", and "verified".
        """
        start = time.time()
        verified = True
        reason = "Verified"

        # Capability check
        for cap in self.required_capabilities:
            if cap not in self.identity.capabilities:
                verified = False
                reason = f"Missing capability: {cap}"
                break

        # Trust score check
        if verified and self.identity.trust_score < self.min_trust_score:
            verified = False
            reason = (
                f"Trust score {self.identity.trust_score:.2f} "
                f"below required {self.min_trust_score:.2f}"
            )

        result = None
        if verified and handler is not None:
            result = handler(query, **kwargs)

        elapsed_ms = (time.time() - start) * 1000

        if self.audit_logging:
            self._audit_log.append(PipelineAuditEntry(
                component_name=self.identity.component_name,
                stage="agent_execution",
                timestamp=datetime.now(timezone.utc),
                trust_score=self.identity.trust_score,
                verified=verified,
                input_keys=["query"] + list(kwargs.keys()),
                output_keys=["result"] if result is not None else [],
                reason=reason,
                duration_ms=elapsed_ms,
            ))

        if not verified:
            raise HaystackTrustError(reason)

        return {
            "result": result,
            "verified": verified,
            "trust_metadata": {
                "did": self.identity.did,
                "trust_score": self.identity.trust_score,
                "execution_time_ms": elapsed_ms,
            },
        }

    def get_audit_log(self) -> List[PipelineAuditEntry]:
        """Return the agent audit log."""
        return self._audit_log.copy()


class TrustedPipeline:
    """Manages a Haystack pipeline with trust gates at each stage.

    Coordinates identity and trust verification across all components
    in a Haystack pipeline.
    """

    def __init__(
        self,
        min_trust_score: float = 0.5,
        audit_logging: bool = True,
    ):
        self.min_trust_score = min_trust_score
        self.audit_logging = audit_logging
        self._components: Dict[str, PipelineIdentity] = {}
        self._gate = TrustGateComponent(
            min_trust_score=min_trust_score,
            audit_logging=audit_logging,
        )

    def add_component(
        self,
        name: str,
        capabilities: Optional[List[str]] = None,
        trust_score: float = 0.5,
    ) -> PipelineIdentity:
        """Add a component with trust identity."""
        identity = PipelineIdentity.generate(
            component_name=name,
            capabilities=capabilities,
            trust_score=trust_score,
        )
        self._components[name] = identity
        self._gate.register_component(name, identity)
        return identity

    def verify_stage(
        self,
        component_name: str,
        data: Dict[str, Any],
        stage: str = "default",
    ) -> Dict[str, Any]:
        """Verify trust for a pipeline stage."""
        return self._gate.run(component_name, data, stage)

    def update_trust(self, component_name: str, delta: float) -> None:
        """Update a component's trust score."""
        if component_name in self._components:
            identity = self._components[component_name]
            identity.trust_score = max(0.0, min(1.0, identity.trust_score + delta))

    def get_pipeline_report(self) -> Dict[str, Any]:
        """Get trust report for the entire pipeline."""
        audit = self._gate.get_audit_log()
        return {
            "components": {
                name: {
                    "did": identity.did,
                    "trust_score": identity.trust_score,
                    "capabilities": identity.capabilities,
                }
                for name, identity in self._components.items()
            },
            "total_verifications": len(audit),
            "passed": sum(1 for e in audit if e.verified),
            "blocked": sum(1 for e in audit if not e.verified),
        }


__all__ = [
    "HaystackTrustError",
    "PipelineAuditEntry",
    "PipelineIdentity",
    "TrustAgentComponent",
    "TrustGateComponent",
    "TrustedPipeline",
]
