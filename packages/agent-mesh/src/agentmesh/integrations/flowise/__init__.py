# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""Flowise integration with Agent-Mesh trust layer.

Provides trust-gated API client and custom node definitions for Flowise,
a drag-and-drop UI for building LLM flows. Since Flowise is a Node.js
application, this integration works via the Flowise REST API with trust
headers injected into every request.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import urllib.request
    import urllib.error
    _HTTP_AVAILABLE = True
except ImportError:
    _HTTP_AVAILABLE = False


from agentmesh.exceptions import TrustError  # noqa: E402


class FlowiseTrustError(TrustError):
    """Raised when a Flowise trust verification fails."""


@dataclass
class FlowiseNodeIdentity:
    """Identity for a Flowise flow node."""

    node_name: str
    node_type: str
    did: str
    public_key: str
    trust_score: float = 0.5
    capabilities: List[str] = field(default_factory=list)

    @classmethod
    def generate(
        cls,
        node_name: str,
        node_type: str = "custom",
        capabilities: Optional[List[str]] = None,
        trust_score: float = 0.5,
    ) -> "FlowiseNodeIdentity":
        """Generate identity for a Flowise node."""
        seed = f"flowise:{node_name}:{node_type}:{time.time_ns()}"
        did_hash = hashlib.sha256(seed.encode()).hexdigest()[:32]
        return cls(
            node_name=node_name,
            node_type=node_type,
            did=f"did:flowise:{did_hash}",
            public_key=hashlib.sha256(f"pub:{seed}".encode()).hexdigest(),
            trust_score=trust_score,
            capabilities=capabilities or [],
        )


@dataclass
class FlowiseCallRecord:
    """Audit record for a Flowise API call."""

    flow_id: str
    endpoint: str
    timestamp: datetime
    caller_did: str
    trust_score: float
    status_code: int = 0
    response_time_ms: float = 0.0
    verified: bool = True


@dataclass
class FlowiseTrustPolicy:
    """Trust policy for Flowise API interactions."""

    min_trust_score: float = 0.5
    allowed_flows: Optional[List[str]] = None
    blocked_flows: Optional[List[str]] = None
    require_https: bool = True
    audit_logging: bool = True
    max_calls_per_minute: int = 60


class TrustGatedFlowiseClient:
    """Flowise REST API client with trust verification.

    Wraps Flowise API calls with Agent-Mesh identity headers and
    trust-based access control. Each API call is verified against
    the configured trust policy before execution.

    Usage::

        from agentmesh.integrations.flowise import (
            TrustGatedFlowiseClient, FlowiseNodeIdentity, FlowiseTrustPolicy
        )

        identity = FlowiseNodeIdentity.generate(
            "my-agent", capabilities=["chat"]
        )
        policy = FlowiseTrustPolicy(min_trust_score=0.6)
        client = TrustGatedFlowiseClient(
            base_url="http://localhost:3000",
            identity=identity,
            policy=policy,
        )
        result = client.predict(flow_id="abc-123", question="Hello")
    """

    def __init__(
        self,
        base_url: str,
        identity: FlowiseNodeIdentity,
        policy: Optional[FlowiseTrustPolicy] = None,
        api_key: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.identity = identity
        self.policy = policy or FlowiseTrustPolicy()
        self.api_key = api_key
        self._call_log: List[FlowiseCallRecord] = []
        self._call_timestamps: List[float] = []

    def _build_headers(self) -> Dict[str, str]:
        """Build request headers with trust metadata."""
        headers = {
            "Content-Type": "application/json",
            "X-AgentMesh-DID": self.identity.did,
            "X-AgentMesh-TrustScore": str(self.identity.trust_score),
            "X-AgentMesh-Capabilities": ",".join(self.identity.capabilities),
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _check_policy(self, flow_id: str) -> None:
        """Verify the call is allowed by trust policy."""
        if self.identity.trust_score < self.policy.min_trust_score:
            raise FlowiseTrustError(
                f"Trust score {self.identity.trust_score:.2f} "
                f"below required {self.policy.min_trust_score:.2f}"
            )

        if self.policy.blocked_flows and flow_id in self.policy.blocked_flows:
            raise FlowiseTrustError(f"Flow '{flow_id}' is blocked by policy")

        if self.policy.allowed_flows and flow_id not in self.policy.allowed_flows:
            raise FlowiseTrustError(f"Flow '{flow_id}' not in allowed list")

        if self.policy.require_https and not self.base_url.startswith("https"):
            if not self.base_url.startswith("http://localhost"):
                raise FlowiseTrustError(
                    "HTTPS required by policy (localhost exempt)"
                )

        # Rate limiting
        now = time.time()
        self._call_timestamps = [
            t for t in self._call_timestamps if now - t < 60
        ]
        if len(self._call_timestamps) >= self.policy.max_calls_per_minute:
            raise FlowiseTrustError("Rate limit exceeded")
        self._call_timestamps.append(now)

    def predict(
        self,
        flow_id: str,
        question: str,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send a prediction request to a Flowise chatflow.

        Args:
            flow_id: The Flowise chatflow ID.
            question: The user question/prompt.
            overrides: Optional config overrides for the flow.

        Returns:
            The Flowise API response as a dictionary.
        """
        self._check_policy(flow_id)

        url = f"{self.base_url}/api/v1/prediction/{flow_id}"
        payload: Dict[str, Any] = {"question": question}
        if overrides:
            payload["overrideConfig"] = overrides

        return self._make_request(url, payload, flow_id)

    def upsert(
        self,
        flow_id: str,
        documents: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Upsert documents into a Flowise vector store flow."""
        self._check_policy(flow_id)

        url = f"{self.base_url}/api/v1/vector/upsert/{flow_id}"
        payload = {"documents": documents}
        return self._make_request(url, payload, flow_id)

    def _make_request(
        self,
        url: str,
        payload: Dict[str, Any],
        flow_id: str,
    ) -> Dict[str, Any]:
        """Execute an HTTP request with trust headers."""
        headers = self._build_headers()
        data = json.dumps(payload).encode("utf-8")

        start_time = time.time()
        status_code = 0

        try:
            req = urllib.request.Request(
                url, data=data, headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                status_code = resp.status
                result = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            status_code = e.code
            raise FlowiseTrustError(
                f"Flowise API error {e.code}: {e.reason}"
            ) from e
        except Exception as e:
            raise FlowiseTrustError(f"Flowise API error: {e}") from e
        finally:
            elapsed_ms = (time.time() - start_time) * 1000
            if self.policy.audit_logging:
                self._call_log.append(FlowiseCallRecord(
                    flow_id=flow_id,
                    endpoint=url,
                    timestamp=datetime.now(timezone.utc),
                    caller_did=self.identity.did,
                    trust_score=self.identity.trust_score,
                    status_code=status_code,
                    response_time_ms=elapsed_ms,
                ))

        return result

    def get_audit_log(self) -> List[FlowiseCallRecord]:
        """Return the API call audit log."""
        return self._call_log.copy()

    def get_trust_report(self) -> Dict[str, Any]:
        """Get trust status report for this client."""
        return {
            "identity": {
                "name": self.identity.node_name,
                "did": self.identity.did,
                "trust_score": self.identity.trust_score,
                "capabilities": self.identity.capabilities,
            },
            "total_calls": len(self._call_log),
            "base_url": self.base_url,
            "policy": {
                "min_trust_score": self.policy.min_trust_score,
                "require_https": self.policy.require_https,
                "rate_limit": self.policy.max_calls_per_minute,
            },
        }


class FlowiseNodeDefinition:
    """Helper to generate Flowise-compatible custom node JSON.

    Creates node definitions that can be loaded into Flowise as
    custom trust verification nodes.
    """

    @staticmethod
    def trust_gate_node() -> Dict[str, Any]:
        """Generate a trust gate node definition for Flowise."""
        return {
            "label": "AgentMesh Trust Gate",
            "name": "agentMeshTrustGate",
            "type": "AgentMeshTrustGate",
            "icon": "shield-check",
            "category": "Security",
            "description": "Verifies agent trust before allowing data flow",
            "baseClasses": ["AgentMeshTrustGate"],
            "inputs": [
                {
                    "label": "Min Trust Score",
                    "name": "minTrustScore",
                    "type": "number",
                    "default": 0.5,
                    "description": "Minimum trust score (0.0-1.0)",
                },
                {
                    "label": "Required Capabilities",
                    "name": "requiredCapabilities",
                    "type": "string",
                    "description": "Comma-separated capability list",
                    "optional": True,
                },
                {
                    "label": "On Failure",
                    "name": "onFailure",
                    "type": "options",
                    "options": [
                        {"label": "Block", "name": "block"},
                        {"label": "Warn", "name": "warn"},
                        {"label": "Audit Only", "name": "audit"},
                    ],
                    "default": "block",
                },
            ],
            "outputs": [
                {
                    "label": "Verified Output",
                    "name": "verifiedOutput",
                    "baseClasses": ["string"],
                },
            ],
        }

    @staticmethod
    def identity_node() -> Dict[str, Any]:
        """Generate an identity setup node definition for Flowise."""
        return {
            "label": "AgentMesh Identity",
            "name": "agentMeshIdentity",
            "type": "AgentMeshIdentity",
            "icon": "fingerprint",
            "category": "Security",
            "description": "Creates a cryptographic identity for an agent",
            "baseClasses": ["AgentMeshIdentity"],
            "inputs": [
                {
                    "label": "Agent Name",
                    "name": "agentName",
                    "type": "string",
                    "description": "Unique agent identifier",
                },
                {
                    "label": "Trust Score",
                    "name": "trustScore",
                    "type": "number",
                    "default": 0.5,
                    "description": "Initial trust score (0.0-1.0)",
                },
                {
                    "label": "Capabilities",
                    "name": "capabilities",
                    "type": "string",
                    "description": "Comma-separated capabilities",
                    "optional": True,
                },
            ],
            "outputs": [
                {
                    "label": "Identity",
                    "name": "identity",
                    "baseClasses": ["AgentMeshIdentity"],
                },
            ],
        }

    @classmethod
    def export_all(cls) -> List[Dict[str, Any]]:
        """Export all AgentMesh node definitions."""
        return [cls.trust_gate_node(), cls.identity_node()]


__all__ = [
    "FlowiseCallRecord",
    "FlowiseNodeDefinition",
    "FlowiseNodeIdentity",
    "FlowiseTrustError",
    "FlowiseTrustPolicy",
    "TrustGatedFlowiseClient",
]
