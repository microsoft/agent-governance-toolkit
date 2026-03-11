"""
A2A-compliant Agent Card — maps AgentMesh identity to A2A discovery format.

An Agent Card is the A2A standard's agent "business card", published at
``/.well-known/agent.json`` for discovery.  This module lets any AgentMesh
agent generate an A2A-compliant card from its identity.

Spec reference: https://a2a-protocol.org/latest/specification/
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AgentSkill:
    """A single capability the agent can perform (A2A ``skills[]`` entry)."""

    id: str
    name: str
    description: str = ""
    tags: List[str] = field(default_factory=list)
    input_modes: List[str] = field(default_factory=lambda: ["text/plain"])
    output_modes: List[str] = field(default_factory=lambda: ["text/plain"])
    examples: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"id": self.id, "name": self.name}
        if self.description:
            d["description"] = self.description
        if self.tags:
            d["tags"] = self.tags
        if self.input_modes:
            d["inputModes"] = self.input_modes
        if self.output_modes:
            d["outputModes"] = self.output_modes
        if self.examples:
            d["examples"] = self.examples
        return d


@dataclass
class AgentCard:
    """
    A2A-compliant Agent Card with AgentMesh trust metadata.

    Core A2A fields:
        name, description, url, version, skills, capabilities, authentication

    AgentMesh extensions (``x-agentmesh-*``):
        agent_did, trust_score, organization, public_key_fingerprint,
        supported_protocols
    """

    # ---- A2A core fields ----
    name: str
    description: str = ""
    url: str = ""
    version: str = "1.0.0"
    skills: List[AgentSkill] = field(default_factory=list)
    capabilities: Dict[str, bool] = field(default_factory=dict)
    authentication: Dict[str, Any] = field(default_factory=dict)

    # ---- AgentMesh extensions ----
    agent_did: str = ""
    trust_score: int = 0
    organization: str = ""
    public_key_fingerprint: str = ""
    supported_protocols: List[str] = field(default_factory=list)

    # ---- Metadata ----
    created_at: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_identity(
        cls,
        *,
        did: str,
        name: str,
        description: str = "",
        capabilities: Optional[List[str]] = None,
        public_key: str = "",
        trust_score: int = 0,
        organization: str = "",
        url: str = "",
    ) -> "AgentCard":
        """
        Create an A2A Agent Card from AgentMesh identity fields.

        ``capabilities`` are mapped to A2A skills (one skill per capability).
        """
        skills = [
            AgentSkill(id=cap, name=cap.replace("_", " ").title())
            for cap in (capabilities or [])
        ]
        fingerprint = ""
        if public_key:
            fingerprint = hashlib.sha256(public_key.encode()).hexdigest()[:16]

        return cls(
            name=name,
            description=description,
            url=url,
            skills=skills,
            agent_did=did,
            trust_score=trust_score,
            organization=organization,
            public_key_fingerprint=fingerprint,
            supported_protocols=["a2a/1.0", "iatp/1.0"],
            capabilities={"streaming": False, "pushNotifications": False},
            authentication={"schemes": ["iatp"]},
        )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to A2A-compliant JSON-ready dict."""
        d: Dict[str, Any] = {
            "name": self.name,
            "version": self.version,
        }
        if self.description:
            d["description"] = self.description
        if self.url:
            d["url"] = self.url
        if self.skills:
            d["skills"] = [s.to_dict() for s in self.skills]
        if self.capabilities:
            d["capabilities"] = self.capabilities
        if self.authentication:
            d["authentication"] = self.authentication

        # AgentMesh extensions
        extensions: Dict[str, Any] = {}
        if self.agent_did:
            extensions["x-agentmesh-did"] = self.agent_did
        if self.trust_score:
            extensions["x-agentmesh-trust-score"] = self.trust_score
        if self.organization:
            extensions["x-agentmesh-organization"] = self.organization
        if self.public_key_fingerprint:
            extensions["x-agentmesh-public-key-fingerprint"] = self.public_key_fingerprint
        if self.supported_protocols:
            extensions["x-agentmesh-protocols"] = self.supported_protocols
        if extensions:
            d.update(extensions)

        return d

    def to_json(self, indent: int = 2) -> str:
        """Serialise to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentCard":
        """Deserialise from a dict (e.g. fetched from ``/.well-known/agent.json``)."""
        skills = [
            AgentSkill(
                id=s["id"],
                name=s["name"],
                description=s.get("description", ""),
                tags=s.get("tags", []),
                input_modes=s.get("inputModes", ["text/plain"]),
                output_modes=s.get("outputModes", ["text/plain"]),
                examples=s.get("examples", []),
            )
            for s in data.get("skills", [])
        ]
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            url=data.get("url", ""),
            version=data.get("version", "1.0.0"),
            skills=skills,
            capabilities=data.get("capabilities", {}),
            authentication=data.get("authentication", {}),
            agent_did=data.get("x-agentmesh-did", ""),
            trust_score=data.get("x-agentmesh-trust-score", 0),
            organization=data.get("x-agentmesh-organization", ""),
            public_key_fingerprint=data.get("x-agentmesh-public-key-fingerprint", ""),
            supported_protocols=data.get("x-agentmesh-protocols", []),
        )

    def has_skill(self, skill_id: str) -> bool:
        """Check if agent advertises a specific skill."""
        return any(s.id == skill_id for s in self.skills)

    def skill_ids(self) -> List[str]:
        """Return list of skill IDs."""
        return [s.id for s in self.skills]
