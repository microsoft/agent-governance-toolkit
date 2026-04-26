# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Manifest Schema

Defines the complete identity and capability manifest for Nexus registration.
Extends the IATP manifest (RFC-001) with Nexus-specific fields.
"""

from datetime import datetime, timezone
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator
import re


class AgentIdentity(BaseModel):
    """Decentralized identity for an agent."""
    
    did: str = Field(
        ...,
        description="Decentralized Identifier (did:nexus:...)",
        examples=["did:nexus:carbon-auditor-v1.2.0"]
    )
    verification_key: str = Field(
        ...,
        description="Ed25519 public key (base64 encoded)",
        examples=["ed25519:abc123..."]
    )
    owner_id: str = Field(
        ...,
        description="Developer/Organization ID"
    )
    display_name: Optional[str] = Field(
        None,
        description="Human-readable agent name"
    )
    contact: Optional[str] = Field(
        None,
        description="Contact email for security issues"
    )
    
    @field_validator("did")
    @classmethod
    def validate_did(cls, v: str) -> str:
        """Validate DID format."""
        if not v.startswith("did:nexus:"):
            raise ValueError("DID must start with 'did:nexus:'")
        return v
    
    @field_validator("verification_key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        """Validate verification key format."""
        if not v.startswith("ed25519:"):
            raise ValueError("Verification key must be Ed25519 format")
        return v


class AgentCapabilities(BaseModel):
    """What this agent can do."""
    
    domains: list[str] = Field(
        default_factory=list,
        description="Capability domains (e.g., 'data-analysis', 'code-generation')"
    )
    tools: list[str] = Field(
        default_factory=list,
        description="Available tool names"
    )
    max_concurrency: int = Field(
        default=10,
        ge=1,
        le=1000,
        description="Maximum concurrent requests"
    )
    sla_latency_ms: int = Field(
        default=5000,
        ge=100,
        le=300000,
        description="SLA latency in milliseconds"
    )
    idempotency: bool = Field(
        default=False,
        description="Whether operations are idempotent"
    )
    reversibility: Literal["full", "partial", "none"] = Field(
        default="partial",
        description="Level of operation reversibility"
    )
    undo_window_seconds: Optional[int] = Field(
        default=3600,
        description="Time window for undo operations (if reversible)"
    )


class AgentPrivacy(BaseModel):
    """Privacy and data handling policies."""
    
    retention_policy: Literal["ephemeral", "session", "permanent"] = Field(
        default="ephemeral",
        description="How long data is retained"
    )
    pii_handling: Literal["reject", "anonymize", "accept"] = Field(
        default="reject",
        description="How PII is handled"
    )
    human_in_loop: bool = Field(
        default=False,
        description="Whether human review is part of processing"
    )
    training_consent: bool = Field(
        default=False,
        description="Whether data may be used for training"
    )
    data_residency: Optional[str] = Field(
        default=None,
        description="Required data residency region (e.g., 'us', 'eu')"
    )


class MuteRules(BaseModel):
    """Agent OS Mute Agent rules attached to this agent."""
    
    rule_hashes: list[str] = Field(
        default_factory=list,
        description="SHA-256 hashes of attached mute rules"
    )
    last_validated: Optional[datetime] = Field(
        default=None,
        description="When rules were last validated by Control Plane"
    )
    control_plane_signature: Optional[str] = Field(
        default=None,
        description="Control Plane signature of rule validation"
    )


class AgentManifest(BaseModel):
    """
    Complete manifest for Nexus registration.
    
    This extends the IATP manifest (RFC-001) with Nexus-specific fields
    for the Trust Exchange.
    """
    
    schema_version: str = Field(
        default="1.0",
        description="Schema version for forward compatibility"
    )
    identity: AgentIdentity
    capabilities: AgentCapabilities = Field(default_factory=AgentCapabilities)
    privacy: AgentPrivacy = Field(default_factory=AgentPrivacy)
    mute_rules: MuteRules = Field(default_factory=MuteRules)
    
    # Nexus-specific fields
    verification_level: Literal["verified_partner", "verified", "registered", "unknown"] = Field(
        default="registered",
        description="Verification tier on Nexus"
    )
    registered_at: Optional[datetime] = Field(
        default=None,
        description="When agent was registered on Nexus"
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="Last activity timestamp"
    )
    trust_score: int = Field(
        default=400,
        ge=0,
        le=1000,
        description="Current trust score (0-1000)"
    )
    
    # Attestation
    codebase_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of agent codebase"
    )
    config_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of agent configuration"
    )
    attestation_signature: Optional[str] = Field(
        default=None,
        description="Control Plane signature of attestation"
    )
    attestation_expires: Optional[datetime] = Field(
        default=None,
        description="When attestation expires"
    )
    
    def is_attestation_valid(self) -> bool:
        """Check if attestation is present and not expired."""
        if not self.attestation_signature or not self.attestation_expires:
            return False
        return datetime.now(timezone.utc) < self.attestation_expires
    
    def to_iatp_manifest(self) -> dict:
        """Convert to IATP-compatible manifest format."""
        return {
            "$schema": "https://agent-os.dev/iatp/v1/manifest.schema.json",
            "identity": {
                "agent_id": self.identity.did.replace("did:nexus:", ""),
                "verification_key": self.identity.verification_key,
                "owner": self.identity.owner_id,
                "contact": self.identity.contact,
            },
            "trust_level": self.verification_level,
            "capabilities": {
                "idempotency": self.capabilities.idempotency,
                "max_concurrency": self.capabilities.max_concurrency,
                "sla_latency_ms": self.capabilities.sla_latency_ms,
            },
            "reversibility": {
                "level": self.capabilities.reversibility,
                "undo_window_seconds": self.capabilities.undo_window_seconds,
            },
            "privacy": {
                "retention_policy": self.privacy.retention_policy,
                "human_in_loop": self.privacy.human_in_loop,
                "training_consent": self.privacy.training_consent,
            },
            "protocol_version": "1.0",
        }
