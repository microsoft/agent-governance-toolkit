# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Compliance Schemas

Defines data structures for compliance auditing and reporting.
Supports SOC2, HIPAA, and other regulatory frameworks.
"""

from datetime import datetime
from typing import Literal, Optional, Any
from pydantic import BaseModel, Field
import hashlib
import json


class ComplianceRecord(BaseModel):
    """A single compliance-auditable event."""
    
    event_id: str = Field(
        ...,
        description="Unique event identifier"
    )
    event_type: Literal[
        "agent_registered",
        "agent_updated",
        "agent_deregistered",
        "iatp_handshake",
        "iatp_rejected",
        "escrow_created",
        "escrow_released",
        "escrow_refunded",
        "escrow_disputed",
        "dispute_resolved",
        "reputation_updated",
        "reputation_slashed",
        "mute_triggered",
        "policy_signed",
        "data_accessed",
    ] = Field(
        ...,
        description="Type of compliance event"
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the event occurred"
    )
    
    # Participants
    requester_did: Optional[str] = Field(
        default=None,
        description="DID of the requesting agent"
    )
    provider_did: Optional[str] = Field(
        default=None,
        description="DID of the providing agent"
    )
    organization_id: Optional[str] = Field(
        default=None,
        description="Organization that owns the agent(s)"
    )
    
    # Event details (no PII - only metadata)
    operation_type: Optional[str] = Field(
        default=None,
        description="Type of operation performed"
    )
    data_classification: Optional[Literal["public", "internal", "confidential", "pii"]] = Field(
        default=None,
        description="Classification of data involved"
    )
    duration_ms: Optional[int] = Field(
        default=None,
        ge=0,
        description="Duration of operation"
    )
    outcome: Optional[str] = Field(
        default=None,
        description="Outcome of the operation"
    )
    
    # Policy compliance
    policy_signed: Optional[str] = Field(
        default=None,
        description="Hash of signed data handling policy"
    )
    retention_policy: Optional[str] = Field(
        default=None,
        description="Data retention policy applied"
    )
    
    # Cryptographic attestation
    signature: Optional[str] = Field(
        default=None,
        description="Ed25519 signature of the record"
    )
    previous_event_hash: Optional[str] = Field(
        default=None,
        description="Hash of previous event (blockchain-style chaining)"
    )
    
    # Tracing
    trace_id: Optional[str] = Field(
        default=None,
        description="Distributed tracing ID"
    )
    
    def compute_hash(self) -> str:
        """Compute deterministic hash of this record."""
        data = self.model_dump(exclude={"signature"})
        # Convert datetime to ISO format for deterministic hashing
        if data.get("timestamp"):
            data["timestamp"] = data["timestamp"].isoformat()
        canonical = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


class ComplianceEventFilter(BaseModel):
    """Filter criteria for querying compliance events."""
    
    organization_id: Optional[str] = None
    agent_did: Optional[str] = None
    event_types: Optional[list[str]] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    data_classification: Optional[str] = None
    outcome: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=10000)
    offset: int = Field(default=0, ge=0)


class ComplianceStats(BaseModel):
    """Aggregated compliance statistics."""
    
    total_events: int
    events_by_type: dict[str, int]
    events_by_outcome: dict[str, int]
    events_by_classification: dict[str, int]
    
    # Agent metrics
    unique_agents: int
    total_handshakes: int
    rejected_handshakes: int
    rejection_rate: float
    
    # Escrow metrics
    total_escrows: int
    successful_escrows: int
    disputed_escrows: int
    dispute_rate: float
    
    # Reputation metrics
    reputation_slashes: int
    mute_triggers: int
    
    # Time range
    start_date: datetime
    end_date: datetime


class ComplianceAuditReport(BaseModel):
    """
    Complete compliance audit report for regulatory review.
    
    Designed for SOC2, HIPAA, and similar frameworks.
    """
    
    report_id: str = Field(
        ...,
        description="Unique report identifier"
    )
    report_type: Literal["soc2", "hipaa", "gdpr", "custom"] = Field(
        ...,
        description="Compliance framework"
    )
    generated_at: datetime = Field(
        default_factory=datetime.utcnow
    )
    
    # Scope
    organization_id: str = Field(
        ...,
        description="Organization being audited"
    )
    start_date: datetime = Field(
        ...,
        description="Audit period start"
    )
    end_date: datetime = Field(
        ...,
        description="Audit period end"
    )
    
    # Summary
    executive_summary: str = Field(
        ...,
        description="High-level summary of compliance status"
    )
    stats: ComplianceStats = Field(
        ...,
        description="Aggregated statistics"
    )
    
    # Events
    events: list[ComplianceRecord] = Field(
        default_factory=list,
        description="All compliance events in period"
    )
    
    # Findings
    violations: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Compliance violations found"
    )
    warnings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Compliance warnings"
    )
    recommendations: list[str] = Field(
        default_factory=list,
        description="Recommendations for improvement"
    )
    
    # Attestation
    report_hash: Optional[str] = Field(
        default=None,
        description="Hash of complete report"
    )
    nexus_signature: Optional[str] = Field(
        default=None,
        description="Nexus signature attesting to report"
    )
    
    def compute_hash(self) -> str:
        """Compute hash of the report for integrity verification."""
        data = self.model_dump(exclude={"report_hash", "nexus_signature"})
        canonical = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


class DataHandlingAudit(BaseModel):
    """Audit record for data handling policy compliance."""
    
    audit_id: str
    escrow_id: str
    
    # Policy details
    policy_hash: str = Field(
        ...,
        description="Hash of the signed data handling policy"
    )
    max_retention_seconds: int
    allow_persistence: bool
    allow_training: bool
    allow_forwarding: bool
    
    # Compliance checks
    policy_signed: bool = Field(
        ...,
        description="Whether policy was signed before data access"
    )
    policy_signed_at: Optional[datetime] = None
    signer_did: str
    
    # Verification
    data_deleted_on_schedule: Optional[bool] = Field(
        default=None,
        description="Whether data was deleted per retention policy"
    )
    deletion_verified_at: Optional[datetime] = None
    
    # Violations
    violations_detected: list[str] = Field(
        default_factory=list,
        description="Any policy violations detected"
    )
