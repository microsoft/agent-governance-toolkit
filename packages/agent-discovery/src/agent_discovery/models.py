"""Data models for agent discovery.

All models use Pydantic v2 for validation and serialization.
Evidence-based discovery: every finding carries its provenance, confidence,
and detection basis so consumers can filter noise and deduplicate.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DetectionBasis(str, Enum):
    """How the agent was detected."""

    PROCESS = "process"
    GITHUB_REPO = "github_repo"
    CONFIG_FILE = "config_file"
    KUBERNETES = "kubernetes"
    AZURE = "azure"
    NETWORK = "network"
    MANUAL = "manual"


class AgentStatus(str, Enum):
    """Governance status of a discovered agent."""

    REGISTERED = "registered"
    UNREGISTERED = "unregistered"
    SHADOW = "shadow"
    DECOMMISSIONED = "decommissioned"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk classification for ungoverned agents."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Evidence(BaseModel):
    """A single piece of evidence supporting agent discovery."""

    scanner: str = Field(description="Scanner that produced this evidence")
    basis: DetectionBasis = Field(description="Detection method")
    source: str = Field(description="Where the evidence was found (path, URL, PID, etc.)")
    detail: str = Field(description="Human-readable description")
    raw_data: dict[str, Any] = Field(
        default_factory=dict, description="Structured data from the scanner (secrets redacted)"
    )
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence score (0.0 = guess, 1.0 = certain)"
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DiscoveredAgent(BaseModel):
    """An AI agent discovered during scanning.

    A logical agent may have multiple observations from different scanners.
    The `fingerprint` field is the deduplication key — observations with the
    same fingerprint are merged into a single DiscoveredAgent.
    """

    fingerprint: str = Field(description="Stable dedup key (hash of merge keys)")
    name: str = Field(description="Best-guess name for the agent")
    agent_type: str = Field(default="unknown", description="Agent type/framework if detectable")
    description: str = Field(default="", description="What this agent appears to do")

    # Identity linkage
    did: str | None = Field(default=None, description="DID if registered with AgentMesh")
    spiffe_id: str | None = Field(default=None, description="SPIFFE ID if available")
    owner: str | None = Field(default=None, description="Human or team owner if determinable")

    # Governance status
    status: AgentStatus = Field(default=AgentStatus.UNKNOWN)

    # Evidence chain — every observation that supports this finding
    evidence: list[Evidence] = Field(default_factory=list)

    # Aggregate confidence (max of all evidence)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)

    # Merge keys — used for deduplication across scanners
    merge_keys: dict[str, str] = Field(
        default_factory=dict,
        description="Stable identifiers: repo+path, image_digest, pid+exe, endpoint+cert, etc.",
    )

    # Timestamps
    first_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Tags for filtering
    tags: dict[str, str] = Field(default_factory=dict)

    def add_evidence(self, ev: Evidence) -> None:
        """Add an observation and update aggregate confidence."""
        self.evidence.append(ev)
        self.confidence = max(self.confidence, ev.confidence)
        self.last_seen_at = ev.timestamp

    @staticmethod
    def compute_fingerprint(merge_keys: dict[str, str]) -> str:
        """Compute a stable fingerprint from merge keys."""
        canonical = "|".join(f"{k}={v}" for k, v in sorted(merge_keys.items()))
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]


class ScanResult(BaseModel):
    """Result of a single scanner run."""

    scanner_name: str
    agents: list[DiscoveredAgent] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    scanned_targets: int = 0

    @property
    def agent_count(self) -> int:
        return len(self.agents)


class ShadowAgent(BaseModel):
    """An agent found by discovery but not present in any governance registry."""

    agent: DiscoveredAgent
    risk: RiskAssessment | None = None
    recommended_actions: list[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    """Risk assessment for an ungoverned agent."""

    level: RiskLevel
    score: float = Field(ge=0.0, le=100.0, description="Numeric risk score 0-100")
    factors: list[str] = Field(default_factory=list, description="Contributing risk factors")
    assessed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
