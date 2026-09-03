"""Impact report models."""
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class TransitionCounts(BaseModel):
    admissible_to_inadmissible: int = 0
    inadmissible_to_admissible: int = 0
    unchanged: int = 0
    invalidated: int = 0


class BlastRadius(BaseModel):
    agents_affected: List[str] = Field(default_factory=list)
    tools_affected: List[str] = Field(default_factory=list)
    policy_versions_affected: List[str] = Field(default_factory=list)
    decision_types_affected: List[str] = Field(default_factory=list)


class ImpactReport(BaseModel):
    """Complete report of a governance change impact analysis."""
    change_description: str
    baseline_policy_version: str
    proposed_policy_version: str
    total_traces_analyzed: int
    total_decisions_evaluated: int
    transitions: TransitionCounts = Field(default_factory=TransitionCounts)
    blast_radius: BlastRadius = Field(default_factory=BlastRadius)
    estimated_exposure: float = 0.0
    impact_rate: float = 0.0
    severity: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    recommendation: str = "ALLOW"  # ALLOW, REVIEW, BLOCK
    primary_regression: str = ""
    per_decision_explanations: Dict[str, str] = Field(default_factory=dict)
    report_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))