"""Governance state and admissibility model."""
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class GovernanceDimension(str, Enum):
    POLICY = "policy"
    AUTHORITY = "authority"
    EVIDENCE = "evidence"
    CAPABILITY = "capability"
    MODEL = "model"
    CONTEXT = "context"


class GovernanceState(BaseModel):
    """Snapshot of all governance dimensions at a point in time."""
    policy_version: str
    policy_valid: bool = True
    authority_valid: bool = True
    authority_chain: List[str] = Field(default_factory=list)
    evidence_fresh: bool = True
    evidence_age_hours: float = 0.0
    capability_authorized: bool = True
    tool_permissions: List[str] = Field(default_factory=list)
    model_approved: bool = True
    model_version: str = ""
    context_valid: bool = True

    # Overall admissibility
    is_admissible: bool = True
    reason: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = Field(default_factory=dict)

    def mark_inadmissible(self, reason: str) -> None:
        """Mark this state as inadmissible with a reason."""
        self.is_admissible = False
        self.reason = reason