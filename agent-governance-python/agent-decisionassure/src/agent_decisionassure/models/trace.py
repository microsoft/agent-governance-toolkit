"""Decision trace models extracted from production audit logs."""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, UUID4, Field


class Action(BaseModel):
    """An action that was taken by an agent."""
    id: UUID4
    name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    tool: str
    version: str
    transaction_amount: Optional[float] = None


class DecisionTrace(BaseModel):
    """A single governance decision from production, with full context."""
    action: Action
    agent_id: UUID4
    agent_version: str
    timestamp: datetime
    policy_version: str
    authority_chain: List[str] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    evidence_used: List[UUID4] = Field(default_factory=list)
    evidence_age_hours: float = 0.0
    tool_permissions_at_time: List[str] = Field(default_factory=list)
    model_version: str = ""
    result: str  # 'ALLOW' or 'DENY' from runtime


class TraceBatch(BaseModel):
    """A batch of decisions from a single trace."""
    trace_id: UUID4
    decisions: List[DecisionTrace]
    environment: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)