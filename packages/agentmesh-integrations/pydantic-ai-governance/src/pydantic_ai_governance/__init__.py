"""
pydantic-ai-governance: Governance middleware for PydanticAI.

Semantic policy enforcement, trust scoring, and audit trails
for agent tool execution.
"""

from pydantic_ai_governance.policy import (
    GovernancePolicy,
    PatternType,
    GovernanceEventType,
)
from pydantic_ai_governance.decorator import govern
from pydantic_ai_governance.toolset import GovernanceToolset
from pydantic_ai_governance.trust import TrustScore, TrustScorer
from pydantic_ai_governance.intent import SemanticIntent, classify_intent
from pydantic_ai_governance.audit import AuditEntry, AuditTrail

__all__ = [
    "GovernancePolicy",
    "PatternType",
    "GovernanceEventType",
    "govern",
    "GovernanceToolset",
    "TrustScore",
    "TrustScorer",
    "SemanticIntent",
    "classify_intent",
    "AuditEntry",
    "AuditTrail",
]

__version__ = "0.1.0"
