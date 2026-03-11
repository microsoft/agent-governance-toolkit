"""openai-agents-trust: Trust & governance layer for OpenAI Agents SDK."""

from .guardrails import (
    trust_input_guardrail,
    policy_input_guardrail,
    content_output_guardrail,
    TrustGuardrailConfig,
    PolicyGuardrailConfig,
)
from .hooks import GovernanceHooks
from .handoffs import trust_gated_handoff
from .identity import AgentIdentity
from .trust import TrustScorer, TrustScore
from .policy import GovernancePolicy
from .audit import AuditLog, AuditEntry

__all__ = [
    "trust_input_guardrail",
    "policy_input_guardrail",
    "content_output_guardrail",
    "TrustGuardrailConfig",
    "PolicyGuardrailConfig",
    "GovernanceHooks",
    "trust_gated_handoff",
    "AgentIdentity",
    "TrustScorer",
    "TrustScore",
    "GovernancePolicy",
    "AuditLog",
    "AuditEntry",
]

__version__ = "0.1.0"
