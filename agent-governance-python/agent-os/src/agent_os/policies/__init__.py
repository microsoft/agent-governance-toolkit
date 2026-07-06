# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Declarative policy language for Agent-OS governance.

Separates policy rules (YAML/JSON data) from evaluation logic,
enabling policies to be authored, versioned, and shared as plain files.
"""

from .async_evaluator import AsyncPolicyEvaluator, ConcurrencyStats
from .backends import (
    BackendDecision,
    CedarBackend,
    ExternalPolicyBackend,
    OPABackend,
)
from .bridge import document_to_governance, governance_to_document
from .conflict_resolution import (
    CandidateDecision,
    ConflictResolutionStrategy,
    PolicyConflictResolver,
    PolicyScope,
    ResolutionResult,
)
from .context_accumulation import (
    ContextDecision,
    ContextOutcome,
    accumulate,
    decide_next,
    to_policy_action,
)
from .context_aggregation import (
    AggregationResult,
    AggregationRule,
    AggregationRuleSet,
    evaluate_aggregation,
)
from .context_audit import ContextEvent, context_event
from .context_delegation import merge_restrictions
from .context_envelope import (
    ContextEnvelope,
    EnvelopeReference,
    apply_restrictions,
    envelope_reference,
    fold,
)
from .decision import PolicyCheckResult, ViolationCategory
from .dynamic_context import (
    CostContext,
    DynamicContext,
    QuotaContext,
    SystemContext,
    TimeContext,
)
from .evaluator import PolicyDecision, PolicyEvaluator
from .obligations import Obligation, ObligationSet
from .rate_limiting import RateLimitConfig, RateLimitExceeded, TokenBucket
from .schema import (
    DynamicCondition,
    DynamicConditionType,
    PolicyAction,
    PolicyCondition,
    PolicyDefaults,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
    SandboxMounts,
)
from .shared import (
    Condition,
    SharedPolicyDecision,
    SharedPolicyEvaluator,
    SharedPolicyRule,
    SharedPolicySchema,
    policy_document_to_shared,
    shared_to_policy_document,
)

__all__ = [
    "AggregationResult",
    "AggregationRule",
    "AggregationRuleSet",
    "AsyncPolicyEvaluator",
    "BackendDecision",
    "CandidateDecision",
    "CedarBackend",
    "ConcurrencyStats",
    "Condition",
    "ConflictResolutionStrategy",
    "DynamicCondition",
    "DynamicConditionType",
    "ContextDecision",
    "ContextEnvelope",
    "ContextEvent",
    "ContextOutcome",
    "EnvelopeReference",
    "Obligation",
    "ObligationSet",
    "accumulate",
    "apply_restrictions",
    "context_event",
    "decide_next",
    "envelope_reference",
    "evaluate_aggregation",
    "fold",
    "merge_restrictions",
    "to_policy_action",
    "ExternalPolicyBackend",
    "OPABackend",
    "CostContext",
    "DynamicContext",
    "QuotaContext",
    "SystemContext",
    "TimeContext",
    "PolicyAction",
    "PolicyCheckResult",
    "PolicyCondition",
    "PolicyConflictResolver",
    "PolicyDecision",
    "PolicyDefaults",
    "PolicyDocument",
    "PolicyEvaluator",
    "PolicyOperator",
    "PolicyRule",
    "PolicyScope",
    "RateLimitConfig",
    "RateLimitExceeded",
    "ResolutionResult",
    "SandboxMounts",
    "TokenBucket",
    "ViolationCategory",
    "SharedPolicyDecision",
    "SharedPolicyEvaluator",
    "SharedPolicyRule",
    "SharedPolicySchema",
    "document_to_governance",
    "governance_to_document",
    "policy_document_to_shared",
    "shared_to_policy_document",
]
