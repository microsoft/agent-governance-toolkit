# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Governance & Compliance Plane (Layer 3)

Declarative policy engine with automated compliance mapping.
Append-only audit logs with optional external sinks.
"""

from .async_policy_evaluator import AsyncTrustPolicyEvaluator
from .async_policy_evaluator import ConcurrencyStats as TrustConcurrencyStats
from .audit import AuditChain, AuditEntry, AuditLog
from .audit_backends import (
    AuditSink,
    FileAuditSink,
    HashChainVerifier,
    SignedAuditEntry,
)
from .authority import (
    ActionRequest,
    AuthorityDecision,
    AuthorityRequest,
    AuthorityResolver,
    DefaultAuthorityResolver,
    DelegationInfo,
    TrustInfo,
)
from .cedar import CedarDecision, CedarEvaluator, load_cedar_into_engine
from .compliance import ComplianceEngine, ComplianceFramework, ComplianceReport
from .conflict_resolution import (
    CandidateDecision,
    ConflictResolutionStrategy,
    PolicyConflictResolver,
    PolicyScope,
    ResolutionResult,
)
from .opa import OPADecision, OPAEvaluator, load_rego_into_engine
from .policy import Policy, PolicyDecision, PolicyEngine, PolicyRule
from .policy_evaluator import PolicyEvaluator, TrustPolicyDecision
from .shadow import ShadowMode, ShadowResult
from .trust_policy import (
    ConditionOperator,
    TrustCondition,
    TrustDefaults,
    TrustPolicy,
    TrustRule,
    load_policies,
)

__all__ = [
    "AsyncTrustPolicyEvaluator",
    "TrustConcurrencyStats",
    "PolicyEngine",
    "Policy",
    "PolicyRule",
    "PolicyDecision",
    "ConflictResolutionStrategy",
    "PolicyScope",
    "PolicyConflictResolver",
    "CandidateDecision",
    "ResolutionResult",
    "ComplianceEngine",
    "ComplianceFramework",
    "ComplianceReport",
    "AuditLog",
    "AuditEntry",
    "AuditChain",
    "AuditSink",
    "SignedAuditEntry",
    "FileAuditSink",
    "HashChainVerifier",
    "ShadowMode",
    "ShadowResult",
    "OPAEvaluator",
    "OPADecision",
    "load_rego_into_engine",
    "CedarEvaluator",
    "CedarDecision",
    "load_cedar_into_engine",
    "AuthorityDecision",
    "AuthorityRequest",
    "AuthorityResolver",
    "ActionRequest",
    "DefaultAuthorityResolver",
    "DelegationInfo",
    "TrustInfo",
    "TrustPolicy",
    "TrustRule",
    "TrustCondition",
    "TrustDefaults",
    "ConditionOperator",
    "load_policies",
    "PolicyEvaluator",
    "TrustPolicyDecision",
]
