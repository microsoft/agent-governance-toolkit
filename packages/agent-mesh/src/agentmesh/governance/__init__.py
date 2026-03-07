# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Governance & Compliance Plane (Layer 3)

Declarative policy engine with automated compliance mapping.
Append-only audit logs with optional external sinks.
"""

from .policy import PolicyEngine, Policy, PolicyRule, PolicyDecision
from .conflict_resolution import (
    ConflictResolutionStrategy,
    PolicyScope,
    PolicyConflictResolver,
    CandidateDecision,
    ResolutionResult,
)
from .compliance import ComplianceEngine, ComplianceFramework, ComplianceReport
from .audit import AuditLog, AuditEntry, AuditChain
from .audit_backends import (
    AuditSink,
    SignedAuditEntry,
    FileAuditSink,
    HashChainVerifier,
)
from .shadow import ShadowMode, ShadowResult
from .opa import OPAEvaluator, OPADecision, load_rego_into_engine
from .trust_policy import (
    TrustPolicy,
    TrustRule,
    TrustCondition,
    TrustDefaults,
    ConditionOperator,
    load_policies,
)
from .async_policy_evaluator import AsyncTrustPolicyEvaluator
from .async_policy_evaluator import ConcurrencyStats as TrustConcurrencyStats
from .policy_evaluator import PolicyEvaluator, TrustPolicyDecision

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
    "TrustPolicy",
    "TrustRule",
    "TrustCondition",
    "TrustDefaults",
    "ConditionOperator",
    "load_policies",
    "PolicyEvaluator",
    "TrustPolicyDecision",
]
