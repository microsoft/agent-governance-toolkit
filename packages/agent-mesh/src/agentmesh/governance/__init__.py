# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Governance & Compliance Plane (Layer 3)

Declarative policy engine with automated compliance mapping.
Append-only audit logs.
"""

from .policy import PolicyEngine, Policy, PolicyRule, PolicyDecision
from .compliance import ComplianceEngine, ComplianceFramework, ComplianceReport
from .audit import AuditLog, AuditEntry, AuditChain
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
from .policy_evaluator import PolicyEvaluator, TrustPolicyDecision

__all__ = [
    "PolicyEngine",
    "Policy",
    "PolicyRule",
    "PolicyDecision",
    "ComplianceEngine",
    "ComplianceFramework",
    "ComplianceReport",
    "AuditLog",
    "AuditEntry",
    "AuditChain",
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
