# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Governance & Compliance Plane (Layer 3)

Declarative policy engine with automated compliance mapping.
Append-only audit logs with optional external sinks.
"""

from .govern import govern, GovernedCallable, GovernanceConfig, GovernanceDenied
from .approval import (
    ApprovalHandler,
    ApprovalRequest,
    ApprovalDecision,
    AutoRejectApproval,
    CallbackApproval,
    ConsoleApproval,
    WebhookApproval,
)
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
from .cedar import CedarEvaluator, CedarDecision, load_cedar_into_engine
from .authority import (
    AuthorityDecision,
    AuthorityRequest,
    AuthorityResolver,
    ActionRequest,
    DefaultAuthorityResolver,
    DelegationInfo,
    TrustInfo,
)
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
from .annex_iv import (
    AnnexIVDocument,
    AnnexIVSection,
    TechnicalDocumentationExporter,
    to_json as annex_iv_to_json,
    to_markdown as annex_iv_to_markdown,
)
from .eu_ai_act import (
    RiskLevel,
    AgentRiskProfile,
    ClassificationResult,
    EUAIActRiskClassifier,
)
from .federation import (
    PolicyCategory,
    OrgPolicyRule,
    DataClassification,
    OrgPolicy,
    OrgPolicyDecision,
    OrgTrustAgreement,
    PolicyDelegation,
    FederationDecision,
    FederationStore,
    InMemoryFederationStore,
    FileFederationStore,
    FederationEngine,
)

__all__ = [
    # High-level wrapper (issue #1372)
    "govern",
    "GovernedCallable",
    "GovernanceConfig",
    "GovernanceDenied",
    # Approval workflows (issue #1374)
    "ApprovalHandler",
    "ApprovalRequest",
    "ApprovalDecision",
    "AutoRejectApproval",
    "CallbackApproval",
    "ConsoleApproval",
    "WebhookApproval",
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
    # Federation (issue #93)
    "PolicyCategory",
    "OrgPolicyRule",
    "DataClassification",
    "OrgPolicy",
    "OrgPolicyDecision",
    "OrgTrustAgreement",
    "PolicyDelegation",
    "FederationDecision",
    "FederationStore",
    "InMemoryFederationStore",
    "FileFederationStore",
    "FederationEngine",
    # Annex IV Technical Documentation (issue #757)
    "AnnexIVDocument",
    "AnnexIVSection",
    "TechnicalDocumentationExporter",
    "annex_iv_to_json",
    "annex_iv_to_markdown",
    # EU AI Act risk classifier (issue #756)
    "RiskLevel",
    "AgentRiskProfile",
    "ClassificationResult",
    "EUAIActRiskClassifier",
]

