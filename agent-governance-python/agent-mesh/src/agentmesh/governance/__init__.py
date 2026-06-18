# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Governance & Compliance Plane (Layer 3)

Declarative policy engine with automated compliance mapping.
Append-only audit logs with optional external sinks.
"""
from .govern import govern, GovernedCallable, GovernanceConfig, GovernanceDenied
from .trace_sink import TraceConfig, TRACEAuditSink
from hypervisor.models import ExecutionRing
from hypervisor.rings.enforcer import ResourceConstraints, ResourceType, RING_CONSTRAINTS, RingCheckResult
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
from .session_state import SessionState, SessionAttribute
from .otel_observability import (
    enable_otel,
    trace_policy_evaluation,
    trace_approval,
    trace_trust_verification,
    record_denial,
)
from .advisory import (
    AdvisoryCheck,
    AdvisoryDecision,
    CallbackAdvisory,
    HttpAdvisory,
    PatternAdvisory,
    CompositeAdvisory,
)
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
    StdoutAuditSink,
)
from .shadow import ShadowMode, ShadowResult
from .backend import ExternalPolicyBackend, PolicyDecisionResult, BackendRegistry
from .opa import OPAEvaluator, OPADecision, OPAPolicyBackend, load_rego_into_engine
from .cedar import CedarEvaluator, CedarDecision, CedarPolicyBackend, load_cedar_into_engine
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
from .protocol_facets import (
    FacetRegistry,
    extract_protocol_facets,
    default_registry,
)
from .trace_model import (
    TraceModelConfig,
    TraceSession,
    TrustRecord,
    session_to_trust_record,
)

__all__ = [
    # High-level wrapper (issue #1372)
    "govern",
    "GovernedCallable",
    "GovernanceConfig",
    "GovernanceDenied",
    # TRACE Trust Record emission (ADR-0032)
    "TraceConfig",
    "TRACEAuditSink",
    # Ring enforcement (issue #2667)
    "ExecutionRing",
    "ResourceConstraints",
    "ResourceType",
    "RING_CONSTRAINTS",
    "RingCheckResult",
    # Approval workflows (issue #1374)
    "ApprovalHandler",
    "ApprovalRequest",
    "ApprovalDecision",
    "AutoRejectApproval",
    "CallbackApproval",
    "ConsoleApproval",
    "WebhookApproval",
    # Session state / attribute ratchets (issue #1375)
    "SessionState",
    "SessionAttribute",
    # OTel observability (issue #1376)
    "enable_otel",
    "trace_policy_evaluation",
    "trace_approval",
    "trace_trust_verification",
    "record_denial",
    # Advisory layer (issue #1377)
    "AdvisoryCheck",
    "AdvisoryDecision",
    "CallbackAdvisory",
    "HttpAdvisory",
    "PatternAdvisory",
    "CompositeAdvisory",
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
    "StdoutAuditSink",
    "ShadowMode",
    "ShadowResult",
    "OPAEvaluator",
    "OPADecision",
    "OPAPolicyBackend",
    "load_rego_into_engine",
    "CedarEvaluator",
    "CedarDecision",
    "CedarPolicyBackend",
    "load_cedar_into_engine",
    # External policy backend protocol (issue #2280)
    "ExternalPolicyBackend",
    "PolicyDecisionResult",
    "BackendRegistry",
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
    # Wire protocol facets (issue #2483)
    "FacetRegistry",
    "extract_protocol_facets",
    "default_registry",
    # TRACE v0.2 Trust Record model (ADR-0032, issue #3086)
    "TraceModelConfig",
    "TraceSession",
    "TrustRecord",
    "session_to_trust_record",
]

