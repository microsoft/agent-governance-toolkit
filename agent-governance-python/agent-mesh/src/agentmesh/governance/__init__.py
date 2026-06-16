# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Governance & Compliance Plane (Layer 3)
"""

from .govern import govern, GovernedCallable, GovernanceConfig, GovernanceDenied
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

# ---------- NEW IMPORTS for continuity ----------
from agent_os.continuity import ContinuityVerifier
from agent_os.exceptions import GovernanceDenied as AGT_GovernanceDenied
from agent_os.policy_engine import PolicyEngine as AGT_PolicyEngine
from agentmesh.continuity_helpers import get_execution_context
# -------------------------------------------------

import logging
from functools import wraps
from typing import Any, Callable, Dict, Optional, Union

__all__ = [
    # High-level wrapper (issue #1372)
    "govern",
    "GovernedCallable",
    "GovernanceConfig",
    "GovernanceDenied",
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
]

logger = logging.getLogger(__name__)

# ---------- NEW govern function (overrides imported one) ----------
def govern(
    tool_func: Callable,
    policy: Union[AGT_PolicyEngine, Dict, str],
    *,
    enable_continuity: bool = False,
    enforcement_mode: str = "enforce",
) -> Callable:
    if not isinstance(policy, AGT_PolicyEngine):
        policy = AGT_PolicyEngine.from_dict(policy) if isinstance(policy, dict) else AGT_PolicyEngine()

    @wraps(tool_func)
    def wrapper(*args, **kwargs):
        verifier = None
        if enable_continuity:
            verifier = ContinuityVerifier(execution_id=f"{tool_func.__name__}-{id(tool_func)}")
            ctx = get_execution_context()
            verifier.capture_pre_state(**ctx)

        action_context = {"action": kwargs.get("action", tool_func.__name__), "args": args, "kwargs": kwargs}
        decision = policy.evaluate(action_context)
        if decision != "allow":
            raise AGT_GovernanceDenied(f"Policy denied: {decision}")

        try:
            result = tool_func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Tool execution failed: {e}")
            raise

        if verifier is not None:
            ctx = get_execution_context()
            trace = verifier.capture_post_state(**ctx)
            if not trace.admissible:
                msg = f"Continuity drift: {trace.diff}"
                if enforcement_mode == "enforce":
                    raise AGT_GovernanceDenied(msg)
                else:
                    logger.warning(msg)
        return result

    return wrapper
# ---------------------------------------------------------------