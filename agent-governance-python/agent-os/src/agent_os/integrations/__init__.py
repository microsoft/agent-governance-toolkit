# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent OS Integrations

Adapters to wrap existing agent frameworks with Agent OS governance.

Supported Frameworks:
- LangChain: Chains, Agents, Runnables
- LlamaIndex: Query Engines, Chat Engines, Agents
- CrewAI: Crews and Agents
- AutoGen: Multi-agent conversations
- OpenAI Assistants: Assistants API with tools
- Anthropic Claude: Messages API with tool use
- Google Gemini: GenerativeModel with function calling
- Mistral AI: Chat API with tool calls
- Semantic Kernel: Microsoft's AI orchestration framework
- PydanticAI: Model-agnostic agents with tool governance

Usage:
    # LangChain
    from agent_os.integrations import LangChainKernel
    kernel = LangChainKernel()
    governed_chain = kernel.wrap(my_chain)

    # LlamaIndex
    from agent_os.integrations import LlamaIndexKernel
    kernel = LlamaIndexKernel()
    governed_engine = kernel.wrap(my_query_engine)

    # OpenAI Assistants
    from agent_os.integrations import OpenAIKernel
    kernel = OpenAIKernel()
    governed = kernel.wrap(assistant, client)

    # Semantic Kernel
    from agent_os.integrations import SemanticKernelWrapper
    governed = SemanticKernelWrapper().wrap(sk_kernel)
"""

from agent_os.exceptions import (
    AdapterNotFoundError,
    AdapterTimeoutError,
    AgentOSError,
    BudgetError,
    BudgetExceededError,
    BudgetWarningError,
    ConfigurationError,
    CredentialExpiredError,
    IdentityError,
    IdentityVerificationError,
    IntegrationError,
    InvalidPolicyError,
    MissingConfigError,
    PolicyDeniedError,
    PolicyError,
    PolicyTimeoutError,
    PolicyViolationError,
    RateLimitError,
)

# ---------------------------------------------------------------------------
# Framework adapters are loaded lazily via __getattr__ below to avoid a
# 40-60 s cold-start penalty from eagerly importing heavy SDKs (anthropic,
# google, chromadb, scipy, etc.) that most callers don't need at import time.
# ---------------------------------------------------------------------------

_LAZY_ADAPTER_MAP: dict[str, tuple[str, str]] = {
    # name -> (module, real_name)
    "A2AEvaluation": (".a2a_adapter", "A2AEvaluation"),
    "A2AGovernanceAdapter": (".a2a_adapter", "A2AGovernanceAdapter"),
    "A2APolicy": (".a2a_adapter", "A2APolicy"),
    "AnthropicKernel": (".anthropic_adapter", "AnthropicKernel"),
    "GovernedAnthropicClient": (".anthropic_adapter", "GovernedAnthropicClient"),
    "AnthropicGovernanceHook": (".anthropic_adapter", "GovernanceMessageHook"),
    "AutoGenKernel": (".autogen_adapter", "AutoGenKernel"),
    "AutoGenGovernanceHandler": (".autogen_adapter", "GovernanceInterventionHandler"),
    "CrewAIKernel": (".crewai_adapter", "CrewAIKernel"),
    "CrewAIGovernanceHooks": (".crewai_adapter", "GovernanceHooks"),
    "GeminiKernel": (".gemini_adapter", "GeminiKernel"),
    "GovernedGeminiModel": (".gemini_adapter", "GovernedGeminiModel"),
    "ADKExecutionContext": (".google_adk_adapter", "ADKExecutionContext"),
    "ADKAuditEvent": (".google_adk_adapter", "AuditEvent"),
    "ADKGovernancePlugin": (".google_adk_adapter", "GovernancePlugin"),
    "GoogleADKKernel": (".google_adk_adapter", "GoogleADKKernel"),
    "ADKPolicyConfig": (".google_adk_adapter", "PolicyConfig"),
    "GuardrailsKernel": (".guardrails_adapter", "GuardrailsKernel"),
    "LangChainGovernanceMiddleware": (".langchain_adapter", "GovernanceMiddleware"),
    "LangChainKernel": (".langchain_adapter", "LangChainKernel"),
    "MAFAuditTrailMiddleware": (".maf_adapter", "AuditTrailMiddleware"),
    "MAFCapabilityGuardMiddleware": (".maf_adapter", "CapabilityGuardMiddleware"),
    "MAFGovernancePolicyMiddleware": (".maf_adapter", "GovernancePolicyMiddleware"),
    "MAFRogueDetectionMiddleware": (".maf_adapter", "RogueDetectionMiddleware"),
    "maf_create_governance_middleware": (".maf_adapter", "create_governance_middleware"),
    "FirewallMode": (".llamafirewall", "FirewallMode"),
    "FirewallResult": (".llamafirewall", "FirewallResult"),
    "FirewallVerdict": (".llamafirewall", "FirewallVerdict"),
    "LlamaFirewallAdapter": (".llamafirewall", "LlamaFirewallAdapter"),
    "LlamaIndexKernel": (".llamaindex_adapter", "LlamaIndexKernel"),
    "GovernedMistralClient": (".mistral_adapter", "GovernedMistralClient"),
    "MistralKernel": (".mistral_adapter", "MistralKernel"),
    "GovernedAssistant": (".openai_adapter", "GovernedAssistant"),
    "OpenAIKernel": (".openai_adapter", "OpenAIKernel"),
    "PydanticAIGovernanceCapability": (".pydantic_ai_adapter", "GovernanceCapability"),
    "PydanticAIKernel": (".pydantic_ai_adapter", "PydanticAIKernel"),
    "SKGovernanceFilter": (".semantic_kernel_adapter", "GovernanceFunctionFilter"),
    "GovernedSemanticKernel": (".semantic_kernel_adapter", "GovernedSemanticKernel"),
    "SemanticKernelWrapper": (".semantic_kernel_adapter", "SemanticKernelWrapper"),
    "SmolagentsGovernanceCallback": (".smolagents_adapter", "GovernanceStepCallback"),
    "SmolagentsKernel": (".smolagents_adapter", "SmolagentsKernel"),
}


def __getattr__(name: str):
    if name in _LAZY_ADAPTER_MAP:
        mod_path, real_name = _LAZY_ADAPTER_MAP[name]
        import importlib
        mod = importlib.import_module(mod_path, __package__)
        obj = getattr(mod, real_name)
        globals()[name] = obj  # cache for next access
        return obj
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

from .base import (
    AsyncGovernedWrapper,
    BaseIntegration,
    BoundedSemaphore,
    CompositeInterceptor,
    ContentHashInterceptor,
    DriftResult,
    GovernancePolicy,
    PolicyInterceptor,
    ToolCallInterceptor,
    ToolCallRequest,
    ToolCallResult,
)
from .config import AgentOSConfig, get_config, reset_config
from .conversation_guardian import (
    AlertAction,
    AlertSeverity,
    ConversationAlert,
    ConversationGuardian,
    ConversationGuardianConfig,
    EscalationClassifier,
    FeedbackLoopBreaker,
    OffensiveIntentDetector,
)
from .dry_run import DryRunCollector, DryRunDecision, DryRunPolicy, DryRunResult
from .escalation import (
    ApprovalBackend,
    DefaultTimeoutAction,
    EscalationDecision,
    EscalationHandler,
    EscalationPolicy,
    EscalationRequest,
    EscalationResult,
    InMemoryApprovalQueue,
    QuorumConfig,
    WebhookApprovalBackend,
)
from .compat import CompatReport, check_compatibility, doctor, warn_on_import
from .health import ComponentHealth, HealthChecker, HealthReport, HealthStatus
from .logging import GovernanceLogger, JSONFormatter, get_logger
from .policy_compose import PolicyHierarchy, compose_policies, override_policy
from .rate_limiter import RateLimiter, RateLimitStatus
from .templates import PolicyTemplates
from .token_budget import TokenBudgetStatus, TokenBudgetTracker
from .tool_aliases import ToolAliasRegistry
from .webhooks import DeliveryRecord, WebhookConfig, WebhookEvent, WebhookNotifier

__all__ = [
    # Base
    "AsyncGovernedWrapper",
    "BaseIntegration",
    "DriftResult",
    "GovernancePolicy",
    # Tool Call Interceptor (vendor-neutral)
    "ToolCallInterceptor",
    "ToolCallRequest",
    "ToolCallResult",
    "PolicyInterceptor",
    "CompositeInterceptor",
    # Backpressure / Concurrency
    "BoundedSemaphore",
    # LangChain
    "LangChainKernel",
    # LlamaIndex
    "LlamaIndexKernel",
    # CrewAI
    "CrewAIKernel",
    # AutoGen
    "AutoGenKernel",
    "AutoGenGovernanceHandler",
    # OpenAI Assistants
    "OpenAIKernel",
    "GovernedAssistant",
    # Anthropic Claude
    "AnthropicKernel",
    "GovernedAnthropicClient",
    "AnthropicGovernanceHook",
    "GeminiKernel",
    "GovernedGeminiModel",
    # Mistral AI
    "MistralKernel",
    "GovernedMistralClient",
    # Semantic Kernel
    "SemanticKernelWrapper",
    "GovernedSemanticKernel",
    "SKGovernanceFilter",
    # Guardrails
    "GuardrailsKernel",
    # Google ADK
    "GoogleADKKernel",
    "ADKGovernancePlugin",
    "ADKExecutionContext",
    "ADKPolicyConfig",
    "ADKAuditEvent",
    # A2A (Agent-to-Agent)
    "A2AGovernanceAdapter",
    "A2APolicy",
    "A2AEvaluation",
    # A2A Conversation Guardian
    "ConversationGuardian",
    "ConversationGuardianConfig",
    "ConversationAlert",
    "AlertAction",
    "AlertSeverity",
    "EscalationClassifier",
    "FeedbackLoopBreaker",
    "OffensiveIntentDetector",
    # PydanticAI
    "PydanticAIKernel",
    "PydanticAIGovernanceCapability",
    # Smolagents
    "SmolagentsKernel",
    "SmolagentsGovernanceCallback",
    # Microsoft Agent Framework (MAF)
    "MAFGovernancePolicyMiddleware",
    "MAFCapabilityGuardMiddleware",
    "MAFAuditTrailMiddleware",
    "MAFRogueDetectionMiddleware",
    "maf_create_governance_middleware",
    # LlamaFirewall
    "LlamaFirewallAdapter",
    "FirewallMode",
    "FirewallVerdict",
    "FirewallResult",
    # Token Budget Tracking
    "TokenBudgetTracker",
    "TokenBudgetStatus",
    # Dry Run
    "DryRunPolicy",
    "DryRunResult",
    "DryRunDecision",
    "DryRunCollector",
    # Escalation (Human-in-the-Loop)
    "EscalationPolicy",
    "EscalationHandler",
    "EscalationRequest",
    "EscalationResult",
    "EscalationDecision",
    "DefaultTimeoutAction",
    "ApprovalBackend",
    "InMemoryApprovalQueue",
    "WebhookApprovalBackend",
    # Version Compatibility
    "doctor",
    "check_compatibility",
    "CompatReport",
    "warn_on_import",
    # Tool Aliases
    "ToolAliasRegistry",
    # Rate Limiting
    "RateLimiter",
    "RateLimitStatus",
    # Policy Templates
    "PolicyTemplates",
    # Webhooks
    "WebhookConfig",
    "WebhookEvent",
    "WebhookNotifier",
    "DeliveryRecord",
    # Policy Composition
    "compose_policies",
    "PolicyHierarchy",
    "override_policy",
    # Exceptions
    "AgentOSError",
    "PolicyError",
    "PolicyViolationError",
    "PolicyDeniedError",
    "PolicyTimeoutError",
    "BudgetError",
    "BudgetExceededError",
    "BudgetWarningError",
    "IdentityError",
    "IdentityVerificationError",
    "CredentialExpiredError",
    "IntegrationError",
    "AdapterNotFoundError",
    "AdapterTimeoutError",
    "ConfigurationError",
    "InvalidPolicyError",
    "MissingConfigError",
    "RateLimitError",
    # Health Checks
    "HealthChecker",
    "HealthReport",
    "HealthStatus",
    "ComponentHealth",
    # Structured Logging
    "GovernanceLogger",
    "JSONFormatter",
    "get_logger",
    # Environment Configuration
    "AgentOSConfig",
    "get_config",
    "reset_config",
]
