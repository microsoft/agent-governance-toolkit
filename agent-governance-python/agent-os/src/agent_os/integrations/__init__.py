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
from agent_os.integrations.a2a_adapter import A2AEvaluation, A2AGovernanceAdapter, A2APolicy
from agent_os.integrations.anthropic_adapter import AnthropicKernel, GovernedAnthropicClient
from agent_os.integrations.autogen_adapter import AutoGenKernel
from agent_os.integrations.crewai_adapter import CrewAIKernel
from agent_os.integrations.gemini_adapter import GeminiKernel, GovernedGeminiModel
from agent_os.integrations.google_adk_adapter import GoogleADKKernel
from agent_os.integrations.guardrails_adapter import GuardrailsKernel
from agent_os.integrations.langchain_adapter import LangChainKernel
try:
    from agent_os.integrations.maf_adapter import (
        AuditTrailMiddleware as MAFAuditTrailMiddleware,
        CapabilityGuardMiddleware as MAFCapabilityGuardMiddleware,
        GovernancePolicyMiddleware as MAFGovernancePolicyMiddleware,
        RogueDetectionMiddleware as MAFRogueDetectionMiddleware,
        create_governance_middleware as maf_create_governance_middleware,
    )
except ImportError:  # agent_framework is an optional dependency
    pass
from agent_os.integrations.llamafirewall import (
    FirewallMode,
    FirewallResult,
    FirewallVerdict,
    LlamaFirewallAdapter,
)
from agent_os.integrations.llamaindex_adapter import LlamaIndexKernel
from agent_os.integrations.mistral_adapter import GovernedMistralClient, MistralKernel
from agent_os.integrations.openai_adapter import GovernedAssistant, OpenAIKernel
from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel
from agent_os.integrations.semantic_kernel_adapter import (
    GovernedSemanticKernel,
    SemanticKernelWrapper,
)

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
    # OpenAI Assistants
    "OpenAIKernel",
    "GovernedAssistant",
    # Anthropic Claude
    "AnthropicKernel",
    "GovernedAnthropicClient",
    # Google Gemini
    "GeminiKernel",
    "GovernedGeminiModel",
    # Mistral AI
    "MistralKernel",
    "GovernedMistralClient",
    # Semantic Kernel
    "SemanticKernelWrapper",
    "GovernedSemanticKernel",
    # Guardrails
    "GuardrailsKernel",
    # Google ADK
    "GoogleADKKernel",
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
