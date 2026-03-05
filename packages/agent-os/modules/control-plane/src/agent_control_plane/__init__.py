# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic YAML policy enforcement
"""
Agent Control Plane

Layer 3: The Framework - A governance and management layer for autonomous AI agents.

Publication Target: PyPI (pip install agent-control-plane)
"""

from .agent_kernel import (
    AgentKernel,
    AgentContext,
    ExecutionRequest,
    ExecutionResult,
    ActionType,
    PermissionLevel,
    ExecutionStatus,
    PolicyRule,
)

from .policy_engine import (
    PolicyEngine,
    ResourceQuota,
    RiskPolicy,
    Condition,
    ConditionalPermission,
    create_default_policies,
)

from .execution_engine import (
    ExecutionEngine,
    ExecutionContext,
    SandboxLevel,
    ExecutionMetrics,
)

from .control_plane import (
    AgentControlPlane,
    create_read_only_agent,
    create_standard_agent,
    create_admin_agent,
)

# Interfaces for dependency injection (Layer 3 pattern)
from .interfaces import (
    KernelInterface,
    KernelCapability,
    KernelMetadata,
    ValidatorInterface,
    ExecutorInterface,
    ContextRouterInterface,
    PolicyProviderInterface,
    PluginCapability,
    PluginMetadata,
    MessageSecurityInterface,
    VerificationInterface,
    ContextRoutingInterface,
)

# Plugin Registry for dependency injection
from .plugin_registry import (
    PluginRegistry,
    PluginType,
    PluginRegistration,
    RegistryConfiguration,
    get_registry,
)

from .adapter import (
    ControlPlaneAdapter,
    create_governed_client,
    DEFAULT_TOOL_MAPPING,
)

from .langchain_adapter import (
    LangChainAdapter,
    create_governed_langchain_client,
    DEFAULT_LANGCHAIN_TOOL_MAPPING,
)

from .mcp_adapter import (
    MCPAdapter,
    MCPServer,
    create_governed_mcp_server,
)

from .a2a_adapter import (
    A2AAdapter,
    A2AAgent,
    create_governed_a2a_agent,
)

from .tool_registry import (
    ToolRegistry,
    Tool,
    ToolType,
    ToolSchema,
    create_standard_tool_registry,
)

from .orchestrator import (
    AgentOrchestrator,
    AgentNode,
    AgentRole,
    Message,
    MessageType,
    OrchestrationType,
    WorkflowState,
    create_rag_pipeline,
)

from .governance_layer import (
    GovernanceLayer,
    AlignmentPrinciple,
    AlignmentRule,
    BiasType,
    BiasDetectionResult,
    PrivacyLevel,
    PrivacyAnalysis,
    create_default_governance,
)

from .compliance import (
    ComplianceEngine,
    ConstitutionalAI,
    RegulatoryFramework,
    RiskCategory,
    ConstitutionalPrinciple,
    ComplianceCheck,
    create_compliance_suite,
)

from .observability import (
    PrometheusExporter,
    AlertManager,
    TraceCollector,
    ObservabilityDashboard,
    Metric,
    Alert,
    Trace,
    Span,
    MetricType,
    AlertSeverity,
    create_observability_suite,
)

# Lifecycle Management (v0.2.0 - Agent Runtime Features)
from .lifecycle import (
    EnhancedAgentControlPlane,
    AgentControlPlaneV2,
    create_control_plane,
    HealthMonitor,
    HealthCheckConfig,
    HealthCheckResult,
    HealthCheckable,
    HealthStatus,
    AutoRecoveryManager,
    RecoveryConfig,
    RecoveryEvent,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerMetrics,
    CircuitBreakerRegistry,
    CircuitBreakerOpenError,
    CircuitState,
    AgentScaler,
    ScalingConfig,
    AgentReplica,
    DistributedCoordinator,
    LeaderElectionConfig,
    LeaderInfo,
    CoordinationRole,
    DependencyGraph,
    AgentDependency,
    GracefulShutdownManager,
    ShutdownConfig,
    InFlightOperation,
    ShutdownPhase,
    ResourceQuotaManager,
    AgentResourceQuota,
    ResourceUsage,
    AgentObservabilityProvider,
    AgentMetric,
    AgentLogEntry,
    HotReloadManager,
    HotReloadConfig,
    ReloadEvent,
    AgentState,
    AgentRegistration,
)

# ========== Kernel Architecture (v0.3.0) ==========

# Signal Handling - POSIX-style signals for agents
from .signals import (
    AgentSignal,
    SignalDisposition,
    SignalInfo,
    SignalMask,
    SignalDispatcher,
    AgentKernelPanic,
    SignalAwareAgent,
    kill_agent,
    pause_agent,
    resume_agent,
    policy_violation,
)

# Agent Virtual File System
from .vfs import (
    AgentVFS,
    VFSBackend,
    MemoryBackend,
    VectorBackend,
    FileMode,
    FileType,
    INode,
    FileDescriptor,
    MountPoint,
    create_agent_vfs,
)

# Kernel/User Space Separation
from .kernel_space import (
    KernelSpace,
    AgentContext,
    ProtectionRing,
    SyscallType,
    SyscallRequest,
    SyscallResult,
    KernelState,
    KernelMetrics,
    user_space_execution,
    create_kernel,
)

# Hugging Face Hub utilities (optional - requires huggingface_hub)
try:
    from .hf_utils import (
        HFConfig,
        download_red_team_dataset,
        upload_dataset,
        upload_experiment_logs,
        list_experiment_logs,
        ModelCardInfo,
        create_model_card,
    )
    _HF_AVAILABLE = True
except ImportError:
    _HF_AVAILABLE = False

__version__ = "0.3.0"
__author__ = "Imran Siddique"

__all__ = [
    # Main interface
    "AgentControlPlane",
    "create_read_only_agent",
    "create_standard_agent",
    "create_admin_agent",
    
    # Lifecycle Management (v0.2.0)
    "EnhancedAgentControlPlane",
    "AgentControlPlaneV2",
    "create_control_plane",
    "HealthMonitor",
    "HealthCheckConfig",
    "HealthCheckResult",
    "HealthCheckable",
    "HealthStatus",
    "AutoRecoveryManager",
    "RecoveryConfig",
    "RecoveryEvent",
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerMetrics",
    "CircuitBreakerRegistry",
    "CircuitBreakerOpenError",
    "CircuitState",
    "AgentScaler",
    "ScalingConfig",
    "AgentReplica",
    "DistributedCoordinator",
    "LeaderElectionConfig",
    "LeaderInfo",
    "CoordinationRole",
    "DependencyGraph",
    "AgentDependency",
    "GracefulShutdownManager",
    "ShutdownConfig",
    "InFlightOperation",
    "ShutdownPhase",
    "ResourceQuotaManager",
    "AgentResourceQuota",
    "ResourceUsage",
    "AgentObservabilityProvider",
    "AgentMetric",
    "AgentLogEntry",
    "HotReloadManager",
    "HotReloadConfig",
    "ReloadEvent",
    "AgentState",
    "AgentRegistration",
    
    # Interfaces for Dependency Injection
    "KernelInterface",
    "KernelCapability",
    "KernelMetadata",
    "ValidatorInterface",
    "ExecutorInterface",
    "ContextRouterInterface",
    "PolicyProviderInterface",
    "PluginCapability",
    "PluginMetadata",
    "MessageSecurityInterface",
    "VerificationInterface",
    "ContextRoutingInterface",
    
    # Plugin Registry
    "PluginRegistry",
    "PluginType",
    "PluginRegistration",
    "RegistryConfiguration",
    "get_registry",
    
    # Adapters
    "ControlPlaneAdapter",
    "create_governed_client",
    "DEFAULT_TOOL_MAPPING",
    "LangChainAdapter",
    "create_governed_langchain_client",
    "DEFAULT_LANGCHAIN_TOOL_MAPPING",
    "MCPAdapter",
    "MCPServer",
    "create_governed_mcp_server",
    "A2AAdapter",
    "A2AAgent",
    "create_governed_a2a_agent",
    
    # Tool Registry
    "ToolRegistry",
    "Tool",
    "ToolType",
    "ToolSchema",
    "create_standard_tool_registry",
    
    # Multi-Agent Orchestration
    "AgentOrchestrator",
    "AgentNode",
    "AgentRole",
    "Message",
    "MessageType",
    "OrchestrationType",
    "WorkflowState",
    "create_rag_pipeline",
    
    # Governance Layer
    "GovernanceLayer",
    "AlignmentPrinciple",
    "AlignmentRule",
    "BiasType",
    "BiasDetectionResult",
    "PrivacyLevel",
    "PrivacyAnalysis",
    "create_default_governance",
    
    # Compliance & Constitutional AI
    "ComplianceEngine",
    "ConstitutionalAI",
    "RegulatoryFramework",
    "RiskCategory",
    "ConstitutionalPrinciple",
    "ComplianceCheck",
    "create_compliance_suite",
    
    # Observability & Monitoring
    "PrometheusExporter",
    "AlertManager",
    "TraceCollector",
    "ObservabilityDashboard",
    "Metric",
    "Alert",
    "Trace",
    "Span",
    "MetricType",
    "AlertSeverity",
    "create_observability_suite",
    
    # Kernel
    "AgentKernel",
    "AgentContext",
    "ExecutionRequest",
    "ExecutionResult",
    "PolicyRule",
    
    # Enums
    "ActionType",
    "PermissionLevel",
    "ExecutionStatus",
    "SandboxLevel",
    
    # Policy
    "PolicyEngine",
    "ResourceQuota",
    "RiskPolicy",
    "Condition",
    "ConditionalPermission",
    "create_default_policies",
    
    # Execution
    "ExecutionEngine",
    "ExecutionContext",
    "ExecutionMetrics",
    
    # Signal Handling
    "AgentSignal",
    "SignalDisposition",
    "SignalInfo",
    "SignalMask",
    "SignalDispatcher",
    "AgentKernelPanic",
    "SignalAwareAgent",
    "kill_agent",
    "pause_agent",
    "resume_agent",
    "policy_violation",
    
    # Agent VFS
    "AgentVFS",
    "VFSBackend",
    "MemoryBackend",
    "VectorBackend",
    "FileMode",
    "FileType",
    "INode",
    "FileDescriptor",
    "MountPoint",
    "create_agent_vfs",
    
    # Kernel/User Space
    "KernelSpace",
    "AgentContext",
    "ProtectionRing",
    "SyscallType",
    "SyscallRequest",
    "SyscallResult",
    "KernelState",
    "KernelMetrics",
    "user_space_execution",
    "create_kernel",
    
    # Hugging Face Hub utilities (optional)
    "HFConfig",
    "download_red_team_dataset",
    "upload_dataset",
    "upload_experiment_logs",
    "list_experiment_logs",
    "ModelCardInfo",
    "create_model_card",
]

# Conditionally remove HF exports if not available
if not _HF_AVAILABLE:
    _hf_exports = [
        "HFConfig",
        "download_red_team_dataset",
        "upload_dataset",
        "upload_experiment_logs",
        "list_experiment_logs",
        "ModelCardInfo",
        "create_model_card",
    ]
    __all__ = [x for x in __all__ if x not in _hf_exports]
