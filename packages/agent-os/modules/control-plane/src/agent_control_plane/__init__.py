# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Agent Control Plane

Layer 3: The Framework - A governance and management layer for autonomous AI agents.

The governance layer that defines Agent, Supervisor, Tool, and Policy.
This is the chassis that connects the primitives (caas, cmvk) to the protocols (iatp).

Publication Target: PyPI (pip install agent-control-plane)

Allowed Dependencies:
    - iatp: Inter-Agent Transport Protocol (for message security)
    - cmvk: Cryptographic Message Verification Kit (for verification)
    - caas: Context-as-a-Service (for context routing)

Forbidden Dependencies:
    - scak: Self-Correcting Agent Kernel (should implement KernelInterface instead)
    - mute-agent: Should use ValidatorInterface instead of hard imports

Pattern: Components are injected at runtime via PluginRegistry.
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

from .flight_recorder import (
    FlightRecorder,
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
    # Kernel Interface (for custom kernel implementations like SCAK)
    KernelInterface,
    KernelCapability,
    KernelMetadata,
    
    # Plugin Interfaces (for extensibility)
    ValidatorInterface,
    ExecutorInterface,
    ContextRouterInterface,
    PolicyProviderInterface,
    PluginCapability,
    PluginMetadata,
    
    # Protocol Interfaces (for iatp, cmvk, caas integration)
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

from .ml_safety import (
    JailbreakDetector,
    AnomalyDetector,
    ThreatLevel,
    ThreatDetectionResult,
    DetectionMethod,
    create_ml_safety_suite,
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

from .multimodal import (
    VisionCapability,
    AudioCapability,
    VectorStoreIntegration,
    RAGPipeline,
    ImageInput,
    AudioInput,
    MultimodalInput,
    VectorDocument,
    VectorStoreType,
    ModalityType,
    create_multimodal_suite,
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

# Agent Hibernation - Serverless Agents
from .agent_hibernation import (
    HibernationManager,
    HibernationConfig,
    HibernationFormat,
    AgentState as HibernationAgentState,
    HibernatedAgentMetadata,
)

# Time-Travel Debugging
from .time_travel_debugger import (
    TimeTravelDebugger,
    TimeTravelConfig,
    ReplayMode,
    ReplayEvent,
    ReplayEventType,
    ReplaySession,
)

# Lifecycle Management (v0.2.0 - Agent Runtime Features)
from .lifecycle import (
    # Enhanced Control Plane
    EnhancedAgentControlPlane,
    AgentControlPlaneV2,
    create_control_plane,
    
    # Health Monitoring (ACP-001)
    HealthMonitor,
    HealthCheckConfig,
    HealthCheckResult,
    HealthCheckable,
    HealthStatus,
    
    # Auto-Recovery (ACP-002)
    AutoRecoveryManager,
    RecoveryConfig,
    RecoveryEvent,
    
    # Circuit Breaker (ACP-003)
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerMetrics,
    CircuitBreakerRegistry,
    CircuitBreakerOpenError,
    CircuitState,
    
    # Scaling (ACP-004)
    AgentScaler,
    ScalingConfig,
    AgentReplica,
    
    # Distributed Coordination (ACP-005)
    DistributedCoordinator,
    LeaderElectionConfig,
    LeaderInfo,
    CoordinationRole,
    
    # Dependency Graph (ACP-006)
    DependencyGraph,
    AgentDependency,
    
    # Graceful Shutdown (ACP-007)
    GracefulShutdownManager,
    ShutdownConfig,
    InFlightOperation,
    ShutdownPhase,
    
    # Resource Quotas (ACP-008)
    ResourceQuotaManager,
    AgentResourceQuota,
    ResourceUsage,
    
    # Agent Observability (ACP-009)
    AgentObservabilityProvider,
    AgentMetric,
    AgentLogEntry,
    
    # Hot Reload (ACP-010)
    HotReloadManager,
    HotReloadConfig,
    ReloadEvent,
    
    # Agent State
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

__version__ = "0.3.0"  # Bump for kernel architecture features
__author__ = "Imran Siddique"

__all__ = [
    # Main interface
    "AgentControlPlane",
    "create_read_only_agent",
    "create_standard_agent",
    "create_admin_agent",
    
    # ===== Lifecycle Management (v0.2.0) =====
    
    # Enhanced Control Plane
    "EnhancedAgentControlPlane",
    "AgentControlPlaneV2",
    "create_control_plane",
    
    # Health Monitoring (ACP-001)
    "HealthMonitor",
    "HealthCheckConfig",
    "HealthCheckResult",
    "HealthCheckable",
    "HealthStatus",
    
    # Auto-Recovery (ACP-002)
    "AutoRecoveryManager",
    "RecoveryConfig",
    "RecoveryEvent",
    
    # Circuit Breaker (ACP-003)
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerMetrics",
    "CircuitBreakerRegistry",
    "CircuitBreakerOpenError",
    "CircuitState",
    
    # Scaling (ACP-004)
    "AgentScaler",
    "ScalingConfig",
    "AgentReplica",
    
    # Distributed Coordination (ACP-005)
    "DistributedCoordinator",
    "LeaderElectionConfig",
    "LeaderInfo",
    "CoordinationRole",
    
    # Dependency Graph (ACP-006)
    "DependencyGraph",
    "AgentDependency",
    
    # Graceful Shutdown (ACP-007)
    "GracefulShutdownManager",
    "ShutdownConfig",
    "InFlightOperation",
    "ShutdownPhase",
    
    # Resource Quotas (ACP-008)
    "ResourceQuotaManager",
    "AgentResourceQuota",
    "ResourceUsage",
    
    # Agent Observability (ACP-009)
    "AgentObservabilityProvider",
    "AgentMetric",
    "AgentLogEntry",
    
    # Hot Reload (ACP-010)
    "HotReloadManager",
    "HotReloadConfig",
    "ReloadEvent",
    
    # Agent State
    "AgentState",
    "AgentRegistration",
    
    # ===== Layer 3: Interfaces for Dependency Injection =====
    
    # Kernel Interface (for custom kernel implementations like SCAK)
    "KernelInterface",
    "KernelCapability",
    "KernelMetadata",
    
    # Plugin Interfaces (for extensibility)
    "ValidatorInterface",
    "ExecutorInterface",
    "ContextRouterInterface",
    "PolicyProviderInterface",
    "PluginCapability",
    "PluginMetadata",
    
    # Protocol Interfaces (for iatp, cmvk, caas integration)
    "MessageSecurityInterface",
    "VerificationInterface",
    "ContextRoutingInterface",
    
    # Plugin Registry (for dependency injection)
    "PluginRegistry",
    "PluginType",
    "PluginRegistration",
    "RegistryConfiguration",
    "get_registry",
    
    # ===== Adapters =====
    
    # OpenAI Adapter (Drop-in Middleware)
    "ControlPlaneAdapter",
    "create_governed_client",
    "DEFAULT_TOOL_MAPPING",
    
    # LangChain Adapter
    "LangChainAdapter",
    "create_governed_langchain_client",
    "DEFAULT_LANGCHAIN_TOOL_MAPPING",
    
    # MCP (Model Context Protocol) Adapter
    "MCPAdapter",
    "MCPServer",
    "create_governed_mcp_server",
    
    # A2A (Agent-to-Agent) Adapter
    "A2AAdapter",
    "A2AAgent",
    "create_governed_a2a_agent",
    
    # Tool Registry (Dynamic Tool Management)
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
    
    # Governance Layer (Ethical Alignment & Advanced Safety)
    "GovernanceLayer",
    "AlignmentPrinciple",
    "AlignmentRule",
    "BiasType",
    "BiasDetectionResult",
    "PrivacyLevel",
    "PrivacyAnalysis",
    "create_default_governance",
    
    # ML-Based Safety & Anomaly Detection
    "JailbreakDetector",
    "AnomalyDetector",
    "ThreatLevel",
    "ThreatDetectionResult",
    "DetectionMethod",
    "create_ml_safety_suite",
    
    # Compliance & Constitutional AI
    "ComplianceEngine",
    "ConstitutionalAI",
    "RegulatoryFramework",
    "RiskCategory",
    "ConstitutionalPrinciple",
    "ComplianceCheck",
    "create_compliance_suite",
    
    # Multimodal Capabilities (Vision, Audio, RAG)
    "VisionCapability",
    "AudioCapability",
    "VectorStoreIntegration",
    "RAGPipeline",
    "ImageInput",
    "AudioInput",
    "MultimodalInput",
    "VectorDocument",
    "VectorStoreType",
    "ModalityType",
    "create_multimodal_suite",
    
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
    
    # Agent Hibernation - Serverless Agents
    "HibernationManager",
    "HibernationConfig",
    "HibernationFormat",
    "HibernationAgentState",
    "HibernatedAgentMetadata",
    
    # Time-Travel Debugging
    "TimeTravelDebugger",
    "TimeTravelConfig",
    "ReplayMode",
    "ReplayEvent",
    "ReplayEventType",
    "ReplaySession",
    
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
    
    # Audit
    "FlightRecorder",
    
    # Execution
    "ExecutionEngine",
    "ExecutionContext",
    "ExecutionMetrics",
    
    # ========== Kernel Architecture (v0.3.0) ==========
    
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
    "AgentContext",  # Note: Also exported from agent_kernel
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
