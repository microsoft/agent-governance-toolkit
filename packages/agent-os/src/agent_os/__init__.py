# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent OS - A Safety-First Kernel for Autonomous AI Agents

Agent OS provides POSIX-inspired primitives for AI agent systems with
a 0% policy violation guarantee through kernel-level enforcement.

Architecture Layers:
    Layer 1 - Primitives: Base models, verification, context, memory
    Layer 2 - Infrastructure: Trust protocol, message bus, tool registry
    Layer 3 - Framework: Control plane, signals, VFS, kernel space
    Layer 4 - Intelligence: Self-correction, reasoning/execution split

Quick Start:
    >>> from agent_os import KernelSpace, AgentSignal, AgentVFS
    >>> kernel = KernelSpace()
    >>> ctx = kernel.create_agent_context("agent-001")
    >>> await ctx.write("/mem/working/task.txt", "Hello World")

Stateless API (MCP June 2026):
    >>> from agent_os import stateless_execute
    >>> result = await stateless_execute(
    ...     action="database_query",
    ...     params={"query": "SELECT * FROM users"},
    ...     agent_id="analyst-001",
    ...     policies=["read_only"]
    ... )

Installation:
    pip install agent-os-kernel[full]  # Everything
    pip install agent-os-kernel        # Core
"""

from __future__ import annotations

__version__ = "2.0.2"
__author__ = "Imran Siddique"
__license__ = "MIT"

import logging

logger = logging.getLogger(__name__)

# ============================================================================
# Layer 1: Primitives
# ============================================================================

# Agent Primitives - Base failure models
try:
    from agent_primitives import (
        AgentFailure,
        FailureSeverity,
        FailureType,
    )
    _PRIMITIVES_AVAILABLE = True
except ImportError:
    _PRIMITIVES_AVAILABLE = False

# CMVK - Verification Kernel
# DriftDetector (#138): Compares agent outputs across models or over time to
# detect semantic drift — situations where an agent's behaviour diverges from
# its stated intent or baseline.  Drift is quantified as a float score in
# [0.0, 1.0] (0 = identical, 1 = completely divergent).  When the score
# exceeds GovernancePolicy.drift_threshold a ``DRIFT_DETECTED`` governance
# event is emitted.
#
# SemanticDrift: Data class holding drift metadata (score, drift type, etc.).
# verify_outputs: Pure function that compares two text outputs for drift.
#
# Threshold parameters (from GovernancePolicy):
#   - confidence_threshold (float): Minimum confidence for acceptance.
#   - drift_threshold (float): Maximum tolerable drift before alerting.
#
# Example — detecting agent behaviour drift:
#   >>> from agent_os import DriftDetector  # requires cmvk package
#   >>> detector = DriftDetector(threshold=0.15)
#   >>> drift = detector.compare(
#   ...     baseline="Transfer $100 to savings account",
#   ...     current="Transfer $10,000 to external account XYZ",
#   ... )
#   >>> if drift.score > 0.15:
#   ...     print(f"DRIFT DETECTED: {drift.score:.2f}")
try:
    from cmvk import (
        DriftDetector,
        SemanticDrift,
        verify_outputs,
    )
    _CMVK_AVAILABLE = True
except ImportError:
    _CMVK_AVAILABLE = False

# CaaS - Context as a Service
# ContextPipeline (#139): A composable, multi-stage pipeline for transforming
# and filtering context before it reaches an agent.  The architecture follows
# a pipes-and-filters pattern where each stage receives a context object,
# applies a transformation (e.g. PII redaction, summarisation, relevance
# scoring), and passes the result to the next stage.
#
# Pipeline stages:
#   1. Ingestion  — parse raw documents into structured Sections.
#   2. Enrichment — add metadata (timestamps, source citations).
#   3. Filtering  — remove irrelevant or sensitive content.
#   4. Routing    — classify the query and select the right model tier.
#   5. Assembly   — build the final context window within token budget.
#
# RAGContext: Holds retrieval-augmented generation context with citations.
#
# Example — building a context pipeline:
#   >>> from agent_os import ContextPipeline  # requires caas package
#   >>> pipeline = ContextPipeline(stages=[
#   ...     RedactPIIStage(),
#   ...     SummarizeStage(max_tokens=512),
#   ...     RelevanceScoringStage(threshold=0.7),
#   ... ])
#   >>> context = pipeline.run(raw_documents, query="quarterly revenue")
try:
    from caas import (
        ContextPipeline,
        RAGContext,
    )
    _CAAS_AVAILABLE = True
except ImportError:
    _CAAS_AVAILABLE = False

# EMK - Episodic Memory Kernel
try:
    from emk import (
        Episode,
        EpisodicMemory,
        MemoryStore,
    )
    _EMK_AVAILABLE = True
except ImportError:
    _EMK_AVAILABLE = False

# ============================================================================
# Layer 2: Infrastructure
# ============================================================================

# IATP - Inter-Agent Trust Protocol
try:
    from iatp import (
        CapabilityManifest,
        Pipeline,
        PipeMessage,
        PolicyCheckPipe,
        SidecarProxy,
        TrustLevel,
        TypedPipe,
    )
    _IATP_AVAILABLE = True
except ImportError:
    _IATP_AVAILABLE = False

# AMB - Agent Message Bus
try:
    from amb_core import (
        Message,
        MessageBus,
        Topic,
    )
    _AMB_AVAILABLE = True
except ImportError:
    _AMB_AVAILABLE = False

# ATR - Agent Tool Registry
try:
    from atr import (
        Tool,
        ToolExecutor,
        ToolRegistry,
    )
    _ATR_AVAILABLE = True
except ImportError:
    _ATR_AVAILABLE = False

# ============================================================================
# Layer 3: Framework (Control Plane)
# ============================================================================

try:
    from agent_control_plane import (
        AgentContext,
        # Main Interface
        AgentControlPlane,
        AgentKernelPanic,
        # Kernel Architecture (v0.3.0)
        AgentSignal,
        # Agent VFS
        AgentVFS,
        # Execution
        ExecutionEngine,
        ExecutionStatus,
        FileMode,
        # Flight Recorder
        FlightRecorder,
        # Kernel/User Space
        KernelSpace,
        KernelState,
        MemoryBackend,
        # Policy Engine
        PolicyEngine,
        PolicyRule,
        ProtectionRing,
        SignalAwareAgent,
        SignalDispatcher,
        SyscallRequest,
        SyscallResult,
        SyscallType,
        VFSBackend,
        create_agent_vfs,
        create_control_plane,
        create_kernel,
        kill_agent,
        pause_agent,
        policy_violation,
        resume_agent,
        user_space_execution,
    )
    _CONTROL_PLANE_AVAILABLE = True
except ImportError:
    _CONTROL_PLANE_AVAILABLE = False

# ============================================================================
# Layer 4: Intelligence
# ============================================================================

# SCAK - Self-Correcting Agent Kernel
try:
    from agent_kernel import (
        DifferentialAuditor,
        LazinessDetector,
        SelfCorrectingKernel,
    )
    _SCAK_AVAILABLE = True
except ImportError:
    _SCAK_AVAILABLE = False

# Mute Agent (external module)
try:
    from mute_agent import (
        ExecutionAgent,
        MuteAgent,
        ReasoningAgent,
    )
    _MUTE_AGENT_AVAILABLE = True
except ImportError:
    _MUTE_AGENT_AVAILABLE = False

# Mute Agent Primitives — Face/Hands kernel-level decorators (always available)
from agent_os.agents_compat import (
    AgentConfig as AgentsConfig,  # Renamed to avoid conflict
)

# AGENTS.md Compatibility
from agent_os.agents_compat import (
    AgentSkill,
    AgentsParser,
    discover_agents,
)

# Base Agent Classes
from agent_os.base_agent import (
    AgentConfig,
    AuditEntry,
    BaseAgent,
    PolicyDecision,
    ToolUsingAgent,
    TypedResult,
)

# Context Budget Scheduler — token budget as a kernel primitive (always available)
from agent_os.context_budget import (
    AgentSignal,
    BudgetExceeded,
    ContextPriority,
    ContextScheduler,
    ContextWindow,
)

# LlamaFirewall Integration — defense-in-depth with Meta's LlamaFirewall
from agent_os.integrations.llamafirewall import (
    FirewallMode,
    FirewallResult,
    FirewallVerdict,
    LlamaFirewallAdapter,
)

# MCP Security — tool poisoning defense (always available)
from agent_os.mcp_security import (
    MCPSecurityScanner,
    MCPSeverity,
    MCPThreat,
    MCPThreatType,
    ScanResult,
    ToolFingerprint,
)
from agent_os.mute import (
    ActionStatus,
    ActionStep,
    CapabilityViolation,
    ExecutionPlan,
    PipelineResult,
    StepResult,
    face_agent,
    mute_agent,
    pipe,
)

# Prompt Injection Detection — input screening (always available)
from agent_os.prompt_injection import (
    DetectionConfig,
    DetectionResult,
    InjectionType,
    PromptInjectionDetector,
    ThreatLevel,
)

# Semantic Policy Engine — intent-based enforcement (always available)
from agent_os.semantic_policy import (
    IntentCategory,
    IntentClassification,
    PolicyDenied,
    SemanticPolicyEngine,
)

# ============================================================================
# Local Components (Always Available)
# ============================================================================
# Stateless Kernel (MCP June 2026)
from agent_os.stateless import (
    ExecutionContext,
    ExecutionRequest,
    ExecutionResult,
    StatelessKernel,
    stateless_execute,
)
from agent_os.stateless import (
    MemoryBackend as StatelessMemoryBackend,
)

# ============================================================================
# Availability Flags
# ============================================================================

AVAILABLE_PACKAGES = {
    "primitives": _PRIMITIVES_AVAILABLE if '_PRIMITIVES_AVAILABLE' in dir() else False,
    "cmvk": _CMVK_AVAILABLE if '_CMVK_AVAILABLE' in dir() else False,
    "caas": _CAAS_AVAILABLE if '_CAAS_AVAILABLE' in dir() else False,
    "emk": _EMK_AVAILABLE if '_EMK_AVAILABLE' in dir() else False,
    "iatp": _IATP_AVAILABLE if '_IATP_AVAILABLE' in dir() else False,
    "amb": _AMB_AVAILABLE if '_AMB_AVAILABLE' in dir() else False,
    "atr": _ATR_AVAILABLE if '_ATR_AVAILABLE' in dir() else False,
    "control_plane": _CONTROL_PLANE_AVAILABLE if '_CONTROL_PLANE_AVAILABLE' in dir() else False,
    "scak": _SCAK_AVAILABLE if '_SCAK_AVAILABLE' in dir() else False,
    "mute_agent": _MUTE_AGENT_AVAILABLE if '_MUTE_AGENT_AVAILABLE' in dir() else False,
}


def check_installation() -> None:
    """Check which Agent OS packages are installed."""
    logger.info("Agent OS Installation Status:")
    logger.info("=" * 40)
    for pkg, available in AVAILABLE_PACKAGES.items():
        status = "✓ Installed" if available else "✗ Not installed"
        logger.info(f"  {pkg:15} {status}")
    logger.info("=" * 40)
    logger.info("\nInstall missing packages with:")
    logger.info("  pip install agent-os-kernel[full]")


# ============================================================================
# Public API
# ============================================================================

__all__ = [
    # Metadata
    "__version__",
    "__author__",
    "AVAILABLE_PACKAGES",
    "check_installation",

    # Layer 1: Primitives
    "AgentFailure",
    "FailureType",
    "FailureSeverity",
    "DriftDetector",
    "SemanticDrift",
    "verify_outputs",
    "ContextPipeline",
    "RAGContext",
    "EpisodicMemory",
    "Episode",
    "MemoryStore",

    # Layer 2: Infrastructure
    "CapabilityManifest",
    "TrustLevel",
    "SidecarProxy",
    "TypedPipe",
    "Pipeline",
    "PipeMessage",
    "PolicyCheckPipe",
    "MessageBus",
    "Message",
    "Topic",
    "ToolRegistry",
    "Tool",
    "ToolExecutor",

    # Layer 3: Framework
    "AgentControlPlane",
    "create_control_plane",
    "AgentSignal",
    "SignalDispatcher",
    "AgentKernelPanic",
    "SignalAwareAgent",
    "kill_agent",
    "pause_agent",
    "resume_agent",
    "policy_violation",
    "AgentVFS",
    "VFSBackend",
    "MemoryBackend",
    "FileMode",
    "create_agent_vfs",
    "KernelSpace",
    "AgentContext",
    "ProtectionRing",
    "SyscallType",
    "SyscallRequest",
    "SyscallResult",
    "KernelState",
    "user_space_execution",
    "create_kernel",
    "PolicyEngine",
    "PolicyRule",
    "FlightRecorder",
    "ExecutionEngine",
    "ExecutionStatus",

    # Layer 4: Intelligence
    "SelfCorrectingKernel",
    "LazinessDetector",
    "DifferentialAuditor",
    "MuteAgent",
    "ReasoningAgent",
    "ExecutionAgent",

    # Mute Agent Primitives (Face/Hands kernel-level decorators)
    "face_agent",
    "mute_agent",
    "pipe",
    "ActionStep",
    "ActionStatus",
    "ExecutionPlan",
    "StepResult",
    "PipelineResult",
    "CapabilityViolation",

    # Stateless API (MCP June 2026)
    "StatelessKernel",
    "ExecutionContext",
    "ExecutionRequest",
    "ExecutionResult",
    "StatelessMemoryBackend",
    "stateless_execute",

    # Base Agent Classes
    "BaseAgent",
    "ToolUsingAgent",
    "AgentConfig",
    "AuditEntry",
    "PolicyDecision",
    "TypedResult",

    # AGENTS.md Compatibility
    "AgentsParser",
    "AgentsConfig",
    "AgentSkill",
    "discover_agents",

    # Semantic Policy Engine
    "SemanticPolicyEngine",
    "IntentCategory",
    "IntentClassification",
    "PolicyDenied",

    # Prompt Injection Detection
    "PromptInjectionDetector",
    "InjectionType",
    "ThreatLevel",
    "DetectionResult",
    "DetectionConfig",

    # MCP Security — Tool Poisoning Defense
    "MCPSecurityScanner",
    "MCPThreatType",
    "MCPSeverity",
    "MCPThreat",
    "ToolFingerprint",
    "ScanResult",

    # LlamaFirewall Integration
    "LlamaFirewallAdapter",
    "FirewallMode",
    "FirewallVerdict",
    "FirewallResult",

    # Context Budget Scheduler
    "ContextScheduler",
    "ContextWindow",
    "ContextPriority",
    "AgentSignal",
    "BudgetExceeded",
]
