# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent OS - A Safety-First Kernel for Autonomous AI Agents

Agent OS provides POSIX-inspired primitives for AI agent systems with
a 0% policy violation guarantee through kernel-level enforcement.

Core capabilities:
    - Policy engine and action interception
    - Prompt injection detection
    - MCP tool-poisoning defense
    - Semantic policy enforcement
    - Context budget scheduling
    - Stateless kernel execution

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

Optional ecosystem packages (import directly):
    - agent_primitives: Base failure models
    - cmvk: Verification kernel / drift detection
    - caas: Context-as-a-Service pipelines
    - emk: Episodic memory kernel
    - amb_core: Agent message bus
    - atr: Agent tool registry
    - agent_kernel: Self-correcting kernel
    - mute_agent: Reasoning/execution split

Installation:
    pip install agent-os-kernel[full]  # Everything
    pip install agent-os-kernel        # Core
"""

from __future__ import annotations

__version__ = "3.0.2"
__author__ = "Microsoft Corporation"
__license__ = "MIT"

import logging

logger = logging.getLogger(__name__)


def _check_optional(module_name: str) -> bool:
    """Return True if *module_name* is importable."""
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False


AVAILABLE_PACKAGES: dict[str, bool] = {
    "control_plane": _check_optional("agent_control_plane"),
    "primitives": _check_optional("agent_primitives"),
    "cmvk": _check_optional("cmvk"),
    "caas": _check_optional("caas"),
    "emk": _check_optional("emk"),
    "amb": _check_optional("amb_core"),
    "atr": _check_optional("atr"),
    "scak": _check_optional("agent_kernel"),
    "mute_agent": _check_optional("mute_agent"),
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
# Control Plane (optional — requires agent_control_plane package)
# ============================================================================

try:
    from agent_control_plane import (
        AgentContext,
        AgentControlPlane,
        AgentKernelPanic,
        AgentSignal,
        AgentVFS,
        ExecutionEngine,
        ExecutionStatus,
        FileMode,
        FlightRecorder,
        KernelSpace,
        KernelState,
        MemoryBackend,
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
# Core Governance Modules (always available)
# ============================================================================

# AGENTS.md Compatibility
from agent_os.agents_compat import (
    AgentConfig as AgentsConfig,
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

# Context Budget Scheduler
from agent_os.context_budget import (
    BudgetExceeded,
    ContextPriority,
    ContextScheduler,
    ContextWindow,
)

# LlamaFirewall Integration
from agent_os.integrations.llamafirewall import (
    FirewallMode,
    FirewallResult,
    FirewallVerdict,
    LlamaFirewallAdapter,
)

# MCP Security — tool poisoning defense
from agent_os.mcp_security import (
    MCPSecurityScanner,
    MCPSeverity,
    MCPThreat,
    MCPThreatType,
    ScanResult,
    ToolFingerprint,
)

# Mute Agent Primitives — Face/Hands kernel-level decorators
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

# Prompt Injection Detection
from agent_os.prompt_injection import (
    DetectionConfig,
    DetectionResult,
    InjectionType,
    PromptInjectionDetector,
    ThreatLevel,
)

# Semantic Policy Engine
from agent_os.semantic_policy import (
    IntentCategory,
    IntentClassification,
    PolicyDenied,
    SemanticPolicyEngine,
)

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
# Public API
# ============================================================================

__all__ = [
    # Metadata
    "__version__",
    "__author__",
    "AVAILABLE_PACKAGES",
    "check_installation",

    # Control Plane
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

    # Mute Agent Primitives
    "face_agent",
    "mute_agent",
    "pipe",
    "ActionStep",
    "ActionStatus",
    "ExecutionPlan",
    "StepResult",
    "PipelineResult",
    "CapabilityViolation",

    # Stateless API
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

    # MCP Security
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
    "BudgetExceeded",
]
