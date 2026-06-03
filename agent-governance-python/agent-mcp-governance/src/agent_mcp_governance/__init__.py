# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ruff: noqa: E402 — deprecation warning must fire before re-exports
"""agent_mcp_governance— MCP governance primitives for the Agent Governance Toolkit.

This package provides a focused surface for governing agents that communicate
over the Model Context Protocol (MCP). It re-exports:

General governance primitives (from ``agent-os``):
    - GovernanceMiddleware: policy enforcement for agent actions
    - AuditMiddleware: structured audit logging
    - TrustGate: inter-agent trust verification
    - BehaviorMonitor: runtime behavioral anomaly detection

MCP-specific security primitives (from ``agent_os.mcp_security``):
    - MCPSecurityScanner: scans MCP tool definitions for poisoning, rug pulls,
      cross-server attacks, and hidden instructions
    - MCPSecurityConfig: configuration for scanner sensitivity and thresholds
    - ToolFingerprint: immutable fingerprint of a registered tool definition
    - ScanResult: result of a single tool scan, including any detected threats
    - MCPThreat: individual threat record with type, severity, and evidence
    - MCPThreatType: enumeration of MCP threat categories
    - MCPSeverity: enumeration of threat severity levels
"""

from __future__ import annotations

import warnings as _warnings
_warnings.warn(
    "agent-mcp-governance is deprecated. Use agent-governance-toolkit-protocols instead. "
    "See https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)
del _warnings

__version__ = "3.6.0"

from agent_os.governance.middleware import GovernanceMiddleware
from agent_os.audit.middleware import AuditMiddleware
from agent_os.trust.gate import TrustGate
from agent_os.services.behavior_monitor import BehaviorMonitor

from agent_os.mcp_security import (
    MCPSecurityScanner,
    MCPSecurityConfig,
    ToolFingerprint,
    ScanResult,
    MCPThreat,
    MCPThreatType,
    MCPSeverity,
)

__all__ = [
    "__version__",
    # General governance primitives
    "GovernanceMiddleware",
    "AuditMiddleware",
    "TrustGate",
    "BehaviorMonitor",
    # MCP-specific security primitives
    "MCPSecurityScanner",
    "MCPSecurityConfig",
    "ToolFingerprint",
    "ScanResult",
    "MCPThreat",
    "MCPThreatType",
    "MCPSeverity",
]
