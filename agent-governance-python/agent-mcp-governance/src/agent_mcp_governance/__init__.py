# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""agent_mcp_governance — MCP-adjacent governance helpers for Agent Governance Toolkit.

Provides a focused import surface over the governance, audit, and trust primitives
that are currently available from ``agent-os-kernel``.
"""

from __future__ import annotations

__version__ = "0.1.0"

from agent_os.audit_logger import AuditEntry, GovernanceAuditLogger
from agent_os.compat import GovernanceMiddleware, PolicyEvaluator
from agent_os.integrations.base import GovernancePolicy
from agent_os.trust_root import TrustDecision, TrustRoot

__all__ = [
    "__version__",
    "AuditEntry",
    "GovernanceAuditLogger",
    "GovernanceMiddleware",
    "GovernancePolicy",
    "PolicyEvaluator",
    "TrustDecision",
    "TrustRoot",
]
