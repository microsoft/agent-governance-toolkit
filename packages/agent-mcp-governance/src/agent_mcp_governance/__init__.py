# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""agent_mcp_governance — MCP governance primitives for the Agent Governance Toolkit.

Re-exports the core governance, audit, trust, and monitoring classes from
``agent-os-kernel`` so that downstream consumers can depend on a single,
focused package.
"""

from __future__ import annotations

__version__ = "0.1.0"

from agent_os.governance.middleware import GovernanceMiddleware
from agent_os.audit.middleware import AuditMiddleware
from agent_os.trust.gate import TrustGate
from agent_os.services.behavior_monitor import BehaviorMonitor

__all__ = [
    "__version__",
    "GovernanceMiddleware",
    "AuditMiddleware",
    "TrustGate",
    "BehaviorMonitor",
]
