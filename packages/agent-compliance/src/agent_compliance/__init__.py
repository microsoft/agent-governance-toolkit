# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Governance - Unified installer and runtime policy enforcement.

Install the full stack:
    pip install agent-governance-toolkit[full]

Note: The package was previously published as ``ai-agent-compliance``.
That name is deprecated and will redirect here for 6 months.

Components:
    - agent-os-kernel: Governance kernel with policy enforcement
    - agentmesh-platform: Zero-trust agent communication (SSL for AI Agents)
    - agent-runtime: Runtime supervisor with execution rings
    - agent-sre: Site reliability engineering for AI agents
    - agentmesh-marketplace: Plugin lifecycle management
    - agent-lightning: RL training governance
"""

__version__ = "1.1.0"

# Re-export core components for convenience
try:
    from agent_os import StatelessKernel, ExecutionContext  # noqa: F401
except ImportError:
    pass

try:
    from agentmesh import TrustManager  # noqa: F401
except ImportError:
    pass
