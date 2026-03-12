# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Compliance - Unified installer and compliance documentation.

Install the full stack:
    pip install ai-agent-compliance[full]

Components:
    - agent-os-kernel: Governance kernel with policy enforcement
    - agentmesh-platform: Zero-trust agent communication (SSL for AI Agents)
    - agent-hypervisor: Runtime supervisor with execution rings
    - agent-sre: Site reliability engineering for AI agents
"""

__version__ = "1.0.2"

# Re-export core components for convenience
try:
    from agent_os import StatelessKernel, ExecutionContext  # noqa: F401
except ImportError:
    pass

try:
    from agentmesh import TrustManager  # noqa: F401
except ImportError:
    pass
