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
    - agentmesh-runtime: Runtime supervisor with execution rings
    - agent-sre: Site reliability engineering for AI agents
    - agentmesh-marketplace: Plugin lifecycle management
    - agent-lightning: RL training governance
"""

import logging

__version__ = "3.2.2"

_logger = logging.getLogger(__name__)

# Re-export optional companion packages. The legacy ``try: import; except
# ImportError: pass`` form silenced every failure with no breadcrumb,
# which made "why isn't ``StatelessKernel`` resolvable?" much harder to
# diagnose than it needed to be (typo'd extras install, broken venv,
# half-uninstalled agent-os). A DEBUG-level log line records the missing
# symbol and the original exception message so opt-in debugging
# (``logging.getLogger("agent_compliance").setLevel(logging.DEBUG)``)
# surfaces the cause without spamming default-config callers.
try:
    from agent_os import StatelessKernel, ExecutionContext  # noqa: F401
except ImportError as exc:
    _logger.debug(
        "agent_compliance: optional dependency 'agent_os' not importable "
        "(StatelessKernel, ExecutionContext unavailable): %s",
        exc,
    )

try:
    from agentmesh import TrustManager  # noqa: F401
except ImportError as exc:
    _logger.debug(
        "agent_compliance: optional dependency 'agentmesh' not importable "
        "(TrustManager unavailable): %s",
        exc,
    )

from agent_compliance.supply_chain import (  # noqa: F401,E402
    SupplyChainGuard,
    SupplyChainFinding,
    SupplyChainConfig,
)
from agent_compliance.prompt_defense import (  # noqa: F401,E402
    PromptDefenseEvaluator,
    PromptDefenseConfig,
    PromptDefenseFinding,
    PromptDefenseReport,
)
