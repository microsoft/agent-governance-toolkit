# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import warnings
warnings.warn(
    "adk-agentmesh is deprecated and will be removed in a future release. "
    "Use agent-governance-toolkit-integrations[adk] instead. "
    "See https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)

from adk_agentmesh.audit import AuditEvent
from adk_agentmesh.evaluator import ADKPolicyEvaluator
from adk_agentmesh.governance import DelegationScope, GovernanceCallbacks

__all__ = [
    "ADKPolicyEvaluator",
    "AuditEvent",
    "DelegationScope",
    "GovernanceCallbacks",
]
