# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Primitives - Shared data models for Agent OS.

This is a Layer 1 primitive package providing foundational models
used across the Agent OS stack.
"""


import warnings as _warnings
_warnings.warn(
    "agentmesh-primitives is deprecated. Use agent-governance-toolkit-core instead. "
    "See https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)
del _warnings
__version__ = "3.2.2"

from .failures import (
    FailureType,
    FailureSeverity,
    FailureTrace,
    AgentFailure,
)

__all__ = [
    "FailureType",
    "FailureSeverity",
    "FailureTrace",
    "AgentFailure",
]
