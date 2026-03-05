# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Primitives - Shared data models for Agent OS.

This is a Layer 1 primitive package providing foundational models
used across the Agent OS stack.
"""

__version__ = "0.2.0"

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
