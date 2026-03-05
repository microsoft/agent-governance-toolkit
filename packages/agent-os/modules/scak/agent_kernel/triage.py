# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic self-correction with retry
"""
Failure Triage — always returns SYNC_JIT in Community Edition.
"""

from enum import Enum
from typing import Dict, Any, Optional


class FixStrategy(Enum):
    """Strategy for fixing agent failures."""
    SYNC_JIT = "jit_retry"
    ASYNC_BATCH = "async_patch"


class FailureTriage:
    """Community Edition triage — always routes to synchronous retry."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def decide_strategy(
        self,
        prompt: str,
        tool_name: Optional[str] = None,
        user_metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> FixStrategy:
        """Always return SYNC_JIT."""
        return FixStrategy.SYNC_JIT

    def is_critical(
        self,
        prompt: str,
        tool_name: Optional[str] = None,
        user_metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        return True
