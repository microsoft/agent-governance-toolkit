# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Session Isolation Levels — stub implementation.

Public Preview: all access is serialized via a single lock.
Isolation levels are retained for API compatibility but not enforced.
"""

from __future__ import annotations

from enum import Enum


class IsolationLevel(str, Enum):
    """Session isolation levels (Public Preview: not enforced)."""

    SNAPSHOT = "snapshot"
    READ_COMMITTED = "read_committed"
    SERIALIZABLE = "serializable"

    @property
    def requires_vector_clocks(self) -> bool:
        return False

    @property
    def requires_intent_locks(self) -> bool:
        return False

    @property
    def allows_concurrent_writes(self) -> bool:
        return True

    @property
    def coordination_cost(self) -> str:
        return "none"
