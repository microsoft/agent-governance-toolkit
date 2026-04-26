# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Cascading failure protection for multi-agent workflows (OWASP ASI08)."""

from agent_sre.cascade.circuit_breaker import (
    CascadeDetector,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpen,
    CircuitOpenError,
)

__all__ = [
    "CascadeDetector",
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerOpen",
    "CircuitOpenError",
]
