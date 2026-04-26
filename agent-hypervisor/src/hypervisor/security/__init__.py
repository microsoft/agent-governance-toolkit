# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Security module — rate limiting, kill switch, and agent protection."""

from hypervisor.security.kill_switch import KillResult, KillSwitch
from hypervisor.security.rate_limiter import AgentRateLimiter, RateLimitExceeded

__all__ = [
    "AgentRateLimiter",
    "RateLimitExceeded",
    "KillSwitch",
    "KillResult",
]
