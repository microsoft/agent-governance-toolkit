# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent Sandbox — Docker-based execution isolation for AI agents.

Provides ``SandboxProvider``, the abstract base class for all sandbox
backends, and ``DockerSandboxProvider``, a hardened Docker implementation
with policy-driven resource limits, tool/network proxies, and filesystem
checkpointing via ``docker commit``.
"""

from agent_sandbox.sandbox_provider import (
    ExecutionHandle,
    ExecutionStatus,
    SandboxConfig,
    SandboxProvider,
    SandboxResult,
    SessionHandle,
    SessionStatus,
)
from agent_sandbox.isolation_runtime import IsolationRuntime
from agent_sandbox.docker_sandbox_provider import DockerSandboxProvider
from agent_sandbox.state import SandboxCheckpoint, SandboxStateManager

__version__ = "3.2.2"
__author__ = "Microsoft Corporation"

__all__ = [
    "DockerSandboxProvider",
    "ExecutionHandle",
    "ExecutionStatus",
    "IsolationRuntime",
    "SandboxCheckpoint",
    "SandboxConfig",
    "SandboxProvider",
    "SandboxResult",
    "SandboxStateManager",
    "SessionHandle",
    "SessionStatus",
]
