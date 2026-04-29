# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent Sandbox — Docker-based execution isolation for AI agents.

Provides ``SandboxProvider``, the abstract base class for all sandbox
backends, and ``DockerSandboxProvider``, a hardened Docker implementation
with policy-driven resource limits, tool/network proxies, and filesystem
checkpointing via ``docker commit``.
"""

from importlib.metadata import PackageNotFoundError, version

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
from agent_sandbox.state import SandboxCheckpoint, SandboxStateManager

# Lazy import: DockerSandboxProvider requires the optional ``docker`` SDK.
try:
    from agent_sandbox.docker_sandbox_provider import DockerSandboxProvider
except ImportError:
    DockerSandboxProvider = None  # type: ignore[assignment,misc]

try:
    __version__ = version("agent-sandbox")
except PackageNotFoundError:
    __version__ = "0.0.0"
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
