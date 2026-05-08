# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Docker-backed sandbox provider for ``agent-sandbox``.

Implements :class:`agent_sandbox.SandboxProvider` on top of hardened
Docker containers with policy-driven resource limits, tool/network
proxies, and filesystem checkpointing via ``docker commit``.

Importing :class:`DockerSandboxProvider` requires the optional
``docker`` SDK to be installed.
"""

from agent_sandbox.docker_provider.provider import (
    DockerSandboxProvider,
    docker_config_from_policy,
    has_iptables,
)
from agent_sandbox.docker_provider.state import (
    SandboxCheckpoint,
    SandboxStateManager,
)

__all__ = [
    "DockerSandboxProvider",
    "SandboxCheckpoint",
    "SandboxStateManager",
    "docker_config_from_policy",
    "has_iptables",
]
