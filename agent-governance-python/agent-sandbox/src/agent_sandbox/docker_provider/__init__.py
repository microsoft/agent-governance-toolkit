# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Docker-backed sandbox provider for ``agent-sandbox``.

Implements :class:`agent_sandbox.SandboxProvider` on top of hardened
Docker containers with explicit resource and network configuration plus
filesystem checkpointing via ``docker commit``.

Importing :class:`DockerSandboxProvider` requires the optional
``docker`` SDK to be installed.
"""

from agent_sandbox.docker_provider.provider import (
    DockerSandboxProvider,
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
    "has_iptables",
]
