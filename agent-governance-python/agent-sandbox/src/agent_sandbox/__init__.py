# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent Sandbox — execution isolation for AI agents.

Provides ``SandboxProvider``, the abstract base class for all sandbox
backends, plus three built-in implementations:

* :class:`DockerSandboxProvider` — hardened Docker containers with
  policy-driven resource limits, tool/network proxies, and filesystem
  checkpointing via ``docker commit``.
* :class:`HyperLightSandboxProvider` — micro-VM isolation backed by the
  upstream `hyperlight-sandbox <https://github.com/hyperlight-dev/hyperlight-sandbox>`_
  project (CNCF Sandbox). Capability-bound tools and domains, with
  in-memory snapshots.
* :class:`AzureSandboxProvider` — Azure Dynamic Container (ADC)
  managed sandbox sessions with host-side policy gating and Azure-side
  egress allowlist enforcement.
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
from agent_sandbox.docker_provider.state import SandboxCheckpoint, SandboxStateManager

# Lazy import: DockerSandboxProvider requires the optional ``docker`` SDK.
try:
    from agent_sandbox.docker_provider import DockerSandboxProvider
except ImportError:
    DockerSandboxProvider = None  # type: ignore[assignment,misc]

# Lazy import: HyperLightSandboxProvider requires the optional
# ``hyperlight-sandbox`` SDK. The class itself does not import the
# SDK at module load — the dependency is resolved at session-creation
# time — but we still wrap the import in ``try/except ImportError`` for
# symmetry with ``DockerSandboxProvider`` and to remain robust against
# future refactors that might pull the SDK in eagerly.
try:
    from agent_sandbox.hyperlight_provider import (
        HyperlightBackend,
        HyperlightConfig,
        HyperLightSandboxProvider,
        SnapshotHandle,
        hyperlight_config_from_policy,
    )
except ImportError:
    HyperlightBackend = None  # type: ignore[assignment,misc]
    HyperlightConfig = None  # type: ignore[assignment,misc]
    HyperLightSandboxProvider = None  # type: ignore[assignment,misc]
    SnapshotHandle = None  # type: ignore[assignment,misc]
    hyperlight_config_from_policy = None  # type: ignore[assignment]

# Lazy import: AzureSandboxProvider requires the optional
# ``azure-sandbox`` (and optionally ``azure-mgmt-sandbox``) SDKs.
try:
    from agent_sandbox.azureadc_sandbox_provider import AzureSandboxProvider
except ImportError:
    AzureSandboxProvider = None  # type: ignore[assignment,misc]

try:
    __version__ = version("agent-sandbox")
except PackageNotFoundError:
    __version__ = "0.0.0"
__author__ = "Microsoft Corporation"

__all__ = [
    "AzureSandboxProvider",
    "DockerSandboxProvider",
    "ExecutionHandle",
    "ExecutionStatus",
    "HyperLightSandboxProvider",
    "HyperlightBackend",
    "HyperlightConfig",
    "IsolationRuntime",
    "SandboxCheckpoint",
    "SandboxConfig",
    "SandboxProvider",
    "SandboxResult",
    "SandboxStateManager",
    "SessionHandle",
    "SessionStatus",
    "SnapshotHandle",
    "hyperlight_config_from_policy",
]
