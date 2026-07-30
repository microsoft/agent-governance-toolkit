# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ruff: noqa: E402 — deprecation warning must fire before re-exports
"""Agent Sandbox — execution isolation for AI agents.

Provides ``SandboxProvider``, the abstract base class for all sandbox
backends, plus five built-in implementations:

* :class:`DockerSandboxProvider` — hardened Docker containers with
  explicit resource limits and filesystem
  checkpointing via ``docker commit``.
* :class:`HyperLightSandboxProvider` — micro-VM isolation backed by the
  upstream `hyperlight-sandbox <https://github.com/hyperlight-dev/hyperlight-sandbox>`_
  project (CNCF Sandbox). Capability-bound tools and domains, with
  in-memory snapshots.
* :class:`ACASandboxProvider` — Azure Container Apps (ACA)
  managed sandbox sessions with native governance and Azure-side
  egress allowlist enforcement.
* :class:`MxcSandboxProvider` — `MXC <https://github.com/microsoft/mxc>`_
  (Microsoft eXecution Container) native sandbox runner driven through
  its ``wxc-exec`` / ``lxc-exec`` / ``mxc-exec-mac`` binary, with
  explicit filesystem and network configuration.
* :class:`NonoSandboxProvider` — `nono <https://github.com/always-further/nono>`_
  capability-based sandbox enforced by OS-native kernel primitives
  (Landlock on Linux, Seatbelt on macOS) via its ``nono-py`` bindings,
  with a filtering network proxy. Linux/macOS only.
"""


import warnings as _warnings
_warnings.warn(
    "agt-sandbox is deprecated. Use agent-governance-toolkit-cli instead. "
    "See https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)
del _warnings
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
    )
except ImportError:
    HyperlightBackend = None  # type: ignore[assignment,misc]
    HyperlightConfig = None  # type: ignore[assignment,misc]
    HyperLightSandboxProvider = None  # type: ignore[assignment,misc]
    SnapshotHandle = None  # type: ignore[assignment,misc]

# Lazy import: ACASandboxProvider requires the optional
# ``azure-sandbox`` (and optionally ``azure-mgmt-sandbox``) SDKs.
try:
    from agent_sandbox.aca_sandbox_provider import ACASandboxProvider
except ImportError:
    ACASandboxProvider = None  # type: ignore[assignment,misc]

# MxcSandboxProvider has no Python package dependency — it drives the
# native MXC binary via subprocess — but is imported defensively for
# symmetry with the other optional providers.
try:
    from agent_sandbox.mxc_sandbox_provider import (
        MxcConfig,
        MxcSandboxProvider,
    )
except ImportError:
    MxcConfig = None  # type: ignore[assignment,misc]
    MxcSandboxProvider = None  # type: ignore[assignment,misc]

# Lazy import: NonoSandboxProvider requires the optional ``nono-py``
# extension (Linux / macOS only).
try:
    from agent_sandbox.nono_sandbox_provider import (
        NonoConfig,
        NonoSandboxProvider,
    )
except ImportError:
    NonoConfig = None  # type: ignore[assignment,misc]
    NonoSandboxProvider = None  # type: ignore[assignment,misc]

try:
    __version__ = version("agt-sandbox")
except PackageNotFoundError:
    __version__ = "0.0.0"
__author__ = "Microsoft Corporation"

__all__ = [
    "ACASandboxProvider",
    "DockerSandboxProvider",
    "ExecutionHandle",
    "ExecutionStatus",
    "HyperLightSandboxProvider",
    "HyperlightBackend",
    "HyperlightConfig",
    "IsolationRuntime",
    "MxcConfig",
    "MxcSandboxProvider",
    "NonoConfig",
    "NonoSandboxProvider",
    "SandboxCheckpoint",
    "SandboxConfig",
    "SandboxProvider",
    "SandboxResult",
    "SandboxStateManager",
    "SessionHandle",
    "SessionStatus",
    "SnapshotHandle",
]
