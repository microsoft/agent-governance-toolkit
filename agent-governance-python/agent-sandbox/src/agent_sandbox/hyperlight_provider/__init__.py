# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Hyperlight-backed sandbox provider for ``agent-sandbox``.

Implements :class:`agent_sandbox.SandboxProvider` on top of the upstream
`hyperlight-sandbox <https://github.com/hyperlight-dev/hyperlight-sandbox>`_
project (CNCF Sandbox, Apache-2.0).

See ``docs/proposals/HYPERLIGHT-SANDBOX-ISOLATION-DESIGN.md`` for the
design rationale.

Importing :class:`HyperLightSandboxProvider` does not require
``hyperlight-sandbox`` to be installed; the dependency is only resolved
when the provider is constructed and ``is_available()`` is queried.
"""

from agent_sandbox.hyperlight_provider.config import (
    HyperlightConfig,
    hyperlight_config_from_policy,
)
from agent_sandbox.hyperlight_provider.provider import (
    HyperlightBackend,
    HyperLightSandboxProvider,
    SnapshotHandle,
)

__all__ = [
    "HyperlightBackend",
    "HyperlightConfig",
    "HyperLightSandboxProvider",
    "SnapshotHandle",
    "hyperlight_config_from_policy",
]
