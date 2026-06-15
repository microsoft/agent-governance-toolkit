# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""MXC-backed sandbox provider for ``agent-sandbox``.

Implements :class:`agent_sandbox.SandboxProvider` on top of
`MXC <https://github.com/microsoft/mxc>`_ (Microsoft eXecution Container,
MIT), a native, JSON-configured sandbox runner with multiple OS-native
and VM containment backends.

MXC ships no Python SDK; this provider drives the native ``wxc-exec`` /
``lxc-exec`` / ``mxc-exec-mac`` binary as a subprocess. Importing
:class:`MxcSandboxProvider` does not require the binary to be present —
the dependency is only resolved when the provider is constructed and
``is_available()`` is queried.

See ``docs/proposals/MXC-SANDBOX-PROVIDER.md`` for the design rationale.
"""

from agent_sandbox.mxc_sandbox_provider.config import (
    MxcConfig,
    backend_requires_experimental,
    mxc_config_from_policy,
    policy_to_mxc_json,
    policy_yaml_to_mxc_json,
)
from agent_sandbox.mxc_sandbox_provider.provider import MxcSandboxProvider

__all__ = [
    "MxcConfig",
    "MxcSandboxProvider",
    "backend_requires_experimental",
    "mxc_config_from_policy",
    "policy_to_mxc_json",
    "policy_yaml_to_mxc_json",
]
