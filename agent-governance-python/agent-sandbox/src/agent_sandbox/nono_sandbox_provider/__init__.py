# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""nono-backed sandbox provider for ``agent-sandbox``.

Implements :class:`agent_sandbox.SandboxProvider` on top of
`nono <https://github.com/always-further/nono>`_ (Apache-2.0), a
capability-based sandbox enforced by OS-native kernel primitives
(Landlock on Linux, Seatbelt on macOS), via its ``nono-py`` Python
bindings. Linux and macOS only.

Importing :class:`NonoSandboxProvider` does not require ``nono-py`` to be
present — the dependency is resolved when the provider is constructed and
``is_available()`` is queried.

See ``docs/proposals/NONO-SANDBOX-PROVIDER.md`` for the design rationale.
"""

from agent_sandbox.nono_sandbox_provider.config import (
    NonoConfig,
    default_system_paths,
    nono_config_from_policy,
    policy_yaml_to_nono_config,
)
from agent_sandbox.nono_sandbox_provider.provider import NonoSandboxProvider

__all__ = [
    "NonoConfig",
    "NonoSandboxProvider",
    "default_system_paths",
    "nono_config_from_policy",
    "policy_yaml_to_nono_config",
]
