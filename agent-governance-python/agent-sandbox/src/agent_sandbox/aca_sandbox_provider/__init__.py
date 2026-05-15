# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Azure Container Apps (ACA) sandbox provider package.

Re-exports the provider class and public helpers from
:mod:`agent_sandbox.aca_sandbox_provider.aca_sandbox_provider`
so callers can write ``from agent_sandbox.aca_sandbox_provider
import ACASandboxProvider``.
"""

from agent_sandbox.aca_sandbox_provider.aca_sandbox_provider import (
    ACASandboxProvider,
    aca_config_from_policy,
)

# Note: ``_network_allowlist``, ``_network_default``, and
# ``_validate_resource_name`` remain importable from the implementation
# module for tests, but are intentionally excluded from ``__all__``.
# Their underscore prefix marks them as internal — they may be
# refactored or removed without a deprecation cycle.
__all__ = [
    "ACASandboxProvider",
    "aca_config_from_policy",
]
