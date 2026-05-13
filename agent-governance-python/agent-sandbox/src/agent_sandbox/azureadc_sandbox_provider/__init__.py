# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Azure ADC (Azure Dynamic Container) sandbox provider package.

Re-exports the provider class and public helpers from
:mod:`agent_sandbox.azureadc_sandbox_provider.azureadc_sandbox_provider`
so callers can write ``from agent_sandbox.azureadc_sandbox_provider
import AzureSandboxProvider``.
"""

from agent_sandbox.azureadc_sandbox_provider.azureadc_sandbox_provider import (
    AzureSandboxProvider,
    _network_allowlist,
    _network_default,
    _validate_resource_name,
    azure_config_from_policy,
)

__all__ = [
    "AzureSandboxProvider",
    "_network_allowlist",
    "_network_default",
    "_validate_resource_name",
    "azure_config_from_policy",
]
