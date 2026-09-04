# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""cedarling-acs: Cedarling policy dispatcher for the AGT ACS v5 runtime.

Bring Cedarling authorization into AGT through the v5 custom policy extension
point instead of the removed v4 ``ExternalPolicyBackend`` adapter.

    from agent_control_specification import AgentControl
    from cedarling_acs import CedarlingPolicyDispatcher, CedarlingConfig

    dispatcher = CedarlingPolicyDispatcher.from_bootstrap(
        {"CEDARLING_POLICY_STORE_LOCAL_FN": "policy-store.json"},
        config=CedarlingConfig(auth_type="multi-issuer"),
    )
    runtime = AgentControl.from_path("manifest.yaml", policy_dispatcher=dispatcher)

The manifest binds a ``type: custom`` policy with ``adapter: cedarling`` at the
intervention points Cedarling should govern.
"""

from cedarling_acs.dispatcher import CedarlingConfig, CedarlingPolicyDispatcher

__all__ = ["CedarlingPolicyDispatcher", "CedarlingConfig"]
