# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CLI entry point for running AgentMesh component servers.

Usage:
    python -m agentmesh.server trust-engine
    python -m agentmesh.server policy-server
    python -m agentmesh.server audit-collector
    python -m agentmesh.server api-gateway

Or via AGENTMESH_COMPONENT env var (used by Docker):
    AGENTMESH_COMPONENT=trust-engine python -m agentmesh.server
"""

import os
import sys

COMPONENTS = {
    "trust-engine": ("agentmesh.server.trust_engine", "main"),
    "policy-server": ("agentmesh.server.policy_server", "main"),
    "audit-collector": ("agentmesh.server.audit_collector", "main"),
    "api-gateway": ("agentmesh.server.api_gateway", "main"),
}


def main() -> None:
    # Accept component from CLI arg or AGENTMESH_COMPONENT env var
    component = None
    if len(sys.argv) >= 2 and sys.argv[1] in COMPONENTS:
        component = sys.argv[1]
    else:
        component = os.getenv("AGENTMESH_COMPONENT")

    if component not in COMPONENTS or not component:
        print("Usage: python -m agentmesh.server <component>")
        print("   or: AGENTMESH_COMPONENT=<component> python -m agentmesh.server")
        print("Components:", ", ".join(COMPONENTS))
        sys.exit(1)

    module_path, func_name = COMPONENTS[component]

    import importlib

    mod = importlib.import_module(module_path)
    getattr(mod, func_name)()


if __name__ == "__main__":
    main()
