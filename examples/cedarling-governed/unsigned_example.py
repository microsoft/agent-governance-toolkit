# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""No-JWT (unsigned) authorization for agents with Cedarling + AGT ACS v5.

For internal services, background jobs, and test harnesses there is often no
token to present. In unsigned mode the principal's identity and attributes come
straight from the snapshot: ``envelope.agent.id`` becomes the principal and
``envelope.agent.attributes`` (e.g. ``{"role": "admin"}``) populate its entity
attributes. Cedarling then evaluates Cedar policies against those attributes,
a role-based access control setup.

Cedarling runs through the ACS v5 custom policy extension point. The
``CedarlingPolicyDispatcher`` implements ``agent_control_specification.PolicyDispatcher``,
so its decisions flow through the native runtime with no change to AGT core.
Authorization is made in-process against the bundled local policy store in
``./policy-stores/unsigned``.

Run:
    pip install -r requirements.txt
    python unsigned_example.py

For the JWT / trusted-issuer path, see multi_issuer_example.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Run straight from a source checkout: if cedarling_acs is not installed, add
# its package source to the path before importing.
_PKG_SRC = (
    Path(__file__).resolve().parents[2]
    / "agent-governance-python"
    / "agentmesh-integrations"
    / "cedarling-acs"
)
if _PKG_SRC.is_dir() and str(_PKG_SRC) not in sys.path:
    sys.path.insert(0, str(_PKG_SRC))

try:
    from cedarling_acs import CedarlingConfig, CedarlingPolicyDispatcher
except ImportError:
    sys.exit(
        "This example needs the Cedarling dispatcher and the cedarling-python\n"
        "engine. Install them with:\n"
        "    pip install -r requirements.txt\n"
        "and run from a checkout of the repository."
    )

# ---------------------------------------------------------------------------
# Configure the dispatcher (unsigned authorization)
# ---------------------------------------------------------------------------
#
# Cedarling evaluates policies in-process. Point it at the local policy store
# directory shipped next to this script (metadata.json + schema + policies).
# CEDARLING_POLICY_STORE_LOCAL_FN accepts a directory or a packaged JSON file.

POLICY_STORE = str(Path(__file__).resolve().parent / "policy-stores" / "unsigned")

dispatcher = CedarlingPolicyDispatcher.from_bootstrap(
    {
        "CEDARLING_POLICY_STORE_LOCAL_FN": POLICY_STORE,
        # Keep the example output clean; flip to "std_out" to see engine logs.
        "CEDARLING_LOG_TYPE": "off",
    },
    application_name="cedarling-governed-example",
    # The Cedar schema in policy-stores/unsigned/ declares its entities under
    # the "AGT" namespace, so the dispatcher prefixes principal/resource/action
    # accordingly (e.g. AGT::Agent, AGT::Action::"pre_tool_call").
    config=CedarlingConfig(namespace="AGT", auth_type="unsigned"),
)


# ---------------------------------------------------------------------------
# Build an ACS policy input
# ---------------------------------------------------------------------------
#
# The native runtime hands the dispatcher the final policy input under
# invocation["input"]. Here we build it by hand so the example is self
# contained. The dispatcher maps it to a Cedar query:
#   envelope.agent.id         -> principal id            (AGT::Agent)
#   envelope.agent.attributes -> principal entity attributes (unsigned only)
#   intervention_point        -> action  (AGT::Action::"pre_tool_call")
#   tool.name                 -> resource id             (AGT::Tool)
#
# Policies in policy-stores/unsigned/:
#   allow-admin-tools     : permit pre_tool_call on any Tool when role == "admin"
#   forbid-auditor-delete : forbid pre_tool_call on Tool::"delete_file" for auditor
# Anything not permitted is denied by default.


def policy_input(*, agent_id: str, role: str, tool: str) -> dict:
    return {
        "input": {
            "intervention_point": "pre_tool_call",
            "policy_target": {
                "kind": "tool_args",
                "path": "$.tool_call.args",
                "value": {},
            },
            "snapshot": {
                "envelope": {"agent": {"id": agent_id, "attributes": {"role": role}}}
            },
            "annotations": {},
            "tool": {"name": tool, "clearance": "public"},
        }
    }


test_cases = [
    # admin calling any tool -> matches allow-admin-tools -> ALLOW
    {"agent_id": "agent-analyst", "role": "admin", "tool": "read_data"},
    # guest calling a tool -> no permit applies -> DENY (default deny)
    {"agent_id": "agent-guest", "role": "guest", "tool": "read_data"},
    # admin deleting -> admin permit still applies -> ALLOW
    {"agent_id": "agent-writer", "role": "admin", "tool": "delete_file"},
    # auditor deleting -> matches forbid-auditor-delete -> DENY (explicit forbid)
    {"agent_id": "agent-auditor", "role": "auditor", "tool": "delete_file"},
]

print(f"Policy store : {POLICY_STORE}")
print()

for case in test_cases:
    verdict = dispatcher.evaluate(policy_input(**case))
    status = "ALLOW" if verdict["decision"] == "allow" else "DENY "
    print(
        f"[{status}] {case['agent_id']} (role={case['role']}) "
        f"→ pre_tool_call on {case['tool']}"
    )
    print(f"         decision: {verdict['decision']}  reason: {verdict.get('reason')}")
    print()
