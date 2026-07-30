# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""No-JWT (unsigned) authorization for agents with Cedarling + AGT.

For internal services, background jobs, and test harnesses there is often no
token to present. In unsigned mode the principal's identity and attributes come
straight from the request dict: ``agent_id`` becomes the principal and
``principal_attributes`` (e.g. ``{"role": "admin"}``) populate its entity
attributes. Cedarling then evaluates Cedar policies against those attributes —
a role-based access control setup.

Authorization decisions are made in-process by the Cedarling engine against the
bundled local policy store in ``./policy-stores/unsigned``.

Run:
    pip install -r requirements.txt
    pip install -e ../../agent-governance-python/agentmesh-integrations/cedarling-agentmesh
    python unsigned_example.py

For the JWT / trusted-issuer path, see multi_issuer_example.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

from agent_os.policies import PolicyEvaluator

try:
    from cedarling_agentmesh import CedarlingBackend
except ImportError:
    sys.exit(
        "This example needs the Cedarling bindings. Install them with:\n"
        "    pip install -r requirements.txt\n"
        "    pip install -e ../../agent-governance-python/agentmesh-integrations/cedarling-agentmesh\n"
        "(requirements.txt provides cedarling-python; cedarling_agentmesh installs from source)."
    )

# ---------------------------------------------------------------------------
# Configure the backend (unsigned authorization)
# ---------------------------------------------------------------------------
#
# Cedarling evaluates policies in-process. Point it at the local policy store
# directory shipped next to this script (metadata.json + schema + policies).
# CEDARLING_POLICY_STORE_LOCAL_FN accepts a directory or a packaged JSON file.

POLICY_STORE = str(Path(__file__).resolve().parent / "policy-stores" / "unsigned")

backend = CedarlingBackend(
    application_name="cedarling-governed-example",
    # The Cedar schema in policy-stores/unsigned/ declares its entities under
    # the "AGT" namespace, so the backend prefixes principal/resource/action
    # accordingly (e.g. AGT::Agent, AGT::Action::"ReadData").
    namespace="AGT",
    auth_type="unsigned",
    bootstrap_config={
        "CEDARLING_POLICY_STORE_LOCAL_FN": POLICY_STORE,
        # Keep the example output clean; flip to "std_out" to see engine logs.
        "CEDARLING_LOG_TYPE": "off",
    },
)

# ---------------------------------------------------------------------------
# Build the evaluator and register the backend
# ---------------------------------------------------------------------------

evaluator = PolicyEvaluator()
evaluator.add_backend(backend)

# ---------------------------------------------------------------------------
# Evaluate tool calls
# ---------------------------------------------------------------------------
#
# Each request maps to a Cedar authorization query:
#   agent_id             -> principal id        (AGT::Agent)
#   tool_name            -> action  (snake_case -> PascalCase, e.g. ReadData)
#   resource             -> resource id         (AGT::Resource)
#   principal_attributes -> principal entity attributes (unsigned auth only)
#
# Policies in policy-stores/unsigned/:
#   allow-read   : permit Read/ReadData when principal.role == "admin"
#   forbid-write : forbid Write when principal.role == "auditor"
# Anything not permitted is denied by default.

test_cases = [
    # admin reading data -> matches allow-read -> ALLOW
    {
        "tool_name": "read_data",
        "agent_id": "agent-analyst",
        "resource": "reports",
        "principal_attributes": {"role": "admin"},
    },
    # guest reading data -> no permit applies -> DENY (default deny)
    {
        "tool_name": "read_data",
        "agent_id": "agent-guest",
        "resource": "reports",
        "principal_attributes": {"role": "guest"},
    },
    # admin writing -> no permit for Write -> DENY (default deny)
    {
        "tool_name": "write",
        "agent_id": "agent-writer",
        "resource": "db",
        "principal_attributes": {"role": "admin"},
    },
    # auditor writing -> matches forbid-write -> DENY (explicit forbid)
    {
        "tool_name": "write",
        "agent_id": "agent-auditor",
        "resource": "db",
        "principal_attributes": {"role": "auditor"},
    },
]

print(f"Cedarling backend : {backend.name!r}")
print(f"Policy store       : {POLICY_STORE}")
print()

for ctx in test_cases:
    decision = evaluator.evaluate(ctx)
    audit = decision.audit_entry
    status = "ALLOW" if decision.allowed else "DENY "
    role = ctx["principal_attributes"]["role"]
    print(f"[{status}] {ctx['agent_id']} (role={role}) → {ctx['tool_name']} on {ctx['resource']}")
    print(f"         reason : {decision.reason}")
    print(f"         backend: {audit['backend']}  timing: {audit['evaluation_ms']:.2f}ms")
    print()
