# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Cedarling + AGT policy evaluation example.

Demonstrates how CedarlingBackend integrates with AGT's PolicyEvaluator
as an external backend — without modifying AGT core.

Run:
    pip install agent-os-kernel cedarling_agentmesh
    python example.py

To use real Cedarling evaluation, also install the Python bindings:
    pip install cedarling-python

Or set CEDARLING_URL to point at an existing Cedarling HTTP service.
"""

from __future__ import annotations

import os

from agent_os.policies import PolicyEvaluator
from cedarling_agentmesh import CedarlingBackend

# ---------------------------------------------------------------------------
# Configure the backend
# ---------------------------------------------------------------------------

# The backend selects its runtime automatically:
#   1. cedarling_python bindings (if installed)
#   2. HTTP service at CEDARLING_URL (if set)
#   3. Safe denial with a clear error message (if neither is available)

cedarling_url = os.environ.get("CEDARLING_URL")

backend = CedarlingBackend(
    bootstrap_config={
        "application_name": "cedarling-governed-example",
        "policy_store_uri": os.environ.get(
            "POLICY_STORE_URI",
            "https://example.com/cedarling/policies",
        ),
    },
    cedarling_url=cedarling_url,
    mode="auto",
)

# ---------------------------------------------------------------------------
# Build the evaluator and register the backend
# ---------------------------------------------------------------------------

evaluator = PolicyEvaluator()
evaluator.add_backend(backend)

# ---------------------------------------------------------------------------
# Evaluate tool calls
# ---------------------------------------------------------------------------

test_cases = [
    {"tool_name": "read_data",    "agent_id": "agent-analyst",  "resource": "reports"},
    {"tool_name": "write_record", "agent_id": "agent-writer",   "resource": "db"},
    {"tool_name": "delete_file",  "agent_id": "agent-untrusted","resource": "system"},
]

print(f"Cedarling backend: {backend.name!r}")
print(f"Runtime: cedarling_url={cedarling_url or '(none)'}")
print()

for ctx in test_cases:
    decision = evaluator.evaluate(ctx)
    status = "ALLOW" if decision.allowed else "DENY "
    print(f"[{status}] {ctx['agent_id']} → {ctx['tool_name']}")
    print(f"         reason : {decision.reason}")
    print(f"         backend: {decision.backend}  timing: {decision.evaluation_ms:.1f}ms")
    if decision.error:
        print(f"         error  : {decision.error}")
    print()
