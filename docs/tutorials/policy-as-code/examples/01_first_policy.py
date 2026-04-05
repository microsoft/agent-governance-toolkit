# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Chapter 1: Your First Policy — Allow/Deny Basics

Loads a YAML policy and evaluates three agent actions against it.

Run from the repo root:
    pip install agent-os-kernel[full]
    python docs/tutorials/policy-as-code/examples/01_first_policy.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from the repo root without installing the packages.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument

# ── 1. Load the policy ──────────────────────────────────────────────────

evaluator = PolicyEvaluator()
policy_path = Path(__file__).parent / "01_first_policy.yaml"
evaluator.policies.append(PolicyDocument.from_yaml(policy_path))

# ── 2. Simulate three agent actions ─────────────────────────────────────

scenarios = [
    {"tool_name": "delete_database", "description": "Agent tries to delete a database"},
    {"tool_name": "send_email", "description": "Agent tries to send an email"},
    {"tool_name": "search_documents", "description": "Agent tries to search documents"}
]

# ── 3. Evaluate each action against the policy ──────────────────────────

print("=" * 60)
print("  Chapter 1: Your First Policy")
print("=" * 60)

for scenario in scenarios:
    context = {"tool_name": scenario["tool_name"]}
    decision = evaluator.evaluate(context)

    status = "ALLOWED" if decision.allowed else "DENIED"
    icon = "\u2705" if decision.allowed else "\U0001f6ab"
    print(f"\n{icon} {scenario['description']}")
    print(f"   Tool:   {scenario['tool_name']}")
    print(f"   Result: {status}")
    print(f"   Reason: {decision.reason}")

print("\n" + "=" * 60)
print(f"  Done. {len(scenarios)} actions evaluated.")
print("=" * 60)
