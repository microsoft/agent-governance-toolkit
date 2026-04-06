# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Chapter 2: Capability Scoping — Restricting Tool Access by Agent Role

Demonstrates how different agents get different permissions by loading
separate policy files for each role.

Run from the repo root:
    pip install agent-os-kernel[full]
    python docs/tutorials/policy-as-code/examples/02_capability_scoping.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from the repo root without installing the packages.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument

# ── Helper ───────────────────────────────────────────────────────────────

EXAMPLES_DIR = Path(__file__).parent


def load_single_policy(filename: str) -> PolicyEvaluator:
    """Create an evaluator loaded with one specific policy file."""
    evaluator = PolicyEvaluator()
    policy = PolicyDocument.from_yaml(EXAMPLES_DIR / filename)
    evaluator.policies.append(policy)
    return evaluator


# ── 1. Load a separate policy for each role ──────────────────────────────

reader_evaluator = load_single_policy("02_reader_policy.yaml")
admin_evaluator = load_single_policy("02_admin_policy.yaml")

# ── 2. Define the same actions to test with both roles ───────────────────

actions = [
    {"tool_name": "search_documents"},
    {"tool_name": "send_email"},
    {"tool_name": "write_file"},
    {"tool_name": "delete_database"},
]

# ── 3. Evaluate each action for both roles ───────────────────────────────

print("=" * 64)
print("  Chapter 2: Capability Scoping")
print("=" * 64)
print(f"\n  {'Action':<25} {'Reader':<15} {'Admin':<15}")
print("  " + "-" * 55)

for action in actions:
    reader_decision = reader_evaluator.evaluate(action)
    admin_decision = admin_evaluator.evaluate(action)

    reader_status = "\u2705 allowed" if reader_decision.allowed else "\U0001f6ab denied"
    admin_status = "\u2705 allowed" if admin_decision.allowed else "\U0001f6ab denied"

    print(f"  {action['tool_name']:<25} {reader_status:<15} {admin_status:<15}")

print("\n" + "=" * 64)
print("  Same actions, different permissions per role.")
print("=" * 64)
