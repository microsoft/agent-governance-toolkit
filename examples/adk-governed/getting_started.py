# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Google ADK + Governance Toolkit — Getting Started
=================================================

Minimal example showing how to add governance to a Google ADK workflow.

    pip install agent-governance-toolkit[full] google-adk
    python examples/adk-governed/getting_started.py

What this demonstrates:
  1. Configure GoogleADKKernel governance
  2. Enforce tool allow/block policies
  3. Detect dangerous tool arguments
  4. Review audit events and violations

For the full showcase, run adk_governance_demo.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(
    0,
    str(_REPO_ROOT / "agent-governance-python" / "agent-os" / "src"),
)

from agent_os.integrations.google_adk_adapter import GoogleADKKernel


kernel = GoogleADKKernel(
    max_tool_calls=10,
    allowed_tools=["search", "summarize"],
    blocked_tools=["execute_shell", "run_command"],
    blocked_patterns=["DROP TABLE", "rm -rf"],
    on_violation=lambda _e: None,
)

print("=" * 60)
print("  Google ADK + Governance Toolkit — Getting Started")
print("=" * 60)

print("\n[1] Agent attempts blocked tool...")
result = kernel.before_tool_callback(
    tool_name="execute_shell",
    tool_args={},
    agent_name="research-agent",
)

if result and result.get("error"):
    print(f"    BLOCKED — {result['error']}")

print("\n[2] Agent attempts unauthorized tool...")
result = kernel.before_tool_callback(
    tool_name="web_scraper",
    tool_args={},
    agent_name="research-agent",
)

if result and result.get("error"):
    print(f"    BLOCKED — {result['error']}")

print("\n[3] Dangerous tool argument detected...")
result = kernel.before_tool_callback(
    tool_name="search",
    tool_args={"query": "DROP TABLE users"},
    agent_name="research-agent",
)

if result and result.get("error"):
    print(f"    BLOCKED — {result['error']}")

print("\n[4] Governance summary...")

stats = kernel.get_stats()

print("    Violations recorded:", stats["violations"])
print("    Audit events recorded:", stats["audit_events"])

stats = kernel.get_stats()
violations = kernel.get_violations()

print("\nGovernance Summary")
print("-" * 60)
print(f"Violations:   {stats['violations']}")
print(f"Audit Events: {stats['audit_events']}")

print("\nViolation Details")
for i, violation in enumerate(violations, start=1):
    print(
        f"  [{i}] {violation.policy_name}: "
        f"{violation.description}"
    )

print("\nDone! See adk_governance_demo.py for the full showcase.")