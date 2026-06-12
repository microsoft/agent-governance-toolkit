#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Google ADK + Governance Toolkit — End-to-End Demo
================================================

Demonstrates Google ADK governance enforcement using GoogleADKKernel.

Governance scenarios:
  1. Blocked Tool Enforcement
  2. Tool Allowlist Enforcement
  3. Dangerous Content Detection
  4. Human Approval Workflow
  5. Sensitive Tool Approval
  6. Tool Call Limits
  7. Budget Controls
  8. Audit Trail Review
  9. Governance Summary

Usage:

    python examples/adk-governed/adk_governance_demo.py
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

def banner(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def scenario(title: str) -> None:
    print(f"\n[{title}]")


def show_result(result) -> None:
    if result is None:
        print("  ALLOWED")
    elif isinstance(result, dict) and result.get("error"):
        print(f"  BLOCKED -> {result['error']}")
    else:
        print(f"  RESULT -> {result}")

banner("Google ADK + Governance Toolkit — End-to-End Demo")

kernel = GoogleADKKernel(
    max_tool_calls=20,
    allowed_tools=["search", "summarize", "send_email"],
    blocked_tools=["execute_shell", "run_command"],
    blocked_patterns=["DROP TABLE", "rm -rf"],
    require_human_approval=True,
    sensitive_tools=["send_email"],
    max_budget=5.0,
    on_violation=lambda _e: None,
)

scenario("1. Blocked Tool Enforcement")

result = kernel.before_tool_callback(
    tool_name="execute_shell",
    tool_args={},
    agent_name="research-agent",
)
show_result(result)


scenario("2. Tool Allowlist Enforcement")

result = kernel.before_tool_callback(
    tool_name="web_scraper",
    tool_args={},
    agent_name="research-agent",
)
show_result(result)


scenario("3. Dangerous Content Detection")

result = kernel.before_tool_callback(
    tool_name="search",
    tool_args={"query": "DROP TABLE users"},
    agent_name="research-agent",
)
show_result(result)

scenario("4. Human Approval Workflow")

result = kernel.before_tool_callback(
    tool_name="send_email",
    tool_args={"to": "user@example.com"},
    agent_name="publisher-agent",
)
show_result(result)


scenario("5. Sensitive Tool Approval")

result = kernel.before_tool_callback(
    tool_name="send_email",
    tool_args={"subject": "Governance Demo"},
    agent_name="publisher-agent",
)
show_result(result)


scenario("6. Tool Call Limits")

limit_kernel = GoogleADKKernel(
    max_tool_calls=3,
    blocked_tools=["execute_shell"],
    on_violation=lambda _e: None,
)

for i in range(5):
    result = limit_kernel.before_tool_callback(
        tool_name="execute_shell",
        tool_args={},
        agent_name="research-agent",
    )

print("  Final limit check:")
show_result(result)

scenario("7. Budget Controls")

print("  Budget limit configured:", kernel.get_stats().get("budget_limit"))


scenario("8. Audit Trail Review")

stats = kernel.get_stats()

print("  Violations:", stats.get("violations"))
print("  Audit Events:", stats.get("audit_events"))


scenario("9. Governance Summary")

violations = kernel.get_violations()

print("  Total Violations:", len(violations))

for i, violation in enumerate(violations, start=1):
    print(
        f"    [{i}] "
        f"{violation.policy_name}: "
        f"{violation.description}"
    )

print("\nDemo complete.")
