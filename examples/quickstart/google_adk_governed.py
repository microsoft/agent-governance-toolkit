# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Google ADK Agent with Policy Gates — Quickstart
================================================

pip install agent-governance-toolkit[full] google-adk
python examples/quickstart/google_adk_governed.py

Shows real policy violations being caught by ADK governance callbacks,
then a compliant call succeeding, with a printed audit trail.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

from agent_os.integrations.google_adk_adapter import GoogleADKKernel

# ── 1. Define a governance policy ─────────────────────────────────────────
kernel = GoogleADKKernel(
    max_tool_calls=10,
    allowed_tools=["search", "summarize"],  # explicit allowlist
    blocked_tools=["exec_code", "shell"],  # explicit blocklist
    blocked_patterns=["DROP TABLE", "rm -rf"],  # ban dangerous strings
    max_budget=5.0,  # cost cap per session
    on_violation=lambda _e: None,  # collect silently; printed below
)

print("=" * 60)
print("  Google ADK Agent — Governance Quickstart")
print("=" * 60)

# ── 2. Policy violation: blocked tool ────────────────────────────────────
print("\n[1] ADK callback — blocked tool ('shell') invoked by agent …")
result = kernel.before_tool_callback(
    tool_name="shell", tool_args={}, agent_name="adk-agent"
)
if result and result.get("error"):
    print(f"    🚫 BLOCKED — {result['error']}")

# ── 3. Policy violation: tool not on allowlist ────────────────────────────
print("\n[2] ADK callback — tool not on allowlist ('web_scraper') …")
result = kernel.before_tool_callback(
    tool_name="web_scraper", tool_args={}, agent_name="adk-agent"
)
if result and result.get("error"):
    print(f"    🚫 BLOCKED — {result['error']}")

# ── 4. Policy violation: blocked content in tool arguments ────────────────
print("\n[3] ADK callback — tool argument contains dangerous pattern …")
result = kernel.before_tool_callback(
    tool_name="search",
    tool_args={"query": "DROP TABLE sessions; SELECT 1"},
    agent_name="adk-agent",
)
if result and result.get("error"):
    print(f"    🚫 BLOCKED — {result['error']}")

# ── 5. Compliant tool call passes all policy gates ────────────────────────
print("\n[4] ADK callback — allowed tool with safe arguments …")
result = kernel.before_tool_callback(
    tool_name="search",
    tool_args={"query": "AI governance best practices"},
    agent_name="adk-agent",
)
if result is None:
    print("    ✅ ALLOWED — all policy gates passed")

# ── 6. Audit trail from kernel ────────────────────────────────────────────
stats = kernel.get_stats()
violations = kernel.get_violations()
print("\n── Kernel Stats ─────────────────────────────────────────")
print(f"  violations={stats['violations']}  audit_events={stats['audit_events']}")

print("\n── Audit Trail ──────────────────────────────────────────")
for i, v in enumerate(violations, 1):
    print(f"  [{i}] BLOCKED  policy={v.policy_name!r}  reason={v.description!r}")
for j, entry in enumerate(kernel.get_audit_log()[-1:], len(violations) + 1):
    print(
        f"  [{j}] ALLOWED  tool={entry.details.get('tool')!r}  agent={entry.agent_name!r}"
    )

print("\n🎉 Google ADK governance demo complete.")
