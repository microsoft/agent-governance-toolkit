# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CrewAI Crew with Governance Middleware — Quickstart
====================================================

pip install agent-governance-toolkit[full] crewai
python examples/quickstart/crewai_governed.py

Shows a real policy violation being caught, then a compliant run succeeding,
with a printed audit trail.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

from agent_os.integrations import CrewAIKernel
from agent_os.integrations.base import GovernancePolicy, PolicyViolationError

# ── 1. Define a governance policy ─────────────────────────────────────────
policy = GovernancePolicy(
    name="crewai-demo-policy",
    blocked_patterns=["DROP TABLE", "rm -rf"],  # dangerous SQL/shell commands
    max_tool_calls=3,
    require_human_approval=False,
)

kernel = CrewAIKernel(policy=policy)
ctx = kernel.create_context("crewai-demo-crew")
audit: list[dict] = []

print("=" * 60)
print("  CrewAI Crew — Governance Quickstart")
print("=" * 60)

# ── 2. Policy violation: blocked content pattern ───────────────────────────
print("\n[1] Crew task with a dangerous SQL injection pattern …")
allowed, reason = kernel.pre_execute(ctx, "Execute: DROP TABLE users")
if not allowed:
    print(f"    🚫 BLOCKED — {reason}")
    audit.append({"ts": datetime.now().isoformat(), "task": "DROP TABLE users", "status": "BLOCKED"})

# ── 3. Policy violation: call budget exhausted ────────────────────────────
print("\n[2] Exhausting the call budget …")
ctx.call_count = policy.max_tool_calls  # simulate budget consumed
allowed, reason = kernel.pre_execute(ctx, "Summarise quarterly reports")
if not allowed:
    print(f"    🚫 BLOCKED — {reason}")
    audit.append({"ts": datetime.now().isoformat(), "task": "summarise reports", "status": "BLOCKED"})
ctx.call_count = 0  # reset for next check

# ── 4. Compliant task succeeds ────────────────────────────────────────────
print("\n[3] Safe crew task passes policy check …")
allowed, reason = kernel.pre_execute(ctx, "Summarise the quarterly financial reports")
if allowed:
    print("    ✅ ALLOWED — policy check passed")
    audit.append({"ts": datetime.now().isoformat(), "task": "summarise reports", "status": "ALLOWED"})

# ── 5. Audit trail ────────────────────────────────────────────────────────
print("\n── Audit Trail ──────────────────────────────────────────")
for i, entry in enumerate(audit, 1):
    print(f"  [{i}] {entry['ts']}  task={entry['task']!r}  status={entry['status']}")

print("\n🎉 CrewAI governance demo complete.")
