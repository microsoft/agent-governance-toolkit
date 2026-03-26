# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
LangChain Agent with Policy Enforcement — Quickstart
=====================================================

pip install agent-governance-toolkit[full] langchain langchain-openai
python examples/quickstart/langchain_governed.py

Shows a real policy violation being caught, then a compliant call succeeding,
with a printed audit trail.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

# Allow running from the repo root without installing the toolkit.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

from agent_os.integrations import LangChainKernel
from agent_os.integrations.base import GovernancePolicy

# ── 1. Define a strict governance policy ──────────────────────────────────
policy = GovernancePolicy(
    name="langchain-demo-policy",
    blocked_patterns=["DROP TABLE", "rm -rf"],  # ban dangerous patterns
    require_human_approval=False,
    max_tool_calls=5,
)

kernel = LangChainKernel(policy=policy)
ctx = kernel.create_context("langchain-demo-agent")
audit: list[dict] = []

print("=" * 60)
print("  LangChain Agent — Governance Quickstart")
print("=" * 60)

# ── 2. Policy violation: blocked content pattern ──────────────────────────
print("\n[1] Agent task containing a dangerous SQL pattern …")
allowed, reason = kernel.pre_execute(ctx, "Execute: DROP TABLE users; SELECT 1")
if not allowed:
    print(f"    🚫 BLOCKED — {reason}")
    audit.append(
        {"ts": datetime.now().isoformat(), "input": "DROP TABLE", "status": "BLOCKED"}
    )

# ── 3. Policy violation: call budget exhausted ────────────────────────────
print("\n[2] Exceeding the maximum call budget …")
ctx.call_count = policy.max_tool_calls
allowed, reason = kernel.pre_execute(ctx, "Summarise the quarterly report")
if not allowed:
    print(f"    🚫 BLOCKED — {reason}")
    audit.append(
        {
            "ts": datetime.now().isoformat(),
            "input": "summarise reports",
            "status": "BLOCKED",
        }
    )
ctx.call_count = 0  # reset for the next check

# ── 4. Compliant call succeeds ────────────────────────────────────────────
print("\n[3] Safe agent input passes policy check …")
allowed, reason = kernel.pre_execute(ctx, "What is the weather in London today?")
if allowed:
    print("    ✅ ALLOWED — policy check passed")
    audit.append(
        {
            "ts": datetime.now().isoformat(),
            "input": "weather query",
            "status": "ALLOWED",
        }
    )

# ── 5. Print audit trail ──────────────────────────────────────────────────
print("\n── Audit Trail ──────────────────────────────────────────")
for i, entry in enumerate(audit, 1):
    print(f"  [{i}] {entry['ts']}  input={entry['input']!r}  status={entry['status']}")

print("\n🎉 LangChain governance demo complete.")
