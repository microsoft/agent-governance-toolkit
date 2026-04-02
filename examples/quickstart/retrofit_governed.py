# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Retrofit Governance — Standalone Verification Demo
===================================================

Companion script for docs/tutorials/retrofit-governance.md

Run from the repo root:
    pip install agent-governance-toolkit[full]
    python docs/tutorials/retrofit-governance-demo.py

No additional dependencies required. Works without an LLM API key —
governance runs entirely at the application layer.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

# Allow running from the repo root without installing the packages.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

from agent_os.integrations import LangChainKernel
from agent_os.integrations.base import GovernancePolicy

# ── 1. Your original agent — completely unchanged ─────────────────────────


def run_agent(user_input: str) -> str:
    """Simulated existing agent. No changes needed here."""
    return f"Agent result for: {user_input}"


# ── 2. Wrap it with governance (the only new code) ────────────────────────

policy = GovernancePolicy(
    name="my-agent-policy",
    blocked_patterns=["DROP TABLE", "rm -rf", "os.system"],
    max_tool_calls=10,
)
kernel = LangChainKernel(policy=policy)
ctx = kernel.create_context("retrofit-demo-agent")
audit: list[dict] = []


def governed_run(user_input: str) -> str:
    """Drop-in replacement: checks policy before delegating to run_agent."""
    allowed, reason = kernel.pre_execute(ctx, user_input)
    status = "ALLOWED" if allowed else "BLOCKED"
    audit.append(
        {
            "ts": datetime.now().isoformat(),
            "input": user_input[:40],
            "status": status,
        }
    )
    if not allowed:
        print(f"    🚫 BLOCKED — {reason}")
        return ""
    result = run_agent(user_input)
    print(f"    ✅ ALLOWED — {result}")
    return result


# ── 3. Verify it works ────────────────────────────────────────────────────

print("=" * 60)
print("  Retrofit Governance — Verification Demo")
print("=" * 60)

print("\n[1] Dangerous SQL input …")
governed_run("DROP TABLE users;")

print("\n[2] Shell injection attempt …")
governed_run("rm -rf /data")

print("\n[3] Safe input …")
governed_run("Summarise last week's sales report")

print("\n── Audit Trail ─────────────────────────────────────────────")
for i, entry in enumerate(audit, 1):
    print(
        f"  [{i}] {entry['ts']}  "
        f"input={entry['input']!r:<42}  "
        f"status={entry['status']}"
    )

print(f"\n🎉 Governance is working. {len(audit)} decisions logged.")