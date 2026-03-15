# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AutoGen Agents with Trust Verification — Quickstart
====================================================

pip install agent-governance-toolkit[full] pyautogen
python examples/quickstart/autogen_governed.py

Shows a real policy violation being caught during message routing,
then a safe message passing verification, with a printed audit trail.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

from agent_os.integrations import AutoGenKernel
from agent_os.integrations.base import GovernancePolicy, PolicyViolationError

# ── 1. Define a governance policy ─────────────────────────────────────────
policy = GovernancePolicy(
    name="autogen-demo-policy",
    blocked_patterns=["api_key=", "password="],  # block credential leaks
    max_tool_calls=5,
)

kernel = AutoGenKernel(policy=policy)
ctx = kernel.create_context("autogen-assistant")
audit: list[dict] = []

print("=" * 60)
print("  AutoGen Agents — Governance Quickstart")
print("=" * 60)

# ── 2. Policy violation: credential leak in message ───────────────────────
print("\n[1] Agent message containing a credential leak …")
msg = {"role": "assistant", "content": "Here is your token: api_key=sk-abc123"}
allowed, reason = kernel.pre_execute(ctx, msg)
if not allowed:
    print(f"    🚫 BLOCKED — {reason}")
    audit.append({"ts": datetime.now().isoformat(), "msg": "api_key leak", "status": "BLOCKED"})

# ── 3. Policy violation: call budget exhausted ────────────────────────────
print("\n[2] Agent conversation budget exhausted …")
ctx.call_count = policy.max_tool_calls
allowed, reason = kernel.pre_execute(ctx, {"role": "assistant", "content": "Let me help."})
if not allowed:
    print(f"    🚫 BLOCKED — {reason}")
    audit.append({"ts": datetime.now().isoformat(), "msg": "budget exceeded", "status": "BLOCKED"})
ctx.call_count = 0

# ── 4. Compliant message passes ───────────────────────────────────────────
print("\n[3] Safe agent message passes trust verification …")
msg = {"role": "assistant", "content": "Here is a summary of the quarterly report."}
allowed, reason = kernel.pre_execute(ctx, msg)
if allowed:
    print("    ✅ ALLOWED — trust verification passed")
    audit.append({"ts": datetime.now().isoformat(), "msg": "quarterly summary", "status": "ALLOWED"})

# ── 5. Health check ───────────────────────────────────────────────────────
health = kernel.health_check()
print(f"\n[4] Kernel health: status={health['status']!r}, "
      f"backend={health['backend']!r}")

# ── 6. Audit trail ────────────────────────────────────────────────────────
print("\n── Audit Trail ──────────────────────────────────────────")
for i, entry in enumerate(audit, 1):
    print(f"  [{i}] {entry['ts']}  msg={entry['msg']!r}  status={entry['status']}")

print("\n🎉 AutoGen governance demo complete.")
