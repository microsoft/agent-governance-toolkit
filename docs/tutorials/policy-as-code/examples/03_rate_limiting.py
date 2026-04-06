# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Chapter 3: Rate Limiting — Preventing Runaway Agents

Shows two approaches:
  1. Policy-level max_tool_calls — a hard cap on total actions.
  2. TokenBucket — a per-second rate limiter for bursty workloads.

Run from the repo root:
    pip install agent-os-kernel[full]
    python docs/tutorials/policy-as-code/examples/03_rate_limiting.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from the repo root without installing the packages.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

from agent_os.policies import PolicyEvaluator
from agent_os.policies.rate_limiting import RateLimitConfig, TokenBucket
from agent_os.policies.schema import PolicyDocument

EXAMPLES_DIR = Path(__file__).parent

# ── Part 1: max_tool_calls ───────────────────────────────────────────────

print("=" * 60)
print("  Chapter 3: Rate Limiting")
print("=" * 60)

print("\n--- Part 1: max_tool_calls (policy-level cap) ---\n")

policy = PolicyDocument.from_yaml(EXAMPLES_DIR / "03_rate_limit_policy.yaml")
# In Chapter 1 we created the evaluator first, then added the policy; here we do both in one step.
evaluator = PolicyEvaluator(policies=[policy])
max_calls = policy.defaults.max_tool_calls

call_count = 0
for i in range(1, 6):
    # The policy tells us the limit; our code enforces it.
    if call_count >= max_calls:
        print(f"  Call {i}: \U0001f6ab DENIED — limit of {max_calls} calls reached")
        continue

    decision = evaluator.evaluate({"tool_name": "search_documents"})
    if decision.allowed:
        call_count += 1
        print(f"  Call {i}: \u2705 ALLOWED ({call_count}/{max_calls} used)")
    else:
        print(f"  Call {i}: \U0001f6ab DENIED — {decision.reason}")

print(f"\n  The policy allows at most {max_calls} tool calls.")
print("  Your application code checks the counter against max_tool_calls.")

# ── Part 2: TokenBucket ─────────────────────────────────────────────────

print("\n--- Part 2: TokenBucket (per-second rate limiter) ---\n")

config = RateLimitConfig(capacity=3, refill_rate=1.0)
bucket = TokenBucket.from_config(config)

print(f"  Bucket: capacity={config.capacity}, refill_rate={config.refill_rate}/sec")
print(f"  Starting tokens: {bucket.available}\n")

for i in range(1, 6):
    if bucket.consume():
        print(f"  Request {i}: \u2705 ALLOWED ({bucket.available:.0f} tokens left)")
    else:
        wait = bucket.time_until_available()
        print(f"  Request {i}: \U0001f6ab DENIED — retry in {wait:.1f}s")

print("\n" + "=" * 60)
print("  Two rate-limiting approaches, same goal: prevent runaway agents.")
print("=" * 60)
