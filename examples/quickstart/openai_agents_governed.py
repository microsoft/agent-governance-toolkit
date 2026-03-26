# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OpenAI Agents SDK with Guardrails — Quickstart
===============================================

pip install agent-governance-toolkit[full] openai-agents
python examples/quickstart/openai_agents_governed.py

Shows a real policy violation being caught by a tool guard, then a compliant
tool call succeeding, with a printed audit trail.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

from agent_os.integrations.openai_agents_sdk import (
    GovernancePolicy,
    OpenAIAgentsKernel,
    PolicyViolationError,
)

# ── 1. Define a strict governance policy ──────────────────────────────────
policy = GovernancePolicy(
    allowed_tools=["file_search", "code_interpreter"],  # explicit allowlist
    blocked_tools=["shell_exec", "network_request"],  # explicit blocklist
    blocked_patterns=["DROP TABLE", "rm -rf"],  # ban dangerous strings
    max_tool_calls=10,
)

kernel = OpenAIAgentsKernel(policy=policy, on_violation=lambda _e: None)
guard = kernel.create_tool_guard()
audit: list[dict] = []

print("=" * 60)
print("  OpenAI Agents SDK — Governance Quickstart")
print("=" * 60)


async def main() -> None:
    # ── 2. Policy violation: blocked tool (not in allowlist) ──────────────
    print("\n[1] Guarded tool call to a disallowed function ('web_search') …")

    @guard
    async def web_search(query: str) -> str:
        return f"results for {query}"

    try:
        await web_search("AI governance news")
    except PolicyViolationError as exc:
        print(f"    🚫 BLOCKED — {exc}")
        audit.append(
            {
                "ts": datetime.now().isoformat(),
                "tool": "web_search",
                "status": "BLOCKED",
            }
        )

    # ── 3. Policy violation: blocked content in argument ──────────────────
    print("\n[2] Allowed tool called with a dangerous argument …")

    @guard
    async def code_interpreter(code: str) -> str:
        return "executed"

    try:
        await code_interpreter("import os; os.system('rm -rf /')")
    except PolicyViolationError as exc:
        print(f"    🚫 BLOCKED — {exc}")
        audit.append(
            {
                "ts": datetime.now().isoformat(),
                "tool": "code_interpreter",
                "status": "BLOCKED",
            }
        )

    # ── 4. Compliant tool call succeeds ───────────────────────────────────
    print("\n[3] Allowed tool called with safe content …")

    @guard
    async def file_search(query: str) -> list[str]:
        return ["Q4_report.pdf", "annual_summary.pdf"]

    result = await file_search("Find Q4 financial reports")
    print(f"    ✅ ALLOWED — guardrails passed, found: {result}")
    audit.append(
        {"ts": datetime.now().isoformat(), "tool": "file_search", "status": "ALLOWED"}
    )

    # ── 5. Audit trail ────────────────────────────────────────────────────
    print("\n── Audit Trail ──────────────────────────────────────────")
    for i, entry in enumerate(audit, 1):
        print(
            f"  [{i}] {entry['ts']}  tool={entry['tool']!r}  status={entry['status']}"
        )
    print("\n🎉 OpenAI Agents SDK governance demo complete.")


asyncio.run(main())
