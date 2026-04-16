# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CrewAI + Governance Toolkit — Getting Started
==============================================

Minimal example showing how to add governance to an existing CrewAI
workflow. Copy this pattern into your own project.

    pip install agent-governance-toolkit[full]
    python examples/crewai-governed/getting_started.py

What this demonstrates:
  1. Load YAML governance policies
  2. Wire up middleware (policy + capability guard + audit)
  3. Run agent messages through governance BEFORE calling the LLM
  4. Verify the tamper-proof audit trail

For the full 9-scenario showcase, run crewai_governance_demo.py instead.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# --- Setup: importable from pip install agent-governance-toolkit[full] ---
# (The sys.path lines below are only needed when running from the repo
# checkout. With a pip install, just `from agent_os...` works directly.)
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-mesh" / "src"))

from agent_os.policies.evaluator import PolicyEvaluator
from agent_os.integrations.maf_adapter import (
    GovernancePolicyMiddleware,
    CapabilityGuardMiddleware,
    MiddlewareTermination,
    AgentResponse,
    Message,
)
from agentmesh.governance.audit import AuditLog


# ── Step 1: Load your YAML governance policies ───────────────────────────

audit_log = AuditLog()
evaluator = PolicyEvaluator()
evaluator.load_policies(Path(__file__).parent / "policies")

policy_middleware = GovernancePolicyMiddleware(
    evaluator=evaluator, audit_log=audit_log
)

# ── Step 2: Set up capability guard per agent role ───────────────────────
# This is the equivalent of declaring tools on a CrewAI Agent.
# allowed_tools = what the agent CAN use; denied_tools = hard blocks.

researcher_guard = CapabilityGuardMiddleware(
    allowed_tools=["web_search", "read_file"],
    denied_tools=["shell_exec", "publish_content"],
    audit_log=audit_log,
)


# ── Step 3: Minimal context shims ────────────────────────────────────────
# These adapt your agent's messages to the middleware interface.
# In production, the toolkit's framework adapters handle this for you.

class AgentContext:
    """Wraps an agent message for the governance middleware."""

    def __init__(self, agent_name: str, user_message: str) -> None:
        self.agent = type("A", (), {"name": agent_name})()
        self.messages = [Message("user", [user_message])]
        self.metadata: dict = {}
        self.stream = False
        self.result: AgentResponse | None = None


class ToolContext:
    """Wraps a tool invocation for the capability guard."""

    def __init__(self, tool_name: str) -> None:
        self.function = type("F", (), {"name": tool_name})()
        self.result: str | None = None


# ── Step 4: Run governance checks ────────────────────────────────────────

async def main() -> None:
    print("=" * 55)
    print("  CrewAI + Governance Toolkit — Getting Started")
    print("=" * 55)

    # --- Check 1: Safe message passes policy ---
    print("\n[1] Researcher sends a safe query...")
    ctx = AgentContext("researcher", "Search for recent AI governance papers")

    async def llm_call() -> None:
        # Replace this with your actual LLM / CrewAI task execution
        ctx.result = AgentResponse(
            messages=[Message("assistant", ["Here are the top papers..."])]
        )

    try:
        await policy_middleware.process(ctx, llm_call)  # type: ignore[arg-type]
        print("    ALLOWED -- policy check passed")
    except MiddlewareTermination:
        print("    BLOCKED -- policy violation")

    # --- Check 2: PII is blocked ---
    print("\n[2] Writer tries to include an email address...")
    ctx2 = AgentContext("writer", "Include john.doe@example.com in the report")

    async def blocked_call() -> None:
        ctx2.result = AgentResponse(messages=[Message("assistant", ["Done"])])

    try:
        await policy_middleware.process(ctx2, blocked_call)  # type: ignore[arg-type]
        print("    ALLOWED")
    except MiddlewareTermination:
        print("    BLOCKED -- PII detected, LLM was never called")

    # --- Check 3: Capability guard ---
    print("\n[3] Researcher tries to use an unauthorized tool...")
    tool_ctx = ToolContext("shell_exec")

    async def tool_exec() -> None:
        tool_ctx.result = "executed"

    try:
        await researcher_guard.process(tool_ctx, tool_exec)  # type: ignore[arg-type]
        print("    ALLOWED")
    except MiddlewareTermination:
        print("    BLOCKED -- tool not in researcher's allowed list")

    # --- Check 4: Verify audit trail ---
    print("\n[4] Verifying audit trail...")
    valid, err = audit_log.verify_integrity()
    total = len(audit_log._chain._entries)
    print(f"    {total} audit entries logged")
    print(f"    Merkle chain integrity: {'VERIFIED' if valid else f'FAILED: {err}'}")

    print("\nDone! See crewai_governance_demo.py for the full 9-scenario showcase.")


if __name__ == "__main__":
    asyncio.run(main())
