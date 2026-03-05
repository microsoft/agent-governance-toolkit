# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Governance — Full Stack Example

Shows all four governance layers working together:
  1. Agent OS Kernel — policy enforcement
  2. AgentMesh — zero-trust identity and communication
  3. Agent Hypervisor — execution rings and resource limits
  4. Agent SRE — health monitoring and SLO enforcement

Usage:
    pip install ai-agent-governance[full]
    python examples/governed_agent.py
"""

import asyncio
from agent_os import StatelessKernel, ExecutionContext
from agentmesh import AgentIdentity

# Optional: import hypervisor and SRE if installed
try:
    from hypervisor import Hypervisor, SessionConfig, ConsistencyMode
    HAS_HYPERVISOR = True
except ImportError:
    HAS_HYPERVISOR = False

try:
    from agent_sre import SLO, ErrorBudget
    from agent_sre.slo.indicators import TaskSuccessRate
    HAS_SRE = True
except ImportError:
    HAS_SRE = False


async def main():
    print("=" * 60)
    print("  Agent Governance — Full Stack Demo")
    print("=" * 60)

    # --- Layer 1: Kernel ---
    kernel = StatelessKernel()
    ctx = ExecutionContext(
        agent_id="governed-agent-001",
        policies=["read_only"],
    )
    print("\n[Agent OS] Kernel booted, context created")

    # --- Layer 2: Trust Mesh ---
    identity = AgentIdentity.create(
        name="governed-agent-001",
        sponsor="admin@company.com",
        capabilities=["read:data", "write:reports", "execute:queries"],
    )
    print(f"[AgentMesh] Agent registered — DID: {identity.did}")

    # --- Layer 3: Hypervisor ---
    if HAS_HYPERVISOR:
        hv = Hypervisor()
        session = await hv.create_session(
            config=SessionConfig(consistency_mode=ConsistencyMode.EVENTUAL),
            creator_did=identity.did,
        )
        print(f"[Hypervisor] Session created: {session.sso.session_id}")
    else:
        print("[Hypervisor] Not installed — pip install ai-agent-governance[full]")

    # --- Layer 4: SRE ---
    if HAS_SRE:
        indicator = TaskSuccessRate(target=0.95)
        slo = SLO(
            name="agent-success-rate",
            indicators=[indicator],
            error_budget=ErrorBudget(total=1000, consumed=0),
        )
        indicator.record_task(success=True)
        evaluation = slo.evaluate()
        print(f"[Agent SRE] SLO evaluation: status={evaluation.value}")
    else:
        print("[Agent SRE] Not installed — pip install ai-agent-governance[full]")

    # --- Execute a governed action ---
    print("\n--- Executing governed action ---")

    result = await kernel.execute(
        action="database_query",
        params={"query": "SELECT * FROM users WHERE role = 'admin'"},
        context=ctx,
    )
    print(f"Policy check: {'ALLOWED' if result.success else 'DENIED'}")

    if result.success:
        print(f"Data: {result.data}")
    else:
        print(f"Blocked — signal: {result.signal}")

    # Try a write (should be blocked by read_only)
    result = await kernel.execute(
        action="file_write",
        params={"path": "/etc/config", "content": "malicious"},
        context=ctx,
    )
    print(f"Write attempt: {'ALLOWED' if result.success else 'BLOCKED'} (signal: {result.signal})")

    print("\n" + "=" * 60)
    print("  All governance layers operational")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
