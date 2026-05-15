# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Governance — Quick Start

Boot the full governance stack and execute a governed action.

Usage:
    pip install agent-governance-toolkit
    python quickstart.py
"""

import asyncio
from agent_os import StatelessKernel, ExecutionContext
from agentmesh import AgentIdentity

# 1. Boot the governance kernel
kernel = StatelessKernel()
print("✅ Governance kernel booted")

# 2. Create an execution context for our agent
ctx = ExecutionContext(
    agent_id="quickstart-agent",
    policies=["read_only"],
)

# 3. Register a zero-trust agent identity
identity = AgentIdentity.create(
    name="quickstart-agent",
    sponsor="demo@example.com",
    capabilities=["read:data", "write:reports"],
)
print(f"✅ Agent identity created: {identity.did}")


async def main():
    # 4. Execute a governed action
    result = await kernel.execute(
        action="database_query",
        params={"query": "SELECT * FROM reports"},
        context=ctx,
    )
    print(f"✅ Query result: success={result.success}")

    # 5. Try a blocked action (write blocked by read_only policy)
    result = await kernel.execute(
        action="file_write",
        params={"path": "/data/secret.txt", "content": "test"},
        context=ctx,
    )
    print(f"✅ Write blocked: success={result.success}, signal={result.signal}")

    print("\n🎉 Governance stack is running! Your agent is now governed.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"❌ Error: {e}")
        raise
