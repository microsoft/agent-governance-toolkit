# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Hello World - Agent OS

The simplest possible governed agent.
Run with: pip install agent-os-kernel && python agent.py
"""

import asyncio
from agent_os.stateless import StatelessKernel, ExecutionContext


async def main():
    print("Hello World Agent")
    print("=" * 30)

    # Create a stateless kernel (includes read_only, no_pii, strict policies)
    kernel = StatelessKernel()

    # Agent runs with read_only policy enforced
    ctx = ExecutionContext(agent_id="hello-agent-001", policies=["read_only"])

    # Safe action - allowed by read_only policy
    result = await kernel.execute("respond", {"message": "Hello!"}, ctx)
    print(f"[SAFE]    success={result.success}  data={result.data}")

    # Dangerous action - blocked by read_only policy
    result = await kernel.execute("file_write", {"path": "/etc/passwd"}, ctx)
    print(f"[BLOCKED] success={result.success}  signal={result.signal}")
    print(f"          reason: {result.error}")


if __name__ == "__main__":
    asyncio.run(main())