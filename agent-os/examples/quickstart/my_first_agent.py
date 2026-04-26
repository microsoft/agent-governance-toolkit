# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
My First Governed Agent

This agent is protected by Agent OS with kernel-level safety guarantees.
Run with: pip install agent-os-kernel && python my_first_agent.py
"""

import asyncio
from agent_os.stateless import StatelessKernel, ExecutionContext


async def main():
    # Create kernel with default safety policies
    kernel = StatelessKernel()
    ctx = ExecutionContext(agent_id="my-first-agent", policies=["read_only", "no_pii"])

    # Safe action - kernel allows it
    result = await kernel.execute("respond", {"message": "Hello Agent OS!"}, ctx)
    print(f"Safe action:      success={result.success}")

    # Dangerous action - kernel blocks file_write under read_only policy
    result = await kernel.execute("file_write", {"path": "/tmp/data"}, ctx)
    print(f"Blocked (write):  success={result.success}  signal={result.signal}")

    # PII violation - kernel blocks content containing 'password'
    result = await kernel.execute("respond", {"message": "password=abc123"}, ctx)
    print(f"Blocked (PII):    success={result.success}  signal={result.signal}")


if __name__ == "__main__":
    asyncio.run(main())