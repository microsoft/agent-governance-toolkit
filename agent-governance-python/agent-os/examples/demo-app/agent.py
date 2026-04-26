# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent OS Demo - Your First Governed Agent"""
import asyncio
from agent_os import StatelessKernel, ExecutionContext

# Create stateless kernel (no external dependencies)
kernel = StatelessKernel()

async def my_agent(task: str) -> str:
    """Process a task safely through the kernel."""
    
    # Create execution context
    ctx = ExecutionContext(
        agent_id="demo-agent",
        policies=["read_only"]  # Apply safety policy
    )
    
    # Execute through the kernel
    result = await kernel.execute(
        action="process_task",
        params={"task": task, "output": f"Processed: {task.upper()}"},
        context=ctx
    )
    
    return result.data if result.success else f"Error: {result.error}"

async def main():
    print("[Agent OS] Demo")
    print("=" * 40)
    
    result = await my_agent("Hello, Agent OS!")
    print(f"[OK] Result: {result}")
    print("")
    print("Success! Your agent ran safely under kernel governance!")
    print("")
    print("The kernel checked the 'read_only' policy before execution.")

if __name__ == "__main__":
    asyncio.run(main())
