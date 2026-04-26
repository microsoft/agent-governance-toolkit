# Quickstart Example

The fastest way to get started with Agent OS.

## Run the Example

```bash
# From the repo root
python examples/quickstart/my_first_agent.py
```

## What it Does

```python
from agent_os import KernelSpace

# Create kernel with strict policy
kernel = KernelSpace(policy="strict")

@kernel.register
async def my_first_agent(task: str):
    """A simple agent that processes tasks safely."""
    result = f"Processed: {task}"
    return result

# Execute with kernel-level safety
result = asyncio.run(kernel.execute(my_first_agent, "Hello Agent OS!"))
```

## Next Steps

- **More examples**: See [examples/hello-world](../hello-world/) for a minimal working example
- **Add policies**: See [examples/chat-agent](../chat-agent/) for custom policies
- **Full demo**: See [examples/demo-app](../demo-app/) for a complete application
- **Tutorials**: See [notebooks/](../../notebooks/) for Jupyter tutorials
