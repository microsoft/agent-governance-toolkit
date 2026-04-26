# 5-Minute Getting Started

> **Get Agent OS running in under 5 minutes.**

## Prerequisites

- Python 3.10+
- pip

## Step 1: Install (30 seconds)

```bash
pip install agent-os-kernel
```

## Step 2: Create Your First Agent (2 minutes)

Create a file called `my_agent.py`:

```python
from agent_os import KernelSpace

# Create the kernel (enforces safety policies)
kernel = KernelSpace(policy="strict")

@kernel.register
async def my_agent(task: str) -> str:
    """A simple agent that processes tasks safely."""
    # This could be any LLM call
    return f"Processed: {task}"

# Run it
if __name__ == "__main__":
    import asyncio
    result = asyncio.run(kernel.execute(my_agent, "Hello, Agent OS!"))
    print(result)
```

## Step 3: Run It (30 seconds)

```bash
python my_agent.py
```

Output:
```
Processed: Hello, Agent OS!
```

## Step 4: Try a Policy Violation (1 minute)

Edit `my_agent.py` to try something dangerous:

```python
@kernel.register
async def my_agent(task: str) -> str:
    # Try to delete a file - this will be blocked!
    import os
    os.remove("/etc/passwd")  # SIGKILL!
    return "Done"
```

Run it again:

```bash
python my_agent.py
```

Output:
```
⚠️  POLICY VIOLATION DETECTED
⚠️  Signal: SIGKILL
⚠️  Action: file_write
⚠️  Policy: strict
⚠️  Status: TERMINATED
```

**The kernel blocked the dangerous action before it executed.**

## Step 5: Add an LLM (1 minute)

```python
from agent_os import KernelSpace
from openai import OpenAI  # or any LLM

kernel = KernelSpace(policy="strict")
client = OpenAI()

@kernel.register
async def smart_agent(task: str) -> str:
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": task}]
    )
    return response.choices[0].message.content

if __name__ == "__main__":
    import asyncio
    result = asyncio.run(kernel.execute(smart_agent, "Explain quantum computing"))
    print(result)
```

## What's Happening?

```
┌─────────────────────────────────────────────────────────┐
│              USER SPACE (Your Agent)                    │
│   my_agent() runs here. Can crash, hallucinate, etc.   │
├─────────────────────────────────────────────────────────┤
│              KERNEL SPACE (Agent OS)                    │
│   Policy Engine checks every action before execution    │
│   If policy violated → SIGKILL (non-catchable)         │
└─────────────────────────────────────────────────────────┘
```

Your agent code runs in "user space" - it can do anything. But the kernel intercepts all actions and checks them against policies. If a policy is violated, the kernel sends a signal (like `SIGKILL`) that the agent cannot catch or ignore.

## Next Steps

| Tutorial | Time | Description |
|----------|------|-------------|
| [Building Your First Governed Agent](./first-governed-agent.md) | 10 min | Complete walkthrough |
| [Using Message Bus Adapters](./message-bus-adapters.md) | 10 min | Connect agents with Redis/Kafka |
| [Creating Custom Tools](./custom-tools.md) | 15 min | Build safe tools |
| [Carbon Auditor Example](../examples/carbon-auditor/) | 15 min | Full multi-agent demo |

## Quick Reference

### Installation Options

```bash
# Core only
pip install agent-os-kernel

# With specific features
pip install agent-os-kernel[cmvk]           # Verification
pip install agent-os-kernel[observability]  # Prometheus/OpenTelemetry
pip install agent-os-kernel[full]           # Everything
```

### CLI Commands

```bash
agentos init my-project    # Create new project
agentos run                # Run with kernel
agentos check src/         # Check for violations
agentos audit              # Audit policies
```

### Policy Modes

```python
# Strict - blocks writes, PII, shell commands
kernel = KernelSpace(policy="strict")

# Permissive - logs only, no blocking
kernel = KernelSpace(policy="permissive")

# Custom - your own rules
kernel = KernelSpace(policy_file="my-policies.yaml")
```

---

<div align="center">

**Ready to build something real?**

[Building Your First Governed Agent →](./first-governed-agent.md)

</div>
