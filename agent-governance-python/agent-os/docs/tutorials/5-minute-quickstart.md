# 5-Minute Quickstart

> **From zero to governed agent in 5 minutes.**

## TL;DR

```bash
pip install agent-os-kernel
```

```python
from agent_os import KernelSpace

kernel = KernelSpace(policy="strict")

@kernel.register
async def my_agent(task: str):
    return f"Processed: {task}"

# Run with kernel governance
import asyncio
result = asyncio.run(kernel.execute(my_agent, "Hello, Agent OS!"))
print(result)
```

That's it. Your agent now runs with kernel-level policy enforcement.

---

## Step 1: Install

```bash
pip install agent-os-kernel
```

**Optional extras:**

```bash
pip install agent-os-kernel[cmvk]           # Verification
pip install agent-os-kernel[observability]  # Prometheus/OpenTelemetry
pip install agent-os-kernel[full]           # Everything
```

## Step 2: Create Your First Agent

Create a file called `my_agent.py`:

```python
from agent_os import KernelSpace

# Initialize the kernel with strict policy
kernel = KernelSpace(policy="strict")

@kernel.register
async def analyze_data(task: str):
    """Your agent logic goes here."""
    # This could be any LLM call, data processing, etc.
    return f"Analysis complete: {task}"

# Execute with governance
if __name__ == "__main__":
    import asyncio
    
    result = asyncio.run(
        kernel.execute(analyze_data, "Summarize Q4 sales data")
    )
    print(result)
```

## Step 3: Run It

```bash
python my_agent.py
```

Output:
```
Analysis complete: Summarize Q4 sales data
```

---

## What Just Happened?

```
┌─────────────────────────────────────────────────────────┐
│              USER SPACE (Your Code)                     │
│   analyze_data() runs here                              │
├─────────────────────────────────────────────────────────┤
│              KERNEL SPACE (Agent OS)                    │
│   Every action checked against policies                 │
│   Violations → SIGKILL (non-catchable)                  │
└─────────────────────────────────────────────────────────┘
```

1. **`@kernel.register`** wraps your function with kernel governance
2. **`kernel.execute()`** runs your agent through the policy engine
3. **If policy violated** → automatic SIGKILL before execution

---

## Add an LLM (Optional)

```python
from agent_os import KernelSpace
from openai import OpenAI

kernel = KernelSpace(policy="strict")
client = OpenAI()

@kernel.register
async def smart_agent(task: str):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": task}]
    )
    return response.choices[0].message.content

if __name__ == "__main__":
    import asyncio
    result = asyncio.run(kernel.execute(smart_agent, "What is 2+2?"))
    print(result)
```

---

## Try Policy Enforcement

See what happens when your agent tries something blocked:

```python
@kernel.register
async def dangerous_agent(task: str):
    import os
    os.remove("/etc/passwd")  # ← This will be blocked!
    return "Done"
```

Output:
```
⚠️  POLICY VIOLATION DETECTED
⚠️  Signal: SIGKILL
⚠️  Action: file_write
⚠️  Status: TERMINATED
```

The kernel blocked the action **before** it executed.

---

## Next Steps

| Time | Tutorial | What You'll Learn |
|------|----------|-------------------|
| 10 min | [30-Minute Deep Dive](30-minute-deep-dive.md) | Policies, signals, VFS |
| 15 min | [Episodic Memory](../../notebooks/02-episodic-memory-demo.ipynb) | Agent memory that persists |
| 15 min | [Verification](../../notebooks/04-verification.ipynb) | Detect hallucinations |
| 20 min | [Time-Travel Debugging](../../notebooks/03-time-travel-debugging.ipynb) | Replay and debug decisions |

---

## Common Patterns

### Wrap Existing LangChain Agents

```python
from agent_os.integrations import LangChainKernel
from langchain.agents import AgentExecutor

kernel = LangChainKernel()
governed_agent = kernel.wrap(my_langchain_agent)
```

### Wrap OpenAI Assistants

```python
from agent_os.integrations import OpenAIKernel

kernel = OpenAIKernel()
governed = kernel.wrap_assistant(assistant, client)
```

### Wrap CrewAI

```python
from agent_os.integrations import CrewAIKernel

kernel = CrewAIKernel()
governed = kernel.wrap(my_crew)
```

---

## Get Help

- 📚 [Full Documentation](../index.md)
- 🐛 [GitHub Issues](https://github.com/microsoft/agent-governance-toolkit/issues)
- 💡 [Examples](../../examples/)
