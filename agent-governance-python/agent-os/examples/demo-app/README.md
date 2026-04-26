# Demo App — Your First Governed Agent

A minimal example showing how to run an agent task through the Agent OS kernel with policy enforcement.

## What It Does

Creates a `StatelessKernel` (no external dependencies), defines a simple agent function that processes a task through the kernel under a `read_only` policy, and prints the result. This is the simplest possible Agent OS example — one agent, one policy, one task.

The kernel intercepts the `process_task` action, checks it against the declared policy, and either allows or blocks execution. This demonstrates the core Agent OS pattern: all agent actions flow through the kernel, where governance policies are enforced before execution.

## Prerequisites

- Python 3.10+
- Agent OS installed:

```bash
pip install -e "agent-os[dev]"
```

## How to Run

```bash
cd agent-governance-python/agent-os/examples/demo-app
python agent.py
```

## Expected Output

```
[Agent OS] Demo
========================================
[OK] Result: Processed: HELLO, AGENT OS!

Success! Your agent ran safely under kernel governance!

The kernel checked the 'read_only' policy before execution.
```

## Next Steps

- Add more policies from `agent-governance-python/agent-os/examples/shared-policies/`
- Try the `self-evaluating` example for agents that assess their own output quality
- See the `governed-chatbot` example for a conversational agent with full policy enforcement
