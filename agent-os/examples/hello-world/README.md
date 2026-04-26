# Hello World - Agent OS

The simplest possible Agent OS example.

## What This Demonstrates

- Basic kernel setup
- Agent registration
- Policy enforcement

## Quick Start

```bash
# Install
pip install agent-os-kernel

# Run
python agent.py
```

## Files

- `agent.py` - The agent code (15 lines)
- `README.md` - This file

## Expected Output

```
🚀 Hello World Agent
====================
✅ Agent executed successfully
📤 Result: Hello from a governed agent!
```

## Try Breaking It

Uncomment the "dangerous" line in `agent.py` to see policy enforcement:

```
⚠️  POLICY VIOLATION DETECTED
⚠️  Signal: SIGKILL
⚠️  Action: shell_exec
⚠️  Status: TERMINATED
```

## Next Steps

- [Chat Agent](../chat-agent/) - Interactive conversation
- [Tool-Using Agent](../tool-using-agent/) - Agent with tools
- [Carbon Auditor](../carbon-auditor/) - Full multi-agent system
