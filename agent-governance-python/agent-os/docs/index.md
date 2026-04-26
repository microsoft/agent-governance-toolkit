# Agent OS Documentation

Welcome to the Agent OS documentation. Agent OS is a kernel architecture for governing autonomous AI agents with deterministic policy enforcement.

## Quick Navigation

### 🚀 Getting Started

| Guide | Time | Description |
|-------|------|-------------|
| [5-Minute Quickstart](tutorials/5-minute-quickstart.md) | 5 min | Minimal setup, maximum speed |
| [30-Minute Deep Dive](tutorials/30-minute-deep-dive.md) | 30 min | Comprehensive walkthrough |
| [First Governed Agent](tutorials/first-governed-agent.md) | 15 min | Build a complete agent |
| [Cheatsheet](cheatsheet.md) | - | Quick reference card |

### 📓 Interactive Notebooks

Learn by doing with our Jupyter notebooks:

| Notebook | Time | Description |
|----------|------|-------------|
| [Hello Agent OS](../notebooks/01-hello-agent-os.ipynb) | 5 min | Your first governed agent |
| [Episodic Memory](../notebooks/02-episodic-memory-demo.ipynb) | 15 min | Persistent agent memory |
| [Time-Travel Debugging](../notebooks/03-time-travel-debugging.ipynb) | 20 min | Replay agent decisions |
| [Verification](../notebooks/04-verification.ipynb) | 15 min | Detect hallucinations |
| [Multi-Agent Coordination](../notebooks/05-multi-agent-coordination.ipynb) | 20 min | Agent trust protocols |
| [Policy Engine](../notebooks/06-policy-engine.ipynb) | 15 min | Deep dive into policies |

### 📚 Tutorials

- [Using Message Bus Adapters](tutorials/message-bus-adapters.md) - Connect agents with Redis, Kafka, NATS
- [Creating Custom Tools](tutorials/custom-tools.md) - Build safe tools for agents

### 🏗️ Architecture

- [Kernel Internals](kernel-internals.md) - How the kernel works

### 🔧 Reference

- [Framework Integrations](integrations.md) - LangChain, OpenAI, CrewAI
- [AgentConfig File Reference](agent-config-reference.md) - Supported YAML keys and validation rules
- [Dependencies](dependencies.md) - Package dependencies
- [Security Specification](security-spec.md) - Security model
- [FAQ](faq.md) - Common questions and answers

### 📋 RFCs

- [RFC-003: Agent Signals](rfcs/RFC-003-Agent-Signals.md) - POSIX-style signals
- [RFC-004: Agent Primitives](rfcs/RFC-004-Agent-Primitives.md) - Core primitives

### 🎯 Case Studies

- [Carbon Auditor](case-studies/) - Fraud detection example
- [DeFi Sentinel](case-studies/) - Attack detection
- [Grid Balancing](case-studies/) - Multi-agent coordination

---

## Installation

```bash
# Core package
pip install agent-os-kernel

# With all features
pip install agent-os-kernel[full]
```

## One-Command Quickstart

**macOS/Linux:**
```bash
curl -sSL https://get.agent-os.dev | bash
```

**Windows (PowerShell):**
```powershell
iwr -useb https://get.agent-os.dev/win | iex
```

## Hello World

```python
from agent_os import KernelSpace

kernel = KernelSpace(policy="strict")

@kernel.register
async def my_agent(task: str):
    return f"Processed: {task}"

# Run with kernel governance
result = await kernel.execute(my_agent, "analyze data")
```

## Key Concepts

### Kernel vs User Space

```
┌─────────────────────────────────────────────────────────┐
│              USER SPACE (Agent Code)                    │
│   Your agent code runs here. Can crash, hallucinate.   │
├─────────────────────────────────────────────────────────┤
│              KERNEL SPACE (Agent OS)                    │
│   Policy Engine checks every action before execution    │
│   If policy violated → SIGKILL (non-catchable)         │
└─────────────────────────────────────────────────────────┘
```

### Signals

Agent OS uses POSIX-style signals for control:

| Signal | Description |
|--------|-------------|
| `SIGKILL` | Terminate immediately (cannot be caught) |
| `SIGSTOP` | Pause for human review |
| `SIGCONT` | Resume execution |

### Policies

Policies define what agents can and cannot do:

```yaml
policies:
  - name: read_only
    deny:
      - action: file_write
      - action: database_write
```

## IDE Extensions

| IDE | Status | Link |
|-----|--------|------|
| VS Code | ✅ Available | [Marketplace](../../agent-governance-typescript/agent-os-vscode/) |
| JetBrains | ✅ Available | [Plugin](extensions/jetbrains/) |
| Cursor | ✅ Available | [Extension](extensions/cursor/) |
| GitHub Copilot | ✅ Available | [Extension](extensions/copilot/) |

## Policy Templates

Pre-built templates for common use cases:

| Template | Use Case |
|----------|----------|
| [secure-coding](../templates/policies/secure-coding.yaml) | General development |
| [data-protection](../templates/policies/data-protection.yaml) | PII handling |
| [enterprise](../templates/policies/enterprise.yaml) | Production deployments |

```bash
# Use a template
agentos init my-project --template secure-coding
```

## Support

- [GitHub Issues](https://github.com/microsoft/agent-governance-toolkit/issues)
- [Discussions](https://github.com/microsoft/agent-governance-toolkit/discussions)
- [Contributing Guide](../CONTRIBUTING.md)

---

<div align="center">

**Kernel-level safety for AI agents.**

[GitHub](https://github.com/microsoft/agent-governance-toolkit) · [Examples](../examples/)

</div>
