# ATR - Agent Tool Registry

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

[![PyPI version](https://badge.fury.io/py/agent-tool-registry.svg)](https://badge.fury.io/py/agent-tool-registry)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/actions/workflow/status/microsoft/agent-governance-toolkit/test.yml?branch=main)](https://github.com/microsoft/agent-governance-toolkit/actions)

**A type-safe, decentralized tool registry for autonomous agents. Part of the Agent OS ecosystem.**

---

## Why This Exists

Most agent frameworks hardcode tools directly into their runtimes. This creates tight coupling: add a new capability, restart the entire system. Change a function signature, update dozens of agents. Scale by addition leads to fragility.

**We built `atr` because tool registration should not require restarting your infrastructure.**  

The Agent Tool Registry decouples tool providers from tool consumers. Agents discover capabilities at runtime through a standardized interface. We subtract the dependency between agent logic and tool implementation to add scale.

This is **Scale by Subtraction** applied to the agent capability layer.

---

## Installation

```bash
pip install agent-tool-registry
```

For sandboxed execution with Docker:

```bash
pip install agent-tool-registry[sandbox]
```

---

## Quick Start

Register a tool in 5 lines:

```python
import atr

@atr.register(name="calculator", tags=["math"])
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
```

Discover and execute:

```python
tool = atr.get_tool("calculator")
schema = tool.to_openai_function_schema()  # OpenAI-compatible
func = atr.get_callable("calculator")
result = func(a=5, b=3)  # Returns 8

# Or use sandboxed execution (recommended for untrusted code)
from atr import DockerExecutor
docker_exec = DockerExecutor()
result = atr.execute_tool("calculator", {"a": 5, "b": 3}, executor=docker_exec)
```

---

## Sandboxed Execution

**NEW:** ATR now supports sandboxed execution using Docker containers. This is essential for running untrusted or agent-generated code safely.

### Why Sandboxed Execution?

SDLC agents and LLMs may generate Python or Bash scripts that you cannot safely run directly on your host machine. Sandboxed execution provides:

- **Isolation**: Code runs in ephemeral containers, completely isolated from your host
- **Security**: No network access, memory limits, automatic cleanup
- **Safety**: Protects against malicious code, resource exhaustion, and unintended side effects

### Usage

```python
import atr
from atr import DockerExecutor

# Register a tool
@atr.register(name="processor", tags=["data"])
def process_data(numbers: list) -> int:
    """Process data safely in a sandbox."""
    return sum(numbers)

# Option 1: Direct execution (NOT sandboxed - trusted code only)
result = atr.execute_tool("processor", {"numbers": [1, 2, 3, 4]})

# Option 2: Sandboxed execution (RECOMMENDED for untrusted code)
docker_exec = DockerExecutor()
result = atr.execute_tool(
    "processor",
    {"numbers": [1, 2, 3, 4]},
    executor=docker_exec,
    timeout=30
)
```

### Execution Modes

| Feature | LocalExecutor | DockerExecutor |
|---------|---------------|----------------|
| Speed | Fast | Slower |
| Security | No isolation | Full isolation |
| Network | Full access | Disabled |
| Use Case | Trusted code | Untrusted code |

See `examples/sandbox_demo.py` for complete examples.

---

## Architecture

`atr` sits in **Layer 2 (Infrastructure)** of the Agent OS stack.

**Responsibility:** Tool registration, discovery, and schema generation.  
**Not responsible for:** Tool execution (handled by the Agent Control Plane).

### Design

- **Registry:** In-memory dictionary-based lookup (local or distributed).
- **Decorator:** `@atr.register()` extracts type signatures and validates strict typing.
- **Spec:** Pydantic schema enforcing inputs, outputs, side effects, and metadata.
- **Schema Export:** Converts to OpenAI, Anthropic, and other LLM function-calling formats.

The registry stores specifications, not callables. Execution happens in the control plane with proper error handling and observability.

---

## The Ecosystem Map

ATR is one component in a modular Agent OS. Each layer solves a specific problem:

### Primitives (Layer 1)
- **[caas](https://github.com/microsoft/agent-governance-toolkit)** - Context-as-a-Service: Manages agent memory and state.
- **[cmvk](https://github.com/microsoft/agent-governance-toolkit)** - Context Verification Kit: Cryptographic verification of context integrity.
- **[emk](https://github.com/microsoft/agent-governance-toolkit)** - Episodic Memory Kit: Long-term memory storage and retrieval.

### Infrastructure (Layer 2)
- **[iatp](https://github.com/microsoft/agent-governance-toolkit)** - Inter-Agent Trust Protocol: Secure message authentication.
- **[amb](https://github.com/microsoft/agent-governance-toolkit)** - Agent Message Bus: Decoupled event transport.
- **[atr](https://github.com/microsoft/agent-governance-toolkit)** - Agent Tool Registry: Tool discovery and schema generation *(you are here)*.

### Framework (Layer 3)
- **[agent-control-plane](https://github.com/microsoft/agent-governance-toolkit)** - The Core: Agent orchestration and lifecycle management.
- **[scak](https://github.com/microsoft/agent-governance-toolkit)** - Self-Correction Agent Kit: Automated error recovery and learning.

---

## Citation

If you use ATR in research, please cite:

```bibtex
@software{atr2024,
  title={ATR: Agent Tool Registry},
  author={Siddique, Imran},
  year={2024},
  url={https://github.com/microsoft/agent-governance-toolkit},
  note={Part of the Agent OS ecosystem}
}
```

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

**Repository:** https://github.com/microsoft/agent-governance-toolkit  
**Documentation:** https://github.com/microsoft/agent-governance-toolkit#readme  
**Issues:** https://github.com/microsoft/agent-governance-toolkit/issues
