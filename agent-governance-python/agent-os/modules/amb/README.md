# AMB - Agent Message Bus

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

[![PyPI version](https://badge.fury.io/py/amb-core.svg)](https://badge.fury.io/py/amb-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Broker-agnostic message transport for decoupled agent communication.**

## Why AMB?

In multi-agent systems, tight coupling between agents creates dependency graphs that scale exponentially with system size. When Agent A must know about Agent B, C, and D to communicate, the system becomes rigid and unmaintainable.

We built `amb` because **direct agent coupling creates spaghetti code**. The solution: **Scale by Subtraction**. 

By removing the requirement for agents to know about each other, we eliminate O(n²) dependencies and replace them with O(1) broadcast semantics. Agents emit signals (`"I am thinking"`, `"I need verification"`) without knowing who listens. The bus stays dumb and fast—it just transports the envelope.



## Installation

```bash
pip install amb-core
```

For production deployments with Redis, RabbitMQ, or Kafka:
```bash
pip install amb-core[redis]      # Redis support
pip install amb-core[rabbitmq]   # RabbitMQ support
pip install amb-core[kafka]      # Kafka support
pip install amb-core[all]        # All adapters
```

## Quick Start

```python
import asyncio
from amb_core import MessageBus, Message

async def main():
    async with MessageBus() as bus:
        async def handler(msg: Message): print(msg.payload)
        await bus.subscribe("agent.events", handler)
        await bus.publish("agent.events", {"status": "ready"})
        await asyncio.sleep(0.1)

asyncio.run(main())
```

## Features

### 🚦 Priority Lanes
Tag messages as `CRITICAL` (Security/Governance) vs `BACKGROUND` (Memory consolidation). Critical messages jump the queue.

```python
# Critical security alert - jumps ahead
await bus.publish(
    "agent.alerts", 
    {"alert": "Security anomaly detected"},
    priority=MessagePriority.CRITICAL
)

# Background task - processed when system is idle
await bus.publish(
    "agent.tasks",
    {"task": "Memory consolidation"},
    priority=MessagePriority.BACKGROUND
)
```

**Priority Levels:** `CRITICAL` > `URGENT` > `HIGH` > `NORMAL` > `LOW` > `BACKGROUND`

### 🌊 Backpressure Protocols
Implements Reactive Streams-style flow control. If a consumer is slow, the producer automatically slows down.

```python
# Configure backpressure parameters
broker = InMemoryBroker(
    max_queue_size=1000,           # Max messages per topic
    backpressure_threshold=0.8,    # Activate at 80% capacity
    backpressure_delay=0.01        # 10ms delay when active
)

bus = MessageBus(adapter=broker)

# If 100 agents spam the bus, backpressure prevents crashes
for agent_id in range(100):
    await bus.publish("agent.events", {"agent": agent_id})
# Producer automatically throttles when consumer is overwhelmed
```

**Scale by Subtraction:** No external load balancer needed. The bus handles flow control automatically.

### 🔍 OpenTelemetry Tracing (The "X-Ray")
Built-in distributed tracing for debugging multi-agent workflows. When an SDLC agent fails, trace the flow: `Thought` → `Message` → `Tool Call` → `Error` across all agents.

```python
from amb_core import MessageBus, get_tracer, initialize_tracing

# Initialize tracing (usually done once at startup)
initialize_tracing("my-agent-system")

# Get a tracer for creating spans
tracer = get_tracer("agent-workflow")

async with MessageBus() as bus:
    # Messages published within a span automatically get the trace_id
    with tracer.start_as_current_span("agent-thinking"):
        await bus.publish("agent.thoughts", {"thought": "Processing data"})
    
    # Or explicitly set trace_id for cross-system tracing
    await bus.publish(
        "agent.action",
        {"action": "execute"},
        trace_id="custom-trace-id-from-upstream"
    )
```

**Key Features:**
- **Automatic Injection:** `trace_id` automatically injected from active OpenTelemetry span
- **Cross-Agent Tracing:** Same `trace_id` flows through request-response patterns
- **Explicit Control:** Can manually set `trace_id` for integration with external systems
- **Zero Config:** Works out of the box with InMemoryBroker, scales to production backends

See `examples/tracing_demo.py` for a complete multi-agent tracing example.

## Architecture

`amb` sits in **Layer 2 (Infrastructure)** of the Agent OS stack. It transports message envelopes without inspecting content or enforcing policy.

```
┌──────────────────────────────────────┐
│  Layer 3: Framework                  │  agent-control-plane, scak
│  (Orchestration & Self-Correction)   │
└────────────────┬─────────────────────┘
                 │
┌────────────────▼─────────────────────┐
│  Layer 2: Infrastructure    ← AMB    │  iatp (Trust), atr (Registry)
│  (Transport & Discovery)             │
└────────────────┬─────────────────────┘
                 │
┌────────────────▼─────────────────────┐
│  Layer 1: Primitives                 │  caas (Context), cmvk (Verification),
│  (State & Identity)                  │  emk (Memory)
└──────────────────────────────────────┘
```

**Design Principles:**
- **No Business Logic:** The bus never decides routing based on message content.
- **Broker Agnostic:** Swap Redis for RabbitMQ without changing application code.
- **Local-First:** Works on a laptop with InMemoryBroker—no Docker required.
- **Separation of Concerns:** The bus transports. The receiver validates trust (via `iatp`), not the bus.

## The Agent OS Ecosystem

`amb` is one component of a modular Agent Operating System. Each layer solves a specific problem.

### Layer 1: Primitives (State & Identity)
- **[caas](https://github.com/microsoft/agent-governance-toolkit)** - Context as a Service: Manages agent context and state
- **[cmvk](https://github.com/microsoft/agent-governance-toolkit)** - Context Verification Kit: Cryptographic verification of context
- **[emk](https://github.com/microsoft/agent-governance-toolkit)** - Episodic Memory Kit: Persistent memory for agents

### Layer 2: Infrastructure (Transport & Discovery)
- **[iatp](https://github.com/microsoft/agent-governance-toolkit)** - Inter-Agent Trust Protocol: Trust verification for agent messages
- **[amb](https://github.com/microsoft/agent-governance-toolkit)** - Agent Message Bus: Broker-agnostic transport *(you are here)*
- **[atr](https://github.com/microsoft/agent-governance-toolkit)** - Agent Tool Registry: Decentralized tool discovery

### Layer 3: Framework (Orchestration & Self-Correction)
- **[agent-control-plane](https://github.com/microsoft/agent-governance-toolkit)** - The orchestration core
- **[scak](https://github.com/microsoft/agent-governance-toolkit)** - Self-Correction & Alignment Kit: Runtime safety and alignment

## Citation

If you use AMB in research, please cite:

```bibtex
@software{amb2026,
  author = {Siddique, Imran},
  title = {AMB: Agent Message Bus for Decoupled Multi-Agent Systems},
  year = {2026},
  url = {https://github.com/microsoft/agent-governance-toolkit},
  version = {0.1.0}
}
```

---

**License:** MIT | **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md) | **Changelog:** [CHANGELOG.md](CHANGELOG.md)
