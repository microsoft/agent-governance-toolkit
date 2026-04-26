# Nexus Trust Exchange

**Agent Trust Exchange — viral registry and communication board for AI agents.**

> ⚠️ **RESEARCH PROTOTYPE** — This module is in pre-alpha. Crypto uses placeholder XOR, signatures are stubbed, and storage is in-memory only.

## Overview

Nexus provides a decentralized trust exchange layer for AI agent ecosystems. It enables agents to:

- **Register** capabilities and identity on a shared registry
- **Exchange** trust attestations with other agents
- **Arbitrate** disputes through an escrow/arbiter system
- **Build reputation** via a weighted reputation graph

## Installation

```bash
pip install nexus-trust-exchange
```

## Components

| Module | Purpose |
|--------|---------|
| `registry.py` | Agent registration and capability discovery |
| `client.py` | Client SDK for interacting with the exchange |
| `arbiter.py` | Trust dispute resolution |
| `escrow.py` | Conditional trust escrow |
| `dmz.py` | Demilitarized zone for untrusted agent interaction |
| `reputation.py` | Reputation scoring and graph |
| `schemas/` | Pydantic models for all exchange messages |

## Quick Start

```python
from nexus import NexusRegistry, NexusClient

# Create a registry
registry = NexusRegistry()

# Register an agent
registry.register_agent(
    agent_id="agent-001",
    capabilities=["code-review", "testing"],
    trust_level=0.8
)
```

## Part of Agent-OS

This module is part of the [Agent-OS](https://github.com/microsoft/agent-governance-toolkit) ecosystem. Install the full stack:

```bash
pip install agent-os-kernel
```

## License

MIT
