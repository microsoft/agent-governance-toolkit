# Agent Primitives

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

**Layer 1 Primitive** - Shared data models for the Agent OS stack.

## Purpose

This package provides foundational data models used across multiple Agent OS components. By extracting these primitives into a dedicated Layer 1 package, we ensure proper dependency layering:

```
Layer 1 (Primitives): cmvk, emk, caas, agent-primitives
Layer 2 (Infrastructure): iatp, amb, atr
Layer 3 (Kernel): agent-control-plane  
Layer 4/5 (Intelligence): scak, mute-agent
```

## Installation

```bash
pip install agent-primitives
```

## Models

### Failure Models

Core failure tracking primitives used by iatp, scak, and other components:

```python
from agent_primitives import (
    FailureType,
    FailureSeverity,
    AgentFailure,
    FailureTrace,
)

# Create a failure record
failure = AgentFailure(
    agent_id="agent-123",
    failure_type=FailureType.TIMEOUT,
    error_message="Request timed out after 30s",
    severity=FailureSeverity.MEDIUM,
)
```

### Available Types

- **FailureType**: Enumeration of failure categories (TIMEOUT, INVALID_ACTION, RESOURCE_EXHAUSTED, etc.)
- **FailureSeverity**: Severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- **AgentFailure**: Core failure record with agent ID, type, message, and context
- **FailureTrace**: Detailed trace including reasoning chain and failed action

## Design Principles

1. **Zero Agent OS Dependencies**: This package only depends on `pydantic`
2. **Backward Compatible**: Other packages can re-export these models
3. **Type Safe**: Full typing support with `py.typed` marker

## License

MIT
