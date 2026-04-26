# Mute Agent — Public Preview

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Muted agent execution with graph-based constraints.**

Mute Agent separates reasoning from execution. A reasoning component proposes actions, and an execution component carries them out — but only if the action passes validation against a constraint graph. Out-of-scope requests return NULL instead of hallucinated responses.

## Installation

```bash
pip install -e .
```

For development with testing tools:
```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from mute_agent import ReasoningAgent, ExecutionAgent, HandshakeProtocol

protocol = HandshakeProtocol()
reasoning = ReasoningAgent(knowledge_graph, router, protocol)
execution = ExecutionAgent(protocol)

session = reasoning.propose_action(
    action_id="read_file",
    parameters={"path": "/data/file.txt"},
    context={"user": "admin"},
    justification="User requested file read"
)
if session.validation_result.is_valid:
    protocol.accept_proposal(session.session_id)
    result = execution.execute(session.session_id)
```

## Features

- Separation of reasoning and execution concerns
- Graph-based constraint validation
- Deterministic action authorization
- Complete audit trail via session tracking

## License

MIT License
