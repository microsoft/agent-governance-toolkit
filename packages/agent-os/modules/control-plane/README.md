# Agent Control Plane — Public Preview

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

[![PyPI version](https://img.shields.io/pypi/v/agent-control-plane.svg)](https://pypi.org/project/agent-control-plane/)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Policy-based governance for autonomous AI agents.**

The Agent Control Plane provides a governance layer that sits between your AI agent and the actions it performs. Define policies in YAML or Python and the control plane enforces them deterministically before any action executes.

## Installation

```bash
pip install agent-control-plane
```

## Quick Start

```python
from agent_control_plane import AgentControlPlane

plane = AgentControlPlane()
plane.load_policy("policies.yaml")

result = await plane.execute(
    action="database_query",
    params={"query": "SELECT * FROM users"},
    agent_id="analyst-001"
)
# Safe queries execute; destructive queries are blocked by policy
```

## Features

- Deterministic policy enforcement (YAML or Python)
- Permission management and resource quotas
- Sandboxed execution with rollback support
- Audit logging via SQLite-based Flight Recorder
- Multi-framework support (OpenAI, LangChain, MCP, A2A)

## Documentation

See [docs/](./docs/) for guides and [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup.

## License

MIT License - see [LICENSE](LICENSE) for details.
