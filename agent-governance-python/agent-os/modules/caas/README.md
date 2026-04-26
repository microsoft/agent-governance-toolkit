# Context-as-a-Service (CaaS) — Public Preview

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

[![PyPI](https://img.shields.io/pypi/v/caas-core.svg)](https://pypi.org/project/caas-core/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Context management for RAG systems.**

CaaS provides stateless utilities for routing, prioritizing, and filtering context in retrieval-augmented generation (RAG) pipelines. It manages what information gets sent to the LLM, reducing token waste and improving response quality.

## Installation

```bash
pip install caas-core
```

## Quick Start

```python
from caas import DocumentStore, VirtualFileSystem

store = DocumentStore()
store.add_document({"content": "API auth uses JWT", "timestamp": "2025-01-15"})

vfs = VirtualFileSystem()
vfs.create_file("/project/main.py", "print('hello')", agent_id="agent-1")
```

## Features

- Document storage with time-based prioritization
- Virtual File System for multi-agent collaboration
- Context routing to appropriate model tiers
- Stateless design with no framework dependencies

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT License — see [LICENSE](LICENSE) for details.
