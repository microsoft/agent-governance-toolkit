# emk - Episodic Memory Kernel — Community Edition

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

[![PyPI](https://img.shields.io/pypi/v/emk)](https://pypi.org/project/emk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Episodic memory storage for AI agents.**

emk provides a simple append-only store for recording agent experiences. Episodes are immutable once written, giving you a reliable audit trail of what your agent did and learned.

## Installation

```bash
pip install emk
```

## Quick Start

```python
from emk import Episode, FileAdapter

store = FileAdapter("agent_memory.jsonl")
episode = Episode(goal="Query user data", action="SELECT * FROM users",
                  result="200 rows", reflection="Query was fast")
store.store(episode)
```

## Features

- Immutable, append-only episode storage
- JSONL file-based persistence
- Episode retrieval and querying
- Pluggable storage adapters

## License

MIT License - see [LICENSE](LICENSE) for details.
