# Self-Correcting Agent Kernel (SCAK) — Public Preview

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

[![PyPI version](https://img.shields.io/badge/pypi-scak-blue.svg)](https://pypi.org/project/scak/)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Basic self-correction with retry for AI agents.**

SCAK provides a lightweight self-correction loop that detects agent failures and retries with corrective feedback. When an agent produces an incorrect or incomplete result, SCAK catches the failure, applies a correction strategy, and retries the action.

## Installation

```bash
pip install scak
```

## Quick Start

```python
from scak import SelfCorrectingKernel

kernel = SelfCorrectingKernel()
result = await kernel.run(task="Summarize this document", max_retries=3)
```

## Features

- Failure detection and classification
- Configurable retry strategies
- Memory of past corrections to avoid repeated mistakes
- Integration with Agent OS policy engine

## Documentation

See [docs/](./docs/) for guides and [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup.

## License

MIT License - see [LICENSE](LICENSE) for details.
