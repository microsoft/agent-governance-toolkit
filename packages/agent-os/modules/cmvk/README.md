# CMVK — Verification Kernel — Community Edition

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

[![PyPI version](https://badge.fury.io/py/cmvk.svg)](https://badge.fury.io/py/cmvk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Basic drift detection between model outputs.**

CMVK provides lightweight functions for comparing text and embeddings to detect when model outputs diverge. Use it to verify that two models (or two runs of the same model) produce semantically equivalent results.

## Installation

```bash
pip install cmvk
```

## Quick Start

```python
from cmvk import verify

score = verify("def add(a, b): return a + b", "def add(x, y): return x + y")
print(f"Drift: {score.drift_score:.3f}")  # 0.0 = identical
```

## Features

- Text comparison with drift scoring (0.0–1.0)
- Embedding and distribution comparison utilities
- Batch verification with aggregation
- Zero external service dependencies (numpy only)

## License

MIT License - see [LICENSE](LICENSE) for details.
