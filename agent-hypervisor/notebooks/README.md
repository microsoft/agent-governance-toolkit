# Notebooks

Interactive Jupyter notebooks for exploring the **agent-hypervisor** runtime.

## Available Notebooks

| Notebook | Description |
|----------|-------------|
| [`hypervisor-exploration.ipynb`](hypervisor-exploration.ipynb) | End-to-end tour of execution rings, sagas, kill switch, rate limiting, audit trails, and joint liability |

## Quick Start

```bash
# From the repository root
pip install -e ".[dev]" plotly nest-asyncio
jupyter notebook notebooks/
```

## What's Covered

1. **Setup** — Import hypervisor modules and create a session
2. **Execution Rings** — Assign agents to rings based on trust scores; enforce ring-level permissions
3. **Saga Pattern** — Define multi-step workflows with automatic compensation on failure
4. **Kill Switch** — Terminate misbehaving agents and hand off in-flight work
5. **Resource Limits** — Per-ring rate limiting demonstration
6. **Audit Trail** — Hash-chained, tamper-evident delta log with chain verification
7. **Joint Liability** — Vouching bonds and slashing cascades
8. **Visualization** — Plotly charts showing ring distribution, trust mapping, and audit timeline

## Requirements

- Python ≥ 3.11
- `agent-hypervisor` (this package)
- `plotly` (optional — the notebook falls back to text output without it)
- `nest-asyncio` (for running async code in Jupyter)
