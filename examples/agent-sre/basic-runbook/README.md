# Agent SRE Basic Runbook

This example creates a synthetic SLO breach incident, executes a small Agent SRE runbook, and prints each step result.

```bash
cd agent-governance-python/agent-sre
pip install -e .
cd ../../..
python examples/agent-sre/basic-runbook/main.py
```

For local source-tree testing without installing the package:

```bash
PYTHONPATH=agent-governance-python/agent-sre/src python examples/agent-sre/basic-runbook/main.py
```
