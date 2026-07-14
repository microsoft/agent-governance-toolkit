# langgraph-trust

This package is deprecated. Install
`agent-governance-toolkit-integrations[langgraph]` for the consolidated
integration surface.

Trust scoring, identity, and trust-aware graph edges remain host controls.
Policy checkpoints use the native ACS runtime through the Agent OS LangGraph
adapter.

```python
from agt.policies import AgtRuntime
from agent_os.integrations.langgraph_adapter import LangGraphKernel

runtime = AgtRuntime("policies/manifest.yaml")
kernel = LangGraphKernel(runtime=runtime)
```

This package no longer creates or interprets inline policy objects.

See the
[package consolidation migration guide](../../../docs/package-consolidation/MIGRATION.md).
