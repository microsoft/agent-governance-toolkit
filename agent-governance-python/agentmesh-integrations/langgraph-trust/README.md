# langgraph-trust

This package is deprecated. Install
`agent-governance-toolkit-integrations[langgraph]` for the consolidated
integration surface.

Trust scoring, identity, and trust-aware graph edges remain host controls.
Policy checkpoints use the native ACS runtime through the Agent OS LangGraph
adapter.

```python
from agent_control_specification import AgentControl
from agent_os.integrations.langgraph_adapter import LangGraphKernel

runtime = AgentControl.from_path("policies/manifest.yaml")
kernel = LangGraphKernel(runtime=runtime)
```

Policy for the graph itself comes from the ACS manifest above.

`PolicyCheckpoint` still interprets the package's own `GraphTrustRules`
(`blocked_tools`, `blocked_patterns`, `max_tokens`) for checkpoint-level trust
decisions. That type was renamed as part of this change; it was not removed.

See the
[package consolidation migration guide](../../../docs/package-consolidation/MIGRATION.md).
