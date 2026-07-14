# agentmesh-openai-agents-trust

This package is deprecated. Install
`agent-governance-toolkit-integrations[openai-agents]` for the consolidated
integration surface.

Policy guardrails now use the native ACS runtime owned by Agent OS. Trust
scoring, handoffs, hooks, identity, and tamper-evident audit helpers remain
separate host concerns.

```python
from agt.policies import AgtRuntime
from agent_os.integrations.openai_agents_sdk import OpenAIAgentsKernel

runtime = AgtRuntime("policies/manifest.yaml")
kernel = OpenAIAgentsKernel(runtime=runtime)
```

The manifest owns policy bindings, tool catalogs, budgets, transforms, and
approval. This package no longer exposes an inline policy interpreter.

See the
[package consolidation migration guide](../../../docs/package-consolidation/MIGRATION.md).
