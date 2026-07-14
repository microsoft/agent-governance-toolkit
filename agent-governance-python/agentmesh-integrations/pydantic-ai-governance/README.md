# pydantic-ai-governance

This package is deprecated. Install
`agent-governance-toolkit-integrations[pydantic-ai]` for the consolidated
integration surface.

Inline rule objects, decorators, and toolset wrappers are no longer provided.
Use a native ACS manifest with `AgtRuntime`, then pass that runtime to the Agent
OS Pydantic AI adapter.

```python
from agt.policies import AgtRuntime
from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel

runtime = AgtRuntime("policies/manifest.yaml")
kernel = PydanticAIKernel(runtime=runtime)
```

The remaining package modules expose trust, audit, and semantic-intent helpers
for compatibility during package consolidation. They do not interpret policy
documents.

See the
[package consolidation migration guide](../../../docs/package-consolidation/MIGRATION.md).
