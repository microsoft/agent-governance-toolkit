# agentmesh-openai-agents-trust

This package is deprecated. Install
`agent-governance-toolkit-integrations[openai-agents]` for the consolidated
integration surface.

Policy guardrails now use the native ACS runtime owned by Agent OS. Trust
scoring, handoffs, hooks, identity, and tamper-evident audit helpers remain
separate host concerns.

```python
from agent_control_specification import AgentControl
from agent_os.integrations.openai_agents_sdk import OpenAIAgentsKernel

runtime = AgentControl.from_path("policies/manifest.yaml")
kernel = OpenAIAgentsKernel(runtime=runtime)
```

The manifest owns policy bindings, tool catalogs, budgets, transforms, and
approval. This package no longer exposes an inline policy interpreter.

**Caveat:** the openai-agents lifecycle hook signature does not carry
tool-call arguments, so `GovernanceHooks` evaluates `pre_tool_call` and
`post_tool_call` with empty `args`. Policy rules that condition on tool
arguments never match on the hooks path — enforce them through the guardrail
integration instead.

See the
[package consolidation migration guide](../../../docs/package-consolidation/MIGRATION.md).
