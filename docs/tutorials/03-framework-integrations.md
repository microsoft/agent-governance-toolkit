---
title: Framework Integrations
last_reviewed: 2026-07-12
owner: docs-team
---

# Framework Integrations

Agent OS adapters mediate framework lifecycle events through one native ACS
runtime.

## Create the runtime

```python
from agt.policies import AgtRuntime

runtime = AgtRuntime("policies/manifest.yaml")
```

The manifest owns policies, tool catalogs, budgets, transforms, annotators, and
approval. Adapter constructors do not accept inline policy objects.

## Attach an adapter

```python
from agent_os.integrations.openai_adapter import OpenAIKernel

kernel = OpenAIKernel(runtime=runtime)
```

All framework adapters use `runtime=` except `AgentShieldKernel`, which uses
`agt_runtime=` because its positional `runtime` argument belongs to the host
SDK.

## Session lifecycle

Adapters create a session-scoped `AdapterRuntimeSession` and synchronize host
counters before each evaluation. Attempted tool calls are charged before
policy evaluation.

```python
context = kernel.create_context("agent-1")
result = kernel.evaluate_pre_tool_call(
    context,
    tool_name="search",
    args={"query": "quarterly results"},
)
```

## Intervention points

Adapters mediate the intervention points supported by their host framework.
Common paths include:

- `input`
- `pre_model_call`
- `post_model_call`
- `pre_tool_call`
- `post_tool_call`
- `output`

The adapter mediation contract tests verify that public framework paths reach
their required native intervention points before side effects or disclosure.

## Denials

```python
from agent_os.exceptions import PolicyViolationError

if not result.allowed:
    raise result.to_policy_violation(PolicyViolationError)
```

The public exception message is sanitized. Trusted code can inspect
`error.evaluation_result` and its `audit_record()`.

## Transforms

When a policy returns `transform`, use the materialized transform supplied by
the native result. Do not publish the original input or output after a
successful transform.

## Approval

Register an approval resolver when constructing `AgtRuntime`. The resolver must
return an `ApprovalDecision` bound to the evaluation's enforced identity.
Identity mismatch fails closed.

## Manifest preflight

Adapters can declare `AdapterManifestContract` requirements for intervention
points, tool catalogs, approval, transforms, and budget accounting. Resolve
`extends` before preflight.

## Supported frameworks

Agent OS includes adapters for A2A, AgentShield, Anthropic, AutoGen, Bedrock,
CrewAI, Gemini, Google ADK, Guardrails AI, LangChain, LangGraph, LlamaIndex,
Microsoft Agent Framework, Mistral, OpenAI, OpenAI Agents SDK, Pydantic AI,
Semantic Kernel, and Smolagents.

See [Retrofit Governance](retrofit-governance.md) and the
[Framework Adapter Contract](../specs/FRAMEWORK-ADAPTER-CONTRACT-1.0.md).
