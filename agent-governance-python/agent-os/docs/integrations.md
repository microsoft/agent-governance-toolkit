# Framework Integrations

Agent OS framework adapters use one native ACS runtime. Each adapter receives
`runtime=` and routes framework inputs, model calls, tool calls, and outputs
through the intervention points it supports.

## Runtime setup

```python
from agt.policies import AgtRuntime
from agent_os.integrations.langchain_adapter import LangChainKernel

runtime = AgtRuntime("policies/manifest.yaml")
kernel = LangChainKernel(runtime=runtime)
```

The manifest owns policy definitions, tool catalogs, budgets, transforms, and
approval bindings. Adapter constructors do not accept inline rule objects or
policy directories.

## Supported adapters

| Framework | Adapter |
|-----------|---------|
| A2A | `A2AGovernanceAdapter` |
| AgentShield | `AgentShieldKernel` |
| Anthropic | `AnthropicKernel` |
| AutoGen | `AutoGenKernel` |
| Amazon Bedrock | `BedrockKernel` |
| CrewAI | `CrewAIKernel` |
| Gemini | `GeminiKernel` |
| Google ADK | `GoogleADKKernel` |
| Guardrails AI | `GuardrailsKernel` |
| LangChain | `LangChainKernel` |
| LangGraph | `LangGraphKernel` |
| LlamaIndex | `LlamaIndexKernel` |
| Microsoft Agent Framework | `MAFKernel` |
| Mistral | `MistralKernel` |
| OpenAI | `OpenAIKernel` |
| OpenAI Agents SDK | `OpenAIAgentsKernel` |
| Pydantic AI | `PydanticAIKernel` |
| Semantic Kernel | `SemanticKernelWrapper` |
| Smolagents | `SmolagentsKernel` |

## Manifest preflight

Adapters that declare an `AdapterManifestContract` validate required
intervention points, tool catalogs, approval support, and transform support
before execution. Unresolved `extends` entries must be resolved before adapter
preflight.

```python
from agt.policies import AdapterManifestContract, AdapterRuntimeSession

contract = AdapterManifestContract(
    name="example",
    required_intervention_points=frozenset({"input", "pre_tool_call", "output"}),
)
session = AdapterRuntimeSession(
    runtime,
    agent_id="agent-1",
    session_id="session-1",
    contract=contract,
)
```

## Denials and audit

Denied and escalated evaluations raise the canonical
`agent_os.exceptions.PolicyViolationError`. The public message is sanitized.
The structured `PolicyEvaluation` remains available through
`error.evaluation_result`, and its restricted audit payload is available through
`audit_record()`.

```python
from agent_os.exceptions import PolicyViolationError

try:
    result = session.evaluate_input(body="user request")
    if not result.is_allowed():
        raise PolicyViolationError.from_evaluation_result(result)
except PolicyViolationError as error:
    print(str(error))
    print(error.evaluation_result.audit_record())
```

## Lifecycle ownership

`AgtRuntime` is policy-state-free and may be shared when host dispatchers and
approval callbacks are thread-safe. `AdapterRuntimeSession` owns session
counters and charges attempted tool calls before evaluation.

See [Framework Adapter Contract](../../../docs/specs/FRAMEWORK-ADAPTER-CONTRACT-1.0.md)
and [v4 policy-language removal](../../../docs/v4-removal.md).
