# OpenAI Agents AgentMesh

AgentMesh trust layer for OpenAI Agents SDK — trust-gated function calling and handoff verification.

## Features

- **TrustedFunctionGuard**: Verify agent trust before allowing function/tool calls
- **HandoffVerifier**: Validate trust when agents hand off tasks to each other
- **AgentTrustContext**: Propagate trust metadata through agent conversations

## Quick Start

```python
from openai_agents_agentmesh import TrustedFunctionGuard, HandoffVerifier

# Guard function calls with trust
guard = TrustedFunctionGuard(
    min_trust_score=500,
    sensitive_functions={"delete_file": 800, "send_email": 700},
)

result = guard.check_call(
    agent_did="did:mesh:assistant",
    agent_trust_score=600,
    function_name="search",
)
assert result.allowed

# Verify handoffs between agents
verifier = HandoffVerifier(min_trust_score=400)
result = verifier.verify_handoff(
    source_did="did:mesh:triage",
    source_trust=700,
    target_did="did:mesh:specialist",
    target_trust=600,
)
assert result.allowed
```
