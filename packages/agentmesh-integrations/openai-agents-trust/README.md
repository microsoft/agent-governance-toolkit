# openai-agents-trust

Trust & governance layer for the [OpenAI Agents SDK](https://github.com/openai/openai-agents-python). Adds policy enforcement, trust-gated handoffs, and tamper-evident audit trails using native SDK guardrails and hooks.

> Built by [AgentMesh](https://github.com/imran-siddique/agent-mesh) — the open-source trust layer for multi-agent systems. Similar integrations merged into [Dify](https://github.com/langgenius/dify-plugins/pull/2060) (65K ⭐), [LlamaIndex](https://github.com/run-llama/llama_index/pull/20644) (47K ⭐), and [Microsoft Agent-Lightning](https://github.com/microsoft/agent-lightning/pull/478) (15K ⭐).

## Install

```bash
pip install openai-agents-trust
```

## Quick Start

```python
from agents import Agent, Runner
from openai_agents_trust import (
    trust_input_guardrail,
    policy_input_guardrail,
    GovernanceHooks,
    TrustGuardrailConfig,
    PolicyGuardrailConfig,
    TrustScorer,
    GovernancePolicy,
    AuditLog,
)

# Shared governance state
scorer = TrustScorer()
audit = AuditLog()
policy = GovernancePolicy(
    name="production",
    max_tool_calls=20,
    blocked_patterns=[r"DROP TABLE", r"rm -rf", r"eval\("],
    min_trust_score=0.7,
)

# Create guardrails
trust_config = TrustGuardrailConfig(scorer=scorer, min_score=0.7, audit_log=audit)
policy_config = PolicyGuardrailConfig(policy=policy, audit_log=audit)

# Attach to agents
agent = Agent(
    name="researcher",
    instructions="You are a research assistant.",
    input_guardrails=[
        trust_input_guardrail(trust_config),
        policy_input_guardrail(policy_config),
    ],
)

# Run with governance hooks
result = await Runner.run(
    agent,
    input="Analyze this data",
    run_config=RunConfig(hooks=GovernanceHooks(policy=policy, scorer=scorer, audit_log=audit)),
)

# Verify audit integrity
print(f"Audit entries: {len(audit)}")
print(f"Chain valid: {audit.verify_chain()}")
```

## Trust-Gated Handoffs

```python
from openai_agents_trust import trust_gated_handoff

billing_agent = Agent(name="billing", instructions="Handle billing.")
support_agent = Agent(name="support", instructions="Handle support.")

triage = Agent(
    name="triage",
    handoffs=[
        trust_gated_handoff(billing_agent, scorer=scorer, min_score=0.8),
        trust_gated_handoff(support_agent, scorer=scorer, min_score=0.6),
    ],
)
```

## Features

| Feature | SDK Hook | Description |
|---------|----------|-------------|
| **Trust Guardrail** | `InputGuardrail` | Blocks agents below trust threshold |
| **Policy Guardrail** | `InputGuardrail` | Enforces blocked patterns, tool limits |
| **Content Guardrail** | `OutputGuardrail` | Validates output against policies |
| **Governance Hooks** | `RunHooksBase` | Tracks tools, audits handoffs, scores trust |
| **Trust-Gated Handoff** | `is_enabled` | Disables handoffs to untrusted agents |
| **hash-chain Audit** | — | Tamper-evident chain of all decisions |

## License

MIT
