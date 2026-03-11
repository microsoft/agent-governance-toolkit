# pydantic-ai-governance

Governance middleware for [PydanticAI](https://ai.pydantic.dev/) — semantic policy enforcement, trust scoring, and audit trails for agent tool execution.

> Part of the [AgentMesh](https://github.com/imran-siddique/agent-os) ecosystem.

## What This Does

Unlike input/output guardrails that validate LLM I/O, this package enforces **what tools are allowed to do** based on semantic policy — blocking dangerous operations before they execute.

| Layer | Scope | Example |
|-------|-------|---------|
| **Guardrails** (#1197) | LLM input/output | "Don't discuss competitor products" |
| **Hooks/Traits** (#2885/#4303) | Agent lifecycle | Transform PII in messages |
| **Governance** (this) | Tool execution | "Block `rm -rf`, limit to 10 tool calls, require trust score > 0.7" |

## Features

- **`GovernancePolicy`** — Pydantic model defining execution limits, blocked patterns, allowed tools
- **`govern()` decorator** — Wrap any PydanticAI tool with policy enforcement
- **`GovernanceToolset`** — Apply governance to all tools via PydanticAI's `WrapperToolset`
- **`TrustScorer`** — Multi-dimensional trust tracking (reliability, capability, security, compliance)
- **Semantic intent classification** — Categorize tool calls by threat type, not just keyword matching
- **YAML policy files** — Version-controlled policies alongside code
- **Audit trail** — Every policy decision logged with context

## Quick Start

```python
from pydantic_ai import Agent
from pydantic_ai_governance import GovernancePolicy, govern, PatternType

policy = GovernancePolicy(
    max_tokens_per_request=4096,
    max_tool_calls_per_request=10,
    blocked_patterns=[
        ("rm -rf", PatternType.SUBSTRING),
        (r".*password.*=.*", PatternType.REGEX),
    ],
    allowed_tools=["search", "read_file"],
)

agent = Agent("openai:gpt-4o")

@agent.tool
@govern(policy)
async def search(ctx, query: str) -> str:
    """Search the web."""
    return f"Results for {query}"
```

### GovernanceToolset (apply to all tools)

```python
from pydantic_ai_governance import GovernanceToolset

toolset = GovernanceToolset(policy=policy, tools=[search, read_file])
agent = Agent("openai:gpt-4o", toolsets=[toolset])
```

### Trust Scoring

```python
from pydantic_ai_governance import TrustScorer

scorer = TrustScorer()
scorer.record_success("agent-1", dimensions=["reliability", "security"])
scorer.record_failure("agent-1", dimensions=["compliance"])

score = scorer.get_score("agent-1")
print(f"Trust: {score.overall:.2f}")  # 0.0-1.0
```

### YAML Policies

```yaml
# governance-policy.yaml
max_tokens_per_request: 4096
max_tool_calls_per_request: 10
blocked_patterns:
  - pattern: "rm -rf"
    type: substring
  - pattern: ".*password.*=.*"
    type: regex
allowed_tools:
  - search
  - read_file
confidence_threshold: 0.8
```

```python
policy = GovernancePolicy.from_yaml("governance-policy.yaml")
```

## How It Differs from Guardrails

See [pydantic/pydantic-ai#4335](https://github.com/pydantic/pydantic-ai/issues/4335) for the full discussion. Key differences:

1. **Semantic intent classification** — Weighted signal classifier with 9 threat categories
2. **Policy composition** — Hierarchical "most-restrictive-wins" merging
3. **Multi-agent awareness** — Swarm-level anomaly detection
4. **Deterministic** — Zero LLM dependency, sub-millisecond enforcement

## License

Apache-2.0
