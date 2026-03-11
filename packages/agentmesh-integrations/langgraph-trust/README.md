# langgraph-trust

**Trust-gated checkpoint nodes for LangGraph** — cryptographic identity, governance policy enforcement, and trust-aware routing for multi-agent graphs.

Built on [AgentMesh](https://github.com/imran-siddique/agent-mesh) trust primitives. Designed as an external package per [LangGraph maintainer guidance](https://github.com/langchain-ai/langgraph/issues/6824#issuecomment-3916188130).

## Install

```bash
pip install langgraph-trust
```

## Quick Start

```python
from langgraph.graph import StateGraph, END
from langgraph_trust import TrustGate, PolicyCheckpoint, trust_edge
from langgraph_trust.gate import TrustScoreTracker

# Shared trust tracker
tracker = TrustScoreTracker()
tracker.set_score("research-agent", 0.85)

# Build a trust-gated graph
graph = StateGraph(dict)

graph.add_node("research", research_agent)
graph.add_node("trust_check", TrustGate(min_score=0.7, tracker=tracker))
graph.add_node("execute", execution_agent)
graph.add_node("human_review", human_review_agent)

graph.add_edge("research", "trust_check")
graph.add_conditional_edges("trust_check", trust_edge(
    pass_node="execute",
    fail_node="human_review",
))
graph.add_edge("execute", END)
graph.add_edge("human_review", END)

graph.set_entry_point("research")
app = graph.compile()
```

## Components

### TrustGate

Conditional checkpoint node that evaluates an agent's trust score before allowing graph transitions.

```python
gate = TrustGate(
    min_score=0.7,           # Minimum score to pass
    review_threshold=0.8,    # Optional: scores between min and review → REVIEW verdict
    tracker=tracker,         # TrustScoreTracker instance
    identity_manager=idm,   # Optional: AgentIdentityManager for capability checks
    agent_name="my-agent",   # Default agent (overridden by state["trust_agent"])
    required_capabilities=["summarize"],  # Optional capability requirements
)
```

### PolicyCheckpoint

Governance policy enforcement at graph transitions.

```python
from langgraph_trust.policy import GovernancePolicy

policy = GovernancePolicy(
    name="production-safety",
    max_tokens=4000,
    max_tool_calls=5,
    blocked_tools=["shell_exec", "file_delete"],
    blocked_patterns=["password", "api_key", "secret"],
    require_human_approval=False,
)

checkpoint = PolicyCheckpoint(policy=policy)
graph.add_node("policy_gate", checkpoint)
```

### Trust-Aware Edges

```python
from langgraph_trust import trust_edge, trust_router

# Simple pass/fail routing
graph.add_conditional_edges("gate", trust_edge(
    pass_node="execute",
    fail_node="quarantine",
    review_node="human_review",  # Optional
))

# General-purpose routing
graph.add_conditional_edges("gate", trust_router({
    "pass": "execute",
    "fail": "quarantine",
    "review": "escalate",
}))
```

### Dynamic Trust Scoring

```python
from langgraph_trust.gate import TrustScoreTracker

tracker = TrustScoreTracker(default_score=0.5)

# After successful task
tracker.record_success("agent-a")  # +0.01

# After failure (severity configurable)
tracker.record_failure("agent-a", severity=0.2)  # -0.2

# Agent auto-blocked when score < min_score
```

### Cryptographic Identity

```python
from langgraph_trust import AgentIdentityManager

idm = AgentIdentityManager()

# Create Ed25519 identity with capabilities
alice = idm.create_identity("alice", capabilities=["summarize", "translate"])
print(alice.did)  # did:langgraph:a3f7c2...

# Sign and verify data
sig = alice.sign(b"important data")
assert alice.verify(sig, b"important data")
```

## How It Works

All components write their verdict to `state["trust_result"]`:

```python
{
    "verdict": "pass" | "fail" | "review",
    "score": 0.85,
    "threshold": 0.7,
    "agent_did": "did:langgraph:abc...",
    "reason": "Trust gate passed",
    "capabilities_checked": ["summarize"],
    "policy_violations": [],
    "timestamp": "2026-02-17T..."
}
```

The `trust_edge` and `trust_router` functions read this verdict to route the graph.

## Integration with Full AgentMesh

This package provides a lightweight, self-contained trust layer. For the full 5-dimension trust scoring engine with temporal decay, trust contagion, and hash-chain audit chains, install:

```bash
pip install langgraph-trust[agentmesh]
```

## Related

- [AgentMesh](https://github.com/imran-siddique/agent-mesh) — Full trust scoring engine
- [Agent OS](https://github.com/imran-siddique/agent-os) — Governance kernel for AI agents
- [Dify Trust Layer](https://github.com/langgenius/dify-plugins/pull/2060) — Similar integration for Dify (merged)
- [LlamaIndex Integration](https://github.com/run-llama/llama_index/pull/20644) — Trust layer for LlamaIndex (merged)

## License

MIT
