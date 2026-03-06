# CoSAI/OASIS WS4 — RFC: Kernel-Based Runtime Governance

**Submission:** [cosai-oasis/ws4-secure-design-agentic-systems#42](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/42)
**Status:** Open — awaiting WS4 review
**Type:** RFC (Request for Comments)
**Priority:** P1 — foundational pattern enabling other security controls
**Level of Effort:** Medium (1-2 weeks for full documentation)
**Date Submitted:** March 2, 2026

---

## Summary

We propose documenting **kernel-based runtime governance** as a secure design pattern for agentic AI systems. Unlike static guardrails or prompt-level filtering, this pattern enforces security policies at the execution layer — analogous to how operating system kernels mediate hardware access.

## The Four Governance Layers

### 1. Policy Engine
- **What:** Declarative YAML policies validated at runtime against agent goals and actions
- **Mitigates:** ASI-01 (Agent Hijacking)
- **Mechanism:** Every agent goal/action is checked against a policy before execution; unauthorized goals are rejected with audit trail

### 2. Capability Sandbox
- **What:** Ring-based permission model (Ring 0–3) restricting agent access to tools, filesystem, and network
- **Mitigates:** ASI-02 (Excessive Agency)
- **Mechanism:** Inspired by OS kernel ring architecture — agents operate at the lowest privilege needed, with explicit capability grants

### 3. Inter-Agent Trust Protocol (IATP)
- **What:** DID-based identity verification for multi-agent communication with cryptographic handshakes
- **Mitigates:** ASI-03 (Insecure Communication), ASI-07 (Identity Spoofing)
- **Mechanism:** Each agent has a DID identity; trust scores (0–1000) are verified before delegation; mutual authentication via challenge-response

### 4. Kill Switch & Circuit Breakers
- **What:** Emergency shutdown with state preservation and graceful degradation patterns
- **Mitigates:** ASI-08 (Unbounded Autonomy), ASI-10 (Cascading Hallucinations)
- **Mechanism:** Kill switch triggers immediate halt; circuit breakers prevent cascading failures; saga rollback for multi-step operations

## Relevance to WS4

This pattern directly addresses the workstream's focus on secure design patterns for agentic systems:

- **Secure inter-agent communication** — aligns with the MCP security analysis already in the WS4 repo
- **Runtime policy enforcement** — complementary to static analysis approaches
- **Least-privilege capability management** — for tool-using agents
- **External enforcement** — governance is mandatory, not optional for agents

## Why Kernel-Based (Not Alternatives)?

| Approach | Limitation |
|----------|-----------|
| **Prompt-level guardrails** (Lakera, Guardrails AI) | Only filter inputs/outputs, not runtime behavior |
| **Static policy frameworks** (OPA/Rego for AI) | Good for pre-deployment, can't catch runtime goal drift |
| **Agent-level self-governance** (constitutional AI) | Agent policing itself = single point of failure |
| **Kernel-based runtime governance** | External, runtime, mandatory — agents cannot bypass |

## Reference Implementation

[Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) — 5 packages, 3,900+ tests, covering 9/10 OWASP Agentic Top 10 risks.

### Code Example: Policy Enforcement

```python
from agent_os import PolicyEngine, CapabilitySandbox

# Declarative policy — no code changes needed
policy = PolicyEngine.from_yaml("production-policy.yaml")

# Agent action is checked at runtime
result = policy.evaluate(
    agent_id="support-agent",
    action="tool_call",
    tool="database_query",
    parameters={"query": "SELECT * FROM users"}
)
# result.allowed = True/False with audit trail
```

### Code Example: Capability Sandbox

```python
from agent_os import CapabilitySandbox, Ring

sandbox = CapabilitySandbox(ring=Ring.USER)  # Ring 3 = least privilege
sandbox.grant("read_docs", "search_web")     # Explicit capability grants

# This will raise CapabilityViolation:
sandbox.check("execute_shell")  # Not granted → blocked
```

## Drawbacks

- Adds runtime overhead (policy checks on every action) — mitigated by caching and fast-path optimization
- Requires agents to integrate with the governance layer — intentional (security by design)
- Opinionated about enforcement location (runtime vs. design-time) — complements rather than replaces static analysis

## Unresolved Questions

1. Should this document cover multi-tenant governance (multiple organizations sharing a governance kernel)?
2. How should the pattern address dynamic policy updates (hot-reloading policies without agent restart)?
3. What level of formal verification is appropriate for policy engines in safety-critical deployments?

## Reference Material

- [OWASP Agentic Top 10 Compliance Mapping](https://github.com/microsoft/agent-governance-toolkit/blob/master/docs/OWASP-COMPLIANCE.md)
- [Agent OS](https://github.com/microsoft/agent-governance-toolkit) — reference implementation
- [Agent Mesh](https://github.com/microsoft/agent-governance-toolkit) — inter-agent trust layer
- [Agent Hypervisor](https://github.com/microsoft/agent-governance-toolkit) — execution isolation
- [CoSAI MCP Security Analysis](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md) — complementary work
- OS kernel security model (Linux capabilities, SELinux mandatory access control) — inspiration for ring-based approach
