# Architecture

## Overview

The Agent Governance Toolkit provides **deterministic application-layer interception**: every agent action is evaluated against policy **before execution**, at sub-millisecond latency. For high-security environments, composes with container/VM isolation for defense-in-depth.

Each major component has a formal RFC 2119 specification with conformance tests. See [Specifications](specs/) for the full list.

## Video Walkthrough Series

Community video series covering the toolkit architecture:

1. [Agent OS & Policy Engine](https://www.youtube.com/watch?v=jq-3FWk5KlI)
2. [Agent Mesh & Trust Layer](https://www.youtube.com/watch?v=pCJWqCWpXRI)
3. [Agent SRE & Observability](https://youtu.be/5Rey8lzgVvs)

## System Architecture

```
╔══════════════════════════════════════════════════════════════════════════╗
║                    AGENT GOVERNANCE TOOLKIT  v3.7.0                     ║
║              pip install agent-governance-toolkit[full]                  ║
║                                                                         ║
║  Agent Action ──► POLICY CHECK ──► Allow / Deny    (< 0.1 ms)          ║
║                                                                         ║
║  ┌──────────────────────────┐     ┌──────────────────────────────┐      ║
║  │      AGENT OS ENGINE     │◄───►│          AGENTMESH           │      ║
║  │                          │     │                              │      ║
║  │  ● Policy Engine         │     │  ● Zero-Trust Identity       │      ║
║  │  ● Capability Model      │     │  ● Ed25519 / SPIFFE Certs    │      ║
║  │  ● Governance Gate       │     │  ● Trust Scoring (0-1000)    │      ║
║  │  ● GovernanceEventSink   │     │  ● Wire Protocol (A2A/MCP)   │      ║
║  │  ● Decision BOM          │     │  ● Delegation Chains         │      ║
║  └────────────┬─────────────┘     └───────────────┬──────────────┘      ║
║               │                                   │                     ║
║               ▼                                   ▼                     ║
║  ┌──────────────────────────┐     ┌──────────────────────────────┐      ║
║  │     AGENT RUNTIME        │     │         AGENT SRE            │      ║
║  │                          │     │                              │      ║
║  │  ● Execution Rings (0-3) │     │  ● SLO Engine + Error Budgets│      ║
║  │  ● Resource Limits       │     │  ● Replay & Chaos Testing    │      ║
║  │  ● Runtime Sandboxing    │     │  ● Progressive Delivery      │      ║
║  │  ● Termination Control   │     │  ● Circuit Breakers          │      ║
║  └──────────────────────────┘     └──────────────────────────────┘      ║
║                                                                         ║
║  ┌──────────────────────────┐     ┌──────────────────────────────┐      ║
║  │    AGENT HYPERVISOR      │     │      AGENT LIGHTNING         │      ║
║  │                          │     │                              │      ║
║  │  ● Execution Audit       │     │  ● RL Training Governance    │      ║
║  │  ● Delta Engine          │     │  ● Violation Penalties       │      ║
║  │  ● Commitment Anchoring  │     │  ● Reward Shaping            │      ║
║  │  ● Merkle Chain Logs     │     │  ● Training Checkpoints      │      ║
║  └──────────────────────────┘     └──────────────────────────────┘      ║
║                                                                         ║
║  ┌──────────────────────────┐     ┌──────────────────────────────┐      ║
║  │   AGENT MARKETPLACE      │     │   MCP SECURITY GATEWAY       │      ║
║  │                          │     │                              │      ║
║  │  ● Plugin Discovery      │     │  ● Tool-Call Policy Checks   │      ║
║  │  ● Signing & Verification│     │  ● Trust Verification        │      ║
║  │  ● Trust Scoring         │     │  ● Rate Limiting             │      ║
║  └──────────────────────────┘     └──────────────────────────────┘      ║
║                                                                         ║
║  ┌──────────────────────────────────────────────────────────────┐       ║
║  │              FRAMEWORK ADAPTERS                              │       ║
║  │  LangChain · CrewAI · AutoGen · OpenAI · ADK · smolagents   │       ║
║  └──────────────────────────────────────────────────────────────┘       ║
║                                                                         ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### Component Specifications

| Component | Specification |
|---|---|
| Agent OS Policy Engine | [AGENT-OS-POLICY-ENGINE-1.0](specs/AGENT-OS-POLICY-ENGINE-1.0.md) |
| AgentMesh Identity and Trust | [AGENTMESH-IDENTITY-TRUST-1.0](specs/AGENTMESH-IDENTITY-TRUST-1.0.md) |
| Agent Hypervisor | [AGENT-HYPERVISOR-EXECUTION-CONTROL-1.0](specs/AGENT-HYPERVISOR-EXECUTION-CONTROL-1.0.md) |
| AgentMesh Trust and Coordination | [AGENTMESH-TRUST-COORDINATION-1.0](specs/AGENTMESH-TRUST-COORDINATION-1.0.md) |
| Agent SRE | [AGENT-SRE-GOVERNANCE-1.0](specs/AGENT-SRE-GOVERNANCE-1.0.md) |
| MCP Security Gateway | [MCP-SECURITY-GATEWAY-1.0](specs/MCP-SECURITY-GATEWAY-1.0.md) |
| Agent Lightning | [AGENT-LIGHTNING-FAST-PATH-1.0](specs/AGENT-LIGHTNING-FAST-PATH-1.0.md) |
| Framework Adapters | [FRAMEWORK-ADAPTER-CONTRACT-1.0](specs/FRAMEWORK-ADAPTER-CONTRACT-1.0.md) |
| Audit and Compliance | [AUDIT-COMPLIANCE-1.0](specs/AUDIT-COMPLIANCE-1.0.md) |
| AgentMesh Wire Protocol | [AGENTMESH-WIRE-1.0](specs/AGENTMESH-WIRE-1.0.md) |

Design rationale is documented in [25 Architecture Decision Records](adr/).

## Security Model & Boundaries

| Enforcement Capability | Defense-in-Depth Composition |
|---|---|
| Intercepts and evaluates every agent action before execution | Add container isolation (Docker, gVisor, Kata) for OS-level separation |
| Enforces capability-based least-privilege policies | Add network policies for cross-agent communication control |
| Provides cryptographic agent identity (Ed25519) | Add external PKI for certificate lifecycle management |
| Maintains append-only audit logs with Merkle chains | Add external append-only sink (Azure Monitor, write-once storage) for tamper-evidence |
| Terminates non-compliant agents via signal system | Add OS-level `process.kill()` for isolated agent processes |
| Governance gate blocks actions before execution (fail-closed) | Add MCP Security Gateway for tool-call-level interception |

The POSIX metaphor (kernel, signals, syscalls) is an architectural pattern that provides a familiar, well-understood mental model for agent governance. The enforcement boundary is the Python interpreter, which is the same trust boundary used by every Python-based agent framework (LangChain, AutoGen, CrewAI, OpenAI Agents SDK).

> **Production recommendation:** For high-security deployments, run each agent in a separate container with the governance middleware inside. This gives you both application-level policy enforcement *and* OS-level isolation.

## Trust Score Algorithm

AgentMesh assigns trust scores on a 0-1000 scale with the following tiers:

| Score Range | Tier | Meaning |
|---|---|---|
| 900-1000 | Verified Partner | Cryptographically verified, long-term trusted |
| 700-899 | Trusted | Established track record, elevated privileges |
| 500-699 | Standard | Default for new agents with valid identity |
| 300-499 | Probationary | Limited privileges, under observation |
| 0-299 | Untrusted | Restricted to read-only or blocked |

Default score for new agents: **500** (Standard tier). Score changes are driven by policy compliance history, successful task completions, and trust boundary violations. Full algorithm documentation is in [`agent-governance-python/agent-mesh/docs/TRUST-SCORING.md`](../agent-governance-python/agent-mesh/docs/TRUST-SCORING.md).

## Benchmark Methodology

Policy enforcement benchmarks are measured on a **30-scenario test suite** covering the OWASP Agentic Top 10 risk categories. Results (e.g., policy violation rates, latency) are specific to this test suite and should not be interpreted as universal guarantees. See [`agent-governance-python/agent-os/modules/control-plane/benchmark/`](../agent-governance-python/agent-os/modules/control-plane/benchmark/) for methodology, datasets, and reproduction instructions.

Full benchmark results: **[BENCHMARKS.md](../BENCHMARKS.md)**
