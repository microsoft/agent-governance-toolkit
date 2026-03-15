# Architecture

## Overview

The Agent Governance Toolkit provides **deterministic application-layer interception** — every agent action is evaluated against policy **before execution**, at sub-millisecond latency. For high-security environments, composes with container/VM isolation for defense-in-depth.

## System Architecture

```
╔══════════════════════════════════════════════════════════════════════════╗
║                    AGENT GOVERNANCE TOOLKIT                              ║
║                 pip install agent-governance[full]                        ║
║                                                                          ║
║   Agent Action ───► POLICY CHECK ───► Allow / Deny    (< 0.1 ms)        ║
║                                                                          ║
║   ┌──────────────────────────┐     ┌──────────────────────────────┐      ║
║   │      AGENT OS ENGINE     │◄───►│          AGENTMESH           │      ║
║   │                          │     │                              │      ║
║   │  ● Policy Engine         │     │  ● Zero-Trust Identity       │      ║
║   │  ● Capability Model      │     │  ● Ed25519 / SPIFFE Certs    │      ║
║   │  ● Audit Logging         │     │  ● Trust Scoring (0-1000)    │      ║
║   │  ● Action Interception   │     │  ● A2A + MCP Protocol Bridge │      ║
║   └────────────┬─────────────┘     └───────────────┬──────────────┘      ║
║                │                                   │                     ║
║                ▼                                   ▼                     ║
║   ┌──────────────────────────┐     ┌──────────────────────────────┐      ║
║   │     AGENT RUNTIME        │     │         AGENT SRE            │      ║
║   │                          │     │                              │      ║
║   │  ● Execution Rings       │     │  ● SLO Engine + Error Budgets│      ║
║   │  ● Resource Limits       │     │  ● Replay & Chaos Testing    │      ║
║   │  ● Runtime Sandboxing    │     │  ● Progressive Delivery      │      ║
║   │  ● Termination Control   │     │  ● Circuit Breakers          │      ║
║   └──────────────────────────┘     └──────────────────────────────┘      ║
║                                                                          ║
║   ┌──────────────────────────┐     ┌──────────────────────────────┐      ║
║   │   AGENT MARKETPLACE      │     │      AGENT LIGHTNING         │      ║
║   │                          │     │                              │      ║
║   │  ● Plugin Discovery      │     │  ● RL Training Governance    │      ║
║   │  ● Signing & Verification│     │  ● Policy Rewards            │      ║
║   └──────────────────────────┘     └──────────────────────────────┘      ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

## Security Model & Boundaries

| Enforcement Capability | Defense-in-Depth Composition |
|---|---|
| Intercepts and evaluates every agent action before execution | Add container isolation (Docker, gVisor, Kata) for OS-level separation |
| Enforces capability-based least-privilege policies | Add network policies for cross-agent communication control |
| Provides cryptographic agent identity (Ed25519) | Add external PKI for certificate lifecycle management |
| Maintains append-only audit logs with hash chains | Add external append-only sink (Azure Monitor, write-once storage) for tamper-evidence |
| Terminates non-compliant agents via signal system | Add OS-level `process.kill()` for isolated agent processes |

The POSIX metaphor (kernel, signals, syscalls) is an architectural pattern — it provides a familiar, well-understood mental model for agent governance. The enforcement boundary is the Python interpreter, which is the same trust boundary used by every Python-based agent framework (LangChain, AutoGen, CrewAI, OpenAI Agents SDK).

> **Production recommendation:** For high-security deployments, run each agent in a separate container with the governance middleware inside. This gives you both application-level policy enforcement *and* OS-level isolation.

## Trust Score Algorithm

AgentMesh assigns trust scores on a 0–1000 scale with the following tiers:

| Score Range | Tier | Meaning |
|---|---|---|
| 900–1000 | Verified Partner | Cryptographically verified, long-term trusted |
| 700–899 | Trusted | Established track record, elevated privileges |
| 500–699 | Standard | Default for new agents with valid identity |
| 300–499 | Probationary | Limited privileges, under observation |
| 0–299 | Untrusted | Restricted to read-only or blocked |

Default score for new agents: **500** (Standard tier). Score changes are driven by policy compliance history, successful task completions, and trust boundary violations. Full algorithm documentation is in [`packages/agent-mesh/docs/TRUST-SCORING.md`](../packages/agent-mesh/docs/TRUST-SCORING.md).

## Benchmark Methodology

Policy enforcement benchmarks are measured on a **30-scenario test suite** covering the OWASP Agentic Top 10 risk categories. Results (e.g., policy violation rates, latency) are specific to this test suite and should not be interpreted as universal guarantees. See [`packages/agent-os/modules/control-plane/benchmark/`](../packages/agent-os/modules/control-plane/benchmark/) for methodology, datasets, and reproduction instructions.

Full benchmark results: **[BENCHMARKS.md](../BENCHMARKS.md)**
