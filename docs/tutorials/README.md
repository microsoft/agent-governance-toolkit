# 📚 Tutorials

Step-by-step guides for every layer of the Agent Governance Toolkit — from your
first policy rule to production-grade observability. Each tutorial includes
runnable code examples, API reference tables, and cross-references to related
guides.

> **New here?** Start with [Tutorial 01 — Policy Engine](01-policy-engine.md),
> then follow the numbered sequence. Each tutorial builds on concepts from
> earlier ones.

---

## Core Governance

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------|
| 01 | [Policy Engine](01-policy-engine.md) | YAML rules, operators, conflict resolution, middleware integration | `agent-os-kernel` |
| 02 | [Trust & Identity](02-trust-and-identity.md) | Ed25519 credentials, DIDs, SPIFFE/SVID, trust scoring (0–1000) | `agentmesh-platform` |
| 03 | [Framework Integrations](03-framework-integrations.md) | Govern LangChain, CrewAI, AutoGen, OpenAI Agents, Google ADK | `agent-os-kernel` |
| 04 | [Audit & Compliance](04-audit-and-compliance.md) | Append-only audit logs, hash chains, OWASP ASI mapping | `agent-governance-toolkit` |

## Policy & Security

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------|
| 07 | [MCP Security Gateway](07-mcp-security-gateway.md) | Tool poisoning detection, parameter sanitization, human-in-the-loop | `agent-os-kernel` |
| 08 | [OPA/Rego & Cedar Policies](08-opa-rego-cedar-policies.md) | External policy backends, 3 evaluation modes, enterprise policies | `agent-os-kernel` |
| 09 | [Prompt Injection Detection](09-prompt-injection-detection.md) | 7 attack types, MemoryGuard, ConversationGuardian, red-teaming | `agent-os-kernel` |

## Runtime & Execution

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------|
| 05 | [Agent Reliability (SRE)](05-agent-reliability.md) | SLOs, error budgets, circuit breakers, chaos testing | `agent-sre` |
| 06 | [Execution Sandboxing](06-execution-sandboxing.md) | 4-tier privilege rings, resource limits, termination control | `agentmesh-runtime` |
| 11 | [Saga Orchestration](11-saga-orchestration.md) | Multi-step transactions, DSL, fan-out, compensating actions | `agentmesh-runtime` |
| 12 | [Liability & Attribution](12-liability-and-attribution.md) | Vouching, slashing, causal attribution, quarantine | `agentmesh-runtime` |
| 14 | [Kill Switch & Rate Limiting](14-kill-switch-and-rate-limiting.md) | Emergency termination, rate limiting, ring elevation | `agentmesh-runtime` |

## Trust & Networking

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------|
| 16 | [Protocol Bridges](16-protocol-bridges.md) | A2A, MCP proxy, IATP attestation, trust-gated communication | `agentmesh-platform` |
| 17 | [Advanced Trust & Behavior](17-advanced-trust-and-behavior.md) | Behavior monitoring, reward engine, trust policies, shadow mode | `agentmesh-platform` |

## Ecosystem

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------|
| 10 | [Plugin Marketplace](10-plugin-marketplace.md) | Plugin signing, verification, CLI, supply-chain security | `agentmesh-marketplace` |
| 13 | [Observability & Tracing](13-observability-and-tracing.md) | Causal traces, event bus, Prometheus, OpenTelemetry | `agentmesh-runtime` |
| 15 | [RL Training Governance](15-rl-training-governance.md) | GovernedRunner, PolicyReward, Gym-compatible environments | `agentmesh-lightning` |
| 18 | [Compliance Verification](18-compliance-verification.md) | Governance grading, regulatory frameworks, attestation | `agent-governance-toolkit` |

## Multi-Language SDKs

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------|
| 19 | [.NET SDK](19-dotnet-sdk.md) | GovernanceKernel, policy, rings, saga, SLO, OpenTelemetry in C# | `Microsoft.AgentGovernance` |
| 20 | [TypeScript SDK](20-typescript-sdk.md) | Identity, trust, policy, audit in TypeScript/Node.js | `@agentmesh/sdk` |

---

## Learning Paths

### 🚀 "I want to govern my agent in 10 minutes"

1. [01 — Policy Engine](01-policy-engine.md) → define allow/deny rules
2. [03 — Framework Integrations](03-framework-integrations.md) → wrap your framework
3. [04 — Audit & Compliance](04-audit-and-compliance.md) → log everything

### 🔒 "I need production-grade security"

1. [02 — Trust & Identity](02-trust-and-identity.md) → cryptographic agent identity
2. [09 — Prompt Injection Detection](09-prompt-injection-detection.md) → input security
3. [07 — MCP Security Gateway](07-mcp-security-gateway.md) → tool call security
4. [06 — Execution Sandboxing](06-execution-sandboxing.md) → privilege rings
5. [14 — Kill Switch & Rate Limiting](14-kill-switch-and-rate-limiting.md) → emergency controls

### 🏢 "I need enterprise compliance"

1. [08 — OPA/Rego & Cedar](08-opa-rego-cedar-policies.md) → bring existing policies
2. [04 — Audit & Compliance](04-audit-and-compliance.md) → tamper-proof audit trails
3. [18 — Compliance Verification](18-compliance-verification.md) → regulatory grading
4. [13 — Observability & Tracing](13-observability-and-tracing.md) → distributed tracing

### 🤖 "I'm building multi-agent systems"

1. [02 — Trust & Identity](02-trust-and-identity.md) → agent credentials
2. [16 — Protocol Bridges](16-protocol-bridges.md) → cross-protocol communication
3. [11 — Saga Orchestration](11-saga-orchestration.md) → multi-step workflows
4. [12 — Liability & Attribution](12-liability-and-attribution.md) → who's responsible
5. [17 — Advanced Trust & Behavior](17-advanced-trust-and-behavior.md) → dynamic trust

---

## Prerequisites

- **Python 3.10+** for Python tutorials (01–18)
- **.NET 8.0+** for the .NET tutorial (19)
- **Node.js 18+** for the TypeScript tutorial (20)

Install the full toolkit:

```bash
pip install agent-governance-toolkit[full]    # Python
dotnet add package Microsoft.AgentGovernance  # .NET
npm install @agentmesh/sdk                    # TypeScript
```

## More Resources

- **[Quick Start](../../QUICKSTART.md)** — Zero to governed agents in 10 minutes
- **[Architecture](../ARCHITECTURE.md)** — System design and security model
- **[OWASP Compliance](../OWASP-COMPLIANCE.md)** — ASI-01 through ASI-10 mapping
- **[Benchmarks](../../BENCHMARKS.md)** — Performance data
- **[Examples](../../examples/)** — One-file quickstarts for each framework
