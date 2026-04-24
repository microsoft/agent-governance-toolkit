# 📚 Tutorials

Step-by-step guides for every layer of the Agent Governance Toolkit — from your
first policy rule to production-grade observability. Each tutorial includes
runnable code examples, API reference tables, and cross-references to related
guides.

> **New here?** Try the [2-hour hands-on workshop](../workshop/README.md) first —
> it covers policy, trust, and audit with guided labs. Then work through the
> numbered tutorials for deeper dives.
>
> Already comfortable with the basics? Start with
> [Tutorial 01 — Policy Engine](01-policy-engine.md) and follow the numbered sequence.

---

## Getting Started

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------| 
| – | [Retrofit Governance onto an Existing Agent](retrofit-governance.md) | Add policy enforcement to any existing agent in 3 steps | `agent-os-kernel` |
| – | [Progressive Governance — Start Simple, Add Layers](progressive-governance.md) | 5-level progressive complexity model; pick the level that matches your risk | All |

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
| 31 | [Entra Agent ID Bridge](31-entra-agent-id-bridge.md) | Bridge DID identity with Microsoft Entra Agent ID, Conditional Access, sponsor accountability | `agentmesh-platform` |
| 32 | [E2E Encrypted Messaging](32-e2e-encrypted-messaging.md) | Signal protocol (X3DH + Double Ratchet), SecureChannel, trust-gated encryption | `agentmesh-platform` |

## Ecosystem

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------|
| 10 | [Plugin Marketplace](10-plugin-marketplace.md) | Plugin signing, verification, CLI, supply-chain security | `agentmesh-marketplace` |
| 13 | [Observability & Tracing](13-observability-and-tracing.md) | Causal traces, event bus, Prometheus, OpenTelemetry | `agentmesh-runtime` |
| 15 | [RL Training Governance](15-rl-training-governance.md) | GovernedRunner, PolicyReward, Gym-compatible environments | `agentmesh-lightning` |
| 18 | [Compliance Verification](18-compliance-verification.md) | Governance grading, regulatory frameworks, attestation | `agent-governance-toolkit` |

## Multi-Language Packages

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------|
| 19 | [.NET package](19-dotnet-sdk.md) | GovernanceKernel, policy, rings, saga, SLO, OpenTelemetry in C# | `Microsoft.AgentGovernance` |
| 42 | [C# MCP extension](42-csharp-mcp-extension.md) | Add governed tool execution, startup scanning, and response sanitization to MCP servers | `Microsoft.AgentGovernance.Extensions.ModelContextProtocol` |
| 20 | [TypeScript package](20-typescript-sdk.md) | Identity, trust, policy, audit in TypeScript/Node.js | `@microsoft/agentmesh-sdk` |
| 21 | [Rust crate](21-rust-sdk.md) | Policy, trust, audit, identity with `agentmesh` crate | `agentmesh` |
| 22 | [Go module](22-go-sdk.md) | Policy, trust, audit, identity with Go module | `agentmesh` |

## Delegation & Cost Control

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------|
| 23 | [Delegation Chains](23-delegation-chains.md) | Monotonic scope narrowing, multi-agent delegation, cascade revocation | `@microsoft/agentmesh-sdk` |
| 24 | [Cost & Token Budgets](24-cost-and-token-budgets.md) | Per-session token limits, context scheduling, budget signals | `agent-os-kernel` |

## Supply Chain Security

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------|
| 25 | [Security Hardening](25-security-hardening.md) | Gitleaks, Dependabot, CodeQL, fuzzing, Scorecard, branch protection | `agent-governance-toolkit` |
| 26 | [SBOM & Signing](26-sbom-and-signing.md) | SPDX/CycloneDX SBOMs, Ed25519 artifact signing, attestation | `agent-compliance` |
| 27 | [MCP Scan CLI](27-mcp-scan-cli.md) | MCP tool scanning, rug-pull detection, CI integration | `agent-os-kernel` |
| 33 | [Offline-Verifiable Decision Receipts](33-offline-verifiable-receipts.md) | Ed25519 + JCS receipts, hash-chained, externally verifiable per tool call | `protect-mcp` / `agent-governance-toolkit` |

---

## Discovery & Inventory

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------|
| 29 | [Agent Discovery](29-agent-discovery.md) | Shadow AI scanning, inventory dedup, reconciliation, risk scoring, CI/CD integration | `agent-discovery` |
| 30 | [Agent Lifecycle Management](30-agent-lifecycle.md) | Provisioning, approval workflows, credential rotation, orphan detection, decommissioning | `agentmesh-platform` |

## Enterprise Identity

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------|
| 31 | [Entra Agent ID Bridge](31-entra-agent-id-bridge.md) | Bridge AGT DIDs with Microsoft Entra Agent ID / Agent365, AKS workload identity, roles & responsibilities | `agentmesh-platform` |

## Advanced Governance (v3.2+)

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------|
| 35 | [Policy Composition](35-policy-composition.md) | `extends` for 3-tier governance hierarchies (CISO → platform → app), additive-only merge, diamond dedup | `agentmesh-platform` |
| 36 | [2-Line Governance with govern()](36-govern-quickstart.md) | The `govern()` wrapper — policy enforcement + audit in 2 lines of code | `agentmesh-platform` |
| 37 | [Multi-Stage Policy Pipeline](37-multi-stage-pipeline.md) | 4-stage lifecycle: pre_input → pre_tool → post_tool → pre_output | `agentmesh-platform` |
| 38 | [Approval Workflows](38-approval-workflows.md) | Human-in-the-loop gates with Callback, Webhook, and Console handlers | `agentmesh-platform` |
| 39 | [DLP with Attribute Ratchets](39-dlp-attribute-ratchets.md) | Monotonic session state — sensitivity only goes up, never resets | `agentmesh-platform` |
| 40 | [OTel Observability](40-otel-observability.md) | OpenTelemetry spans + metrics for policy, approval, and trust operations | `agentmesh-platform` |
| 41 | [Advisory Defense-in-Depth](41-advisory-defense-in-depth.md) | Pattern, ML, and HTTP classifiers as non-deterministic defense layer | `agentmesh-platform` |

## Extending the Toolkit

| # | Tutorial | What You'll Learn | Package |
|---|----------|-------------------|---------|
| 28 | [Building Custom Integrations](28-build-custom-integration.md) | Trust integrations, kernel adapters, publishing your own governance package | `agent-os-kernel` / standalone |

## Policy-as-Code Deep Dive

A self-contained sub-series progressing from basic allow/deny rules to production-grade policy management. Each chapter has a matching Python script in [`policy-as-code/examples/`](policy-as-code/examples/).

| Chapter | Topic | What You'll Learn |
|---------|-------|-------------------|
| [01 — Your First Policy](policy-as-code/01-your-first-policy.md) | Allow/deny basics | Write a YAML policy and evaluate it with Python |
| [02 — Capability Scoping](policy-as-code/02-capability-scoping.md) | Restricting tool access by agent role | Give different agents different permissions |
| [03 — Rate Limiting](policy-as-code/03-rate-limiting.md) | Preventing runaway agents | Set limits on how many actions an agent can take |
| [04 — Conditional Policies](policy-as-code/04-conditional-policies.md) | Policy composition and conflict resolution | Layer base + environment policies with conflict strategies |
| [05 — Approval Workflows](policy-as-code/05-approval-workflows.md) | Human-in-the-loop for sensitive actions | Route dangerous actions to a human before execution |
| [06 — Policy Testing](policy-as-code/06-policy-testing.md) | Systematic validation with test matrices | Test every role + action + environment combination |
| [07 — Policy Versioning](policy-as-code/07-policy-versioning.md) | Safe rollout of policy changes | Compare v1 vs v2 behavior, catch regressions before deploying |
| [MCP Governance](policy-as-code/mcp-governance.md) | Supplemental | Governing MCP tool access with the proxy, trust-gated components, OWASP-aligned rules |

> See the [Policy-as-Code README](policy-as-code/README.md) for installation and running instructions.

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
6. [25 — Security Hardening](25-security-hardening.md) → CI/CD security gates
7. [27 — MCP Scan CLI](27-mcp-scan-cli.md) → scan tool definitions for threats

### 🏢 "I need enterprise compliance"

1. [08 — OPA/Rego & Cedar](08-opa-rego-cedar-policies.md) → bring existing policies
2. [04 — Audit & Compliance](04-audit-and-compliance.md) → tamper-proof audit trails
3. [18 — Compliance Verification](18-compliance-verification.md) → regulatory grading
4. [13 — Observability & Tracing](13-observability-and-tracing.md) → distributed tracing
5. [26 — SBOM & Signing](26-sbom-and-signing.md) → supply chain security
6. [33 — Offline-Verifiable Decision Receipts](33-offline-verifiable-receipts.md) → external accountability for each decision
7. [31 — Entra Agent ID Bridge](31-entra-agent-id-bridge.md) → enterprise identity with Entra / Agent365

### 🛡️ "I need enterprise-grade governance" (v3.2+ features)

1. [36 — govern() Quickstart](36-govern-quickstart.md) → 2-line integration
2. [35 — Policy Composition](35-policy-composition.md) → CISO → platform → app layers
3. [37 — Multi-Stage Pipeline](37-multi-stage-pipeline.md) → 4-stage lifecycle checks
4. [38 — Approval Workflows](38-approval-workflows.md) → human-in-the-loop for regulated actions
5. [39 — DLP with Ratchets](39-dlp-attribute-ratchets.md) → sensitivity that only goes up
6. [40 — OTel Observability](40-otel-observability.md) → production monitoring
7. [41 — Advisory Layer](41-advisory-defense-in-depth.md) → ML-based defense-in-depth

### 🤖 "I'm building multi-agent systems"

1. [02 — Trust & Identity](02-trust-and-identity.md) → agent credentials
2. [32 — E2E Encrypted Messaging](32-e2e-encrypted-messaging.md) → encrypted agent channels
3. [23 — Delegation Chains](23-delegation-chains.md) → scope narrowing and delegation
4. [16 — Protocol Bridges](16-protocol-bridges.md) → cross-protocol communication
5. [11 — Saga Orchestration](11-saga-orchestration.md) → multi-step workflows
6. [12 — Liability & Attribution](12-liability-and-attribution.md) → who's responsible
7. [17 — Advanced Trust & Behavior](17-advanced-trust-and-behavior.md) → dynamic trust
8. [24 — Cost & Token Budgets](24-cost-and-token-budgets.md) → control agent spend

### 🔎 "I need to find all agents in my org"

1. [29 — Agent Discovery](29-agent-discovery.md) → scan processes, configs, and repos
2. [02 — Trust & Identity](02-trust-and-identity.md) → register discovered agents
3. [01 — Policy Engine](01-policy-engine.md) → govern the agents you find
4. [27 — MCP Scan CLI](27-mcp-scan-cli.md) → secure discovered MCP servers

---

## Prerequisites

- **Python 3.10+** for Python tutorials (01–18, 24–27, 29–31)
- **.NET 8.0+** for the .NET tutorials (19, 42)
- **Node.js 18+** for the TypeScript tutorials (20, 23)
- **Rust 1.75+** for the Rust tutorial (21)
- **Go 1.21+** for the Go tutorial (22)

Install the full toolkit:

```bash
pip install agent-governance-toolkit[full]    # Python
dotnet add package Microsoft.AgentGovernance  # .NET
npm install @microsoft/agentmesh-sdk                    # TypeScript
cargo add agentmesh                           # Rust
go get github.com/microsoft/agent-governance-toolkit/agent-governance-golang  # Go
```

## More Resources

- **[Quick Start](../../QUICKSTART.md)** — Zero to governed agents in 10 minutes
- **[Architecture](../ARCHITECTURE.md)** — System design and security model
- **[OWASP Compliance](../OWASP-COMPLIANCE.md)** — ASI-01 through ASI-10 mapping
- **[Benchmarks](../../BENCHMARKS.md)** — Performance data
- **[Examples](../../examples/)** — One-file quickstarts for each framework
