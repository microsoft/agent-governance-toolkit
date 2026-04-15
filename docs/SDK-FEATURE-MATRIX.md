# SDK Feature Matrix

> **Last updated:** April 2026 · AGT v3.1.0

The Agent Governance Toolkit ships SDKs in **5 languages**. Python is the primary
implementation; other SDKs provide the core governance primitives needed to build
governed agents in each ecosystem.

## Quick Comparison

| Capability | Python | TypeScript | .NET | Rust | Go |
|---|:---:|:---:|:---:|:---:|:---:|
| **Policy Engine** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Identity & Auth** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Trust Scoring** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Audit Logging** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **MCP Security** | ✅ | ✅ | — | ✅ | ✅ |
| **Execution Rings** | ✅ | — | ✅ | ✅ | ✅ |
| **SRE / SLOs** | ✅ | — | ✅ | — | — |
| **Kill Switch** | ✅ | — | ✅ | — | — |
| **Lifecycle Management** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Framework Integrations** | ✅ | — | ✅ | — | — |
| **Unified CLI** | ✅ | — | — | — | — |
| **Governance Dashboard** | ✅ | — | — | — | — |
| **Shadow AI Discovery** | ✅ | — | — | — | — |
| **Prompt Defense Evaluator** | ✅ | — | — | — | — |

**Legend:** ✅ Implemented · ◑ Partial · — Not yet available

---

## Detailed Breakdown

### Core Governance (all 5 SDKs)

Every SDK implements the four foundational governance primitives. These are sufficient
to build governed agents in any language:

| Primitive | What It Does | Python | TS | .NET | Rust | Go |
|---|---|---|---|---|---|---|
| Policy evaluation | Evaluate actions against rules before execution | `PolicyEvaluator` | `PolicyEngine` | `PolicyEngine` | `PolicyEngine` | `PolicyEngine` |
| Agent identity | Cryptographic credentials (Ed25519) | `AgentIdentity` | `AgentIdentity` | `AgentIdentity` | `Identity` | `Identity` |
| Trust scoring | 0–1000 score based on behavior | `TrustEngine` | `TrustEngine` | `TrustStore` | `TrustEngine` | `TrustEngine` |
| Audit logging | Append-only action log | `AuditLogger` | `AuditLogger` | `AuditLogger` | `AuditLogger` | `AuditLogger` |

### Python-Only Capabilities

These capabilities are only available in Python today. They represent the full
governance stack for enterprise deployments:

| Capability | Package | Description |
|---|---|---|
| **Execution Rings** | `agent-hypervisor` | 4-tier privilege model (Ring 0–3) with resource limits |
| **Saga Orchestration** | `agent-hypervisor` | Multi-step workflows with compensating actions |
| **Kill Switch** | `agent-hypervisor` | Instant agent termination for non-compliance |
| **SRE / SLOs** | `agent-sre` | Service level objectives, error budgets, chaos testing |
| **Circuit Breakers** | `agent-sre` | Automatic throttling when error thresholds exceeded |
| **Replay Debugging** | `agent-sre` | Deterministic replay of agent sessions |
| **MCP Security Scanner** | `agent-os` | Detect tool poisoning, typosquatting, hidden instructions |
| **Shadow AI Discovery** | `agent-discovery` | Find unregistered agents in processes, configs, repos |
| **Lifecycle Management** | `agentmesh` | Provisioning → rotation → orphan detection → decommission |
| **Governance Dashboard** | `demo/` | Real-time fleet visibility (Streamlit) |
| **Unified CLI (`agt`)** | `agent-compliance` | `agt verify`, `agt doctor`, `agt lint-policy` |
| **Prompt Defense** | `agent-compliance` | 12-vector prompt injection audit |
| **OWASP Verification** | `agent-compliance` | ASI 2026 compliance attestation |
| **OPA/Rego Policies** | `agent-os` | Evaluate policies via Open Policy Agent |
| **Cedar Policies** | `agent-os` | Evaluate policies via Cedar (Amazon Verified Permissions) |
| **20+ Framework Adapters** | `agentmesh-integrations` | LangChain, CrewAI, AutoGen, OpenAI Agents, Google ADK, etc. |

### TypeScript SDK

**Package:** [`@microsoft/agentmesh-sdk`](https://www.npmjs.com/package/@microsoft/agentmesh-sdk) ·
**Source:** [`packages/agent-mesh/sdks/typescript/`](../packages/agent-mesh/sdks/typescript/)

| Module | Features |
|--------|----------|
| `PolicyEngine` | Rule evaluation, allow/deny decisions, effect-based policies |
| `AgentIdentity` | Ed25519 key generation, DID creation, credential signing/verification |
| `TrustEngine` | Trust score tracking, tier classification, decay |
| `AuditLogger` | Structured audit events, JSON export |
| `McpSecurityScanner` | Tool poisoning, typosquatting, hidden instruction, rug pull detection |
| `LifecycleManager` | 8-state lifecycle with validated transitions and event logging |
| `AgentMeshClient` | High-level client combining all primitives |

**Roadmap:** Framework middleware (Express, Fastify), execution rings.

### .NET SDK

**Package:** [`Microsoft.AgentGovernance`](https://www.nuget.org/packages/Microsoft.AgentGovernance) ·
**Source:** [`packages/agent-governance-dotnet/`](../packages/agent-governance-dotnet/)

| Namespace | Features |
|-----------|----------|
| `Policy` | `PolicyEngine` with YAML policy loading, rule evaluation |
| `Trust` | `AgentIdentity`, `IdentityRegistry`, `FileTrustStore` |
| `Audit` | `AuditLogger`, `AuditEmitter` with structured events |
| `Hypervisor` | `ExecutionRings` (4-tier), `SagaOrchestrator`, `KillSwitch` |
| `Lifecycle` | `LifecycleManager` with 8-state machine and validated transitions |
| `Sre` | `SloEngine` with objectives and error budget tracking |
| `Integration` | `GovernanceMiddleware` for ASP.NET / Agent Framework |
| `RateLimiting` | Token bucket rate limiter |
| `Telemetry` | OpenTelemetry integration |

**Roadmap:** MCP security, full lifecycle persistence.

### Rust SDK

**Crate:** [`agentmesh`](https://crates.io/crates/agentmesh) +
[`agentmesh-mcp`](https://crates.io/crates/agentmesh-mcp) ·
**Source:** [`packages/agent-mesh/sdks/rust/`](../packages/agent-mesh/sdks/rust/)

| Module | Features |
|--------|----------|
| `policy` | Rule-based policy evaluation with allow/deny effects |
| `identity` | Ed25519 key generation, DID creation, credential signing |
| `trust` | Trust scoring, tier classification, behavioral tracking |
| `audit` | Append-only audit log with structured events |
| `mcp` | MCP tool definition scanning, poisoning detection |
| `rings` | 4-tier execution privilege rings with configurable permissions |
| `lifecycle` | 8-state lifecycle manager with validated transitions |

The standalone `agentmesh-mcp` crate provides MCP-specific security primitives
(gateway, rate limiting, redaction, session management) without pulling in the
full governance stack.

**Roadmap:** Async runtime support, framework integrations (Rig, Swarm-RS), SRE primitives.

### Go SDK

**Module:** `github.com/microsoft/agent-governance-toolkit/sdks/go` ·
**Source:** [`packages/agent-mesh/sdks/go/`](../packages/agent-mesh/sdks/go/)

| File | Features |
|------|----------|
| `policy.go` | Rule-based policy evaluation, conflict resolution |
| `identity.go` | Ed25519 identity generation, DID creation |
| `trust.go` | Trust scoring, tier classification, behavioral events |
| `audit.go` | Structured audit logging |
| `mcp.go` | MCP security scanning — tool poisoning, typosquatting, hidden chars, rug pull |
| `rings.go` | 4-tier execution privilege rings with default-deny access control |
| `lifecycle.go` | 8-state lifecycle manager with validated transitions |
| `client.go` | High-level client combining all primitives |

**Roadmap:** Framework integrations, gRPC transport, SRE primitives.

---

## Policy Backend Support

| Backend | Python | TS | .NET | Rust | Go |
|---------|:---:|:---:|:---:|:---:|:---:|
| **YAML rules** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **OPA / Rego** | ✅ | — | — | — | — |
| **Cedar** | ✅ | — | — | — | — |
| **Programmatic** | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## Install

| Language | Command |
|----------|---------|
| Python | `pip install agent-governance-toolkit[full]` |
| TypeScript | `npm install @microsoft/agentmesh-sdk` |
| .NET | `dotnet add package Microsoft.AgentGovernance` |
| Rust | `cargo add agentmesh` |
| Rust (MCP only) | `cargo add agentmesh-mcp` |
| Go | `go get github.com/microsoft/agent-governance-toolkit/sdks/go` |

---

## Contributing

Want to add a feature to a non-Python SDK? We welcome contributions!
See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines. The Python
implementation serves as the reference — match its behavior and test patterns.
