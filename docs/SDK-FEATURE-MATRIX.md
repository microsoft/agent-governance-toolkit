# Language Package Feature Matrix

> **Last updated:** April 2026 · AGT v3.1.0

The Agent Governance Toolkit ships language packages in **5 languages**. Python is the primary
implementation; the other language packages provide the core governance primitives needed to build
governed agents in each ecosystem.

## Quick Comparison

| Capability | Python | TypeScript | .NET | Rust | Go |
|---|:---:|:---:|:---:|:---:|:---:|
| **Policy Engine** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Identity & Auth** | ✅ | ✅ | ◑ | ✅ | ✅ |
| **Trust Scoring** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Audit Logging** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **MCP Security** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Execution Rings** | ✅ | — | ✅ | ✅ | ✅ |
| **SRE / SLOs** | ✅ | — | ✅ | — | ✅ |
| **Kill Switch** | ✅ | — | ✅ | — | — |
| **Lifecycle Management** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Framework Integrations** | ✅ | — | ✅ | — | ✅ |
| **Unified CLI** | ✅ | — | — | — | — |
| **Governance Dashboard** | ✅ | — | — | — | — |
| **Shadow AI Discovery** | ✅ | — | — | — | ✅ |
| **Prompt Defense Evaluator** | ✅ | — | — | — | ✅ |

**Legend:** ✅ Implemented · ◑ Partial · — Not yet available

---

## Detailed Breakdown

### Core Governance (all 5 language packages)

Every language package implements the four foundational governance primitives. These are sufficient
to build governed agents in any language:

| Primitive | What It Does | Python | TS | .NET | Rust | Go |
|---|---|---|---|---|---|---|
| Policy evaluation | Evaluate actions against rules before execution | `PolicyEvaluator` | `PolicyEngine` | `PolicyEngine` | `PolicyEngine` | `PolicyEngine` |
| Agent identity | Cryptographic credentials | `AgentIdentity` | `AgentIdentity` | `AgentIdentity` (.NET 8 compatibility signing, delegation, JWK/JWKS, DID docs) | `Identity` | `AgentIdentity` |
| Trust scoring | 0–1000 score based on behavior | `TrustEngine` | `TrustEngine` | `TrustStore` | `TrustEngine` | `TrustManager` |
| Audit logging | Append-only action log | `AuditLogger` | `AuditLogger` | `AuditLogger` | `AuditLogger` | `AuditLogger` |

### Python-Only Capabilities

These capabilities are only available in Python today. They represent the full
governance stack for enterprise deployments:

| Capability | Package | Description |
|---|---|---|
| **Replay Debugging** | `agent-sre` | Deterministic replay of agent sessions |
| **Governance Dashboard** | `demo/` | Real-time fleet visibility (Streamlit) |
| **Unified CLI (`agt`)** | `agent-compliance` | `agt verify`, `agt doctor`, `agt lint-policy` |
| **OWASP Verification** | `agent-compliance` | ASI 2026 compliance attestation |
| **20+ Framework Adapters** | `agentmesh-integrations` | LangChain, CrewAI, AutoGen, OpenAI Agents, Google ADK, etc. |

### TypeScript package

**Package:** [`@microsoft/agentmesh-sdk`](https://www.npmjs.com/package/@microsoft/agentmesh-sdk) ·
**Source:** [`agent-governance-typescript/`](../agent-governance-typescript/)

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

### .NET package

**Package:** [`Microsoft.AgentGovernance`](https://www.nuget.org/packages/Microsoft.AgentGovernance) ·
**Source:** [`agent-governance-dotnet/`](../agent-governance-dotnet/)

| Namespace | Features |
|-----------|----------|
| `Policy` | `PolicyEngine` with YAML/JSON policy loading, organization scope, and richer decision metadata |
| `Trust` | `AgentIdentity`, `IdentityRegistry`, `FileTrustStore`, delegation helpers, JWK/JWKS, DID document export |
| `Audit` | `AuditLogger`, `AuditEmitter` with structured events |
| `Hypervisor` | `ExecutionRings` (4-tier), `SagaOrchestrator`, `KillSwitch` |
| `Lifecycle` | `LifecycleManager` with 8-state machine and validated transitions |
| `Sre` | `SloEngine` with objectives and error budget tracking |
| `Integration` | `GovernanceMiddleware` for ASP.NET / Agent Framework |
| `RateLimiting` | Token bucket rate limiter |
| `Telemetry` | OpenTelemetry integration |
| `Mcp` | `McpSecurityScanner` (poisoning, typosquatting, hidden instructions, rug pull, schema abuse, cross-server), `McpResponseSanitizer`, `McpCredentialRedactor`, `McpGateway` |

**Roadmap:** Native asymmetric Ed25519 signing once the target runtime supports it broadly, plus full lifecycle persistence.

### Rust crate

**Crate:** [`agentmesh`](https://crates.io/crates/agentmesh) +
[`agentmesh-mcp`](https://crates.io/crates/agentmesh-mcp) ·
**Source:** [`agent-governance-rust/`](../agent-governance-rust/)

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

### Go module

**Module:** `github.com/microsoft/agent-governance-toolkit/agent-governance-golang` ·
**Source:** [`agent-governance-golang/`](../agent-governance-golang/)

| Python parity area | Go status |
|---|---|
| Core governance primitives | ✅ Parity |
| MCP security | ✅ Parity |
| Execution rings | ✅ Parity |
| Lifecycle management | ✅ Parity |
| SRE / SLOs | ✅ Parity |
| Framework integrations | ✅ Parity |
| Shadow AI discovery | ✅ Parity |
| Prompt defense | ✅ Parity |
| OPA / Rego / Cedar policy backends | ✅ Parity |
| Unified CLI and governance dashboard | — Python only today |

| File | Features |
|------|----------|
| `policy.go` | Rule-based policy evaluation, wildcard/conditional matching, YAML loading, rate limiting, approval gates |
| `identity.go` | Ed25519 identity generation, DID creation, signing/verification, JSON export/import |
| `trust.go` | Trust scoring, tier classification, peer verification, optional disk persistence |
| `audit.go` | Hash-chained audit logging, filtering, JSON export, retention cap |
| `mcp.go` | MCP security scanning — tool poisoning, typosquatting, hidden chars/homoglyphs, rug pull |
| `rings.go` | 4-tier execution privilege rings with default-deny access control |
| `lifecycle.go` | 8-state lifecycle manager with validated transitions and transition history |
| `client.go` | High-level client combining identity, trust, policy, and audit |
| `policy_backends.go` | OPA/Rego remote + CLI + built-in evaluation, Cedar CLI + built-in evaluation |
| `slo.go` | SLO objectives, event recording, latency/availability evaluation, error budget tracking |
| `middleware.go` | Composable governance middleware stack, `net/http` adapter, capability guards, prompt defense, audit, and optional SLO tracking |
| `discovery.go` | Structured shadow discovery models plus text, process, config-path, current-host, and GitHub repository scanners |
| `promptdefense.go` | Prompt injection, prompt exfiltration, credential exfiltration, and approval-bypass detection |
| `metrics.go` | Lightweight governance metrics recorder stubs |

**Roadmap:** Additional transport adapters beyond `net/http`, plus deeper discovery heuristics and integrations.

---

## Policy Backend Support

| Backend | Python | TS | .NET | Rust | Go |
|---------|:---:|:---:|:---:|:---:|:---:|
| **YAML rules** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **OPA / Rego** | ✅ | — | — | — | ✅ |
| **Cedar** | ✅ | — | — | — | ✅ |
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
| Go | `go get github.com/microsoft/agent-governance-toolkit/agent-governance-golang` |

---

## Contributing

Want to add a feature to a non-Python SDK? We welcome contributions!
See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines. The Python
implementation serves as the reference — match its behavior and test patterns.
