# Tutorials

Step-by-step guides organized by what you're trying to accomplish.

!!! tip "Where to start?"
    **New here?** Start with [2-Line Quickstart](36-govern-quickstart.md) to see AGT in action, then follow [Policy Engine Basics](01-policy-engine.md) for a full walkthrough.

---

## Learning Paths

Pick a path based on your role. Each path is a curated sequence of tutorials, not a flat list.

### :material-rocket-launch: **Path 1: First governed agent** (30 min)

For developers adding governance to their first agent.

1. [2-Line Quickstart](36-govern-quickstart.md) — `govern()` in 2 lines
2. [Policy Engine Basics](01-policy-engine.md) — write your first policy
3. [Framework Integrations](03-framework-integrations.md) — connect to LangChain, CrewAI, OpenAI, etc.
4. [Govern an AI Agent](04-audit-and-compliance.md) — full audit trail

### :material-shield-lock: **Path 2: Secure an agent fleet** (60 min)

For platform teams deploying agents in production.

1. [Trust & Identity](02-trust-and-identity.md) — agent identity with SPIFFE
2. [MCP Security Gateway](07-mcp-security-gateway.md) — govern MCP tool servers
3. [Execution Sandboxing](06-execution-sandboxing.md) — privilege rings
4. [Prompt Injection Detection](09-prompt-injection-detection.md) — detect and block attacks
5. [Security Hardening](25-security-hardening.md) — production best practices
6. [Multi-Agent Fleet Policies](49-multi-agent-policies.md) — collective enforcement

### :material-clipboard-check: **Path 3: Compliance and audit** (45 min)

For teams that need to prove what happened to auditors or regulators.

1. [OPA / Rego / Cedar](08-opa-rego-cedar-policies.md) — policy engine options
2. [Delegation Chains](23-delegation-chains.md) — who authorized what
3. [Compliance Verification](18-compliance-verification.md) — OWASP, NIST mapping
4. [SBOM & Signing](26-sbom-and-signing.md) — artifact integrity
5. [Decision BOM](50-decision-bom.md) — audit artifacts

### :material-chart-line: **Path 4: SRE for agents** (45 min)

For SRE teams operating agents at scale.

1. [Agent Reliability](05-agent-reliability.md) — SLOs and error budgets
2. [Kill Switch & Rate Limiting](14-kill-switch-and-rate-limiting.md) — emergency controls
3. [Cost Governance](51-cost-governance.md) — budget enforcement
4. [Chaos Testing](52-chaos-testing-agents.md) — fault injection
5. [Observability & Tracing](13-observability-and-tracing.md) — distributed tracing
6. [OpenTelemetry Integration](40-otel-observability.md) — OTel for governance events

---

## All Tutorials by Category

---

## Getting Started

The essentials to get your first governed agent running in minutes.

| Tutorial | What you'll accomplish |
|----------|----------------------|
| [2-Line Quickstart](36-govern-quickstart.md) | Add governance to any agent in 2 lines of code |
| [Policy Engine Basics](01-policy-engine.md) | Write and evaluate your first policy rules |
| [Framework Integrations](03-framework-integrations.md) | Connect AGT to LangChain, CrewAI, OpenAI, etc. |
| [Progressive Governance](progressive-governance.md) | Start simple, add layers incrementally |

---

## End-to-End Scenarios

Complete workflows from a customer perspective: pick the scenario closest to your use case.

| Scenario | Description |
|----------|-------------|
| [Govern an AI Agent (Python)](04-audit-and-compliance.md) | Full audit trail with compliance mapping for a Python agent |
| [Govern MCP Tool Servers](07-mcp-security-gateway.md) | Per-tool policy enforcement for MCP servers |
| [.NET MAF Integration](34-maf-integration.md) | Govern agents built with Microsoft Agent Framework |
| [.NET MAF Hook](43-dotnet-maf-hook-integration.md) | Add governance hooks to .NET MAF agents |
| [Multi-Agent Fleet Policies](49-multi-agent-policies.md) | Collective policy enforcement across agent fleets |
| [Multi-Stage Pipeline](37-multi-stage-pipeline.md) | Chained policy evaluation for complex workflows |
| [Retrofit Existing Agents](retrofit-governance.md) | Add governance to agents already in production |
| [Shift-Left CI/CD Gates](45-shift-left-governance.md) | Pre-commit hooks, CI gates, build-time enforcement |
| [A2A Conversation Policy](44-a2a-conversation-policy.md) | Govern agent-to-agent conversations |
| [Copilot CLI Governance](46-copilot-cli-governance.md) | Install governance policies for GitHub Copilot CLI |

---

## Security

Hardening, threat mitigation, and data protection.

| Tutorial | What you'll learn |
|----------|-------------------|
| [Execution Sandboxing](06-execution-sandboxing.md) | Privilege rings, runtime isolation |
| [Prompt Injection Detection](09-prompt-injection-detection.md) | Detect and block prompt injection attacks |
| [Security Hardening](25-security-hardening.md) | Production security best practices |
| [DLP & Attribute Ratchets](39-dlp-attribute-ratchets.md) | Data loss prevention, sensitivity escalation |
| [Defense-in-Depth](41-advisory-defense-in-depth.md) | Advisory classifiers, layered security |
| [SBOM & Signing](26-sbom-and-signing.md) | Software bill of materials, artifact signing |
| [MCP Scan CLI](27-mcp-scan-cli.md) | Static analysis for MCP server security |
| [E2E Encrypted Messaging](32-e2e-encrypted-messaging.md) | End-to-end encrypted agent communication |
| [Red-Team Testing](47-red-team-testing.md) | Adversarial security testing |

---

## Policy & Authorization

Writing, composing, and enforcing governance policies.

| Tutorial | What you'll learn |
|----------|-------------------|
| [OPA / Rego / Cedar](08-opa-rego-cedar-policies.md) | Policy engines comparison and integration |
| [Policy Composition](35-policy-composition.md) | Enterprise governance layers, policy merging |
| [Approval Workflows](38-approval-workflows.md) | Human-in-the-loop approval gates |
| [Intent-Based Authorization](48-intent-based-authorization.md) | Authorize actions by declared intent |
| [Delegation Chains](23-delegation-chains.md) | Agent-to-agent authorization |
| [Cost & Token Budgets](24-cost-and-token-budgets.md) | Resource governance and budget enforcement |
| [Cost Governance](51-cost-governance.md) | Budget enforcement, cost attribution |

### Policy-as-Code Series

A focused series on writing, testing, and versioning governance policies.

| # | Tutorial | What you'll learn |
|---|----------|-------------------|
| 1 | [Your First Policy](policy-as-code/01-your-first-policy.md) | Write and evaluate a basic policy |
| 2 | [Capability Scoping](policy-as-code/02-capability-scoping.md) | Restrict agent tool access |
| 3 | [Rate Limiting](policy-as-code/03-rate-limiting.md) | Token and request budgets |
| 4 | [Conditional Policies](policy-as-code/04-conditional-policies.md) | Context-aware policy rules |
| 5 | [Approval Workflows](policy-as-code/05-approval-workflows.md) | Human approval gates |
| 6 | [Policy Testing](policy-as-code/06-policy-testing.md) | Unit testing policies |
| 7 | [Policy Versioning](policy-as-code/07-policy-versioning.md) | Version control for policies |
| - | [MCP Governance](policy-as-code/mcp-governance.md) | MCP-specific policy patterns |

---

## Observability & Operations

Monitoring, alerting, and operational management of governed agents.

| Tutorial | What you'll learn |
|----------|-------------------|
| [Observability & Tracing](13-observability-and-tracing.md) | Distributed tracing for agent systems |
| [OpenTelemetry Integration](40-otel-observability.md) | OTel integration for governance events |
| [Kill Switch & Rate Limiting](14-kill-switch-and-rate-limiting.md) | Emergency controls, throttling |
| [Agent Discovery](29-agent-discovery.md) | Finding shadow AI in your organization |
| [Agent Lifecycle](30-agent-lifecycle.md) | Birth-to-retirement management |
| [Chaos Testing](52-chaos-testing-agents.md) | Chaos engineering for agent reliability |
| [Agent Reliability](05-agent-reliability.md) | SLOs, monitoring, graceful degradation |

---

## Advanced Topics

Deep dives into specialized governance patterns.

| Tutorial | What you'll learn |
|----------|-------------------|
| [Trust & Identity Deep Dive](02-trust-and-identity.md) | Agent identity, trust tiers, verification |
| [Advanced Trust & Behavior](17-advanced-trust-and-behavior.md) | Behavioral analysis, reputation systems |
| [Compliance Verification](18-compliance-verification.md) | Automated compliance checks |
| [Saga Orchestration](11-saga-orchestration.md) | Multi-step workflows with rollback |
| [Liability & Attribution](12-liability-and-attribution.md) | Decision tracing, blame assignment |
| [Protocol Bridges](16-protocol-bridges.md) | Cross-protocol agent communication |
| [Plugin Marketplace](10-plugin-marketplace.md) | Marketplace governance, trust scoring |
| [RL Training Governance](15-rl-training-governance.md) | Governing reinforcement learning agents |
| [Decision BOM](50-decision-bom.md) | Decision bill of materials, audit artifacts |
| [Offline Verifiable Receipts](33-offline-verifiable-receipts.md) | Offline-verifiable decision receipts |
| [Entra Agent ID Bridge](31-entra-agent-id-bridge.md) | Bridging AGT identity with Microsoft Entra |
| [Contributor Governance](53-contributor-governance.md) | Contributor reputation, spam detection |

---

## Language & Platform Guides

SDK-specific guides for each supported language.

| Tutorial | Language |
|----------|----------|
| [.NET SDK](19-dotnet-sdk.md) | C# / .NET |
| [C# MCP Extension](42-csharp-mcp-extension.md) | C# (MCP servers) |
| [TypeScript SDK](20-typescript-sdk.md) | TypeScript / Node.js |
| [Rust Crate](21-rust-sdk.md) | Rust |
| [Go Module](22-go-sdk.md) | Go |
| [Build Custom Integration](28-build-custom-integration.md) | Any language |
