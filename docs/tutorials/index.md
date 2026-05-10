# Tutorials

50+ step-by-step guides covering every aspect of AI agent governance.

> **New here?** Start with [Tutorial 01 -- Policy Engine](01-policy-engine.md), then work through the Foundations section. For a quick taste, try [Tutorial 36 -- 2-Line Governance](36-govern-quickstart.md).

## Foundations

| #  | Tutorial  | What you'll learn   |
|----|-----------|---------------------|
| 01 | [Policy Engine](01-policy-engine.md) | Core policy evaluation, rule authoring |
| 02 | [Trust & Identity](02-trust-and-identity.md) | Agent identity, trust tiers, verification |
| 03 | [Framework Integrations](03-framework-integrations.md) | Connect AGT to LangChain, CrewAI, OpenAI, etc. |
| 04 | [Audit & Compliance](04-audit-and-compliance.md) | Logging, evidence collection, compliance mapping |
| 05 | [Agent Reliability](05-agent-reliability.md) | SLOs, monitoring, graceful degradation |
| 36 | [2-Line Governance Quickstart](36-govern-quickstart.md) | Fastest path to governed agents |

## Security

| #  | Tutorial   | What you'll learn   |
|----|------------|---------------------|
| 06 | [Execution Sandboxing](06-execution-sandboxing.md) | Privilege rings, runtime isolation |
| 07 | [MCP Security Gateway](07-mcp-security-gateway.md) | Per-tool policy enforcement for MCP servers |
| 08 | [OPA / Rego / Cedar Policies](08-opa-rego-cedar-policies.md) | Policy engines comparison and integration |
| 09 | [Prompt Injection Detection](09-prompt-injection-detection.md) | Detecting and preventing prompt injection |
| 25 | [Security Hardening](25-security-hardening.md) | Production security best practices |
| 26 | [SBOM & Signing](26-sbom-and-signing.md) | Software bill of materials, artifact signing |
| 27 | [MCP Scan CLI](27-mcp-scan-cli.md) | Static analysis for MCP server security |
| 39 | [DLP with Attribute Ratchets](39-dlp-attribute-ratchets.md) | Data loss prevention, sensitivity escalation |
| 41 | [Defense-in-Depth](41-advisory-defense-in-depth.md) | Advisory classifiers, layered security |
| 45 | [Shift-Left Governance](45-shift-left-governance.md) | Pre-commit hooks, CI gates, build-time enforcement |
| 46 | [Contributor Governance](46-contributor-governance.md) | Contributor reputation, spam detection, cross-project scanning |
| 47 | [Red-Team Testing](47-red-team-testing.md) | Adversarial security testing with `agt red-team` |

## Advanced Patterns

| #  | Tutorial     | What you'll learn    |
|----|--------------|----------------------|
| 10 | [Plugin Marketplace](10-plugin-marketplace.md) | Marketplace governance, trust scoring |
| 11 | [Saga Orchestration](11-saga-orchestration.md) | Multi-step agent workflows with rollback |
| 12 | [Liability & Attribution](12-liability-and-attribution.md) | Decision tracing, blame assignment |
| 13 | [Observability & Tracing](13-observability-and-tracing.md) | Distributed tracing for agent systems |
| 14 | [Kill Switch & Rate Limiting](14-kill-switch-and-rate-limiting.md) | Emergency controls, throttling |
| 15 | [RL Training Governance](15-rl-training-governance.md) | Governing reinforcement learning agents |
| 16 | [Protocol Bridges](16-protocol-bridges.md)     | Cross-protocol agent communication |
| 17 | [Advanced Trust](17-advanced-trust-and-behavior.md) | Behavioral analysis, reputation systems |
| 18 | [Compliance Verification](18-compliance-verification.md) | Automated compliance checks |
| 23 | [Delegation Chains](23-delegation-chains.md)   | Agent-to-agent authorization |
| 24 | [Cost & Token Budgets](24-cost-and-token-budgets.md) | Resource governance |
| 35 | [Policy Composition](35-policy-composition.md) | Enterprise governance layers, policy merging |
| 37 | [Multi-Stage Pipeline](37-multi-stage-pipeline.md) | Chained policy evaluation pipelines |
| 38 | [Approval Workflows](38-approval-workflows.md) | Human-in-the-loop approval gates |
| 40 | [OpenTelemetry Observability](40-otel-observability.md) | OTel integration for governance events |
| 44 | [A2A Conversation Policy](44-a2a-conversation-policy.md) | Agent-to-agent conversation governance |
| 48 | [Intent-Based Authorization](48-intent-based-authorization.md) | Authorize actions by declared intent |
| 49 | [Multi-Agent Policies](49-multi-agent-policies.md) | Collective policy enforcement across agent fleets |
| 50 | [Decision BOM](50-decision-bom.md) | Decision bill of materials, audit artifacts |
| 51 | [Cost Governance](51-cost-governance.md) | Budget enforcement, cost attribution |

## Language Package Guides

| #  | Tutorial | What you'll learn |
|----|----------|-------------------|
| 19 | [.NET package](19-dotnet-sdk.md) | Agent governance in C# / .NET |
| 42 | [C# MCP extension](42-csharp-mcp-extension.md) | Govern MCP servers built with the official C# SDK |
| 43 | [.NET MAF Hook](43-dotnet-maf-hook-integration.md) | Integrate AGT with Microsoft Agent Framework in .NET |
| 20 | [TypeScript package](20-typescript-sdk.md) | Agent governance in TypeScript |
| 21 | [Rust crate](21-rust-sdk.md) | Agent governance in Rust |
| 22 | [Go module](22-go-sdk.md) | Agent governance in Go |

## Enterprise & Operations

| #  | Tutorial | What you'll learn |
|----|----------|-------------------|
| 28 | [Build Custom Integration](28-build-custom-integration.md) | Create your own governance adapter |
| 29 | [Agent Discovery](29-agent-discovery.md) | Finding shadow AI in your organization |
| 30 | [Agent Lifecycle](30-agent-lifecycle.md) | Agent lifecycle management, birth to retirement |
| 31 | [Entra Agent ID Bridge](31-entra-agent-id-bridge.md) | Bridging AGT identity with Microsoft Entra |
| 32 | [Chaos Testing](32-chaos-testing-agents.md) | Chaos engineering for agent reliability |
| 32b | [E2E Encrypted Messaging](32-e2e-encrypted-messaging.md) | End-to-end encrypted agent communication |
| 33 | [Offline Verifiable Receipts](33-offline-verifiable-receipts.md) | Offline-verifiable decision receipts |
| 34 | [MAF Integration](34-maf-integration.md) | Governing agents with Microsoft Agent Framework |

## Policy-as-Code Series

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

## Guides

| Guide | What you'll learn |
|-------|-------------------|
| [Progressive Governance](progressive-governance.md) | Start simple, add governance layers incrementally |
| [Retrofit Governance](retrofit-governance.md) | Add governance to an existing agent |
