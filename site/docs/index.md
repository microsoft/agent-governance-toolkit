# Agent Governance Toolkit

**Governance, trust, identity, and compliance for AI agents.**

The Agent Governance Toolkit (AGT) provides a comprehensive set of packages for building governed, trustworthy AI agent systems. It covers the full lifecycle: policy enforcement, identity management, runtime sandboxing, reliability engineering, compliance verification, and marketplace governance.

## Quick Links

| | |
|---|---|
| :material-rocket-launch: [**Quick Start**](quickstart.md) | Get running in 5 minutes |
| :material-cube-outline: [**Packages**](packages/index.md) | 11 packages for every governance layer |
| :material-school: [**Tutorials**](tutorials/index.md) | 27 step-by-step guides |
| :material-cloud-upload: [**Deployment**](deployment/index.md) | Azure Container Apps, Foundry, OpenClaw |
| :material-shield-check: [**Security**](security/threat-model.md) | Threat model, OWASP compliance, scanning |

## Packages at a Glance

| Package | Purpose |
|---------|---------|
| [Agent OS](packages/agent-os.md) | Core policy engine and agent lifecycle management |
| [Agent Mesh](packages/agent-mesh.md) | Agent discovery, routing, and trust mesh |
| [Agent Runtime](packages/agent-runtime.md) | Execution sandboxing with privilege rings |
| [Agent SRE](packages/agent-sre.md) | Reliability: kill switch, SLO monitoring, chaos testing |
| [Agent Compliance](packages/agent-compliance.md) | Audit logging, compliance frameworks, evidence collection |
| [Agent Marketplace](packages/agent-marketplace.md) | Plugin governance and marketplace trust |
| [Agent Lightning](packages/agent-lightning.md) | High-performance agent orchestration |
| [Agent Hypervisor](packages/agent-hypervisor.md) | Hardware-level isolation for agent workloads |

## Examples

Governed examples for popular AI agent frameworks:

| Example | Framework | What it demonstrates |
|---------|-----------|---------------------|
| [openai-agents-governed](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/openai-agents-governed) | OpenAI Agents SDK | Policy-gated tool calls with trust tiers |
| [crewai-governed](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/crewai-governed) | CrewAI | Multi-agent governance with role-based policies |
| [smolagents-governed](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/smolagents-governed) | HuggingFace smolagents | Lightweight agent governance |
| [protect-mcp-governed](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/protect-mcp-governed) | protect-mcp | Cedar policies + Ed25519 signed receipts for MCP tool calls |
| [physical-attestation-governed](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/physical-attestation-governed) | Physical sensors | Cold chain sensor attestation (temperature, shock, GPS) |
| [openshell-governed](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/openshell-governed) | OpenShell | Sandboxed shell execution governance |
| [mcp-trust-verified-server](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/mcp-trust-verified-server) | MCP | Trust-verified MCP server implementation |
| [maf-integration](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/maf-integration) | MAF | Microsoft Agent Framework integration |
| [marketplace-governance](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/marketplace-governance) | Marketplace | Plugin governance and trust scoring |
| [atr-community-rules](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/atr-community-rules) | ATR | Community-contributed governance rules |

## Standards

- **OWASP Agentic AI Top 10** — [compliance mapping](security/owasp-compliance.md)
- **NIST AI RMF** — [RFI response](reference/nist-rfi-mapping.md)
- **Ed25519 (RFC 8032)** — [ADR-0001](adr/0001-use-ed25519-for-agent-identity.md)
