# Agent-OS Roadmap

> **Disclaimer:** This roadmap is directional only — no pricing, no commitments.
> Timelines and features are subject to change based on community feedback and project priorities.

---

## Timeline Overview

```
Q1 2026                Q2 2026                Q3 2026
───────────────────────────────────────────────────────────────
│  Core Stabilization  │  Integrations &      │  Enterprise       │
│                      │  Planned Features    │  Exploration      │
│  ✓ Governance kernel │  ✓ WebSocket events  │  ◇ SSO/SAML       │
│  ✓ All adapters      │  ✓ Plugin system     │  ◇ Policy console │
│  ✓ MCP tools & CLI   │  ✓ Federated gov.    │  ◇ Compliance     │
│  ✓ Runtime module    │  ✓ Profiling dash.   │  ◇ Multi-tenant   │
│  ✓ Trust & safety    │                      │  ◇ Support & SLAs │
───────────────────────────────────────────────────────────────
  ✓ = open source                           ◇ = future / TBD
```

---

## Always Open Source (Core)

These features are and will remain fully open source under the project's existing license.

### Governance Kernel
- Policy enforcement engine
- SIGKILL signal handling for agent termination
- Audit logging and event trail

### Framework Adapters
- OpenAI
- LangChain
- CrewAI
- AutoGen
- Semantic Kernel
- Anthropic
- Gemini
- Mistral

### MCP Server Tools
- Full suite of Model Context Protocol server tools

### CLI
- `init` — project scaffolding
- `serve` — run the governance server
- `metrics` — observe runtime telemetry
- `audit` — query the audit log
- `validate` — check policy files

### Runtime Module
- SSO and identity-aware sessions
- Virtual File System (VFS)
- Ring-based permission model
- Saga orchestration for multi-step agent workflows

### Trust & Safety
- Trust root and supervisor hierarchy
- Constraint graph for policy relationships
- Mute agent capability
- Adversarial evaluation framework

### Tests & Documentation
- Full test suite
- All project documentation

---

## Planned (Open Source)

These features are planned for open-source release, targeting **Q2 2026**.

| Feature | Description |
|---|---|
| **WebSocket Real-Time Governance Events** | Stream policy decisions, violations, and audit events to connected clients in real time. |
| **Plugin System for Custom Policy Engines** | Allow third-party and custom policy engines to integrate via a well-defined plugin interface. |
| **Federated Governance for Multi-Org Deployments** | Coordinate governance policies across organizational boundaries with trust delegation. |
| **Performance Profiling Dashboard** | Visual tooling for profiling governance overhead, adapter latency, and policy evaluation performance. |

---

## Enterprise Features (Future, TBD)

These features are under exploration for **Q3 2026** and beyond. Scope, packaging, and availability are not yet determined.

| Feature | Description |
|---|---|
| **SSO/SAML Integration for Agent Identity** | Enterprise identity providers mapped to agent identities for centralized authentication. |
| **Centralized Policy Management Console** | Web-based UI for authoring, versioning, and deploying governance policies across fleets. |
| **Compliance Reporting** | Pre-built templates for SOC 2, HIPAA, and GDPR audit evidence generation. |
| **Multi-Tenant Governance** | Organization-level policy isolation with tenant-scoped audit trails and controls. |
| **Priority Support and SLAs** | Dedicated support channels with guaranteed response times. |
| **Custom Adapter Development** | Bespoke adapter engineering for proprietary or internal AI frameworks. |

---

## How to Influence This Roadmap

- **Open an issue** — feature requests and use-case descriptions help us prioritize.
- **Join the discussion** — participate in [GitHub Discussions](../../discussions) or RFCs in `docs/rfcs/`.
- **Contribute** — see [CONTRIBUTING.md](../CONTRIBUTING.md) for how to get involved.

---

*Last updated: 2025*
