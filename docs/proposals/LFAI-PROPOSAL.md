# LF AI & Data Foundation — Sandbox Project Proposal

**Submission:** [lfai/proposing-projects#102](https://github.com/lfai/proposing-projects/pull/102)
**Status:** Open — awaiting TAC review
**Requested Level:** Sandbox
**Date Submitted:** March 2, 2026

---

## Summary

Agent Governance Toolkit is an open-source governance kernel for autonomous AI agents providing runtime policy enforcement, capability sandboxing, inter-agent trust verification, and kill-switch controls.

The ecosystem consists of 5 interoperating packages:

| Package | Purpose | PyPI |
|---------|---------|------|
| **Agent OS** | Core governance kernel (policy engine, capability sandbox, VFS) | [agent-os](https://pypi.org/project/agent-os/) |
| **Agent Mesh** | Inter-agent trust layer (DID identity, IATP protocol) | [agent-mesh](https://pypi.org/project/agent-mesh/) |
| **Agent Runtime** | Execution isolation (ring model, kill switch) | [agentmesh-runtime](https://pypi.org/project/agentmesh-runtime/) |
| **Agent SRE** | Observability & reliability (circuit breakers, anomaly detection) | [agent-sre](https://pypi.org/project/agent-sre/) |
| **Agent Governance** | Meta-framework & compliance mapping | [agent-governance](https://pypi.org/project/agent-governance/) |

## Key Metrics

- **82+ GitHub stars**, **30+ forks** across 5 repos
- **9,400+ clones** in 14 days
- **5 PyPI packages** published
- **MCP server** on npm + [Glama listing](https://glama.ai/mcp/servers/@microsoft/agentos-mcp-server)
- **10/10 OWASP Agentic Top 10** risks covered
- **4 external contributors**
- All repos: MIT license, CI/CD, branch protection, code of conduct

## Alignment with LF AI & Data Mission

As AI agents become increasingly autonomous, governance infrastructure is critical for safe deployment. The Agent Governance Toolkit provides this as a neutral, open-source project — preventing vendor lock-in and enabling a shared governance standard.

### Why LF AI & Data?

1. **Neutral governance home** — The toolkit needs a vendor-neutral foundation as it moves from Microsoft personal repos to a community project
2. **Cross-framework** — Integrations with LangChain, CrewAI, AutoGen, Google ADK, PydanticAI, Mastra, OpenAI Agents SDK, and Microsoft Agent Framework
3. **Standards alignment** — Active proposals at AAIF, CoSAI/OASIS WS4, and OWASP
4. **Enterprise readiness** — Runtime policy enforcement, audit trails, and compliance mapping are table stakes for enterprise AI agent deployment

## Architecture

```
┌─────────────────────────────────────────────┐
│              Agent Governance                │
│         (Meta-framework + Compliance)        │
├──────────┬──────────┬───────────┬───────────┤
│ Agent OS │  Agent   │  Agent    │  Agent    │
│ (Kernel) │  Mesh    │ Runtime   │  SRE      │
│          │ (Trust)  │(Isolation)│(Observe)  │
├──────────┴──────────┴───────────┴───────────┤
│         Framework Integrations               │
│  MAF · LangChain · CrewAI · ADK · MCP       │
└─────────────────────────────────────────────┘
```

## OWASP Agentic Top 10 Coverage

| Risk | Description | Package |
|------|-------------|---------|
| ASI-01 | Agent Hijacking | Agent OS (PolicyEngine) |
| ASI-02 | Excessive Capabilities | Agent OS (CapabilitySandbox) |
| ASI-03 | Insecure Communication | Agent Mesh (IATP + DID) |
| ASI-05 | Insecure Output | Agent Runtime (OutputValidator) |
| ASI-06 | Confused Deputy | Agent OS (CapabilityGuard) |
| ASI-07 | Identity Spoofing | Agent Mesh (TrustScorer) |
| ASI-08 | Unbounded Autonomy | Agent Runtime (KillSwitch) |
| ASI-09 | Missing Audit Trails | Agent SRE (IncidentTimeline) |
| ASI-10 | Cascading Hallucinations | Agent SRE (CircuitBreaker) |

## Test Coverage

| Package | Tests | Coverage |
|---------|-------|----------|
| Agent OS | 1,327 | Policy engine, capability sandbox, VFS |
| Agent Mesh | 476 | Trust scoring, DID identity, IATP |
| Agent Runtime | 489 | Ring model, kill switch, sagas |
| Agent SRE | 1,071 | SLOs, chaos testing, circuit breakers |
| Agent Governance | 537 | Compliance mapping, meta-framework |
| **Total** | **3,900+** | |

## Community Traction

- **Framework integration PRs:** AutoGen, CrewAI, MetaGPT, OpenAI Swarm
- **Observability integrations:** OpenLit (PR #1037), Logfire, HolmesGPT
- **Awesome-list PRs:** 15+ across major curated lists
- **Standards submissions:** AAIF, LF AI, CoSAI WS4, OWASP ASI
- **Medium articles** driving 598+ views per post

## Project Governance

- **License:** MIT
- **Primary Maintainer:** Imran Siddique (Microsoft)
- **Code of Conduct:** Contributor Covenant v2.1
- **CI/CD:** GitHub Actions on all repos
- **Branch Protection:** Required reviews, status checks

## Links

- [Agent OS](https://github.com/microsoft/agent-governance-toolkit) | [Agent Mesh](https://github.com/microsoft/agent-governance-toolkit) | [Agent Runtime](https://github.com/microsoft/agent-governance-toolkit) | [Agent SRE](https://github.com/microsoft/agent-governance-toolkit) | [Agent Governance](https://github.com/microsoft/agent-governance-toolkit)
- [Microsoft mono-repo](https://github.com/microsoft/agent-governance-toolkit) (pending public release)
- [OWASP Compliance Mapping](https://github.com/microsoft/agent-governance-toolkit/blob/master/docs/OWASP-COMPLIANCE.md)
- [PyPI: agent-os](https://pypi.org/project/agent-os/)
