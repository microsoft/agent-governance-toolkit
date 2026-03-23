# AAIF Technical Project Proposal

## Agent Governance Toolkit — Runtime Governance for Agentic AI

**Proposed by:** Microsoft (microsoft/agent-governance-toolkit)
**Requested Level:** Sandbox → Incubation
**License:** MIT
**Primary Contact:** Imran Siddique (agt@microsoft.com)
**Status:** ⏸️ Paused — Will re-submit after public release. A2A trust provider shipped. 6,100+ tests passing.

---

## 1. Project Summary

The **Agent Governance Toolkit** is an open-source runtime governance framework for autonomous AI agents. It provides deterministic policy enforcement, zero-trust identity, execution sandboxing, and reliability engineering — the security infrastructure layer that agentic AI systems need for safe production deployment.

Unlike prompt-level guardrails that filter inputs/outputs, this toolkit operates at the **kernel level** — intercepting every agent action and enforcing policy before execution. Agents cannot bypass governance because it is external, mandatory, and sits between the agent and its tools.

## 2. Problem Statement

AI agent frameworks (Microsoft Agent Framework, LangChain, CrewAI, Google ADK, OpenAI Agents SDK) enable agents to call tools, spawn sub-agents, and take real-world actions. However, none provide a comprehensive **runtime security model**:

- **No policy enforcement** — Agents can call any tool with any arguments
- **No identity verification** — Agents cannot prove who they are to each other
- **No execution isolation** — A compromised agent can access everything
- **No reliability engineering** — No SLOs, error budgets, or chaos testing for agents

The OWASP Agentic Top 10 codifies these risks. The Agent Governance Toolkit addresses 10 of 10.

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Agent Governance Toolkit                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌───────────────────┐      ┌───────────────────────────┐     │
│   │   Agent OS Kernel │◄────►│     AgentMesh             │     │
│   │                   │      │                           │     │
│   │  Policy Engine    │      │  Zero-Trust Identity      │     │
│   │  Capability Model │      │  Ed25519 / SPIFFE Certs   │     │
│   │  Audit Logging    │      │  Trust Scoring (0-1000)   │     │
│   │  Syscall Layer    │      │  A2A + MCP Protocol Bridge│     │
│   └────────┬──────────┘      └─────────────┬─────────────┘     │
│            │                               │                   │
│            ▼                               ▼                   │
│   ┌───────────────────┐      ┌───────────────────────────┐     │
│   │ Agent Runtime     │      │     Agent SRE             │     │
│   │                   │      │                           │     │
│   │  Execution Rings  │      │  SLO Engine + Error Budget│     │
│   │  Resource Limits  │      │  Replay & Chaos Testing   │     │
│   │  Kill Switch      │      │  Circuit Breakers         │     │
│   └───────────────────┘      └───────────────────────────┘     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 4. Packages

| Package | Description | Tests |
|---------|------------|-------|
| **Agent OS** | Core governance kernel — policy engine, capability model, audit logging, syscall interception, MCP gateway | 700+ |
| **AgentMesh** | Inter-agent trust — Ed25519 DID identity, SPIFFE/SVID credentials, trust scoring (0-1000), A2A/MCP/IATP protocol bridges | 1,600+ |
| **Agent Runtime** | Execution isolation — 4-tier privilege rings, saga orchestration, kill switch, Shapley-value fault attribution | 326 |
| **Agent SRE** | Reliability engineering — SLO engine, error budgets, chaos testing, progressive delivery, anomaly detection | 1,071+ |
| **Agent Governance** | Unified installer, compliance documentation, OWASP mapping | 200+ |

**Total: 3,900+ tests across 5 packages.**

## 5. OWASP Agentic Top 10 Coverage

| Risk | ID | Coverage | Component |
|------|----|----------|-----------|
| Agent Hijacking | ASI-01 | ✅ Covered | Policy Engine — blocked patterns, content safety |
| Tool Misuse | ASI-02 | ✅ Covered | Capability Sandbox — tool allow/deny, rate limits |
| Insecure Identity | ASI-03 | ✅ Covered | AgentMesh — DID identity, IATP, SPIFFE certs |
| Supply Chain | ASI-04 | ⚠️ Partial | Agent-SBOM planned |
| Insecure Output | ASI-05 | ✅ Covered | Runtime — execution rings, output validation |
| Memory Poisoning | ASI-06 | ✅ Covered | VFS + CMVK (content-addressable memory) |
| Insufficient Monitoring | ASI-07 | ✅ Covered | Agent SRE — SLOs, OTel export, anomaly detection |
| Error Handling | ASI-08 | ✅ Covered | Circuit breakers, saga compensation, error budgets |
| HITL Bypass | ASI-09 | ✅ Covered | Approval workflows, human-in-the-loop gates |
| Uncontrolled Autonomy | ASI-10 | ✅ Covered | Kill switch, resource limits, goal drift detection |

## 6. Framework Integrations

| Framework | Integration Type | Status |
|-----------|-----------------|--------|
| **Microsoft Agent Framework** | Native middleware (3 classes + MAFKernel) | ✅ Shipped, 18 tests |
| **LangChain** | Callback handler + trust-verified tools | ✅ Shipped |
| **CrewAI** | Trust-aware task delegation | ✅ Shipped |
| **Google ADK** | GovernancePlugin (BasePlugin) | 📋 Proposed ([#4543](https://github.com/google/adk-python/issues/4543)) |
| **OpenAI Agents SDK** | Published `openai-agents-trust` on PyPI | ✅ Shipped |
| **Mastra** | `@agentmesh/mastra` npm package | ✅ Shipped, 19 tests |
| **MCP** | MCP Kernel Server (stdio + HTTP) | ✅ Shipped, on npm + Glama |
| **A2A Protocol** | A2A trust provider | ✅ Shipped |

## 7. Community Traction

| Metric | Value |
|--------|-------|
| GitHub Stars | 82+ (across repos) |
| GitHub Forks | 30+ |
| 14-day Clones | 9,400+ |
| PyPI Packages | 5 published |
| npm Packages | 2 published |
| External Contributors | 4+ |
| Framework Integrations | 8 (shipped or proposed) |

### External Adoptions and Submissions

- **Merged** into awesome-copilot (21.6K ⭐) — 3 PRs accepted
- **Proposed** to OWASP Agentic Security Initiative ([#2](https://github.com/OWASP/www-project-agentic-security-initiative/issues/2))
- **Proposed** to CoSAI WS4 Secure Design for Agentic Systems ([#42](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/42))
- **Proposed** to LF AI & Data ([lfai/proposing-projects #102](https://github.com/lfai/proposing-projects/pull/102))
- **Integrated** with OpenLit observability ([openlit/openlit #1037](https://github.com/openlit/openlit/pull/1037))

## 8. Alignment with AAIF Mission

The Agent Governance Toolkit is **MCP-native** and directly addresses the safety and governance layer that the agentic AI ecosystem needs:

1. **Complements MCP** — MCP defines how agents communicate with tools; we ensure agents operate within policy boundaries when using those tools
2. **Complements AGENTS.md** — AGENTS.md describes agent capabilities; our capability model enforces what agents are actually allowed to do at runtime
3. **Framework-neutral** — Works with Microsoft, Google, OpenAI, and open-source agent frameworks
4. **Enterprise-grade** — Designed for production deployment with SLOs, audit trails, and compliance mapping

### Differentiation

The toolkit is unique in providing **external, runtime, mandatory** governance:
- **Not prompt-level** — Operates at the kernel level, not input/output filtering
- **Not agent-self-governance** — External enforcement agents cannot bypass
- **Not static analysis** — Runtime checks that catch goal drift, privilege escalation, and policy violations as they happen

## 9. Project Governance

- **License:** MIT
- **Code of Conduct:** Microsoft Open Source Code of Conduct (Contributor Covenant)
- **Contributing Guide:** CONTRIBUTING.md with DCO sign-off
- **CI/CD:** GitHub Actions, branch protection, automated testing
- **Security:** SECURITY.md with vulnerability reporting process

## 10. Proposed Roadmap Under AAIF

### Phase 1: Sandbox
- Public release under microsoft/ org
- Complete ASI-04 (Supply Chain) coverage with Agent-SBOM
- Formalize governance policy schema as an open specification
- Publish integration guides for all major agent frameworks

### Phase 2: Incubation
- Multi-language support (Python + TypeScript + .NET)
- Formal verification of policy engine
- Cross-framework governance policy portability standard
- Reference implementations for AAIF member organizations

### Phase 3: Graduated
- Industry-standard governance policy format (like OPA/Rego for agents)
- Certification program for governance-compliant agent frameworks
- Integration with cloud-native security tooling (Falco, OPA, SPIFFE)

## 11. References

- **Repository:** [microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit)
- **PyPI:** [ai-agent-governance](https://pypi.org/project/ai-agent-governance/)
- **npm:** [agentos-mcp-server](https://www.npmjs.com/package/agentos-mcp-server)
- **OWASP Compliance:** [OWASP-COMPLIANCE.md](https://github.com/microsoft/agent-governance-toolkit/blob/master/docs/OWASP-COMPLIANCE.md)
- **MAF Integration:** [microsoft/agent-framework #4440](https://github.com/microsoft/agent-framework/issues/4440)
