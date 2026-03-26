<div align="center">

# Agent Governance

**Unified installer and runtime policy enforcement for the Agent Governance Toolkit**

*One install for the complete governance stack — kernel · trust mesh · runtime supervisor · reliability engineering*

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../../LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![PyPI](https://img.shields.io/pypi/v/agent-governance-toolkit)](https://pypi.org/project/agent-governance-toolkit/)

> [!IMPORTANT]
> **Community Preview** — The `agent-governance-toolkit` package on PyPI is a community preview
> release for testing and evaluation only. It is **not** an official Microsoft-signed release.
> Official signed packages will be available in a future release.

```
pip install agent-governance-toolkit[full]
```

[Architecture](#architecture) • [Quick Start](#quick-start) • [Components](#components) • [Why Unified?](#why-a-unified-governance-stack) • [Ecosystem](#the-agent-governance-ecosystem) • [OWASP Compliance](docs/OWASP-COMPLIANCE.md) • [Traction](docs/TRACTION.md)

</div>

> ⭐ **If this project helps you, please star it!** It helps others discover the agent governance stack.

> 🔗 **Part of the Agent Governance Ecosystem** — Installs [Agent OS](https://github.com/microsoft/agent-governance-toolkit) · [AgentMesh](https://github.com/microsoft/agent-governance-toolkit) · [Agent Runtime](https://github.com/microsoft/agent-governance-toolkit) · [Agent SRE](https://github.com/microsoft/agent-governance-toolkit)

> **Migrating from `ai-agent-compliance`?** The package has been renamed to `agent-governance-toolkit`.
> Run `pip install agent-governance` — the old name is deprecated and will redirect here for 6 months.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      agent-governance                            │
│                  pip install agent-governance-toolkit[full]              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌───────────────────┐      ┌───────────────────────────┐     │
│   │   Agent OS Kernel │◄────►│   AgentMesh Platform      │     │
│   │                   │      │                           │     │
│   │  Policy Engine    │      │  Zero-Trust Identity      │     │
│   │  Capability Model │      │  Mutual TLS for Agents    │     │
│   │  Audit Logging    │      │  Encrypted Channels       │     │
│   │  Syscall Layer    │      │  Trust Scoring             │     │
│   └────────┬──────────┘      └─────────────┬─────────────┘     │
│            │                               │                   │
│            ▼                               ▼                   │
│   ┌───────────────────┐      ┌───────────────────────────┐     │
│   │ Agent Runtime     │      │   Agent SRE               │     │
│   │                   │      │                           │     │
│   │  Execution Rings  │      │  Health Monitoring        │     │
│   │  Resource Limits  │      │  SLO Enforcement          │     │
│   │  Runtime Sandboxing│     │  Incident Response        │     │
│   │  Kill Switch      │      │  Chaos Engineering        │     │
│   └───────────────────┘      └───────────────────────────┘     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```python
import asyncio
from agent_os import StatelessKernel, ExecutionContext
from agentmesh import AgentIdentity

# Boot the governance kernel
kernel = StatelessKernel()
ctx = ExecutionContext(agent_id="my-agent", policies=["read_only"])

# Establish zero-trust agent identity
identity = AgentIdentity.create(
    name="my-agent",
    sponsor="alice@company.com",
    capabilities=["read:data", "write:reports"],
)

# Execute a governed action
async def main():
    result = await kernel.execute(
        action="database_query",
        params={"query": "SELECT * FROM users"},
        context=ctx,
    )
    print(f"Success: {result.success}, Data: {result.data}")

asyncio.run(main())
```

### Compliance Grading

Check your governance coverage with a compliance grade:

```python
from agent_compliance.verify import GovernanceVerifier

verifier = GovernanceVerifier()
attestation = verifier.verify()
print(f"Grade: {attestation.compliance_grade()}")  # A, B, C, D, or F
print(f"Coverage: {attestation.coverage_pct()}%")
print(attestation.badge_markdown())
```

Install only what you need:

```bash
# Core: kernel + trust mesh
pip install agent-governance-toolkit

# Full stack: adds runtime + SRE
pip install agent-governance-toolkit[full]

# À la carte
pip install agent-governance-toolkit[runtime]
pip install agent-governance-toolkit[sre]
```

---

## Components

| Package | Role |
|---------|------|
| **Agent OS** | Policy engine — deterministic action evaluation |
| **AgentMesh** | Trust infrastructure — identity, credentials, protocol bridges |
| **Agent Runtime** | Execution supervisor — rings, sessions, sagas |
| **Agent SRE** | Reliability — SLOs, circuit breakers, chaos testing |
| **Agent Compliance** | Regulatory compliance — GDPR, HIPAA, SOX frameworks *(this package)* |
| **Agent Marketplace** | Plugin lifecycle — discover, install, verify, sign |
| **Agent Lightning** | RL training governance — governed runners, policy rewards |

### Star the ecosystem

<p align="center">

[![Agent OS Stars](https://img.shields.io/github/stars/microsoft/agent-governance-toolkit?label=Agent%20OS&style=social)](https://github.com/microsoft/agent-governance-toolkit)&nbsp;&nbsp;
[![AgentMesh Stars](https://img.shields.io/github/stars/microsoft/agent-governance-toolkit?label=AgentMesh&style=social)](https://github.com/microsoft/agent-governance-toolkit)&nbsp;&nbsp;
[![Agent Runtime Stars](https://img.shields.io/github/stars/microsoft/agent-governance-toolkit?label=Agent%20Runtime&style=social)](https://github.com/microsoft/agent-governance-toolkit)&nbsp;&nbsp;
[![Agent SRE Stars](https://img.shields.io/github/stars/microsoft/agent-governance-toolkit?label=Agent%20SRE&style=social)](https://github.com/microsoft/agent-governance-toolkit)

</p>

---

## Why a Unified Governance Stack?

Running AI agents in production without governance is like deploying microservices without TLS, RBAC, or monitoring. Each layer solves a different problem:

| Concern | Without Governance | With Agent Governance |
|---------|-------------------|----------------------|
| **Security** | Agents call any tool, access any resource | Capability-based permissions, policy enforcement |
| **Trust** | No identity verification between agents | Mutual TLS, trust scores, encrypted channels |
| **Control** | Runaway agents consume unbounded resources | Execution rings, resource limits, kill switches |
| **Reliability** | Silent failures, no observability | SLO enforcement, health checks, incident automation |
| **Compliance** | No audit trail for agent decisions | Immutable audit logs, decision lineage tracking |

**One install. Four layers of protection.**

The meta-package ensures all components are version-compatible and properly integrated. No dependency conflicts, no version mismatches — just a single `pip install` to go from zero to production-grade agent governance.

---

## The Agent Governance Ecosystem

```
agent-governance ─── The meta-package (you are here)
├── agent-os-kernel ─── Governance kernel
├── agentmesh-platform ─── Zero-trust mesh
├── agentmesh-runtime ─── Runtime supervisor (optional)
└── agent-sre ─── Reliability engineering (optional)
```

Each component works standalone, but they're designed to work together. The kernel enforces policy, the mesh secures communication, the runtime controls execution, and SRE keeps everything running.

---

## Examples

See the [`examples/`](examples/) directory for runnable demos:

```bash
# Quick start — boot the governance stack in 30 lines
python examples/quickstart.py

# Full stack — all 4 layers working together
python examples/governed_agent.py
```

---

## Framework Integration

```bash
# LangChain
pip install langchain agent-governance

# CrewAI
pip install crewai agent-governance

# AutoGen
pip install pyautogen agent-governance
```

---

## 🗺️ Roadmap

| Quarter | Milestone |
|---------|-----------|
| **Q1 2026** | ✅ Unified meta-package, 4 components integrated, PyPI published |
| **Q2 2026** | Cross-component integration tests, unified CLI, dashboard UI |
| **Q3 2026** | Helm chart for Kubernetes, managed cloud preview |
| **Q4 2026** | SOC2 Type II certification, enterprise support tier |

---

## 🛡️ OWASP Agentic Top 10 Coverage

The agent governance stack covers **10 of 10** risks from the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):

| OWASP Risk | Coverage | Component |
|-----------|----------|-----------|
| Agent Goal Hijack | ✅ | Agent OS — Policy Engine |
| Tool Misuse | ✅ | Agent OS — Capability Sandboxing |
| Identity & Privilege Abuse | ✅ | AgentMesh — DID Identity |
| Supply Chain Vulnerabilities | ✅ | AgentMesh — AI-BOM v2.0 |
| Unexpected Code Execution | ✅ | Agent Runtime — Execution Rings |
| Memory & Context Poisoning | ✅ | Agent OS — VFS + CMVK |
| Insecure Inter-Agent Communication | ✅ | AgentMesh — IATP Protocol |
| Cascading Failures | ✅ | Agent SRE — Circuit Breakers |
| Human-Agent Trust Exploitation | ✅ | Agent OS — Approval Workflows |
| Rogue Agents | ✅ | Agent Runtime — Kill Switch |

**[→ Full OWASP compliance mapping with code examples](docs/OWASP-COMPLIANCE.md)**

---

## 📈 Traction

The ecosystem is growing — **3,000+ views, 9,400+ clones, and 1,278 unique developers** in the last 14 days alone. Traffic from Medium, Reddit, LinkedIn, Google, and even ChatGPT.

**[→ See full traction report](docs/TRACTION.md)**

---

## Contributing

We welcome contributions! See our [Contributing Guide](CONTRIBUTING.md) for details.

For component-specific contributions, see:
- [Agent OS](https://github.com/microsoft/agent-governance-toolkit/blob/master/CONTRIBUTING.md)
- [AgentMesh](https://github.com/microsoft/agent-governance-toolkit/blob/master/CONTRIBUTING.md)
- [Agent Runtime](https://github.com/microsoft/agent-governance-toolkit/blob/master/CONTRIBUTING.md)
- [Agent SRE](https://github.com/microsoft/agent-governance-toolkit/blob/master/CONTRIBUTING.md)

## License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

**[github.com/microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit)** · **[Documentation](https://github.com/microsoft/agent-governance-toolkit/tree/main/docs)** · **[GitHub](https://github.com/microsoft/agent-governance-toolkit)**

*Building the governance layer for the agentic era*

</div>
