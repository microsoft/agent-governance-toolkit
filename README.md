<div align="center">

# 🛡️ Agent Governance Toolkit

**Application-level security middleware for autonomous AI agents**

*Policy enforcement · Zero-trust identity · Execution sandboxing · Reliability engineering*

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP_Agentic_Top_10-10%2F10_Covered-blue)](docs/OWASP-COMPLIANCE.md)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12085/badge)](https://www.bestpractices.dev/projects/12085)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/microsoft/agent-governance-toolkit/badge)](https://scorecard.dev/viewer/?uri=github.com/microsoft/agent-governance-toolkit)

[Quick Start](#quick-start) · [Packages](#packages) · [Integrations](#framework-integrations) · [OWASP Coverage](#owasp-agentic-top-10-coverage) · [Architecture Notes](#architecture-notes) · [Contributing](CONTRIBUTING.md)

</div>

---

> **⚠️ Architecture Note:** This toolkit provides **application-level policy enforcement** (Python middleware).
> It does not provide OS kernel-level isolation — agents share the host process by default.
> For high-security environments, combine with infrastructure isolation (containers, VMs, separate processes).
> See [Architecture Notes](#architecture-notes) for details on the security model and its boundaries.

## Why Agent Governance?

AI agent frameworks (LangChain, AutoGen, CrewAI, Google ADK, OpenAI Agents SDK) enable agents to call tools, spawn sub-agents, and take real-world actions — but provide **no runtime security model**. The Agent Governance Toolkit provides:

- **Deterministic policy enforcement** before every agent action
- **Zero-trust identity** with cryptographic agent credentials
- **Execution sandboxing** with privilege rings and termination controls
- **Reliability engineering** with SLOs, error budgets, and chaos testing

Addresses **10 of 10 [OWASP Agentic Top 10](https://owasp.org/www-project-agentic-ai-top-10/)** risks with full coverage across all ASI-01 through ASI-10 categories.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Agent Governance Toolkit                      │
│               pip install ai-agent-compliance[full]              │
├─────────────────────────────────────────────────────────────────┤
│                  (Python middleware layer)                       │
│   ┌───────────────────┐      ┌───────────────────────────┐     │
│   │  Agent OS Engine  │◄────►│     AgentMesh             │     │
│   │                   │      │                           │     │
│   │  Policy Engine    │      │  Zero-Trust Identity      │     │
│   │  Capability Model │      │  Ed25519 / SPIFFE Certs   │     │
│   │  Audit Logging    │      │  Trust Scoring (0-1000)   │     │
│   │  Action Interception│    │  A2A + MCP Protocol Bridge│     │
│   └────────┬──────────┘      └─────────────┬─────────────┘     │
│            │                               │                   │
│            ▼                               ▼                   │
│   ┌───────────────────┐      ┌───────────────────────────┐     │
│   │ Agent Hypervisor  │      │     Agent SRE             │     │
│   │                   │      │                           │     │
│   │  Execution Rings  │      │  SLO Engine + Error Budget│     │
│   │  Resource Limits  │      │  Replay & Chaos Testing   │     │
│   │  Runtime Sandboxing│     │  Progressive Delivery     │     │
│   │  Termination Ctrl │      │  Circuit Breakers         │     │
│   └───────────────────┘      └───────────────────────────┘     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Packages

| Package | PyPI | Description |
|---------|------|-------------|
| **Agent OS** | [`agent-os-kernel`](https://pypi.org/project/agent-os-kernel/) | Policy engine — deterministic action evaluation, capability model, audit logging, action interception, MCP gateway |
| **AgentMesh** | [`agentmesh-platform`](https://pypi.org/project/agentmesh-platform/) | Inter-agent trust — Ed25519 identity, SPIFFE/SVID credentials, trust scoring, A2A/MCP/IATP protocol bridges |
| **Agent Hypervisor** | [`agent-hypervisor`](https://pypi.org/project/agent-hypervisor/) | Execution sandboxing — 4-tier privilege rings, saga orchestration, termination control, joint liability, append-only audit log |
| **Agent SRE** | [`agent-sre`](https://pypi.org/project/agent-sre/) | Reliability engineering — SLOs, error budgets, replay debugging, chaos engineering, progressive delivery |
| **Agent Compliance** | [`ai-agent-compliance`](https://pypi.org/project/ai-agent-compliance/) | Unified installer and compliance documentation |

## Quick Start

```bash
# Install the full governance stack
pip install ai-agent-compliance[full]
```

```python
from agent_os import PolicyEngine, CapabilityModel

# Define agent capabilities
capabilities = CapabilityModel(
    allowed_tools=["web_search", "file_read"],
    denied_tools=["file_write", "shell_exec"],
    max_tokens_per_call=4096
)

# Enforce policy before every action
engine = PolicyEngine(capabilities=capabilities)
decision = engine.evaluate(agent_id="researcher-1", action="tool_call", tool="web_search")

if decision.allowed:
    # proceed with tool call
    ...
```

Or install individual packages:

```bash
pip install agent-os-kernel    # Just the policy engine
pip install agentmesh           # Just the trust mesh
pip install agent-hypervisor    # Just the hypervisor
pip install agent-sre           # Just the SRE toolkit
```

## Framework Integrations

Works with **12+ agent frameworks** including:

| Framework | Stars | Integration |
|-----------|-------|-------------|
| [**Microsoft Agent Framework**](https://github.com/microsoft/agent-framework) | 7.6K+ ⭐ | **Native Middleware** |
| [Dify](https://github.com/langgenius/dify) | 65K+ ⭐ | Plugin |
| [LlamaIndex](https://github.com/run-llama/llama_index) | 47K+ ⭐ | Middleware |
| [LangGraph](https://github.com/langchain-ai/langgraph) | 24K+ ⭐ | Adapter |
| [Microsoft AutoGen](https://github.com/microsoft/autogen) | 42K+ ⭐ | Adapter |
| [CrewAI](https://github.com/crewAIInc/crewAI) | 28K+ ⭐ | Adapter |
| [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) | — | Middleware |
| [Google ADK](https://github.com/google/adk-python) | — | Adapter |
| [Haystack](https://github.com/deepset-ai/haystack) | 22K+ ⭐ | Pipeline |

## OWASP Agentic Top 10 Coverage

| Risk | ID | Status |
|------|----|--------|
| Agent Goal Hijacking | ASI-01 | ✅ Policy engine blocks unauthorized goal changes |
| Excessive Capabilities | ASI-02 | ✅ Capability model enforces least-privilege |
| Identity & Privilege Abuse | ASI-03 | ✅ Zero-trust identity with Ed25519 certs |
| Uncontrolled Code Execution | ASI-04 | ✅ Hypervisor execution rings + sandboxing |
| Insecure Output Handling | ASI-05 | ✅ Content policies validate all outputs |
| Memory Poisoning | ASI-06 | ✅ Episodic memory with integrity checks |
| Unsafe Inter-Agent Communication | ASI-07 | ✅ AgentMesh encrypted channels + trust gates |
| Cascading Failures | ASI-08 | ✅ Circuit breakers + SLO enforcement |
| Human-Agent Trust Deficit | ASI-09 | ✅ Full audit trails + flight recorder |
| Rogue Agents | ASI-10 | ✅ Kill switch + ring isolation + quarantine |

## Documentation

- [OWASP Compliance Mapping](docs/OWASP-COMPLIANCE.md)
- [CSA Agentic Trust Framework Mapping](docs/CSA-ATF-PROPOSAL.md)
- [Changelog](CHANGELOG.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Support](SUPPORT.md)

## Architecture Notes

### Security Model & Boundaries

This toolkit operates as **Python middleware** — it intercepts agent actions at the application level, not at the OS or hypervisor level. Understanding this boundary is critical:

| What it does | What it does NOT do |
|---|---|
| Intercepts and evaluates every agent action before execution | Provide OS kernel-level process isolation |
| Enforces capability-based least-privilege policies | Prevent a compromised Python process from bypassing policies |
| Provides cryptographic agent identity (Ed25519) | Run agents in separate address spaces (by default) |
| Maintains append-only audit logs with hash chains | Guarantee tamper-evidence against in-process adversaries |
| Terminates non-compliant agents via signal system | Prevent a `try/except BaseException` from catching termination |

**For production deployments requiring strong isolation**, we recommend:
- Running each agent in a **separate process or container**
- Writing audit logs to an **external append-only sink** (Azure Monitor, write-once storage)
- Using OS-level `process.kill()` for termination of isolated agent processes

The POSIX metaphor (kernel, signals, syscalls) is an architectural pattern — it provides a familiar, well-understood mental model for agent governance, but the enforcement boundary is the Python interpreter, not the OS scheduler.

### Trust Score Algorithm

AgentMesh assigns trust scores on a 0–1000 scale with the following tiers:

| Score Range | Tier | Meaning |
|---|---|---|
| 900–1000 | Verified Partner | Cryptographically verified, long-term trusted |
| 700–899 | Trusted | Established track record, elevated privileges |
| 500–699 | Standard | Default for new agents with valid identity |
| 300–499 | Probationary | Limited privileges, under observation |
| 0–299 | Untrusted | Restricted to read-only or blocked |

Default score for new agents: **500** (Standard tier). Score changes are driven by policy compliance history, successful task completions, and trust boundary violations. Full algorithm documentation is in [`packages/agent-mesh/docs/TRUST-SCORING.md`](packages/agent-mesh/docs/TRUST-SCORING.md).

### Benchmark Methodology

Policy enforcement benchmarks are measured on a **30-scenario test suite** covering the OWASP Agentic Top 10 risk categories. Results (e.g., policy violation rates, latency) are specific to this test suite and should not be interpreted as universal guarantees. See [`packages/agent-os/modules/control-plane/benchmark/`](packages/agent-os/modules/control-plane/benchmark/) for methodology, datasets, and reproduction instructions.

### Known Limitations & Roadmap

- **ASI-10 Behavioral Detection**: Termination and quarantine are implemented; anomaly detection (tool-call frequency analysis, action entropy scoring) is in active development
- **Audit Trail Integrity**: Current hash-chain is in-process; external append-only log integration is planned
- **Framework Integration Depth**: Current adapters wrap agent execution at the function level; deeper hooks into framework-native tool dispatch and sub-agent spawning are planned
- **Observability**: OpenTelemetry integration for policy decision tracing is planned

## Contributing

This project welcomes contributions and suggestions. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

Most contributions require you to agree to a Contributor License Agreement (CLA). For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions provided by the bot.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any questions.

## License

This project is licensed under the [MIT License](LICENSE).

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
