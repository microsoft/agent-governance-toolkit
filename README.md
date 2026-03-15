<div align="center">

# 🛡️ Agent Governance Toolkit

**Application-level security middleware for autonomous AI agents**

*Policy enforcement · Zero-trust identity · Execution sandboxing · Reliability engineering*

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP_Agentic_Top_10-10%2F10_Covered-blue)](docs/OWASP-COMPLIANCE.md)
[![OpenSSF Best Practices](https://img.shields.io/cii/percentage/12085?label=OpenSSF%20Best%20Practices&logo=opensourcesecurity)](https://www.bestpractices.dev/projects/12085)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/microsoft/agent-governance-toolkit/badge)](https://scorecard.dev/viewer/?uri=github.com/microsoft/agent-governance-toolkit)

[Quick Start](#quick-start) · [Packages](#packages) · [Integrations](#framework-integrations) · [OWASP Coverage](#owasp-agentic-top-10-coverage) · [Performance](#performance) · [Deploy on Azure](docs/deployment/README.md) · [Architecture Notes](#architecture-notes) · [Contributing](CONTRIBUTING.md)

</div>

---

> **🔒 Enforcement Model:** Deterministic application-layer interception — every agent action is evaluated
> against policy **before execution**, at sub-millisecond latency. For high-security environments,
> composes with container/VM isolation for defense-in-depth.
> See [Architecture Notes](#architecture-notes) for details.

## Why Agent Governance?

AI agent frameworks (LangChain, AutoGen, CrewAI, Google ADK, OpenAI Agents SDK) enable agents to call tools, spawn sub-agents, and take real-world actions — but provide **no runtime security model**. The Agent Governance Toolkit provides:

- **Deterministic policy enforcement** before every agent action
- **Zero-trust identity** with cryptographic agent credentials
- **Execution sandboxing** with privilege rings and termination controls
- **Reliability engineering** with SLOs, error budgets, and chaos testing

Addresses **10 of 10 [OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)** risks with full coverage across all ASI-01 through ASI-10 categories.

## Architecture

```
╔═════════════════════════════════════════════════════════════════════════════╗
║                                                                             ║
║               ════════  AGENT GOVERNANCE TOOLKIT   ═══════════              ║
║                    pip install ai-agent-compliance[full]                    ║
║                                                                             ║
║      Agent Action ───► POLICY CHECK ───► Allow / Deny    (< 0.1 ms)         ║
║                                                                             ║
║   ┌─────────────────────────────┐     ┌─────────────────────────────────┐   ║
║   │       AGENT OS ENGINE       │◄───►│            AGENTMESH            │   ║
║   │                             │     │                                 │   ║
║   │  ● Policy Engine            │     │  ● Zero-Trust Identity          │   ║
║   │  ● Capability Model         │     │  ● Ed25519 / SPIFFE Certs       │   ║
║   │  ● Audit Logging            │     │  ● Trust Scoring (0-1000)       │   ║
║   │  ● Action Interception      │     │  ● A2A + MCP Protocol Bridge    │   ║
║   └──────────────┬──────────────┘     └────────────────┬────────────────┘   ║
║                  │                                     │                    ║
║                  ▼                                     ▼                    ║
║   ┌─────────────────────────────┐     ┌─────────────────────────────────┐   ║
║   │        AGENT RUNTIME        │     │            AGENT SRE            │   ║
║   │                             │     │                                 │   ║
║   │  ● Execution Rings          │     │  ● SLO Engine + Error Budgets   │   ║
║   │  ● Resource Limits          │     │  ● Replay & Chaos Testing       │   ║
║   │  ● Runtime Sandboxing       │     │  ● Progressive Delivery         │   ║
║   │  ● Termination Control      │     │  ● Circuit Breakers             │   ║
║   └─────────────────────────────┘     └─────────────────────────────────┘   ║
║                                                                             ║
║   ┌─────────────────────────────┐     ┌─────────────────────────────────┐   ║
║   │      AGENT MARKETPLACE      │     │         AGENT LIGHTNING         │   ║
║   │                             │     │                                 │   ║
║   │  ● Plugin Discovery         │     │  ● RL Training Governance       │   ║
║   │  ● Signing & Verification   │     │  ● Policy Rewards               │   ║
║   └─────────────────────────────┘     └─────────────────────────────────┘   ║
║                                                                             ║
╚═════════════════════════════════════════════════════════════════════════════╝
```

## Packages

| Package | PyPI | Description |
|---------|------|-------------|
| **Agent OS** | [`agent-os-kernel`](https://pypi.org/project/agent-os-kernel/) | Policy engine — deterministic action evaluation, capability model, audit logging, action interception, MCP gateway |
| **AgentMesh** | [`agentmesh-platform`](https://pypi.org/project/agentmesh-platform/) | Inter-agent trust — Ed25519 identity, SPIFFE/SVID credentials, trust scoring, A2A/MCP/IATP protocol bridges |
| **Agent Runtime** | [`agent-runtime`](packages/agent-runtime/) | Execution supervisor — 4-tier privilege rings, saga orchestration, termination control, joint liability, append-only audit log |
| **Agent SRE** | [`agent-sre`](https://pypi.org/project/agent-sre/) | Reliability engineering — SLOs, error budgets, replay debugging, chaos engineering, progressive delivery |
| **Agent Compliance** | [`ai-agent-compliance`](https://pypi.org/project/ai-agent-compliance/) | Regulatory compliance — GDPR, HIPAA, SOX audit frameworks |
| **Agent Marketplace** | [`agent-marketplace`](packages/agent-marketplace/) | Plugin lifecycle — discover, install, verify, and sign plugins |
| **Agent Lightning** | [`agent-lightning`](packages/agent-lightning/) | RL training governance — governed runners, policy rewards |

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
pip install agent-runtime       # Just the runtime supervisor
pip install agent-sre           # Just the SRE toolkit
pip install agent-marketplace   # Just the plugin marketplace
pip install agent-lightning     # Just the RL training governance
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
| Uncontrolled Code Execution | ASI-04 | ✅ Agent Runtime execution rings + sandboxing |
| Insecure Output Handling | ASI-05 | ✅ Content policies validate all outputs |
| Memory Poisoning | ASI-06 | ✅ Episodic memory with integrity checks |
| Unsafe Inter-Agent Communication | ASI-07 | ✅ AgentMesh encrypted channels + trust gates |
| Cascading Failures | ASI-08 | ✅ Circuit breakers + SLO enforcement |
| Human-Agent Trust Deficit | ASI-09 | ✅ Full audit trails + flight recorder |
| Rogue Agents | ASI-10 | ✅ Kill switch + ring isolation + behavioral anomaly detection ([Agent SRE](packages/agent-sre/src/agent_sre/anomaly/)) |

## Performance

Governance overhead is **sub-millisecond** — negligible compared to any LLM API call (typically 200–2,000 ms). 

| Metric | Latency (p50) | Throughput |
|---|---|---|
| Policy evaluation (1 rule) | 0.012 ms | 72K ops/sec |
| Policy evaluation (100 rules) | 0.029 ms | 31K ops/sec |
| Kernel enforcement | 0.091 ms | 9.3K ops/sec |
| Adapter overhead | 0.004–0.006 ms | 130K–230K ops/sec |
| Concurrent throughput (50 agents) | — | 35,481 ops/sec |

**Bottom line:** Governance adds **< 0.1 ms per action** — roughly 10,000× faster than an LLM API call.

Full methodology, per-adapter breakdowns, and memory profiling: **[BENCHMARKS.md](BENCHMARKS.md)**. Benchmarks are reproducible via the scripts in each package's `benchmarks/` directory and run on every release via CI ([`.github/workflows/benchmarks.yml`](.github/workflows/benchmarks.yml)).

## Documentation

- **[Azure Deployment Guides](docs/deployment/README.md)** — AKS, Azure AI Foundry, Container Apps, OpenClaw sidecar
- [OWASP Compliance Mapping](docs/OWASP-COMPLIANCE.md)
- [CSA Agentic Trust Framework Mapping](docs/CSA-ATF-PROPOSAL.md)
- [Changelog](CHANGELOG.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Support](SUPPORT.md)

## Architecture Notes

### Security Model & Boundaries

This toolkit provides **deterministic application-layer interception** — a deliberate architectural choice that enables sub-millisecond policy enforcement without the overhead of IPC or container orchestration. Every agent action passes through the governance pipeline before execution.

| Enforcement Capability | Defense-in-Depth Composition |
|---|---|
| Intercepts and evaluates every agent action before execution | Add container isolation (Docker, gVisor, Kata) for OS-level separation |
| Enforces capability-based least-privilege policies | Add network policies for cross-agent communication control |
| Provides cryptographic agent identity (Ed25519) | Add external PKI for certificate lifecycle management |
| Maintains append-only audit logs with hash chains | Add external append-only sink (Azure Monitor, write-once storage) for tamper-evidence |
| Terminates non-compliant agents via signal system | Add OS-level `process.kill()` for isolated agent processes |

The POSIX metaphor (kernel, signals, syscalls) is an architectural pattern — it provides a familiar, well-understood mental model for agent governance. The enforcement boundary is the Python interpreter, which is the same trust boundary used by every Python-based agent framework (LangChain, AutoGen, CrewAI, OpenAI Agents SDK).

> **Production recommendation:** For high-security deployments, run each agent in a separate container with the governance middleware inside. This gives you both application-level policy enforcement *and* OS-level isolation.

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

- **ASI-10 Behavioral Detection**: Fully implemented in Agent SRE — tool-call frequency analysis (z-score spike detection), action entropy scoring, and capability profile violation detection. See [`packages/agent-sre/src/agent_sre/anomaly/`](packages/agent-sre/src/agent_sre/anomaly/) (72 tests passing)
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
