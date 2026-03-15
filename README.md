![Agent Governance Toolkit](docs/assets/readme-banner.svg)

# Welcome to Agent Governance Toolkit!

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP_Agentic_Top_10-10%2F10_Covered-blue)](docs/OWASP-COMPLIANCE.md)
[![OpenSSF Best Practices](https://img.shields.io/cii/percentage/12085?label=OpenSSF%20Best%20Practices&logo=opensourcesecurity)](https://www.bestpractices.dev/projects/12085)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/microsoft/agent-governance-toolkit/badge)](https://scorecard.dev/viewer/?uri=github.com/microsoft/agent-governance-toolkit)

Runtime governance for AI agents — the only toolkit covering all **10 OWASP Agentic risks** with **6,100+ tests**. Governs what agents *do*, not just what they say — deterministic policy enforcement, zero-trust identity, execution sandboxing, and SRE — one `pip install`.

## 📋 Getting Started

### 📦 Installation

```bash
pip install agent-governance[full]
# This will install all sub-packages, see `packages/` for individual packages.
```

Or install individual packages:

```bash
pip install agent-os-kernel    # Policy engine
pip install agentmesh           # Trust mesh
pip install agent-runtime       # Runtime supervisor
pip install agent-sre           # SRE toolkit
pip install agent-governance    # Compliance & attestation
pip install agent-marketplace   # Plugin marketplace
pip install agent-lightning     # RL training governance
```

### 📚 Documentation

- **[Quick Start](QUICKSTART.md)** — Get from zero to governed agents in 10 minutes
- **[Tutorials](docs/tutorials/)** — Step-by-step guides for policy, identity, integrations, compliance, SRE, and sandboxing
- **[Azure Deployment](docs/deployment/README.md)** — AKS, Azure AI Foundry, Container Apps, OpenClaw sidecar
- **[OWASP Compliance](docs/OWASP-COMPLIANCE.md)** — Full ASI-01 through ASI-10 mapping
- **[Architecture](docs/ARCHITECTURE.md)** — System design, security model, trust scoring
- **[NIST RFI Mapping](docs/nist-rfi-mapping.md)** — Mapping to NIST AI Agent Security RFI (2026-00206)

Still have questions? File a [GitHub issue](https://github.com/microsoft/agent-governance-toolkit/issues) or see our [Community page](COMMUNITY.md).

### ✨ **Highlights**

- **Deterministic Policy Enforcement**: Every agent action evaluated against policy *before* execution at sub-millisecond latency (<0.1 ms)
  - [Policy Engine](packages/agent-os/) | [Benchmarks](BENCHMARKS.md)
- **Zero-Trust Agent Identity**: Ed25519 cryptographic credentials, SPIFFE/SVID support, trust scoring on a 0–1000 scale
  - [AgentMesh](packages/agent-mesh/) | [Trust Scoring docs](packages/agent-mesh/docs/TRUST-SCORING.md)
- **Execution Sandboxing**: 4-tier privilege rings, saga orchestration, termination control, kill switch
  - [Agent Runtime](packages/agent-runtime/) | [Agent Hypervisor](packages/agent-hypervisor/)
- **Agent SRE**: SLOs, error budgets, replay debugging, chaos engineering, circuit breakers, progressive delivery
  - [Agent SRE](packages/agent-sre/) | [Observability integrations](packages/agent-hypervisor/src/hypervisor/observability/)
- **12+ Framework Integrations**: Microsoft Agent Framework, LangChain, CrewAI, AutoGen, Dify, LlamaIndex, OpenAI Agents, Google ADK, and more
  - [Framework quickstarts](examples/quickstart/) | [Integration proposals](docs/proposals/)
- **Full OWASP Coverage**: 10/10 Agentic Top 10 risks addressed with dedicated controls for each ASI category
  - [OWASP Compliance](docs/OWASP-COMPLIANCE.md) | [Competitive Comparison](docs/COMPARISON.md)

### 💬 **We want your feedback!**

- For bugs, please file a [GitHub issue](https://github.com/microsoft/agent-governance-toolkit/issues).

## Quickstart

### Enforce a policy — Python

```python
from agent_os import PolicyEngine, CapabilityModel

# Define what this agent is allowed to do
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

## More Examples & Samples

- **[Framework Quickstarts](examples/quickstart/)** — One-file governed agents for LangChain, CrewAI, AutoGen, OpenAI Agents, Google ADK
- **[Tutorial 1: Policy Engine](docs/tutorials/01-policy-engine.md)** — Define and enforce governance policies
- **[Tutorial 2: Trust & Identity](docs/tutorials/02-trust-and-identity.md)** — Zero-trust agent credentials
- **[Tutorial 3: Framework Integrations](docs/tutorials/03-framework-integrations.md)** — Add governance to any framework
- **[Tutorial 4: Audit & Compliance](docs/tutorials/04-audit-and-compliance.md)** — OWASP compliance and attestation
- **[Tutorial 5: Agent Reliability](docs/tutorials/05-agent-reliability.md)** — SLOs, error budgets, chaos testing
- **[Tutorial 6: Execution Sandboxing](docs/tutorials/06-execution-sandboxing.md)** — Privilege rings and termination

## Packages

| Package | PyPI | Description |
|---------|------|-------------|
| **Agent OS** | [`agent-os-kernel`](https://pypi.org/project/agent-os-kernel/) | Policy engine — deterministic action evaluation, capability model, audit logging, action interception, MCP gateway |
| **AgentMesh** | [`agentmesh-platform`](https://pypi.org/project/agentmesh-platform/) | Inter-agent trust — Ed25519 identity, SPIFFE/SVID credentials, trust scoring, A2A/MCP/IATP protocol bridges |
| **Agent Runtime** | [`agent-runtime`](packages/agent-runtime/) | Execution supervisor — 4-tier privilege rings, saga orchestration, termination control, joint liability, append-only audit log |
| **Agent SRE** | [`agent-sre`](https://pypi.org/project/agent-sre/) | Reliability engineering — SLOs, error budgets, replay debugging, chaos engineering, progressive delivery |
| **Agent Compliance** | [`agent-governance`](https://pypi.org/project/agent-governance/) | Runtime policy enforcement — OWASP ASI 2026 controls, governance attestation, integrity verification |
| **Agent Marketplace** | [`agent-marketplace`](packages/agent-marketplace/) | Plugin lifecycle — discover, install, verify, and sign plugins |
| **Agent Lightning** | [`agent-lightning`](packages/agent-lightning/) | RL training governance — governed runners, policy rewards |

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
| Rogue Agents | ASI-10 | ✅ Kill switch + ring isolation + behavioral anomaly detection |

## Performance

Governance adds **< 0.1 ms per action** — roughly 10,000× faster than an LLM API call.

| Metric | Latency (p50) | Throughput |
|---|---|---|
| Policy evaluation (1 rule) | 0.012 ms | 72K ops/sec |
| Policy evaluation (100 rules) | 0.029 ms | 31K ops/sec |
| Kernel enforcement | 0.091 ms | 9.3K ops/sec |
| Adapter overhead | 0.004–0.006 ms | 130K–230K ops/sec |
| Concurrent throughput (50 agents) | — | 35,481 ops/sec |

Full methodology and per-adapter breakdowns: **[BENCHMARKS.md](BENCHMARKS.md)**

## Contributor Resources

- [Contributing Guide](CONTRIBUTING.md)
- [Community](COMMUNITY.md)
- [Security Policy](SECURITY.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Changelog](CHANGELOG.md)
- [Support](SUPPORT.md)

## Important Notes

If you use the Agent Governance Toolkit to build applications that operate with third-party agent frameworks or services, you do so at your own risk. We recommend reviewing all data being shared with third-party services and being cognizant of third-party practices for retention and location of data. It is your responsibility to manage whether your data will flow outside of your organization's compliance and geographic boundaries and any related implications.

## License

This project is licensed under the [MIT License](LICENSE).

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
