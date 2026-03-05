<div align="center">

# 🛡️ Agent Governance Toolkit

**The missing security layer for autonomous AI agents**

*Policy enforcement · Zero-trust identity · Execution sandboxing · Reliability engineering*

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP_Agentic_Top_10-10%2F10_Covered-brightgreen)](docs/OWASP-COMPLIANCE.md)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12085/badge)](https://www.bestpractices.dev/projects/12085)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/microsoft/agent-governance-toolkit/badge)](https://scorecard.dev/viewer/?uri=github.com/microsoft/agent-governance-toolkit)

[Quick Start](#quick-start) · [Packages](#packages) · [Integrations](#framework-integrations) · [OWASP Coverage](#owasp-agentic-top-10-coverage) · [Contributing](CONTRIBUTING.md)

</div>

---

## Why Agent Governance?

AI agent frameworks (LangChain, AutoGen, CrewAI, Google ADK, OpenAI Agents SDK) enable agents to call tools, spawn sub-agents, and take real-world actions — but provide **no runtime security model**. The Agent Governance Toolkit provides:

- **Deterministic policy enforcement** before every agent action
- **Zero-trust identity** with cryptographic agent credentials
- **Execution isolation** with privilege rings and kill switches
- **Reliability engineering** with SLOs, error budgets, and chaos testing

Covers **10 of 10 [OWASP Agentic Top 10](https://owasp.org/www-project-agentic-ai-top-10/)** risks out of the box.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Agent Governance Toolkit                      │
│               pip install ai-agent-compliance[full]              │
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
│   │ Agent Hypervisor  │      │     Agent SRE             │     │
│   │                   │      │                           │     │
│   │  Execution Rings  │      │  SLO Engine + Error Budget│     │
│   │  Resource Limits  │      │  Replay & Chaos Testing   │     │
│   │  Runtime Sandboxing│     │  Progressive Delivery     │     │
│   │  Kill Switch      │      │  Circuit Breakers         │     │
│   └───────────────────┘      └───────────────────────────┘     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Packages

| Package | PyPI | Description |
|---------|------|-------------|
| **Agent OS** | [`agent-os-kernel`](https://pypi.org/project/agent-os-kernel/) | Kernel architecture — policy engine, capability model, audit logging, syscall interception, MCP gateway |
| **AgentMesh** | [`agentmesh-platform`](https://pypi.org/project/agentmesh-platform/) | Inter-agent trust — Ed25519 identity, SPIFFE/SVID credentials, trust scoring, A2A/MCP/IATP protocol bridges |
| **Agent Hypervisor** | [`agent-hypervisor`](https://pypi.org/project/agent-hypervisor/) | Execution isolation — 4-tier privilege rings, saga orchestration, kill switch, joint liability, hash-chain audit |
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
pip install agent-os-kernel    # Just the kernel
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
| Rogue Agents | ASI-10 | 🔄 Kill switch + quarantine (behavioral detection planned) |

## Documentation

- [OWASP Compliance Mapping](docs/OWASP-COMPLIANCE.md)
- [CSA Agentic Trust Framework Mapping](docs/CSA-ATF-PROPOSAL.md)
- [Changelog](CHANGELOG.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Support](SUPPORT.md)

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
