![Agent Governance Toolkit](docs/assets/readme-banner.svg)

# Welcome to Agent Governance Toolkit!

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-npm_%40agentmesh%2Fsdk-blue?logo=typescript)](packages/agent-mesh/sdks/typescript/)
[![.NET 8.0+](https://img.shields.io/badge/.NET_8.0+-NuGet-blue?logo=dotnet)](https://www.nuget.org/packages/Microsoft.AgentGovernance)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP_Agentic_Top_10-10%2F10_Covered-blue)](docs/OWASP-COMPLIANCE.md)
[![OpenSSF Best Practices](https://img.shields.io/cii/percentage/12085?label=OpenSSF%20Best%20Practices&logo=opensourcesecurity)](https://www.bestpractices.dev/projects/12085)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/microsoft/agent-governance-toolkit/badge)](https://scorecard.dev/viewer/?uri=github.com/microsoft/agent-governance-toolkit)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/microsoft/agent-governance-toolkit)

> [!IMPORTANT]
> **Public Preview** — All packages published from this repository are
> **Microsoft-signed public preview releases**. They are production-quality but
> may have breaking changes before GA. For feedback, please
> [open a GitHub issue](https://github.com/microsoft/agent-governance-toolkit/issues).
>
> **What this toolkit is:** Runtime governance infrastructure — deterministic policy
> enforcement, zero-trust identity, execution sandboxing, and reliability engineering
> that sits between your agent framework and the actions agents take.
>
> **What this toolkit is not:** This is not a model safety or prompt guardrails tool.
> It does not filter LLM inputs/outputs or perform content moderation. It governs
> *agent actions* (tool calls, resource access, inter-agent communication) at the
> application layer. For model-level safety, see
> [Azure AI Content Safety](https://learn.microsoft.com/azure/ai-services/content-safety/).

Runtimegovernance for AI agents — the only toolkit covering all **10 OWASP Agentic risks** with **9,500+ tests**. Governs what agents *do*, not just what they say — deterministic policy enforcement, zero-trust identity, execution sandboxing, and SRE — **Python · TypeScript · .NET**

> **Works with any stack** — AWS Bedrock, Google ADK, Azure AI, LangChain, CrewAI, AutoGen, OpenAI Agents, LlamaIndex, and more. Pure `pip install` with zero vendor lock-in.

## 📋 Getting Started

### 📦 Installation

**Python** (PyPI)
```bash
pip install agent-governance-toolkit[full]
```

**TypeScript / Node.js** (npm)
```bash
npm install @agentmesh/sdk
```

**.NET** (NuGet)
```bash
dotnet add package Microsoft.AgentGovernance
```

<details>
<summary>Install individual Python packages</summary>

```bash
pip install agent-os-kernel        # Policy engine
pip install agentmesh-platform     # Trust mesh
pip install agentmesh-runtime       # Runtime supervisor
pip install agent-sre              # SRE toolkit
pip install agent-governance-toolkit    # Compliance & attestation
pip install agentmesh-marketplace      # Plugin marketplace
pip install agentmesh-lightning        # RL training governance
```
</details>

### 📚 Documentation

- **[Quick Start](QUICKSTART.md)** — Get from zero to governed agents in 10 minutes (Python · TypeScript · .NET)
- **[TypeScript SDK](packages/agent-mesh/sdks/typescript/README.md)** — npm package with identity, trust, policy, and audit
- **[.NET SDK](packages/agent-governance-dotnet/README.md)** — NuGet package with full OWASP coverage
- **[Tutorials](docs/tutorials/)** — Step-by-step guides for policy, identity, integrations, compliance, SRE, and sandboxing
- **[Azure Deployment](docs/deployment/README.md)** — AKS, Azure AI Foundry, Container Apps, OpenClaw sidecar
- **[NVIDIA OpenShell Integration](docs/integrations/openshell.md)** — Combine sandbox isolation with governance intelligence
- **[OWASP Compliance](docs/OWASP-COMPLIANCE.md)** — Full ASI-01 through ASI-10 mapping
- **[Threat Model](docs/THREAT_MODEL.md)** — Trust boundaries, attack surfaces, and STRIDE analysis
- **[Architecture](docs/ARCHITECTURE.md)** — System design, security model, trust scoring
- **[Architecture Decisions](docs/adr/README.md)** — ADR log for key identity, runtime, and policy choices
- **[NIST RFI Mapping](docs/nist-rfi-mapping.md)** — Mapping to NIST AI Agent Security RFI (2026-00206)

Still have questions? File a [GitHub issue](https://github.com/microsoft/agent-governance-toolkit/issues) or see our [Community page](COMMUNITY.md).

### ✨ **Highlights**

- **Deterministic Policy Enforcement**: Every agent action evaluated against policy *before* execution at sub-millisecond latency (<0.1 ms)
  - [Policy Engine](packages/agent-os/) | [Benchmarks](BENCHMARKS.md)
- **Zero-Trust Agent Identity**: Ed25519 cryptographic credentials, SPIFFE/SVID support, trust scoring on a 0–1000 scale
  - [AgentMesh](packages/agent-mesh/) | [Trust Scoring](packages/agent-mesh/)
- **Execution Sandboxing**: 4-tier privilege rings, saga orchestration, termination control, kill switch
  - [Agent Runtime](packages/agent-runtime/) | [Agent Hypervisor](packages/agent-hypervisor/)
- **Agent SRE**: SLOs, error budgets, replay debugging, chaos engineering, circuit breakers, progressive delivery
  - [Agent SRE](packages/agent-sre/) | [Observability integrations](packages/agent-hypervisor/src/hypervisor/observability/)
- **12+ Framework Integrations**: Microsoft Agent Framework, LangChain, CrewAI, AutoGen, Dify, LlamaIndex, OpenAI Agents, Google ADK, and more
  - [Framework quickstarts](examples/quickstart/) | [Integration proposals](docs/proposals/)
- **Full OWASP Coverage**: 10/10 Agentic Top 10 risks addressed with dedicated controls for each ASI category
  - [OWASP Compliance](docs/OWASP-COMPLIANCE.md) | [Competitive Comparison](docs/COMPARISON.md)
- **GitHub Actions for CI/CD**: Automated security scanning and governance attestation for PR workflows
  - [Security Scan Action](action/security-scan/) | [Governance Attestation Action](action/governance-attestation/)

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

### Enforce a policy — TypeScript

```typescript
import { PolicyEngine } from "@agentmesh/sdk";

const engine = new PolicyEngine([
  { action: "web_search", effect: "allow" },
  { action: "shell_exec", effect: "deny" },
]);

const decision = engine.evaluate("web_search"); // "allow"
```

### Enforce a policy — .NET

```csharp
using AgentGovernance;
using AgentGovernance.Policy;

var kernel = new GovernanceKernel(new GovernanceOptions
{
    PolicyPaths = new() { "policies/default.yaml" },
});

var result = kernel.EvaluateToolCall(
    agentId: "did:mesh:researcher-1",
    toolName: "web_search",
    args: new() { ["query"] = "latest AI news" }
);

if (result.Allowed) { /* proceed */ }
```

### Run the governance demo

```bash
# Full governance demo (policy enforcement, audit, trust, cost, reliability)
python demo/maf_governance_demo.py

# Run with adversarial attack scenarios
python demo/maf_governance_demo.py --include-attacks
```

## More Examples & Samples

- **[Framework Quickstarts](examples/quickstart/)** — One-file governed agents for LangChain, CrewAI, AutoGen, OpenAI Agents, Google ADK
- **[Tutorial 1: Policy Engine](docs/tutorials/01-policy-engine.md)** — Define and enforce governance policies
- **[Tutorial 2: Trust & Identity](docs/tutorials/02-trust-and-identity.md)** — Zero-trust agent credentials
- **[Tutorial 3: Framework Integrations](docs/tutorials/03-framework-integrations.md)** — Add governance to any framework
- **[Tutorial 4: Audit & Compliance](docs/tutorials/04-audit-and-compliance.md)** — OWASP compliance and attestation
- **[Tutorial 5: Agent Reliability](docs/tutorials/05-agent-reliability.md)** — SLOs, error budgets, chaos testing
- **[Tutorial 6: Execution Sandboxing](docs/tutorials/06-execution-sandboxing.md)** — Privilege rings and termination

## OPA/Rego & Cedar Policy Support

Bring your existing infrastructure policies to agent governance — no new policy DSL required.

### OPA/Rego (Agent OS)

```python
from agent_os.policies import PolicyEvaluator

evaluator = PolicyEvaluator()
evaluator.load_rego(rego_content="""
package agentos
default allow = false
allow { input.tool_name == "web_search" }
allow { input.role == "admin" }
""")

decision = evaluator.evaluate({"tool_name": "web_search", "role": "analyst"})
# decision.allowed == True
```

### Cedar (Agent OS)

```python
from agent_os.policies import PolicyEvaluator

evaluator = PolicyEvaluator()
evaluator.load_cedar(policy_content="""
permit(principal, action == Action::"ReadData", resource);
forbid(principal, action == Action::"DeleteFile", resource);
""")

decision = evaluator.evaluate({"tool_name": "read_data", "agent_id": "agent-1"})
# decision.allowed == True
```

### AgentMesh OPA/Cedar

```python
from agentmesh.governance import PolicyEngine

engine = PolicyEngine()
engine.load_rego("policies/mesh.rego", package="agentmesh")
engine.load_cedar(cedar_content='permit(principal, action == Action::"Analyze", resource);')

decision = engine.evaluate("did:mesh:agent-1", {"tool_name": "analyze"})
```

Three evaluation modes per backend: **embedded engine** (cedarpy/opa CLI), **remote server**, or **built-in fallback** (zero external deps).

## SDKs & Packages

### Multi-Language SDKs

| Language | Package | Install |
|----------|---------|---------|
| **Python** | [`agent-governance-toolkit[full]`](https://pypi.org/project/agent-governance-toolkit/) | `pip install agent-governance-toolkit[full]` |
| **TypeScript** | [`@agentmesh/sdk`](packages/agent-mesh/sdks/typescript/) | `npm install @agentmesh/sdk` |
| **.NET** | [`Microsoft.AgentGovernance`](https://www.nuget.org/packages/Microsoft.AgentGovernance) | `dotnet add package Microsoft.AgentGovernance` |

### Python Packages (PyPI)

| Package | PyPI | Description |
|---------|------|-------------|
| **Agent OS** | [`agent-os-kernel`](https://pypi.org/project/agent-os-kernel/) | Policy engine — deterministic action evaluation, capability model, audit logging, action interception, MCP gateway |
| **AgentMesh** | [`agentmesh-platform`](https://pypi.org/project/agentmesh-platform/) | Inter-agent trust — Ed25519 identity, SPIFFE/SVID credentials, trust scoring, A2A/MCP/IATP protocol bridges |
| **Agent Runtime** | [`agentmesh-runtime`](packages/agent-runtime/) | Execution supervisor — 4-tier privilege rings, saga orchestration, termination control, joint liability, append-only audit log |
| **Agent SRE** | [`agent-sre`](https://pypi.org/project/agent-sre/) | Reliability engineering — SLOs, error budgets, replay debugging, chaos engineering, progressive delivery |
| **Agent Compliance** | [`agent-governance-toolkit`](https://pypi.org/project/agent-governance-toolkit/) | Runtime policy enforcement — OWASP ASI 2026 controls, governance attestation, integrity verification |
| **Agent Marketplace** | [`agentmesh-marketplace`](packages/agent-marketplace/) | Plugin lifecycle — discover, install, verify, and sign plugins |
| **Agent Lightning** | [`agentmesh-lightning`](packages/agent-lightning/) | RL training governance — governed runners, policy rewards |

## Framework Integrations

Works with **12+ agent frameworks** including:

| Framework | Stars | Integration |
|-----------|-------|-------------|
| [**Microsoft Agent Framework**](https://github.com/microsoft/agent-framework) | 8K+ ⭐ | **Native Middleware** |
| [**Semantic Kernel**](https://github.com/microsoft/semantic-kernel) | 27K+ ⭐ | **Native (.NET + Python)** |
| [Dify](https://github.com/langgenius/dify) | 133K+ ⭐ | Plugin |
| [Microsoft AutoGen](https://github.com/microsoft/autogen) | 55K+ ⭐ | Adapter |
| [LlamaIndex](https://github.com/run-llama/llama_index) | 47K+ ⭐ | Middleware |
| [CrewAI](https://github.com/crewAIInc/crewAI) | 46K+ ⭐ | Adapter |
| [LangGraph](https://github.com/langchain-ai/langgraph) | 27K+ ⭐ | Adapter |
| [Haystack](https://github.com/deepset-ai/haystack) | 24K+ ⭐ | Pipeline |
| [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) | 20K+ ⭐ | Middleware |
| [Google ADK](https://github.com/google/adk-python) | 18K+ ⭐ | Adapter |
| [Azure AI Foundry](https://learn.microsoft.com/azure/ai-studio/) | — | Deployment Guide |

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

Full mapping with implementation details and test evidence: **[OWASP-COMPLIANCE.md](docs/OWASP-COMPLIANCE.md)**

### Regulatory Alignment

| Regulation | Deadline | AGT Coverage |
|------------|----------|-------------|
| EU AI Act — High-Risk AI (Annex III) | August 2, 2026 | Audit trails (Art. 12), risk management (Art. 9), human oversight (Art. 14) |
| Colorado AI Act (SB 24-205) | June 30, 2026 | Risk assessments, human oversight mechanisms, consumer disclosures |
| EU AI Act — GPAI Obligations | Active | Transparency, copyright policies, systemic risk assessment |

AGT provides **runtime governance** — what agents are allowed to do. For **data governance** and regulator-facing evidence export, see [Microsoft Purview DSPM for AI](https://learn.microsoft.com/purview/ai-microsoft-purview) as a complementary layer.

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

## Security Model & Limitations

This toolkit provides **application-level (Python middleware) governance**, not OS kernel-level isolation. The policy engine and the agents it governs run in the **same Python process**. This is the same trust boundary used by every Python-based agent framework (LangChain, CrewAI, AutoGen, etc.).

| Layer | What It Provides | What It Does NOT Provide |
|-------|-----------------|------------------------|
| Policy Engine | Deterministic action interception, deny-list enforcement | Hardware-level memory isolation |
| Identity (IATP) | Ed25519 cryptographic agent credentials, trust scoring | OS-level process separation |
| Execution Rings | Logical privilege tiers with resource limits | CPU ring-level enforcement |
| Bootstrap Integrity | SHA-256 tamper detection of governance modules at startup | Hardware root-of-trust (TPM/Secure Boot) |

**Production recommendations:**
- Run each agent in a **separate container** for OS-level isolation
- All security policy rules ship as **configurable sample configurations** — review and customize for your environment (see `examples/policies/`)
- No built-in rule set should be considered exhaustive
- For details see [Architecture — Security Model & Boundaries](docs/ARCHITECTURE.md)

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
