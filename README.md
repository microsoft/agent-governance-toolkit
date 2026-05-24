🌍 [English](/README.md) | [日本語](./docs/i18n/README.ja.md) | [简体中文](./docs/i18n/README.zh-CN.md) | [한국어](./docs/i18n/README.ko.md)

![Agent Governance Toolkit](docs/assets/readme-banner.svg)

# Agent Governance Toolkit

<p align="center">
  <a href="https://microsoft.github.io/agent-governance-toolkit">
    <img src="https://img.shields.io/badge/%F0%9F%93%96_Full_Documentation-microsoft.github.io%2Fagent--governance--toolkit-0078D4?style=for-the-badge&logoColor=white" alt="Full Documentation" height="40">
  </a>
</p>

<p align="center">
  <strong>
    🚀 <a href="#quick-start">Quick Start</a> ·
    📋 <a href="#specifications">Specifications</a> ·
    📦 <a href="https://pypi.org/project/agent-governance-toolkit/">PyPI</a> ·
    📝 <a href="CHANGELOG.md">Changelog</a>
  </strong>
</p>

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/agent-governance-toolkit?label=PyPI)](https://pypi.org/project/agent-governance-toolkit/)
[![npm](https://img.shields.io/npm/v/%40microsoft/agent-governance-sdk?label=npm)](https://www.npmjs.com/package/@microsoft/agent-governance-sdk)
[![NuGet](https://img.shields.io/nuget/v/Microsoft.AgentGovernance?label=NuGet)](https://www.nuget.org/packages/Microsoft.AgentGovernance)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/microsoft/agent-governance-toolkit/badge)](https://scorecard.dev/viewer/?uri=github.com/microsoft/agent-governance-toolkit)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12085/badge)](https://www.bestpractices.dev/projects/12085)
[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP_Agentic_Top_10-10%2F10_Covered-blue)](docs/OWASP-COMPLIANCE.md)

> [!IMPORTANT]
> **Public Preview** -- production-quality, Microsoft-signed releases. May have breaking changes before GA.

Runtime governance for AI agents. Every tool call, resource access, and inter-agent message is evaluated against policy *before* execution -- deterministic, sub-millisecond, and auditable.

```
Agent Action ──► Policy Check ──► Allow / Deny ──► Audit Log    (< 0.1 ms)
```

Prompt-based safety ("please follow the rules") has a [26.67% policy violation rate](docs/BENCHMARKS.md) in red-team testing. AGT's application-layer enforcement: **0.00%**.

Python · TypeScript · .NET · Rust · Go. Works with LangChain, CrewAI, AutoGen, OpenAI Agents, Google ADK, Semantic Kernel, AWS Bedrock, and [20+ more](#framework-support).

---

## Prerequisites

- **Python**: `pip install agent-governance-toolkit[full]` requires Python 3.10+
- **Node.js**: For TypeScript SDK, Node.js 18+ and npm 9+
- **.NET**: .NET 8+ for the .NET SDK
- **Go**: Go 1.25+ for the Go SDK
- **Rust**: Rust 1.70+ for the Rust SDK

### Optional dependencies

- **Azure credentials**: Set `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET` for Azure-integrated features
- **MCP SDK**: For Model Context Protocol integrations

## Quick Start

**Prerequisites:** Python 3.10+ required.

```bash
pip install agent-governance-toolkit
```

Govern any tool function in two lines:

```python
from agentmesh.governance import govern

safe_tool = govern(my_tool, policy="policy.yaml")   # every call checked, logged, enforced
```

Or use the full `PolicyEvaluator` API for programmatic control:

```python
from agent_os.policies import (
    PolicyEvaluator, PolicyDocument, PolicyRule,
    PolicyCondition, PolicyAction, PolicyOperator, PolicyDefaults
)

evaluator = PolicyEvaluator(policies=[PolicyDocument(
    name="my-policy", version="1.0",
    defaults=PolicyDefaults(action=PolicyAction.ALLOW),
    rules=[PolicyRule(
        name="block-dangerous-tools",
        condition=PolicyCondition(
            field="tool_name",
            operator=PolicyOperator.IN,
            value=["execute_code", "delete_file"]
        ),
        action=PolicyAction.DENY, priority=100,
    )],
)])

result = evaluator.evaluate({"tool_name": "web_search"})    # ✅ Allowed
result = evaluator.evaluate({"tool_name": "delete_file"})   # ❌ Blocked
```

<details>
<summary><b>TypeScript / .NET / Rust / Go examples</b></summary>

**TypeScript**
```typescript
import { PolicyEngine } from "@microsoft/agent-governance-sdk";

const engine = new PolicyEngine([
  { action: "web_search", effect: "allow" },
  { action: "shell_exec", effect: "deny" },
]);
engine.evaluate("web_search"); // "allow"
engine.evaluate("shell_exec"); // "deny"
```

**.NET**
```csharp
using AgentGovernance;
using AgentGovernance.Extensions.ModelContextProtocol;
using AgentGovernance.Policy;

var kernel = new GovernanceKernel(new GovernanceOptions
{
    PolicyPaths = new() { "policies/default.yaml" },
});
var result = kernel.EvaluateToolCall("did:mesh:agent-1", "web_search",
    new() { ["query"] = "latest AI news" });

// MCP server integration
builder.Services.AddMcpServer()
    .WithGovernance(options => options.PolicyPaths.Add("policies/mcp.yaml"));
```

**Rust**
```rust
use agent_governance::{AgentMeshClient, ClientOptions};

let client = AgentMeshClient::new("my-agent").unwrap();
let result = client.execute_with_governance("data.read", None);
assert!(result.allowed);
```

**Go**
```go
import agentmesh "github.com/microsoft/agent-governance-toolkit/agent-governance-golang"

client, _ := agentmesh.NewClient("my-agent",
    agentmesh.WithPolicyRules([]agentmesh.PolicyRule{
        {Action: "data.read", Effect: agentmesh.Allow},
        {Action: "*", Effect: agentmesh.Deny},
    }),
)
result := client.ExecuteWithGovernance("data.read", nil)
```

</details>

CLI tools:

```bash
agt doctor                                        # check installation
agt verify                                        # OWASP compliance check
agt verify --evidence ./agt-evidence.json --strict # fail CI on weak evidence
agt red-team scan ./prompts/ --min-grade B         # prompt injection audit
agt lint-policy policies/                          # validate policy files
```

Full walkthrough: [quickstart.md](docs/quickstart.md) -- zero to governed agents in 5 minutes.
🌍 Also in: [日本語](docs/i18n/quickstart.ja.md) | [简体中文](docs/i18n/quickstart.zh-CN.md) | [한국어](docs/i18n/quickstart.ko.md)

---

## Core Capabilities

### Policy Engine
Deterministic allow/deny evaluation for every agent action. Sub-millisecond latency (0.012ms p50 for single rule, 35K ops/sec concurrent). Supports YAML, OPA/Rego, and Cedar policy languages. Fail-closed by default -- if the engine errors, the action is denied.

[Agent OS](agent-governance-python/agent-os/) · [Benchmarks](docs/BENCHMARKS.md) · [Spec](docs/specs/AGENT-OS-POLICY-ENGINE-1.0.md)

### Zero-Trust Identity
Ed25519 + quantum-safe ML-DSA-65 agent credentials. Behavioral trust scoring (0--1000) that decays when agents act outside expected patterns. SPIFFE/SVID compatible. Trust ceilings propagate through delegation chains -- a delegated agent can never exceed its parent's trust level.

[AgentMesh](agent-governance-python/agent-mesh/) · [Spec](docs/specs/AGENTMESH-IDENTITY-TRUST-1.0.md)

### Execution Sandboxing
Four privilege rings (kernel, supervisor, user, untrusted) with hardware-style isolation semantics. Saga orchestration for multi-step workflows with automatic compensation on failure. Kill switch for immediate agent termination.

[Runtime](agent-governance-python/agent-runtime/) · [Hypervisor](agent-governance-python/agent-hypervisor/) · [Spec](docs/specs/AGENT-HYPERVISOR-EXECUTION-CONTROL-1.0.md)

### Agent SRE
SLOs, error budgets, replay debugging, chaos engineering, and circuit breakers for agent fleets. OTel-native observability with structured governance events.

[Agent SRE](agent-governance-python/agent-sre/) · [Spec](docs/specs/AGENT-SRE-GOVERNANCE-1.0.md)

### Audit and Compliance
Tamper-evident Merkle-chained audit logs. Reconstructible Decision BOMs from observability signals. Automated compliance mapping for EU AI Act, SOC 2, HIPAA, and GDPR. CloudEvents export for SIEM integration.

[Compliance](agent-governance-python/agent-mesh/src/agentmesh/governance/) · [Spec](docs/specs/AUDIT-COMPLIANCE-1.0.md)

### MCP Security Gateway
Tool poisoning detection, description drift monitoring, typosquatting checks, and hidden instruction scanning for MCP tool definitions.

[MCP Scanner](agent-governance-python/agent-os/src/agent_os/mcp_security.py) · [Spec](docs/specs/MCP-SECURITY-GATEWAY-1.0.md)

### Additional Capabilities

| Capability | Description |
|---|---|
| **Inter-Agent Trust** | Mesh-wide trust negotiation, peer signature verification, coordinated policy enforcement ([Spec](docs/specs/AGENTMESH-TRUST-COORDINATION-1.0.md)) |
| **RL Training Governance** | Violation penalties in reward signals, episode termination on critical violations ([Spec](docs/specs/AGENT-LIGHTNING-FAST-PATH-1.0.md)) |
| **Framework Adapters** | 10 adapters with unified governance interceptor chain ([Spec](docs/specs/FRAMEWORK-ADAPTER-CONTRACT-1.0.md)) |
| **Shadow AI Discovery** | Find unregistered agents across processes, configs, and repos ([Discovery](agent-governance-python/agent-discovery/)) |
| **Agent Lifecycle** | Provisioning, credential rotation, orphan detection, decommissioning ([Lifecycle](agent-governance-python/agent-mesh/src/agentmesh/lifecycle/)) |
| **Governance Dashboard** | Real-time fleet visibility for health, trust, and compliance ([Dashboard](examples/demos/governance-dashboard/)) |
| **PromptDefense Evaluator** | 12-vector prompt injection audit ([Evaluator](agent-governance-python/agent-compliance/src/agent_compliance/prompt_defense.py)) |
| **Contributor Reputation** | PR/issue author screening for social engineering. Reusable GitHub Action ([Action](.github/actions/contributor-check/)) |

---

## Specifications

Every major component has a formal RFC 2119 specification with conformance tests. These specs define the behavioral contract -- what implementations MUST, SHOULD, and MAY do.

| Specification | Scope | Tests |
|---|---|---|
| [Agent OS Policy Engine](docs/specs/AGENT-OS-POLICY-ENGINE-1.0.md) | Policy evaluation, rule merging, fail-closed semantics | 68 |
| [AgentMesh Identity and Trust](docs/specs/AGENTMESH-IDENTITY-TRUST-1.0.md) | Credentials, trust scoring, delegation chains | 135 |
| [Agent Hypervisor Execution Control](docs/specs/AGENT-HYPERVISOR-EXECUTION-CONTROL-1.0.md) | Privilege rings, saga orchestration, kill switch | 80 |
| [AgentMesh Trust and Coordination](docs/specs/AGENTMESH-TRUST-COORDINATION-1.0.md) | Peer trust negotiation, mesh-wide policy | 62 |
| [Agent SRE Governance](docs/specs/AGENT-SRE-GOVERNANCE-1.0.md) | SLOs, error budgets, chaos, circuit breakers | 111 |
| [MCP Security Gateway](docs/specs/MCP-SECURITY-GATEWAY-1.0.md) | Tool poisoning, drift detection, hidden instructions | 127 |
| [Agent Lightning Fast-Path](docs/specs/AGENT-LIGHTNING-FAST-PATH-1.0.md) | RL training governance, violation penalties | 100 |
| [Framework Adapter Contract](docs/specs/FRAMEWORK-ADAPTER-CONTRACT-1.0.md) | 10 adapter integrations, interceptor chain | 152 |
| [Audit and Compliance](docs/specs/AUDIT-COMPLIANCE-1.0.md) | Merkle audit, compliance mapping, Decision BOM | 157 |
| [AgentMesh Wire Protocol](docs/specs/AGENTMESH-WIRE-1.0.md) | Message format, routing, serialization | -- |

**992 conformance tests** ensure code stays aligned to specs. [25 Architecture Decision Records](docs/adr/) document why.

---

## Framework Support

| Framework | Integration |
|-----------|-------------|
| [**Microsoft Agent Framework**](https://github.com/microsoft/agent-framework) | Native Middleware |
| [**Semantic Kernel**](https://github.com/microsoft/semantic-kernel) | Native (.NET + Python) |
| [AutoGen](https://github.com/microsoft/autogen) | Adapter |
| [LangGraph](https://github.com/langchain-ai/langgraph) / [LangChain](https://github.com/langchain-ai/langchain) | Adapter |
| [CrewAI](https://github.com/crewAIInc/crewAI) | Adapter |
| [OpenAI Agents SDK](https://github.com/openai/openai-agents-python) | Middleware |
| Claude Code | Governance plugin package |
| [Google ADK](https://github.com/google/adk-python) | Adapter |
| [LlamaIndex](https://github.com/run-llama/llama_index) | Middleware |
| [Haystack](https://github.com/deepset-ai/haystack) | Pipeline |
| [Dify](https://github.com/langgenius/dify) | Plugin |
| [Azure AI Foundry](https://learn.microsoft.com/azure/ai-studio/) | Deployment Guide |
| GitHub Copilot CLI | Governance installer |

Full list: [Framework Integrations](agent-governance-python/agentmesh-integrations/) · [Quickstart Examples](examples/quickstart/)

---

## OWASP Agentic Top 10

AGT covers all 10 risks identified in the [OWASP Agentic Security Top 10](docs/OWASP-COMPLIANCE.md):

| Risk | AGT Control |
|------|-------------|
| ASI-01 Agent Goal Hijack | Policy engine blocks unauthorized goal changes |
| ASI-02 Tool Misuse & Exploitation | Capability model enforces least-privilege |
| ASI-03 Identity & Privilege Abuse | Zero-trust identity with Ed25519 + ML-DSA-65 |
| ASI-04 Agentic Supply Chain Vulnerabilities | Dependency-confusion scanning + tool verification |
| ASI-05 Unexpected Code Execution | 4-tier execution rings + sandboxing |
| ASI-06 Memory & Context Poisoning | Episodic memory with integrity checks |
| ASI-07 Insecure Inter-Agent Communication | Encrypted channels + trust gates |
| ASI-08 Cascading Agent Failures | Circuit breakers + SLO enforcement |
| ASI-09 Human-Agent Trust Exploitation | Full audit trails + flight recorder |
| ASI-10 Rogue Agents | Kill switch + ring isolation + anomaly detection |

Regulatory alignment: [EU AI Act](docs/compliance/) · [NIST AI RMF](docs/compliance/nist-ai-rmf-alignment.md) · [SOC 2](docs/compliance/soc2-mapping.md)

---

## Install

| Language | Package | Command |
|----------|---------|---------|
| **Python** | [`agent-governance-toolkit`](https://pypi.org/project/agent-governance-toolkit/) | `pip install agent-governance-toolkit[full]` |
| **TypeScript** | [`@microsoft/agent-governance-sdk`](agent-governance-typescript/) | `npm install @microsoft/agent-governance-sdk` |
| **Copilot CLI** | [`@microsoft/agent-governance-copilot-cli`](agent-governance-copilot-cli/) | `npx @microsoft/agent-governance-copilot-cli install` |
| **Claude Code** | [`@microsoft/agent-governance-claude-code`](agent-governance-claude-code/) | `claude --plugin-dir ./agent-governance-claude-code` |
| **.NET** | [`Microsoft.AgentGovernance`](https://www.nuget.org/packages/Microsoft.AgentGovernance) | `dotnet add package Microsoft.AgentGovernance` |
| **.NET MCP** | `Microsoft.AgentGovernance.Extensions.ModelContextProtocol` | `dotnet add package Microsoft.AgentGovernance.Extensions.ModelContextProtocol` |
| **Rust** | [`agent-governance`](https://crates.io/crates/agent-governance) | `cargo add agent-governance` |
| **Go** | [`agent-governance-toolkit`](agent-governance-golang/) | `go get github.com/microsoft/agent-governance-toolkit/agent-governance-golang` |

All five language packages implement core governance (policy, identity, trust, audit). Python has the full stack, and the Copilot CLI and Claude Code packages are first-party local developer surfaces built on the TypeScript SDK.
See **[Language Package Matrix](docs/PACKAGE-FEATURE-MATRIX.md)** for detailed per-language coverage.

<details>
<summary><b>Individual Python packages</b></summary>

| Package | PyPI | Description |
|---------|------|-------------|
| Agent OS | [`agent-os-kernel`](https://pypi.org/project/agent-os-kernel/) | Policy engine, capability model, audit logging, MCP gateway |
| AgentMesh | [`agentmesh-platform`](https://pypi.org/project/agentmesh-platform/) | Zero-trust identity, trust scoring, A2A/MCP/IATP bridges |
| Agent Runtime | [`agentmesh-runtime`](agent-governance-python/agent-runtime/) | Privilege rings, saga orchestration, termination control |
| Agent SRE | [`agent-sre`](https://pypi.org/project/agent-sre/) | SLOs, error budgets, chaos engineering, circuit breakers |
| Agent Compliance | [`agent-governance-toolkit`](https://pypi.org/project/agent-governance-toolkit/) | OWASP verification, integrity checks, policy linting |
| Agent Discovery | [`agent-discovery`](agent-governance-python/agent-discovery/) | Shadow AI discovery, inventory, risk scoring |
| Agent Hypervisor | [`agent-hypervisor`](agent-governance-python/agent-hypervisor/) | Execution plan validation, reversibility verification |
| Agent Marketplace | [`agentmesh-marketplace`](agent-governance-python/agent-marketplace/) | Plugin lifecycle management |
| Agent Lightning | [`agentmesh-lightning`](agent-governance-python/agent-lightning/) | RL training governance |

</details>

---

## Security

AGT enforces governance at the Python middleware layer, not at the OS kernel level. The policy engine and agents share the same process boundary.

**Production recommendation:** Run each agent in a separate container for OS-level isolation. See [Architecture -- Security Boundaries](docs/ARCHITECTURE.md).

| Tool | Coverage |
|------|----------|
| CodeQL | Python + TypeScript SAST |
| Gitleaks | Secret scanning on PR/push/weekly |
| ClusterFuzzLite | 7 fuzz targets (policy, injection, MCP, sandbox, trust) |
| Dependabot | 13 ecosystems |
| OpenSSF Scorecard | Weekly scoring + SARIF upload |

See [Known Limitations](docs/LIMITATIONS.md) for honest design boundaries and recommended layered defense.

---

## Documentation

| Category | Links |
|----------|-------|
| **Getting Started** | [Quick Start](docs/quickstart.md) · [Tutorials](docs/tutorials/) (60+) · [FAQ](docs/FAQ.md) |
| **Architecture** | [System Design](docs/ARCHITECTURE.md) · [Threat Model](docs/THREAT_MODEL.md) · [ADRs](docs/adr/) (25) |
| **Specifications** | [All Specs](docs/specs/) (10 formal specs, 992 conformance tests) |
| **API Reference** | [Agent OS](agent-governance-python/agent-os/README.md) · [AgentMesh](agent-governance-python/agent-mesh/README.md) · [Agent SRE](agent-governance-python/agent-sre/README.md) |
| **Compliance** | [OWASP](docs/OWASP-COMPLIANCE.md) · [EU AI Act](docs/compliance/) · [NIST AI RMF](docs/compliance/nist-ai-rmf-alignment.md) · [SOC 2](docs/compliance/soc2-mapping.md) |
| **Deployment** | [Azure](docs/deployment/README.md) · [AWS](docs/deployment/README.md) · [GCP](docs/deployment/README.md) · [Docker Compose](docs/deployment/README.md) |
| **Extensions** | [VS Code](agent-governance-typescript/agent-os-vscode/) · [Framework Integrations](agent-governance-python/agentmesh-integrations/) |

---

## Contributing

[Contributing Guide](CONTRIBUTING.md) · [Community](docs/COMMUNITY.md) · [Security Policy](SECURITY.md) · [Changelog](CHANGELOG.md)

**Using AGT?** Add your organization to [ADOPTERS.md](docs/ADOPTERS.md).

## Governance

| Document | Purpose |
|----------|---------|
| [GOVERNANCE.md](GOVERNANCE.md) | Decision-making, roles, contributor ladder |
| [CHARTER.md](docs/CHARTER.md) | Technical charter (LF Projects format) |
| [MAINTAINERS.md](MAINTAINERS.md) | Maintainers and organizations |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting and response SLAs |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Microsoft Open Source Code of Conduct |
| [ANTITRUST.md](ANTITRUST.md) | Competition law guidelines for participants |
| [TRADEMARKS.md](TRADEMARKS.md) | Trademark usage policy |

## Important Notes

If you use the Agent Governance Toolkit to build applications that operate with third-party agent frameworks or services, you do so at your own risk. We recommend reviewing all data being shared with third-party services and being cognizant of third-party practices for retention and location of data.

## License

This project is licensed under the [MIT License](LICENSE).

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
