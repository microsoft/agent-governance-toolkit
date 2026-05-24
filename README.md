🌍 [English](/README.md) | [日本語](./docs/i18n/README.ja.md) | [简体中文](./docs/i18n/README.zh-CN.md) | [한국어](./docs/i18n/README.ko.md)

![Agent Governance Toolkit](docs/assets/readme-banner.svg)

# Agent Governance Toolkit

### Ship agents to production without losing sleep

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

Policy enforcement, identity, sandboxing, and SRE for autonomous AI agents. One `pip install`, any framework.

---

## The Problem

Your AI agents call tools, browse the web, query databases, and delegate to other agents. Once deployed, they make decisions autonomously. You need answers to three questions:

**1. Is this action allowed?** An agent with access to `send_email` and `query_database` should not be able to `drop_table`. OAuth scopes and IAM roles control which services an agent can reach, not what it does once connected.

**2. Which agent did this?** In a multi-agent system, five agents might share a single API key. When something goes wrong, "an agent did it" is not an incident response.

**3. Can you prove what happened?** Auditors and regulators need tamper-evident records of every decision: what policy was active, what the agent requested, and why it was allowed or denied.

Prompt-based safety ("please follow the rules") has a [26.67% policy violation rate](docs/BENCHMARKS.md) in red-team testing. AGT's application-layer enforcement: **0.00%**.

---

## Quick Start

**Prerequisites:** Python 3.10+

```bash
pip install agent-governance-toolkit
```

Govern any tool function in two lines:

```python
from agentmesh.governance import govern

safe_tool = govern(my_tool, policy="policy.yaml")   # every call checked, logged, enforced
```

That's it. `safe_tool` evaluates your YAML policy on every call, logs the decision, and raises `GovernanceDenied` if the action is blocked.

```yaml
# policy.yaml
apiVersion: governance.toolkit/v1
name: production-policy
default_action: allow
rules:
  - name: block-destructive
    condition: "action.type in ['drop', 'delete', 'truncate']"
    action: deny
    description: "Destructive operations require human approval"

  - name: require-approval-for-send
    condition: "action.type == 'send_email'"
    action: require_approval
    approvers: ["security-team"]
```

```python
>>> safe_tool(action="read", table="users")
{'table': 'users', 'rows': 42}

>>> safe_tool(action="drop", table="users")
GovernanceDenied: Action denied by policy rule 'block-destructive':
  Destructive operations require human approval
```

Or use the full `PolicyEvaluator` API for programmatic control:

<details>
<summary><b>PolicyEvaluator example</b></summary>

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

result = evaluator.evaluate({"tool_name": "web_search"})    # Allowed
result = evaluator.evaluate({"tool_name": "delete_file"})   # Blocked
```

</details>

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

## How It Works

```
Agent ──► Policy Engine ──► Identity ──► Audit Log
            (YAML/OPA/Cedar)  (SPIFFE/DID/mTLS)  (Tamper-evident)
                 │                                      │
                 ├── Allowed ──► Tool executes           │
                 └── Denied  ──► GovernanceDenied        │
                                                        ▼
                                                 Decision Record
```

Every layer is optional. Start with `govern()` and add layers as your risk profile grows. Most teams run policy enforcement + audit logging and never need the full stack.

---

## Packages

| Package | Description |
|---------|-------------|
| [**Agent OS**](agent-governance-python/agent-os/) | Policy engine, agent lifecycle, governance gate |
| [**Agent Mesh**](agent-governance-python/agent-mesh/) | Agent discovery, routing, and trust mesh |
| [**Agent Runtime**](agent-governance-python/agent-runtime/) | Execution sandboxing with four privilege rings |
| [**Agent SRE**](agent-governance-python/agent-sre/) | Kill switch, SLO monitoring, chaos testing |
| [**Agent Compliance**](agent-governance-python/agent-compliance/) | OWASP verification, policy linting, integrity checks |
| [**Agent Marketplace**](agent-governance-python/agent-marketplace/) | Plugin governance and trust scoring |
| [**Agent Lightning**](agent-governance-python/agent-lightning/) | RL training governance with violation penalties |
| [**Agent Hypervisor**](agent-governance-python/agent-hypervisor/) | Execution audit, delta engine, commitment anchoring |

### Additional Capabilities

| Capability | Description |
|---|---|
| **MCP Security Gateway** | Tool poisoning detection, drift monitoring, typosquatting, hidden instruction scanning ([Spec](docs/specs/MCP-SECURITY-GATEWAY-1.0.md)) |
| **Shadow AI Discovery** | Find unregistered agents across processes, configs, and repos ([Discovery](agent-governance-python/agent-discovery/)) |
| **Governance Dashboard** | Real-time fleet visibility for health, trust, and compliance ([Dashboard](examples/demos/governance-dashboard/)) |
| **PromptDefense Evaluator** | 12-vector prompt injection audit ([Evaluator](agent-governance-python/agent-compliance/src/agent_compliance/prompt_defense.py)) |
| **Contributor Reputation** | PR/issue author screening for social engineering. Reusable GitHub Action ([Action](.github/actions/contributor-check/)) |

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

All five language SDKs implement core governance (policy, identity, trust, audit). Python has the full stack. Copilot CLI and Claude Code are first-party developer surfaces built on the TypeScript SDK.
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

### Prerequisites

- **Python**: 3.10+
- **Node.js**: 18+ / npm 9+ (TypeScript SDK)
- **.NET**: 8+
- **Go**: 1.25+
- **Rust**: 1.70+
- **Optional**: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET` for Azure-integrated features

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
| [Mastra](https://github.com/mastra-ai/mastra) | Adapter |
| [Dify](https://github.com/langgenius/dify) | Plugin |
| [Azure AI Foundry](https://learn.microsoft.com/azure/ai-studio/) | Deployment Guide |
| GitHub Copilot CLI | Governance installer |

Full list: [Framework Integrations](agent-governance-python/agentmesh-integrations/) · [Quickstart Examples](examples/quickstart/)

---

## Examples

| Example | Framework | What it demonstrates |
|---------|-----------|----------------------|
| [openai-agents-governed](examples/openai-agents-governed) | OpenAI Agents SDK | Policy-gated tool calls with trust tiers |
| [crewai-governed](examples/crewai-governed) | CrewAI | Multi-agent governance with role-based policies |
| [smolagents-governed](examples/smolagents-governed) | HuggingFace smolagents | Lightweight agent governance |
| [maf-integration](examples/maf-integration) | MAF | Microsoft Agent Framework integration |
| [mcp-trust-verified-server](examples/mcp-trust-verified-server) | MCP | Trust-verified MCP server implementation |
| [cedarling-governed](examples/cedarling-governed) | Cedar/Cedarling | Janssen Cedarling policy engine integration |
| [governance-dashboard](examples/demos/governance-dashboard) | Streamlit | Real-time fleet visibility dashboard |

---

## Specifications

Every major component has a formal RFC 2119 specification with conformance tests. These specs define the behavioral contract: what implementations MUST, SHOULD, and MAY do.

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

## Standards Compliance

| Standard | Coverage |
|----------|----------|
| [OWASP Agentic AI Top 10](docs/OWASP-COMPLIANCE.md) | All 10 risks covered with deterministic controls |
| [NIST AI RMF 1.0](docs/compliance/nist-ai-rmf-alignment.md) | Full GOVERN, MAP, MEASURE, MANAGE alignment |
| [EU AI Act](docs/compliance/) | Compliance mapping with automated evidence |
| [SOC 2](docs/compliance/soc2-mapping.md) | Control mapping with audit trail export |

---

## Security

AGT enforces governance at the application middleware layer, not at the OS kernel level. The policy engine and agents share the same process boundary.

**Production recommendation:** Run each agent in a separate container for OS-level isolation. See [Architecture: Security Boundaries](docs/ARCHITECTURE.md).

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
| **Architecture** | [System Design](docs/ARCHITECTURE.md) · [Threat Model](docs/security/threat-model.md) · [ADRs](docs/adr/) (25) |
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
