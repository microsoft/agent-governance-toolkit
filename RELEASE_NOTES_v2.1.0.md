# Agent Governance Toolkit v2.1.0

> [!IMPORTANT]
> **Community Preview Release** — This release is for testing and evaluation purposes only.
> Packages published to PyPI, npm, and NuGet are **not** official Microsoft-signed releases.
> Official Microsoft-signed packages via ESRP Release will be available in a future release.

**The missing security layer for AI agents — now in Python, TypeScript, and .NET.**

Runtime policy enforcement, zero-trust identity, execution sandboxing, and SRE — 10/10 OWASP Agentic Top 10 coverage with 6,100+ tests across three languages.

## 🚀 What's New

### Multi-Language SDK Readiness

The toolkit is now a **polyglot governance layer**. All three SDKs have first-class install instructions, quickstart code, and package metadata ready for registry publishing.

| Language | Package | Install |
|----------|---------|---------|
| **Python** | [`agent-governance-toolkit[full]`](https://pypi.org/project/agent-governance-toolkit/) | `pip install agent-governance-toolkit[full]` |
| **TypeScript** | [`@microsoft/agentmesh-sdk`](https://www.npmjs.com/package/@microsoft/agentmesh-sdk) | `npm install @microsoft/agentmesh-sdk` |
| **.NET** | [`Microsoft.AgentGovernance`](https://www.nuget.org/packages/Microsoft.AgentGovernance) | `dotnet add package Microsoft.AgentGovernance` |

### TypeScript SDK Full Parity (1.0.0)

The TypeScript SDK now has full feature parity with the Python PolicyEngine and AgentIdentity:

- **PolicyEngine** — rich policy evaluation with 4 conflict resolution strategies, expression evaluator (equality, inequality, numeric, in/not-in, boolean, and/or, nested paths), rate limiting, YAML/JSON policy document loading
- **AgentIdentity** — Ed25519 cryptographic identity with lifecycle management (active/suspended/revoked), capability wildcards, delegation chains, JWK/JWKS import/export, W3C DID Document export
- **IdentityRegistry** — agent registry with cascade revocation
- **PolicyConflictResolver** — 4 strategies: deny-overrides, allow-overrides, priority-first-match, most-specific-wins
- **136 tests** passing (57 existing + 79 new parity tests)

### .NET SDK Hardened for NuGet

Enhanced NuGet package metadata — authors, license, repository URL, package tags, and readme now included in the `.csproj`. The .NET SDK covers all 10 OWASP Agentic risks with policy enforcement, execution rings, saga orchestration, circuit breakers, SLO tracking, prompt injection detection, and OpenTelemetry metrics.

### Framework Integrations Expanded

Now supports **13+ agent frameworks** including new entries:

- **Semantic Kernel** — Native (.NET + Python) integration
- **Azure AI Foundry** — Deployment guide for agent governance in Foundry Agent Service

Plus existing integrations: Microsoft Agent Framework, LangChain, LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, Google ADK, Dify, LlamaIndex, Haystack.

### Performance Benchmarks Published

| Metric | Latency (p50) | Throughput |
|---|---|---|
| Policy evaluation (1 rule) | 0.012 ms | 72K ops/sec |
| Policy evaluation (100 rules) | 0.029 ms | 31K ops/sec |
| Kernel enforcement | 0.091 ms | 9.3K ops/sec |
| Concurrent throughput (50 agents) | — | 35,481 ops/sec |

Full methodology: [BENCHMARKS.md](BENCHMARKS.md)

## Key Changes Since v1.1.0

### Added
- TypeScript SDK full parity — PolicyEngine + Identity + 136 tests (#269)
- 5 standalone framework quickstarts — LangChain, CrewAI, AutoGen, OpenAI Agents, Google ADK
- Competitive comparison page — vs NeMo Guardrails, Guardrails AI, LiteLLM, Portkey
- GitHub Copilot Extension for agent governance code review
- Observability integrations — Prometheus, OTel, PagerDuty, Grafana (#49)
- NIST RFI mapping — NIST AI Agent Security RFI 2026-00206 (#29)
- 6 comprehensive governance tutorials (#187)
- Azure deployment guides — AKS, AI Foundry, Container Apps, OpenClaw

### Fixed
- CostGuard input validation + org kill bypass prevention (#272)
- CostGuard thread safety — bound breach history + Lock (#253)
- .NET bug sweep — thread safety, error surfacing, caching, disposal (#252)
- Behavioral anomaly detection in RingBreachDetector
- ErrorBudget._events bounded with deque (#172)
- VectorClock thread safety (#243)
- Cross-package import errors (#222)
- OWASP-COMPLIANCE.md broken link (#270)

### Infrastructure
- Architecture rename propagated across 52 files (#221)
- OpenSSF Scorecard improved to ~7.7 (#113, #137)
- agentmesh-integrations migrated into monorepo (#138)
- Phase 2 + Phase 3 architecture consolidation (#206, #207)

## Security & Compliance

| Framework | Coverage |
|-----------|----------|
| OWASP Agentic Top 10 (2026) | 10/10 risks |
| CSA Agentic Trust Framework | 15/15 requirements |
| NIST AI RMF | Govern, Map, Measure, Manage |
| EU AI Act | Risk classification, audit trails, human oversight |

## Quick Start

```bash
# Python
pip install agent-governance-toolkit[full]

# TypeScript
npm install @microsoft/agentmesh-sdk

# .NET
dotnet add package Microsoft.AgentGovernance
```

```python
from agent_os import PolicyEngine, CapabilityModel

engine = PolicyEngine(capabilities=CapabilityModel(
    allowed_tools=["web_search", "file_read"],
    denied_tools=["file_write", "shell_exec"],
))
decision = engine.evaluate(agent_id="researcher-1", action="tool_call", tool="web_search")
```

## Full Changelog

See [CHANGELOG.md](CHANGELOG.md) for the complete list of changes.

## License

[MIT](LICENSE) — © Microsoft Corporation
