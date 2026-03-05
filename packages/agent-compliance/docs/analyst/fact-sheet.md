# Agent Governance Stack — Fact Sheet

### Open-Source Governance for Production AI Agents

> One install. Four layers of protection. MIT licensed.

---

## The Stack

| Component | Purpose | Tests | Key Metric |
|-----------|---------|-------|------------|
| **[Agent OS](https://github.com/microsoft/agent-governance-toolkit)** | Governance kernel — policy enforcement, capability security, audit trails | 2,000+ | 0% policy violations in governed agents |
| **[AgentMesh](https://github.com/microsoft/agent-governance-toolkit)** | Trust & identity — zero-trust communication, encrypted channels | 500+ | DID-based cryptographic auth |
| **[Agent Hypervisor](https://github.com/microsoft/agent-governance-toolkit)** | Runtime isolation — execution rings, resource limits, kill switches | 200+ | Process-level isolation |
| **[Agent SRE](https://github.com/microsoft/agent-governance-toolkit)** | Reliability engineering — SLOs, chaos engineering, incident response | 329+ | 11 observability platforms |
| **[Agent Governance](https://github.com/microsoft/agent-governance-toolkit)** | Unified installer — single package for the complete stack | — | `pip install ai-agent-governance[full]` |

---

## Key Capabilities

- **Prompt injection detection** — 7 detection strategies (heuristic, ML classifier, canary tokens, perplexity analysis, and more)
- **Policy-as-code** — YAML rule sets for capability control, tool allowlists, and output filtering
- **SLO/error budget management** — Define availability and latency targets for agents with automated enforcement
- **Chaos engineering + adversarial testing** — Inject faults, simulate attacks, and validate governance under stress
- **Circuit breakers and cascade protection** — Prevent single-agent failures from cascading across multi-agent systems
- **DID-based cryptographic agent identity** — Decentralized identifiers for verifiable, non-repudiable agent authentication
- **OpenTelemetry-native observability** — Export governance telemetry as traces, metrics, and logs to any OTEL-compatible backend
- **12+ framework adapters** — LangChain, CrewAI, AutoGen, Semantic Kernel, LlamaIndex, Haystack, OpenAI Agents SDK, Google ADK, MCP, A2A, and more
- **Behavioral anomaly detection** — ML-based detection of unusual agent behavior patterns
- **REST API for language-agnostic integration** — Use from any language, not just Python

---

## OWASP Agentic AI Top 10 Coverage

**9/10 risks fully covered** (ASI01–ASI10, partial on ASI04)

| Risk | Coverage | Mechanism |
|------|----------|-----------|
| ASI01 Agent Hijacking | ✅ Full | Multi-strategy prompt injection detection |
| ASI02 Privilege Escalation | ✅ Full | Capability-based access control |
| ASI03 Insecure Communication | ✅ Full | mTLS, encrypted channels, trust scoring |
| ASI04 Insufficient Identity | ⚠️ Partial | DID-based identity (SPIFFE alternative supported) |
| ASI05 Unsafe Code Execution | ✅ Full | Sandboxed execution with resource limits |
| ASI06 Excessive Autonomy | ✅ Full | Human-approval policies |
| ASI07 Data Leakage | ✅ Full | Output scanning, PII redaction |
| ASI08 Lack of Observability | ✅ Full | Audit logging, OpenTelemetry |
| ASI09 Resource Exhaustion | ✅ Full | Resource governor, rate limiting |
| ASI10 Lack of Error Handling | ✅ Full | Circuit breakers, SLOs, error budgets |

See the full [OWASP Implementation Guide](owasp-agentic-mapping.md) for code examples.

---

## Differentiators

1. **Only full-stack governance solution** — Kernel + trust mesh + runtime isolation + SRE in a single, integrated platform. No other project covers all four layers.

2. **SRE discipline for AI agents** — SLOs, error budgets, chaos engineering, and incident response automation applied to agentic AI workloads. This is unique in the market — no other tool brings SRE practices to AI agents.

3. **Zero vendor lock-in** — MIT license, open protocols (OpenTelemetry, DID, REST), pluggable architecture. Works with any LLM provider, any framework, any cloud.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    agent-governance                          │
│               pip install ai-agent-governance[full]          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐          ┌─────────────────────────┐   │
│  │  Agent OS Kernel │◄────────►│  AgentMesh Platform     │   │
│  │  Policy Engine   │          │  Zero-Trust Identity    │   │
│  │  Injection Detect│          │  Mutual TLS             │   │
│  │  Audit Logging   │          │  Trust Scoring           │   │
│  └────────┬─────────┘          └────────────┬────────────┘   │
│           │                                 │                │
│  ┌────────▼─────────┐          ┌────────────▼────────────┐   │
│  │ Agent Hypervisor  │          │  Agent SRE              │   │
│  │ Execution Rings   │          │  SLO Enforcement        │   │
│  │ Resource Limits   │          │  Chaos Engineering      │   │
│  │ Kill Switch       │          │  Anomaly Detection      │   │
│  └──────────────────┘          └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Getting Started

```bash
# Install the full stack
pip install ai-agent-governance[full]

# Or install individual components
pip install agent-os-kernel          # Governance kernel only
pip install agentmesh-platform       # Trust mesh only
pip install agent-hypervisor         # Runtime isolation only
pip install agent-sre                # Reliability engineering only
```

```python
from agent_os import StatelessKernel, ExecutionContext

kernel = StatelessKernel()
ctx = ExecutionContext(agent_id="my-agent", capabilities=["read", "write"])
result = kernel.execute(ctx, action="call_tool", tool="search", args={"q": "query"})
```

---

## Links

| Resource | URL |
|----------|-----|
| GitHub | [github.com/microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) |
| Documentation | [github.com/microsoft/agent-governance-toolkit/agent-os-docs](https://github.com/microsoft/agent-governance-toolkit/tree/main/docs) |
| PyPI | [pypi.org/project/ai-agent-governance](https://pypi.org/project/ai-agent-governance/) |
| OWASP Mapping | [OWASP Implementation Guide](owasp-agentic-mapping.md) |
| Architecture Guide | [Enterprise Reference Architecture](../enterprise/reference-architecture.md) |
| CNCF Proposal | [CNCF Sandbox Proposal](cncf-sandbox-proposal.md) |
| Author | [github.com/microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) |

---

*Part of the [Agent Governance](https://github.com/microsoft/agent-governance-toolkit) ecosystem — Building the governance layer for the agentic era*
