# Frequently Asked Questions

Common questions from customers, partners, and evaluators about the Agent Governance Toolkit.

---

## General

### What is the Agent Governance Toolkit?

A **runtime governance layer** for autonomous AI agents. It intercepts every agent action (tool calls, API requests, inter-agent messages) *before* execution and enforces deterministic policies at sub-millisecond latency. It is **not** a model safety or prompt guardrails tool — it governs what agents *do*, not what they say.

### Is this a Microsoft product or an open-source project?

Both. It is an MIT-licensed open-source project maintained by Microsoft. Packages are Microsoft-signed and published to PyPI, npm, NuGet, crates.io, and Go modules. Currently in **Public Preview** — production-quality with 9,700+ tests, but APIs may have breaking changes before GA.

### Does it work outside Azure?

**Yes.** Zero Azure dependencies. It runs on AWS, GCP, on-prem, or any environment that runs Python, Node.js, .NET, Rust, or Go. Deployment guides are provided for [AWS ECS](docs/deployment/aws-ecs.md), [GCP GKE](docs/deployment/gcp-gke.md), and Azure AKS.

### What frameworks does it work with?

21 framework integrations including LangChain, CrewAI, AutoGen, OpenAI Agents SDK, Google ADK, Semantic Kernel, Microsoft Agent Framework, LlamaIndex, Haystack, PydanticAI, Dify, Flowise, and more. See [`packages/agentmesh-integrations/`](packages/agentmesh-integrations/) for the full list.

### How is it different from prompt guardrails / Azure AI Content Safety?

| | Agent Governance Toolkit | Prompt Guardrails |
|---|---|---|
| **What it governs** | Agent *actions* (tool calls, API access, data access) | Agent *outputs* (text, content) |
| **Enforcement** | Deterministic — policy-as-code, 0% violation rate | Probabilistic — LLM-based classification, ~27% bypass rate |
| **Latency** | <0.1ms per check | 50-200ms per check |
| **Scope** | Runtime behavior, identity, trust, audit | Content moderation |

They are complementary. Use AGT for action governance and Content Safety for output moderation.

---

## Architecture & Integration

### What is the relationship between AGT and the Foundry Control Plane?

**Complementary.** Foundry Control Plane manages agent fleet *lifecycle* (inventory, health, deployment). AGT governs what agents *do at runtime* (policy enforcement, identity, audit). Think of Foundry as Kubernetes (manages pods) and AGT as network policy + service mesh (governs traffic).

### How does it integrate with Entra ID / Azure Managed Identities?

Native support via `agentmesh.identity`:
- Binds agent DIDs to Entra object IDs (1:1 mapping)
- Acquires tokens from Azure IMDS for downstream service access
- Validates tokens (expiry, issuer, audience)
- Also supports AWS IAM Roles and GCP Workload Identity

### Do agents need to restart when policies change?

**No.** Policies can be reloaded at runtime via `PolicyEvaluator.reload_policies()` with thread-safe atomic swap. No agent restart required. Recommended pattern: push policy updates via your config management tool, then trigger reload via AGT API.

### What's the difference between agent-hypervisor and agent-runtime?

`agent-hypervisor` is the core execution supervisor (privilege rings, saga engine, kill switch). `agent-runtime` is a thin wrapper that re-exports everything from hypervisor and adds Docker/Kubernetes deployment helpers. Most users install `agentmesh-runtime`.

---

## Security & Compliance

### Which OWASP risks does it cover?

All 10 OWASP Agentic AI Top 10 risks (ASI-01 through ASI-10):

| Risk | Control |
|------|---------|
| Goal Hijacking | Policy engine blocks unauthorized goal changes |
| Excessive Capabilities | Capability model enforces least-privilege |
| Identity & Privilege Abuse | Zero-trust identity with Ed25519 + quantum-safe ML-DSA-65 |
| Uncontrolled Code Execution | Execution rings + sandboxing |
| Insecure Output Handling | Content policies validate outputs |
| Memory Poisoning | Episodic memory with integrity checks |
| Unsafe Inter-Agent Communication | Encrypted channels + trust gates |
| Cascading Failures | Circuit breakers + SLO enforcement |
| Human-Agent Trust Deficit | Full audit trails + flight recorder |
| Rogue Agents | Kill switch + ring isolation + anomaly detection |

### Is the sandboxing "real" or application-level?

**Application-level.** The README is transparent about this: governance runs in the same Python process as agents. For OS-level isolation, run each agent in a separate container. AGT provides the *policy brain*; containers provide the *isolation walls*. Both are needed for defense-in-depth.

### Does it support quantum-safe cryptography?

Yes. ML-DSA-65 (FIPS 204, NIST Level 3) is supported alongside Ed25519 via `agentmesh.identity.quantum_safe`. This provides long-term audit trail integrity against future quantum computing threats, as required by the EU AI Act's 10+ year evidence retention requirements.

### What compliance frameworks does it map to?

- **EU AI Act** — Article 9 (risk management), Article 12 (audit trails), Article 14 (human oversight)
- **HIPAA** — Access controls, audit logging, data classification
- **SOX / PCI-DSS** — Separation of duties, transaction logging, data protection
- **SOC 2** — Trust service criteria mapping
- **ISO 42001** — AI management system alignment
- **NIST AI RMF** — Risk management framework mapping

---

## Getting Started

### What's the fastest way to try it?

Three lines of Python:

```python
from agent_os.lite import govern

check = govern(allow=["read_file", "web_search"], deny=["execute_code", "delete_file"])
check("read_file")      # ✅ Allowed
check("execute_code")   # 💥 Blocked
```

Install: `pip install agent-os-kernel`

### Is there a production-ready policy I can start with?

Yes. Five battle-tested policy templates in [`examples/policies/production/`](examples/policies/production/):

| Policy | Use Case |
|--------|----------|
| `minimal.yaml` | Startups, internal tools |
| `enterprise.yaml` | General enterprise, SaaS |
| `healthcare.yaml` | HIPAA-regulated |
| `financial.yaml` | SOX/PCI-regulated |
| `strict.yaml` | Defense, ITAR, critical infrastructure |

### Where can I see a demo?

Two dashboard options:
- **Fleet governance demo**: `cd demo/governance-dashboard && streamlit run app.py` (simulated data, fleet overview)
- **Trust score dashboard**: `cd packages/agent-mesh/examples/06-trust-score-dashboard && streamlit run trust_dashboard.py` (trust network, credentials, compliance — pluggable to live data)

---

## Pricing & Licensing

### Is it free?

Yes. MIT License. No usage fees, no telemetry, no phone-home.

### Is there a commercial/managed version?

A managed cloud service (AgentMesh Cloud) is on the roadmap for Q4 2026. The open-source version will remain fully functional and free.

### What support is available?

- **Community**: [GitHub Issues](https://github.com/microsoft/agent-governance-toolkit/issues) and [Discussions](https://github.com/microsoft/agent-governance-toolkit/discussions)
- **Enterprise**: Contact the AGT team via your Microsoft account team for direct engagement

---

## Performance

### What's the latency overhead?

| Operation | Latency |
|-----------|---------|
| Single policy rule check | 0.003ms |
| 100-rule policy evaluation | 0.029ms |
| Full kernel enforcement | 0.091ms |
| Adapter overhead | 0.004-0.006ms |

For comparison, a typical LLM API call takes 500-2000ms. AGT's overhead is invisible.

### How does it scale?

- Stateless policy checks — horizontally scalable
- 35,481 ops/sec throughput with 50 concurrent agents (benchmarked)
- Per-process state by default; Redis/PostgreSQL backends available for shared state

---

*Last updated: April 14, 2026. For corrections or additions, please open an issue or PR.*
