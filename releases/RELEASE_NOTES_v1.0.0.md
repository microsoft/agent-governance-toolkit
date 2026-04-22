# Agent Governance Toolkit v1.0.0

> [!IMPORTANT]
> **Community Preview Release** — This release is for testing and evaluation purposes only.
> Packages published to PyPI are **not** official Microsoft-signed releases.
> Official Microsoft-signed packages via ESRP Release will be available in a future release.

**The missing security layer for AI agents.** Runtime policy enforcement, identity mesh, execution sandboxing, and reliability engineering — in one toolkit.

## Highlights

- 🛡️ **10/10 OWASP Agentic Top 10 coverage** — full compliance mapping across all ASI-01 through ASI-10 risks
- 🔐 **Microsoft Entra Agent ID integration** — bridge DID identity with enterprise Zero Trust via Entra Agent ID
- 📦 **AI-BOM v2.0** — full AI supply chain tracking: model provenance, dataset lineage, weights versioning
- 🏛️ **CSA Agentic Trust Framework** — compliance mapping across all 5 ATF pillars (15/15 requirements)
- ✅ **OpenSSF Scorecard hardened** — pinned dependencies, CodeQL SAST, Dependabot, signed workflows

## Packages

| Package | Description | Install |
|---------|-------------|---------|
| **Agent OS** | Stateless governance kernel with policy engine, VFS, and MCP proxy | `pip install agent-os-kernel` |
| **AgentMesh** | Zero-trust identity mesh with DID, trust scoring, delegation chains | `pip install agentmesh-platform` |
| **Agent Runtime** | Execution rings, resource limits, kill switch, saga orchestration | `pip install agentmesh-runtime` |
| **Agent SRE** | SLOs, error budgets, circuit breakers, chaos engineering | `pip install agent-sre` |
| **Agent Compliance** | Unified installer and runtime policy enforcement | `pip install agent-governance` |
| **Agent Marketplace** | Plugin lifecycle management for governed agent ecosystems | `pip install agentmesh-marketplace` |
| **Agent Lightning** | RL training governance with governed runners and policy rewards | `pip install agentmesh-lightning` |

## Security & Compliance

| Framework | Coverage |
|-----------|----------|
| [OWASP Agentic Top 10 (2026)](docs/OWASP-COMPLIANCE.md) | 10/10 risks covered |
| [CSA Agentic Trust Framework](docs/compliance/csa-atf-mapping.md) | 15/15 requirements |
| [NIST AI RMF](https://www.nist.gov/artificial-intelligence/ai-risk-management-framework) | Govern, Map, Measure, Manage |
| [Singapore MGF for Agentic AI](docs/analyst/singapore-mgf-mapping.md) | Zero-trust, accountability, oversight |
| [EU AI Act](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai) | Risk classification, audit trails, human oversight |

## Key Features in v1.0.0

### Identity & Trust
- Cryptographic DID identity (`did:mesh:`) with Ed25519 key pairs
- Microsoft Entra Agent ID adapter (sponsor accountability, lifecycle management, Conditional Access)
- Trust scoring with decay, delegation chains with capability narrowing
- SPIFFE/SVID workload identity support

### Governance
- Policy-as-code engine (strict/permissive/audit modes)
- MCP Governance Proxy for tool call interception
- Approval workflows with quorum logic and expiration
- Prompt injection detection and PII protection

### Runtime Security
- Execution rings (Ring 0–3) with graduated privilege
- Kill switch for instant agent termination
- Saga orchestration with automatic rollback
- Joint liability scoring (Shapley values)

### Reliability (SRE)
- Agent-specific SLOs (correctness, safety, latency, cost)
- Circuit breakers with cascading failure detection
- Chaos engineering framework for AI agents
- Cost anomaly detection with per-agent budgets

### Supply Chain
- AI-BOM v2.0 — model provenance, dataset tracking, weights versioning
- SLSA-compatible build provenance for model artifacts
- CycloneDX ML-BOM export support

## External Submissions

45 integration proposals submitted across the ecosystem:
- **Merged:** GitHub Copilot (×3), Dify (×1)
- **Under Review:** Microsoft Agent Framework, Google ADK, AutoGen, CrewAI, LangChain, OpenAI Swarm, MetaGPT, Anthropic, MCP, OpenLit, OWASP, LF AI, CoSAI, AAIF

See [docs/proposals/](docs/proposals/) for the full list.

## Quick Start

```bash
pip install agent-governance[full]
```

```python
from agent_os import StatelessKernel, ExecutionContext

kernel = StatelessKernel()
ctx = ExecutionContext(agent_id="my-agent", policies=["read_only"])
result = await kernel.execute(action="query_db", params={"table": "users"}, context=ctx)
```

## License

[MIT](LICENSE) — © Microsoft Corporation
