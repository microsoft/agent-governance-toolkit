# Roadmap

Public roadmap for the Agent Governance Toolkit. Items are not commitments — they
reflect current direction and priorities. Community input is welcome via
[GitHub Discussions](https://github.com/microsoft/agent-governance-toolkit/discussions).

## Current Release: v3.2.0 (Public Preview)

### Shipped
- 8 Python packages (agent-os, agent-mesh, agent-hypervisor, agent-sre, agent-compliance, agent-runtime, agent-lightning, agent-marketplace)
- 5 SDK languages (Python, TypeScript, .NET, Rust, Go)
- 12+ framework integrations (Semantic Kernel, AutoGen, LangChain, CrewAI, Google ADK, OpenAI Agents, MCP, A2A, etc.)
- 32 tutorials + 7 policy-as-code chapters
- 9,500+ tests, 10/10 OWASP Agentic coverage
- OpenClaw sidecar for Kubernetes governance
- Container images on GHCR (trust-engine, policy-server, audit-collector, api-gateway)

## Near-Term (Next 1-2 Releases)

### Governance Core
- [ ] Policy hot-reload without agent restart
- [ ] Cedar policy language GA support
- [ ] OPA/Rego integration hardening
- [ ] Multi-tenant policy isolation

### Identity & Trust
- [ ] Entra ID ↔ Agent DID bridge (Graph API integration)
- [ ] SPIFFE/SVID production deployment guide
- [ ] ML-DSA-65 (post-quantum) signing GA

### Deployment & Operations
- [ ] Published container images on GHCR (automated via release)
- [ ] Helm chart v1.0 with production defaults
- [ ] Agent SRE dashboard (Grafana templates)
- [ ] Shadow AI discovery scanner GA

### Compliance
- [ ] ISO 42001 mapping completion
- [ ] EU AI Act Annex IV automated evidence generation
- [ ] SOC 2 audit trail export tooling

## Medium-Term (3-6 Months)

### Platform Integration
- [ ] Microsoft Foundry Control Plane integration
- [ ] Azure AI Foundry governance middleware
- [ ] GitHub Copilot Extensions governance hooks

### Ecosystem
- [ ] AAIF (AI Alliance) project submission
- [ ] LF AI & Data Foundation sandbox submission
- [ ] CoSAI/OASIS WS4 reference implementation

### Advanced Governance
- [ ] Multi-agent delegation chain verification
- [ ] Economic scope limits (budget governance)
- [ ] Constitutional constraint layer (community extension)
- [ ] Agent behavior anomaly detection

## Long-Term (6-12 Months)

- [ ] Federated trust across organizational boundaries
- [ ] Formal verification of policy evaluation
- [ ] Hardware-backed agent identity (TPM/SGX)
- [ ] Agent governance as a managed Azure service

## How to Influence the Roadmap

1. **Vote on existing issues** — 👍 issues you care about
2. **Open a discussion** — Propose new features or directions
3. **Submit an ADR** — For architectural proposals, see `docs/adr/`
4. **Contribute** — PRs are the strongest signal of priority
