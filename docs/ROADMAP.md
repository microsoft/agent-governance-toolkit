# Roadmap

Public roadmap for the Agent Governance Toolkit. Items are not commitments -- they
reflect current direction and priorities. Community input is welcome via
[GitHub Discussions](https://github.com/microsoft/agent-governance-toolkit/discussions).

## Current Release: v3.7.0 (Public Preview)

### Shipped
- 14 Python core packages + 20+ framework integrations
- 5 SDK languages (Python, TypeScript, .NET, Rust, Go)
- 20+ framework integrations (Semantic Kernel, AutoGen, LangChain, CrewAI, Google ADK, OpenAI Agents SDK, MCP, A2A, Haystack, LangGraph, LlamaIndex, Dify, Pydantic AI, smolagents, MAF, and more)
- 10 formal RFC 2119 specifications with 992 conformance tests
- 25 Architecture Decision Records
- 46+ tutorials + 7 policy-as-code chapters
- 13,000+ tests, 10/10 OWASP Agentic coverage
- OpenSSF Best Practices 100%, OpenSSF Scorecard tracked
- Contributor reputation screening (reusable GitHub Action)
- Unified CLI (`agt verify`, `agt red-team`, `agt doctor`, `agt lint-policy`)
- PromptDefense 12-vector prompt injection evaluator
- OpenClaw sidecar for Kubernetes governance
- Container images on GHCR (trust-engine, policy-server, audit-collector, api-gateway)
- GovernanceEventSink SPI with circuit breaker and batch processing
- OTel-native audit backends and structured governance events

## Near-Term (Next 1-2 Releases)

### Governance Core
- [ ] Policy hot-reload without agent restart
- [ ] Cedar policy language production support
- [ ] OPA/Rego integration hardening
- [ ] Multi-tenant policy isolation

### Identity & Trust
- [ ] Entra ID agent identity bridge
- [ ] SPIFFE/SVID production deployment guide
- [ ] ML-DSA-65 (post-quantum) signing production support

### Deployment & Operations
- [ ] Helm chart v1.0 with production defaults
- [ ] Agent SRE dashboard (Grafana templates)
- [ ] Shadow AI discovery scanner production support

### Compliance
- [ ] ISO 42001 mapping completion
- [ ] EU AI Act Annex IV automated evidence generation
- [ ] SOC 2 audit trail export tooling

## Medium-Term (3-6 Months)

### Advanced Governance
- [ ] Multi-agent delegation chain verification
- [ ] Economic scope limits (budget governance)
- [ ] Constitutional constraint layer (community extension)
- [ ] Agent behavior anomaly detection via trust scoring

### Ecosystem
- [ ] Foundation project submissions
- [ ] CoSAI/OASIS WS4 reference implementation
- [ ] Cross-project spec alignment

## Long-Term (6-12 Months)

- [ ] Federated trust across organizational boundaries
- [ ] Formal verification of policy evaluation
- [ ] Hardware-backed agent identity (TPM/SGX)

## How to Influence the Roadmap

1. **Vote on existing issues** -- 👍 issues you care about
2. **Open a discussion** -- Propose new features or directions
3. **Submit an ADR** -- For architectural proposals, see `docs/adr/`
4. **Contribute** -- PRs are the strongest signal of priority
