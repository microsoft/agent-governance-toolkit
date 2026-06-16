---
title: OWASP Compliance
last_reviewed: 2026-06-16
owner: agt-maintainers
---

# OWASP Compliance

AGT maps to three OWASP standards relevant to agentic AI systems.

| Standard | Scope | Coverage |
|----------|-------|----------|
| [OWASP Agentic Security Initiative (ASI) Top 10](../compliance/owasp-agentic-top10-architecture.md) | Agent-specific attack classes — prompt injection, tool misuse, privilege escalation, data exfiltration | Full reference architecture with per-risk AGT controls |
| [OWASP ASI Policy-Rule Mapping](../compliance/owasp-asi-policy-mapping.md) | Cedar/OPA policy rules that enforce each ASI control | Machine-readable policy stubs per ASI risk |
| [OWASP LLM Top 10](../compliance/owasp-llm-top10-mapping.md) | LLM application risks — training data poisoning, insecure output, model theft, etc. | 9 of 10 risks detected; enforcement gap noted for 6 |
| [OWASP MCP Top 10](../compliance/mcp-owasp-top10-mapping.md) | MCP protocol attack surface — server impersonation, tool injection, credential leakage | cMCP gateway + Agent Manifest cover the full attack surface |

## AGT security controls by OWASP category

### Prompt Injection (ASI-01 / LLM-01)

AGT enforces at the **tool-call boundary**, not the prompt layer. Injected instructions that attempt to call unauthorized tools are blocked by the Cedar policy engine before execution — the prompt content is irrelevant to the enforcement decision.

Relevant: [MCP Security Gateway tutorial](../tutorials/07-mcp-security-gateway.md) · [Prompt Injection Detection tutorial](../tutorials/09-prompt-injection-detection.md)

### Excessive Agency / Privilege Escalation (ASI-02 / ASI-03)

Agent Manifest carries the authorized scope. cMCP evaluates scope against Cedar policy on every tool call. Delegation chains enforce trust ceilings — a delegated agent cannot exceed the permissions of its delegator.

Relevant: [Delegation Chains tutorial](../tutorials/23-delegation-chains.md) · [ADR-0016: Trust Ceiling Propagation](../adr/0016-trust-ceiling-propagation-for-delegation.md)

### Audit and Tamper Evidence (ASI-07)

TRACE records are IETF RATS/EAT-compliant attestation evidence produced for every governed action. Records are chained via Merkle tree — any tampering breaks the chain. When produced inside an Opaque TEE, the signing key is hardware-rooted and cannot be forged even by a compromised platform.

Relevant: [ADR-0017: Merkle Audit Chain](../adr/0017-merkle-chain-for-audit-tamper-evidence.md) · [Audit & Compliance tutorial](../tutorials/04-audit-and-compliance.md)

### Tool and Plugin Security (OWASP MCP Top 10)

The cMCP gateway intercepts all tool calls before they reach MCP servers. Server impersonation is blocked by mutual TLS + Agent Manifest verification. Tool injection (a server returning malicious tool definitions) is blocked by Cedar policy evaluation against the allowed tool schema.

Relevant: [OWASP MCP Top 10 mapping](../compliance/mcp-owasp-top10-mapping.md) · [MCP Trust Guide](../integrations/mcp-trust-guide.md)

---

> **Scope note:** This page covers the runtime security controls that address OWASP risks.
> For compliance framework mapping (EU AI Act, NIST AI RMF, SOC 2, ISO 42001), see the
> [Compliance](../compliance/index.md) section.
