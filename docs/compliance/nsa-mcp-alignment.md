<div align="center">

# NSA MCP Security Considerations — Compliance Mapping

> **Disclaimer**: This document is an internal self-assessment mapping, NOT a validated certification or third-party audit. It documents how the toolkit's capabilities align with the referenced publication. Organizations must perform their own compliance assessments with qualified reviewers.

**How the Agent Governance Toolkit (AGT) aligns with the NSA publication _Security Design Considerations for AI-Driven Automation Leveraging Model Context Protocol (MCP)_**

> **Sources**:
> NSA press release:
> `https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/nsa-releases-security-design-considerations-for-ai-driven-automation-leveraging/`
> ·
> NSA PDF:
> `https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf`
>
> **Assessment note**: This mapping aligns AGT to the principal design themes and recommendations surfaced by the NSA publication. It is not yet a page-by-page or section-by-section crosswalk to the source PDF.

</div>

---

## Coverage Summary

| NSA MCP Theme | Coverage | Primary AGT Components |
|---|---|---|
| Zero-trust defaults | ✅ Covered | MCP Security Gateway, Trust Proxy, session authentication |
| Least-privilege tool access | ✅ Covered | `MCPGateway`, policy engine, capability sandbox |
| Authentication and authorization | ✅ Covered | `MCPSessionAuthenticator`, DID identity, auth enforcement |
| Tool poisoning and metadata abuse | ✅ Covered | `MCPSecurityScanner`, trust-gated MCP controls |
| Context and output protection | ✅ Covered | `MCPResponseScanner`, `CredentialRedactor` |
| Integrity and replay protection | ✅ Covered | `MCPMessageSigner`, nonce replay protection |
| Auditability and telemetry | ✅ Covered | MCP audit logging, Merkle audit patterns, observability integration |
| Supply-chain awareness | ✅ Covered | OSV/CVE feed, schema drift detection, rug-pull detection |
| Intent-flow subversion | ⚠️ Partial | Prompt-injection detection, MCP metadata/output scanning |
| Shadow MCP servers | ⚠️ Partial | Trust proxy, approved-server controls, trust scoring |
| Token and secret exposure | ⚠️ Partial | Credential redaction, audit-safe logging, response scanning |

**8 themes covered, 3 partial.** The covered areas align strongest with AGT's MCP runtime governance stack. The partial areas are the same ones AGT already identifies as partial in its OWASP MCP mapping.

---

## Methodology

- **Assessment date:** 2026-05-22
- **Scope reviewed:** [README.md](../../README.md), [MCP Security Gateway spec](../specs/MCP-SECURITY-GATEWAY-1.0.md), [MCP trust guide](../integrations/mcp-trust-guide.md), [MCP gateway tutorial](../tutorials/07-mcp-security-gateway.md), [OWASP MCP mapping](mcp-owasp-top10-mapping.md), and the Python MCP implementation modules in `agent-governance-python/agent-os/src/agent_os/`
- **Approach:** Map the principal security design themes reflected in the NSA MCP publication to concrete AGT runtime controls, security scanners, trust components, and compliance evidence already present in the repository
- **Limitations:** This is a repository-backed documentation assessment only. It does not validate live production deployment posture, operational procedures, or runtime telemetry from a deployed AGT environment.

Coverage levels are assigned as:

| Level | Criteria |
|-------|----------|
| ✅ **Covered** | AGT contains production-oriented code and documentation that materially addresses the theme |
| ⚠️ **Partial** | AGT addresses the theme in part, but the repo documents material limitations or roadmap items |
| ❌ **Gap** | No meaningful AGT capability or documentation addresses the theme |

---

## Detailed Mapping

### 1. Zero-Trust Defaults

**Coverage: ✅ COVERED**

AGT's MCP Security Gateway specification explicitly states that unknown agents start with no session, no call budget, and no tool access until explicitly granted. This aligns well with the NSA publication's emphasis on explicit trust boundaries and defensive default posture.

- **MCP Security Gateway** — fail-closed interception for all MCP tool calls and responses
- **Trust Proxy** — identity- and trust-gated tool access
- **Session Authentication** — explicit session issuance and validation before access

**Evidence:**
- [MCP Security Gateway spec](../specs/MCP-SECURITY-GATEWAY-1.0.md)
- [MCP trust guide](../integrations/mcp-trust-guide.md)

---

### 2. Least-Privilege Tool Access

**Coverage: ✅ COVERED**

AGT applies least privilege to MCP tool invocation through allow-lists, deny-lists, sensitive-tool approvals, parameter sanitization, and per-agent call budgets.

- **`MCPGateway`** — allow/deny filtering before tool execution
- **Capability sandbox** — scoped access patterns for sensitive actions
- **Approval workflows** — human-in-the-loop gating for sensitive tools

**Evidence:**
- [Tutorial 07 — MCP Security Gateway](../tutorials/07-mcp-security-gateway.md)
- `agent-governance-python/agent-os/src/agent_os/mcp_gateway.py`

---

### 3. Authentication and Authorization

**Coverage: ✅ COVERED**

AGT provides session-based MCP authentication, DID- and trust-based authorization, and per-server authentication method enforcement with TLS requirements.

- **`MCPSessionAuthenticator`** — scoped, time-bounded MCP sessions
- **Trust-gated MCP** — DID identity, trust thresholds, required capabilities
- **Auth enforcement** — approved authentication methods and TLS validation

**Evidence:**
- [MCP trust guide](../integrations/mcp-trust-guide.md)
- `agent-governance-python/agent-os/src/agent_os/mcp_session_auth.py`
- `agent-governance-python/agent-os/src/agent_os/mcp_auth_enforcement.py`

---

### 4. Tool Poisoning and Metadata Abuse

**Coverage: ✅ COVERED**

AGT's MCP security model directly addresses one of the most important MCP-specific risk areas in the NSA guidance: malicious or manipulated tool metadata.

- **`MCPSecurityScanner`** — hidden instruction detection, schema abuse detection, description injection scanning
- **Rug-pull detection** — fingerprint comparison for silent tool-definition drift
- **Cross-server attack detection** — typosquatting and impersonation checks

**Evidence:**
- [OWASP MCP Top 10 mapping](mcp-owasp-top10-mapping.md)
- `agent-governance-python/agent-os/src/agent_os/mcp_security.py`

---

### 5. Context and Output Protection

**Coverage: ✅ COVERED**

AGT treats MCP tool outputs as a separate attack surface and scans them before they are reintroduced into agent context. This is strongly aligned with the NSA publication's emphasis on securing agentic automation end to end rather than trusting downstream context blindly.

- **`MCPResponseScanner`** — prompt-injection markers, credential leaks, PII exposure, exfiltration URL detection
- **`CredentialRedactor`** — redaction before audit persistence or downstream reuse

**Evidence:**
- `agent-governance-python/agent-os/src/agent_os/mcp_response_scanner.py`
- [MCP Security Gateway spec](../specs/MCP-SECURITY-GATEWAY-1.0.md)

---

### 6. Integrity and Replay Protection

**Coverage: ✅ COVERED**

AGT includes cryptographic message integrity and replay protection for MCP traffic.

- **`MCPMessageSigner`** — HMAC signing of MCP messages
- **Replay protection** — nonce tracking and replay-window enforcement
- **Minimum key length** — 32-byte HMAC signing key floor

**Evidence:**
- `agent-governance-python/agent-os/src/agent_os/mcp_message_signer.py`
- [OWASP MCP Top 10 mapping](mcp-owasp-top10-mapping.md)

---

### 7. Auditability and Telemetry

**Coverage: ✅ COVERED**

AGT records MCP decisions and integrates MCP governance into its broader audit and observability posture.

- **Structured audit records** — tool name, parameters, decision, and reason
- **Audit-safe redaction** — secret masking before persistence
- **Observability integration** — broader AGT audit and telemetry patterns documented across the repo

**Evidence:**
- [README.md](../../README.md)
- `agent-governance-python/agent-os/src/agent_os/mcp_gateway.py`
- [OWASP MCP Top 10 mapping](mcp-owasp-top10-mapping.md)

---

### 8. Supply-Chain Awareness

**Coverage: ✅ COVERED**

AGT extends MCP protection beyond immediate policy checks by monitoring for known package vulnerabilities and silent schema drift.

- **OSV-backed vulnerability lookups** — MCP package CVE awareness
- **Schema drift detection** — change detection for registered tools
- **Rug-pull detection** — security posture around mutated definitions

**Evidence:**
- `agent-governance-python/agent-os/src/agent_os/mcp_cve_feed.py`
- [MCP Security Gateway spec](../specs/MCP-SECURITY-GATEWAY-1.0.md)

---

### 9. Intent-Flow Subversion

**Coverage: ⚠️ PARTIAL**

AGT includes prompt-injection detection for MCP metadata and outputs, but its own mapping documents that deeper context-as-instruction separation remains an area for improvement.

**Current coverage:**
- prompt-injection pattern detection
- MCP response scanning
- hidden instruction detection in tool metadata

**Gap:** AGT does not yet claim complete semantic separation of data from instructions across the full MCP context lifecycle.

**Evidence:**
- [OWASP MCP Top 10 mapping](mcp-owasp-top10-mapping.md)

---

### 10. Shadow MCP Servers

**Coverage: ⚠️ PARTIAL**

AGT includes trust proxy and approved-server patterns, but the repo's current MCP mapping still treats shadow-server governance as partial.

**Current coverage:**
- trust-gated access
- approved-server and registration concepts
- trust scores for MCP peers and services

**Gap:** AGT's own MCP mapping calls out stronger server-card style validation as future work.

**Evidence:**
- [OWASP MCP Top 10 mapping](mcp-owasp-top10-mapping.md)
- [MCP trust guide](../integrations/mcp-trust-guide.md)

---

### 11. Token and Secret Exposure

**Coverage: ⚠️ PARTIAL**

AGT meaningfully reduces MCP secret exposure risk through redaction, audit-safe logging, and response scanning, but it still treats this theme as partial in its own MCP compliance mapping.

**Current coverage:**
- credential redaction
- PEM block masking
- audit-safe persistence
- response scanning for leaked credentials

**Gap:** The repo explicitly documents that MCP-specific secret scanning still has room for deeper coverage.

**Evidence:**
- [OWASP MCP Top 10 mapping](mcp-owasp-top10-mapping.md)
- `agent-governance-python/agent-os/src/agent_os/mcp_response_scanner.py`

---

## Summary

| Area | Assessment |
|------|------------|
| Strongest alignment | Zero trust, tool governance, authentication, poisoning defense, response scanning, auditability |
| Partial areas | Intent-flow subversion, shadow MCP servers, token/secret exposure |
| Best-fit AGT surfaces | MCP Security Gateway, MCP trust model, MCP scanner, response scanner, message signer |
| Overall conclusion | AGT aligns well with the NSA MCP security direction in most major technical areas |

**Overall assessment:** AGT already contains a substantial MCP governance stack that is consistent with the main security themes in the NSA publication. The strongest fit is around governed tool execution, zero-trust defaults, layered controls, metadata scanning, response scanning, and verifiable decision-making. The remaining gaps are limited and already acknowledged in AGT's existing MCP compliance materials.

---

## Related Mappings

- [OWASP MCP Top 10 mapping](mcp-owasp-top10-mapping.md)
- [NIST AI RMF alignment](nist-ai-rmf-alignment.md)
- [ISO 42001 mapping](iso-42001-mapping.md)
- [NIST RFI 2026-00206](nist-rfi-2026-00206.md)
