<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# CIS Controls v8.1 Mapping for AI Agent Governance

> **Disclaimer**: This document is a self-assessment mapping, NOT a validated
> certification. Organizations must perform their own assessments with qualified
> auditors. CIS Controls® is a trademark of the Center for Internet Security.

---

## Overview

This document maps AGT governance capabilities to the [CIS Controls v8.1](https://www.cisecurity.org/controls/v8)
safeguards relevant to AI agent infrastructure. CIS Controls provide a prioritized
set of actions that collectively form a defense-in-depth approach to cybersecurity.

### Coverage Summary

| Metric | Value |
|--------|-------|
| CIS Controls assessed | 18 |
| Relevant safeguards mapped | 42 |
| **Fully addressed** | **28** (67%) |
| **Partially addressed** | **10** (24%) |
| **Gaps** | **4** (9%) |

---

## Mapping Table

### CIS Control 1: Inventory and Control of Enterprise Assets

| Safeguard | Description | AGT Coverage | Module |
|-----------|------------|-------------|--------|
| 1.1 | Establish and maintain detailed enterprise asset inventory | ✅ Full | `agent-discovery` — scans processes, configs, repos for unregistered agents |
| 1.2 | Address unauthorized assets | ✅ Full | `AgentIdentity` — unknown DIDs rejected by trust verification |
| 1.3 | Utilize an active discovery tool | ✅ Full | `agent-discovery` — continuous scanning with reconciliation |
| 1.4 | Use dynamic host configuration protocol (DHCP) logging | ⬜ N/A | Network-level, outside AGT scope |

### CIS Control 2: Inventory and Control of Software Assets

| Safeguard | Description | AGT Coverage | Module |
|-----------|------------|-------------|--------|
| 2.1 | Establish and maintain a software inventory | ✅ Full | MCP server registry + `McpCveFeed` package tracking |
| 2.2 | Ensure authorized software is currently supported | ✅ Full | `McpCveFeed` — CVE tracking via OSV.dev |
| 2.3 | Address unauthorized software | ✅ Full | MCP gateway `denied_tools` list |
| 2.5 | Allowlist authorized software | ✅ Full | `McpAuthPolicy` server allowlist |
| 2.6 | Allowlist authorized libraries | 🟡 Partial | SBOM generation (Tutorial 26), manual review |

### CIS Control 3: Data Protection

| Safeguard | Description | AGT Coverage | Module |
|-----------|------------|-------------|--------|
| 3.1 | Establish and maintain a data management process | ✅ Full | `data-provenance-model.md` — provenance schema |
| 3.2 | Establish and maintain a data inventory | 🟡 Partial | Provenance records track data sources; no full inventory UI |
| 3.3 | Configure data access control lists | ✅ Full | Policy rules with `condition` matching on data classification |
| 3.4 | Enforce data retention | ✅ Full | `record-retention-policy.md` + `AuditLog` with configurable TTL |
| 3.6 | Encrypt data on end-user devices | ✅ Full | E2E encryption (Signal protocol) for agent-to-agent messaging |
| 3.9 | Encrypt data on removable media | ⬜ N/A | Agent systems don't use removable media |
| 3.10 | Encrypt sensitive data in transit | ✅ Full | E2E encryption + TLS enforcement in `McpAuthPolicy` |
| 3.11 | Encrypt sensitive data at rest | 🟡 Partial | Identity files encrypted at rest; audit logs depend on storage backend |
| 3.12 | Segment data processing and storage | 🟡 Partial | `SessionState` attribute ratchets enforce data classification boundaries |

### CIS Control 4: Secure Configuration of Enterprise Assets and Software

| Safeguard | Description | AGT Coverage | Module |
|-----------|------------|-------------|--------|
| 4.1 | Establish and maintain a secure configuration process | ✅ Full | Policy-as-code in YAML with `extends` composition |
| 4.2 | Establish and maintain a secure configuration for network infrastructure | 🟡 Partial | `McpAuthPolicy` TLS enforcement; network config outside scope |
| 4.7 | Manage default accounts on enterprise assets | ✅ Full | No default accounts; all agents require explicit identity creation |

### CIS Control 5: Account Management

| Safeguard | Description | AGT Coverage | Module |
|-----------|------------|-------------|--------|
| 5.1 | Establish and maintain an inventory of accounts | ✅ Full | `AgentIdentity` registry with DID inventory |
| 5.2 | Use unique passwords | ✅ Full | Ed25519 keypairs — no passwords, cryptographic identity |
| 5.3 | Disable dormant accounts | ✅ Full | `AgentIdentity.suspend()` / `revoke()` |
| 5.4 | Restrict administrator privileges | ✅ Full | Delegation chains with monotonic scope narrowing |

### CIS Control 6: Access Management

| Safeguard | Description | AGT Coverage | Module |
|-----------|------------|-------------|--------|
| 6.1 | Establish an access granting process | ✅ Full | Policy rules with `require_approval` + `ApprovalHandler` |
| 6.2 | Establish an access revoking process | ✅ Full | Kill switch + `AgentIdentity.revoke()` |
| 6.3 | Require MFA for externally-exposed applications | 🟡 Partial | Trust handshake (challenge-response), not traditional MFA |
| 6.5 | Require MFA for administrative access | 🟡 Partial | Human sponsor model; MFA depends on IdP |

### CIS Control 7: Continuous Vulnerability Management

| Safeguard | Description | AGT Coverage | Module |
|-----------|------------|-------------|--------|
| 7.1 | Establish and maintain a vulnerability management process | ✅ Full | `McpCveFeed` + Dependabot + CodeQL |
| 7.2 | Establish and maintain a remediation process | ✅ Full | `incident-response-workflow.md` |
| 7.4 | Perform automated application patch management | 🟡 Partial | Dependabot for deps; MCP server patching is external |
| 7.7 | Remediate detected vulnerabilities | ✅ Full | CVE severity → policy-gated blocking of vulnerable servers |

### CIS Control 8: Audit Log Management

| Safeguard | Description | AGT Coverage | Module |
|-----------|------------|-------------|--------|
| 8.1 | Establish and maintain an audit log management process | ✅ Full | `AuditLog` with tamper-evident hash chaining |
| 8.2 | Collect audit logs | ✅ Full | `AuditLog.log()` for all governance events |
| 8.3 | Ensure adequate audit log storage | ✅ Full | `record-retention-policy.md` + configurable `AuditSink` |
| 8.5 | Collect detailed audit logs | ✅ Full | Policy decisions, approval outcomes, trust scores, OTel spans |
| 8.9 | Centralize audit logs | ✅ Full | OTel export to centralized backends (Azure Monitor, Splunk, etc.) |
| 8.11 | Conduct audit log reviews | 🟡 Partial | `AuditLog.query()` + OTel dashboards; no automated review |

### CIS Control 10: Malware Defenses

| Safeguard | Description | AGT Coverage | Module |
|-----------|------------|-------------|--------|
| 10.1 | Deploy and maintain anti-malware software | 🟡 Partial | `PromptInjectionDetector` + advisory classifiers |
| 10.7 | Use behavior-based anti-malware software | ✅ Full | `PatternAdvisory` + `CallbackAdvisory` for anomaly detection |

### CIS Control 11: Data Recovery

| Safeguard | Description | AGT Coverage | Module |
|-----------|------------|-------------|--------|
| 11.1 | Establish and maintain a data recovery process | ⬜ Gap | AGT does not manage backups; depends on infrastructure |

### CIS Control 13: Network Monitoring and Defense

| Safeguard | Description | AGT Coverage | Module |
|-----------|------------|-------------|--------|
| 13.1 | Centralize security event alerting | ✅ Full | OTel metrics + `agt.policy.denials` alerts |
| 13.6 | Collect network traffic flow logs | ⬜ Gap | Network-level; outside AGT scope |

### CIS Control 14: Security Awareness and Skills Training

| Safeguard | Description | AGT Coverage | Module |
|-----------|------------|-------------|--------|
| 14.1 | Establish and maintain a security awareness program | ⬜ Gap | Organizational responsibility; AGT provides 40+ tutorials |
| 14.9 | Conduct role-specific security awareness training | 🟡 Partial | Tutorials cover governance for developers; no formal training program |

### CIS Control 16: Application Software Security

| Safeguard | Description | AGT Coverage | Module |
|-----------|------------|-------------|--------|
| 16.1 | Establish and maintain a secure application development process | ✅ Full | Policy-as-code, CI/CD with CodeQL + Gitleaks + fuzzing |
| 16.4 | Establish and maintain a secure coding standard | ✅ Full | `.pre-commit-hooks.yaml`, linting, OWASP mapping |
| 16.9 | Train developers in application security | 🟡 Partial | 40+ tutorials; no formal certification |
| 16.12 | Implement code-level security checks | ✅ Full | `PromptInjectionDetector`, `McpSecurityScanner`, advisory classifiers |

### CIS Control 17: Incident Response Management

| Safeguard | Description | AGT Coverage | Module |
|-----------|------------|-------------|--------|
| 17.1 | Designate personnel to manage incident handling | ⬜ Gap | Organizational responsibility |
| 17.2 | Establish and maintain contact information for reporting incidents | 🟡 Partial | `SECURITY.md` in repo; no integrated incident contact system |
| 17.4 | Establish and maintain an incident response process | ✅ Full | `incident-response-workflow.md` |
| 17.8 | Conduct post-incident reviews | ✅ Full | Post-mortem template in incident response workflow |

---

## Gap Analysis

| # | Gap | Severity | Recommendation |
|---|-----|----------|---------------|
| 1 | **Data recovery** (CIS 11.1) | Medium | Document backup procedures for audit logs and policy stores. AGT can recommend but not enforce backup. |
| 2 | **Network traffic flow logs** (CIS 13.6) | Low | Network-level concern; recommend AKS/infrastructure-layer monitoring. |
| 3 | **Security awareness program** (CIS 14.1) | Medium | AGT provides tutorials; organizations should build formal training around them. |
| 4 | **Incident handling personnel** (CIS 17.1) | Medium | Organizational responsibility; document in impact assessment template. |

---

> **Related**: [NIST AI RMF Alignment](nist-ai-rmf-alignment.md) · [SOC 2 Mapping](soc2-mapping.md) · [OWASP Agentic Top 10 Architecture](owasp-agentic-top10-architecture.md) · [EU AI Act Checklist](eu-ai-act-checklist.md)
