---
title: "OWASP ASI Policy Mapping"
last_reviewed: 2026-06-18
owner: agt-maintainers
---

# OWASP ASI Policy Mapping

<!-- Copyright (c) Microsoft Corporation. -->
<!-- Licensed under the MIT License. -->

Cross-references every rule in the ASI starter policy packs
(`examples/policy-templates/`) to the OWASP Agentic Security Initiative
(ASI) Top 10 risk it mitigates. Use this table during security audits.

**Packs:** `healthcare` · `financial-services` · `general-saas` · `edu-k12`

**References:** 
- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Arcanum-Sec: Prompt Injection Taxonomy](https://github.com/Arcanum-Sec/arc_pi_taxonomy)
- [Arcanum-Sec: sec-context (Code Anti-Patterns)](https://github.com/Arcanum-Sec/sec-context)

---

## Cross-Reference Table

| Rule Name | Pack(s) | ASI Risk(s) | AGT Component |
|-----------|---------|-------------|---------------|
| <a id="asi01-prompt-injection-override"></a>`asi01-prompt-injection-override` | All | ASI-01 | Agent OS — Policy Engine |
| <a id="asi01-prompt-injection-role-hijack"></a>`asi01-prompt-injection-role-hijack` | All | ASI-01 | Agent OS — Policy Engine |
| <a id="asi01-prompt-injection-delimiter"></a>`asi01-prompt-injection-delimiter` | All | ASI-01 | Agent OS — MCP Proxy Sanitizer |
| <a id="healthcare-asi01-cbrn-guardrail"></a>`healthcare-asi01-cbrn-guardrail` | healthcare | ASI-01 | Agent OS — Policy Engine |
| <a id="asi01-prompt-injection-jailbreak"></a>`asi01-prompt-injection-jailbreak` | general-saas | ASI-01 | Agent OS — Policy Engine |
| <a id="asi01-integrity-shipping-guardrail"></a>`asi01-integrity-shipping-guardrail` | All | ASI-01, ASI-02 | Business Continuity — Logistics Guard |
| <a id="asi01-integrity-fraud-guardrail"></a>`asi01-integrity-fraud-guardrail` | All | ASI-01, ASI-02 | Business Continuity — Fraud Guard |
| <a id="asi01-nested-swarm-guardrail"></a>`asi01-nested-swarm-guardrail` | general-saas | ASI-01 | AgentMesh — Delegation Guard |
| <a id="asi02-block-shell-execution"></a>`asi02-block-shell-execution` | All | ASI-02 | Agent OS — Capability Sandboxing |
| <a id="asi02-block-network-exfiltration"></a>`asi02-block-network-exfiltration` | All | ASI-02 | Agent OS — Capability Sandboxing |
| <a id="asi02-block-file-deletion"></a>`asi02-block-file-deletion` | healthcare | ASI-02 | Agent OS — Capability Sandboxing |
| <a id="asi02-block-destructive-operations"></a>`asi02-block-destructive-operations` | financial-services, general-saas | ASI-02 | Agent OS — Capability Sandboxing |
| <a id="financial-asi02-obfuscation-guardrail"></a>`financial-asi02-obfuscation-guardrail` | financial-services | ASI-02 | Agent OS — Binary Inspector |
| <a id="asi02-block-database-mutation"></a>`asi02-block-database-mutation` | general-saas | ASI-02 | Agent SRE — Audit Trail |
| <a id="asi03-block-privilege-escalation"></a>`asi03-block-privilege-escalation` | All | ASI-03 | AgentMesh — DID Identity & Trust |
| <a id="asi03-block-credential-access"></a>`asi03-block-credential-access` | All | ASI-03 | AgentMesh — DID Identity & Trust |
| <a id="financial-asi03-identity-guardrail"></a>`financial-asi03-identity-guardrail` | financial-services | ASI-03 | AgentMesh — Trust Boundary |
| <a id="asi03-block-user-impersonation"></a>`asi03-block-user-impersonation` | general-saas | ASI-03 | AgentMesh — DID Identity & Trust |
| <a id="asi03-account-mfa-bypass"></a>`asi03-account-mfa-bypass` | All | ASI-03 | AgentMesh — Identity Governance |
| <a id="asi03-account-admin-promotion"></a>`asi03-account-admin-promotion` | All | ASI-03 | AgentMesh — Identity Governance |
| <a id="asi03-account-password-reset"></a>`asi03-account-password-reset` | All | ASI-03 | AgentMesh — Identity Governance |
| <a id="asi03-account-audit-tampering"></a>`asi03-account-audit-tampering` | All | ASI-03 | AgentMesh — Identity Governance |
| <a id="asi04-supply-chain-tool-enumeration"></a>`asi04-supply-chain-tool-enumeration` | All | ASI-04 | Agent OS — Recon Guard |
| <a id="asi04-supply-chain-dependency-poisoning"></a>`asi04-supply-chain-dependency-poisoning` | All | ASI-04 | Agent OS — Payload Guard |
| <a id="asi04-supply-chain-plugin-hijack"></a>`asi04-supply-chain-plugin-hijack` | All | ASI-04 | Agent OS — Registry Proxy |
| <a id="asi04-supply-chain-config-mutation"></a>`asi04-supply-chain-config-mutation` | All | ASI-04 | Agent OS — State Guard |
| <a id="asi05-block-code-execution"></a>`asi05-block-code-execution` | All | ASI-05 | Agent Runtime — Execution Rings |
| <a id="asi05-block-dynamic-eval"></a>`asi05-block-dynamic-eval` | All | ASI-05 | Agent Runtime — Execution Rings |
| <a id="asi05-sandbox-anti-pattern-detection"></a>`asi05-sandbox-anti-pattern-detection` | All | ASI-05 | Agent Runtime — Context Guard |
| <a id="asi05-block-ssh"></a>`asi05-block-ssh` | general-saas | ASI-05 | Agent Runtime — Execution Rings |
| <a id="asi06-context-budget-limit"></a>`asi06-context-budget-limit` | All | ASI-06 | Agent OS — VFS / ContextScheduler |
| <a id="asi06-block-context-manipulation"></a>`asi06-block-context-manipulation` | All | ASI-06 | Agent OS — Context Integrity Firewall |
| <a id="asi07-hidden-channel-guardrail"></a>`asi07-hidden-channel-guardrail` | All | ASI-07 | AgentMesh — Signal Monitor |
| <a id="asi08-session-tool-call-limit"></a>`asi08-session-tool-call-limit` | All | ASI-08 | Agent SRE — Circuit Breakers |
| <a id="asi08-swarm-heat-guardrail"></a>`asi08-swarm-heat-guardrail` | All | ASI-08 | Agent SRE — Swarm Monitor |
| <a id="asi09-trust-payment-redirection"></a>`asi09-trust-payment-redirection` | All | ASI-09 | Business Continuity — Trust Firewall |
| <a id="asi09-trust-vip-impersonation"></a>`asi09-trust-vip-impersonation` | All | ASI-09 | Business Continuity — Trust Firewall |
| <a id="asi09-trust-urgency-pretext"></a>`asi09-trust-urgency-pretext` | All | ASI-09 | Business Continuity — Trust Firewall |
| <a id="asi09-trust-phishing-link"></a>`asi09-trust-phishing-link` | All | ASI-09 | Business Continuity — Trust Firewall |
| <a id="asi10-charter-roleplay-block"></a>`asi10-charter-roleplay-block` | All | ASI-10 | Agent OS — Charter Enforcement |
| <a id="asi10-charter-purpose-override"></a>`asi10-charter-purpose-override` | All | ASI-10 | Agent OS — Charter Enforcement |
| <a id="asi10-charter-autonomous-loop"></a>`asi10-charter-autonomous-loop` | All | ASI-10 | Agent OS — Charter Enforcement |
| <a id="asi03-block-credentials-in-output"></a>`asi03-block-credentials-in-output` | All | ASI-02, ASI-03 | Agent OS — Policy Engine |
| <a id="asi06-block-pii-ssn"></a>`asi06-block-pii-ssn` | All | ASI-01, ASI-06 | Agent OS — PII Protection |
| <a id="healthcare-block-phi-mrn"></a>`healthcare-block-phi-mrn` | healthcare | ASI-01, ASI-06 | Agent OS — PII Protection |
| <a id="healthcare-block-phi-dea"></a>`healthcare-block-phi-dea` | healthcare | ASI-01, ASI-06 | Agent OS — PII Protection |
| <a id="healthcare-enforce-deidentification"></a>`healthcare-enforce-deidentification` | healthcare | ASI-02, ASI-06 | Agent OS — Data Pipeline Security |
| <a id="financial-block-pii-credit-card"></a>`financial-block-pii-credit-card` | financial-services | ASI-01, ASI-06 | Agent OS — PII Protection |
| <a id="saas-block-pii-email-bulk"></a>`saas-block-pii-email-bulk` | general-saas | ASI-02, ASI-06 | Agent OS — PII Protection |
| <a id="edu-asi01-homework-bypass"></a>`edu-asi01-homework-bypass` | edu-k12 | ASI-01 | Agent OS — Policy Engine |
| <a id="edu-asi01-content-filter-bypass"></a>`edu-asi01-content-filter-bypass` | edu-k12 | ASI-01 | Agent OS — Policy Engine |
| <a id="edu-asi02-block-grade-mutation"></a>`edu-asi02-block-grade-mutation` | edu-k12 | ASI-02 | Agent OS — Capability Sandboxing |
| <a id="edu-asi02-block-record-write"></a>`edu-asi02-block-record-write` | edu-k12 | ASI-02 | Agent OS — Capability Sandboxing |
| <a id="edu-asi03-block-student-impersonation"></a>`edu-asi03-block-student-impersonation` | edu-k12 | ASI-03 | AgentMesh — DID Identity & Trust |
| <a id="edu-asi06-block-curriculum-poisoning"></a>`edu-asi06-block-curriculum-poisoning` | edu-k12 | ASI-06 | Agent OS — Context Integrity Firewall |
| <a id="edu-asi09-parental-impersonation"></a>`edu-asi09-parental-impersonation` | edu-k12 | ASI-09 | Business Continuity — Trust Firewall |
| <a id="edu-asi09-block-minor-contact-info"></a>`edu-asi09-block-minor-contact-info` | edu-k12 | ASI-09 | Agent OS — PII Protection |
| <a id="edu-block-student-id"></a>`edu-block-student-id` | edu-k12 | ASI-01, ASI-06 | Agent OS — PII Protection |
| <a id="edu-block-phi-iep"></a>`edu-block-phi-iep` | edu-k12 | ASI-01, ASI-06 | Agent OS — PII Protection |
| <a id="edu-block-disciplinary-record"></a>`edu-block-disciplinary-record` | edu-k12 | ASI-01, ASI-06 | Agent OS — PII Protection |
| <a id="edu-cipa-block-adult-content"></a>`edu-cipa-block-adult-content` | edu-k12 | ASI-01, ASI-06 | Agent OS — Policy Engine |
| <a id="edu-cipa-block-violence-content"></a>`edu-cipa-block-violence-content` | edu-k12 | ASI-01, ASI-06 | Agent OS — Policy Engine |
| <a id="edu-block-credentials-in-output"></a>`edu-block-credentials-in-output` | edu-k12 | ASI-02, ASI-03 | Agent OS — Policy Engine |
| <a id="edu-ferpa-audit-record-access"></a>`edu-ferpa-audit-record-access` | edu-k12 | ASI-01, ASI-06 | Agent OS — Audit Trail |

---

## ASI Risk Coverage Matrix

| ASI Risk | healthcare | financial-services | general-saas | edu-k12 |
|----------|:----------:|:-----------------:|:------------:|:-------:|
| ASI-01 Agent Goal Hijack | ✅ | ✅ | ✅ | ✅ |
| ASI-02 Tool Misuse & Exploitation | ✅ | ✅ | ✅ | ✅ |
| ASI-03 Identity & Privilege Abuse | ✅ | ✅ | ✅ | ✅ |
| ASI-04 Agentic Supply Chain | 🔗 | 🔗 | 🔗 | 🔗 |
| ASI-05 Unexpected Code Execution | ✅ | ✅ | ✅ | ✅ |
| ASI-06 Memory & Context Poisoning | ✅ | ✅ | ✅ | ✅ |
| ASI-07 Insecure Inter-Agent Communication | 🔗 | 🔗 | 🔗 | 🔗 |
| ASI-08 Cascading Agent Failures | ✅ | ✅ | ✅ | ✅ |
| ASI-09 Human-Agent Trust Exploitation | 🔗 | 🔗 | 🔗 | ✅ |
| ASI-10 Rogue Agents | 🔗 | 🔗 | 🔗 | 🔗 |

**Legend:**
- ✅ Direct policy rule(s) in this starter pack mitigate this risk
- 🔗 Covered by the AGT runtime stack — see [OWASP ASI coverage](owasp-agentic-top10-architecture.md)

> ASI-04, ASI-07, ASI-09, and ASI-10 are primarily mitigated at the infrastructure
> layer (AgentMesh IATP, approval workflows, execution ring isolation). Policy-level
> controls for those risks require runtime context fields not universally available.
> These are tracked for future starter pack versions.
>
> **edu-k12 exception:** ASI-09 has direct policy-level rules in this pack
> (`edu-asi09-parental-impersonation`, `edu-asi09-block-minor-contact-info`) because
> the elevated duty of care owed to minors warrants inline guardrails even without
> full runtime context.

---

## Default Posture by Pack

| Pack | Default Action | Max Tokens | Max Tool Calls | Confidence |
|------|:--------------:|:----------:|:--------------:|:----------:|
| <a id="healthcare"></a>`healthcare` | `deny` | 8,192 | 15 | 0.95 |
| <a id="financial-services"></a>`financial-services` | `deny` | 6,000 | 20 | 0.95 |
| <a id="general-saas"></a>`general-saas` | `deny` | 12,000 | 30 | 0.85 |
| <a id="edu-k12"></a>`edu-k12` | `deny` | 4,096 | 10 | 0.90 |

All packs implement **deny-all by default**, enforcing the
[Least Agency principle](owasp-agentic-top10-architecture.md).

---

## Regulatory Alignment

| Regulation | Pack | Controls Applied |
|------------|------|-----------------|
| HIPAA §164.514 (PHI De-identification) | healthcare | SSN, MRN, DEA, NPI blocking |
| HIPAA §164.530 (Minimum Necessary) | healthcare | Deny-all default, read-only allowlist |
| PCI DSS Req 3 (Protect Account Data) | financial-services | PAN/SSN blocking in output |
| PCI DSS Req 6 (Secure Systems) | financial-services | Shell/code execution deny |
| SOX §302/906 (Financial Reporting) | financial-services | Transaction action audit trail |
| AML / BSA (Structuring Detection) | financial-services | Bulk transaction blocking |
| GDPR / CCPA (PII Minimization) | general-saas | SSN, bulk email blocking |
| FERPA 20 U.S.C. § 1232g (Education Records) | edu-k12 | Student ID, IEP, disciplinary record blocking; read-access audit logging |
| COPPA 15 U.S.C. § 6501 (Children's Privacy) | edu-k12 | Minor contact info blocking, parental consent audit, SSN/PII deny |
| CIPA 47 U.S.C. § 254(h) (Internet Content) | edu-k12 | Adult content blocking, violence/harmful content blocking |
| PPRA 20 U.S.C. § 1232h (Pupil Rights) | edu-k12 | Academic integrity guardrail, homework-bypass deny |

---

## Prior Art & Acknowledgments

These packs extend existing patterns from this repository:

- `examples/policies/production/healthcare.yaml` — PHI detection patterns
- `examples/policies/production/financial.yaml` — PCI/SOX patterns
- `examples/policies/production/enterprise.yaml` — general enterprise deny rules
- `examples/policies/prompt-injection-safety.yaml` — ASI-01 injection detection
- **Arcanum-Sec Intelligence**: Rules prefixed with `(Arcanum-Sec)` leverage the Arcanum-Sec Prompt Injection Taxonomy or `sec-context` anti-pattern library for high-fidelity detection.

**OWASP reference:** [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

---

*Last updated: June 2026*

**[⬅ Back to Compliance index](index.md)** · **[🛡️ Full OWASP ASI Coverage](owasp-agentic-top10-architecture.md)**
