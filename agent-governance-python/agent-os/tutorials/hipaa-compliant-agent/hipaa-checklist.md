# HIPAA Compliance Checklist for AI Agents

> Use this checklist to ensure your AI agent meets HIPAA requirements. Items marked with ✅ are covered by Agent OS; items marked with 🔧 require external implementation.

---

## Administrative Safeguards (§164.308)

| # | Requirement | Agent OS | Status | Notes |
|---|------------|:--------:|:------:|-------|
| 1 | **Security Management Process** — Risk analysis and risk management | 🔧 | ☐ | Perform risk analysis covering AI agent data flows |
| 2 | **Assigned Security Responsibility** — Designated security officer | 🔧 | ☐ | Assign HIPAA Security Officer for agent operations |
| 3 | **Workforce Security** — Authorization and supervision procedures | ✅ | ☐ | Agent OS enforces role-based access control (RBAC) |
| 4 | **Information Access Management** — Access authorization policies | ✅ | ☐ | HIPAA policy template enforces minimum necessary |
| 5 | **Security Awareness Training** — Training for workforce members | 🔧 | ☐ | Train staff on AI agent HIPAA procedures |
| 6 | **Security Incident Procedures** — Incident response plan | ✅ Partial | ☐ | Agent OS detects violations; you need response procedures |
| 7 | **Contingency Plan** — Data backup and disaster recovery | 🔧 | ☐ | Backup audit logs and agent configurations |
| 8 | **Evaluation** — Periodic security assessments | 🔧 | ☐ | Regularly audit agent access patterns and policies |
| 9 | **Business Associate Agreements** — BAAs with all vendors | 🔧 | ☐ | BAAs with LLM providers, cloud hosts, and Agent OS |

---

## Physical Safeguards (§164.310)

| # | Requirement | Agent OS | Status | Notes |
|---|------------|:--------:|:------:|-------|
| 1 | **Facility Access Controls** — Limit physical access to systems | 🔧 | ☐ | Secure servers running AI agents |
| 2 | **Workstation Use** — Policies for workstation access | 🔧 | ☐ | Define acceptable agent access points |
| 3 | **Workstation Security** — Physical safeguards for workstations | 🔧 | ☐ | Secure devices that interact with agents |
| 4 | **Device and Media Controls** — Disposal and reuse procedures | 🔧 | ☐ | Secure disposal of systems with cached PHI |

> **Note:** Physical safeguards are primarily infrastructure concerns. Agent OS operates at the software layer.

---

## Technical Safeguards (§164.312)

| # | Requirement | Agent OS | Status | Notes |
|---|------------|:--------:|:------:|-------|
| 1 | **Access Control — Unique User ID** | ✅ | ☐ | Agent OS tracks `agent_id`, `user_id`, `session_id` |
| 2 | **Access Control — Emergency Access** | ✅ | ☐ | Break-the-glass with full audit trail (see healthcare example) |
| 3 | **Access Control — Automatic Logoff** | ✅ | ☐ | Session timeout (`timeout_seconds`) and tool call limits |
| 4 | **Access Control — Encryption** | 🔧 | ☐ | Encrypt PHI at rest and in transit (TLS, AES-256) |
| 5 | **Audit Controls** | ✅ | ☐ | Immutable, hash-chained audit logs with 6-year retention |
| 6 | **Integrity Controls** | ✅ | ☐ | Tamper-evident audit logs with hash verification |
| 7 | **Authentication** | ✅ Partial | ☐ | Agent OS validates agent identity; integrate with your IdP |
| 8 | **Transmission Security** | 🔧 | ☐ | Use TLS for all agent API calls; encrypt PHI in transit |

---

## AI Agent–Specific Considerations

These are not explicit HIPAA requirements but are critical for AI agents handling PHI:

| # | Consideration | Agent OS | Status | Notes |
|---|--------------|:--------:|:------:|-------|
| 1 | **PHI in prompts** — Detect and block PHI in LLM inputs | ✅ | ☐ | Regex-based detection for all 18 identifiers |
| 2 | **PHI in responses** — Detect and block PHI in LLM outputs | ✅ | ☐ | Output scanning with SIGKILL on violation |
| 3 | **Model training data** — Ensure PHI not used for training | 🔧 | ☐ | Use LLM providers with no-training guarantees |
| 4 | **Prompt injection** — Prevent PHI extraction via prompt attacks | ✅ | ☐ | Pattern blocking prevents PHI in any context |
| 5 | **Data minimization** — Send minimum data to LLM | ✅ | ☐ | Minimum necessary policy blocks bulk queries |
| 6 | **Session isolation** — Prevent cross-patient data leakage | ✅ | ☐ | Session-scoped policies with tool call limits |
| 7 | **Human oversight** — Human-in-the-loop for PHI access | ✅ | ☐ | SIGSTOP with approval_level: hipaa_officer |
| 8 | **Vendor assessment** — Evaluate LLM provider HIPAA compliance | 🔧 | ☐ | Choose providers with BAA and SOC 2 compliance |
| 9 | **De-identification** — Remove PHI before non-clinical use | ✅ | ☐ | PHI detection + de-identification utilities |
| 10 | **Breach detection** — Real-time PHI exposure alerting | ✅ | ☐ | SIGUSR1 signal for compliance officer escalation |

---

## Coverage Summary

| Category | Total Items | Agent OS Covers | External Needed |
|----------|:-----------:|:---------------:|:---------------:|
| Administrative Safeguards | 9 | 3 | 6 |
| Physical Safeguards | 4 | 0 | 4 |
| Technical Safeguards | 8 | 5 | 3 |
| AI Agent–Specific | 10 | 7 | 3 |
| **Total** | **31** | **15** | **16** |

Agent OS covers **~48% of HIPAA requirements** at the technical layer. The remaining items require organizational policies, physical security, legal agreements (BAAs), and infrastructure-level controls.

---

## How to Use This Checklist

1. **Review each item** and check the Status column as you implement it
2. **For ✅ items**: Verify Agent OS is configured with the HIPAA policy template
3. **For 🔧 items**: Implement the external control and document it
4. **For ✅ Partial items**: Agent OS provides part of the solution; complete with your infrastructure
5. **Re-evaluate quarterly** — HIPAA compliance is ongoing, not one-time

### Quick Start

```python
from agent_os.templates.policies.loader import load_policy

# Load the HIPAA template to cover all ✅ items
policy = load_policy("hipaa")
```

### Key Agent OS Configuration for HIPAA

```yaml
# templates/policies/hipaa.yaml covers:
policies:
  - phi_ssn_detection        # ✅ Technical Safeguard: Access Control
  - phi_mrn_detection        # ✅ Technical Safeguard: Access Control
  - phi_phone_detection      # ✅ AI-Specific: PHI in prompts/responses
  - phi_health_identifiers   # ✅ AI-Specific: PHI in prompts/responses
  - phi_data_access_approval # ✅ Administrative: Information Access Management
  - session_tool_call_limit  # ✅ Technical Safeguard: Automatic Logoff
  - minimum_necessary        # ✅ Administrative: Information Access Management

audit:
  enabled: true              # ✅ Technical Safeguard: Audit Controls
  mandatory: true
  retention_days: 2190       # ✅ 6-year retention
  immutable: true            # ✅ Technical Safeguard: Integrity Controls
```

---

## References

- [HIPAA Security Rule (45 CFR Part 164)](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [HIPAA Privacy Rule](https://www.hhs.gov/hipaa/for-professionals/privacy/index.html)
- [HHS Guidance on AI and HIPAA](https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/index.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Agent OS HIPAA Policy Template](../../templates/policies/hipaa.yaml)
- [Agent OS Healthcare Example](../../examples/healthcare-hipaa/)
