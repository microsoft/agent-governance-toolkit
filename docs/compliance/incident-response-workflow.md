<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# AI Agent Incident Classification and Response Workflow

> **Purpose**: Define how AI agent governance incidents are classified, triaged,
> and resolved. Aligns with Colorado AI Act disclosure requirements, EU AI Act
> Article 62 (serious incident reporting), and NIST AI RMF MANAGE function.

---

## 1. Incident Classification

### 1.1 Severity Levels

| Severity | Definition | Response SLA | Examples |
|----------|-----------|-------------|---------|
| **P0 — Critical** | Agent caused or is actively causing harm to individuals or systems | Immediate (< 1 hour) | Unauthorized financial transactions, PII breach, discriminatory decisions affecting protected classes |
| **P1 — High** | Agent policy bypass detected, potential for harm if unchecked | < 4 hours | Kill switch failure, prompt injection succeeded, trust verification bypassed |
| **P2 — Medium** | Agent behavior anomaly, no confirmed harm | < 24 hours | Unexpected tool calls, trust score degradation, audit log gaps |
| **P3 — Low** | Governance configuration issue, no user impact | < 1 week | Policy rule misconfiguration, non-critical test failures, documentation gap |

### 1.2 Category Taxonomy

| Category | Description | OWASP Reference |
|----------|------------|----------------|
| **HIJACK** | Agent taken over by adversarial input | ASI-01 |
| **CAPABILITY_BREACH** | Agent performed unauthorized action | ASI-02 |
| **DATA_LEAK** | Sensitive data exposed through agent | ASI-04, ASI-05 |
| **TRUST_FAILURE** | Identity verification or trust scoring failed | ASI-06, ASI-07 |
| **CASCADE** | Multi-agent failure propagation | ASI-08 |
| **AUDIT_FAILURE** | Audit trail compromised or incomplete | ASI-09 |
| **RESOURCE_ABUSE** | Agent consumed excessive resources | ASI-10 |
| **BIAS_HARM** | Agent produced discriminatory outcome | Fairness |
| **POLICY_BYPASS** | Deterministic policy was circumvented | Governance |

## 2. Response Workflow

```
Incident Detected
      │
      ▼
┌──────────────────┐
│ 1. TRIAGE         │ Classify severity + category
│    (< 15 min)     │ Assign incident commander
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 2. CONTAIN        │ Kill switch if P0/P1
│    (< 1 hour P0)  │ Isolate affected agents
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 3. INVESTIGATE    │ Pull audit logs
│                   │ Reproduce with evidence
│                   │ Identify root cause
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 4. REMEDIATE      │ Fix policy/code
│                   │ Deploy updated governance
│                   │ Verify fix with tests
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 5. NOTIFY         │ Affected individuals (if required)
│                   │ Regulators (P0, per jurisdiction)
│                   │ Internal stakeholders
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 6. POST-MORTEM    │ Root cause analysis
│                   │ Update policies/ratchets
│                   │ Add regression tests
│                   │ Update this workflow if needed
└──────────────────┘
```

## 3. Containment Actions by Severity

### P0 — Critical
1. **Immediately** activate kill switch: `agt kill --agent <DID> --reason INCIDENT`
2. Isolate the agent from all network communication
3. Preserve audit logs (do NOT rotate or delete)
4. Notify incident commander and legal within 1 hour

### P1 — High
1. Disable the affected policy rule or tool capability
2. Switch agent to read-only mode if available
3. Review last 24 hours of audit logs for scope assessment

### P2/P3 — Medium/Low
1. Create tracking issue with full reproduction steps
2. Update policy YAML with corrective rule
3. Schedule fix for next sprint

## 4. Evidence Collection

For every incident, collect and preserve:

| Artifact | Source | Retention |
|----------|--------|-----------|
| Audit log entries | `AuditLog.query(agent_did=..., start_time=...)` | Per [retention policy](record-retention-policy.md) |
| Policy decision chain | `PolicyDecision` objects with matched rules | Duration of investigation + 3 years |
| Agent identity and trust state | `AgentIdentity`, trust scores at time of incident | Duration of investigation + 3 years |
| OTel traces | `agt.policy.evaluate` spans | 90 days (configurable) |
| Approval decisions | `approval_decision` audit entries | Duration of investigation + 3 years |
| Session state snapshots | `SessionState.get_all()` | Duration of investigation |

## 5. Notification Requirements

### Colorado AI Act (SB 21-169)
- **When**: Within 90 days of discovering a consequential decision that harmed a consumer
- **Who**: Affected consumers
- **What**: Description of the AI system, the decision made, how to contest it

### EU AI Act (Article 62)
- **When**: Without undue delay, no later than 15 days after becoming aware
- **Who**: Market surveillance authority of the Member State
- **What**: Serious incidents involving high-risk AI systems that led to death, serious damage to health, serious disruption to critical infrastructure, or violation of fundamental rights

### General Best Practice
- Internal stakeholders: within 24 hours for P0/P1
- Security team: immediately for any policy bypass
- Customers: per contractual SLA

## 6. Post-Mortem Template

```markdown
# Incident Post-Mortem: [INCIDENT-ID]

**Date**: 
**Severity**: P0 / P1 / P2 / P3
**Category**: 
**Agent**: 
**Duration**: 
**Impact**: 

## Timeline
- [time] Incident detected by [method]
- [time] Triage completed, classified as [severity]
- [time] Containment action taken
- [time] Root cause identified
- [time] Fix deployed
- [time] Incident resolved

## Root Cause
[Description]

## What Went Well
- 

## What Went Wrong
- 

## Action Items
| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
| | | | |

## Policy Changes
- [ ] New policy rule added
- [ ] Attribute ratchet updated
- [ ] Advisory classifier pattern added
- [ ] Test added to prevent regression
```

---

> **Related**: [Impact Assessment Template](impact-assessment-template.md) · [Record Retention Policy](record-retention-policy.md) · [OWASP Agentic Top 10 Architecture](owasp-agentic-top10-architecture.md)
