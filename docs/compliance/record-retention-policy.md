<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Record Retention Policy for AI Governance Artifacts

> **Purpose**: Define how long AI agent governance artifacts (audit logs, policy
> decisions, identity records, incident reports) must be retained. Aligns with
> Colorado AI Act (SB 21-169), EU AI Act, SOC 2, and ISO 42001 requirements.

---

## 1. Retention Schedule

| Artifact Type | Minimum Retention | Regulatory Basis | AGT Source |
|--------------|-------------------|-----------------|------------|
| **Audit log entries** | 3 years | Colorado AI Act §6-1-1703; EU AI Act Art. 12(2) | `AuditLog`, `AuditChain` |
| **Policy decision records** | 3 years | Colorado AI Act §6-1-1703(2) | `PolicyDecision` objects |
| **Policy YAML versions** | Lifetime of agent + 3 years | SOC 2 CC8.1; ISO 42001 A.6.2.6 | Git version control |
| **Agent identity records** | Lifetime of agent + 3 years | EU AI Act Art. 49(4) | `AgentIdentity`, DID documents |
| **Trust verification results** | 1 year | Best practice | `TrustHandshake` results |
| **Approval decisions** | 3 years | SOC 2 CC6.1; Colorado AI Act | `approval_decision` audit entries |
| **Impact assessments** | Lifetime of agent + 5 years | EU AI Act Art. 9(7) | [impact-assessment-template.md](impact-assessment-template.md) |
| **Incident reports** | 5 years | SOC 2 CC7.4; EU AI Act Art. 62 | [incident-response-workflow.md](incident-response-workflow.md) |
| **Session state snapshots** | 90 days (or duration of investigation) | Operational | `SessionState` |
| **OTel traces and metrics** | 90 days | Operational | OTel exporters |
| **Compliance assessment reports** | 5 years | ISO 42001 A.6.2.3 | Compliance docs |
| **Training/fine-tuning data provenance** | Lifetime of model + 3 years | EU AI Act Art. 10 | Future: data provenance model |

## 2. Retention by Regulation

### 2.1 Colorado AI Act (SB 21-169)
- **What**: Records of consequential decisions made by AI agents
- **Duration**: At least 3 years from date of decision
- **Content**: Decision outcome, factors considered, consumer notification
- **AGT mapping**: `AuditLog.query()` entries with `policy_decision` field

### 2.2 EU AI Act
- **What**: Logs of high-risk AI system operations (Art. 12)
- **Duration**: At least 6 months; longer for high-risk (Art. 12(2))
- **Content**: Input data, decisions, anomalies, cross-border transfers
- **AGT mapping**: Tamper-evident `AuditChain` with hash-chaining

### 2.3 SOC 2
- **What**: Evidence of control operation (Type II)
- **Duration**: Duration of audit period + retention per SOC 2 criteria
- **AGT mapping**: `ComplianceEngine` verification reports, policy versions in git

### 2.4 ISO 42001
- **What**: Records of AI management system operation
- **Duration**: Per organizational policy (recommended: 5 years)
- **AGT mapping**: Impact assessments, policy YAML, compliance reports

## 3. Storage Requirements

### 3.1 Integrity
- Audit logs MUST be stored in tamper-evident format
- AGT's `AuditChain` uses SHA-256 hash chaining — each entry includes the hash of the previous entry
- External sinks (via `AuditSink`) should use append-only storage

### 3.2 Accessibility
- Retained records MUST be retrievable within a reasonable timeframe
- `AuditLog.query()` supports filtering by agent, time range, event type, and outcome
- Archive older records to cold storage after 1 year; maintain index for retrieval

### 3.3 Confidentiality
- Records containing PII must be encrypted at rest
- Access to audit logs should be restricted to authorized roles
- Deletion requests (GDPR Art. 17) must be balanced against retention obligations

### 3.4 Recommended Storage Backends

| Backend | Use Case | Retention Support |
|---------|----------|-------------------|
| Azure Blob Storage (immutable) | Production audit logs | WORM policy, legal hold |
| Azure Table Storage | Operational logs | TTL-based cleanup |
| Git repository | Policy versions | Permanent history |
| Azure Data Explorer / Log Analytics | OTel traces | Configurable retention |
| On-premises encrypted storage | Regulated environments | Per policy |

## 4. Disposal

### 4.1 When to Delete
- After the retention period expires AND no active investigation or legal hold
- Never delete during an active incident investigation
- Never delete records subject to litigation hold

### 4.2 How to Delete
- Securely erase (not just remove references)
- Log the deletion event in the audit trail
- Retain a deletion record (what was deleted, when, by whom) for 1 year

### 4.3 Exceptions
- **Legal hold**: Overrides all retention schedules — retain indefinitely until hold is released
- **Active investigation**: Extend retention until investigation concludes + 1 year
- **Regulatory request**: Comply with the longer of retention schedule or regulatory requirement

## 5. Implementation with AGT

### 5.1 Configure Audit Sink for Long-Term Storage

```python
from agentmesh.governance import AuditLog
from agentmesh.governance import FileAuditSink

# File-based sink with daily rotation
sink = FileAuditSink(
    directory="/var/log/agt/audit",
    rotate="daily",
    compress=True,
)
audit = AuditLog(sink=sink)
```

### 5.2 Policy Versioning via Git

```bash
# All policy changes are tracked in git
git log --oneline policies/
# Each commit = a version with timestamp, author, and diff
```

### 5.3 Automated Retention Enforcement

```yaml
# Example: Azure Blob Storage immutable policy
retention:
  audit_logs:
    storage: azure_blob_immutable
    duration_days: 1095  # 3 years
    legal_hold: false
  incident_reports:
    storage: azure_blob_immutable
    duration_days: 1825  # 5 years
    legal_hold: false
```

---

> **Related**: [Impact Assessment Template](impact-assessment-template.md) · [Incident Response Workflow](incident-response-workflow.md) · [SOC 2 Mapping](soc2-mapping.md) · [EU AI Act Checklist](eu-ai-act-checklist.md)
