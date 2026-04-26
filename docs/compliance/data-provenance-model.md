<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Data Provenance Model for AI Agents

> **Purpose**: Track the origin, lineage, and transformation of data that flows
> through AI agent systems. Required by EU AI Act Article 10 (data governance)
> for high-risk AI systems.
>
> **Deadline**: EU AI Act high-risk provisions apply from **August 2, 2026**.

---

## 1. Overview

AI agents consume data from multiple sources (tools, APIs, databases, other agents)
and produce outputs that may affect individuals. Data provenance tracking answers:

- **Where did the data come from?** (origin)
- **How was it transformed?** (lineage)
- **What decisions was it used for?** (purpose)
- **What is its quality and classification?** (metadata)

## 2. Provenance Record Schema

```yaml
# Example provenance record for a tool call
provenance:
  record_id: "prov-2026-07-15-abc123"
  timestamp: "2026-07-15T10:30:00Z"
  agent_did: "did:agentmesh:customer-service-agent"

  # Source: where did the data come from?
  source:
    type: tool_output          # tool_output | api_response | agent_message | user_input | database | file
    tool_name: read_customer_record
    endpoint: "https://api.internal/customers/12345"
    source_agent_did: null     # if from another agent
    source_classification: confidential

  # Data metadata
  data:
    classification: confidential   # public | internal | confidential | restricted
    contains_pii: true
    pii_types: [name, email, phone]
    jurisdiction: [EU, US]
    size_bytes: 2048
    hash: "sha256:a1b2c3..."      # content hash for integrity verification

  # Transformation: what happened to it?
  transformation:
    type: none                     # none | aggregation | anonymization | redaction | enrichment
    description: "Raw customer record, no transformation"

  # Purpose: what was it used for?
  purpose:
    decision_type: customer_inquiry_response
    policy_decision: allow
    policy_rule: allow-read-customer
    audit_entry_id: "audit_abc123"

  # Retention
  retention:
    policy: "3_years"
    expiry: "2029-07-15T10:30:00Z"
    legal_hold: false
```

## 3. Provenance Chain

When data flows through multiple agents or transformation steps, provenance records
form a chain:

```
User Input (prov-001)
    │
    ▼
Agent A reads customer DB (prov-002, parent: prov-001)
    │
    ▼
Agent A sends summary to Agent B (prov-003, parent: prov-002)
    │  transformation: aggregation
    │  classification ratchet: confidential → confidential
    │
    ▼
Agent B generates response (prov-004, parent: prov-003)
    │  transformation: enrichment
    │
    ▼
Response to user (prov-005, parent: prov-004)
    │  policy check: pre_output stage
    │  PII redacted
```

## 4. Integration with AGT

### 4.1 With Session State (Attribute Ratchets)

Data provenance feeds the monotonic attribute ratchets:

```python
from agentmesh.governance import SessionState, SessionAttribute

state = SessionState([
    SessionAttribute(
        name="data_sensitivity",
        ordering=["public", "internal", "confidential", "restricted"],
        monotonic=True,
    ),
])

# After tool returns, check provenance and ratchet sensitivity
provenance = get_provenance(tool_output)
state.set("data_sensitivity", provenance["data"]["classification"])
# If tool returned "confidential" data, sensitivity ratchets up
# and cannot be reset for the rest of the session
```

### 4.2 With Multi-Stage Pipeline

```yaml
rules:
  # post_tool stage: check data classification from tool output
  - name: block-restricted-forwarding
    stage: post_tool
    condition: "tool.output.classification == 'restricted'"
    action: deny
    description: "Restricted data cannot be forwarded to other agents"

  # pre_output stage: check provenance before responding
  - name: redact-pii-in-response
    stage: pre_output
    condition: "response.provenance.contains_pii"
    action: require_approval
    description: "Responses containing PII require human review"
```

### 4.3 With Audit Trail

Every provenance record links to an audit entry:

```python
from agentmesh.governance import AuditLog

audit = AuditLog()
audit.log(
    event_type="data_provenance",
    agent_did="did:agentmesh:agent-1",
    action="read_customer_record",
    data={
        "provenance_id": "prov-002",
        "source": "tool:read_customer_record",
        "classification": "confidential",
        "contains_pii": True,
        "pii_types": ["name", "email"],
    },
    outcome="allow",
)
```

## 5. EU AI Act Article 10 Mapping

| Article 10 Requirement | AGT Provenance Feature |
|----------------------|----------------------|
| **10(2)(a)** Relevant design choices | Provenance schema documents data source selection |
| **10(2)(b)** Data collection processes | `source` field tracks origin and collection method |
| **10(2)(c)** Data preparation operations | `transformation` field records all processing steps |
| **10(2)(d)** Formulation of assumptions | Policy YAML documents decision criteria |
| **10(2)(e)** Assessment of availability, quantity, and suitability | Data quality metadata (classification, size, hash) |
| **10(2)(f)** Examination for bias | `pii_types` and `jurisdiction` enable bias analysis |
| **10(3)** Data governance and management practices | Provenance chain + retention policy |
| **10(4)** Specific considerations for personal data | `contains_pii`, `pii_types`, `jurisdiction` fields |
| **10(5)** Specific data processing provisions | `transformation` field, attribute ratchets |

## 6. Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| Provenance schema | ✅ Defined | This document |
| Audit trail integration | ✅ Shipped | `AuditLog.log(event_type="data_provenance", ...)` |
| Session state ratchets | ✅ Shipped | `SessionState` with monotonic attributes |
| Multi-stage policy | ✅ Shipped | post_tool stage checks tool output classification |
| Provenance chain tracking | 🔜 Planned | Linked provenance records with parent IDs |
| Provenance Python API | 🔜 Planned | `ProvenanceTracker` class |
| Automated PII detection in provenance | 🔜 Planned | Integration with advisory classifiers |

---

> **Related**: [Record Retention Policy](record-retention-policy.md) · [FRIA Template](fria-template.md) · [EU AI Act Checklist](eu-ai-act-checklist.md) · [Tutorial 39 — DLP Attribute Ratchets](../tutorials/39-dlp-attribute-ratchets.md)
