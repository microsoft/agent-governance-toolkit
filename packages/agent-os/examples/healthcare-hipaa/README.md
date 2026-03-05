# Healthcare Agent (HIPAA + HL7 FHIR Compliant)

A medical records assistant with built-in HIPAA compliance and HL7 FHIR interoperability using Agent OS governance.

> **HL7 FHIR Compatible** - Built to integrate with the [HL7 FHIR](https://hl7.org/fhir/) healthcare interoperability standard.

## Features

| Feature | Description | Standard |
|---------|-------------|----------|
| **PHI Protection** | Block unauthorized disclosure | HIPAA Privacy Rule |
| **Audit Logging** | 6-year retention with tamper detection | HIPAA §164.312(b) |
| **Role-Based Access** | Minimum necessary principle | HIPAA §164.514(d) |
| **FHIR Resources** | Native Patient, Observation, MedicationRequest | HL7 FHIR R4 |
| **Smart on FHIR** | OAuth2 authorization | SMART App Launch |

## Quick Start

```bash
pip install agent-os-kernel
python main.py
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Healthcare Agent                           │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Patient    │  │  Clinical   │  │  Medication         │  │
│  │  Lookup     │  │  Notes      │  │  Orders             │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────────────┘  │
│         │                │                │                  │
│         ▼                ▼                ▼                  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              Agent OS Governance Layer                 │  │
│  │  • PHI Filter (blocks external disclosure)            │  │
│  │  • Audit Logger (HIPAA §164.312)                     │  │
│  │  • Role Enforcer (minimum necessary)                  │  │
│  │  • Consent Manager (patient authorization)            │  │
│  └───────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  FHIR R4    │  │  Epic       │  │  Cerner             │  │
│  │  Server     │  │  MyChart    │  │  PowerChart         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Policy Configuration

```yaml
# policy.yaml - HIPAA + FHIR Compliance Policy
version: "1.0"
name: healthcare-hipaa-agent
compliance_frameworks:
  - HIPAA
  - HL7_FHIR_R4

phi_identifiers:
  - patient_name
  - date_of_birth
  - ssn
  - medical_record_number
  - phone
  - email
  - address
  - biometric

rules:
  # Block PHI in external communications
  - name: block-phi-external
    trigger: action
    condition: 
      action_type: send_message
      destination: external
    check: does_not_contain_phi
    action: block
    alert: compliance-team

  # Require audit log for all patient data access
  - name: audit-patient-access
    trigger: action
    condition:
      action_type: read
      resource_type: [Patient, Observation, MedicationRequest, DiagnosticReport]
    action: log
    log_level: audit
    retention_years: 6
    
  # Minimum necessary - only access required fields
  - name: minimum-necessary
    trigger: action
    condition:
      action_type: query
      resource_type: Patient
    action: filter_response
    allowed_fields_by_role:
      nurse: [name, birthDate, gender, telecom]
      doctor: [name, birthDate, gender, telecom, identifier, address]
      admin: [name, identifier]

  # Break-the-glass emergency access
  - name: emergency-access
    trigger: action
    condition:
      emergency_flag: true
    action: allow
    require: [reason_documented, supervisor_notified]
    audit_level: critical

# FHIR Resource mappings
fhir_resources:
  Patient:
    phi_fields: [name, birthDate, identifier, telecom, address]
    minimum_necessary: true
  Observation:
    phi_fields: [subject, performer]
    allowed_categories: [vital-signs, laboratory]
  MedicationRequest:
    requires_consent: true
```

## HL7 FHIR Integration

### FHIR Client with Governance

```python
from agent_os.integrations.fhir import FHIRClient

# Connect to FHIR server with governance
client = FHIRClient(
    base_url="https://fhir.hospital.org/r4",
    governance=True  # Enable Agent OS governance
)

# Search patients - automatically filtered by role
patients = await client.search("Patient", {
    "name": "Smith",
    "_count": 10
})
# Only returns fields allowed for current role
# All access logged to audit trail

# Read observation with PHI protection
obs = await client.read("Observation", "12345")
# PHI automatically masked in logs
```

### SMART on FHIR Authorization

```python
from agent_os.integrations.fhir import SMARTAuth

# SMART App Launch
auth = SMARTAuth(
    client_id="my-healthcare-agent",
    scopes=["patient/*.read", "user/*.read"]
)

# Agent OS validates scopes against policy
token = await auth.authorize(
    launch_context={"patient": "12345"}
)
```

## HIPAA Compliance Mapping

| HIPAA Section | Requirement | Agent OS Implementation |
|---------------|-------------|------------------------|
| §164.312(a)(1) | Access Control | Role-based permissions, SMART scopes |
| §164.312(b) | Audit Controls | 6-year audit logs, tamper detection |
| §164.312(c)(1) | Integrity | Hash-chained audit trail |
| §164.312(d) | Authentication | SMART on FHIR, OAuth2 |
| §164.312(e)(1) | Transmission Security | TLS enforcement, PHI encryption |
| §164.514(d) | Minimum Necessary | Field-level filtering by role |
| §164.528 | Accounting of Disclosures | Complete PHI access history |

## Sample Output

```
┌─────────────────────────────────────────────────────────────┐
│  AUDIT LOG - Patient Access                                  │
├─────────────────────────────────────────────────────────────┤
│  2026-02-04 14:30:15 | USER: nurse.jones                    │
│  ACTION: Read Patient/12345                                 │
│  FIELDS: name, birthDate, gender (role-filtered)            │
│  HIPAA: §164.312(b) audit logged                           │
├─────────────────────────────────────────────────────────────┤
│  2026-02-04 14:31:22 | USER: dr.smith                       │
│  ACTION: Read Observation/67890                             │
│  CATEGORY: vital-signs                                      │
│  HIPAA: §164.514(d) minimum necessary applied              │
├─────────────────────────────────────────────────────────────┤
│  2026-02-04 14:32:45 | USER: nurse.jones                    │
│  ACTION: ❌ BLOCKED - Email PHI to external                 │
│  REASON: PHI disclosure to non-covered entity               │
│  HIPAA: §164.502 use/disclosure restriction                │
│  ALERT: Sent to compliance@hospital.org                     │
└─────────────────────────────────────────────────────────────┘
```

## Contributing to HL7

This example follows HL7 FHIR standards. To contribute:

1. Join the FHIR community at [chat.fhir.org](https://chat.fhir.org)
2. Review [FHIR Implementation Guides](https://www.hl7.org/fhir/implementationguide.html)
3. Submit improvements via PR

## License

MIT - Compatible with HL7 contribution requirements.

## References

- [HL7 FHIR R4 Specification](https://hl7.org/fhir/R4/)
- [SMART App Launch Framework](https://docs.smarthealthit.org/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/)
- [US Core Implementation Guide](https://hl7.org/fhir/us/core/)
- [Agent OS Documentation](https://github.com/microsoft/agent-governance-toolkit/tree/main/docs)
