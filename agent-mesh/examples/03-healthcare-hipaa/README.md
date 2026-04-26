# Healthcare Data Analysis Agent (HIPAA Compliant)

This example demonstrates a HIPAA-compliant healthcare data analysis agent secured with AgentMesh compliance automation.

## What This Example Shows

- **HIPAA Compliance Automation:** Automatic compliance mapping and reporting
- **PHI Handling Policies:** Strict policies for Protected Health Information
- **Audit Logs:** Comprehensive audit trail for compliance
- **Automated Compliance Reports:** Generate SOC 2 and HIPAA reports on demand

## Use Case

A healthcare analytics agent that:
- Analyzes patient data for insights
- **Never exports** PHI without encryption
- Requires approval for certain operations
- Maintains comprehensive audit logs
- Generates compliance reports for auditors

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│           Healthcare Data Analysis Agent                   │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐ │
│  │ AgentMesh HIPAA Compliance Layer                     │ │
│  │ • PHI Detection & Protection                         │ │
│  │ • Access Controls (need-to-know basis)              │ │
│  │ • Audit Logging (tamper-evident)                     │ │
│  │ • Compliance Reporting (automated)                   │ │
│  └──────────────────────────────────────────────────────┘ │
│                         │                                  │
│         ┌───────────────┴───────────────┐                 │
│         │                               │                 │
│  ┌──────▼─────────┐            ┌───────▼────────┐        │
│  │ EHR Database   │            │ Analytics      │        │
│  │ (PHI)          │            │ Engine         │        │
│  └────────────────┘            └────────────────┘        │
└────────────────────────────────────────────────────────────┘
```

## HIPAA Controls Implemented

| Control | Implementation |
|---------|----------------|
| **Access Control** | Role-based access with minimum necessary principle |
| **Audit Controls** | Comprehensive logging of all PHI access |
| **Integrity** | Append-only audit logs prevent tampering |
| **Person/Entity Authentication** | Cryptographic identity for the agent |
| **Transmission Security** | PHI encrypted in transit (TLS 1.3) |
| **Encryption** | PHI encrypted at rest and in transit |

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the healthcare agent
python main.py

# Generate HIPAA compliance report
python main.py --compliance-report
```

## Key Features

### 1. PHI Detection

```python
# Automatic PHI detection in data
phi_detector = PHIDetector()
contains_phi = phi_detector.scan(data)

if contains_phi:
    # Apply strict controls
    policy_engine.enforce_phi_policy()
```

### 2. Compliance Mapping

```yaml
compliance:
  frameworks:
    - hipaa
    - soc2
  
  controls:
    hipaa:
      - "164.312(a)(1) - Access Control"
      - "164.312(b) - Audit Controls"
      - "164.312(c)(1) - Integrity"
      - "164.312(d) - Person/Entity Authentication"
```

### 3. Automated Compliance Reports

```bash
# Generate compliance report
agentmesh compliance-report \
  --framework hipaa \
  --period 2026-01 \
  --output report.pdf
```

### 4. Audit Trail

Every PHI access creates an audit entry:

```json
{
  "timestamp": "2026-01-31T10:15:00Z",
  "agent": "did:agentmesh:healthcare-agent",
  "action": "phi_access",
  "patient_id": "[ENCRYPTED]",
  "purpose": "analytics",
  "approved_by": "dr.smith@hospital.com"
}
```

## Security Features

- **No PHI Export:** Policy blocks export of unencrypted PHI
- **Approval Required:** Certain operations require human approval
- **Automatic Redaction:** PII/PHI automatically redacted in logs
- **Encrypted Storage:** All patient data encrypted at rest
- **TLS 1.3:** All network communication encrypted
- **Credential Rotation:** 15-minute TTL on credentials

## Compliance Reports

Generate reports for:
- HIPAA compliance status
- SOC 2 Type II evidence
- Audit log summaries
- Access control matrices
- Risk assessments

## Running the Example

```bash
python main.py
```

You'll see:
1. Agent initialization with HIPAA compliance
2. PHI detection in sample data
3. Policy enforcement on PHI access
4. Audit log entries for all operations
5. Compliance report generation

## Production Deployment

For production use:
1. Configure real database connection
2. Set up proper secret management (e.g., HashiCorp Vault)
3. Enable backup and disaster recovery
4. Integrate with SIEM for monitoring
5. Set up regular compliance report generation

## Learn More

- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/)
- [AgentMesh Compliance Engine](../../docs/compliance.md)
- [SOC 2 Automation](../../docs/soc2.md)

---

**Disclaimer:** This example demonstrates technical controls. Consult with legal and compliance teams before deploying in production healthcare environments.
