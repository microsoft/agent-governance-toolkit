# HR Recruiting Agent

A governed AI agent for recruiting and candidate screening with bias prevention and data privacy.

## Use Case

HR departments need AI assistance for recruiting while ensuring:
- Fair hiring practices (no discriminatory screening)
- Candidate data privacy (GDPR, CCPA)
- Consistent evaluation criteria
- Audit trails for compliance

## Governance Features

| Feature | Implementation |
|---------|----------------|
| **Bias Prevention** | Block access to protected characteristics |
| **Data Privacy** | GDPR/CCPA compliant data handling |
| **Fair Screening** | Consistent criteria across all candidates |
| **Audit Trail** | Log all screening decisions |
| **Data Retention** | Auto-delete candidate data per policy |

## Quick Start

```bash
pip install agent-os-kernel[full]
python main.py
```

## Policy Configuration

```yaml
# policy.yaml
governance:
  name: hr-recruiting-agent
  framework: fair-hiring
  
permissions:
  candidate_data:
    blocked_fields:
      - age
      - gender
      - race
      - religion
      - marital_status
      - disability
      - national_origin
    allowed_fields:
      - skills
      - experience
      - education
      - work_history
      
  screening:
    - action: evaluate_candidate
      require: [consistent_criteria, blind_review]
    - action: reject_candidate
      require: [documented_reason, non_discriminatory]
      
data_retention:
  unsuccessful_candidates: 180  # days
  successful_candidates: 2555   # 7 years
  
audit:
  level: comprehensive
  include:
    - candidate_id (hashed)
    - decision
    - criteria_used
    - reviewer_id
```

## Compliance

- **EEOC Guidelines**: Title VII compliance
- **GDPR Article 22**: Automated decision-making rights
- **CCPA**: California consumer privacy
- **ADA**: Disability accommodation
