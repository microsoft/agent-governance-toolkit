<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# AI Agent Impact Assessment Template

> **Purpose**: Structured template for assessing risks and impacts before deploying
> AI agents in high-risk environments. Aligns with Colorado AI Act (SB 21-169),
> EU AI Act Article 9, and NIST AI RMF MAP function.
>
> **Usage**: Complete this template for each agent deployment. Store completed
> assessments alongside the agent's policy YAML in version control.

---

## 1. Agent Identification

| Field | Value |
|-------|-------|
| **Agent Name** | |
| **Agent DID** | `did:agentmesh:...` |
| **Version** | |
| **Owner / Sponsor** | |
| **Deployment Environment** | ☐ Development ☐ Staging ☐ Production |
| **Assessment Date** | |
| **Assessor** | |
| **Review Due Date** | |

## 2. Purpose and Scope

### 2.1 Agent Purpose
_Describe what the agent does, what decisions it makes, and what actions it takes._

### 2.2 Target Population
_Who is affected by the agent's actions? Include both direct users and downstream affected parties._

### 2.3 Decision Types
| Decision | Consequential? | Reversible? |
|----------|---------------|-------------|
| _e.g., Loan approval_ | ☐ Yes ☐ No | ☐ Yes ☐ No |
| _e.g., Content moderation_ | ☐ Yes ☐ No | ☐ Yes ☐ No |

> **Consequential decisions** (Colorado AI Act): decisions that have a material
> legal or similarly significant effect on consumers in education, employment,
> financial services, healthcare, housing, insurance, or government services.

## 3. Risk Classification

### 3.1 Risk Level
| Framework | Classification | Justification |
|-----------|---------------|---------------|
| EU AI Act | ☐ Minimal ☐ Limited ☐ High ☐ Unacceptable | |
| NIST AI RMF | ☐ Low ☐ Moderate ☐ High ☐ Critical | |
| OWASP Agentic | Applicable risks: | |
| Organization | ☐ Tier 1 ☐ Tier 2 ☐ Tier 3 | |

### 3.2 OWASP Agentic Top 10 Assessment
| # | Risk | Applicable? | AGT Mitigation |
|---|------|------------|----------------|
| ASI-01 | Agent Hijacking | ☐ Yes ☐ No | Policy engine, prompt injection detection |
| ASI-02 | Excessive Capabilities | ☐ Yes ☐ No | Capability allow/deny lists |
| ASI-03 | Tool Poisoning | ☐ Yes ☐ No | MCP security scanner |
| ASI-04 | Insecure Data Handling | ☐ Yes ☐ No | Attribute ratchets, DLP |
| ASI-05 | Insecure Output | ☐ Yes ☐ No | Pre-output policy stage |
| ASI-06 | Confused Deputy | ☐ Yes ☐ No | Zero-trust identity, trust scoring |
| ASI-07 | Unsafe Inter-Agent Communication | ☐ Yes ☐ No | E2E encryption (Signal protocol) |
| ASI-08 | Cascading Failures | ☐ Yes ☐ No | Circuit breaker, kill switch |
| ASI-09 | Inadequate Logging | ☐ Yes ☐ No | Tamper-evident audit, OTel |
| ASI-10 | Resource Exhaustion | ☐ Yes ☐ No | Rate limiting, token budgets |

## 4. Data Assessment

### 4.1 Data Inputs
| Data Source | Contains PII? | Classification | Jurisdiction |
|------------|--------------|----------------|-------------|
| | ☐ Yes ☐ No | ☐ Public ☐ Internal ☐ Confidential ☐ Restricted | |

### 4.2 Data Outputs
| Output Type | Contains PII? | External Recipients? |
|------------|--------------|---------------------|
| | ☐ Yes ☐ No | ☐ Yes ☐ No |

### 4.3 Data Residency
- Storage locations: 
- Cross-border transfers: ☐ Yes ☐ No
- If yes, legal basis:

## 5. Bias and Fairness

### 5.1 Protected Classes Potentially Affected
☐ Race/Ethnicity ☐ Gender ☐ Age ☐ Disability ☐ Religion ☐ National Origin ☐ Other: ___

### 5.2 Fairness Testing
- Has the agent been tested for disparate impact? ☐ Yes ☐ No
- Testing methodology:
- Results summary:

### 5.3 Mitigation Measures
_Describe controls to prevent discriminatory outcomes._

## 6. Governance Controls

### 6.1 AGT Policy Configuration
```yaml
# Reference the agent's policy file
policy_file: policies/<agent-name>.yaml
extends:
  - policies/org-baseline.yaml
```

### 6.2 Approval Gates
| Action | Requires Approval? | Approver |
|--------|-------------------|----------|
| _e.g., Financial transaction > $10K_ | ☐ Yes ☐ No | |

### 6.3 Human Oversight
- Kill switch configured? ☐ Yes ☐ No
- Human-in-the-loop for consequential decisions? ☐ Yes ☐ No
- Escalation path defined? ☐ Yes ☐ No

## 7. Transparency and Explainability

- Can the agent explain its decisions to affected individuals? ☐ Yes ☐ No
- Is there a consumer-facing disclosure that AI is being used? ☐ Yes ☐ No
- Are audit logs accessible for review? ☐ Yes ☐ No

## 8. Incident Response

- Incident classification defined? ☐ Yes ☐ No (see [incident-response-workflow.md](incident-response-workflow.md))
- Rollback procedure documented? ☐ Yes ☐ No
- Notification process for affected individuals? ☐ Yes ☐ No

## 9. Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Agent Owner | | | |
| Security Review | | | |
| Privacy Review | | | |
| Legal/Compliance | | | |
| Management Approval | | | |

## 10. Review Schedule

- Next review date:
- Review trigger events: ☐ Major version change ☐ Policy update ☐ Incident ☐ Regulatory change ☐ Annual

---

> **Related**: [NIST AI RMF Alignment](nist-ai-rmf-alignment.md) · [EU AI Act Checklist](eu-ai-act-checklist.md) · [SOC 2 Mapping](soc2-mapping.md) · [Record Retention Policy](record-retention-policy.md)
