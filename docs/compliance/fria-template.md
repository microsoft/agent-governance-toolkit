<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Fundamental Rights Impact Assessment (FRIA) Template

> **Purpose**: Template for assessing the impact of high-risk AI agent systems on
> fundamental rights, as required by EU AI Act Article 27. Must be completed before
> deploying high-risk AI systems that affect individuals in the EU.
>
> **Deadline**: EU AI Act high-risk provisions apply from **August 2, 2026**.
>
> **Who completes this**: Deployers of high-risk AI systems. This template helps
> structure the assessment; organizations should engage legal counsel and rights
> experts for production deployments.

---

## 1. System Identification

| Field | Value |
|-------|-------|
| **AI System Name** | |
| **Agent DID** | `did:agentmesh:...` |
| **Provider** | |
| **Deployer Organization** | |
| **EU AI Act Risk Classification** | ☐ High-risk (Annex III) ☐ Other |
| **Annex III Category** | ☐ Biometrics ☐ Critical infrastructure ☐ Education ☐ Employment ☐ Essential services ☐ Law enforcement ☐ Migration ☐ Justice |
| **Assessment Date** | |
| **Assessor(s)** | |
| **Data Protection Officer consulted** | ☐ Yes ☐ No |

## 2. Purpose and Intended Use

### 2.1 Description of Purpose
_What is the AI system designed to do? What decisions does it make or support?_

### 2.2 Intended Use Context
_In what context will the system be deployed? What processes does it integrate with?_

### 2.3 Groups of Persons Affected
_Who is directly or indirectly affected by the system's output?_

| Group | How Affected | Estimated Scale |
|-------|-------------|-----------------|
| | | |

## 3. Fundamental Rights Assessment

For each applicable right, assess the potential impact of the AI agent system.

### 3.1 Right to Human Dignity (EU Charter Art. 1)

| Question | Assessment |
|----------|-----------|
| Can the system make decisions that affect a person's dignity? | ☐ Yes ☐ No |
| Is there a risk of dehumanizing or objectifying individuals? | ☐ Yes ☐ No |
| **Impact level** | ☐ None ☐ Low ☐ Medium ☐ High |
| **Mitigation measures** | |

### 3.2 Right to Non-Discrimination (EU Charter Art. 21)

| Question | Assessment |
|----------|-----------|
| Does the system process data related to protected characteristics? | ☐ Yes ☐ No |
| Has bias testing been performed? | ☐ Yes ☐ No |
| Has disparate impact analysis been conducted? | ☐ Yes ☐ No |
| **Impact level** | ☐ None ☐ Low ☐ Medium ☐ High |
| **Mitigation measures** | |

### 3.3 Right to Privacy and Data Protection (EU Charter Art. 7-8)

| Question | Assessment |
|----------|-----------|
| Does the system process personal data? | ☐ Yes ☐ No |
| Is a Data Protection Impact Assessment (DPIA) required? | ☐ Yes ☐ No |
| What is the legal basis for processing? | ☐ Consent ☐ Contract ☐ Legal obligation ☐ Legitimate interest |
| Are data minimization principles applied? | ☐ Yes ☐ No |
| **Impact level** | ☐ None ☐ Low ☐ Medium ☐ High |
| **Mitigation measures** | |

### 3.4 Right to an Effective Remedy (EU Charter Art. 47)

| Question | Assessment |
|----------|-----------|
| Can affected persons contest decisions made by the system? | ☐ Yes ☐ No |
| Is there a human review mechanism for automated decisions? | ☐ Yes ☐ No |
| Is there a complaint procedure? | ☐ Yes ☐ No |
| **Impact level** | ☐ None ☐ Low ☐ Medium ☐ High |
| **Mitigation measures** | |

### 3.5 Freedom of Expression (EU Charter Art. 11)

| Question | Assessment |
|----------|-----------|
| Does the system filter, moderate, or restrict content? | ☐ Yes ☐ No |
| Could the system have a chilling effect on expression? | ☐ Yes ☐ No |
| **Impact level** | ☐ None ☐ Low ☐ Medium ☐ High |
| **Mitigation measures** | |

### 3.6 Right to Education (EU Charter Art. 14)

| Question | Assessment |
|----------|-----------|
| Does the system affect access to education? | ☐ Yes ☐ No |
| Are admissions, grading, or assessment decisions involved? | ☐ Yes ☐ No |
| **Impact level** | ☐ None ☐ Low ☐ Medium ☐ High |
| **Mitigation measures** | |

### 3.7 Workers' Rights (EU Charter Art. 31)

| Question | Assessment |
|----------|-----------|
| Does the system monitor or evaluate workers? | ☐ Yes ☐ No |
| Does it affect hiring, promotion, or termination decisions? | ☐ Yes ☐ No |
| Were workers' representatives consulted? | ☐ Yes ☐ No |
| **Impact level** | ☐ None ☐ Low ☐ Medium ☐ High |
| **Mitigation measures** | |

### 3.8 Rights of the Child (EU Charter Art. 24)

| Question | Assessment |
|----------|-----------|
| Could the system affect persons under 18? | ☐ Yes ☐ No |
| Are age-appropriate safeguards in place? | ☐ Yes ☐ No |
| **Impact level** | ☐ None ☐ Low ☐ Medium ☐ High |
| **Mitigation measures** | |

## 4. AGT Governance Controls Mapping

| Fundamental Right | AGT Control | Configuration |
|-------------------|------------|---------------|
| Non-discrimination | Advisory classifier (bias detection) | `PatternAdvisory` or `CallbackAdvisory` with fairness model |
| Privacy/Data protection | Attribute ratchets (sensitivity monotonic) | `SessionState` with `monotonic: true` |
| Effective remedy | Approval workflows (human-in-the-loop) | `CallbackApproval` or `WebhookApproval` |
| All rights | Tamper-evident audit trail | `AuditLog` with hash-chaining |
| All rights | Multi-stage policy pipeline | Pre-input → pre-tool → post-tool → pre-output |
| All rights | OTel observability | `enable_otel()` for monitoring and accountability |

## 5. Overall Risk Assessment

| Dimension | Rating | Justification |
|-----------|--------|---------------|
| **Severity of potential impact** | ☐ Low ☐ Medium ☐ High ☐ Very High | |
| **Probability of impact** | ☐ Low ☐ Medium ☐ High ☐ Very High | |
| **Number of persons affected** | ☐ Small ☐ Medium ☐ Large ☐ Very Large | |
| **Reversibility of impact** | ☐ Fully reversible ☐ Partially ☐ Irreversible | |
| **Overall risk level** | ☐ Acceptable ☐ Acceptable with mitigations ☐ Unacceptable | |

## 6. Mitigation Plan

| Risk Identified | Mitigation Measure | Implementation Status | Owner | Due Date |
|----------------|--------------------|-----------------------|-------|----------|
| | | ☐ Planned ☐ In progress ☐ Complete | | |

## 7. Consultation Record

| Stakeholder | Date | Key Findings | Actions Taken |
|-------------|------|-------------|---------------|
| Data Protection Officer | | | |
| Workers' representatives | | | |
| Affected communities | | | |
| Legal counsel | | | |

## 8. Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Assessment Lead | | | |
| Data Protection Officer | | | |
| Legal/Compliance | | | |
| Senior Management | | | |

## 9. Review and Update

- This assessment must be **updated** when:
  - The AI system is significantly modified
  - New risks are identified
  - The intended use changes
  - Relevant regulations change
- **Minimum review frequency**: Annually
- **Retention**: Lifetime of the AI system + 5 years (per [retention policy](record-retention-policy.md))

---

> **Legal Note**: This template provides a structured framework for FRIA. It does
> not constitute legal advice. Organizations should consult qualified legal counsel
> to ensure compliance with the EU AI Act and applicable national implementing laws.

> **Related**: [EU AI Act Checklist](eu-ai-act-checklist.md) · [Impact Assessment Template](impact-assessment-template.md) · [NIST AI RMF Alignment](nist-ai-rmf-alignment.md) · [Record Retention Policy](record-retention-policy.md)
