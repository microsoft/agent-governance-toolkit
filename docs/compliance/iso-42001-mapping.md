# ISO 42001 Alignment Assessment

> Mapping the Agent Governance Toolkit (AGT) v3.1.0 against ISO/IEC 42001:2023 — AI Management System requirements.

## Scope

This document assesses AGT's coverage of ISO 42001 clauses 4 through 10. For each clause, we identify which AGT capabilities address the requirement, note gaps, and suggest remediation where applicable.

## Clause-by-Clause Assessment

### Clause 4: Context of the Organization

**Requirement:** The organization shall determine external and internal issues relevant to its purpose and strategic direction that affect its ability to achieve the intended outcomes of the AI management system.

| Sub-clause | AGT Coverage | Status |
|------------|-------------|--------|
| 4.1 Understanding the organization and its context | AGT's policy engine supports environment-aware rules (e.g., dev/staging/prod policies) | Partial |
| 4.2 Understanding the needs and interests of interested parties | Policy templates include role-based access controls and stakeholder mapping | Partial |
| 4.3 Determining the scope of the AI management system | Policy scopes define which agents and tools fall under governance | Covered |
| 4.4 AI management system | AGT provides the core management framework | Covered |

**Gap:** AGT does not prescribe a formal context-analysis process. Organizations need to supplement with their own stakeholder analysis.

### Clause 5: Leadership

**Requirement:** Top management shall demonstrate leadership and commitment with respect to the AI management system.

| Sub-clause | AGT Coverage | Status |
|------------|-------------|--------|
| 5.1 Leadership and commitment | Policy approval workflows require explicit human sign-off | Covered |
| 5.2 Policy | AGT policies serve as the formal AI governance policy document | Covered |
| 5.3 Organizational roles, responsibilities, and authorities | Role-based policy rules define who can do what | Covered |
| 5.4 AI policy | YAML policy format supports formal AI policy definition | Covered |

**Gap:** None significant. AGT's approval and policy model aligns well with leadership requirements.

### Clause 6: Planning

**Requirement:** The organization shall plan actions to address risks and opportunities.

| Sub-clause | AGT Coverage | Status |
|------------|-------------|--------|
| 6.1 Actions to address risks and opportunities | Risk-based policy rules with severity ratings | Covered |
| 6.2 AI objectives and planning to achieve them | Policy testing framework supports measurable objectives | Partial |
| 6.3 AI risk assessment | Policy evaluation includes risk scoring for agent actions | Covered |
| 6.4 AI risk treatment | Deny-by-default with explicit allow rules; approval workflows for high-risk actions | Covered |

**Gap:** AGT does not include a formal risk register. Organizations should maintain one externally.

### Clause 7: Support

**Requirement:** The organization shall determine and provide the resources needed for the AI management system.

| Sub-clause | AGT Coverage | Status |
|------------|-------------|--------|
| 7.1 Resources | AGT is open-source and self-hosted | Covered |
| 7.2 Competence | Documentation includes tutorials and training materials | Covered |
| 7.3 Awareness | Audit logs and monitoring dashboards provide awareness | Partial |
| 7.4 Communication | Policy versioning and change logs support communication | Partial |
| 7.5 Documented information | Full audit trail; policy-as-code versioned in git | Covered |

**Gap:** Awareness and communication processes are partially covered. Organizations may need additional internal communication procedures.

### Clause 8: Operation

**Requirement:** The organization shall plan, implement, and control the processes needed to meet AI management system requirements.

| Sub-clause | AGT Coverage | Status |
|------------|-------------|--------|
| 8.1 Operational planning and control | Policy deployment via CI/CD pipelines | Covered |
| 8.2 AI risk assessment | Real-time policy evaluation at agent runtime | Covered |
| 8.3 AI risk treatment | Automated enforcement (allow/deny/escalate) | Covered |
| 8.4 AI system development and deployment | Policy testing framework validates changes before deployment | Covered |

**Gap:** None. This is AGT's strongest area.

### Clause 9: Performance Evaluation

**Requirement:** The organization shall evaluate the performance and effectiveness of the AI management system.

| Sub-clause | AGT Coverage | Status |
|------------|-------------|--------|
| 9.1 Monitoring, measurement, analysis, and evaluation | Benchmark suite and metrics collection | Covered |
| 9.2 Internal audit | Audit logging provides data for internal audits | Partial |
| 9.3 Management review | Policy change history and approval records | Partial |

**Gap:** AGT provides data for audits and reviews but does not prescribe the review process itself.

### Clause 10: Improvement

**Requirement:** The organization shall continually improve the suitability, adequacy, and effectiveness of the AI management system.

| Sub-clause | AGT Coverage | Status |
|------------|-------------|--------|
| 10.1 Continual improvement | Policy versioning supports iterative improvement | Covered |
| 10.2 Nonconformity and corrective action | Audit logs identify nonconformities; policy updates serve as corrective actions | Partial |

**Gap:** Formal corrective action tracking is not built into AGT. Organizations should use an external issue tracker.

## Summary

| Clause | Coverage | Gaps |
|--------|----------|------|
| 4. Context | Partial | No formal context-analysis process |
| 5. Leadership | Covered | None |
| 6. Planning | Covered | No formal risk register |
| 7. Support | Partial | Awareness and communication procedures |
| 8. Operation | Covered | None |
| 9. Performance Evaluation | Partial | No prescribed review process |
| 10. Improvement | Partial | No corrective action tracking |

**Overall assessment:** AGT provides strong coverage for operational controls (Clause 8) and planning (Clause 6). Gaps are primarily in organizational process areas (context analysis, risk registers, corrective action tracking) that fall outside the scope of a technical toolkit.

## Recommendations

1. **Supplement with organizational processes.** AGT handles technical governance well. Pair it with organizational procedures for stakeholder analysis, risk registers, and management reviews.

2. **Use AGT audit logs as evidence.** For ISO 42001 certification, AGT's audit trail serves as documentary evidence of operational controls.

3. **Version policies in git.** Keeping policies in version control alongside application code creates the documented information trail that auditors expect.

4. **Establish a regular review cadence.** Schedule quarterly policy reviews using AGT's benchmark data to demonstrate continual improvement.

---

*For implementation guidance on specific AGT features, see the [policy-as-code tutorials](https://github.com/microsoft/agent-governance-toolkit/tree/main/docs/tutorials/policy-as-code) and [compliance documentation](https://github.com/microsoft/agent-governance-toolkit/tree/main/docs/compliance).*
