<!--
  MIT License

  Copyright (c) Microsoft Corporation.

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
-->

# ISO/IEC 42001:2023 Annex A — Control Mapping

> **Disclaimer**: This document is an internal self-assessment mapping, NOT a validated certification or third-party audit. It documents how the toolkit's capabilities align with the referenced standard. Organizations must perform their own compliance assessments with qualified auditors. ISO/IEC 42001:2023 is a licensed publication; control titles below are paraphrased summaries for reference only and are not reproductions of the standard text. Refer to the purchased standard for normative wording.

**Agent Governance Toolkit (AGT)**
**Document Version:** 0.1 (Draft)
**Date:** 2026-06-22
**Classification:** Public
**Framework Reference:** [ISO/IEC 42001:2023 — Information technology — Artificial intelligence — Management system](https://www.iso.org/standard/81230.html)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Methodology](#2-methodology)
3. [A.2 — Policies Related to AI](#3-a2--policies-related-to-ai)
4. [A.3 — Internal Organization](#4-a3--internal-organization)
5. [A.4 — Resources for AI Systems](#5-a4--resources-for-ai-systems)
6. [A.5 — Assessing Impacts of AI Systems](#6-a5--assessing-impacts-of-ai-systems)
7. [A.6 — AI System Life Cycle](#7-a6--ai-system-life-cycle)
8. [A.7 — Data for AI Systems](#8-a7--data-for-ai-systems)
9. [A.8 — Information for Interested Parties](#9-a8--information-for-interested-parties)
10. [A.9 — Use of AI Systems](#10-a9--use-of-ai-systems)
11. [A.10 — Third-Party and Customer Relationships](#11-a10--third-party-and-customer-relationships)
12. [Coverage Summary Matrix](#12-coverage-summary-matrix)
13. [Gap Analysis and Recommended Actions](#13-gap-analysis-and-recommended-actions)
14. [Cross-References to Other Compliance Frameworks](#14-cross-references-to-other-compliance-frameworks)

---

## 1. Executive Summary

The Agent Governance Toolkit (AGT) is an open-source, multi-language governance
framework for AI agent systems. This document maps AGT capabilities against the
**38 controls of ISO/IEC 42001:2023 Annex A**, organized into nine control
objectives (A.2 through A.10). It complements the existing
[ISO/IEC 42001 clause-level mapping](./iso-42001-mapping.md), which covers the
management-system requirements in Clauses 4–10.

Annex A is a **reference set of controls**, not a prescriptive checklist. Under
Clause 6.1.3, organizations select applicable controls based on their AI risk
assessment and document inclusions and exclusions in a Statement of
Applicability (SoA). The coverage statuses below indicate where AGT provides
**technical enablement** for a control; controls that are primarily
organizational (workforce competence, formal review cadences) are enabled but
not fully satisfied by tooling alone.

### Scorecard

| Metric | Value |
|--------|-------|
| Total Annex A controls assessed | 38 |
| **Covered** | **20** (53%) |
| **Partial** | **13** (34%) |
| **Gap** | **5** (13%) |
| Strongest objectives | A.6 (Life Cycle), A.9 (Responsible Use), A.10 (Third-Party), A.2 (Policy) |
| Areas for improvement | A.5 (Impact Assessment), A.7.4 (Data Quality), A.8.5 (Interested-Party Transparency), A.4.6 (Human Resources) |

AGT provides **strong technical enablement** for the controls that translate
into runtime enforcement: policy-as-code (A.2), life-cycle governance and event
logging (A.6), responsible-use constraints (A.9), and third-party/supply-chain
governance (A.10). The primary gaps are in areas that ISO 42001 frames as
assessment and disclosure obligations — AI impact assessment including bias and
fairness (A.5.4–A.5.5), formal data-quality evaluation (A.7.4), and outward
transparency reporting to interested parties (A.8.5).

---

## 2. Methodology

This assessment maps AGT capabilities to each Annex A control using the
following evidence types:

- **Code artifacts** — Source files, classes, functions, and configuration schemas
- **Documentation** — Architecture docs, tutorials, and compliance mappings
- **Policy templates** — Policy-as-code YAML templates for common regulatory patterns
- **Runtime mechanisms** — Enforcement, logging, and monitoring behavior at execution time

Coverage levels are assigned as:

| Level | Criteria |
|-------|----------|
| ✅ **Covered** | The control is met by production-ready capability with code and documentation; an organization can evidence it largely through AGT artifacts |
| ⚠️ **Partial** | Core technical capability exists but with documented gaps, or the control also requires organizational process AGT does not supply |
| ❌ **Gap** | No AGT capability meaningfully addresses this control; it must be satisfied by external process or tooling |

> **Note on "Partial" for organizational controls.** ISO 42001 includes controls
> that are inherently organizational (e.g., human-resource competence). AGT can
> support evidence collection for these but cannot satisfy them through tooling;
> such controls are marked Partial or Gap with a plain explanation rather than
> overstated.

---

## 3. A.2 — Policies Related to AI

**Objective:** Provide management direction and support for AI systems through
documented, aligned, and regularly reviewed policies.

AGT's strongest area. Policy-as-code is the toolkit's core primitive: declarative
policies with schema validation, versioning, conflict resolution, and multiple
backends (native, OPA/Rego, Cedar).

| Control | AGT Capability | Status | Implementation Note |
|---------|---------------|--------|---------------------|
| **A.2.2** AI policy | `PolicyEngine` + YAML policy templates (GDPR, production, enterprise, data-protection, content-safety) | ✅ Covered | `agent-mesh` `governance/policy.py`; templates in `agent-os/templates/policies/`. See policy-as-code tutorial. |
| **A.2.3** Alignment with other organizational policies | Policy composition across scopes (global/tenant/agent); OPA/Cedar backends reuse existing org policy infrastructure | ✅ Covered | `governance/opa.py`, `governance/cedar.py`; `most_specific_wins` conflict strategy. |
| **A.2.4** Review of the AI policy | Policy versioning, diff tracking, `PolicyVersion` lifecycle | ⚠️ Partial | Version/diff machinery exists; the periodic **review cadence and sign-off** is an organizational process AGT does not enforce. |

**Gaps:** A.2.4 requires a documented review schedule and management approval
that lives outside the toolkit.

---

## 4. A.3 — Internal Organization

**Objective:** Establish accountability structures, defined roles, and a path
for raising AI-related concerns.

| Control | AGT Capability | Status | Implementation Note |
|---------|---------------|--------|---------------------|
| **A.3.2** AI roles and responsibilities | RBAC, DID-based agent identity, role-scoped policy rules, `require_approval` authority gates | ⚠️ Partial | `agent-mesh` identity (`identity/agent_id.py`) + policy roles enforce technical responsibilities; the **organizational RACI / role charter** is documentation AGT does not author. |
| **A.3.3** Reporting of concerns | Incident detection, escalation paths, `require_approval` routing, rogue-agent reporting | ⚠️ Partial | `agent-sre` anomaly/incident tooling routes technical concerns; a **human whistleblowing / concern-reporting channel** is an organizational control. |

**Gaps:** Both controls have a human-process component (formal role definitions,
a concern-reporting channel) that AGT enables but does not constitute.

---

## 5. A.4 — Resources for AI Systems

**Objective:** Identify and document the data, tooling, computing, and human
resources needed for AI systems.

| Control | AGT Capability | Status | Implementation Note |
|---------|---------------|--------|---------------------|
| **A.4.2** Resource documentation | AI-BOM (AI bill of materials), agent registry / discovery | ✅ Covered | `agent-discovery`; AI-BOM generation captures the resource inventory per system. |
| **A.4.3** Data resources | Data inventory, provenance tracking, data-access governance | ⚠️ Partial | Provenance + access control exist; a **formal per-system data resource register** is partly organizational. See A.7. |
| **A.4.4** Tooling resources | Tool access control, MCP tool governance and scanning | ✅ Covered | `agent-mcp-governance` inventories and governs the tools/integrations available to agents. |
| **A.4.5** System and computing resources | Four-ring execution model, sandboxing, resource isolation and limits | ✅ Covered | `agent-hypervisor` (execution rings) + `agent-sandbox`; compute/network resources are governed at runtime. |
| **A.4.6** Human resources | — | ❌ Gap | Workforce **competence, training, and awareness** for AI is an organizational HR control with no AGT analog. Must be satisfied externally. |

**Gaps:** A.4.6 (human resources / competence) is out of scope for tooling and
is called out plainly as a Gap.

---

## 6. A.5 — Assessing Impacts of AI Systems

**Objective:** Establish a process to assess the impacts of AI systems on
individuals, groups, and society, and document the results.

This is AGT's weakest objective and the primary improvement area. AGT has
strong **risk classification** primitives but lacks a formal **AI impact
assessment** workflow and bias/fairness evaluation.

| Control | AGT Capability | Status | Implementation Note |
|---------|---------------|--------|---------------------|
| **A.5.2** AI system impact assessment process | EU AI Act risk classifier, `RiskLevel` / `AgentRiskProfile`, risk tiering | ⚠️ Partial | Risk **classification** exists; a structured **impact assessment process** (akin to a DPIA for AI) is not yet a first-class workflow. |
| **A.5.3** Documentation of impact assessments | Risk profile records, policy decision logs with reasons | ⚠️ Partial | Decision logs capture risk rationale, but there is **no dedicated impact-assessment artifact/template**. |
| **A.5.4** Assessing impacts on individuals or groups | PII detection (regex), data-protection templates | ❌ Gap | PII detection is present, but **algorithmic bias / fairness evaluation** (demographic parity, equalized odds) is absent. `fairness` exists only as a governance-dimension enum value, with no evaluation implementation behind it. |
| **A.5.5** Assessing societal impacts | — | ❌ Gap | No capability assesses broader **societal impact**; this is an assessment obligation AGT does not address. |

**Gaps:** A.5.4 and A.5.5 are genuine gaps. AGT detects PII but does not
evaluate bias, fairness, or societal impact — consistent with the
bias/fairness gap already documented in the
[NIST AI RMF alignment](./nist-ai-rmf-alignment.md) (MAP 5).

---

## 7. A.6 — AI System Life Cycle

**Objective:** Define and apply responsible processes across the AI system life
cycle — development objectives, design, verification, deployment, operation,
documentation, and event logging.

AGT's deepest area alongside A.2. The toolkit governs the life cycle from
shift-left policy testing through runtime monitoring and tamper-evident logging.

| Control | AGT Capability | Status | Implementation Note |
|---------|---------------|--------|---------------------|
| **A.6.1.2** Objectives for responsible development | Policy-as-code development objectives; enforcement modes | ✅ Covered | `strict` / `permissive` / `audit` modes encode development-stage objectives. |
| **A.6.1.3** Processes for responsible design and development | Shift-left policy checks, CI/CD governance gates | ✅ Covered | `agent-os` shift-left tooling integrates governance into the delivery pipeline. |
| **A.6.2.2** Requirements and specification | Policy specification, JSON policy schema | ⚠️ Partial | Machine-readable policy specs exist; full **system requirements documentation** is partly an authoring process. |
| **A.6.2.3** Documentation of design and development | AI card, architecture/technical docs | ✅ Covered | AI card captures intended use, design, and constraints per system. |
| **A.6.2.4** Verification and validation | Policy testing, red-team workflows, evaluation hooks | ✅ Covered | `agent-mesh` policy tests + red-team tooling validate behavior pre-release. |
| **A.6.2.5** Deployment | Progressive rollout via enforcement modes; release gates | ✅ Covered | Audit → permissive → strict progression supports controlled deployment. |
| **A.6.2.6** Operation and monitoring | OpenTelemetry, fleet monitoring, drift/rogue detection | ✅ Covered | `agent-sre` provides runtime observability and anomaly detection. |
| **A.6.2.7** Technical documentation | AI-BOM, generated technical docs | ✅ Covered | `agent-discovery` AI-BOM is the technical-documentation backbone. |
| **A.6.2.8** Recording of event logs | Merkle-chained tamper-evident audit log, flight recorder | ✅ Covered | `agent-mesh` `governance/audit.py` (`MerkleAuditChain`, exported as `AuditChain`) provides verifiable event logs. |

**Gaps:** A.6.2.2 partial — requirements authoring is partly a documentation
process beyond policy specs.

---

## 8. A.7 — Data for AI Systems

**Objective:** Govern the data used across the AI life cycle — acquisition,
provenance, quality, and preparation.

| Control | AGT Capability | Status | Implementation Note |
|---------|---------------|--------|---------------------|
| **A.7.2** Data for development and enhancement | Data-access governance, `data_access` action policies | ⚠️ Partial | Access to development data is governed; **dataset management** is partly external. |
| **A.7.3** Acquisition of data | Data lineage / provenance capture, egress policy | ⚠️ Partial | Provenance is tracked; formal **acquisition controls** depend on org process. |
| **A.7.4** Quality of data | — | ❌ Gap | No **data-quality evaluation** (accuracy, completeness, representativeness). Must be addressed by external data-quality tooling. |
| **A.7.5** Data provenance | Provenance tracking across agent actions and data sources | ✅ Covered | Provenance is a first-class signal in the policy context and audit log. |
| **A.7.6** Data preparation | Data minimization, PII handling templates | ⚠️ Partial | Minimization/PII templates exist; broader **preparation pipeline** governance is partial. |

**Gaps:** A.7.4 (data quality) is a genuine gap and is called out plainly.

### ComplianceEngine integration (controls-as-code)

`ComplianceEngine` maps runtime agent actions to compliance controls and emits
audit-ready evidence. The existing frameworks (EU AI Act, SOC 2, HIPAA, GDPR)
each register a small set of **representative** controls (two per framework) and
wire them to action types — they are not exhaustive catalogues. The proposal
adds `ISO_42001` following the same pattern, so the engine stays symmetric with
existing frameworks while this document carries the full 38-control mapping.

```python
from agentmesh.governance.compliance import (
    ComplianceEngine,
    ComplianceFramework,  # proposed: + ISO_42001 = "iso_42001"
)

# Engine registers representative Annex A controls (e.g., A.7.5 data
# provenance, A.10.3 suppliers, A.9.4 intended use) and maps them to the
# action types AGT already governs.
engine = ComplianceEngine([ComplianceFramework.ISO_42001])

# A governed data-access action surfaces the data-governance controls.
report = engine.map_action("data_access", context={"provenance": True})
# -> referenced controls include ISO42001-A.7.5 (data provenance)
```

> Representative controls in the engine: **A.7.5** (`data_access`), **A.9.4**
> (intended-use checks), **A.10.3** (`supply_chain_audit`), **A.6.2.8**
> (audit logging). The full set lives in the tables above to avoid asymmetry
> with the other frameworks' two-control footprint.

---

## 9. A.8 — Information for Interested Parties

**Objective:** Provide system documentation and information to users, enable
external reporting, and communicate incidents to relevant parties.

| Control | AGT Capability | Status | Implementation Note |
|---------|---------------|--------|---------------------|
| **A.8.2** System documentation and information for users | AI card, generated docs | ⚠️ Partial | AI card documents the system; **end-user-facing information** delivery is partly external. |
| **A.8.3** External reporting | Audit-log export, compliance reports | ⚠️ Partial | Evidence can be exported; a **formal external-reporting channel** is organizational. |
| **A.8.4** Communication of incidents | Incident detection and response, rogue-agent alerts | ✅ Covered | `agent-sre` detects and routes incidents for communication. |
| **A.8.5** Information for interested parties | — | ❌ Gap | Outward **transparency reporting to interested parties** (beyond internal audit) is not provided. |

**Gaps:** A.8.5 is a genuine gap — AGT's audit trail is internal; structured
outward transparency to interested parties is not yet supported.

---

## 10. A.9 — Use of AI Systems

**Objective:** Ensure AI systems are used responsibly and only for their
intended purpose.

A strong area: AGT's deny-by-default enforcement directly implements
responsible-use constraints.

| Control | AGT Capability | Status | Implementation Note |
|---------|---------------|--------|---------------------|
| **A.9.2** Processes for responsible use | Deny-by-default policy enforcement, runtime interception | ✅ Covered | `PolicyEngine` fail-closed default enforces responsible-use boundaries on every action. |
| **A.9.3** Objectives for responsible use | Intended-use encoded as policy; graduated autonomy | ✅ Covered | Policies express permitted use; trust tiers gate autonomy. |
| **A.9.4** Intended use of the AI system | Four-ring autonomy model, kill switch, overreliance monitoring | ✅ Covered | `agent-hypervisor` rings constrain actions to intended scope; kill switch halts misuse. |

**Gaps:** None identified.

---

## 11. A.10 — Third-Party and Customer Relationships

**Objective:** Allocate responsibilities and manage risks across third parties,
suppliers, and customers throughout the AI life cycle.

A strong area: supply-chain governance is a first-class AGT concern.

| Control | AGT Capability | Status | Implementation Note |
|---------|---------------|--------|---------------------|
| **A.10.2** Allocating responsibilities | Agent-to-agent delegation with trust verification, policy-encoded responsibility boundaries | ✅ Covered | `agent-mesh` a2a delegation enforces responsibility allocation between parties. |
| **A.10.3** Suppliers | MCP scanner, plugin signing, AI-BOM, `supply_chain_audit` action | ✅ Covered | `agent-mcp-governance` + plugin signing govern supplier/third-party components. |
| **A.10.4** Customers | Customer-facing governance reporting | ⚠️ Partial | Evidence can support customer assurances; **customer-relationship terms** are organizational. |

**Gaps:** A.10.4 partial — the customer-facing contractual component is outside
tooling scope.

---

## 12. Coverage Summary Matrix

| # | Control | Coverage | Evidence Strength | Key Artifacts |
|---|---------|----------|-------------------|---------------|
| 1 | **A.2.2** AI policy | ✅ Covered | Strong | PolicyEngine, YAML policy templates |
| 2 | **A.2.3** Policy alignment | ✅ Covered | Strong | OPA/Cedar backends, scope composition |
| 3 | **A.2.4** Policy review | ⚠️ Partial | Moderate | PolicyVersion, diff tracking |
| 4 | **A.3.2** Roles and responsibilities | ⚠️ Partial | Moderate | RBAC, DID identity, role-scoped policy |
| 5 | **A.3.3** Reporting of concerns | ⚠️ Partial | Moderate | Incident routing, escalation, require_approval |
| 6 | **A.4.2** Resource documentation | ✅ Covered | Strong | AI-BOM, agent-discovery |
| 7 | **A.4.3** Data resources | ⚠️ Partial | Moderate | Provenance, data-access governance |
| 8 | **A.4.4** Tooling resources | ✅ Covered | Strong | agent-mcp-governance, tool access control |
| 9 | **A.4.5** System and computing resources | ✅ Covered | Strong | agent-hypervisor rings, agent-sandbox |
| 10 | **A.4.6** Human resources | ❌ Gap | None | — (organizational HR control) |
| 11 | **A.5.2** Impact assessment process | ⚠️ Partial | Moderate | EU AI Act classifier, RiskLevel |
| 12 | **A.5.3** Impact assessment documentation | ⚠️ Partial | Moderate | Risk profiles, decision logs |
| 13 | **A.5.4** Impacts on individuals/groups | ❌ Gap | Weak | PII regex only; no bias/fairness |
| 14 | **A.5.5** Societal impacts | ❌ Gap | None | — |
| 15 | **A.6.1.2** Responsible development objectives | ✅ Covered | Strong | Enforcement modes, policy objectives |
| 16 | **A.6.1.3** Responsible design/development | ✅ Covered | Strong | Shift-left, CI/CD gates |
| 17 | **A.6.2.2** Requirements and specification | ⚠️ Partial | Moderate | Policy schema, policy specs |
| 18 | **A.6.2.3** Design/development documentation | ✅ Covered | Strong | AI card, technical docs |
| 19 | **A.6.2.4** Verification and validation | ✅ Covered | Strong | Policy testing, red-team workflows |
| 20 | **A.6.2.5** Deployment | ✅ Covered | Strong | Progressive enforcement-mode rollout |
| 21 | **A.6.2.6** Operation and monitoring | ✅ Covered | Strong | OTel, fleet monitoring, drift detection |
| 22 | **A.6.2.7** Technical documentation | ✅ Covered | Strong | AI-BOM |
| 23 | **A.6.2.8** Event logs | ✅ Covered | Strong | Merkle AuditChain, flight recorder |
| 24 | **A.7.2** Data for development | ⚠️ Partial | Moderate | data_access governance |
| 25 | **A.7.3** Acquisition of data | ⚠️ Partial | Moderate | Provenance, egress policy |
| 26 | **A.7.4** Quality of data | ❌ Gap | None | — (no data-quality evaluation) |
| 27 | **A.7.5** Data provenance | ✅ Covered | Strong | Provenance tracking in context + audit |
| 28 | **A.7.6** Data preparation | ⚠️ Partial | Moderate | Data minimization, PII templates |
| 29 | **A.8.2** System docs / user information | ⚠️ Partial | Moderate | AI card, generated docs |
| 30 | **A.8.3** External reporting | ⚠️ Partial | Moderate | Audit-log export, compliance reports |
| 31 | **A.8.4** Communication of incidents | ✅ Covered | Strong | Incident detection/response, rogue alerts |
| 32 | **A.8.5** Information for interested parties | ❌ Gap | Weak | Internal audit only; no outward transparency |
| 33 | **A.9.2** Processes for responsible use | ✅ Covered | Strong | Deny-by-default enforcement |
| 34 | **A.9.3** Objectives for responsible use | ✅ Covered | Strong | Intended-use policy, graduated autonomy |
| 35 | **A.9.4** Intended use | ✅ Covered | Strong | Four-ring autonomy, kill switch |
| 36 | **A.10.2** Allocating responsibilities | ✅ Covered | Strong | a2a delegation, trust verification |
| 37 | **A.10.3** Suppliers | ✅ Covered | Strong | MCP scanner, plugin signing, AI-BOM |
| 38 | **A.10.4** Customers | ⚠️ Partial | Moderate | Governance reporting; terms organizational |

**Totals: 20 Covered · 13 Partial · 5 Gap**

---

## 13. Gap Analysis and Recommended Actions

### Priority 1 — HIGH

| Gap | Control | Current State | Recommended Action |
|-----|---------|---------------|--------------------|
| No AI impact assessment workflow | A.5.2 / A.5.3 | Risk classification only (EU AI Act classifier, RiskLevel) | Add an `ImpactAssessment` workflow/template in `agent-compliance` producing a documented AIA artifact linked to the system inventory |
| No bias/fairness evaluation | A.5.4 | PII regex only | Integrate ML-based fairness metrics (demographic parity, equalized odds); add a `FairnessEvaluator`. Mirrors the NIST MAP 5 gap |
| No societal-impact assessment | A.5.5 | None | Provide a societal-impact assessment template as part of the AIA workflow |

### Priority 2 — MEDIUM

| Gap | Control | Current State | Recommended Action |
|-----|---------|---------------|--------------------|
| No data-quality evaluation | A.7.4 | Provenance and minimization only | Add data-quality checks (accuracy/completeness/representativeness) or integrate an external data-quality tool surfaced through `agent-rag-governance` |
| No outward transparency reporting | A.8.5 | Internal audit chain only | Add an interested-party transparency report generated from audit + AI-BOM data |

### Priority 3 — LOW

| Gap | Control | Current State | Recommended Action |
|-----|---------|---------------|--------------------|
| No workforce competence management | A.4.6 | Documentation only | Out of tooling scope; satisfy via organizational HR process and reference in the SoA |

---

## 14. Cross-References to Other Compliance Frameworks

This mapping complements the other AGT compliance documents. The table shows
where each ISO 42001 Annex A objective overlaps with other frameworks.

| ISO 42001 Annex A Objective | NIST AI RMF | ATF | EU AI Act | SOC 2 |
|------------------------------|-------------|-----|-----------|-------|
| A.2 (Policies) | GOVERN 1 | A-1, A-2 | Art. 9 | CC6.1 |
| A.3 (Internal organization) | GOVERN 2 | A-5 | Art. 14 | CC4.1 |
| A.4 (Resources) | MAP 1 | B-1 | Art. 11 | — |
| A.5 (Impact assessment) | MAP 5 | C-1, C-2 | Art. 9, Art. 27 | P1–P8 |
| A.6 (Life cycle) | MAP/MEASURE/MANAGE | B, E, F | Art. 9, Art. 17 | CC7.x |
| A.7 (Data) | MAP 5 | C-1 | Art. 10 | P-series |
| A.8 (Information for parties) | GOVERN 2, MANAGE 4 | A-5, E-3 | Art. 13, Art. 50 | CC4.x |
| A.9 (Responsible use) | MANAGE 1 | F-1, F-2 | Art. 14, Art. 29 | CC7.3 |
| A.10 (Third parties) | GOVERN 4, MANAGE 3 | D-1..D-5 | Art. 28 | CC9.2 |

### Related Documents

- [ISO/IEC 42001 Clause Mapping (Clauses 4–10)](./iso-42001-mapping.md) — management-system requirements
- [NIST AI RMF Alignment Assessment](./nist-ai-rmf-alignment.md) — format reference
- [CSA ATF Conformance Assessment](./atf-conformance-assessment.md) — format reference
- [Compliance Index](./index.md) — framework portfolio overview
