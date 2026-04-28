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

# NIST AI Risk Management Framework (AI RMF 1.0) — Alignment Assessment

> **Disclaimer**: This document is an internal self-assessment mapping, NOT a validated certification or third-party audit. It documents how the toolkit's capabilities align with the referenced standard. Organizations must perform their own compliance assessments with qualified auditors.


**Agent Governance Toolkit (AGT)**
**Document Version:** 1.0
**Date:** 2026-07-14
**Classification:** Public
**Framework Reference:** [NIST AI 100-1 — Artificial Intelligence Risk Management Framework](https://www.nist.gov/artificial-intelligence/ai-risk-management-framework)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Methodology](#2-methodology)
3. [GOVERN — Policies, Processes, and Procedures](#3-govern--policies-processes-and-procedures)
4. [MAP — Context and Risk Identification](#4-map--context-and-risk-identification)
5. [MEASURE — Assessment, Analysis, and Tracking](#5-measure--assessment-analysis-and-tracking)
6. [MANAGE — Risk Response and Monitoring](#6-manage--risk-response-and-monitoring)
7. [Coverage Summary Matrix](#7-coverage-summary-matrix)
8. [Gap Analysis and Recommended Actions](#8-gap-analysis-and-recommended-actions)
9. [Cross-References to Other Compliance Frameworks](#9-cross-references-to-other-compliance-frameworks)

---

## 1. Executive Summary

The Agent Governance Toolkit (AGT) is an open-source, multi-language governance
framework for AI agent systems. This document provides a systematic alignment
assessment of AGT against all 19 subcategories of the NIST AI Risk Management
Framework (AI RMF 1.0), covering the four core functions: **GOVERN**, **MAP**,
**MEASURE**, and **MANAGE**.

### Scorecard

| Metric | Value |
|--------|-------|
| Total subcategories assessed | 19 |
| **Fully Addressed** | **12** (63%) |
| **Partially Addressed** | **7** (37%) |
| **Gaps (Not Addressed)** | **0** (0%) |
| Strongest areas | GOVERN 1 (Policy), MANAGE 1 (Risk Response), MANAGE 4 (Monitoring) |
| Areas for improvement | MAP 5 (Individual Impacts), MEASURE 4 (Measurement Feedback), MANAGE 2 (Benefit Maximization) |

AGT demonstrates **strong-to-excellent coverage** across all four RMF functions.
The toolkit's strongest capabilities lie in policy infrastructure (10+
`PolicyEngine` implementations across Python, .NET, and TypeScript), risk
response mechanisms (circuit breakers, kill switches, saga compensation), and
deep observability (OpenTelemetry, fleet monitoring, rogue agent detection). The
primary improvement opportunities are in bias/fairness evaluation, compliance
trend analysis, and formal benefit-maximization framing.

---

## 2. Methodology

This assessment maps AGT capabilities to each of the 19 NIST AI RMF
subcategories using the following evidence types:

- **Code artifacts** — Source files, classes, functions, and configuration schemas
- **Documentation** — Architecture docs, threat models, and compliance mappings
- **Benchmarks** — Performance measurements quantifying governance overhead
- **Templates** — Policy-as-code YAML templates for common regulatory patterns

Coverage levels are assigned as:

| Level | Criteria |
|-------|----------|
| ✅ **Fully Addressed** | Subcategory requirements are met by production-ready code with tests and documentation |
| ⚠️ **Partially Addressed** | Core capabilities exist but with documented gaps or limitations |
| ❌ **Gap** | No code or documentation addresses this subcategory |

---

## 3. GOVERN — Policies, Processes, and Procedures

### GOVERN 1: Policies Reflecting Risk Management Are in Place

**Coverage: ✅ FULLY ADDRESSED**

AGT implements a multi-layered, declarative policy system with schema
validation, versioning, conflict resolution, and multiple backend support.

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| Core policy evaluator | `agent-governance-python/agent-os/src/agent_os/policies/evaluator.py` | `PolicyEvaluator` |
| Async policy evaluator | `agent-governance-python/agent-os/src/agent_os/policies/async_evaluator.py` | `AsyncPolicyEvaluator` |
| Shared/cross-project policies | `agent-governance-python/agent-os/src/agent_os/policies/shared.py` | `SharedPolicyEvaluator` |
| AgentMesh policy engine | `agent-governance-python/agent-mesh/src/agentmesh/governance/policy.py:317` | `PolicyEngine` |
| AgentMesh policy evaluator | `agent-governance-python/agent-mesh/src/agentmesh/governance/policy_evaluator.py:33` | `PolicyEvaluator` |
| .NET policy engine | `agent-governance-dotnet/src/AgentGovernance/Policy/PolicyEngine.cs:16` | `PolicyEngine` |
| TypeScript MCP policy engine | `agent-governance-python/agent-os/extensions/mcp-server/src/services/policy-engine.ts:208` | `PolicyEngine` |
| VS Code policy engine | `agent-governance-typescript/agent-os-vscode/src/policyEngine.ts:51` | `PolicyEngine` |
| Contextual policy engine | `agent-governance-python/agent-os/src/agent_os/execution_context_policy.py:62` | `ContextualPolicyEngine` |
| Semantic policy engine | `agent-governance-python/agent-os/src/agent_os/semantic_policy.py:248` | `SemanticPolicyEngine` |
| IATP policy engine | `agent-governance-python/agent-os/modules/iatp/iatp/policy_engine.py:78` | `IATPPolicyEngine` |
| Control-plane policy engine | `agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/policy_engine.py:178` | `PolicyEngine` |
| Conflict resolution | `agent-governance-python/agent-os/src/agent_os/policies/conflict_resolution.py` | `ResolutionResult` |
| Policy schema (JSON) | `agent-governance-python/agent-os/src/agent_os/policies/policy_schema.json` | JSON Schema |
| OPA integration | `agent-governance-python/agent-mesh/src/agentmesh/governance/opa.py` | OPA/Rego backend |
| Cedar integration | `agent-governance-python/agent-mesh/src/agentmesh/governance/cedar.py` | Cedar backend |
| Policy templates | `agent-governance-python/agent-os/templates/policies/*.yaml` | GDPR, production, enterprise, data-protection, content-safety |

**How AGT addresses this subcategory:** Policy-as-code with YAML templates
supports declarative governance across environments. Multiple backend engines
(native, OPA Rego, Cedar) allow organizations to use existing policy
infrastructure. Schema validation, versioning (`PolicyVersion`), diff tracking,
and conflict detection provide lifecycle management. Three enforcement modes
(`strict`, `permissive`, `audit`) enable progressive policy rollout.

**Gaps:** None identified.

---

### GOVERN 2: Accountability Structures Are in Place

**Coverage: ✅ FULLY ADDRESSED**

AGT provides cryptographic audit trails, Merkle hash chains, Shapley-value fault
attribution, and joint liability tracking.

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| Merkle audit chain | `agent-governance-python/agent-mesh/src/agentmesh/governance/audit.py:153` | `MerkleAuditChain` |
| Flight recorder (control-plane) | `agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/flight_recorder.py:33` | `FlightRecorder` |
| Flight recorder (IATP) | `agent-governance-python/agent-os/modules/iatp/iatp/telemetry/__init__.py:21` | `FlightRecorder` |
| Flight recorder (Lightning) | `agent-governance-python/agent-lightning/src/agent_lightning_gov/emitter.py:56` | `FlightRecorderEmitter` |
| Hypervisor audit | `agent-governance-python/agent-hypervisor/audit/delta.py` | `DeltaEngine` |
| Shapley attribution | `agent-governance-python/agent-hypervisor/src/hypervisor/liability/attribution.py` | Shapley-value fault attribution |
| Joint liability | `agent-governance-python/agent-hypervisor/src/hypervisor/liability/__init__.py` | Joint liability module |
| Liability ledger | `agent-governance-python/agent-hypervisor/src/hypervisor/liability/ledger.py` | Liability tracking |
| Quarantine system | `agent-governance-python/agent-hypervisor/src/hypervisor/liability/quarantine.py` | Agent quarantine |
| RBAC | `agent-governance-python/agent-os/src/agent_os/integrations/rbac.py` | 4 roles: READER, WRITER, ADMIN, AUDITOR |
| DID-based attribution | `agent-governance-python/agent-mesh/src/agentmesh/governance/audit.py` | `agent_did` field per entry |

**How AGT addresses this subcategory:** Merkle hash chains provide tamper-evident
audit trails where each entry is cryptographically linked to its predecessor.
Shapley-value attribution enables mathematical fault attribution across
multi-agent systems — a capability rare in governance toolkits. RBAC with four
predefined roles (READER, WRITER, ADMIN, AUDITOR) enforces least-privilege
access. DID-based agent identity ensures every action is traceable to a specific
agent.

**Gaps:** None identified.

---

### GOVERN 3: Workforce Diversity and Expertise

**Coverage: ⚠️ PARTIALLY ADDRESSED**

AGT has community governance documentation but no code-level enforcement of
diversity, expertise requirements, or contributor roles.

| Component | File | Notes |
|-----------|------|-------|
| Contributing guide | `CONTRIBUTING.md` | Contribution process, DCO, PR workflow |
| Code of conduct | `CODE_OF_CONDUCT.md` | Microsoft Open Source Code of Conduct |
| Community guide | `COMMUNITY.md` | Community structure, communication channels |
| Security policy | `SECURITY.md` | Vulnerability reporting process |

**How AGT addresses this subcategory:** Community documentation establishes
contribution norms, inclusive conduct standards, and security reporting
processes. The Microsoft Open Source Code of Conduct provides an organizational
commitment to diversity and inclusion.

**Gaps:** No machine-readable role definitions, no expertise verification
mechanisms, no diversity tracking. This is primarily an organizational obligation
typically outside the scope of a governance toolkit.

---

### GOVERN 4: Organizational Practices with Third-Party Entities

**Coverage: ✅ FULLY ADDRESSED**

AGT implements comprehensive supply chain security including plugin signing,
trust tiers, MCP gateway controls, AI-BOM, and dependency confusion protection.

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| MCP security scanner | `agent-governance-python/agent-os/src/agent_os/mcp_security.py:324` | `MCPSecurityScanner` |
| MCP gateway | `agent-governance-python/agent-os/src/agent_os/mcp_gateway.py:99` | `MCPGateway` |
| Plugin signing | `agent-governance-python/agent-marketplace/src/agent_marketplace/signing.py:22` | `PluginSigner` (Ed25519) |
| Plugin manifest | `agent-governance-python/agent-marketplace/src/agent_marketplace/manifest.py:36` | `PluginManifest` |
| MCP trust proxy | `agent-governance-python/agent-mesh/packages/mcp-proxy/` | TypeScript proxy with policy enforcement |
| Trust tiers | `agent-governance-python/agent-marketplace/src/agent_marketplace/trust_tiers.py` | `filter_capabilities()` |
| Usage trust scoring | `agent-governance-python/agent-marketplace/src/agent_marketplace/usage_trust.py:48` | `UsageTrustScorer` |
| Marketplace policy | `agent-governance-python/agent-marketplace/src/agent_marketplace/marketplace_policy.py` | `MCPServerPolicy` |
| Egress policy | `agent-governance-python/agent-os/src/agent_os/egress_policy.py:50` | `EgressPolicy` |
| AI-BOM | `agent-governance-python/agent-mesh/docs/RFC_AGENT_SBOM.md` | AI Bill of Materials v2.0 |
| Federation | `agent-governance-python/agent-mesh/src/agentmesh/governance/federation.py` | Cross-org federation |

**How AGT addresses this subcategory:** Ed25519-signed plugins and manifest
validation ensure supply chain integrity. The five-tier trust scoring system
(0–1000) with `filter_capabilities()` restricts third-party agents to
appropriate privilege levels. MCP gateway allowlist/blocklist controls, security
scanning (tool poisoning and injection detection), and egress policies manage
third-party data flows. AI-BOM v2.0 provides model provenance, dataset lineage,
and weights versioning.

**Gaps:** None identified.

---

### GOVERN 5: Risk Management Processes Are Defined and Implemented

**Coverage: ✅ FULLY ADDRESSED**

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| EU AI Act risk classifier | `agent-governance-python/agent-mesh/src/agentmesh/governance/eu_ai_act.py` | `RiskLevel`, `RiskClassifier`, `AgentRiskProfile` |
| Compliance framework | `agent-governance-python/agent-mesh/src/agentmesh/governance/compliance.py` | Multi-framework compliance |
| Control-plane compliance | `agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/compliance.py` | Compliance engine |
| Rogue agent detector | `agent-governance-python/agent-sre/src/agent_sre/anomaly/rogue_detector.py:304` | `RogueAgentDetector` |

**How AGT addresses this subcategory:** EU AI Act four-tier risk classification
(`UNACCEPTABLE`, `HIGH`, `LIMITED`, `MINIMAL`) provides structured risk
assessment. `AgentRiskProfile` aggregates risk signals per agent. The compliance
engine supports multi-framework verification, allowing organizations to define
and enforce risk management processes declaratively.

**Gaps:** None identified.

---

### GOVERN 6: Policies and Procedures Aligned with Applicable Requirements

**Coverage: ✅ FULLY ADDRESSED**

AGT maintains dedicated compliance mapping documents for seven major frameworks.

| Framework | File | Status |
|-----------|------|--------|
| OWASP Agentic Top 10 | `docs/OWASP-COMPLIANCE.md` | 10/10 risks covered |
| EU AI Act | `docs/compliance/eu-ai-act-checklist.md` | 9/11 articles addressed |
| SOC 2 Type II | `docs/compliance/soc2-mapping.md` | 4/5 criteria addressed |
| ATF Conformance | `docs/compliance/atf-conformance-assessment.md` | 25/25 requirements (7 partial) |
| OWASP LLM Top 10 | `docs/compliance/owasp-llm-top10-mapping.md` | Full mapping |
| NIST RFI (2026) | `docs/compliance/nist-rfi-2026-00206.md` | Question-by-question mapping |
| South Korea AI Framework Act | `agent-governance-python/agent-compliance/docs/compliance/south-korea-ai-framework-act.md` | Mapped |

**How AGT addresses this subcategory:** Each compliance document systematically
maps AGT capabilities to specific regulatory requirements, identifies gaps, and
provides code citations. This document (NIST AI RMF alignment) extends coverage
to the eighth framework.

**Gaps:** None identified.

---

## 4. MAP — Context and Risk Identification

### MAP 1: Context Is Established

**Coverage: ✅ FULLY ADDRESSED**

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| Execution context | `agent-governance-python/agent-os/src/agent_os/execution_context_policy.py:62` | `ContextualPolicyEngine` |
| Stateless kernel context | `agent-governance-python/agent-os/src/agent_os/stateless.py` | `ExecutionContext` |
| Governance tiers | `agent-governance-python/agent-hypervisor/src/hypervisor/models.py` | Ring 0–3 privilege separation |
| Policy modes | `agent-governance-python/agent-os/src/agent_os/policies/schema.py:34-41` | `strict`, `permissive`, `audit` |
| Context budget | `agent-governance-python/agent-os/src/agent_os/context_budget.py` | `ContextScheduler` |

**How AGT addresses this subcategory:** `ContextualPolicyEngine` binds policy
evaluation to rich execution context including governance tiers, environment
type, and operational mode. The four-ring privilege model (Ring 0: kernel through
Ring 3: untrusted) establishes operational boundaries for each agent.
`ContextScheduler` manages token budgets and resource allocation within context.

**Gaps:** None identified.

---

### MAP 2: Categorization of AI Systems

**Coverage: ✅ FULLY ADDRESSED**

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| EU AI Act risk classifier | `agent-governance-python/agent-mesh/src/agentmesh/governance/eu_ai_act.py` | `RiskLevel` enum |
| Agent risk profile | `agent-governance-python/agent-mesh/src/agentmesh/governance/eu_ai_act.py` | `AgentRiskProfile` dataclass |
| Compliance checker example | `agent-governance-python/agent-mesh/examples/06-eu-ai-act-compliance/compliance_checker.py` | Demo risk classifier |
| Trust tiers (5-tier) | `docs/ARCHITECTURE.md` | 0–1000 scale: Untrusted → Verified Partner |
| Execution rings (4-tier) | `agent-governance-python/agent-hypervisor/src/hypervisor/models.py` | Ring 0 (kernel) → Ring 3 (untrusted) |

**How AGT addresses this subcategory:** Dual categorization systems — EU AI Act
risk levels (`UNACCEPTABLE`, `HIGH`, `LIMITED`, `MINIMAL`) and the five-tier
trust score (0–1000) — enable AI systems to be categorized by both regulatory
risk and behavioral trust. The four-ring execution model further segments agents
by privilege level.

**Gaps:** None identified.

---

### MAP 3: Benefits and Costs Assessed

**Coverage: ⚠️ PARTIALLY ADDRESSED**

AGT provides comprehensive performance benchmarks quantifying governance overhead
but lacks formal cost-benefit frameworks.

| Component | File | Key Metric |
|-----------|------|------------|
| Policy benchmarks | `BENCHMARKS.md` | 0.011ms p50 (single rule), 47K ops/sec at 1K agents |
| Kernel benchmarks | `agent-governance-python/agent-os/benchmarks/bench_kernel.py` | 0.103ms p50 full enforcement path |
| Audit benchmarks | `agent-governance-python/agent-os/benchmarks/bench_audit.py` | 2µs per audit write |
| Adapter overhead | `BENCHMARKS.md` | 0.005–0.007ms per adapter check |
| Circuit breaker | `BENCHMARKS.md` | 0.0005ms (1.83M ops/sec) |
| SRE benchmarks | `agent-governance-python/agent-sre/src/agent_sre/benchmarks/__init__.py` | SRE-specific benchmarks |

**How AGT addresses this subcategory:** Governance overhead is rigorously
quantified in latency and throughput terms. Sub-millisecond policy evaluation
and microsecond-level audit writes demonstrate that governance does not impose
meaningful performance penalties.

**Gaps:** No formal ROI model or cost-benefit analysis framework. Overhead is
quantified in technical terms (latency/throughput) but not in business value
terms (risk reduction, compliance cost savings, incident prevention value).

---

### MAP 4: Risks and Impacts Identified

**Coverage: ✅ FULLY ADDRESSED**

| Component | File | Key Content |
|-----------|------|-------------|
| STRIDE threat model | `docs/THREAT_MODEL.md` | 4 trust boundaries, 6 attack surfaces, STRIDE analysis |
| OWASP Agentic Top 10 | `docs/OWASP-COMPLIANCE.md` | 10/10 risks mapped with mitigations |
| Blast radius containment | `agent-governance-python/agent-hypervisor/src/hypervisor/models.py` | Ring isolation, Ring 0–3 |
| Cascade detection | `agent-governance-python/agent-sre/src/agent_sre/cascade/circuit_breaker.py:223` | `CascadeDetector` |
| Ring breach detection | `agent-governance-python/agent-hypervisor/rings/breach_detector.py` | Sliding-window anomaly detection |
| Prompt injection detector | `agent-governance-python/agent-os/src/agent_os/prompt_injection.py:357` | `PromptInjectionDetector` (12+ patterns) |
| Memory guard | `agent-governance-python/agent-os/src/agent_os/memory_guard.py:170` | `MemoryGuard` — memory poisoning defense |
| Adversarial evaluator | `agent-governance-python/agent-sre/src/agent_sre/chaos/adversarial.py` | Adversarial testing |
| Chaos testing | `agent-governance-python/agent-sre/src/agent_sre/chaos/engine.py` | Chaos engineering library |

**How AGT addresses this subcategory:** STRIDE-based threat modeling
systematically identifies risks across four trust boundaries and six attack
surfaces. Prompt injection detection (12+ pattern families), memory poisoning
defense, and cascade detection provide defense-in-depth. Chaos engineering and
adversarial evaluation proactively discover risks before production deployment.

**Gaps:** None identified.

---

### MAP 5: Impacts to Individuals, Groups, and Communities

**Coverage: ⚠️ PARTIALLY ADDRESSED**

AGT has PII/PHI protection via regex patterns and GDPR policy templates but
lacks ML-based bias detection or fairness evaluation.

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| GDPR policy template | `agent-governance-python/agent-os/templates/policies/gdpr.yaml` | 10+ PII pattern categories, right to erasure, data minimization |
| Data protection template | `agent-governance-python/agent-os/templates/policies/data-protection.yaml` | Data protection rules |
| PII detection policy | `agent-governance-python/agent-os/examples/shared-policies/no-pii.yaml` | Shareable PII blocking policy |
| Memory guard PII redaction | `agent-governance-python/agent-os/src/agent_os/memory_guard.py` | PII redaction in context |
| Content governance | `agent-governance-python/agent-os/src/agent_os/content_governance.py:78` | `ContentQualityEvaluator` |
| HIPAA example | `agent-governance-python/agent-os/tutorials/hipaa-compliant-agent/demo.py` | Healthcare compliance demo |
| Healthcare HIPAA example | `agent-governance-python/agent-mesh/examples/03-healthcare-hipaa/main.py` | PHI protection demo |

**How AGT addresses this subcategory:** GDPR policy templates provide declarative
PII protection across 10+ categories with right-to-erasure and data minimization
controls. Memory guard actively redacts PII from agent context. HIPAA-compliant
agent tutorials demonstrate PHI protection patterns.

**Gaps:**
- No ML-based NER (e.g., Presidio) for PII/PHI — regex-only detection
- No bias detection algorithms or fairness metrics
- No demographic parity or equalized odds evaluation
- No consent management system
- No Data Subject Access Request (DSAR) workflow automation

---

## 5. MEASURE — Assessment, Analysis, and Tracking

### MEASURE 1: Metrics Identified and Applied

**Coverage: ✅ FULLY ADDRESSED**

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| SLO engine | `agent-governance-python/agent-sre/src/agent_sre/slo/objectives.py:167` | `SLO`, `ErrorBudget`, `SLOStatus` |
| SLO spec | `agent-governance-python/agent-sre/src/agent_sre/slo/spec.py:51` | `SLOSpec`, `ErrorBudgetPolicy` |
| SLO dashboard | `agent-governance-python/agent-sre/src/agent_sre/slo/dashboard.py:73` | `SLODashboard`, `SLOSnapshot` |
| SLO validator | `agent-governance-python/agent-sre/src/agent_sre/slo/validator.py:33` | `SLODiff` |
| .NET SLO engine | `agent-governance-dotnet/src/AgentGovernance/Sre/SloEngine.cs` | `ErrorBudgetPolicy`, `ErrorBudgetTracker` |
| SLO VS Code panel | `agent-governance-typescript/agent-os-vscode/src/views/sloDashboardView.ts:38` | `SLODashboardProvider` |
| Trust score (AgentMesh) | `agent-governance-python/agent-mesh/src/agentmesh/governance/` | 0–1000 scale, 5 tiers |
| Shift-left metrics | `agent-governance-python/agent-os/src/agent_os/shift_left_metrics.py` | `ShiftLeftTracker`, `ViolationStage`, `ViolationRecord` |
| Usage trust scorer | `agent-governance-python/agent-marketplace/src/agent_marketplace/usage_trust.py:48` | `UsageTrustScorer` |
| OTel metrics | `agent-governance-python/agent-sre/src/agent_sre/integrations/otel/metrics.py` | OpenTelemetry metrics export |
| MCP metrics | `agent-governance-python/agent-os/src/agent_os/_mcp_metrics.py` | MCP-specific metrics |
| Langfuse SLO scores | `agent-governance-python/agent-sre/src/agent_sre/integrations/langfuse/exporter.py:56` | `SLOScore` |

**How AGT addresses this subcategory:** SLI/SLO/error budget engine provides
structured quantitative metrics with dashboard visualization. Trust scoring
(0–1000, five tiers) quantifies agent trustworthiness. Shift-left metrics track
governance violations by lifecycle stage (pre-commit, PR, CI, runtime).
OpenTelemetry integration exports metrics to industry-standard observability
platforms.

**Gaps:** None identified.

---

### MEASURE 2: AI Systems Evaluated

**Coverage: ⚠️ PARTIALLY ADDRESSED**

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| Content quality evaluator | `agent-governance-python/agent-os/src/agent_os/content_governance.py:78` | `ContentQualityEvaluator` |
| Plugin quality assessor | `agent-governance-python/agent-marketplace/src/agent_marketplace/quality_assessment.py:120` | `QualityAssessor` |
| Red team dataset | `agent-governance-python/agent-os/modules/control-plane/benchmark/red_team_dataset.py` | Red-team benchmark data |
| Policy benchmark suite | `agent-governance-python/agent-os/benchmarks/bench_policy.py` | 30-scenario OWASP benchmark |
| CMVK verification | `agent-governance-python/agent-os/modules/cmvk/src/cmvk/constitutional.py` | Cross-Model Verification Kernel |

**How AGT addresses this subcategory:** Content quality evaluation and plugin
quality assessment provide governance-level evaluation. Red-team datasets and
30-scenario OWASP benchmarks test governance enforcement under adversarial
conditions. The Cross-Model Verification Kernel (CMVK) enables constitutional AI
checks across models.

**Gaps:** No formal model accuracy or correctness evaluation pipeline. Quality
assessment focuses on governance and content safety rather than model performance
metrics (e.g., accuracy, calibration, hallucination rate).

---

### MEASURE 3: Mechanisms for Tracking Identified AI Risks

**Coverage: ✅ FULLY ADDRESSED**

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| Behavioral baseline | `agent-governance-python/agent-sre/src/agent_sre/anomaly/detector.py:68` | `BehaviorBaseline` |
| Rogue agent detector | `agent-governance-python/agent-sre/src/agent_sre/anomaly/rogue_detector.py:304` | `RogueAgentDetector` |
| Drift detector (Agent OS) | `agent-governance-python/agent-os/src/agent_os/integrations/drift_detector.py:93` | `DriftDetector`, `DriftType` enum |
| MCP drift detector (SRE) | `agent-governance-python/agent-sre/src/agent_sre/integrations/mcp/__init__.py:169` | `DriftDetector` |
| Flight recorder (control-plane) | `agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/flight_recorder.py:33` | `FlightRecorder` |
| Ring breach detection | `agent-governance-python/agent-hypervisor/rings/breach_detector.py` | Sliding-window anomaly detection |
| Fleet monitoring | `agent-governance-python/agent-sre/src/agent_sre/fleet/__init__.py` | Fleet-wide health with `AgentState.DEGRADED` |

**How AGT addresses this subcategory:** Behavioral baselines establish normal
operating patterns per agent. Drift detectors identify deviations from expected
behavior. The rogue agent detector classifies agents exhibiting anomalous
patterns. Flight recorders provide forensic-grade telemetry for post-incident
analysis. Fleet monitoring aggregates health across agent populations.

**Limitation:** Behavioral baselines are in-memory only — no durable
cross-session persistence. Baselines are lost when agent sessions terminate.

---

### MEASURE 4: Feedback About Efficacy of Measurement

**Coverage: ⚠️ PARTIALLY ADDRESSED**

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| Shift-left tracker | `agent-governance-python/agent-os/src/agent_os/shift_left_metrics.py` | `ShiftLeftTracker` — violations by lifecycle stage |
| SLO dashboard | `agent-governance-python/agent-sre/src/agent_sre/slo/dashboard.py:73` | `SLODashboard` snapshots |
| VS Code SLO panel | `agent-governance-typescript/agent-os-vscode/src/webviews/sidebar/panels/SLOSummary.tsx` | Real-time SLO summary |
| OTel governance export | `agent-governance-python/agent-mesh/src/agentmesh/observability/otel_governance.py` | Governance telemetry |
| Langfuse exporter | `agent-governance-python/agent-sre/src/agent_sre/integrations/langfuse/exporter.py` | SLO scores to Langfuse |
| OpenLit integration | `agent-governance-python/agent-sre/src/agent_sre/integrations/openlit.py` | OpenLit observability |

**How AGT addresses this subcategory:** Shift-left metrics track violations by
lifecycle stage (pre-commit, PR, CI, runtime), enabling measurement of where
governance catches issues. SLO dashboards provide point-in-time compliance
snapshots. Integration with Langfuse and OpenLit enables external measurement
platforms.

**Gaps:** No time-series compliance trend analysis, no
measurement-of-measurement loops, no formal reports on metric effectiveness.
The toolkit provides raw measurement capabilities but does not yet evaluate
whether those measurements are themselves effective.

---

## 6. MANAGE — Risk Response and Monitoring

### MANAGE 1: Risks Prioritized and Responded To

**Coverage: ✅ FULLY ADDRESSED**

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| Circuit breaker (SRE) | `agent-governance-python/agent-sre/src/agent_sre/cascade/circuit_breaker.py:90` | `CircuitBreaker` (trip/open/half-open) |
| Circuit breaker (incidents) | `agent-governance-python/agent-sre/src/agent_sre/incidents/circuit_breaker.py:59` | `CircuitBreaker`, `CircuitBreakerRegistry` |
| Circuit breaker (Agent OS) | `agent-governance-python/agent-os/src/agent_os/_circuit_breaker_impl.py:82` | `CircuitBreaker`, `CascadeDetector` |
| .NET circuit breaker | `agent-governance-dotnet/src/AgentGovernance/Sre/CircuitBreaker.cs:62` | `CircuitBreaker` |
| Kill switch | `agent-governance-python/agent-hypervisor/src/hypervisor/security/kill_switch.py:69` | `KillSwitch.kill()` — 6 kill reasons |
| Rate limiter (hypervisor) | `agent-governance-python/agent-hypervisor/src/hypervisor/security/rate_limiter.py:86` | `AgentRateLimiter` |
| Rate limiter (Agent Mesh) | `agent-governance-python/agent-mesh/src/agentmesh/services/rate_limiter.py:93` | `RateLimiter` |
| Rate limiter (MCP sliding) | `agent-governance-python/agent-os/src/agent_os/mcp_sliding_rate_limiter.py:17` | `MCPSlidingRateLimiter` |
| Rate limiter (TypeScript) | `agent-governance-python/agent-mesh/packages/mcp-proxy/src/rate-limiter.ts:19` | `RateLimiter` |
| .NET rate limiter | `agent-governance-dotnet/src/AgentGovernance/RateLimiting/RateLimiter.cs:11` | `RateLimiter` |
| Approval workflow | `agent-governance-python/agent-os/extensions/mcp-server/src/services/approval-workflow.ts:18` | `ApprovalWorkflow` — quorum, expiration |
| Saga orchestrator | `agent-governance-python/agent-hypervisor/saga/orchestrator.py` | `SagaOrchestrator` — rollback compensation |
| Reversibility registry | `agent-governance-python/agent-hypervisor/reversibility/registry.py` | Undo/rollback registry |

**How AGT addresses this subcategory:** Multi-tier risk response: circuit
breakers (with trip/open/half-open state machine) prevent cascade failures; kill
switches provide immediate agent termination for six enumerated risk categories;
rate limiters (sliding window, token bucket) control throughput across all
language packages. Approval workflows with quorum requirements add human oversight.
Saga orchestrators enable compensating transactions to roll back multi-step
operations upon failure.

**Gaps:** None identified.

---

### MANAGE 2: Strategies to Maximize AI Benefits

**Coverage: ⚠️ PARTIALLY ADDRESSED**

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| Trust scoring (0–1000) | `agent-governance-python/agent-mesh/src/agentmesh/governance/` | 5 tiers: Untrusted → Verified Partner |
| Trust decay | `agent-governance-python/agent-mesh/` | Scores degrade without positive signals |
| Capability delegation | `agent-governance-python/agent-mesh/identity/agent_id.py` | `delegate()`, capability narrowing |
| Graduated rings | `agent-governance-python/agent-hypervisor/src/hypervisor/models.py` | Ring 0–3 privilege escalation/demotion |
| Ring demotion | `agent-governance-python/agent-hypervisor/session/__init__.py` | `update_ring()` |
| Trust-tier filtering | `agent-governance-python/agent-marketplace/src/agent_marketplace/trust_tiers.py` | `filter_capabilities()` |
| Progressive delivery | `agent-governance-python/agent-sre/src/agent_sre/delivery/` | Canary deploys, GitOps |
| NoOp fallbacks | `agent-governance-python/agent-os/src/agent_os/compat.py:37` | `NoOpPolicyEvaluator` |
| RL training governance | `agent-governance-python/agent-lightning/` | Policy rewards for RL training |

**How AGT addresses this subcategory:** Trust-based capability delegation
(child ≤ parent) ensures agents earn expanded privileges through demonstrated
trustworthy behavior. Progressive delivery (canary deploys) minimizes risk when
introducing governance changes. Trust decay ensures agents maintain good
behavior to retain capabilities.

**Gaps:** No formal "benefit maximization" framework. Trust-based capability
delegation exists but is framed as security controls rather than benefit
optimization. No documented strategy for balancing governance overhead against
agent utility.

---

### MANAGE 3: Risks from Third-Party Entities Managed

**Coverage: ✅ FULLY ADDRESSED**

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| MCP security scanner | `agent-governance-python/agent-os/src/agent_os/mcp_security.py:324` | `MCPSecurityScanner` — tool poisoning, injection detection |
| MCP gateway | `agent-governance-python/agent-os/src/agent_os/mcp_gateway.py:99` | `MCPGateway` — allowlist/blocklist |
| MCP trust proxy | `agent-governance-python/agent-mesh/packages/mcp-proxy/` | TypeScript proxy with policy enforcement |
| Plugin signing | `agent-governance-python/agent-marketplace/src/agent_marketplace/signing.py:22` | `PluginSigner` — Ed25519 |
| Plugin manifest validation | `agent-governance-python/agent-marketplace/src/agent_marketplace/manifest.py:36` | `PluginManifest` — Pydantic validation |
| Marketplace policy | `agent-governance-python/agent-marketplace/src/agent_marketplace/marketplace_policy.py` | `MCPServerPolicy`, org-level policies |
| Trust tiers | `agent-governance-python/agent-marketplace/src/agent_marketplace/trust_tiers.py` | Plugin trust tier filtering |
| AI-BOM v2.0 | `agent-governance-python/agent-mesh/docs/RFC_AGENT_SBOM.md` | Model provenance, dataset lineage |
| Egress policy | `agent-governance-python/agent-os/src/agent_os/egress_policy.py:50` | `EgressPolicy` — domain allow/deny |
| Schema adapters | `agent-governance-python/agent-marketplace/src/agent_marketplace/schema_adapters.py` | Copilot/Claude manifest normalization |

**How AGT addresses this subcategory:** Defense-in-depth for third-party risks:
MCP security scanner detects tool poisoning and injection; gateway enforces
allowlist/blocklist policies; plugin signing (Ed25519) and manifest validation
prevent supply chain attacks. AI-BOM v2.0 tracks model provenance and dataset
lineage. Egress policies control outbound data flows to authorized domains only.

**Gaps:** None identified.

---

### MANAGE 4: Risks Monitored

**Coverage: ✅ FULLY ADDRESSED**

| Component | File | Key Class/Function |
|-----------|------|--------------------|
| Rogue agent detector | `agent-governance-python/agent-sre/src/agent_sre/anomaly/rogue_detector.py:304` | `RogueAgentDetector` — scoring, classification |
| Fleet monitoring | `agent-governance-python/agent-sre/src/agent_sre/fleet/__init__.py` | Fleet-wide health, `AgentState` enum |
| OTel tracing (SRE) | `agent-governance-python/agent-sre/src/agent_sre/tracing/spans.py` | Distributed tracing spans |
| OTel metrics (SRE) | `agent-governance-python/agent-sre/src/agent_sre/tracing/metrics.py` | Metrics instrumentation |
| OTel exporters | `agent-governance-python/agent-sre/src/agent_sre/tracing/exporters.py` | OTLP/Jaeger/Zipkin exporters |
| OTel governance SDK | `agent-governance-python/agent-mesh/src/agentmesh/observability/otel_sdk.py` | Governance-aware OTel |
| OTel governance enrichment | `agent-governance-python/agent-mesh/src/agentmesh/observability/otel_governance.py` | Policy events as OTel spans |
| OTel saga sink | `agent-governance-python/agent-sre/src/agent_sre/integrations/otel/saga_sink.py` | Saga lifecycle as OTel spans |
| OTel events | `agent-governance-python/agent-sre/src/agent_sre/integrations/otel/events.py` | Governance event export |
| OpenLit integration | `agent-governance-python/agent-sre/src/agent_sre/integrations/openlit.py` | OpenLit observability |
| Agent OS observability | `agent-governance-python/agent-os/modules/observability/src/agent_os_observability/tracer.py` | Agent OS tracing |
| Hypervisor event bus | `agent-governance-python/agent-hypervisor/src/hypervisor/observability/event_bus.py` | Internal event bus |
| Cascade detector | `agent-governance-python/agent-sre/src/agent_sre/cascade/circuit_breaker.py:223` | `CascadeDetector` |

**How AGT addresses this subcategory:** Deep observability stack: OpenTelemetry
integration across all packages (spans, metrics, events) exports to
OTLP/Jaeger/Zipkin. Rogue agent detector uses behavioral scoring to classify
anomalous agents. Fleet monitoring provides population-level health dashboards.
Governance-enriched OTel spans embed policy evaluation results directly into
distributed traces, enabling governance-aware debugging.

**Gaps:** None identified.

---

## 7. Coverage Summary Matrix

| # | Subcategory | Coverage | Evidence Strength | Key Artifacts |
|---|------------|----------|-------------------|---------------|
| 1 | **GOVERN 1** — Policies | ✅ Full | Strong | 10+ PolicyEngine implementations, OPA/Cedar backends |
| 2 | **GOVERN 2** — Accountability | ✅ Full | Strong | Merkle audit, Shapley attribution, RBAC, DID |
| 3 | **GOVERN 3** — Workforce | ⚠️ Partial | Moderate | CONTRIBUTING.md, CODE_OF_CONDUCT.md |
| 4 | **GOVERN 4** — Third-party practices | ✅ Full | Strong | Plugin signing, MCP scanner, AI-BOM, egress policy |
| 5 | **GOVERN 5** — Risk processes | ✅ Full | Strong | EU AI Act classifier, compliance engine |
| 6 | **GOVERN 6** — Requirements alignment | ✅ Full | Strong | 7 framework compliance mappings |
| 7 | **MAP 1** — Context | ✅ Full | Strong | ExecutionContext, 4-ring model, 3 policy modes |
| 8 | **MAP 2** — Categorization | ✅ Full | Strong | RiskLevel enum, AgentRiskProfile, 5-tier trust |
| 9 | **MAP 3** — Benefits/costs | ⚠️ Partial | Moderate | Latency/throughput benchmarks; no ROI model |
| 10 | **MAP 4** — Risks identified | ✅ Full | Strong | STRIDE threat model, OWASP 10/10, chaos testing |
| 11 | **MAP 5** — Individual impacts | ⚠️ Partial | Moderate | GDPR template, PII regex; no bias/fairness |
| 12 | **MEASURE 1** — Metrics | ✅ Full | Strong | SLO engine, trust scoring, shift-left, OTel |
| 13 | **MEASURE 2** — Evaluation | ⚠️ Partial | Moderate | Content quality, red team; no model eval pipeline |
| 14 | **MEASURE 3** — Risk tracking | ✅ Full | Strong | Drift detection, baselines, flight recorder |
| 15 | **MEASURE 4** — Measurement feedback | ⚠️ Partial | Moderate | Shift-left tracker, SLO dashboard |
| 16 | **MANAGE 1** — Risk response | ✅ Full | Strong | Circuit breakers, kill switch, rate limiters, sagas |
| 17 | **MANAGE 2** — Maximize benefits | ⚠️ Partial | Moderate | Trust scoring, graduated autonomy |
| 18 | **MANAGE 3** — Third-party risks | ✅ Full | Strong | MCP scanner, plugin signing, trust tiers, AI-BOM |
| 19 | **MANAGE 4** — Monitoring | ✅ Full | Strong | OTel, rogue detector, fleet monitoring, cascade |

**Totals: 12 Fully Addressed · 7 Partially Addressed · 0 Gaps**

---

## 8. Gap Analysis and Recommended Actions

### Priority 1 — HIGH

| Gap | Subcategory | Current State | Recommended Action |
|-----|------------|---------------|-------------------|
| No bias/fairness evaluation | MAP 5 | Regex-only PII detection; no algorithmic bias testing | Integrate ML-based NER (e.g., Presidio); add `FairnessEvaluator` with demographic parity and equalized odds metrics |
| No consent/DSAR management | MAP 5 | GDPR template has data minimization but no consent workflow | Implement consent management and DSAR automation in `agent-compliance` |

### Priority 2 — MEDIUM

| Gap | Subcategory | Current State | Recommended Action |
|-----|------------|---------------|-------------------|
| No compliance trend analysis | MEASURE 4 | Point-in-time SLO snapshots only | Add `ComplianceTrendAnalyzer` to aggregate shift-left and SLO data over time; expose via SRE dashboard API |
| No model evaluation pipeline | MEASURE 2 | Content/plugin quality only | Add `ModelEvaluator` module or LM Harness/HELM integration for accuracy/calibration benchmarks |
| No benefit-maximization framing | MANAGE 2 | Trust delegation framed as security | Document governance ROI; reframe trust scoring as benefit optimization with measurable utility metrics |
| In-memory behavioral baselines | MEASURE 3 | Baselines lost on session end | Add `BaselinePersistence` backend (SQLite or file-backed) to `agent-governance-python/agent-sre/anomaly/` |

### Priority 3 — LOW

| Gap | Subcategory | Current State | Recommended Action |
|-----|------------|---------------|-------------------|
| No ROI/cost-benefit model | MAP 3 | Technical benchmarks only | Add "Governance ROI" analysis to `BENCHMARKS.md` framing overhead in business value terms |
| No workforce role enforcement | GOVERN 3 | Documentation only | Consider machine-readable contributor role definitions (organizational scope) |

---

## 9. Cross-References to Other Compliance Frameworks

This alignment assessment complements and cross-references the following AGT
compliance documents. Subcategory mappings below show where NIST AI RMF
requirements overlap with other frameworks.

| NIST AI RMF Subcategory | ATF Reference | OWASP Reference | EU AI Act Reference | SOC 2 Reference |
|--------------------------|---------------|-----------------|---------------------|-----------------|
| GOVERN 1 (Policies) | A-1, A-2 (Policy definition & enforcement) | — | Art. 9 (Risk management system) | CC6.1 (Logical access) |
| GOVERN 2 (Accountability) | A-5 (Audit trails) | — | Art. 12 (Record-keeping) | CC4.1 (Monitoring) |
| GOVERN 3 (Workforce) | — | — | Art. 14 (Human oversight) | — |
| GOVERN 4 (Third-party) | D-1 through D-5 (Supply chain) | A-05 (Insecure Plugin Design) | Art. 28 (Obligations of deployers) | CC9.2 (Vendor mgmt) |
| GOVERN 5 (Risk processes) | A-3 (Risk assessment) | — | Art. 9 (Risk management system) | CC3.2 (Risk assessment) |
| GOVERN 6 (Requirements) | All sections | All risks | All articles | All criteria |
| MAP 1 (Context) | B-1 (Execution boundaries) | — | Art. 9.2 (Intended purpose) | — |
| MAP 2 (Categorization) | A-3 (Risk classification) | — | Art. 6 (Classification rules) | — |
| MAP 3 (Benefits/costs) | — | — | Art. 9.4 (Cost proportionality) | — |
| MAP 4 (Risks identified) | B-2, B-3 (Threat analysis) | A-01 through A-10 (All risks) | Art. 9.2 (Risk identification) | CC3.2 (Risk assessment) |
| MAP 5 (Individual impacts) | C-1, C-2 (Data protection) | A-08 (Excessive Agency) | Art. 10 (Data governance) | P1–P8 (Privacy criteria) |
| MEASURE 1 (Metrics) | E-1 (SLI/SLO) | — | Art. 9.7 (Testing/metrics) | CC4.1 (Monitoring) |
| MEASURE 2 (Evaluation) | E-2 (Quality assessment) | — | Art. 9.5 (Testing) | CC7.1 (System monitoring) |
| MEASURE 3 (Risk tracking) | B-3 (Behavioral baseline) | A-03 (Excessive Agency) | Art. 9.8 (Risk monitoring) | CC7.2 (Change monitoring) |
| MEASURE 4 (Feedback) | E-3 (Continuous improvement) | — | Art. 9.9 (Documentation updates) | CC4.2 (Deficiency mgmt) |
| MANAGE 1 (Risk response) | F-1, F-2 (Circuit breakers, kill switch) | A-06 (Excessive Agency) | Art. 14 (Human oversight) | CC7.3 (Change mgmt) |
| MANAGE 2 (Maximize benefits) | — | — | Recital 4 (Innovation balance) | — |
| MANAGE 3 (Third-party risks) | D-1 through D-5 (Supply chain) | A-05 (Insecure Plugin Design) | Art. 28 (Deployer obligations) | CC9.2 (Vendor mgmt) |
| MANAGE 4 (Monitoring) | E-1, F-3 (Observability) | A-09 (Overreliance) | Art. 72 (Post-market monitoring) | CC7.1 (System monitoring) |

### Related Documents

- **ATF Conformance Assessment:** [`docs/compliance/atf-conformance-assessment.md`](atf-conformance-assessment.md)
- **OWASP Agentic Top 10:** [`docs/OWASP-COMPLIANCE.md`](../OWASP-COMPLIANCE.md)
- **OWASP LLM Top 10:** [`docs/compliance/owasp-llm-top10-mapping.md`](owasp-llm-top10-mapping.md)
- **EU AI Act Checklist:** [`docs/compliance/eu-ai-act-checklist.md`](eu-ai-act-checklist.md)
- **SOC 2 Mapping:** [`docs/compliance/soc2-mapping.md`](soc2-mapping.md)
- **NIST RFI Response:** [`docs/compliance/nist-rfi-2026-00206.md`](nist-rfi-2026-00206.md)
- **Threat Model (STRIDE):** [`docs/THREAT_MODEL.md`](../THREAT_MODEL.md)
- **Architecture Overview:** [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md)

---

*This document was prepared for submission to the National Institute of Standards
and Technology (NIST) in response to the AI Risk Management Framework (AI RMF
1.0) alignment assessment process. It reflects the state of the Agent Governance
Toolkit as of 2026-07-14. For questions or clarifications, please refer to the
project's [SUPPORT.md](../../SUPPORT.md) or open an issue on GitHub.*
