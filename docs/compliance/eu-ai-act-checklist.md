<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# EU AI Act (Regulation 2024/1689) -- Compliance Checklist

**How the Agent Governance Toolkit maps to the EU AI Act**

> **Regulation**: [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng) -- Harmonised Rules on Artificial Intelligence
> **Applicability**: Phased -- Art. 5 (prohibited practices) and Art. 4 (AI literacy) from 2 February 2025; GPAI obligations from 2 August 2025; **high-risk system obligations from 2 August 2026**
> **Prepared**: 2026-04-03
> **Methodology**: 4-wave multi-agent investigation -- parallel discovery, adversarial conformity testing, citation validation, and strategic review. All code citations verified against source at commit `35a7cd0`.

---

## Coverage Summary

| # | Article | Title | Coverage | Conformity Risk |
|---|---------|-------|----------|-----------------|
| 4 | Art. 4 | AI Literacy | Gap (out of scope) | N/A |
| 6 | Art. 6 | High-Risk Classification | Partial | High |
| 9 | Art. 9 | Risk Management System | Partial | High |
| 10 | Art. 10 | Data and Data Governance | Gap (out of scope) | N/A |
| 11 | Art. 11 | Technical Documentation | Partial | Medium |
| 12 | Art. 12 | Record-Keeping and Logging | Partial | Medium |
| 13 | Art. 13 | Transparency and Information | Partial | Medium |
| 14 | Art. 14 | Human Oversight | Partial | Medium |
| 15 | Art. 15 | Accuracy, Robustness, Cybersecurity | Partial | Medium |
| 26 | Art. 26 | Deployer Obligations | Partial | High |
| 50 | Art. 50 | Transparency for Certain AI | Partial | Medium |

**2 of 11 articles fully out of scope. 0 fully covered. 9 partially addressed.**

> **Important**: This toolkit is a runtime governance framework for AI agents. It does not train models, manage training datasets, or provide workforce training programs. Articles 4 and 10 are organizational/ML-pipeline obligations outside the toolkit's architectural boundary. **"Partial" does not mean "mostly compliant"** -- every Partial-rated article would require additional work to pass a conformity assessment. Articles rated Partial with High conformity risk (Art. 6, 9, 26) are functionally non-compliant in their current state.

---

## Is Your System High-Risk?

The EU AI Act classifies AI systems into four risk tiers. The toolkit's applicability depends on how the AI agents it governs are deployed:

| Risk Tier | Trigger | Toolkit Relevance |
|-----------|---------|-------------------|
| **Unacceptable** (Art. 5) | Social scoring, real-time biometric identification, manipulation | Toolkit can detect and block these via policy rules |
| **High-Risk** (Art. 6) | Annex III categories: biometrics, critical infrastructure, education, employment, law enforcement, migration, justice, democratic processes | Full Articles 9-15 and 26 compliance required |
| **Limited Risk** (Art. 50) | AI systems interacting directly with persons, generating synthetic content | Transparency obligations apply |
| **Minimal Risk** | All other AI systems | Voluntary codes of conduct |

The toolkit includes a risk classifier in `agent-governance-python/agent-mesh/examples/06-eu-ai-act-compliance/compliance_checker.py` that maps agent profiles to these tiers. See [Article 6 details](#article-6-high-risk-classification) for limitations.

---

## Article-by-Article Checklist

### Article 4: AI Literacy

> *Providers and deployers shall ensure that their staff and other persons dealing with the operation and use of AI systems on their behalf are made AI literate.* -- Art. 4(1)

**Coverage**: Gap (out of scope)

Article 4 is an organizational/HR obligation requiring training programs, competency assessments, and workforce readiness tracking. This is outside the scope of a runtime governance toolkit. No toolkit changes recommended.

**Deployer action required**: Implement AI literacy programs independently of the toolkit. Consider documenting completion in agent policy metadata (e.g., `operator_certified: true`).

---

### Article 6: High-Risk Classification

> *An AI system shall be considered high-risk where... it falls within any of the areas referred to in Annex III.* -- Art. 6(2)

**Coverage**: Partial | **Conformity Risk**: High

**What exists**:

| Component | Location | Mechanism |
|-----------|----------|-----------|
| Risk level enum and domain constants | `agent-governance-python/agent-mesh/examples/06-eu-ai-act-compliance/compliance_checker.py:30-84` | `RiskLevel` enum (4 tiers) and `UNACCEPTABLE_DOMAINS`, `HIGH_RISK_DOMAINS`, `HIGH_RISK_CAPABILITIES` sets |
| Risk classifier | `agent-governance-python/agent-mesh/examples/06-eu-ai-act-compliance/compliance_checker.py:136-180` | `RiskClassifier.classify()` and `.explain()` methods with trigger explanations |
| Keyword-based classifier | `agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/compliance.py:252-304` | `assess_risk_category()` checks system descriptions against indicator keywords |
| Runtime compliance check | `agent-governance-python/agentmesh-integrations/langflow-agentmesh/src/langflow_agentmesh/compliance_checker.py:103-114` | `_HIGH_RISK_DOMAINS` and `_UNACCEPTABLE_KEYWORDS` sets |

**Gaps**:

- [ ] **Annex I path not implemented**: Art. 6(1) requires classification when the AI system is a safety component of a product covered by Union harmonisation legislation. No classifier addresses this path.
- [ ] **Art. 6(3) exemptions absent**: Narrow procedural tasks, human activity improvement, pattern detection, and preparatory tasks are exempt -- no classifier implements these exemptions.
- [ ] **Profiling override missing**: Art. 6(3) states exemptions never apply when the system performs profiling (GDPR Art. 4(4)). Not checked.
- [ ] **Example-only code**: The most complete classifier is in `examples/`, not library source code. Not importable, not tested in CI, not versioned as package API.
- [ ] **Static domain sets**: Annex III is subject to amendment by delegated acts. Hardcoded Python sets cannot be updated without a code release.

**Conformity assessment risk**: A conformity assessor evaluates the product as delivered, not its examples. The library-level classifier uses keyword substring matching, which is insufficient for structured risk classification.

**Recommendation**: Promote the example classifier into library code with external configuration (YAML/JSON) for regulatory updates. Add Art. 6(3) exemption logic and profiling override check.

---

### Article 9: Risk Management System

> *A risk management system shall be established, implemented, documented and maintained in relation to high-risk AI systems.* -- Art. 9(1)

**Coverage**: Partial | **Conformity Risk**: High

**What exists**:

| Component | Location | Mechanism |
|-----------|----------|-----------|
| Rogue agent detection | `agent-governance-python/agent-sre/src/agent_sre/anomaly/rogue_detector.py:276-401` | Composite behavioral risk scoring: frequency z-scores, entropy deviation, capability profile violations |
| Risk category assessment | `agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/compliance.py:252-304` | Keyword-based risk classification into EU AI Act tiers |
| EUAI-ART9 control | `agent-governance-python/agent-mesh/src/agentmesh/governance/compliance.py:256-268` | Declares risk management control requirements |
| Policy compliance SLI | `agent-governance-python/agent-sre/src/agent_sre/slo/indicators.py:243-266` | Continuous policy adherence tracking (100% target) |
| Chaos testing | `agent-governance-python/agent-sre/src/agent_sre/chaos/engine.py:246` | Resilience testing framework for agent systems |

**Gaps**:

- [ ] **No lifecycle orchestration**: Art. 9(2) requires a "continuous iterative process" throughout the system lifecycle. The toolkit provides risk scoring components but no process orchestrator binding identification, estimation, evaluation, and mitigation into a documented lifecycle.
- [ ] **No misuse analysis**: No structured "reasonably foreseeable misuse" analysis mechanism. `assess_risk_category()` uses keyword matching, not structured misuse frameworks.
- [ ] **No post-market monitoring feedback loop**: Risk detection is runtime-only with no persistent feedback for post-deployment risk reassessment.
- [ ] **Keyword matching is insufficient**: `assess_risk_category()` matches substrings against 15 hardcoded keywords. A system described as "Rate citizens based on behavior for government rewards" classifies as MINIMAL_RISK because no exact keywords appear.

**Conformity assessment risk**: A keyword substring match does not constitute a risk management system. The `RogueAgentDetector` is the strongest contributor (genuine continuous anomaly detection), but it is a behavioral monitoring tool, not a structured risk framework per ISO 31000.

**Recommendation**: Implement a structured risk assessment framework beyond keyword matching. Connect runtime anomaly detection to a risk register lifecycle. Add misuse scenario analysis tooling.

---

### Article 10: Data and Data Governance

> *High-risk AI systems which make use of techniques involving the training of AI models with data shall be developed on the basis of training, validation and testing data sets that meet the quality criteria referred to in paragraphs 2 to 5.* -- Art. 10(1)

**Coverage**: Gap (out of scope)

The toolkit governs agent runtime behavior (policy enforcement, trust scoring, execution isolation), not model training data pipelines. A deployer using this toolkit would need separate tooling for Article 10 compliance.

**Extension point**: The `ToolCallInterceptor` chain could host a `DataGovernanceInterceptor` that validates runtime input data against declared schemas/constraints before tool execution. Policy rules could express data quality requirements (e.g., `requires_consent: true`, `pii_classification: required`).

**Deployer action required**: Use dedicated data quality/bias detection tooling for training pipelines. Consider the interceptor extension point for runtime input data governance.

---

### Article 11: Technical Documentation

> *The technical documentation of a high-risk AI system shall be drawn up before that system is placed on the market or put into service.* -- Art. 11(1)

**Coverage**: Partial | **Conformity Risk**: Medium

**What exists**:

| Component | Location | Mechanism |
|-----------|----------|-----------|
| Compliance reports | `agent-governance-python/agent-mesh/src/agentmesh/governance/compliance.py:121-168` | `ComplianceReport` model with framework, period, controls, scores, violations |
| Policy documents | `agent-governance-python/agent-os/src/agent_os/policies/schema.py:70-115` | Serializable YAML/JSON `PolicyDocument` with version, name, rules, defaults |
| Compliance engine | `agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/compliance.py:306-341` | Framework-scoped reports with requirement counts and pass rates |

**Gaps**:

- [ ] **No Annex IV assembly**: Art. 11 and Annex IV require comprehensive static documentation: system description, design specifications, development methodology, risk management details, applied standards, conformity declaration. The toolkit generates runtime compliance reports, not static conformity dossiers.
- [ ] **No system description generation**: No mechanism to produce the intended-purpose description Art. 11(1)(a) requires.
- [ ] **No development process documentation**: No enforcement or generation of design decision records.
- [ ] **No performance metrics declaration**: SLIs track runtime metrics but do not produce the static documentation Art. 11 mandates.

**Extension point**: A `TechnicalDocumentationExporter` could aggregate `ComplianceReport`, `PolicyDocument`, audit logs, and SLO reports into Annex IV structure, with placeholder sections for deployer-provided content (system description, development methodology).

**Recommendation**: Build an Annex IV template exporter that structures existing governance artifacts into the required format.

---

### Article 12: Record-Keeping and Logging

> *High-risk AI systems shall technically allow for the automatic recording of events (logs) over the lifetime of the system.* -- Art. 12(1)

**Coverage**: Partial | **Conformity Risk**: Medium

**What exists**:

| Component | Location | Mechanism |
|-----------|----------|-----------|
| Merkle audit chain | `agent-governance-python/agent-mesh/src/agentmesh/governance/audit.py:23-344` | `AuditEntry` with SHA-256 hash chaining, `MerkleAuditChain` with inclusion proofs and full chain verification |
| Append-only audit log | `agent-governance-python/agent-mesh/src/agentmesh/governance/audit.py:350-512` | `AuditLog` with agent/type indexes, time-range queries, CloudEvents v1.0 export |
| Signed audit entries | `agent-governance-python/agent-mesh/src/agentmesh/governance/audit_backends.py:31-87` | `AuditSink` protocol, `SignedAuditEntry` with HMAC-SHA256 signatures, `HashChainVerifier` |
| Governance audit logger | `agent-governance-python/agent-os/src/agent_os/audit_logger.py:19-136` | Pluggable backends (JSONL, in-memory, Python logging) capturing event type, agent ID, action, decision, reason, latency |
| Flight recorder | `agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/flight_recorder.py:33-79` | SQLite with WAL mode, Merkle chain tamper detection, captures prompt, action, verdict, result |
| Delta audit engine | `agent-governance-python/agent-hypervisor/src/hypervisor/audit/delta.py:59-110` | Append-only delta log per session with SHA-256 hashed entries |

**Gaps**:

- [ ] **No retention enforcement**: Art. 12(4) requires deployers to preserve logs for at least 6 months. The toolkit provides append-only logs but no retention enforcement, expiration management, or archival lifecycle.
- [ ] **DeltaEngine chain verification is a stub**: `verify_chain()` at `delta.py:99` always returns `True` with comment "Public Preview: no chain verification." The hypervisor's audit trail has zero tamper evidence.
- [ ] **FlightRecorder hash covers INSERT, not final state**: Hash is computed at insert time with `policy_verdict='pending'`, but the verdict is later updated to `'allowed'`/`'blocked'`. Tampering of the verdict field is not detectable by integrity verification.
- [ ] **Anomaly detections not in tamper-evident chain**: `RogueAgentDetector` stores assessments in an in-memory list, not in the integrity-protected audit chain.

**Strengths**: This is the toolkit's strongest area. The `MerkleAuditChain` and `SignedAuditEntry` implementations are genuine cryptographic integrity mechanisms. CloudEvents v1.0 export enables enterprise SIEM integration.

**Recommendation**: Fix FlightRecorder hash to cover final state. Replace DeltaEngine stub with real verification. Add mandatory retention floor of 180 days. Wire anomaly detections into the tamper-evident audit chain.

---

### Article 13: Transparency and Provision of Information to Deployers

> *High-risk AI systems shall be designed and developed in such a way as to ensure that their operation is sufficiently transparent to enable deployers to interpret the system's output and use it appropriately.* -- Art. 13(1)

**Coverage**: Partial | **Conformity Risk**: Medium

**What exists**:

| Component | Location | Mechanism |
|-----------|----------|-----------|
| EUAI-ART13 control | `agent-governance-python/agent-mesh/src/agentmesh/governance/compliance.py:270-282` | Defines explainability, documentation, and user notification requirements |
| Transparency check | `agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/compliance.py:390-401` | Validates `provides_transparency_info` boolean in context |
| Decision explanations | `agent-governance-python/agent-os/src/agent_os/policies/schema.py:52-58` | `PolicyRule.message` field for human-readable explanation of each governance decision |
| CloudEvents export | `agent-governance-python/agent-mesh/src/agentmesh/governance/audit.py:90-128` | Serializes decisions to CloudEvents v1.0 with action, outcome, policy_decision, matched_rule |
| OpenTelemetry tracing | `agent-governance-python/agent-mesh/src/agentmesh/observability/otel_governance.py:31` | `GovernanceTracer` for governance decision instrumentation |

**Gaps**:

- [ ] **No "instructions for use" generation**: Art. 13(3) requires providing deployers with: provider identity, system capabilities/limitations, intended purpose, accuracy metrics, foreseeable misuse, human oversight measures, and log interpretation guidance. No structured mechanism produces this.
- [ ] **No AI disclosure injection**: No feature inserts an AI disclosure notice to end users at interaction time.
- [ ] **Limited decision explainability**: Explanations are limited to policy rule `message` fields and audit `reason` strings -- no structured explanation framework for complex multi-factor decisions.

**Extension point**: A `TransparencyInterceptor` in the `CompositeInterceptor` chain could inject AI disclosure metadata into tool call results. Policy rules with a `transparency_level` attribute could trigger different disclosure requirements by risk classification. Structured "instructions for use" could be exported from `PolicyDocument` + `ComplianceReport` data.

**Recommendation**: Add a `TransparencyInterceptor` and a `transparency_required` policy condition. Build an "instructions for use" template exporter alongside the Art. 11 documentation exporter.

---

### Article 14: Human Oversight

> *High-risk AI systems shall be designed and developed in such a way, including with appropriate human-machine interface tools, as to allow for effective human oversight during the period in which the AI system is in use.* -- Art. 14(1)

**Coverage**: Partial | **Conformity Risk**: Medium

**What exists**:

| Component | Location | Mechanism |
|-----------|----------|-----------|
| Escalation system | `agent-governance-python/agent-os/src/agent_os/integrations/escalation.py:48-583` | `EscalationDecision` enum, `ApprovalBackend` ABC, `InMemoryApprovalQueue`, `WebhookApprovalBackend`, `EscalationHandler` with timeout, quorum, fatigue detection |
| Kill switch | `agent-governance-python/agent-hypervisor/src/hypervisor/security/kill_switch.py:64-136` | `KillSwitch` with `KillReason` enum (BEHAVIORAL_DRIFT, RATE_LIMIT, RING_BREACH, MANUAL, QUARANTINE_TIMEOUT, SESSION_TIMEOUT) |
| Ring breach detection | `agent-governance-python/agent-hypervisor/src/hypervisor/rings/breach_detector.py:1-60` | Internal circuit breaker tripping on HIGH/CRITICAL privilege breaches |
| Base agent escalation | `agent-governance-python/agent-os/src/agent_os/base_agent.py:51-81` | `PolicyDecision.ESCALATE` and `EscalationRequest` with approve/reject |

**Strengths**:
- Timeout defaults to DENY (`EscalationHandler` at line 308) -- the safe default for conformity
- M-of-N quorum approval (`QuorumConfig`) exceeds minimum Art. 14 requirements
- Fatigue detection prevents approval-fatigue attacks (line 324-340)

**Gaps**:

- [ ] **Kill switch has placeholder handoff logic**: `kill()` at line 86 constructs and returns structured `KillResult` objects, but handoff/recovery is not implemented (`handoff_success_count` hardcoded to 0, all in-flight steps auto-marked COMPENSATED without actual compensation). A conformity assessor asking for an emergency shutdown demonstration would find the method returns data but does not terminate agent processes.
- [ ] **No decision reversal**: Escalation gates pre-execution approval only. Art. 14(4)(d) requires the ability to "override or reverse a decision" -- reversal of already-executed actions is not implemented.
- [ ] **No capability/limitation disclosure**: Art. 14(4)(a) requires humans to "understand the relevant capacities and limitations." No capability discovery interface or limitation disclosure mechanism exists.
- [ ] **No automation bias awareness**: Art. 14(4)(b) requires awareness of "the possible tendency of automatically relying on or over-relying on output." No bias warning, confidence calibration, or disagreement indicator is surfaced.
- [ ] **InMemoryApprovalQueue is testing-only**: Single-process, non-persistent. Not suitable for production human oversight.

**Recommendation**: Implement actual process termination in the KillSwitch. Add a decision reversal/compensation mechanism. Surface capability limitations and automation bias warnings in the escalation interface. Provide a production-grade persistent approval backend.

---

### Article 15: Accuracy, Robustness and Cybersecurity

> *High-risk AI systems shall be designed and developed in such a way that they achieve an appropriate level of accuracy, robustness and cybersecurity, and that they perform consistently in those respects throughout their lifecycle.* -- Art. 15(1)

**Coverage**: Partial | **Conformity Risk**: Medium

**What exists**:

*Accuracy:*

| Component | Location | Mechanism |
|-----------|----------|-----------|
| Tool call accuracy SLI | `agent-governance-python/agent-sre/src/agent_sre/slo/indicators.py:159-182` | Measures correct tool selection fraction (default target 99.9%) |
| Task success rate SLI | `agent-governance-python/agent-sre/src/agent_sre/slo/indicators.py:133-156` | Tracks task completion success (default target 99.5%) |
| Hallucination rate SLI | `agent-governance-python/agent-sre/src/agent_sre/slo/indicators.py:297-337` | Measures factual accuracy via LLM-as-judge (default target 5%) |
| Calibration delta SLI | `agent-governance-python/agent-sre/src/agent_sre/slo/indicators.py:340-468` | Tracks predicted confidence vs. actual success rate drift |

*Robustness:*

| Component | Location | Mechanism |
|-----------|----------|-----------|
| Chaos testing | `agent-governance-python/agent-sre/src/agent_sre/chaos/engine.py:246` | `ChaosExperiment` for resilience testing |
| Circuit breakers | `agent-governance-python/agent-sre/src/agent_sre/cascade/circuit_breaker.py:90` | Fault isolation for cascading failures |
| Replay engine | `agent-governance-python/agent-sre/src/agent_sre/replay/engine.py:105` | Debugging and failure reproduction |
| Anomaly detection | `agent-governance-python/agent-sre/src/agent_sre/anomaly/detector.py:123` | Rolling baselines with z-score detection |
| Execution rings | `agent-governance-python/agent-hypervisor/src/hypervisor/models.py:46-69` | 4-tier privilege isolation by trust score |

*Cybersecurity:*

| Component | Location | Mechanism |
|-----------|----------|-----------|
| Ed25519 trust handshake | `agent-governance-python/agent-mesh/src/agentmesh/trust/handshake.py:158-456` | Challenge/response authentication with DoS protection and caching |
| SPIFFE certificate authority | `agent-governance-python/agent-mesh/src/agentmesh/core/identity/ca.py:6-44` | Ed25519 sponsor verification for SVID certificates |
| MCP security threat model | `agent-governance-python/agent-os/src/agent_os/mcp_security.py:1-78` | `MCPThreatType` and `MCPSeverity` enums defining the threat taxonomy |
| MCP security scanner | `agent-governance-python/agent-os/src/agent_os/mcp_security.py:272+` | `MCPSecurityScanner` class detecting tool poisoning, rug pulls, description injection, schema abuse, cross-server attacks, confused deputy |
| Signed audit entries | `agent-governance-python/agent-mesh/src/agentmesh/governance/audit_backends.py:61-87` | HMAC-SHA256 signatures on audit entries |
| Ring breach detection | `agent-governance-python/agent-hypervisor/src/hypervisor/rings/breach_detector.py:1-60` | Privilege escalation detection with severity scoring |
| Input validation | `agent-governance-python/agent-hypervisor/src/hypervisor/models.py:106-220` | Validation on agent_did, API paths, numeric bounds |

**Gaps**:

- [ ] **No accuracy level declaration**: Art. 15(1) requires declaring accuracy metrics in instructions for use. SLIs measure runtime accuracy but no mechanism declares expected accuracy as part of the system specification.
- [ ] **Chaos engine is a framework, not a test runner**: `inject_fault()` records that a fault was injected but does not modify system behavior. Callers must implement actual fault injection externally.
- [ ] **HMAC uses symmetric keys**: Insiders with the HMAC key can forge audit entries. No external commitment (e.g., Merkle root anchoring to a timestamping service) prevents full chain rewrite.
- [ ] **MCP scanner acknowledges incompleteness**: Line 287 warns it "uses built-in sample rules that may not cover all MCP tool poisoning techniques."
- [ ] **No network-level security**: TLS enforcement and certificate pinning are deferred to deployment.

**Strengths**: Cybersecurity primitives are the most robust area. Ed25519 identity, HMAC audit integrity, MCP security scanning, and ring-based isolation provide genuine defense-in-depth.

**Recommendation**: Document recommended accuracy thresholds per risk category. Implement pluggable fault injection hooks in the chaos engine. Consider asymmetric signing for audit entries. Complete MCP security rules for production use.

---

### Article 26: Deployer Obligations

> *Deployers of high-risk AI systems shall... keep the logs referred to in Article 12(1)... for a period appropriate to the intended purpose of the high-risk AI system, of at least six months.* -- Art. 26(6)

**Coverage**: Partial | **Conformity Risk**: High

**What exists**:

| Component | Location | Mechanism |
|-----------|----------|-----------|
| Retention days schema | `agent-governance-python/agent-os/src/agent_os/policies/policy_schema.json:215-218` | `retention_days` field with default 90, minimum 1 |
| Human oversight | `agent-governance-python/agent-os/src/agent_os/integrations/escalation.py:120-583` | Full escalation system with approval backends |
| Kill switch | `agent-governance-python/agent-hypervisor/src/hypervisor/security/kill_switch.py:64-136` | Emergency termination (see Art. 14 caveats) |
| SRE monitoring | `agent-governance-python/agent-sre/src/agent_sre/slo/indicators.py` | SLI/SLO framework for operational monitoring |
| Incident detection | `agent-governance-python/agent-sre/src/agent_sre/incidents/detector.py` | `Signal` and `IncidentSeverity` for risk signal generation |

**Gaps**:

- [ ] **Retention minimum violates Art. 26(6)**: Schema default is 90 days with `minimum: 1`. Article 26(6) requires at least 6 months (~180 days). A deployer can set `retention_days: 1` without validation error. **This is a must-fix.**
- [ ] **No retention enforcement at runtime**: Even if `retention_days` is set, no code actually preserves or deletes logs based on this value. The field is a schema declaration only.
- [ ] **No instructions-for-use tracking**: No mechanism for deployers to load, parse, or validate provider instructions (Art. 26(1)).
- [ ] **No worker notification**: Art. 26(7) requires informing workers and representatives when AI is used in employment contexts. No feature exists.
- [ ] **No affected-individual notification**: Art. 26(8) requires informing persons subject to AI decisions. No disclosure feature exists.
- [ ] **No authority cooperation workflow**: Art. 26(11) requires cooperation with national competent authorities. No data packaging for authority requests.
- [ ] **No input data validation**: Art. 26(4) requires deployers to ensure input data relevance and representativeness. No data quality tooling exists.
- [ ] **No competency tracking for oversight persons**: Art. 26(2) requires human oversight by persons with "necessary competence, training and authority." No authorization tracking.

**Recommendation**: Change `retention_days` default to 180 and minimum to 180 for high-risk systems. Implement actual log retention enforcement. Add `provider_instructions` metadata field. Build an `AuthorityExporter` for regulatory inquiries.

---

### Article 50: Transparency Obligations for Certain AI Systems

> *Providers shall ensure that AI systems intended to interact directly with natural persons are designed and developed in such a way that the natural person concerned is informed that they are interacting with an AI system, unless this is obvious.* -- Art. 50(1), paraphrased

**Coverage**: Partial | **Conformity Risk**: Medium

**What exists**:

| Component | Location | Mechanism |
|-----------|----------|-----------|
| Transparency checker | `agent-governance-python/agent-mesh/examples/06-eu-ai-act-compliance/compliance_checker.py:186-231` | Validates `transparency_disclosure` on `AgentProfile` |
| Transparency requirement | `agent-governance-python/agent-os/modules/control-plane/src/agent_control_plane/compliance.py:390-401` | Checks `provides_transparency_info` boolean in context |
| Risk indicators | `agent-governance-python/agent-mesh/examples/06-eu-ai-act-compliance/compliance_checker.py:80-84` | `LIMITED_RISK_INDICATORS` includes `deepfake_generation` |

**Gaps by sub-obligation**:

| Sub-obligation | Status | Scope |
|---------------|--------|-------|
| Art. 50(1): AI interaction disclosure | Gap (extension point) | In-scope -- toolkit should enforce disclosure policy |
| Art. 50(2): Synthetic content marking (C2PA/watermarking) | Gap (out of scope) | Content-pipeline concern, not agent governance |
| Art. 50(3): Emotion recognition notification | Gap (extension point) | Enforceable via policy conditions |
| Art. 50(4): Deepfake disclosure labeling | Gap (out of scope) | Content-pipeline concern |

- [ ] **No runtime disclosure mechanism**: Transparency checks validate configuration flags but do not deliver actual notices to end users. The toolkit checks *whether you said you would disclose*, not *whether you actually do disclose*.
- [ ] **Compliance checker is example code**: `TransparencyChecker` lives in `examples/`, not library source.

**Extension point**: An `ai_disclosure_required` policy condition could block tool execution if disclosure hasn't been confirmed (via context flag). The `CompositeInterceptor` chain is the natural enforcement point.

**Recommendation**: Promote `TransparencyChecker` to library code. Add `ai_disclosure_required` and `emotion_recognition_notice_required` policy conditions that enforce disclosure before permitting operations.

---

## Coverage Matrix

| Article | Obligation | Status | Evidence | Conformity |
|---------|-----------|--------|----------|------------|
| Art. 4 | AI literacy for staff | Gap | N/A | Out of scope |
| Art. 6(1) | Annex I safety component classification | Gap | N/A | Not implemented |
| Art. 6(2) | Annex III area classification | Partial | `compliance_checker.py:30-84`, `compliance.py:252-304` | Example-only; keyword matching |
| Art. 6(3) | Exemptions and profiling override | Gap | N/A | Not implemented |
| Art. 9(1) | Continuous risk management lifecycle | Partial | `rogue_detector.py:276-401`, `compliance.py:252-304` | Detection exists; lifecycle orchestration absent |
| Art. 10 | Data governance (training data) | Gap | N/A | Out of scope |
| Art. 11 | Technical documentation (Annex IV) | Partial | `compliance.py:121-168`, `schema.py:70-115` | Runtime reports; no conformity dossier |
| Art. 12(1) | Automatic event logging | Partial | `audit.py:23-512`, `audit_logger.py:19-136`, `flight_recorder.py:33-79` | Multiple layers, but 3 of 4 have integrity defects |
| Art. 12(4) | 6-month log retention | Gap | `policy_schema.json:215-218` (default 90, min 1) | **Violates minimum** |
| Art. 13(1) | Output interpretability | Partial | `audit.py:90-128` (CloudEvents), `schema.py:52-58` (rule messages) | Basic; no structured explainability |
| Art. 13(3) | Instructions for use | Gap | N/A | Not implemented |
| Art. 14(1) | Effective human oversight | Partial | `escalation.py:48-583` | Escalation system with quorum and fatigue detection |
| Art. 14(4)(d) | Decline/override/reverse | Partial | `escalation.py:120-213` (approve/deny) | Pre-execution only; no reversal |
| Art. 14(4)(e) | Stop mechanism | Partial | `kill_switch.py:64-136` | Returns structured results; placeholder handoff, no process termination |
| Art. 15(1) | Accuracy levels | Partial | `indicators.py:159-468` | SLIs exist; no formal declaration mechanism |
| Art. 15(3) | Robustness | Partial | `engine.py:246`, `circuit_breaker.py:90` | Framework exists; no actual fault injection |
| Art. 15(4) | Cybersecurity | Partial | `handshake.py:158-456`, `mcp_security.py:272+`, `audit_backends.py:61-87` | Ed25519, HMAC-SHA256 (symmetric key risk), MCP scanning (incomplete rules) |
| Art. 26(2) | Human oversight by competent persons | Partial | `escalation.py:120-583`, `kill_switch.py:64-136` | Mechanisms exist; no competency tracking |
| Art. 26(6) | 6-month log retention | Gap | `policy_schema.json:218` (minimum: 1) | **Must-fix: default 90, minimum 1** |
| Art. 50(1) | AI interaction disclosure | Gap | `compliance_checker.py:186-231` (example) | Config check only; no runtime delivery |
| Art. 50(2) | Synthetic content marking | Gap | N/A | Out of scope |

---

## Recommendations

### Must-Fix (Conformity Blockers)

1. **Log retention minimum** (Art. 12, 26): Change `retention_days` default to 180 and `minimum` to 180 in `policy_schema.json`. Implement actual retention enforcement at runtime. The current `minimum: 1` directly contradicts Art. 26(6).

### High Priority (Would Fail Conformity)

2. **Risk classification** (Art. 6, 9): Promote the example classifier to library code. Replace keyword substring matching with structured risk assessment. Add Art. 6(3) exemptions and profiling override.

3. **Kill switch implementation** (Art. 14): Implement actual process termination and handoff recovery. The current `KillSwitch` returns structured results but has placeholder handoff logic (hardcoded zero successes).

4. **Audit chain integrity** (Art. 12, 15, 26): Fix both DeltaEngine (`verify_chain()` stub returning `True`) and FlightRecorder (hash covers INSERT-time state, not final verdict). These are the same class of defect affecting three articles simultaneously.

### Medium Priority (Extension Points)

5. **Technical documentation exporter** (Art. 11): Build an Annex IV template exporter aggregating existing governance artifacts.

6. **Transparency interceptor** (Art. 13, 50): Add `TransparencyInterceptor` to enforce disclosure policies at the interceptor chain level.

7. **Accuracy declaration** (Art. 15): Document recommended accuracy thresholds per risk category. Add a formal accuracy declaration mechanism alongside SLIs.

### Low Priority (Deployer Responsibility)

8. **AI literacy** (Art. 4): Organizational obligation. Consider adding an `operator_certified` metadata field.

9. **Data governance** (Art. 10): Training data is out of scope. Consider a `DataGovernanceInterceptor` for runtime input validation.

10. **Worker notification** (Art. 26): Employment-context notification is a deployer obligation outside the toolkit's scope.

---

## Article 11: Documentation Templates

The following template maps the Annex IV technical documentation structure to toolkit-generated artifacts. Deployers should fill sections marked **[DEPLOYER]** with their own content. **Note**: The majority of Annex IV documentation requires manual authoring. The toolkit can auto-generate governance artifacts (policies, audit trails, SLO reports) but not system descriptions, design specifications, or development methodology records.

### Annex IV Section 1: General Description

| Field | Source | Notes |
|-------|--------|-------|
| System name and version | **[DEPLOYER]** | |
| Intended purpose | **[DEPLOYER]** | |
| Provider identity | **[DEPLOYER]** | |
| Risk classification | `ComplianceEngine.assess_risk_category()` | Requires promotion from example code |
| Applicable regulations | `ComplianceEngine.generate_report()` | Lists applicable frameworks |

### Annex IV Section 2: Design and Development

| Field | Source | Notes |
|-------|--------|-------|
| Development methodology | **[DEPLOYER]** | |
| Design specifications | `PolicyDocument` (YAML/JSON export) | Governance rules and constraints |
| System architecture | **[DEPLOYER]** | |
| Applied standards | **[DEPLOYER]** | |

### Annex IV Section 3: Monitoring and Functioning

| Field | Source | Notes |
|-------|--------|-------|
| Governance policies | `PolicyDocument.to_yaml()` / `PolicyDocument.to_json()` | Exportable from `schema.py` |
| Audit trail | `AuditLog` CloudEvents export | `audit.py:90-128` |
| SLO compliance | `SLI` framework reports | `indicators.py` |
| Incident history | `Signal` and `IncidentSeverity` logs | `detector.py` |

### Annex IV Section 4: Risk Management

| Field | Source | Notes |
|-------|--------|-------|
| Risk register | **[DEPLOYER]** | Toolkit provides `assess_risk_category()` but not a register |
| Anomaly detections | `RogueAgentDetector` assessments | `rogue_detector.py:276-401` |
| Mitigation measures | Policy rules + escalation configuration | Exportable |

### Annex IV Section 5: Accuracy and Robustness

| Field | Source | Notes |
|-------|--------|-------|
| Accuracy metrics | `ToolCallAccuracy`, `TaskSuccessRate`, `HallucinationRate` SLIs | Runtime metrics, not static declarations |
| Robustness testing | `ChaosExperiment` results | Framework only; deployer must implement injection |
| Cybersecurity measures | Ed25519 identity, HMAC audit, MCP scanning | Exportable configurations |

---

## Scope Limitations

This checklist covers Articles 4, 6, 9-15, 26, and 50 based on primary-source research. The following articles are **not covered** but may be relevant to deployers:

| Article | Title | Why It Matters |
|---------|-------|----------------|
| Art. 17 | Quality Management System | **Provider obligation**: documented QMS covering risk management, post-market monitoring, resource management, and supplier controls |
| Art. 25 | Responsibilities Along the AI Value Chain | Defines provider/deployer boundary and responsibility allocation -- critical for a toolkit used by downstream deployers |
| Art. 27 | Fundamental Rights Impact Assessment | Deployers of high-risk systems must perform FRIA before deployment |
| Art. 43 | Conformity Assessment Procedures | Defines assessment procedures for high-risk systems -- notified body involvement requirements |
| Art. 49 | EU Database Registration | High-risk systems must be registered before market placement |
| Art. 62 | Serious Incident Reporting | **Hard legal obligation**: 15-day reporting deadline to market surveillance authorities for serious incidents |
| Art. 72 | Post-Market Monitoring | Providers must establish post-market monitoring systems proportionate to the risk |

Additionally, this checklist does not address GDPR interplay. Art. 26(9) requires deployers to use the system to conduct **Data Protection Impact Assessments** under GDPR Art. 35. A DPO reviewing this checklist should cross-reference against DPIA obligations.

## Cross-Article Dependencies

Fixing certain gaps yields improvements across multiple articles simultaneously:

| Fix | Articles Improved | Leverage |
|-----|-------------------|----------|
| Retention enforcement (minimum 180 days + runtime) | Art. 12(4), Art. 26(6) | **Highest** -- single fix resolves two regulatory contradictions |
| Promote example classifier to library code | Art. 6, Art. 9, Art. 50 | Risk tier drives classification, management, and transparency triggers |
| Instructions-for-use exporter | Art. 11, Art. 13(3) | Both require structured system description artifacts |
| KillSwitch actual termination | Art. 14(4)(e), Art. 26(2) | Stop mechanism and deployer oversight both depend on it |
| Audit chain integrity (DeltaEngine, FlightRecorder hash) | Art. 12, Art. 15(4), Art. 26(6) | Tamper evidence underpins logging, cybersecurity, and retention |

## Defense-in-Depth Warnings

Several "Partial" ratings rely on a **single mechanism with no fallback**:

- **Art. 14 (Stop mechanism)**: Entire emergency shutdown capability rests on `KillSwitch`, which has placeholder handoff logic. No secondary kill path exists.
- **Art. 12 (Audit integrity)**: Three of four audit implementations have integrity defects (DeltaEngine stub, FlightRecorder hash gap, anomaly detections outside chain). Only `MerkleAuditChain` in agent-mesh is fully sound.
- **Art. 15 (Audit signing)**: HMAC-SHA256 uses symmetric keys. Any insider with the key can forge the entire chain. No external anchoring or asymmetric signing as a second layer.
- **Art. 9 (Risk classification)**: Single keyword substring match with no structured fallback. One evasive system description bypasses it entirely.

---

## Cross-References

- **OWASP Agentic Top 10**: See [`docs/OWASP-COMPLIANCE.md`](../OWASP-COMPLIANCE.md). Overlap with Art. 15 (cybersecurity) and Art. 14 (human oversight via ASI-09).
- **NIST RFI (2026)**: See [`docs/compliance/nist-rfi-2026-00206.md`](nist-rfi-2026-00206.md). Overlap with Section 1 (security threats) and Section 3 (design/development practices).

---

## Sources

- [EU AI Act Official Text (EUR-Lex)](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng)
- [EU AI Act Explorer](https://artificialintelligenceact.eu/)
- [EU AI Act Service Desk -- Article 26](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-26)
- [EU AI Act Service Desk -- Article 50](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-50)
- [EC Digital Strategy -- AI Regulatory Framework](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai)
- [WilmerHale -- High-Risk AI Systems Analysis](https://www.wilmerhale.com/en/insights/blogs/wilmerhale-privacy-and-cybersecurity-law/20240717-what-are-highrisk-ai-systems-within-the-meaning-of-the-eus-ai-act-and-what-requirements-apply-to-them)

---

> **Maintenance**: This checklist should be reviewed when: (a) the toolkit releases a new version, (b) the EU Commission adopts delegated acts amending Annex III risk categories, or (c) implementing acts on conformity procedures are published. The Annex III domain sets in the risk classifier are hardcoded and cannot track regulatory amendments without a code release.

> **Disclaimer**: This checklist is an automated mapping of toolkit capabilities against EU AI Act requirements. It is not legal advice and does not constitute a conformity assessment. **Partial coverage does not equal partial compliance** -- a conformity assessor evaluates pass/fail per obligation, not percentage coverage. Organizations should engage qualified legal counsel and notified bodies for formal compliance evaluation.
