# NIST RFI (2026) — Question-by-Question Mapping

> Source: Federal Register — Request for Information Regarding Security Considerations for Artificial Intelligence Agents (Docket: 2026-00206). Full text: https://www.federalregister.gov/documents/2026/01/08/2026-00206/request-for-information-regarding-security-considerations-for-artificial-intelligence-agents

This document maps the NIST RFI questions (Federal Register docket 2026-00206) to concrete artifacts, files, and evidence found in this repository. Each item below shows: Status (Yes / Partial / Gap), short rationale, and pointers to files or snippets that demonstrate coverage.

Prepared with an automated repository scan and initial synthesis by GPT-5 mini.

Provenance: see [docs/internal/nist-rfi-provenance.md](docs/internal/nist-rfi-provenance.md) for timestamp, commit SHA, search queries, and commands used to generate this mapping.

Notes
- This mapping was prepared from the repository contents and is intended to be used as an evidence appendix when preparing a formal RFI response. It is not a substitute for operational evidence (logs, metrics, third-party test reports).

Methodology
- Generated: automated repository scan (code search + file reads) performed on 2026-03-11.
- What was scanned: repository Markdown, demo code, changelog, `packages/*/docs`, `fuzz/`, and source modules for governance, audit, hypervisor, and SRE features.
- How it was generated: matches were located using repo text search for keywords (identity, policy, audit, sandbox, anomaly, SLO, etc.), file excerpts were inspected, and a best-effort mapping (Yes / Partial / Gap) assigned based on explicit references or code examples.
- Limitations: this is an automated, static analysis of repository contents only. It does not validate runtime behavior, operational telemetry, or external dependencies. Reviewers should attach live operational artifacts (logs, OTLP exports, signed audit samples) and confirm mappings before submission.

---

## 1. Security Threats, Risks, and Vulnerabilities Affecting AI Agent Systems

### 1(a) Unique security threats, risks, or vulnerabilities
- Status: Partial
- Rationale: Agent-specific risks (goal hijacking, capability abuse, rogue agents) are documented and mitigations are implemented, but empirical attack studies are limited.
- Evidence:
  - Coverage table: [README.md](README.md#L133-L142)
  - Risk mapping and mitigation examples: [packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md](packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md#L134-L136)
  - Demo showing rogue detection/quarantine: [demo/maf_governance_demo.py](demo/maf_governance_demo.py#L287-L296)

### 1(b) Variation by model capability, scaffold, deployment, hosting, use case
- Status: Partial
- Rationale: Docs describe deployment boundaries, trust scoring, and identity options; detailed empirical variation analysis is not present.
- Evidence:
  - Deployment boundary notes: [README.md](README.md#L157-L169)
  - Trust scoring description: [README.md](README.md#L186)
  - AgentMesh identity and interoperability: [packages/agent-mesh/AGENTS.md](packages/agent-mesh/AGENTS.md)

### 1(c) Barriers to adoption
- Status: Gap
- Rationale: Mitigations are provided but the repo lacks adoption studies or metrics showing how risks affect uptake.
- Evidence: N/A (recommend collecting telemetry or survey results as supporting evidence)

### 1(d) How threats have changed and likely future evolution
- Status: Partial
- Rationale: Changelog and roadmap notes document feature evolution (anomaly detection, integrity verification), but predictive threat modeling is not included.
- Evidence:
  - Evolution notes: [CHANGELOG.md](CHANGELOG.md#L32-L43)
  - Roadmap / in-progress items: [README.md](README.md#L194-L197)

### 1(e) Multi-agent unique threats
- Status: Partial
- Rationale: Inter-agent trust and mesh are implemented (AgentMesh), but formal adversary studies for multi-agent dynamics are limited.
- Evidence:
  - AgentMesh: [README.md](README.md#L49-L51)
  - AgentMesh docs: [packages/agent-mesh/AGENTS.md](packages/agent-mesh/AGENTS.md)

---

## 2. Security Practices for AI Agent Systems

### 2(a) Technical controls, processes, maturity
- Status: Yes
- Rationale: The repo includes model/agent controls, system-level policies, and human-oversight primitives with CI/test tooling.
- Evidence:
  - Model/agent capability model & `PolicyEngine`: [README.md](README.md#L86-L96)
  - Middleware & system-level controls: [demo/maf_governance_demo.py](demo/maf_governance_demo.py#L49-L60), [demo/README.md](demo/README.md#L11-L14)
  - Human-in-the-loop policies: [packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md](packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md#L169-L172)
  - Sandboxing / hypervisor: [packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md](packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md#L139-L150)

### 2(b) Effectiveness variation by model/scaffold/deployment
- Status: Partial
- Rationale: Alternatives and deployment-boundary notes are present (DID vs mTLS, on-prem vs cloud), but quantitative effectiveness analysis is missing.
- Evidence:
  - Identity alternatives: [packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md](packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md#L122-L126)

### 2(c) How controls must change over time
- Status: Partial
- Rationale: Roadmap items indicate ongoing work (anomaly detection, external audit sinks) showing planned evolution of controls.
- Evidence:
  - Roadmap/in-progress: [README.md](README.md#L194-L197)

### 2(d) Patching/updating lifecycle
- Status: Yes
- Rationale: Policy-as-code CI, schema versioning, bootstrap integrity verification are implemented to support safe updates.
- Evidence:
  - Policy-as-code CI mention: [CHANGELOG.md](CHANGELOG.md#L40)
  - Bootstrap integrity verification: [CHANGELOG.md](CHANGELOG.md#L32)

### 2(e) Relevant frameworks, adoption, challenges
- Status: Partial
- Rationale: The project maps to SPIFFE, DID, OpenTelemetry, OWASP guidance; adoption metrics are not included.
- Evidence:
  - Identity frameworks: [packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md](packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md#L122)
  - Observability: [CHANGELOG.md](CHANGELOG.md#L38)

---

## 3. Assessing the Security of AI Agent Systems

### 3(a) Methods during development to anticipate/detect incidents
- Status: Yes
- Rationale: Fuzzing, policy CI, benchmarking, telemetry, and anomaly detection are present.
- Evidence:
  - Fuzz harnesses: [fuzz/fuzz_policy_yaml.py](fuzz/fuzz_policy_yaml.py#L1-L12)
  - Anomaly detector: [packages/agent-sre/src/agent_sre/anomaly/rogue_detector.py](packages/agent-sre/src/agent_sre/anomaly/rogue_detector.py#L1)
  - Telemetry/tracing: [packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md](packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md#L240-L246), [CHANGELOG.md](CHANGELOG.md#L38)

#### 3(a)(i) Post-deploy detection
- Status: Yes
- Evidence: auto-quarantine demo and audit logs — [demo/maf_governance_demo.py](demo/maf_governance_demo.py#L299-L313)

#### 3(a)(ii–iv) Alignment, maturity, resources
- Status: Partial
- Rationale: The repo aligns with traditional observability and supply-chain good practices, but a formal comparison document and consolidated resources list are not present.

### 3(b) Assessing a particular AI agent system
- Status: Partial
- Rationale: Tools such as `PolicyCI`, benchmarks, and audit logs support assessment; a standardized scoring rubric is not present.
- Evidence: [CHANGELOG.md](CHANGELOG.md#L40), benchmark references in [README.md](README.md#L190)

### 3(c) Documentation/data from upstream developers
- Status: Partial
- Rationale: Supply-chain integrity features (IntegrityVerifier, AI-BOM references) exist; standardized upstream disclosures are not enforced by repo.
- Evidence: [CHANGELOG.md](CHANGELOG.md#L32), AI-BOM mention ([CHANGELOG.md](CHANGELOG.md#L112-L113))

### 3(d) State of practice for user-facing secure-deployment docs
- Status: Yes
- Evidence: Deployment patterns, demo scenarios, and policy examples: [demo/README.md](demo/README.md#L121-L124), `demo/policies/research_policy.yaml` (demo/policies)

---

## 4. Limiting, Modifying, and Monitoring Deployment Environments

### 4(a) Constraining deployment environment access
- Status: Yes
- Rationale: Capability guards, ring isolation, resource governors, and network/tool restrictions are implemented.
- Evidence:
  - Hypervisor / sandbox designs: [packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md](packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md#L139-L150)
  - ResourceGovernor usage: [packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md](packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md#L259-L269)

### 4(b) Environment modification, rollbacks, undo semantics
- Status: Partial
- Rationale: Circuit breakers, SLOManager, and error budgets exist; explicit automated undo/transactional rollback semantics are not documented.
- Evidence: [packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md](packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md#L298-L301)

### 4(c) Managing risks with counterparties
- Status: Partial
- Rationale: Demo scenarios illustrate interaction controls and audit; a formal counterparty risk playbook is not present.
- Evidence: [demo/maf_governance_demo.py](demo/maf_governance_demo.py#L11-L14), [README.md](README.md#L73)

### 4(d) Monitoring deployment environments
- Status: Yes
- Rationale: OpenTelemetry metrics, signed/Merkle audit logs, and anomaly detection are implemented; privacy/legal guidance is limited.
- Evidence: [packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md](packages/agent-compliance/docs/analyst/owasp-agentic-mapping.md#L238-L246), [CHANGELOG.md](CHANGELOG.md#L42-L43)

### 4(e) Open-internet / unbounded deployments
- Status: Partial
- Rationale: Patterns for safer deployment are present; longitudinal traffic-tracking for open internet deployments is not addressed.

---

## 5. Additional Considerations

### 5(a) Methods/tools to aid adoption
- Status: Yes
- Evidence: `PolicyCI`, fuzz harnesses, demo policies and examples — see `CHANGELOG.md` mentions and `fuzz/`, `demo/` folders.

### 5(b) Government collaboration areas
- Status: Partial
- Rationale: The codebase contains building blocks useful for standards (identity, audit, policy) and would benefit from gov collaboration on disclosure standards and audit sinks.

### 5(c) Research priorities
- Status: Partial
- Rationale: In-repo roadmap items highlight anomaly detection and external audit sinks as priorities.

### 5(d/e) International and cross-discipline practices
- Status: Gap
- Rationale: No formal comparative policy analyses or cross-discipline mappings present; recommend adding if RFI response addresses international practices.

---

## Next steps / recommendations
- Add `docs/nist-rfi-response.md` as a narrative response referencing this mapping and the prioritized questions called out by NIST.
- Collect operational evidence (logs, telemetry, benchmark outputs, SLO dashboards) and link with commit SHAs for provenance.
- Optionally open a draft PR `nist/rfi-response` with this mapping and the initial response draft for internal review.

*Prepared by automated repository mapping — review for accuracy and add live operational evidence before submission.*
