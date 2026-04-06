<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

<div align="center">

# 🔒 SOC 2 Type II — Trust Service Criteria Mapping

**How the Agent Governance Toolkit maps to the [AICPA SOC 2 Type II Trust Service Criteria (2017)](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)**

</div>

---

## Executive Summary

The Agent Governance Toolkit provides runtime governance infrastructure that addresses SOC 2 Type II controls across Security, Availability, and Processing Integrity criteria. The toolkit's strongest coverage is in **Security** (CC1–CC9), where the policy engine, RBAC, cryptographic identity, execution rings, and audit logging provide a defense-in-depth enforcement stack. **Availability** (A1) is well-supported through circuit breakers, SLO enforcement, and chaos testing primitives. **Processing Integrity** (PI1) benefits from deterministic policy evaluation, Merkle audit chains, and input validation — though several audit chain implementations have integrity defects.

**Confidentiality** (C1) has partial coverage through egress controls, PII pattern detection, and cryptographic identity — but lacks at-rest encryption, key rotation, and audit log redaction. **Privacy** (P1–P8) is the largest gap area: the toolkit detects only 2 PII patterns (SSN, credit card), has no consent management, no data subject access request support, and no retention enforcement. Organizations deploying this toolkit in SOC 2 scope must supplement Privacy controls with external tooling.

> **Important**: This mapping documents what the toolkit provides as infrastructure. SOC 2 Type II requires evidence of **operating effectiveness over a review period** — policies followed, controls monitored, exceptions investigated. The toolkit provides the enforcement mechanisms; the operating procedures, organizational policies, and evidence collection are the deployer's responsibility. "Partial" coverage means the toolkit provides building blocks but does not satisfy the control independently.

---

## Coverage Summary

| Criteria | Coverage | Key Controls Addressed | Primary Gaps |
|----------|----------|----------------------|--------------|
| **Security** (CC1–CC9) | ⚠️ Partial | Policy engine, RBAC, DID identity, execution rings, audit logging, MCP security scanning | Kill switch placeholder, detection modules unwired from enforcement |
| **Availability** (A1) | ⚠️ Partial | Circuit breakers, SLO/error budgets, chaos testing framework, sub-millisecond enforcement | Chaos engine framework-only, no health check endpoints, rate limiter unwired |
| **Processing Integrity** (PI1) | ⚠️ Partial | Merkle audit chain, policy validation, input sanitization, drift detection | 3 of 4 audit chain implementations have integrity defects, `post_execute()` never blocks |
| **Confidentiality** (C1) | ⚠️ Partial | Ed25519 identity, HMAC-SHA256 signing, egress policy, PII/secret detection | Symmetric HMAC keys, no at-rest encryption, audit logs store unredacted parameters |
| **Privacy** (P1–P8) | ❌ Gap | 2 PII regex patterns, blocked patterns, retention_days schema field | No consent management, no DSAR, no data minimization, retention not enforced |

**0 of 5 criteria fully covered. 4 partially addressed. 1 gap.**

---

## Security (CC1–CC9)

> *The system is protected against unauthorized access, unauthorized disclosure of information, and damage to systems that could compromise the availability, integrity, confidentiality, and privacy of information or systems and affect the entity's ability to meet its objectives.*

### What Exists

#### CC1: Control Environment

| Control | Feature | Location | Coverage |
|---------|---------|----------|----------|
| CC1.1 Commitment to integrity | STRIDE-oriented threat model | `docs/THREAT_MODEL.md` | ⚠️ Partial — documents threats, no control ownership |
| CC1.4 Accountability | RBAC with 4 roles (READER, WRITER, ADMIN, AUDITOR) | `packages/agent-os/src/agent_os/integrations/rbac.py:16-30` | ⚠️ Partial — role-to-permission mapping, no personnel tracking |

#### CC5: Control Activities

| Control | Feature | Location | Coverage |
|---------|---------|----------|----------|
| CC5.1 Risk-mitigating controls | PolicyEvaluator — every agent action evaluated before execution | `packages/agent-os/src/agent_os/policies/evaluator.py` | ✅ Covered |
| CC5.2 Technology controls | GovernancePolicy with max_tool_calls, max_tokens, timeout_seconds, blocked_patterns | `packages/agent-os/src/agent_os/integrations/base.py` | ✅ Covered |
| CC5.2 Policy modes | Strict (deny-by-default), permissive (allow-by-default), audit (log-only) | `packages/agent-os/src/agent_os/policies/schema.py:34-41` | ✅ Covered |

#### CC6: Logical and Physical Access Controls

| Control | Feature | Location | Coverage |
|---------|---------|----------|----------|
| CC6.1 Logical access | RBAC — 4 roles with action-level permissions | `packages/agent-os/src/agent_os/integrations/rbac.py:24-30` | ✅ Covered |
| CC6.1 Tool restrictions | `allowed_tools` per policy, `PolicyInterceptor` blocks unlisted tools | `packages/agent-os/src/agent_os/integrations/base.py:689-693` | ✅ Covered |
| CC6.2 Access provisioning | Trust scoring (0–1000, 5 tiers), delegation chains must narrow | `packages/agent-mesh/src/agentmesh/trust/` | ✅ Covered |
| CC6.3 Access removal | Trust decay over time without positive signals, role removal | `packages/agent-os/src/agent_os/integrations/rbac.py:94-96` | ⚠️ Partial |
| CC6.6 Authentication | Ed25519 challenge-response handshake with DoS protection | `packages/agent-mesh/src/agentmesh/trust/handshake.py:158-456` | ✅ Covered |
| CC6.6 Certificate authority | SPIFFE CA with Ed25519 sponsor verification for SVID certificates | `packages/agent-mesh/src/agentmesh/core/identity/ca.py:6-44` | ✅ Covered |
| CC6.7 Privilege restriction | Execution rings (Ring 0–3) enforce privilege tiers; Ring 0 always denied | `packages/agent-hypervisor/src/hypervisor/models.py:46-69` | ✅ Covered |
| CC6.8 Malicious software prevention | Prompt injection detection (6 regex groups), MCP security scanner, MemoryGuard | `packages/agent-os/src/agent_os/prompt_injection.py:147-197`, `mcp_security.py:272+` | ⚠️ Partial |

#### CC7: System Operations

| Control | Feature | Location | Coverage |
|---------|---------|----------|----------|
| CC7.1 Detection and monitoring | GovernanceAuditLogger with pluggable backends (JSONL, in-memory, logging) | `packages/agent-os/src/agent_os/audit_logger.py:19-136` | ✅ Covered |
| CC7.1 Tamper-evident logging | MerkleAuditChain with SHA-256 hash chaining and inclusion proofs | `packages/agent-mesh/src/agentmesh/governance/audit.py:23-344` | ✅ Covered |
| CC7.2 Change monitoring | Version-controlled PolicyDocument with name, version, description fields | `packages/agent-os/src/agent_os/policies/schema.py:70-115` | ⚠️ Partial |
| CC7.3 Vulnerability management | MCP security scanner: tool poisoning, rug pulls, description injection, schema abuse, cross-server attacks, confused deputy | `packages/agent-os/src/agent_os/mcp_security.py:300-331` | ⚠️ Partial |
| CC7.3 Supply chain | SupplyChainGuard: freshly published packages (<7 days), unpinned versions, typosquatting detection | `packages/agent-os/src/agent_os/supply_chain.py:72-79` | ⚠️ Partial |
| CC7.4 Incident response | Kill switch with 6 kill reasons (BEHAVIORAL_DRIFT, RATE_LIMIT, RING_BREACH, MANUAL, QUARANTINE_TIMEOUT, SESSION_TIMEOUT) | `packages/agent-hypervisor/src/hypervisor/security/kill_switch.py:64-136` | ⚠️ Partial |
| CC7.4 Escalation | EscalationHandler with approval backends, timeout with default-deny, M-of-N quorum, fatigue detection | `packages/agent-os/src/agent_os/integrations/escalation.py:48-583` | ✅ Covered |

#### CC8: Change Management

| Control | Feature | Location | Coverage |
|---------|---------|----------|----------|
| CC8.1 Infrastructure changes | SBOM generation (SPDX 2.3 format), Ed25519 artifact signing | `packages/agent-sre/src/agent_sre/signing.py:18-33` | ⚠️ Partial |
| CC8.1 CI security | Automated dependency review, CodeQL scanning, OpenSSF Scorecard, SBOM generation | `.github/workflows/dependency-review.yml`, `codeql.yml`, `scorecard.yml`, `sbom.yml` | ✅ Covered |
| CC8.1 Progressive delivery | Canary deployments for gradual rollout | `packages/agent-sre/src/agent_sre/delivery/gitops.py` | ⚠️ Partial |

#### CC9: Risk Mitigation

| Control | Feature | Location | Coverage |
|---------|---------|----------|----------|
| CC9.1 Risk identification | Rogue agent detection — composite behavioral risk scoring: frequency z-scores, entropy deviation, capability profile violations | `packages/agent-sre/src/agent_sre/anomaly/rogue_detector.py:276-401` | ✅ Covered |
| CC9.1 Anomaly detection | Rolling baselines with z-score detection | `packages/agent-sre/src/agent_sre/anomaly/detector.py:123` | ✅ Covered |
| CC9.2 Risk mitigation | Circuit breakers for cascading failure prevention | `packages/agent-sre/src/agent_sre/cascade/circuit_breaker.py:90` | ✅ Covered |

```python
# CC6.1 in action: Role-Based Access Control
from agent_os.integrations.rbac import RBACManager, Role

rbac = RBACManager()
rbac.assign_role("data-analyst", Role.READER)
rbac.assign_role("ops-agent", Role.ADMIN)

# Reader cannot write — denied by permission check
assert not rbac.has_permission("data-analyst", "write")   # False
assert rbac.has_permission("data-analyst", "read")         # True
```

```python
# CC7.1 in action: Governance Audit Logging
from agent_os.audit_logger import GovernanceAuditLogger, JsonlFileBackend

audit = GovernanceAuditLogger()
audit.add_backend(JsonlFileBackend("governance_audit.jsonl"))
audit.log_decision(
    agent_id="finance-bot",
    action="transfer",
    decision="deny",
    reason="Policy violation: amount exceeds role limit",
)
```

**Reference implementation:** The [`finance-soc2` example](../../packages/agent-os/examples/finance-soc2/) demonstrates CC6.1, CC6.3, CC7.1, CC7.2, CC7.3, and CC8.1 using real Agent OS governance APIs with role-based separation of duties, approval workflows, and immutable audit trails.

### Security Gaps

- [ ] **Kill switch is placeholder** (CC7.4): `KillSwitch.kill()` at `kill_switch.py:86` returns structured `KillResult` objects but does not terminate agent processes. `handoff_success_count` is hardcoded to 0. All in-flight saga steps are auto-marked COMPENSATED without actual compensation.
- [ ] **Detection modules not wired to enforcement** (CC6.8): `PromptInjectionDetector`, `RateLimiter`, `BoundedSemaphore`, `ScopeGuard`, `SupplyChainGuard`, and `MCPSecurityScanner` exist as standalone utilities but are not auto-wired into the `BaseIntegration` enforcement lifecycle. 6 of 10 OWASP risks share this structural gap.
- [ ] **MCP scanner acknowledges incompleteness** (CC7.3): Line 287 of `mcp_security.py` warns it "uses built-in sample rules that may not cover all MCP tool poisoning techniques."
- [ ] **Regex-only prompt injection detection** (CC6.8): No semantic or multilingual detection. English-only regex patterns can be bypassed via paraphrasing.
- [ ] **No network-level security enforcement** (CC6.6): TLS enforcement and certificate pinning are deferred to deployment configuration.
- [ ] **Organizational controls not addressed** (CC1–CC4): Board oversight, personnel policies, risk assessment governance, and monitoring activities are organizational obligations outside the toolkit's scope.

### Recommended Controls

1. Wire detection modules into `BaseIntegration.pre_execute()` via `GovernancePolicy` flags (closes CC6.8 gaps across multiple OWASP risks).
2. Implement actual process termination in `KillSwitch` (CC7.4).
3. Deploy each agent in a separate container with governance middleware inside for defense-in-depth (CC6.7).
4. Add network policies for cross-agent communication control (CC6.6).
5. Integrate LlamaFirewall for semantic prompt injection detection (CC6.8).

---

## Availability (A1)

> *The system is available for operation and use as committed or agreed.*

### What Exists

| Control | Feature | Location | Coverage |
|---------|---------|----------|----------|
| A1.1 System capacity | Policy enforcement at sub-millisecond latency; 47K ops/sec at 1,000 concurrent agents | `BENCHMARKS.md` | ✅ Covered |
| A1.1 Throughput stability | Near-linear scaling: 46,329 ops/sec (50 agents) → 47,085 ops/sec (1,000 agents) | `packages/agent-os/benchmarks/bench_kernel.py` | ✅ Covered |
| A1.2 Fault isolation | Per-agent circuit breakers (CLOSED → OPEN → HALF_OPEN) with configurable failure thresholds | `packages/agent-sre/src/agent_sre/cascade/circuit_breaker.py:22-26` | ✅ Covered |
| A1.2 Cascading failure prevention | Cascade detection monitors dependency chains for failure propagation patterns | `packages/agent-sre/src/agent_sre/cascade/circuit_breaker.py` | ✅ Covered |
| A1.2 SLO enforcement | 7 SLI types: TaskSuccessRate, ToolCallAccuracy, ResponseLatency, CostPerTask, PolicyComplianceRate, HallucinationRate, CalibrationDelta | `packages/agent-sre/src/agent_sre/slo/indicators.py` | ✅ Covered |
| A1.2 Error budgets | Quantified failure tolerance with burn rate alerts triggering automatic intervention | `packages/agent-sre/src/agent_sre/slo/indicators.py` | ✅ Covered |
| A1.2 Chaos testing | ChaosExperiment framework for resilience testing with fault injection, schedule evaluation, and template library | `packages/agent-sre/src/agent_sre/chaos/engine.py:246` | ⚠️ Partial |
| A1.2 Rate limiting | Token-bucket algorithm, thread-safe with `threading.Lock` | `packages/agent-os/src/agent_os/rate_limiter.py:93-101` | ⚠️ Partial (unwired) |
| A1.2 Replay | Replay engine for failure reproduction and debugging | `packages/agent-sre/src/agent_sre/replay/engine.py:105` | ⚠️ Partial |
| A1.3 Recovery | Saga compensation for automatic rollback on execution failure | `packages/agent-hypervisor/src/hypervisor/security/kill_switch.py` | ⚠️ Partial |

#### Performance Benchmarks

These numbers are relevant to A1.1 (system capacity) and demonstrate that the governance layer does not meaningfully impact availability:

| Measurement | ops/sec | p50 | p99 |
|-------------|--------:|----:|----:|
| Policy evaluation (single rule) | 84,489 | 0.011 ms | 0.037 ms |
| Policy evaluation (100 rules) | 32,025 | 0.030 ms | 0.108 ms |
| Kernel enforcement (allow) | 9,668 | 0.103 ms | 0.347 ms |
| Circuit breaker state check | 1,828,845 | 0.001 ms | 0.001 ms |
| Audit entry write | 285,202 | 0.002 ms | 0.008 ms |
| SLO evaluation | 29,475 | 0.030 ms | 0.097 ms |
| Fault injection | 428,253 | 0.001 ms | 0.007 ms |
| Concurrent throughput (1,000 agents) | 47,085 | — | — |

> Source: [`BENCHMARKS.md`](../../BENCHMARKS.md). Measured with `time.perf_counter()`, 10,000 iterations, on a development workstation.

```python
# A1.2 in action: SLO with Error Budget
from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import TaskSuccessRate, HallucinationRate

slo = SLO(
    name="production-agent",
    description="Production reliability targets",
    indicators=[
        TaskSuccessRate(target=0.95, window="24h"),
        HallucinationRate(target=0.05, window="24h"),
    ],
    error_budget=ErrorBudget(total=0.05),
)
```

### Availability Gaps

- [ ] **Chaos engine is framework-only** (A1.2): `ChaosExperiment.inject_fault()` records that a fault was injected but does not modify system behavior. Callers must implement actual fault injection externally.
- [ ] **RateLimiter not wired** (A1.2): `RateLimiter` at `rate_limiter.py:93-101` has a correct token-bucket algorithm but is not imported by any adapter or interceptor. `BoundedSemaphore` for concurrency limiting is similarly unwired.
- [ ] **No health check endpoints** (A1.1): No liveness or readiness probes exposed for container orchestration.
- [ ] **No disaster recovery automation** (A1.3): Replay engine is designed for debugging and failure reproduction, not automated recovery. Saga compensation in the kill switch is placeholder-only.
- [ ] **No backup/restore for audit data** (A1.3): Audit backends write to JSONL files or in-memory stores with no backup, replication, or archival mechanism.

### Recommended Controls

1. Wire `RateLimiter` and `BoundedSemaphore` into `BaseIntegration` with blocking behavior controlled by policy flags.
2. Implement health check endpoints for Kubernetes liveness/readiness probes.
3. Add pluggable fault injection hooks in the chaos engine for real resilience testing.
4. Deploy audit logs to an external append-only sink (Azure Monitor, write-once storage) for durability.
5. Implement automated backup and retention for audit data stores.

---

## Processing Integrity (PI1)

> *System processing is complete, valid, accurate, timely, and authorized.*

### What Exists

| Control | Feature | Location | Coverage |
|---------|---------|----------|----------|
| PI1.1 Input validation | PolicyEvaluator validates every action against declarative rules before execution | `packages/agent-os/src/agent_os/policies/evaluator.py` | ✅ Covered |
| PI1.1 Blocked patterns | Substring, regex, and glob pattern blocking on tool arguments | `packages/agent-os/src/agent_os/integrations/base.py:695-701` | ✅ Covered |
| PI1.1 Input sanitization | Command injection detection, shell metacharacter blocking, base64 payload decoding | `packages/agent-os/src/agent_os/prompt_injection.py:548-563` | ✅ Covered |
| PI1.2 Processing completeness | Saga orchestration tracks multi-step workflows with checkpoint_frequency | `packages/agent-os/src/agent_os/integrations/base.py` | ⚠️ Partial |
| PI1.3 Accuracy verification | CodeSecurityValidator — AST-based validation of LLM-generated Python code (17 dangerous imports, 22+ dangerous calls, shell/SQL injection, path traversal, secrets) | `packages/agent-os/src/agent_os/secure_codegen.py:179-237` | ⚠️ Partial |
| PI1.3 Drift detection | SequenceMatcher-based drift scoring between baseline and actual output | `packages/agent-os/src/agent_os/integrations/base.py:977-1038` | ⚠️ Partial (advisory only) |
| PI1.3 Accuracy SLIs | ToolCallAccuracy (99.9% target), TaskSuccessRate (99.5% target), HallucinationRate (5% target), CalibrationDelta | `packages/agent-sre/src/agent_sre/slo/indicators.py:133-468` | ✅ Covered |
| PI1.4 Output recording | CloudEvents v1.0 export with action, outcome, policy_decision, matched_rule | `packages/agent-mesh/src/agentmesh/governance/audit.py:90-128` | ✅ Covered |
| PI1.5 Audit chain integrity | MerkleAuditChain with SHA-256 hash chaining, inclusion proofs, full chain verification | `packages/agent-mesh/src/agentmesh/governance/audit.py:23-344` | ✅ Covered |
| PI1.5 Signed audit entries | HMAC-SHA256 signatures on audit entries via AuditSink protocol | `packages/agent-mesh/src/agentmesh/governance/audit_backends.py:31-87` | ⚠️ Partial |
| PI1.5 Flight recorder | SQLite with WAL mode, Merkle chain tamper detection; captures prompt, action, verdict, result | `packages/agent-os/modules/control-plane/src/agent_control_plane/flight_recorder.py:33-79` | ⚠️ Partial |
| PI1.5 Delta audit engine | Append-only delta log per session with SHA-256 hashed entries | `packages/agent-hypervisor/src/hypervisor/audit/delta.py:59-110` | ❌ Stub |

```python
# PI1.5 in action: Merkle Audit Chain
from agentmesh.governance.audit import AuditEntry, AuditLog

log = AuditLog()
entry = AuditEntry(
    event_type="governance_decision",
    agent_did="did:agentmesh:finance-bot:abc123",
    action="transfer",
    outcome="denied",
    policy_decision="DENY",
    matched_rule="max_transfer_limit",
)
log.add_entry(entry)

# Entry gets automatic SHA-256 hash chaining
assert entry.entry_hash != ""
assert entry.previous_hash != "" or log.entries.index(entry) == 0
```

### Processing Integrity Gaps

- [ ] **DeltaEngine chain verification is a stub** (PI1.5): `verify_chain()` at `packages/agent-hypervisor/src/hypervisor/audit/delta.py:99` always returns `True` with comment "Public Preview: no chain verification." The hypervisor's entire audit trail has zero tamper evidence.
- [ ] **FlightRecorder hash covers INSERT-time state** (PI1.5): Hash is computed at insert time with `policy_verdict='pending'`, but the verdict is later updated to `'allowed'`/`'blocked'`. Tampering of the verdict field is undetectable by integrity verification.
- [ ] **Anomaly detections outside tamper-evident chain** (PI1.5): `RogueAgentDetector` stores assessments in an in-memory list, not in the integrity-protected audit chain.
- [ ] **`post_execute()` never blocks** (PI1.3): `base.py:977-1038` computes drift scores and emits `DRIFT_DETECTED` events but always returns `(True, None)` — advisory only, no enforcement on output integrity.
- [ ] **Python-only code validation** (PI1.3): `CodeSecurityValidator` raises `ValueError` for any language other than Python at `secure_codegen.py:193`.
- [ ] **No output text sanitization** (PI1.4): Tool argument scanning exists; LLM response text is not scanned for dangerous content, PII, or secrets.

### Recommended Controls

1. **Fix DeltaEngine `verify_chain()` stub** — replace with real SHA-256 chain verification (same algorithm as `MerkleAuditChain`).
2. **Fix FlightRecorder hash** — compute hash over final state including resolved verdict, not INSERT-time state.
3. Wire anomaly detections into the tamper-evident audit chain.
4. Add `GovernancePolicy.block_on_drift` flag to enable enforcement in `post_execute()`.
5. Use only `MerkleAuditChain` (the sound implementation) for SOC 2 audit evidence until other implementations are fixed.

---

## Confidentiality (C1)

> *Information designated as confidential is protected as committed or agreed.*

### What Exists

| Control | Feature | Location | Coverage |
|---------|---------|----------|----------|
| C1.1 Confidential data identification | PII detection: SSN (`\b\d{3}-\d{2}-\d{4}\b`) and credit card regex patterns in tool parameters | `packages/agent-os/src/agent_os/mcp_gateway.py:34-42` | ⚠️ Partial (2 patterns only) |
| C1.1 Secret detection | 5 regex patterns for API keys, passwords, tokens, AWS keys, private keys in generated code (CRITICAL severity) | `packages/agent-os/src/agent_os/secure_codegen.py:346-360` | ⚠️ Partial |
| C1.2 Data access controls | RBAC with action-level permissions; scoped capabilities with delegation narrowing (child ≤ parent) | `packages/agent-os/src/agent_os/integrations/rbac.py:88-92` | ✅ Covered |
| C1.2 Egress controls | Domain-level egress filtering with first-match-wins and default-deny | `packages/agent-os/src/agent_os/egress_policy.py:113-139` | ✅ Covered |
| C1.2 Cryptographic identity | Ed25519 key pairs for agent identity; DID format `did:agentmesh:{agentId}:{fingerprint}` | `packages/agent-mesh/src/agentmesh/trust/handshake.py` | ✅ Covered |
| C1.2 Signed audit | HMAC-SHA256 signatures on audit entries for tamper detection | `packages/agent-mesh/src/agentmesh/governance/audit_backends.py:61-87` | ⚠️ Partial |
| C1.2 Channel encryption | IATP (Inter-Agent Trust Protocol) provides encrypted inter-agent communication channels | `packages/agent-os/modules/iatp/` | ⚠️ Partial |
| C1.3 Data disposal | `retention_days` field in policy schema (default 90, minimum 1) | `packages/agent-os/src/agent_os/policies/policy_schema.json:215-218` | ❌ Declaration only |

```python
# C1.2 in action: Egress Policy with Default-Deny
from agent_os.egress_policy import EgressPolicy

policy = EgressPolicy(default_action="deny")
policy.add_rule("*.internal.corp.com", action="allow")
policy.add_rule("api.openai.com", action="allow")

# All other domains blocked — prevents data exfiltration
assert not policy.is_allowed("evil-exfil-server.com")  # Denied
assert policy.is_allowed("api.openai.com")              # Allowed
```

### Confidentiality Gaps

- [ ] **HMAC uses symmetric keys** (C1.2): Any insider with the HMAC key can forge the entire audit chain. No external commitment (Merkle root anchoring to a timestamping service) or asymmetric signing prevents full chain rewrite.
- [ ] **No at-rest encryption** (C1.1): Audit logs, policy documents, and configuration files are stored in plaintext. No encryption for data at rest.
- [ ] **No key rotation mechanism** (C1.2): No mechanism for rotating Ed25519 keys, HMAC secrets, or SPIFFE certificates on a schedule.
- [ ] **Audit logs store unredacted parameters** (C1.1): `mcp_gateway.py:165` stores raw `parameters=params` with no redaction. Every tool call's full parameters — including any PII, credentials, or tokens passed as arguments — are stored verbatim in `AuditEntry` and exposed via `logger.info()`. **The toolkit's own security logging is a data leak pathway.**
- [ ] **Only 2 PII patterns** (C1.1): SSN and credit card number. No email, phone, IP address, JWT token, or other sensitive data patterns.
- [ ] **`retention_days` not enforced** (C1.3): The schema field exists but no code preserves or deletes logs based on this value. A deployer can set `retention_days: 1` without validation error.
- [ ] **No TLS enforcement** (C1.2): Network encryption deferred entirely to deployment configuration.

### Recommended Controls

1. **Add `GovernancePolicy.redact_audit_pii` flag** for pattern-based redaction of `AuditEntry.parameters` before persistence.
2. Expand PII patterns to cover the OWASP-recommended set (email, phone, IP address, JWT tokens).
3. Implement asymmetric signing for audit entries to prevent insider forgery.
4. Add key rotation tooling for Ed25519 and HMAC credentials.
5. Enforce `retention_days` at runtime with actual log deletion and archival.
6. Deploy audit logs to encrypted storage (e.g., Azure Blob with SSE, S3 with KMS).

---

## Privacy (P1–P8)

> *Personal information is collected, used, retained, disclosed, and disposed to meet the entity's objectives.*

> **⚠️ Privacy is the largest gap area.** The toolkit is a runtime governance framework for AI agent actions. It was not designed as a privacy management platform. Organizations in SOC 2 scope with Privacy criteria must supplement with dedicated privacy tooling.

### What Exists

| Control | Feature | Location | Coverage |
|---------|---------|----------|----------|
| P1 Notice | No privacy notice mechanism | — | ❌ Gap |
| P2 Choice and consent | No consent management | — | ❌ Gap |
| P3 Collection limitation | `blocked_patterns` can restrict sensitive data in tool arguments (regex, substring, glob) | `packages/agent-os/src/agent_os/integrations/base.py:695-701` | ⚠️ Partial — tool arguments only |
| P4 Use, retention, disposal | `retention_days` schema field (default 90, minimum 1) — declaration only, not enforced at runtime | `packages/agent-os/src/agent_os/policies/policy_schema.json:215-218` | ❌ Gap |
| P5 Access | No data subject access request (DSAR) support | — | ❌ Gap |
| P6 Disclosure and notification | PII detection: 2 regex patterns (SSN, credit card) block matching tool parameters | `packages/agent-os/src/agent_os/mcp_gateway.py:34-42` | ⚠️ Partial |
| P6 Egress controls | Domain-level egress filtering prevents data exfiltration to unauthorized domains | `packages/agent-os/src/agent_os/egress_policy.py:113-139` | ⚠️ Partial |
| P6 Leak detection | Canary token detection catches system prompt leakage in user-visible output | `packages/agent-os/src/agent_os/prompt_injection.py:595-612` | ⚠️ Partial |
| P7 Quality | No data quality or accuracy verification for personal data | — | ❌ Gap |
| P8 Monitoring and enforcement | No privacy-specific monitoring or enforcement mechanisms | — | ❌ Gap |

### Privacy Gaps

- [ ] **No consent management** (P2): No opt-in/opt-out mechanism, consent tracking, purpose limitation, or consent withdrawal support. This is a fundamental Privacy criteria requirement.
- [ ] **No data subject access requests** (P5): No DSAR workflow, data export mechanism, or right-to-erasure support.
- [ ] **No data minimization** (P3): No mechanism to limit data collection to what is necessary for a specific purpose. `blocked_patterns` is a negative control (block known-bad) rather than a positive control (allow only known-good).
- [ ] **No retention enforcement** (P4): `retention_days` field exists in the policy schema but no code preserves or deletes data based on this value. Default is 90 days with minimum 1 — there is no floor enforcement.
- [ ] **Only 2 PII patterns** (P6): SSN (`\b\d{3}-\d{2}-\d{4}\b`) and credit card number regex in `mcp_gateway.py:34-42`. No detection for email addresses, phone numbers, IP addresses, physical addresses, dates of birth, or other PII categories.
- [ ] **No output PII scanning** (P6): PII patterns check tool *input* arguments only. LLM response text is not scanned — an agent can freely output personal data in its responses.
- [ ] **Audit logs record full parameters** (P6): Every tool call's complete arguments are stored verbatim in `AuditEntry` and logged via `logger.info()`. PII in tool arguments becomes PII in audit logs with no redaction. This makes the audit system itself a privacy risk.
- [ ] **No privacy notice mechanism** (P1): No feature generates or delivers privacy notices to end users interacting with governed agents.
- [ ] **No privacy impact assessment tooling** (P8): No DPIA/PIA workflow or template generation.

### Recommended Controls

1. **Implement audit parameter redaction** — apply PII pattern detection to `AuditEntry.parameters` before persistence. This is the highest-leverage single fix.
2. Expand PII detection from 2 patterns to the OWASP-recommended set (email, phone, IP, JWT, passport, driver's license numbers).
3. Apply PII scanning to LLM outputs via `post_execute()` or a dedicated output interceptor.
4. Deploy dedicated privacy management tooling (e.g., OneTrust, BigID, Transcend) for consent, DSAR, and data mapping.
5. Enforce `retention_days` at runtime with automated log deletion.
6. Add `GovernancePolicy.data_classification` metadata to categorize agents by data sensitivity.
7. Document the scope boundary: the toolkit governs agent actions, not personal data lifecycle management.

---

## Evidence Sources

All file paths referenced in this document, organized by package:

### Agent OS (`packages/agent-os/`)
| File | Evidence For |
|------|-------------|
| `src/agent_os/policies/evaluator.py` | CC5.1, PI1.1 — Policy evaluation engine |
| `src/agent_os/policies/schema.py:34-115` | CC5.2, CC7.2 — PolicyDocument, PolicyRule, PolicyAction |
| `src/agent_os/integrations/base.py:689-1038` | CC5.2, CC6.1, PI1.1, PI1.3 — GovernancePolicy, PolicyInterceptor, drift detection |
| `src/agent_os/integrations/rbac.py:16-144` | CC6.1, C1.2 — RBAC roles, permissions, YAML serialization |
| `src/agent_os/integrations/escalation.py:48-583` | CC7.4 — Escalation system, approval backends, quorum, fatigue detection |
| `src/agent_os/audit_logger.py:19-136` | CC7.1 — GovernanceAuditLogger, pluggable backends |
| `src/agent_os/mcp_gateway.py:34-42` | C1.1, P6 — PII pattern detection (SSN, credit card) |
| `src/agent_os/mcp_security.py:272-741` | CC7.3 — MCP security scanner, rug-pull detection, typosquatting |
| `src/agent_os/prompt_injection.py:147-612` | CC6.8 — Prompt injection detection, canary tokens, base64 decoding |
| `src/agent_os/secure_codegen.py:179-393` | PI1.3, C1.1 — Code security validation, secret detection |
| `src/agent_os/supply_chain.py:72-79` | CC7.3 — Supply chain guard |
| `src/agent_os/egress_policy.py:113-139` | C1.2, P6 — Egress filtering |
| `src/agent_os/rate_limiter.py:93-101` | A1.2 — Token-bucket rate limiting (unwired) |
| `policies/policy_schema.json:215-218` | C1.3, P4 — retention_days field |
| `examples/finance-soc2/` | CC6.1, CC6.3, CC7.1, CC7.2, CC7.3, CC8.1 — Reference SOC 2 implementation |
| `modules/control-plane/src/agent_control_plane/flight_recorder.py:33-79` | PI1.5 — Flight recorder (hash integrity defect) |

### AgentMesh (`packages/agent-mesh/`)
| File | Evidence For |
|------|-------------|
| `src/agentmesh/governance/audit.py:23-512` | PI1.5, CC7.1 — MerkleAuditChain, AuditLog, CloudEvents export |
| `src/agentmesh/governance/audit_backends.py:31-87` | PI1.5, C1.2 — HMAC-SHA256 signed audit entries |
| `src/agentmesh/trust/handshake.py:158-456` | CC6.6 — Ed25519 challenge-response handshake |
| `src/agentmesh/core/identity/ca.py:6-44` | CC6.6 — SPIFFE certificate authority |

### Agent Hypervisor (`packages/agent-hypervisor/`)
| File | Evidence For |
|------|-------------|
| `src/hypervisor/models.py:46-69` | CC6.7 — Execution rings (Ring 0–3) |
| `src/hypervisor/security/kill_switch.py:64-136` | CC7.4 — Kill switch (placeholder handoff) |
| `src/hypervisor/audit/delta.py:59-110` | PI1.5 — Delta audit engine (`verify_chain()` stub) |
| `src/hypervisor/rings/breach_detector.py:1-60` | CC9.1 — Ring breach detection |

### Agent SRE (`packages/agent-sre/`)
| File | Evidence For |
|------|-------------|
| `src/agent_sre/cascade/circuit_breaker.py:22-90` | A1.2, CC9.2 — Circuit breakers |
| `src/agent_sre/slo/indicators.py:133-468` | A1.2, PI1.3 — SLIs (7 types), error budgets, burn rate alerts |
| `src/agent_sre/chaos/engine.py:246` | A1.2 — Chaos testing framework |
| `src/agent_sre/anomaly/rogue_detector.py:276-401` | CC9.1 — Rogue agent detection |
| `src/agent_sre/anomaly/detector.py:123` | CC9.1 — Anomaly detection (z-score baselines) |
| `src/agent_sre/replay/engine.py:105` | A1.3 — Replay engine |
| `src/agent_sre/signing.py:18-33` | CC8.1 — Ed25519 artifact signing |
| `src/agent_sre/incidents/detector.py` | CC7.4 — Incident detection |
| `src/agent_sre/delivery/gitops.py` | CC8.1 — Progressive delivery |

### Other
| File | Evidence For |
|------|-------------|
| `BENCHMARKS.md` | A1.1 — Performance benchmarks |
| `docs/THREAT_MODEL.md` | CC1.1 — STRIDE threat model |
| `.github/workflows/dependency-review.yml` | CC8.1 — CI security scanning |
| `.github/workflows/codeql.yml` | CC8.1 — CodeQL analysis |
| `.github/workflows/scorecard.yml` | CC8.1 — OpenSSF Scorecard |

---

## Gaps Summary

All gaps consolidated and rated by severity for remediation prioritization.

### Critical

| Gap | Criteria | Impact | Location |
|-----|----------|--------|----------|
| **Audit logs store unredacted PII** | C1.1, P6 | The audit system records full tool call parameters verbatim, making it a data leak pathway | `mcp_gateway.py:165` |
| **DeltaEngine `verify_chain()` is a stub** | PI1.5 | Returns `True` always — hypervisor audit trail has zero tamper evidence | `delta.py:99` |
| **No consent management** | P2 | Fundamental Privacy criteria requirement not addressed | — |
| **No data subject access request support** | P5 | Required for Privacy criteria compliance | — |

### High

| Gap | Criteria | Impact | Location |
|-----|----------|--------|----------|
| **Kill switch placeholder** | CC7.4 | Does not terminate agent processes; `handoff_success_count` hardcoded to 0 | `kill_switch.py:86` |
| **Detection modules unwired** | CC6.8 | 6 detection modules exist but none are integrated into enforcement lifecycle | `base.py` (multiple) |
| **FlightRecorder hash gap** | PI1.5 | Hash covers INSERT-time state, not final verdict — tampering undetectable | `flight_recorder.py` |
| **HMAC symmetric key risk** | C1.2 | Insider with the key can forge the entire audit chain | `audit_backends.py:61-87` |
| **`retention_days` not enforced** | C1.3, P4 | Schema field exists but no runtime enforcement; default 90, minimum 1 | `policy_schema.json:215-218` |
| **Only 2 PII patterns** | C1.1, P6 | Only SSN and credit card detected; no email, phone, IP, or other PII | `mcp_gateway.py:34-42` |

### Medium

| Gap | Criteria | Impact | Location |
|-----|----------|--------|----------|
| **Chaos engine framework-only** | A1.2 | Records faults but does not inject them; callers must implement injection | `engine.py:246` |
| **RateLimiter not wired** | A1.2 | Correct algorithm exists but not imported by any adapter | `rate_limiter.py:93-101` |
| **No health check endpoints** | A1.1 | No liveness/readiness probes for container orchestration | — |
| **`post_execute()` never blocks** | PI1.3 | Drift detection emits events but always returns `(True, None)` | `base.py:977-1038` |
| **Python-only code validation** | PI1.3 | `CodeSecurityValidator` raises `ValueError` for non-Python languages | `secure_codegen.py:193` |
| **Regex-only prompt injection** | CC6.8 | No semantic or multilingual detection; English-only patterns | `prompt_injection.py` |
| **No at-rest encryption** | C1.1 | Audit logs and policy documents stored in plaintext | — |
| **No key rotation** | C1.2 | No mechanism for rotating Ed25519 or HMAC credentials | — |
| **No privacy notice mechanism** | P1 | No feature delivers privacy notices to end users | — |
| **No data minimization** | P3 | No positive control for limiting data collection to purpose | — |
| **Organizational controls** | CC1–CC4 | Board oversight, personnel policies, risk governance are deployer obligations | — |

---

## Alignment with Other Compliance Mappings

| Framework | Document | Overlap with SOC 2 |
|-----------|----------|-------------------|
| [OWASP Agentic Top 10 (2026)](../OWASP-COMPLIANCE.md) | `docs/OWASP-COMPLIANCE.md` | CC6.8 (malicious software), CC7.3 (vulnerability management), CC9.1 (risk mitigation) |
| [OWASP LLM Top 10 (2025)](owasp-llm-top10-mapping.md) | `docs/compliance/owasp-llm-top10-mapping.md` | CC6.8 (LLM01, LLM07), C1.1 (LLM06), PI1.3 (LLM02, LLM09) |
| [EU AI Act (2024/1689)](eu-ai-act-checklist.md) | `docs/compliance/eu-ai-act-checklist.md` | CC7.1 (Art. 12 logging), CC7.4 (Art. 14 human oversight), PI1.5 (Art. 12 record-keeping) |
| [NIST AI RMF](../nist-rfi-mapping.md) | `docs/nist-rfi-mapping.md` | CC9.1 (Govern/Map functions), A1.2 (Measure function) |

---

<div align="center">

*Last updated: April 2026 · Toolkit version: v2.3.0*

**[⬅ Back to README](../../README.md)** · **[OWASP Agentic Mapping](../OWASP-COMPLIANCE.md)** · **[EU AI Act Checklist](eu-ai-act-checklist.md)**

</div>
