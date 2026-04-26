# CSA Agentic Trust Framework (ATF) — Compliance Mapping

**Framework:** [CSA Agentic Trust Framework v0.1.0](https://github.com/massivescale-ai/agentic-trust-framework/blob/main/SPECIFICATION.md)
**Published:** February 2026 by Cloud Security Alliance
**Mapping Date:** March 4, 2026

---

## Summary

The CSA Agentic Trust Framework (ATF) applies Zero Trust security principles to AI agents. It defines 5 core elements that all ATF-compliant implementations MUST satisfy. The Agent Governance Toolkit covers **all 5 pillars** through its 4 packages.

## Compliance Matrix

| ATF Pillar | Requirement | Toolkit Coverage | Package | Status |
|-----------|-------------|-----------------|---------|--------|
| **4.1 Identity Management** | Unique, verifiable agent identity | Ed25519 DID identity, SPIFFE/SVID certs, trust scoring (0–1000) | AgentMesh | ✅ Full |
| **4.2 Behavioral Monitoring** | Continuous anomaly detection | SLI/SLO tracking, anomaly detection, behavioral baselines | Agent SRE | ✅ Full |
| **4.3 Data Governance** | Input/output validation | Policy engine input validation, output filtering, PII detection | Agent OS | ✅ Full |
| **4.4 Segmentation** | Least-privilege access control | 4-tier Ring model (Ring 0–3), capability sandbox, tool allow/deny | Agent OS + Runtime | ✅ Full |
| **4.5 Incident Response** | Rapid containment and recovery | Kill switch (<1s), saga rollback, circuit breakers | Agent Runtime + SRE | ✅ Full |

---

## Detailed Mapping

### 4.1 Identity Management

> **ATF Requirement:** Every agent MUST have a unique, verifiable identity.

#### 4.1.1 Identity Creation

| ATF MUST | Implementation | Component |
|----------|---------------|-----------|
| Cryptographically unique identifiers per agent | Ed25519 keypair + DID generation (`did:mesh:<fingerprint>`) | `AgentIdentity.create()` |
| Bind identities to agent versions/configs | Identity includes version, capabilities, sponsor metadata | `AgentIdentity` dataclass |
| Support identity rotation without disruption | Key rotation via `rotate()` with continuity chain | `AgentIdentity.rotate()` |

| ATF SHOULD | Implementation |
|------------|---------------|
| Industry-standard identity formats | DID (W3C), SPIFFE SVIDs, x.509 certificates |
| Federated identity providers | SPIFFE federation, A2A protocol bridge |
| Log all identity lifecycle events | Full audit trail via event bus |

#### 4.1.2 Identity Verification

| ATF MUST | Implementation |
|----------|---------------|
| Agent identifier in each request | `agent_id` field in all IATP messages |
| Timestamp | Signed timestamps in challenge-response protocol |
| Cryptographic proof (signature/token/cert) | Ed25519 signature verification, mutual TLS |

### 4.2 Behavioral Monitoring

> **ATF Requirement:** Agent behavior MUST be continuously monitored for anomalies.

#### 4.2.1 Baseline Establishment

| ATF MUST | Implementation | Component |
|----------|---------------|-----------|
| Collect metrics for ≥7 days or 1000 ops | SLI recording with configurable windows (1h to 30d) | `SLI.record()` |
| Define normal ranges for key metrics | SLO targets with thresholds (latency P99, error rate, token usage) | `SLO.evaluate()` |
| Update baselines periodically | Sliding window SLI aggregation, error budget recalculation | `ErrorBudget` |

| ATF Required Metrics | Our Coverage |
|---------------------|-------------|
| Request frequency and patterns | ✅ Rate limiting, request counting |
| Resource consumption (tokens, API calls) | ✅ Token tracking, API call limits per policy |
| Input/output characteristics | ✅ Content pattern matching, output length monitoring |
| Error rates and types | ✅ Error budget tracking (good/bad events), SLI compliance |

#### 4.2.2 Anomaly Detection

| ATF MUST | Implementation |
|----------|---------------|
| Detect deviations exceeding thresholds | SLO burn rate alerts, error budget exhaustion detection |
| Alerts within 60 seconds | Real-time SLO evaluation, circuit breaker trip notifications |
| Statistical and rule-based detection | Rule-based (SLO thresholds) + statistical (burn rate trends) |

| ATF SHOULD | Implementation |
|------------|---------------|
| Correlate anomalies across agents | Agent SRE fleet monitoring, cross-agent SLO dashboards |
| Anomaly severity scoring | Burn rate severity (1x, 2x, 10x, 100x) maps to severity levels |

### 4.3 Data Governance

> **ATF Requirement:** All agent inputs and outputs MUST be validated.

#### 4.3.1 Input Validation

| ATF MUST | Implementation | Component |
|----------|---------------|-----------|
| Validate data schema and types | Policy engine validates action schemas before execution | `PolicyEngine.evaluate()` |
| Detect injection attacks | Blocked patterns (regex/glob) for SQL injection, shell commands, prompt injection | `GovernancePolicy.blocked_patterns` |
| Check for data poisoning | VFS integrity checks, CMVK content verification | Agent OS VFS |

#### 4.3.2 Output Filtering

| ATF MUST | Implementation | Component |
|----------|---------------|-----------|
| Scan outputs for PII/secrets/credentials | PII detection patterns, credential scanning | `OutputValidationMiddleware` |
| Configurable content filtering | Blocked output patterns, max length limits | `GovernancePolicy` |
| Log all filtering actions | Full audit trail of policy decisions | Audit subsystem |

| ATF SHOULD | Implementation |
|------------|---------------|
| Custom filtering rules | YAML policy definitions with regex patterns |
| Redaction capabilities | PII redaction in output validation middleware |
| Output sampling for audit | Audit trail captures all decisions (100% sampling) |

### 4.4 Segmentation

> **ATF Requirement:** Agent access MUST be limited by least-privilege policies.

#### 4.4.1 Access Control

| ATF MUST | Implementation | Component |
|----------|---------------|-----------|
| Granular permissions per agent | Tool-level allow/deny lists, capability-based access control | `CapabilitySandbox` |
| Time-based access restrictions | Rate limiting with sliding windows (60s default) | `GovernancePolicy.rate_limits` |
| Dynamic permission adjustment | Policy hot-reload, context-aware capability grants | `PolicyEngine` |

| ATF Required Policy Elements | Our Coverage |
|-----------------------------|-------------|
| Resource access lists | ✅ `allowed_tools`, `blocked_tools` per policy |
| Operation permissions (read/write/exec) | ✅ Ring-based permissions (Ring 0 = kernel, Ring 3 = user) |
| Rate limits and quotas | ✅ `max_tool_calls`, `max_tokens_per_call`, sliding window rate limits |

#### 4.4.2 Network Isolation

| ATF SHOULD | Implementation |
|------------|---------------|
| Network-level segmentation | Agent Runtime execution rings provide process-level isolation |
| API gateway integration | MCP server acts as governance gateway for tool calls |
| Service mesh compatibility | AgentMesh IATP protocol integrates with service mesh patterns |

### 4.5 Incident Response

> **ATF Requirement:** Systems MUST support rapid agent containment and recovery.

#### 4.5.1 Kill Switch

| ATF MUST | Implementation | Component |
|----------|---------------|-----------|
| Immediate termination (<1 second) | Kill switch with state preservation, < 100ms response | `KillSwitch.activate()` |
| Graceful and forced shutdown modes | Graceful (drain + save state) and forced (immediate halt) modes | Agent Runtime |
| Audit log of all activations | Kill switch events logged with timestamp, reason, initiator | Audit subsystem |

#### 4.5.2 Recovery

| ATF MUST | Implementation | Component |
|----------|---------------|-----------|
| Rollback to last known good config | Saga rollback with compensation actions | `SagaOrchestrator.rollback()` |
| Incident investigation capabilities | Incident timeline reconstruction, event replay | Agent SRE |
| Selective restart with restrictions | Ring demotion (e.g., Ring 1 → Ring 3) on restart | Agent Runtime |

| ATF SHOULD | Implementation |
|------------|---------------|
| Automate incident response | Circuit breakers auto-trip, error budget exhaustion triggers |
| Enterprise incident management integration | OTel export to enterprise SIEM/SOAR systems |
| Forensic data collection | Hash-chain audit trail (SHA-256 Merkle chain, tamper-evident) |

---

## Security Considerations Mapping

### 5.1 Cryptographic Requirements

| ATF SHOULD | Our Implementation |
|------------|-------------------|
| AES-256 for symmetric encryption | AgentMesh encrypted channels |
| RSA-2048 or ECC P-256 for asymmetric | Ed25519 (stronger than P-256 for signatures) |
| SHA-256+ for hashing | SHA-256 hash chains throughout audit subsystem |

### 5.2 Key Management

| ATF MUST | Our Implementation |
|----------|-------------------|
| Never store keys in plain text | Keys managed via SPIFFE workload API or secure env vars |
| Support key rotation | `AgentIdentity.rotate()` with continuity chain |
| HSM support where available | SPIFFE/SVID supports HSM-backed certificate authorities |

### 5.3 Audit Logging

| ATF Required Events | Our Coverage |
|--------------------|-------------|
| Identity operations | ✅ All DID lifecycle events logged |
| Policy changes | ✅ Policy load/reload events in audit trail |
| Anomaly detections | ✅ SLO breach, burn rate alerts, circuit breaker trips |
| Kill switch activations | ✅ Kill switch events with full context |

---

## ATF Compliance Checklist

| Requirement | Status |
|------------|--------|
| ☑ Identity Management — Unique ID generation | ✅ |
| ☑ Identity Management — Credential verification | ✅ |
| ☑ Identity Management — Identity rotation | ✅ |
| ☑ Behavioral Monitoring — Metric collection | ✅ |
| ☑ Behavioral Monitoring — Baseline establishment | ✅ |
| ☑ Behavioral Monitoring — Anomaly detection | ✅ |
| ☑ Data Governance — Input validation | ✅ |
| ☑ Data Governance — Output filtering | ✅ |
| ☑ Data Governance — Audit logging | ✅ |
| ☑ Segmentation — Permission policies | ✅ |
| ☑ Segmentation — Access control | ✅ |
| ☑ Segmentation — Rate limiting | ✅ |
| ☑ Incident Response — Kill switch | ✅ |
| ☑ Incident Response — Recovery procedures | ✅ |
| ☑ Incident Response — Forensics capability | ✅ |

**Result: 15/15 requirements covered. Full ATF compliance.**

---

## References

- [CSA Agentic Trust Framework](https://cloudsecurityalliance.org/blog/2026/02/02/the-agentic-trust-framework-zero-trust-governance-for-ai-agents)
- [ATF Specification v0.1.0](https://github.com/massivescale-ai/agentic-trust-framework/blob/main/SPECIFICATION.md)
- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
