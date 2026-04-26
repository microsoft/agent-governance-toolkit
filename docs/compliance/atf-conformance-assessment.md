<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# ATF Conformance Assessment — Agent Governance Toolkit

> **Disclaimer**: This document is an internal self-assessment mapping, NOT a validated certification or third-party audit. It documents how the toolkit's capabilities align with the referenced standard. Organizations must perform their own compliance assessments with qualified auditors.


**Organization:** Microsoft Corporation
**Implementation:** Agent Governance Toolkit (agent-governance-toolkit)
**ATF Version:** 0.9.0
**Target Maturity Level:** Senior
**Assessment Date:** April 2026
**Toolkit Version:** 3.1.0
**Repository:** https://github.com/microsoft/agent-governance-toolkit

---

## Conformance Statement

Element 1 - Identity:         5/5 requirements met (1 partial)
Element 2 - Behavior:         5/5 requirements met (2 partial)
Element 3 - Data Governance:  5/5 requirements met (2 partial)
Element 4 - Segmentation:     5/5 requirements met
Element 5 - Incident Response: 5/5 requirements met (1 partial)

**Overall: 25/25 requirements addressed — 18 fully met, 7 partially met, 0 not met**

Notes: All 25 requirements are implemented. Seven requirements have partial coverage
where the implementation exists but lacks completeness in specific areas (detailed below).
The toolkit targets Senior maturity level, meeting all MUST requirements for that tier.

---

## Requirement-by-Requirement Assessment

### Element 1: Identity ("Who are you?")

#### I-1: Unique Identifier — ✅ FULLY MET

Every agent receives a globally unique `did:mesh:<fingerprint>` identifier derived from an Ed25519 keypair.

| Component | Location |
|-----------|----------|
| DID generation | `agent-governance-python/agent-mesh/identity/agent_id.py` — `AgentDID.generate()` |
| Identity registry | `agent-governance-python/agent-mesh/identity/agent_id.py` — `IdentityRegistry` |
| Enterprise AAD binding | `agent-governance-python/agent-mesh/identity/entra.py` — `EntraAgentIdentity` |
| .NET package | `AgentGovernance/Trust/AgentIdentity.cs` — `Create()` |
| Rust crate | `agentmesh/src/identity.rs` — `AgentIdentity::generate()` |

#### I-2: Credential Binding — ✅ FULLY MET

Agent identity is bound to Ed25519 cryptographic credentials. Every handshake, delegation, and plugin signature is cryptographically verified.

| Component | Location |
|-----------|----------|
| Ed25519 signing | `agent-governance-python/agent-mesh/identity/agent_id.py` — `sign()`, `verify()` |
| JWK key exchange | `agent-governance-python/agent-mesh/identity/jwk.py` |
| Challenge-response | `agent-governance-python/agent-mesh/trust/handshake.py` |
| mTLS cert binding | `agent-governance-python/agent-mesh/identity/mtls.py` |
| Plugin signing | `agent-governance-python/agent-marketplace/signing.py` — `PluginSigner` |

#### I-3: Ownership Chain — ✅ FULLY MET

Full delegation chain with parent DID tracking, depth limiting, and capability narrowing.

| Component | Location |
|-----------|----------|
| Delegation | `agent-governance-python/agent-mesh/identity/agent_id.py` — `delegate()`, `parent_did`, `delegation_depth` |
| Chain verification | `agent-governance-python/agent-mesh/identity/agent_id.py` — `verify_delegation_chain()` |
| Scope chains | `agent-governance-python/agent-mesh/identity/delegation.py` — `ScopeChain` |
| Capability narrowing | Child capabilities must be subset of parent capabilities |

#### I-4: Purpose Declaration — ⚠️ PARTIALLY MET

Purpose is captured across multiple subsystems but lacks a unified machine-readable taxonomy.

| Component | Location |
|-----------|----------|
| Model card purpose | `agent-governance-python/agent-os/modules/control-plane/hf_utils.py` — `ModelCardInfo.intended_use` |
| GDPR purpose rules | `agent-governance-python/agent-os/templates/policies/gdpr.yaml` |
| Credential purpose | `agent-governance-python/agent-mesh/identity/credentials.py` — `Credential.issued_for` |

**Gap:** No universal `PurposeDeclaration` model enforced at identity creation time. Purpose is fragmented across model cards, policy rules, and credential fields.

#### I-5: Capability Manifest — ✅ FULLY MET

Machine-readable capability declarations for both agents and plugins.

| Component | Location |
|-----------|----------|
| Plugin manifest | `agent-governance-python/agent-marketplace/manifest.py` — `PluginManifest.capabilities` |
| Agent capabilities | `agent-governance-python/agent-mesh/identity/agent_id.py` — `AgentIdentity.capabilities` |
| Capability registry | `agent-governance-python/agent-mesh/trust/capability.py` — `CapabilityRegistry` |
| Effective capabilities | `agent-governance-python/agent-mesh/identity/agent_id.py` — `get_effective_capabilities()` |

---

### Element 2: Behavioral Monitoring ("What are you doing?")

#### B-1: Structured Logging — ✅ FULLY MET

Tamper-evident audit chains with Merkle tree integrity verification.

| Component | Location |
|-----------|----------|
| Merkle audit chain | `agent-governance-python/agent-mesh/audit/merkle_chain.py` — `MerkleAuditChain` |
| Flight recorder | `agent-governance-python/agent-os/modules/control-plane/flight_recorder.py` — `FlightRecorder` |
| Audit trail | `agent-governance-python/agent-hypervisor/audit/delta.py` — `DeltaEngine` |
| OTel integration | `agent-governance-python/agent-mesh/observability/otel_sdk.py` |

#### B-2: Action Attribution — ⚠️ PARTIALLY MET

Actions are attributed to agent identities, but naming conventions vary across packages.

| Component | Location |
|-----------|----------|
| Audit attribution | `agent-governance-python/agent-mesh/audit/merkle_chain.py` — `agent_did` field |
| Hypervisor tracking | `agent-governance-python/agent-hypervisor/audit/delta.py` — `agent_did` per entry |
| Joint liability | `agent-governance-python/agent-hypervisor/liability/joint.py` — `AgentContribution` |

**Gap:** Inconsistent field naming (`agent_id` vs `agent_did` vs `AgentId`) across packages. No shared `Attribution` model.

#### B-3: Behavioral Baseline — ⚠️ PARTIALLY MET

Behavioral baselines with drift detection, but limited cross-session persistence.

| Component | Location |
|-----------|----------|
| Behavior baseline | `agent-governance-python/agent-sre/anomaly/behavioral_baseline.py` — `BehaviorBaseline` |
| Drift detection | `agent-governance-python/agent-os/integrations/drift_detector.py` — `DriftDetector` |
| Rogue agent detection | `agent-governance-python/agent-sre/anomaly/rogue_detector.py` — `RogueAgentDetector` |

**Gap:** Baselines are in-memory only — no durable cross-session persistence.

#### B-4: Anomaly Detection — ✅ FULLY MET

Multi-signal anomaly detection with automated response.

| Component | Location |
|-----------|----------|
| Rogue agent detector | `agent-governance-python/agent-sre/anomaly/rogue_detector.py` — scoring, classification |
| Ring breach detector | `agent-governance-python/agent-hypervisor/rings/breach_detector.py` — sliding-window anomaly |
| Drift scoring | `agent-governance-python/agent-os/integrations/drift_detector.py` — `DriftType` enum |
| Fleet anomaly | `agent-governance-python/agent-sre/fleet/__init__.py` — fleet-wide health monitoring |

#### B-5: Explainability — ✅ FULLY MET

Every policy decision includes a machine-readable reason.

| Component | Location |
|-----------|----------|
| Policy decisions | `agent-governance-python/agent-mesh/governance/policy.py` — `PolicyDecision.reason` |
| Audit rationale | `agent-governance-python/agent-mesh/audit/merkle_chain.py` — `rationale` field |
| Conflict resolution | `agent-governance-python/agent-os/policies/conflict_resolution.py` — `ResolutionResult.winning_reason` |
| .NET decisions | `AgentGovernance/Policy/PolicyDecision.cs` — `Reason` property |

---

### Element 3: Data Governance ("What are you eating? What are you serving?")

#### D-1: Schema Validation — ✅ FULLY MET

Input validation via Pydantic models, JSON Schema, and YAML policy schemas.

| Component | Location |
|-----------|----------|
| Policy schema | `agent-governance-python/agent-os/policies/policy_schema.json` |
| Plugin manifest validation | `agent-governance-python/agent-marketplace/manifest.py` — Pydantic `PluginManifest` |
| CLI validation | `agent-governance-python/agent-os/cli/cmd_validate.py` — JSON Schema + structural |
| OWASP compliance | `agent-governance-python/agent-compliance/verify.py` |

#### D-2: Injection Prevention — ✅ FULLY MET

Multi-layer prompt injection defense with 12+ detection patterns.

| Component | Location |
|-----------|----------|
| Prompt injection detector | `agent-governance-python/agent-os/prompt_injection.py` — `PromptInjectionDetector` |
| MCP tool poisoning scanner | `agent-governance-python/agent-os/mcp_security.py` — `MCPSecurityScanner` |
| Memory guard | `agent-governance-python/agent-os/memory_guard.py` — memory poisoning defense |
| Allowlist/blocklist validation | `agent-governance-python/agent-os/prompt_injection.py` — validated + frozen in `__post_init__` |

#### D-3: PII/PHI Protection — ⚠️ PARTIALLY MET

Regex-based PII detection with redaction, but no ML-based classification.

| Component | Location |
|-----------|----------|
| Secret scanning | `agent-governance-python/agent-os/cli/policy_checker.py` — credential patterns |
| Memory guard redaction | `agent-governance-python/agent-os/memory_guard.py` |
| Policy templates | `agent-governance-python/agent-os/templates/policies/gdpr.yaml` |

**Gap:** Regex-only PII detection. No ML-based NER (e.g., Presidio) integration for complex PII/PHI patterns.

#### D-4: Output Validation — ✅ FULLY MET

Content quality evaluation with multi-dimensional scoring.

| Component | Location |
|-----------|----------|
| Content governance | `agent-governance-python/agent-os/content_governance.py` — `ContentQualityEvaluator` |
| Quality assessment | `agent-governance-python/agent-marketplace/quality_assessment.py` — `QualityAssessor` |
| Output policies | `agent-governance-python/agent-os/templates/policies/content-safety.yaml` |
| Drift detection | `agent-governance-python/agent-os/integrations/drift_detector.py` |

#### D-5: Data Lineage — ⚠️ PARTIALLY MET

Execution-trace-level lineage via flight recorder and audit chains, but no dataset-level provenance.

| Component | Location |
|-----------|----------|
| Flight recorder | `agent-governance-python/agent-os/modules/control-plane/flight_recorder.py` |
| Merkle audit chain | `agent-governance-python/agent-mesh/audit/merkle_chain.py` |
| OTel tracing | `agent-governance-python/agent-mesh/observability/otel_sdk.py` |

**Gap:** No dataset-level lineage tracking. Lineage is execution-trace only — tracks what the agent did, not where the training/reference data came from.

---

### Element 4: Segmentation ("Where can you go?")

#### S-1: Resource Allowlist — ✅ FULLY MET

| Component | Location |
|-----------|----------|
| MCP server allowlist/blocklist | `agent-governance-python/agent-marketplace/marketplace_policy.py` — `MCPServerPolicy` |
| Per-org MCP policies | `agent-governance-python/agent-marketplace/marketplace_policy.py` — `get_effective_mcp_policy()` |
| Egress policy | `agent-governance-python/agent-os/egress_policy.py` — domain-level allow/deny |
| Tool allowlists | `agent-governance-python/agent-os/mcp_gateway.py` — `MCPGateway` |

#### S-2: Action Boundaries — ✅ FULLY MET

| Component | Location |
|-----------|----------|
| Policy rules | `agent-governance-python/agent-os/policies/` — allow/deny/audit rules |
| Allowed/blocked actions | `agent-governance-python/agent-os/templates/policies/*.yaml` |
| Capability gating | `agent-governance-python/agent-mesh/trust/capability.py` — `CapabilityScope` |
| Context-aware enforcement | `agent-governance-python/agent-os/execution_context_policy.py` — `ContextualPolicyEngine` |

#### S-3: Rate Limiting — ✅ FULLY MET

| Component | Location |
|-----------|----------|
| Hypervisor rate limiter | `agent-governance-python/agent-hypervisor/security/rate_limiter.py` |
| Policy rate limits | `agent-governance-python/agent-mesh/governance/policy.py` — `check_rate_limit()` |
| MCP gateway limits | `agent-governance-python/agent-os/mcp_gateway.py` |
| .NET rate limiter | `AgentGovernance/Hypervisor/RateLimiter.cs` |

#### S-4: Transaction Limits — ✅ FULLY MET

| Component | Location |
|-----------|----------|
| Cost guard | `agent-governance-python/agent-sre/slo/__init__.py` — cost-based SLIs |
| Max tool calls | `agent-governance-python/agent-os/integrations/base.py` — `GovernancePolicy.max_tool_calls` |
| Budget enforcement | `agent-governance-python/agent-os/context_budget.py` — `ContextScheduler` |
| Execution context limits | `agent-governance-python/agent-os/execution_context_policy.py` |

#### S-5: Blast Radius Containment — ✅ FULLY MET

| Component | Location |
|-----------|----------|
| 4-ring execution model | `agent-governance-python/agent-hypervisor/models.py` — Ring 0-3 privilege separation |
| Ring breach detection | `agent-governance-python/agent-hypervisor/rings/breach_detector.py` |
| Docker/K8s isolation | `agent-governance-python/agent-runtime/deploy.py` — `DockerDeployer`, `KubernetesDeployer` |
| Cascade detection | `agent-governance-python/agent-sre/cascade/circuit_breaker.py` — `CascadeDetector` |

---

### Element 5: Incident Response ("What if you go rogue?")

#### R-1: Circuit Breaker — ✅ FULLY MET

| Component | Location |
|-----------|----------|
| Python circuit breaker | `agent-governance-python/agent-sre/cascade/circuit_breaker.py` — trip/open/half-open state machine |
| .NET circuit breaker | `AgentGovernance/Sre/CircuitBreaker.cs` |
| Cascade detector | `agent-governance-python/agent-sre/cascade/circuit_breaker.py` — `CascadeDetector` |

#### R-2: Kill Switch — ✅ FULLY MET

| Component | Location |
|-----------|----------|
| Kill switch | `agent-governance-python/agent-hypervisor/security/kill_switch.py` — `KillSwitch.kill()` |
| Kill reasons | 6 types: behavioral drift, rate limit, ring breach, manual, quarantine timeout, session timeout |
| CLI kill | `agent-governance-python/agent-hypervisor/cli/session_commands.py` — `cmd_kill` |
| Saga compensation | Handoff to substitutes, in-flight step compensation |

#### R-3: Session Revocation — ✅ FULLY MET

| Component | Location |
|-----------|----------|
| Revocation list | `agent-governance-python/agent-mesh/identity/revocation.py` — `RevocationList` |
| Credential revocation | `agent-governance-python/agent-mesh/identity/credentials.py` — `Credential.revoke()` |
| Identity suspension | `agent-governance-python/agent-mesh/identity/agent_id.py` — `suspend()`, `reactivate()` |
| Capability stripping | `agent-governance-python/agent-mesh/trust/capability.py` — `revoke_all_from()` |

#### R-4: State Rollback — ✅ FULLY MET

| Component | Location |
|-----------|----------|
| Saga orchestrator | `agent-governance-python/agent-hypervisor/saga/orchestrator.py` — `SagaOrchestrator` |
| Reversibility registry | `agent-governance-python/agent-hypervisor/reversibility/registry.py` |
| VFS snapshots | `agent-governance-python/agent-hypervisor/session/__init__.py` — `create_vfs_snapshot()` |
| .NET sagas | `AgentGovernance/Hypervisor/SagaOrchestrator.cs` |

#### R-5: Graceful Degradation — ⚠️ PARTIALLY MET

Degradation mechanisms exist but are not unified under a single autonomy controller.

| Component | Location |
|-----------|----------|
| NoOp fallbacks | `agent-governance-python/agent-os/compat.py` — `NoOpPolicyEvaluator` |
| Ring demotion | `agent-governance-python/agent-hypervisor/session/__init__.py` — `update_ring()` |
| Trust-tier demotion | `agent-governance-python/agent-marketplace/trust_tiers.py` — `filter_capabilities()` |
| Fleet degraded state | `agent-governance-python/agent-sre/fleet/__init__.py` — `AgentState.DEGRADED` |

**Gap:** No unified autonomy controller that coordinates demotion across rings, trust tiers, and capability sets in a single workflow.

---

## Gap Analysis Summary

| ID | Requirement | Gap | Recommended Fix |
|----|------------|-----|-----------------|
| I-4 | Purpose Declaration | No unified PurposeDeclaration model | Create machine-readable taxonomy enforced at identity creation |
| B-2 | Action Attribution | Inconsistent agent_id vs agent_did naming | Standardize on agent_did across all packages |
| B-3 | Behavioral Baseline | In-memory only, no cross-session persistence | Add file/DB-backed baseline persistence |
| D-3 | PII/PHI Protection | Regex-only detection | Integrate ML-based NER (e.g., Presidio) |
| D-5 | Data Lineage | Execution-trace only | Add dataset-level provenance tracking |
| R-5 | Graceful Degradation | Scattered fallback mechanisms | Create unified AutonomyController |
| — | .NET package | HMAC fallback instead of Ed25519 | Implement full Ed25519 asymmetric signing |

---

## Maturity Level Assessment

Targeting **Senior** maturity level per ATF v0.9.0 maturity matrix:

- All 25 MUST requirements for Senior level: ✅ Met
- All SHOULD requirements for Senior level: ✅ Met (with noted partial implementations)
- Principal-level requirements (D-5 Data Lineage, R-4 State Rollback, S-4/S-5 limits): ✅ Met

The toolkit meets Senior requirements and partially addresses Principal-level requirements.

---

## References

- [ATF Specification](https://github.com/massivescale-ai/agentic-trust-framework)
- [ATF Conformance Specification v0.9.0](https://github.com/massivescale-ai/agentic-trust-framework/blob/main/CONFORMANCE.md)
- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [OWASP Agentic Security Top 10](https://owasp.org/www-project-agentic-security/)
