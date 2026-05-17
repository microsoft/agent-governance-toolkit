<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Agent Hypervisor Execution Control -- Version 1.0

> **Status:** Draft · **Date:** 2026-05-17 · **Authors:** Agent Governance Toolkit team
>
> This specification defines the execution control model for the Agent
> Hypervisor, including execution rings, privilege elevation, resource
> constraints, rate limiting, session isolation, kill switch, audit
> integrity, and quarantine. All SDK implementations MUST conform to
> this specification.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in
[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) and
[RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174).

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Execution Rings](#3-execution-rings)
4. [Ring Assignment](#4-ring-assignment)
5. [Action Classification](#5-action-classification)
6. [Ring Enforcement](#6-ring-enforcement)
7. [Resource Constraints](#7-resource-constraints)
8. [Privilege Elevation](#8-privilege-elevation)
9. [Rate Limiting](#9-rate-limiting)
10. [Session Model](#10-session-model)
11. [Session Isolation](#11-session-isolation)
12. [Kill Switch](#12-kill-switch)
13. [Quarantine](#13-quarantine)
14. [Audit and Hash Chain Integrity](#14-audit-and-hash-chain-integrity)
15. [Saga Orchestration](#15-saga-orchestration)
16. [Risk Weight Model](#16-risk-weight-model)
17. [Configuration Validation](#17-configuration-validation)
18. [Provider Extensibility](#18-provider-extensibility)
19. [Failure Semantics](#19-failure-semantics)
20. [Security Considerations](#20-security-considerations)
21. [Conformance Requirements](#21-conformance-requirements)
22. [Worked Examples](#22-worked-examples)
23. [References](#23-references)

---

## 1. Introduction

### 1.1 Purpose

The Agent Hypervisor provides hardware-inspired execution isolation for
AI agents. Just as an OS kernel uses privilege rings to separate user
processes from kernel operations, the Agent Hypervisor assigns agents to
execution rings based on their trust scores and enforces resource
boundaries at each ring level.

### 1.2 Scope

This specification covers:

- **Execution rings:** Four privilege levels (Ring 0-3) with distinct
  resource constraints.
- **Ring assignment:** Trust-score-based ring derivation with consensus
  requirements.
- **Action classification:** Mapping actions to required rings based on
  reversibility, read-only status, and admin flags.
- **Privilege elevation:** Time-bounded, trust-gated ring elevation
  with attestation requirements.
- **Rate limiting:** Per-agent token bucket enforcement scaled by ring.
- **Session management:** Multi-agent session lifecycle with consistency
  modes and participation requirements.
- **Session isolation:** Filesystem-level isolation with configurable
  cross-session access.
- **Kill switch:** Agent termination with step handoff and compensation.
- **Audit:** Append-only hash chain for tamper-evident session records.

### 1.3 Relationship to Other Specifications

| Specification | Relationship |
| --- | --- |
| Agent OS Policy Engine 1.0 | Policy decisions may trigger ring demotion or quarantine |
| AgentMesh Identity and Trust 1.0 | Trust scores drive ring assignment; DIDs identify agents |
| Agent SRE (planned) | SRE Witness required for Ring 0; circuit breakers feed kill switch |

### 1.4 Design Principles

1. **Least privilege by default.** Unknown agents start at Ring 3
   (Sandbox) with minimal resource access.
2. **Ring 0 is system-only.** No agent, regardless of trust score, can
   execute Ring 0 actions without SRE Witness attestation.
3. **Elevation is temporary.** Privilege elevation is always
   time-bounded and automatically expires.
4. **Fail closed.** Any enforcement check failure MUST result in
   denial, never silent permission.
5. **Append-only audit.** Session operations form a hash chain that
   can detect tampering.

---

## 2. Terminology

| Term | Definition |
| --- | --- |
| **Execution Ring** | One of four privilege levels (0-3) that determine what resources and actions an agent can access. |
| **Ring 0 (Root)** | Highest privilege; reserved for hypervisor configuration and penalty operations. Requires SRE Witness. |
| **Ring 1 (Privileged)** | Non-reversible actions; requires high trust score (>0.95) plus consensus. |
| **Ring 2 (Standard)** | Reversible actions; requires moderate trust score (>0.60). |
| **Ring 3 (Sandbox)** | Read-only and research actions; default for unknown or low-trust agents. |
| **Effective Score** | A normalized 0.0-1.0 trust score combining raw reputation with environmental factors. |
| **SRE Witness** | A human Site Reliability Engineer who must attest Ring 0 operations. |
| **Privilege Elevation** | A time-bounded promotion from a lower ring to a higher ring. |
| **Token Bucket** | Rate limiting algorithm with a refill rate and burst capacity. |
| **Session** | A bounded multi-agent collaboration context with lifecycle, consistency mode, and audit trail. |
| **Kill Switch** | Emergency agent termination mechanism with step handoff capability. |
| **Quarantine** | Temporary isolation of a misbehaving agent from the execution environment. |
| **Saga** | A multi-step distributed transaction with compensation (undo) support. |
| **Hash Chain** | Append-only sequence of SHA-256 linked records for tamper detection. |
| **Action Descriptor** | Metadata about an action including reversibility, APIs, and admin status. |
| **Resource Constraint** | Per-ring rules governing network, filesystem, and subprocess access. |

---

## 3. Execution Rings

### 3.1 Ring Definitions

The hypervisor MUST implement exactly four execution rings:

| Ring | Value | Name | Description |
| --- | --- | --- | --- |
| Ring 0 | 0 | Root | Hypervisor config and penalty. System-only. |
| Ring 1 | 1 | Privileged | Non-reversible actions with full resource access |
| Ring 2 | 2 | Standard | Reversible actions with scoped resource access |
| Ring 3 | 3 | Sandbox | Read-only actions with minimal resource access |

**[Pure Specification]**

### 3.2 Ring Ordering

Rings are numerically ordered: lower value = higher privilege.
Ring `A` is more privileged than Ring `B` if `A.value < B.value`.
**[Pure Specification]**

### 3.3 Default Ring

Agents without a computed ring assignment MUST be assigned Ring 3
(Sandbox). **[Pure Specification]**

---

## 4. Ring Assignment

### 4.1 Score-Based Assignment

Ring assignment from an effective score MUST follow these rules:

| Condition | Assigned Ring |
| --- | --- |
| `eff_score > 0.95` AND `has_consensus == true` | Ring 1 (Privileged) |
| `eff_score > 0.60` | Ring 2 (Standard) |
| Otherwise | Ring 3 (Sandbox) |

Ring 0 is NEVER assigned through score-based computation.
**[Pure Specification]**

### 4.2 Trust Thresholds

| Threshold | Value | Purpose |
| --- | --- | --- |
| `RING_1_TRUST_THRESHOLD` | 0.95 | Score-based Ring 1 assignment |
| `RING_2_TRUST_THRESHOLD` | 0.60 | Score-based Ring 2 assignment |
| `RING_1_ENFORCER_THRESHOLD` | 0.70 | Ring enforcer Ring 1 access |

**[Default Implementation]**

### 4.3 Ring Demotion

An agent SHOULD be demoted when their effective score drops below the
threshold for their current ring. The `should_demote()` check MUST
compare the agent's current ring against the ring that would be
computed from their current score. **[Pure Specification]**

---

## 5. Action Classification

### 5.1 Action Descriptor

An ActionDescriptor MUST contain the following fields:

| Field | Type | Description |
| --- | --- | --- |
| `action_id` | string | Unique identifier (validated format) |
| `name` | string | Human-readable name (non-empty, max 256 chars) |
| `execute_api` | string | API path for execution (non-empty, max 2048 chars) |
| `undo_api` | string or null | API path for undo (if reversible) |
| `reversibility` | enum | FULL, PARTIAL, or NONE |
| `undo_window_seconds` | int | Window for undo (0-86400, default 0) |
| `compensation_method` | string or null | Compensation strategy name |
| `is_read_only` | bool | Whether the action only reads data |
| `is_admin` | bool | Whether this is an administrative action |

### 5.2 Required Ring Derivation

The required ring for an action MUST be computed as:

```
if is_admin:          -> Ring 0 (Root)
elif reversibility == NONE and not is_read_only:
                      -> Ring 1 (Privileged)
elif is_read_only:    -> Ring 3 (Sandbox)
else:                 -> Ring 2 (Standard)
```

**[Pure Specification]**

### 5.3 Validation Rules

1. `action_id` MUST match the pattern
   `^[a-zA-Z0-9]([a-zA-Z0-9._:-]*[a-zA-Z0-9])?$` and MUST NOT
   exceed 256 characters. **[Pure Specification]**
2. `name` MUST be non-empty and MUST NOT exceed 256 characters.
   **[Pure Specification]**
3. `execute_api` MUST be non-empty and MUST NOT exceed 2048 characters.
   **[Pure Specification]**
4. `undo_window_seconds` MUST be in the range [0, 86400].
   **[Pure Specification]**

---

## 6. Ring Enforcement

### 6.1 Access Check

The ring enforcer MUST perform the following checks in order:

1. **Ring 0 denial:** If the action requires Ring 0, the check MUST
   deny access with `requires_sre_witness = true`. Ring 0 actions are
   never available to agents through the standard API.
   **[Pure Specification]**

2. **Ring comparison:** If `agent_ring.value > required_ring.value`
   (agent has less privilege than required), the check MUST deny
   access. **[Pure Specification]**

3. **Grant:** If neither condition above applies, access MUST be
   granted. **[Pure Specification]**

### 6.2 Check Result

A RingCheckResult MUST contain:

| Field | Type | Description |
| --- | --- | --- |
| `allowed` | bool | Whether access is granted |
| `required_ring` | ExecutionRing | Ring the action requires |
| `agent_ring` | ExecutionRing | Agent's current ring |
| `eff_score` | float | Agent's effective score |
| `reason` | string | Human-readable explanation |
| `requires_consensus` | bool | Whether consensus is needed |
| `requires_sre_witness` | bool | Whether SRE attestation is needed |
| `denied_resources` | list | Resource types that were denied |

### 6.3 Resource Check

Resource access checks MUST consult the ring-to-constraint mapping
(Section 7). If the constraint allows the resource, access MUST be
granted. Otherwise, access MUST be denied with the denied resource
type recorded. **[Pure Specification]**

### 6.4 Unknown Ring Fallback

If a ring is not found in the constraint mapping, the constraints for
Ring 3 (Sandbox) MUST be used as fallback. **[Pure Specification]**

---

## 7. Resource Constraints

### 7.1 Constraint Model

Each ring has an associated ResourceConstraints record:

| Field | Type | Description |
| --- | --- | --- |
| `network_allowed` | bool | Whether network access is permitted |
| `network_allowlist` | list\[string\] | Allowed network destinations (empty = all) |
| `filesystem_writable` | bool | Whether filesystem writes are permitted |
| `filesystem_scope` | string | Scope: "none", "session", "scoped", or "full" |
| `subprocess_allowed` | bool | Whether subprocess creation is permitted |
| `max_concurrent_tools` | int | Maximum concurrent tool executions |

### 7.2 Ring-to-Constraint Mapping

| Ring | Network | FS Scope | Subprocess | Max Tools |
| --- | --- | --- | --- | --- |
| Ring 0 (Root) | Yes | full | Yes | 32 |
| Ring 1 (Privileged) | Yes | full | Yes | 16 |
| Ring 2 (Standard) | Yes (allowlist) | scoped | Yes | 8 |
| Ring 3 (Sandbox) | No | none | No | 2 |

**[Default Implementation]**

### 7.3 Resource Types

Implementations MUST support at least the following resource types:

- `NETWORK`: External network access.
- `FILESYSTEM`: File read/write operations.
- `SUBPROCESS`: Process creation.
- `TOOL_EXECUTION`: Tool invocation (always allowed).

**[Pure Specification]**

### 7.4 Filesystem Scope Semantics

| Scope | Meaning |
| --- | --- |
| `"none"` | No filesystem access |
| `"session"` | Agent's own session directory only |
| `"scoped"` | Agent's directories plus explicitly granted paths |
| `"full"` | Unrestricted filesystem access |

**[Pure Specification]**

---

## 8. Privilege Elevation

### 8.1 Overview

Privilege elevation allows an agent to temporarily operate at a
higher ring level. Elevations are time-bounded, trust-gated, and
subject to attestation requirements.

### 8.2 Elevation Request

An elevation request MUST specify:

| Field | Type | Description |
| --- | --- | --- |
| `agent_did` | string | Requesting agent's DID |
| `session_id` | string | Session context |
| `current_ring` | ExecutionRing | Agent's current ring |
| `target_ring` | ExecutionRing | Requested ring |
| `ttl_seconds` | int | Requested duration |
| `attestation` | string or null | Sponsor attestation for Ring 1 |
| `reason` | string | Justification for elevation |
| `trust_score` | float or null | Agent's current trust score |

### 8.3 Denial Reasons

Elevation requests MUST be denied with a specific reason for each
failure condition:

| Reason | Condition |
| --- | --- |
| `invalid_target` | Target ring is same or lower privilege than current |
| `ring_0_forbidden` | Target is Ring 0 (never allowed via standard API) |
| `duplicate_elevation` | Agent already has an active elevation in this session |
| `insufficient_trust` | Trust score is missing or below threshold |
| `no_sponsorship` | Ring 1 elevation without attestation |
| `expired_ttl` | (reserved for future use) |
| `community_edition` | (reserved for future use) |

**[Pure Specification]**

### 8.4 Trust Thresholds for Elevation

| Target Ring | Required Trust Score |
| --- | --- |
| Ring 1 (Privileged) | >= 0.85 |
| Ring 2 (Standard) | >= 0.50 |

**[Default Implementation]**

### 8.5 Time Bounds

1. `DEFAULT_TTL` MUST be 300 seconds (5 minutes).
   **[Default Implementation]**
2. `MAX_ELEVATION_TTL` MUST be 3600 seconds (1 hour).
   **[Default Implementation]**
3. Requested TTL MUST be clamped to `MAX_ELEVATION_TTL`.
   **[Pure Specification]**

### 8.6 Elevation Lifecycle

1. On grant: create a `RingElevation` record with expiry timestamp.
2. On `tick()`: check all active elevations for expiry and revoke
   expired ones.
3. On `revoke_elevation()`: immediately remove the elevation.
4. `get_effective_ring()`: return the elevated ring if an active
   elevation exists, otherwise the base ring.

**[Pure Specification]**

### 8.7 Ring 0 Prohibition

Ring 0 elevation MUST be forbidden through the standard elevation API.
Ring 0 operations require out-of-band SRE Witness attestation.
**[Pure Specification]**

### 8.8 Child Registration

When a parent agent delegates to a child, the child's ring MUST NOT
exceed the parent's effective ring. The child MUST be registered with
`register_child()`. **[Pure Specification]**

---

## 9. Rate Limiting

### 9.1 Token Bucket Algorithm

Rate limiting MUST use a token bucket algorithm with:

1. `capacity`: Maximum burst size.
2. `tokens`: Current available tokens.
3. `refill_rate`: Tokens added per second.
4. `consume(n)`: Attempt to consume `n` tokens. Returns `true` if
   successful, `false` if insufficient tokens.
5. `_refill()`: Add tokens based on elapsed time, capped at capacity.

**[Pure Specification]**

### 9.2 Ring-Based Rate Limits

Each ring MUST have a configured rate limit (requests/sec, burst):

| Ring | Rate (req/s) | Burst |
| --- | --- | --- |
| Ring 0 (Root) | 100.0 | 200.0 |
| Ring 1 (Privileged) | 50.0 | 100.0 |
| Ring 2 (Standard) | 20.0 | 40.0 |
| Ring 3 (Sandbox) | 5.0 | 10.0 |

**[Default Implementation]**

### 9.3 Fallback Rate Limit

If an agent's ring is not found in the rate limit map, the Ring 2
(Standard) rate limit MUST be used as fallback. **[Pure Specification]**

### 9.4 Rate Limit Exceeded

When an agent exceeds their rate limit, implementations MUST raise
`RateLimitExceeded`. **[Pure Specification]**

### 9.5 Ring Change

When an agent's ring changes (elevation or demotion), the rate limiter
MUST recreate the token bucket with the new ring's limits.
**[Pure Specification]**

### 9.6 Bucket Management

Implementations MUST enforce a maximum number of active token buckets
to prevent memory exhaustion. **[Pure Specification]**

**[Default Implementation]** Maximum buckets: 100,000.

---

## 10. Session Model

### 10.1 Session States

Sessions MUST follow this state machine:

```
CREATED -> HANDSHAKING -> ACTIVE -> TERMINATING -> ARCHIVED
```

| State | Description |
| --- | --- |
| `CREATED` | Session created, not yet accepting participants |
| `HANDSHAKING` | Accepting participant join requests |
| `ACTIVE` | Executing actions |
| `TERMINATING` | Shutting down, completing in-flight operations |
| `ARCHIVED` | Permanently closed, read-only |

**[Pure Specification]**

### 10.2 Session Configuration

A SessionConfig MUST contain:

| Field | Type | Default | Constraints |
| --- | --- | --- | --- |
| `consistency_mode` | enum | EVENTUAL | STRONG or EVENTUAL |
| `max_participants` | int | 10 | [1, 1000] |
| `max_duration_seconds` | int | 3600 | [1, 604800] (7 days) |
| `min_eff_score` | float | 0.60 | [0.0, 1.0] |
| `enable_audit` | bool | true | |
| `enable_blockchain_commitment` | bool | false | |

### 10.3 Session Participant

A SessionParticipant MUST contain:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `agent_did` | string | (required) | Valid agent identifier |
| `ring` | ExecutionRing | Ring 3 | Current execution ring |
| `sigma_raw` | float | 0.0 | Raw reputation score [0.0, 1.0] |
| `eff_score` | float | 0.0 | Effective score [0.0, 1.0] |
| `joined_at` | datetime | now(UTC) | Join timestamp |
| `is_active` | bool | true | Active participation flag |

### 10.4 Consistency Modes

| Mode | Description |
| --- | --- |
| `STRONG` | Requires consensus for state changes |
| `EVENTUAL` | Uses gossip-based eventual consistency |

**[Pure Specification]**

---

## 11. Session Isolation

### 11.1 Isolation Levels

Implementations MUST support at least three isolation levels:

| Level | Description | Coordination Cost |
| --- | --- | --- |
| `SNAPSHOT` | Complete isolation; agent sees only its own session state | Low |
| `READ_COMMITTED` | Can read from granted sessions; writes to own only | Medium |
| `SERIALIZABLE` | Full causal ordering with vector clocks and intent locks | High |

**[Pure Specification]**

### 11.2 Working Directory

Each session MUST have an isolated working directory at
`{base_path}/{session_id}`. **[Pure Specification]**

**[Default Implementation]** Base path: `/var/agt/sessions`.

### 11.3 Path Access Rules

The `is_path_allowed()` check MUST enforce:

1. An agent's own session directory is always allowed.
2. Under `READ_COMMITTED`, explicitly granted sessions are allowed.
3. All other paths MUST be denied.

**[Pure Specification]**

### 11.4 Fail-Closed Access

If no isolation scope is configured for an agent, all access MUST be
denied (fail closed). Implementations MUST NOT default to permissive
access. **[Pure Specification]**

### 11.5 Cross-Session Access

Cross-session access grants MUST only work under `READ_COMMITTED`
isolation level. Granting access under `SNAPSHOT` or `SERIALIZABLE`
MUST be rejected. **[Pure Specification]**

---

## 12. Kill Switch

### 12.1 Purpose

The kill switch provides emergency agent termination with graceful
step handoff when possible. It is the last resort for stopping a
misbehaving agent.

### 12.2 Kill Reasons

| Reason | Description |
| --- | --- |
| `behavioral_drift` | Agent behavior diverged from expected patterns |
| `rate_limit` | Persistent rate limit violations |
| `ring_breach` | Attempted unauthorized ring access |
| `manual` | Operator-initiated kill |
| `quarantine_timeout` | Quarantine period exceeded |
| `session_timeout` | Session duration exceeded |

**[Pure Specification]**

### 12.3 Step Handoff

Before killing an agent, the kill switch SHOULD attempt to hand off
in-flight steps to a registered substitute agent:

1. Check if a substitute is registered for the session.
2. If a substitute exists, create `StepHandoff` records for each
   in-flight step.
3. Execute the handoff.
4. If handoff fails, mark steps for compensation.

**[Pure Specification]**

### 12.4 Kill Result

A KillResult MUST contain:

| Field | Type | Description |
| --- | --- | --- |
| `kill_id` | string | Unique kill identifier |
| `agent_did` | string | Killed agent's DID |
| `session_id` | string | Session context |
| `reason` | KillReason | Why the agent was killed |
| `timestamp` | datetime | Kill timestamp |
| `handoffs` | list | Step handoff records |
| `handoff_success_count` | int | Successful handoffs |
| `compensation_triggered` | bool | Whether compensation was needed |
| `terminated` | bool | Whether the agent was actually terminated |
| `details` | string | Additional context |

### 12.5 Callback Timeout

Agent termination callbacks MUST have a configurable timeout.
**[Pure Specification]**

**[Default Implementation]** Timeout: 5 seconds.

### 12.6 Failure Modes

| Failure | Behavior |
| --- | --- |
| No callback registered | `terminated = false`, warning logged |
| Callback timeout | `terminated = false`, timeout recorded |
| Callback exception | `terminated = false`, exception recorded |

All failure modes MUST result in `terminated = false` but MUST NOT
prevent the kill result from being recorded. **[Pure Specification]**

### 12.7 Cleanup

After a kill (success or failure), the agent and any registered
substitute MUST be unregistered from the kill switch.
**[Pure Specification]**

---

## 13. Quarantine

### 13.1 Quarantine Reasons

| Reason | Description |
| --- | --- |
| `behavioral_drift` | Detected behavioral regime change |
| `liability_violation` | Exceeded liability bounds |
| `ring_breach` | Unauthorized ring access attempt |
| `rate_limit_exceeded` | Persistent rate limit violations |
| `manual` | Operator-initiated quarantine |
| `cascade_slash` | Trust cascade from connected agent failure |

**[Pure Specification]**

### 13.2 Quarantine Duration

**[Default Implementation]** Default quarantine: 300 seconds
(5 minutes).

### 13.3 Quarantine Record

A quarantine record MUST contain:

| Field | Type | Description |
| --- | --- | --- |
| `agent_did` | string | Quarantined agent's DID |
| `session_id` | string | Session context |
| `reason` | QuarantineReason | Quarantine trigger |
| `started_at` | datetime | Quarantine start time |
| `expires_at` | datetime | Quarantine expiry |
| `is_active` | bool | Whether actively quarantined |

### 13.4 Operations

Implementations MUST provide:

- `quarantine(agent_did, session_id, reason, duration)`: Add agent
  to quarantine.
- `release(agent_did, session_id)`: Remove from quarantine.
- `is_quarantined(agent_did, session_id)`: Check status.
- `tick()`: Process expirations.

**[Pure Specification]**

> **Note:** The reference implementation provides quarantine data
> structures but does not enforce quarantine restrictions at runtime.
> This is documented as a known gap for future versions.

---

## 14. Audit and Hash Chain Integrity

### 14.1 Semantic Delta

Each auditable operation MUST be recorded as a SemanticDelta with:

| Field | Type | Description |
| --- | --- | --- |
| `delta_id` | string | Unique delta identifier |
| `session_id` | string | Session context |
| `agent_did` | string | Acting agent |
| `action` | string | Action performed |
| `timestamp` | datetime | Operation time |
| `previous_hash` | string | Hash of preceding delta |
| `delta_hash` | string | SHA-256 hash of this delta |

### 14.2 Hash Chain

Deltas MUST form an append-only hash chain where each delta's
`previous_hash` equals the preceding delta's `delta_hash`.
**[Pure Specification]**

### 14.3 Hash Computation

The delta hash MUST be computed as:

```
SHA-256(delta_id + session_id + agent_did + action + timestamp + previous_hash)
```

**[Pure Specification]**

### 14.4 Chain Verification

The `verify_chain()` method MUST:

1. Iterate through all deltas in order.
2. Verify each delta's hash matches its computed hash.
3. Verify each delta's `previous_hash` matches the preceding
   delta's `delta_hash`.
4. Return `true` only if all verifications pass.

**[Pure Specification]**

### 14.5 Tamper Detection

If any hash in the chain fails verification, the entire chain MUST
be considered compromised. Implementations MUST NOT attempt to
recover or skip invalid entries. **[Pure Specification]**

### 14.6 Commitment

Session root hashes MAY be committed to an external commitment store
for non-repudiation.

### 14.7 Retention

**[Default Implementation]** Retention defaults:

| Data | Retention |
| --- | --- |
| Deltas | 180 days |
| Hashes | Permanent |
| Liability snapshots | Retained |

---

## 15. Saga Orchestration

### 15.1 Purpose

Sagas provide multi-step distributed transaction support with
automatic compensation (undo) when steps fail.

### 15.2 Saga Defaults

| Parameter | Default | Description |
| --- | --- | --- |
| `max_retries` | 2 | Maximum retries per step |
| `retry_delay_seconds` | 1.0 | Base delay between retries (linear backoff) |
| `step_timeout_seconds` | 300 | Maximum duration for a single step |

**[Default Implementation]**

### 15.3 Compensation

When a step fails after exhausting retries, the saga orchestrator
MUST execute compensation (undo) for all previously completed steps
in reverse order. **[Pure Specification]**

---

## 16. Risk Weight Model

### 16.1 Reversibility Levels

| Level | Risk Weight Range | Default Weight |
| --- | --- | --- |
| `FULL` | [0.1, 0.3] | 0.2 |
| `PARTIAL` | [0.5, 0.8] | 0.65 |
| `NONE` | [0.9, 1.0] | 0.95 |

**[Default Implementation]**

### 16.2 Risk Weight Computation

The default risk weight for an action MUST be the midpoint of its
reversibility level's range:

```
default_weight = (range_low + range_high) / 2
```

**[Pure Specification]**

---

## 17. Configuration Validation

### 17.1 Identifier Validation

All agent identifiers, action IDs, and session IDs MUST be validated
against the pattern `^[a-zA-Z0-9]([a-zA-Z0-9._:-]*[a-zA-Z0-9])?$`
with a maximum length of 256 characters. **[Pure Specification]**

### 17.2 API Path Validation

API paths MUST be non-empty strings with a maximum length of 2048
characters. **[Pure Specification]**

### 17.3 Session Config Validation

Implementations MUST validate:

1. `max_participants` is an integer in [1, 1000].
2. `max_duration_seconds` is an integer in [1, 604800].
3. `min_eff_score` is a float in [0.0, 1.0].
4. Type mismatches MUST raise `TypeError`.
5. Range violations MUST raise `ValueError`.

**[Pure Specification]**

### 17.4 Participant Validation

Implementations MUST validate:

1. `sigma_raw` is a float in [0.0, 1.0].
2. `eff_score` is a float in [0.0, 1.0].
3. `ring` is a valid ExecutionRing (0-3).

**[Pure Specification]**

---

## 18. Provider Extensibility

### 18.1 Plugin Architecture

Implementations SHOULD support pluggable providers for:

| Provider | Fallback |
| --- | --- |
| `ring_engine` | `RingEnforcer` |
| `liability` | `LiabilityMatrix` |
| `saga_engine` | `SagaOrchestrator` |
| `breach_detector` | `RingBreachDetector` |
| `session_manager` | (implementation-specific) |
| `audit_engine` | (implementation-specific) |

### 18.2 Discovery

Providers SHOULD be discovered via entry points. When no provider
is registered, the built-in fallback MUST be used.
**[Default Implementation]**

---

## 19. Failure Semantics

### 19.1 Fail Closed

All enforcement operations MUST fail closed:

| Operation | Failure Behavior |
| --- | --- |
| Ring check | Deny access |
| Resource check | Deny access |
| Rate limit check | Raise `RateLimitExceeded` |
| Elevation request | Return denial with reason |
| Session isolation check | Deny access |
| Kill switch callback failure | `terminated = false`, operation recorded |
| Audit chain verification | Report chain as compromised |

### 19.2 Error Types

Implementations MUST define the following error types:

| Error | Context |
| --- | --- |
| `RateLimitExceeded` | Token bucket exhausted |
| `RingElevationError` | Elevation request denied |

---

## 20. Security Considerations

### 20.1 Ring 0 Access

Ring 0 MUST never be accessible to agents through the standard API.
Ring 0 operations require explicit SRE Witness attestation through
an out-of-band mechanism. This prevents any compromised agent from
escalating to hypervisor-level privileges.

### 20.2 Elevation Time Bounds

Elevations MUST be time-bounded to prevent permanent privilege
escalation. The `tick()` function MUST be called periodically to
expire stale elevations.

### 20.3 Rate Limit DoS Protection

Bucket count limits prevent memory exhaustion from spawning many
agent identifiers. The maximum bucket count MUST be enforced.

### 20.4 Hash Chain Integrity

The audit hash chain provides tamper evidence. If any entry is
modified, all subsequent hashes will fail verification. This
enables detection of unauthorized modifications to the audit trail.

### 20.5 Session Path Traversal

Session isolation MUST prevent path traversal attacks. Path checks
MUST resolve to canonical paths before comparison.

### 20.6 CORS Security

If the hypervisor exposes an HTTP API, wildcard CORS origins (`*`)
MUST be rejected when credentials are enabled.

---

## 21. Conformance Requirements

### 21.1 MUST Requirements

An implementation is conformant if it satisfies all MUST requirements:

1. Exactly four execution rings (0-3) with correct ordering.
2. Ring 0 denied to agents via standard enforcement.
3. Score-based ring assignment follows threshold rules.
4. Action required-ring derivation matches the classification rules.
5. Ring enforcement fails closed on all checks.
6. Resource constraints enforce the ring-to-constraint mapping.
7. Privilege elevation is time-bounded and trust-gated.
8. Ring 0 elevation is forbidden via the standard API.
9. Rate limiting uses token bucket with per-ring limits.
10. Session configurations are validated against constraints.
11. Session isolation is fail-closed.
12. Kill switch records results even on callback failure.
13. Audit hash chain is append-only with SHA-256 linking.
14. Identifiers are validated against the allowed pattern.

### 21.2 Test Coverage

Conformance tests MUST cover:

- Ring assignment from trust scores.
- Action classification to required rings.
- Ring enforcement (allow/deny decisions).
- Resource constraint enforcement per ring.
- Elevation request approval and denial.
- Rate limiter token consumption and exhaustion.
- Session configuration validation.
- Session isolation path checks.
- Kill switch operation and failure modes.
- Audit hash chain construction and verification.
- Identifier and configuration validation.

---

## 22. Worked Examples

### 22.1 Ring Assignment

```
Given: eff_score = 0.97, has_consensus = true
When:  ExecutionRing.from_eff_score(0.97, true)
Then:  Ring 1 (Privileged)

Given: eff_score = 0.80, has_consensus = false
When:  ExecutionRing.from_eff_score(0.80, false)
Then:  Ring 2 (Standard)  (>0.60 but no consensus for Ring 1)

Given: eff_score = 0.40, has_consensus = false
When:  ExecutionRing.from_eff_score(0.40, false)
Then:  Ring 3 (Sandbox)
```

### 22.2 Action Classification

```
Given: action with is_admin=true
Then:  required_ring = Ring 0

Given: action with reversibility=NONE, is_read_only=false
Then:  required_ring = Ring 1

Given: action with is_read_only=true
Then:  required_ring = Ring 3

Given: action with reversibility=FULL, is_read_only=false
Then:  required_ring = Ring 2
```

### 22.3 Elevation Denial

```
Given: agent at Ring 2, requests Ring 1, trust_score=0.60
When:  request_elevation(target=Ring 1, trust_score=0.60)
Then:  DENIED, reason="insufficient_trust"
       (Ring 1 requires >= 0.85)

Given: agent at Ring 2, requests Ring 0
When:  request_elevation(target=Ring 0)
Then:  DENIED, reason="ring_0_forbidden"
```

### 22.4 Rate Limit Exhaustion

```
Given: agent at Ring 3 (5.0 req/s, burst 10.0)
When:  11 requests in rapid succession
Then:  First 10 succeed (burst capacity)
       11th raises RateLimitExceeded
```

---

## 23. References

- [RFC 2119: Key words for use in RFCs](https://datatracker.ietf.org/doc/html/rfc2119)
- [RFC 8174: Ambiguity of Uppercase vs Lowercase in RFC 2119](https://datatracker.ietf.org/doc/html/rfc8174)
- [Agent OS Policy Engine Specification v1.0](./AGENT-OS-POLICY-ENGINE-1.0.md)
- [AgentMesh Identity and Trust Specification v1.0](./AGENTMESH-IDENTITY-TRUST-1.0.md)
