# IATP-001: Trust Handshake Protocol

**Status:** Draft  
**Author:** Inter-Agent Trust Protocol Team  
**Created:** 2026-01-23  
**Updated:** 2026-01-23

## Abstract

This document specifies the Trust Handshake Protocol for the Inter-Agent Trust Protocol (IATP). The handshake enables two agents (or their sidecars) to negotiate trust, capabilities, and operational guarantees before exchanging sensitive data or executing transactions.

## 1. Introduction

### 1.1 Motivation

Current LLM agents operate in a "zero-trust void" where:
- Agents cannot discover what other agents are capable of
- No mechanism exists to verify claims about reversibility, privacy, or SLAs
- Context is shared blindly, leading to potential data leaks
- Failed transactions leave systems in inconsistent states

The Trust Handshake Protocol solves these problems by establishing a contract between agents before any work begins.

### 1.2 Design Goals

1. **Zero Configuration** - Works out of the box with sensible defaults
2. **Progressive Trust** - Support various trust levels from untrusted to verified partners
3. **Human Override** - Users can override warnings but are informed of risks
4. **Audit Trail** - Every decision is logged for accountability
5. **Fail Safe** - Blocks truly dangerous operations (e.g., credit cards to untrusted agents)

## 2. Protocol Flow

### 2.1 The Three-Phase Handshake

```
┌─────────┐                                    ┌─────────┐
│ Agent A │                                    │ Agent B │
│ Sidecar │                                    │ Sidecar │
└────┬────┘                                    └────┬────┘
     │                                              │
     │ Phase 1: Capability Discovery                │
     │ GET /.well-known/agent-manifest              │
     ├─────────────────────────────────────────────>│
     │                                              │
     │ 200 OK + Capability Manifest                 │
     │<─────────────────────────────────────────────┤
     │                                              │
     │ Phase 2: Policy Validation                   │
     │ (Local check: Does manifest meet policy?)    │
     │                                              │
     │ Phase 3: Execution or Warning                │
     │ POST /proxy {task, data, trace_id}           │
     ├─────────────────────────────────────────────>│
     │                                              │
     │ Success/Warning/Blocked                      │
     │<─────────────────────────────────────────────┤
     │                                              │
```

### 2.2 Phase 1: Capability Discovery

Every IATP-compliant agent MUST expose a capability manifest at:

```
GET /.well-known/agent-manifest
```

**Response Format:**
```json
{
  "$schema": "http://inter-agent-trust.org/v1/schema",
  "identity": {
    "agent_id": "booking-agent-v2.1.0",
    "verification_key": "ed25519:abc123...",
    "owner": "Expedia Group",
    "contact": "security@expedia.com"
  },
  "trust_level": "verified_partner",
  "scopes": ["repo:read", "repo:write"],
  "capabilities": {
    "idempotency": true,
    "concurrency_limit": 10,
    "sla_latency_ms": 2000,
    "sla_availability": 0.999
  },
  "reversibility": {
    "level": "partial",
    "undo_window_seconds": 3600,
    "compensation_method": "refund_minus_fee",
    "compensation_sla_ms": 5000
  },
  "privacy": {
    "retention_policy": "ephemeral",
    "storage_location": "us-west-2",
    "human_in_loop": false,
    "training_consent": false,
    "encryption_at_rest": true,
    "encryption_in_transit": true
  },
  "protocol_version": "1.0"
}
```

### 2.3 Phase 2: Policy Validation

The requesting sidecar evaluates the manifest against local policies:

**Trust Score Calculation:**
- Base score = trust_level (verified_partner=10, trusted=7, standard=5, unknown=2, untrusted=0)
- +2 if reversibility != "none"
- +1 if retention_policy == "ephemeral"
- -1 if retention_policy == "permanent" or "forever"
- -2 if human_in_loop == true
- -1 if training_consent == true
- Min: 0, Max: 10

**Policy Decisions:**

| Condition | Action |
|-----------|--------|
| Trust score >= 7 | ✅ Allow |
| Trust score 3-6 | ⚠️ Warn (449 status, requires override) |
| Trust score < 3 | ⚠️ Warn (449 status, requires override) |
| Credit card + permanent retention | 🚫 Block (403 Forbidden) |
| SSN + non-ephemeral retention | 🚫 Block (403 Forbidden) |

### 2.4 Phase 3: Execution

**Allowed Request:**
```http
POST /proxy
Content-Type: application/json
X-Agent-Trace-ID: e4b5c6d7-8a9b-0c1d-2e3f-4a5b6c7d8e9f

{
  "task": "book_flight",
  "data": {
    "destination": "NYC",
    "date": "2026-02-15"
  }
}
```

**Response:**
```http
HTTP/1.1 200 OK
X-Agent-Trace-ID: e4b5c6d7-8a9b-0c1d-2e3f-4a5b6c7d8e9f
X-Agent-Trust-Score: 8
X-Agent-Latency-Ms: 1243.56

{
  "result": "Flight booked",
  "confirmation": "ABC123"
}
```

**Warning Response:**
```http
HTTP/1.1 449 Retry With

{
  "warning": "⚠️ WARNING:\n  • Low trust score (2/10)\n  • No reversibility support\n  • Data stored permanently",
  "requires_override": true,
  "trace_id": "..."
}
```

**User Override:**
```http
POST /proxy
X-User-Override: true
X-Agent-Trace-ID: e4b5c6d7-8a9b-0c1d-2e3f-4a5b6c7d8e9f

{...}
```

## 3. Capability Manifest Fields

### 3.1 Identity

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | string | Yes | Unique identifier (semver recommended) |
| `verification_key` | string | No | Public key for signature verification |
| `owner` | string | Yes | Organization or individual owner |
| `contact` | string | No | Security contact email |

### 3.2 Trust Level

| Value | Meaning |
|-------|---------|
| `verified_partner` | Cryptographically verified, legally contracted |
| `trusted` | Established reputation, no formal verification |
| `standard` | Default for unknown but legitimate agents |
| `unknown` | No prior interaction |
| `untrusted` | Known bad actor or policy violator |

### 3.3 RBAC Scopes (Role-Based Access Control)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scopes` | array[string] | No | List of permission scopes granted to the agent |

**Common Scope Values:**

| Scope | Meaning |
|-------|---------|
| `repo:read` | Read-only access to repositories (Reviewer Agent) |
| `repo:write` | Write access to repositories (Coder Agent) |
| `admin:manage` | Administrative management capabilities |
| `data:read` | Read access to data resources |
| `data:write` | Write access to data resources |

**Examples:**

- **Coder Agent**: `["repo:read", "repo:write"]` - Can read and modify code
- **Reviewer Agent**: `["repo:read"]` - Can only review code, no modifications
- **Admin Agent**: `["repo:read", "repo:write", "admin:manage"]` - Full access

**Usage in Handshake:**
When validating a handshake, the requesting agent can specify `required_scopes` to ensure the remote agent has the necessary permissions. If the remote agent lacks required scopes, the handshake will fail with an error message indicating the missing scopes.

### 3.4 Reversibility

| Field | Type | Description |
|-------|------|-------------|
| `level` | enum | `full`, `partial`, or `none` |
| `undo_window_seconds` | integer | Time window for undo (0 = no limit) |
| `compensation_method` | string | How undo works (e.g., "rollback", "refund") |
| `compensation_sla_ms` | integer | Max time to complete undo |

### 3.5 Privacy

| Field | Type | Description |
|-------|------|-------------|
| `retention_policy` | enum | `ephemeral`, `temporary`, `permanent`, `forever` |
| `storage_location` | string | AWS region, country code, or "on-premises" |
| `human_in_loop` | boolean | Whether humans review data |
| `training_consent` | boolean | Whether data is used for ML training |

## 4. Error Handling

### 4.1 Manifest Unavailable

If `GET /.well-known/agent-manifest` fails:
- Status: 503 Service Unavailable
- Action: Treat agent as `unknown` with trust_level=2

### 4.2 Invalid Manifest

If manifest is malformed or missing required fields:
- Status: 400 Bad Request
- Action: Block transaction, log error

### 4.3 Conflicting Policies

If local policy strictly forbids an operation:
- Status: 403 Forbidden
- Return: `{"error": "Policy violation: <reason>", "blocked": true}`

## 5. Security Considerations

### 5.1 Manifest Integrity

- Manifests SHOULD be signed with the `verification_key`
- Sidecars MAY cache manifests (recommended: 1 hour TTL)
- Manifest changes SHOULD trigger re-validation

### 5.2 Agent Attestation (Verifiable Credentials)

**NEW:** IATP supports cryptographic attestation to verify agents run unmodified code.

**Attestation Endpoint:**
```
GET /.well-known/agent-attestation
```

**Response Format:**
```json
{
  "agent_id": "booking-agent-v2.1.0",
  "codebase_hash": "sha256:a3f5b9c...",
  "config_hash": "sha256:d8e2a1b...",
  "signature": "base64_signature",
  "signing_key_id": "control-plane-prod-2026",
  "timestamp": "2026-01-25T10:00:00Z",
  "expires_at": "2026-01-26T10:00:00Z"
}
```

**Attestation Handshake Flow:**
1. Agent requests remote agent's manifest
2. Agent requests remote agent's attestation
3. Agent validates attestation signature using Control Plane's public key
4. Agent verifies codebase_hash matches expected value
5. Agent checks attestation hasn't expired
6. If valid, proceed with request; if invalid, reject

**Benefits:**
- Prevents running hacked/modified agent code
- No need for complex firewall rules between agents
- Security is in the protocol, not the infrastructure
- Control Plane acts as trusted signing authority

### 5.3 Sensitive Data Detection

Sidecars MUST detect:
- Credit card numbers (Luhn algorithm validation)
- SSNs (pattern: `\d{3}-\d{2}-\d{4}`)
- API keys, tokens (entropy-based detection)

### 5.4 Privacy Scrubbing

All logged data MUST be scrubbed:
- Credit cards → `[CREDIT_CARD_REDACTED]`
- SSNs → `[SSN_REDACTED]`

## 6. Implementation Guidance

### 6.1 Minimal Implementation

A minimal IATP sidecar must:
1. Expose `/.well-known/agent-manifest`
2. Validate incoming requests against manifest
3. Generate unique trace IDs
4. Log all transactions

### 6.2 Recommended Features

- Distributed tracing (OpenTelemetry compatible)
- User override mechanism (449 status + X-User-Override header)
- Flight recorder (append-only audit log)
- Quarantine tracking for risky transactions
- Agent attestation verification
- Reputation tracking and slashing

### 6.3 Reputation Slashing

**NEW:** IATP supports network-wide reputation tracking to penalize misbehavior.

**Reputation Endpoints:**

Get reputation for an agent:
```
GET /reputation/{agent_id}
```

Slash reputation (called by cmvk or other verification systems):
```
POST /reputation/{agent_id}/slash
{
  "reason": "hallucination",
  "severity": "high",
  "trace_id": "trace-123",
  "details": {"context": "additional info"}
}
```

Export reputation data:
```
GET /reputation/export
```

Import reputation data from other nodes:
```
POST /reputation/import
{
  "reputation_data": {...}
}
```

**Reputation Scoring:**
- Agents start at 5.0/10
- Hallucinations: -0.25 to -2.0 depending on severity
- Failures/timeouts: -0.5
- Successful operations: +0.1
- Score range: 0.0 to 10.0

**Trust Level Mapping:**
- 8.0-10.0 → VERIFIED_PARTNER
- 6.0-7.9 → TRUSTED
- 4.0-5.9 → STANDARD
- 2.0-3.9 → UNKNOWN
- 0.0-1.9 → UNTRUSTED

**Network Propagation:**
- Nodes export reputation data periodically
- Importing nodes use conservative merge (take lower score)
- Prevents reputation gaming across network

**Integration with cmvk:**
When cmvk (Context Memory Verification Kit) detects a hallucination, it calls:
```bash
POST http://sidecar:8001/reputation/{agent_id}/slash
```
This automatically reduces the agent's reputation across the network.

## 7. Future Extensions

- **IATP-003:** ✅ **Implemented:** Cryptographic attestation of agent code
- **IATP-004:** Rate limiting and quota management
- **IATP-005:** Multi-agent transaction coordination
- **IATP-006:** ✅ **Implemented:** Network-wide reputation tracking
- **IATP-007:** Federated trust networks with cross-organization verification

## 8. References

- JSON Schema specification: https://json-schema.org/
- OpenTelemetry: https://opentelemetry.io/
- Luhn algorithm: https://en.wikipedia.org/wiki/Luhn_algorithm
- Service Mesh patterns: https://www.envoyproxy.io/

## Appendix A: Example Scenarios

### A.1 High-Trust Scenario

**Agent:** Verified banking partner  
**Trust Score:** 10  
**Result:** Immediate execution, full audit trail

### A.2 Low-Trust with Override

**Agent:** Unknown booking service  
**Trust Score:** 3  
**Result:** Warning → User override → Quarantined execution

### A.3 Blocked Transaction

**Agent:** Untrusted + permanent retention  
**Data:** Contains credit card  
**Result:** 403 Forbidden, no execution

---

**Document Status:** This is a living document. Feedback welcome via GitHub issues.
