# ADR 0005: Add liveness attestation to TrustHandshake

- Status: proposed
- Date: 2026-04-12

## Context

The current TrustHandshake (`TrustBridge.verify_peer`) validates identity and computes a trust score at connection time, but has no mechanism to detect whether a previously verified agent is still alive and responsive. This creates two gaps:

1. **Ghost agents.** An agent that passed verification an hour ago may have crashed, lost its credential, or been decommissioned. The cached `HandshakeResult` still shows `verified: true` with a high trust score, so callers continue routing work to a dead peer. Because the trust score never drops below threshold, the agent remains cryptographically valid and authorized but operationally dead — a ghost agent whose authority persists silently.

2. **Ungraceful handoff.** When an agent restarts (crash, deployment, scaling event), its in-flight delegation context — scoped capabilities, active task state, ephemeral credentials — is lost. The current protocol has no way for the restarted agent to signal "I'm back" and for peers to re-evaluate trust without a full handshake re-execution.

Both gaps become acute in multi-agent orchestration where agents delegate chains of work. A stale or silently restarted agent in the middle of a delegation chain can cause silent failures that propagate before any peer notices.

ADR 0003 sets a 200ms SLA for the trust handshake. Liveness checks must stay well below this budget — they are not full handshakes, they are lightweight probes that compose with the existing trust model.

## Decision

Add a liveness attestation layer to TrustHandshake as an opt-in extension. The design decomposes agent trust into three independent properties, each with its own lifecycle, and models liveness as a gate rather than a score modifier.

### Three-property decomposition

Agent trust is decomposed into three independent properties with distinct timelines:

| Property | What it proves | Decay timeline | Recovery path |
|----------|---------------|----------------|---------------|
| **Identity** | Who the agent is (DID + Ed25519 keypair) | Extremely slow — rotation only on key compromise | Re-registration with new keypair |
| **Authority** | What the agent is allowed to do (delegation scope, capabilities) | Medium — delegation expiration, explicit revocation | Principal re-delegation |
| **Liveness** | Whether the agent is operationally alive right now | Rapid — minutes to hours, configurable per context | Heartbeat resumption |

These three properties are evaluated independently. A valid agent must satisfy all three: `identity_valid AND authority_valid AND liveness_active`.

### Liveness as a gate, not a score modifier

Liveness is modeled as an independent boolean gate rather than a delta on trust_score. The enforcement rule is:

```
can_exercise_authority = identity_valid AND authority_valid AND liveness_active
```

This eliminates the ghost-agent gap. A high-reputation agent (trust_score: 900) that crashes cannot exercise authority during downtime regardless of its score — liveness is a hard gate, not a soft penalty. Score-based approaches permit ghost agents when the base score is high enough to absorb the liveness penalty; gate-based approaches do not.

### Heartbeat protocol

An agent that wants to be considered "live" registers a heartbeat with its local TrustBridge, specifying a TTL (default: 300 seconds). The agent refreshes the heartbeat at `TTL / 2` intervals. The TrustBridge tracks the last heartbeat timestamp per DID.

The heartbeat payload includes:
- Agent DID
- Timestamp
- **Delegation chain hash** — binds liveness proof to authority proof in the same message, so validators do not need a second round-trip to check whether the alive agent still holds the scope it claims

```python
# Agent registers liveness
await bridge.register_liveness(ttl_seconds=300)

# TrustBridge exposes liveness status
status = bridge.get_liveness(peer_did="did:mesh:agent-b")
# Returns: LivenessStatus(is_alive=True, last_seen=..., ttl_remaining=142,
#                          delegation_chain_hash="sha256:abc...")
```

This follows the SIP REGISTER pattern — lightweight, stateless, and compatible with the 200ms handshake SLA since heartbeats are asynchronous background signals, not in the critical path.

### Suspension semantics

Missed heartbeats trigger **authority suspension** (reversible), not **revocation** (irreversible):

- **Active** (heartbeat within TTL): Agent can exercise full delegated authority.
- **Suspended** (heartbeat missed, within 2× TTL): Authority is frozen. The agent cannot exercise delegated authority, but the delegation itself is not revoked. The TrustBridge emits an `agent.liveness.suspended` event.
- **Expired** (beyond 2× TTL): Agent is marked `unreachable`. The TrustBridge emits an `agent.liveness.expired` event. Delegation remains intact but dormant.

On heartbeat resumption:
- Suspended → Active: Immediate. Authority restored, no re-delegation needed.
- Expired → Active: Requires delegation chain hash verification. If the delegation is still valid (not expired, not revoked), authority is restored. If the delegation expired during downtime, the agent must obtain a new delegation from its principal.

This allows rapid recovery from transient failures (restarts, network partitions) without requiring principal re-delegation.

A background cleanup task removes expired liveness records periodically (default: every 60 seconds).

### Backward compatibility

Agents that do not emit heartbeats are treated as `liveness_unknown`. The enforcement behavior depends on context:

- **Enforcement-enabled contexts** (default for new delegations): `liveness_unknown` agents cannot exercise delegated authority. This prevents the ghost-agent gap from persisting in production.
- **Legacy mode** (opt-in per operator): `liveness_unknown` agents are permitted. Operators can explicitly opt out of liveness enforcement during migration.

This is stricter than "no penalty, no bonus" but provides a clear migration path. Operators upgrading existing deployments enable legacy mode, migrate agents to emit heartbeats, then disable legacy mode.

`HandshakeResult` gains an optional `liveness` field. Existing consumers that do not read this field see no behavioral change in legacy mode.

No changes to the IATP protocol wire format. Heartbeats are a local TrustBridge concern, not a cross-agent protocol message.

## Consequences

**Benefits:**
- Ghost agents are eliminated by the gate model — no amount of base trust score can compensate for a failed liveness check.
- The three-property decomposition gives operators independent knobs for identity, authority, and liveness, each with appropriate timelines.
- Suspension semantics allow rapid recovery from transient failures without principal involvement.
- Delegation chain hash in heartbeat payload eliminates a round-trip for authority freshness verification.
- The RewardEngine gets new signals (`heartbeat_missed`, `heartbeat_resumed`, `authority_suspended`) for behavioral scoring.

**Tradeoffs:**
- Stricter backward compatibility (enforcement-enabled by default) requires operators to actively opt out for legacy agents. This is intentional — the ghost-agent gap is a security issue, not a convenience issue.
- Adds background state (last heartbeat timestamp + delegation chain hash per DID) to TrustBridge. For deployments with thousands of agents, this needs a storage backend beyond in-memory.
- Agents behind NAT or firewalls that cannot send outbound heartbeats will show as `liveness_unknown` and cannot exercise delegated authority in enforcement-enabled contexts. Operators must use legacy mode or establish a heartbeat relay for these agents.

**Follow-up work:**
- Integration with the Orphan Detection module: agents that are both `unreachable` (liveness) and `unowned` (no sponsor) should be flagged for decommissioning.
- Cross-bridge liveness propagation: in federated deployments, a TrustBridge should be able to query another bridge's liveness records for remote agents.

**Reference implementations:**
- [AgentNexus ADR-012 §3](https://github.com/kevinkaylie/AgentNexus/blob/main/docs/adr/012-push-gateway-and-mcp-collaboration.md) — SIP REGISTER-style TTL registration with `expires/2` refresh, production-tested with 330+ test cases.
- [AgentNexus ADR-014 §3](https://github.com/kevinkaylie/AgentNexus/blob/main/docs/adr/014-governance-trust-network.md) — Three-dimensional trust scoring (base_score + behavior_delta + attestation_bonus) with independent decay timelines.
- APS session-heartbeat machinery — reference implementation of the liveness property with delegation binding.
