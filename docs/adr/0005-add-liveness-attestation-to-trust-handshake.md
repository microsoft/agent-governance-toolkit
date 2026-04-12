# ADR 0005: Add liveness attestation to TrustHandshake

- Status: proposed
- Date: 2026-04-12

## Context

The current TrustHandshake (`TrustBridge.verify_peer`) validates identity and computes a trust score at connection time, but has no mechanism to detect whether a previously verified agent is still alive and responsive. This creates two gaps:

1. **Stale trust scores.** An agent that passed verification an hour ago may have crashed, lost its credential, or been decommissioned. The cached `HandshakeResult` still shows `verified: true` with a high trust score, so callers continue routing work to a dead peer. The RewardEngine cannot penalize an agent it doesn't know is gone.

2. **Ungraceful handoff.** When an agent restarts (crash, deployment, scaling event), its in-flight delegation context — scoped capabilities, active task state, ephemeral credentials — is lost. The current protocol has no way for the restarted agent to signal "I'm back" and for peers to re-evaluate trust without a full handshake re-execution.

Both gaps become acute in multi-agent orchestration where agents delegate chains of work. A stale or silently restarted agent in the middle of a delegation chain can cause silent failures that propagate before any peer notices.

ADR 0003 sets a 200ms SLA for the trust handshake. Liveness checks must stay well below this budget — they are not full handshakes, they are lightweight probes that feed into the existing trust score.

## Decision

Add a liveness attestation layer to TrustHandshake as an opt-in extension. The design has four components:

**1. Heartbeat protocol.** An agent that wants to be considered "live" registers a heartbeat with its local TrustBridge, specifying a TTL (default: 300 seconds). The agent refreshes the heartbeat at `TTL / 2` intervals. The TrustBridge tracks the last heartbeat timestamp per DID. This follows the SIP REGISTER pattern — lightweight, stateless, and compatible with the 200ms handshake SLA since heartbeats are asynchronous background signals, not in the critical path.

```python
# Agent registers liveness
await bridge.register_liveness(ttl_seconds=300)

# TrustBridge exposes liveness status
status = bridge.get_liveness(peer_did="did:mesh:agent-b")
# Returns: LivenessStatus(is_alive=True, last_seen=..., ttl_remaining=142)
```

**2. Composition with HandshakeResult.** Liveness becomes a `liveness_delta` component in the trust score, not a replacement for any existing signal. The formula:

```
effective_trust_score = handshake_trust_score + liveness_delta
```

Where `liveness_delta` is:
- `+50` if the agent has a valid, non-expired heartbeat (alive and responsive)
- `0` if the agent has never registered a heartbeat (liveness unknown — no penalty)
- `-100` after soft expiry (1× TTL elapsed since last heartbeat)
- `-200` after hard expiry (2× TTL elapsed — agent marked unreachable)

The delta values are configurable per deployment. The key invariant is that agents that never opt into liveness see no change to their trust score — backward compatibility is preserved by treating "no heartbeat" as "liveness unknown" rather than "dead."

**3. Decay model.** Two-phase decay after a missed heartbeat:

- **Soft decay** (1× TTL to 2× TTL): `liveness_delta` decreases linearly from 0 to -200. The agent is still routable but peers see a declining trust score. The RewardEngine records a `heartbeat_missed` event.
- **Hard expiry** (beyond 2× TTL): Agent is marked `unreachable`. `verify_peer` calls return `verified: false` unless the caller explicitly opts into `allow_stale=True`. The TrustBridge emits an `agent.liveness.expired` event for observability.

A background cleanup task removes expired liveness records periodically (default: every 60 seconds).

**4. Restart recovery.** When a restarted agent sends its first heartbeat, the TrustBridge:
- Clears the `unreachable` flag
- Resets `liveness_delta` to `+50`
- Does NOT require a full handshake re-execution — the existing `HandshakeResult` (identity + capabilities) remains valid if the credential has not expired

If the agent's ephemeral credential has also expired during the downtime (15-minute TTL per current design), a full handshake is required. This composes naturally: liveness recovery is fast (single heartbeat), credential recovery follows the existing rotation flow.

## Consequences

**Benefits:**
- Stale agents are detected within 2× TTL (default: 10 minutes) without any change to the handshake critical path.
- The RewardEngine gets a new signal (`heartbeat_missed`, `heartbeat_resumed`) for behavioral scoring.
- Delegation chains can check liveness before forwarding work, reducing silent failures.
- The opt-in design means zero impact on existing agents and deployments.

**Tradeoffs:**
- Adds background state (last heartbeat timestamp per DID) to TrustBridge. For deployments with thousands of agents, this needs a storage backend beyond in-memory (Redis or the existing agent registry).
- The `liveness_delta` values (+50 / -100 / -200) are initial proposals based on production experience with SIP REGISTER-style systems. They may need tuning after real-world deployment data.
- Agents behind NAT or firewalls that cannot send outbound heartbeats will show as "liveness unknown" permanently. This is acceptable (no penalty) but limits the value of liveness attestation in those environments.

**Backward compatibility:**
- `HandshakeResult` gains an optional `liveness` field. Existing consumers that don't read this field see no change.
- `verify_peer` behavior is unchanged for agents without heartbeats. Only agents that have registered AND subsequently expired see a trust score reduction.
- No changes to the IATP protocol wire format. Heartbeats are a local TrustBridge concern, not a cross-agent protocol message.

**Follow-up work:**
- Integration with the Orphan Detection module: agents that are both `unreachable` (liveness) and `unowned` (no sponsor) should be flagged for decommissioning.
- Cross-bridge liveness propagation: in federated deployments, a TrustBridge should be able to query another bridge's liveness records for remote agents.

**Reference implementations:**
- [AgentNexus ADR-012 §3](https://github.com/kevinkaylie/AgentNexus/blob/main/docs/adr/012-push-gateway-and-mcp-collaboration.md) — SIP REGISTER-style TTL registration with `expires/2` refresh, production-tested with 330+ test cases.
- [AgentNexus ADR-014 §3](https://github.com/kevinkaylie/AgentNexus/blob/main/docs/adr/014-governance-trust-network.md) — Reputation system with `behavior_delta` component, including interaction frequency as a liveness proxy.
