# Protocol Sequence Diagrams

This document contains Mermaid sequence diagrams for the core AgentMesh protocols.

---

## 1. Agent Registration

An agent generates its cryptographic identity, creates a DID, registers with the
credential authority, and receives scoped credentials.

```mermaid
sequenceDiagram
    participant Agent
    participant KeyGen as Ed25519 KeyGen
    participant DID as DID Generator
    participant CA as Credential Authority
    participant SPIFFE as SPIFFE Provider

    Agent->>KeyGen: generate key pair
    KeyGen-->>Agent: (private_key, public_key)

    Agent->>DID: derive DID from public key
    DID->>DID: sha256(public_key_bytes)[:32]
    DID-->>Agent: did:mesh:<hex>

    Agent->>CA: register(did, public_key, requested_capabilities)
    CA->>CA: verify key ownership (challenge-response)
    CA->>CA: issue scoped credential (TTL: 15 min)
    CA-->>Agent: credential + key_id (key-<sha256_first_16>)

    Agent->>SPIFFE: register SVID(did, public_key)
    SPIFFE->>SPIFFE: issue X.509 SVID (TTL: 1 hr)
    SPIFFE-->>Agent: SVID certificate

    loop Credential rotation (every < 10 min remaining)
        Agent->>CA: renew credential
        CA-->>Agent: new credential (zero-downtime)
    end
```

---

## 2. Trust Handshake

Two agents establish mutual trust through a 3-phase challenge–response protocol with
trust score computation.

```mermaid
sequenceDiagram
    participant A as Agent A
    participant B as Agent B
    participant TS as Trust Scorer

    Note over A,B: Phase 1 — Challenge
    A->>B: initiate handshake(A.did, A.public_key)
    B->>B: generate nonce (random, 30s expiry)
    B-->>A: challenge(nonce, B.did, B.public_key)

    Note over A,B: Phase 2 — Response
    A->>A: sign(nonce, A.private_key)
    A->>B: response(signature, A.did, A.capabilities)
    B->>B: verify Ed25519 signature against A.public_key

    Note over A,B: Phase 3 — Mutual Verification
    B->>B: sign(nonce, B.private_key)
    B-->>A: counter_response(signature, B.did, B.capabilities)
    A->>A: verify Ed25519 signature against B.public_key

    Note over A,B: Trust Score Computation
    A->>TS: compute_trust(B.did)
    TS->>TS: evaluate 5 dimensions
    TS-->>A: trust_score (0–1000)
    B->>TS: compute_trust(A.did)
    TS-->>B: trust_score (0–1000)

    alt Both scores ≥ 700
        Note over A,B: ✅ Trust established — full collaboration
    else Score ≥ 500
        Note over A,B: ⚠️ Standard trust — limited capabilities
    else Score < 300
        Note over A,B: ❌ Trust denied — connection rejected
    end
```

---

## 3. Scope Chain Verification

Agent A delegates to Agent B, who sub-delegates to Agent C. When Agent C presents its
chain to a verifier, the chain is walked back to the root sponsor.

```mermaid
sequenceDiagram
    participant Sponsor as Human Sponsor
    participant A as Agent A
    participant B as Agent B
    participant C as Agent C
    participant V as Verifier

    Note over Sponsor,A: Link 1 — Root delegation
    Sponsor->>A: delegate(capabilities: [read:*, write:data, delegate:*])
    Sponsor->>Sponsor: sign link with sponsor Ed25519 key
    Sponsor-->>A: DelegationLink(hash: H1, sig: S1)

    Note over A,B: Link 2 — Sub-delegation (narrowed)
    A->>B: delegate(capabilities: [read:data])
    A->>A: verify read:data ⊆ read:* (narrowing check)
    A->>A: sign link with Agent A Ed25519 key
    A-->>B: DelegationLink(prev_hash: H1, hash: H2, sig: S2)

    Note over B,C: Link 3 — Further sub-delegation
    B->>C: delegate(capabilities: [read:data])
    B->>B: verify read:data ⊆ read:data (narrowing check)
    B->>B: sign link with Agent B Ed25519 key
    B-->>C: DelegationLink(prev_hash: H2, hash: H3, sig: S3)

    Note over C,V: Chain verification
    C->>V: present full chain [Link1, Link2, Link3]

    V->>V: Check depth ≤ max (3)
    V->>V: Link 3: verify S3 with B.public_key
    V->>V: Link 3: verify prev_hash == H2
    V->>V: Link 3: verify capabilities ⊆ Link 2 capabilities
    V->>V: Link 2: verify S2 with A.public_key
    V->>V: Link 2: verify prev_hash == H1
    V->>V: Link 2: verify capabilities ⊆ Link 1 capabilities
    V->>V: Link 1: verify S1 with Sponsor.public_key
    V->>V: Link 1: verify root sponsor identity

    alt All checks pass
        V-->>C: ✅ Chain valid — capabilities: [read:data]
    else Any check fails
        V-->>C: ❌ Chain invalid — access denied
    end
```

---

## 4. Reward Distribution

After a task completes, the reward engine computes contributions, selects a distribution
strategy, distributes rewards, and updates trust scores.

```mermaid
sequenceDiagram
    participant Task as Task Orchestrator
    participant RE as Reward Engine
    participant RD as Reward Distributor
    participant TS as Trust Scorer
    participant TD as Trust Decay Engine

    Note over Task,RE: Task completion
    Task->>RE: task_completed(task_id, participants[])
    RE->>RE: collect signals per participant
    RE->>RE: compute contribution weights

    Note over RE,RD: Strategy selection
    RE->>RD: create RewardPool(total, participants)
    RD->>RD: select strategy (default: trust_weighted)

    alt Trust Weighted Strategy
        RD->>RD: weight = participant.trust_score / sum(all_trust_scores)
        RD->>RD: allocation = total × weight
    else Equal Split Strategy
        RD->>RD: allocation = total / num_participants
    else Hierarchical Strategy
        RD->>RD: allocation = base × (decay_factor ^ delegation_depth)
    else Contribution Weighted Strategy
        RD->>RD: allocation = total × (contribution_weight / sum(all_weights))
    end

    RD-->>RE: RewardAllocation[] (per agent)

    Note over RE,TS: Trust score updates
    loop For each participant
        RE->>TS: update_dimensions(agent_did, signals)
        TS->>TS: recalculate 5-dimension weighted score
        TS-->>RE: new_score (0–1000)

        alt new_score < 300
            RE->>RE: trigger credential revocation
        else new_score < 500
            RE->>RE: raise warning alert
        end
    end

    Note over TS,TD: Ongoing decay
    TD->>TD: apply −2 pts/hr for inactive agents
    TD->>TD: floor at 100 (prevent permanent lockout)
    TD->>TD: check KL divergence for regime shifts
    TD-->>TS: propagate decay to neighbor scores (factor: 0.3, depth: 2)
```

---

## See Also

- [Architecture Overview](../ARCHITECTURE.md)
- [Trust Scoring Algorithm](trust-scoring.md)
- [ADR-001: Ed25519 Keys](adr/001-ed25519-keys.md)
- [ADR-003: Scope Chain Design](adr/003-scope-chain-design.md)
