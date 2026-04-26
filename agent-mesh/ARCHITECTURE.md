# AgentMesh Architecture

> Trust-first communication layer for AI agents — cryptographic identity,
> multi-dimensional trust scoring, scope chains, and governance enforcement.

## 1. Overview

AgentMesh provides a **4-layer trust stack** that lets autonomous AI agents
discover, authenticate, and collaborate with each other while maintaining
cryptographic accountability and policy compliance at every hop.

```mermaid
graph TB
    subgraph AgentMesh
        L4[Layer 4 — Reward]
        L3[Layer 3 — Governance]
        L2[Layer 2 — Trust]
        L1[Layer 1 — Identity]
    end

    External["External Agents<br/>(A2A · MCP · IATP · ACP)"] -->|TrustBridge| L2
    L1 -->|DID + Ed25519| L2
    L2 -->|Trust Score| L3
    L3 -->|Policy Verdict| L4
    L4 -->|Reputation Signal| L2

    Storage[(Storage<br/>Redis · Postgres · Memory)] --- L1
    Storage --- L2
    Storage --- L3
    Storage --- L4
```

### Module Map

```text
src/agentmesh/
├── identity/        # Layer 1 — DID, credentials, delegation, SPIFFE
├── trust/           # Layer 2 — scoring, handshake, bridge, capability
├── governance/      # Layer 3 — policy, OPA, audit, compliance, shadow
├── reward/          # Layer 4 — engine, scoring, trust decay, anomaly
├── integrations/    # Protocol adapters (A2A, MCP, LangFlow, …)
├── storage/         # Pluggable backend (Redis, Postgres, memory)
├── services/        # Backend services
├── cli/             # CLI commands
├── core/            # Shared core types
└── observability/   # Metrics and tracing
```

---

## 2. 4-Layer Trust Stack

```mermaid
graph LR
    subgraph "Layer 1 — Identity"
        DID["DID<br/>did:mesh:hex"]
        Ed["Ed25519<br/>Key Pair"]
        SPIFFE["SPIFFE SVID<br/>X.509 / JWT"]
        AICard["AI Card<br/>Signed Discovery"]
    end

    subgraph "Layer 2 — Trust"
        TS["Trust Score<br/>0–1000"]
        HS["Handshake<br/>Challenge-Response"]
        TB["TrustBridge<br/>A2A · MCP · IATP · ACP"]
        Cap["Capability<br/>action:resource:qualifier"]
    end

    subgraph "Layer 3 — Governance"
        Pol["Policy Engine<br/>YAML/JSON + Rego"]
        OPA["OPA Integration"]
        Audit["Hash Chain Audit<br/>Chain"]
        Shadow["Shadow Mode"]
    end

    subgraph "Layer 4 — Reward"
        Rep["Reputation<br/>Engine"]
        Decay["Trust Decay<br/>Engine"]
        Anomaly["Anomaly<br/>Detection"]
    end

    DID --> HS
    Ed --> HS
    SPIFFE --> HS
    AICard --> TB
    HS --> TS
    TS --> Pol
    Pol --> OPA
    Pol --> Audit
    Shadow -.->|dry-run| Pol
    TS --> Rep
    Rep --> Decay
    Decay --> Anomaly
    Anomaly -->|feedback| TS
```

### Layer Details

| Layer | Responsibility | Key Modules |
|-------|---------------|-------------|
| **1 — Identity** | Ed25519 key pairs, DID generation (`did:mesh:<hex>`), SPIFFE mTLS, AI Card discovery, scope chains | `identity/` |
| **2 — Trust** | 5-dimension trust scoring (0–1000), 3-phase handshake (<200 ms), TrustBridge protocol unification, capability grants | `trust/` |
| **3 — Governance** | Declarative policy rules (<5 ms), OPA/Rego integration, hash chain audit trails, compliance mapping (EU AI Act, SOC 2, HIPAA, GDPR), shadow mode | `governance/` |
| **4 — Reward** | Reputation engine, weighted scoring, trust decay (2 pts/hr), anomaly detection (5 classes) | `reward/` |

---

## 3. Identity Lifecycle

```mermaid
sequenceDiagram
    participant Agent
    participant Identity as identity/agent_id
    participant Cred as identity/credentials
    participant SPIFFE as identity/spiffe
    participant Trust as trust/handshake
    participant Cap as trust/capability

    Agent->>Identity: generate DID<br/>SHA256(name:org:uuid) → did:mesh:hex
    Identity->>SPIFFE: register SVID<br/>(X.509, 1h TTL)
    Identity->>Cred: issue credential<br/>(scoped capabilities, 15 min TTL)
    Agent->>Trust: initiate handshake
    Trust->>Trust: Phase 1 — challenge (nonce, 30s expiry)
    Trust->>Trust: Phase 2 — peer signs nonce (Ed25519)
    Trust->>Trust: Phase 3 — verify signature + trust score
    Trust->>Cap: grant capabilities<br/>(action:resource:qualifier)

    loop Every < 10 min remaining
        Cred->>Cred: zero-downtime rotation
    end

    Note over Cred: Revocation propagation ≤ 5 s
    Agent->>Cred: revoke credential
    Cred-->>Trust: broadcast revocation
```

### Key Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| DID format | `did:mesh:<32-char-hex>` | `identity/agent_id.py` |
| Key algorithm | Ed25519 | `identity/agent_id.py` |
| Credential TTL | 15 min (configurable) | `identity/credentials.py` |
| SVID TTL | 1 h (rotate at <10 min) | `identity/spiffe.py` |
| Handshake expiry | 30 s nonce | `trust/handshake.py` |
| Handshake cache TTL | 15 min | `trust/handshake.py` |
| Revocation propagation | ≤ 5 s | `identity/credentials.py` |
| Sponsor max agents | 10 (default) | `identity/sponsor.py` |
| Max delegation depth | 3 (default) | `identity/sponsor.py` |

---

## 4. Trust Scoring Model

### 5 Dimensions

```mermaid
pie title Trust Score Weight Distribution
    "Policy Compliance" : 25
    "Security Posture" : 25
    "Output Quality" : 20
    "Resource Efficiency" : 15
    "Collaboration Health" : 15
```

| Dimension | Weight | Description |
|-----------|--------|-------------|
| Policy Compliance | 25 % | Adherence to governance rules |
| Security Posture | 25 % | Credential hygiene, vulnerability posture |
| Output Quality | 20 % | Task success rate, accuracy |
| Resource Efficiency | 15 % | Compute/token usage vs. budget |
| Collaboration Health | 15 % | Responsiveness, protocol compliance |

### Thresholds & Tiers

```mermaid
graph LR
    subgraph "Score Range 0–1000"
        U["Untrusted<br/>&lt; 300"]
        P["Probationary<br/>300–499"]
        S["Standard<br/>500–699"]
        T["Trusted<br/>700–899"]
        V["Verified Partner<br/>≥ 900"]
    end

    U -->|"revocation<br/>threshold"| P
    P -->|"warn<br/>threshold"| S
    S --> T
    T --> V

    style U fill:#ef4444,color:#fff
    style P fill:#f97316,color:#fff
    style S fill:#eab308,color:#000
    style T fill:#22c55e,color:#fff
    style V fill:#3b82f6,color:#fff
```

| Threshold | Score | Action |
|-----------|-------|--------|
| Revocation | < 300 | Credentials revoked, peer blacklisted |
| Warning | < 500 | Alert raised, capabilities restricted |
| Allow | ≥ 500 | Normal operation |
| Trusted bridge | ≥ 700 | TrustBridge default threshold |

### Trust Decay Model

```mermaid
graph TD
    A[Agent Active?] -->|No positive signals| B[Decay: −2 pts/hr]
    B --> C{Score > 100?}
    C -->|Yes| D[Apply decay]
    C -->|No| E[Floor at 100]
    D --> F{KL divergence > 0.5?}
    F -->|Yes| G[Regime shift detected]
    F -->|No| H[Continue monitoring]
    G --> I[Propagate to neighbors<br/>factor: 0.3, depth: 2 hops]
```

| Parameter | Value |
|-----------|-------|
| Decay rate | 2.0 pts / hour |
| Minimum floor | 100 |
| Propagation factor | 0.3 |
| Propagation depth | 2 hops |
| Regime threshold (KL divergence) | 0.5 |
| Recent window | 1 hour |
| Baseline window | 30 days |

### Anomaly Detection

```mermaid
graph TB
    Behavioral[Behavioral Monitor] --> RF[Rapid-fire<br/>&gt; 10 actions / 5 s<br/>HIGH]
    Behavioral --> AD[Action Drift<br/>New actions post-baseline<br/>MEDIUM]
    Behavioral --> FS[Frequency Spike<br/>&gt; 3σ above mean<br/>MEDIUM]
    Behavioral --> TD[Trust Degradation<br/>≥ 15 % drop<br/>HIGH]
    Behavioral --> TOD[Time-of-Day<br/>&lt; 1 % baseline activity<br/>LOW]

    RF --> Feedback[Feed back into<br/>Trust Score]
    AD --> Feedback
    FS --> Feedback
    TD --> Feedback
    TOD --> Feedback
```

---

## 5. Governance Engine Flow

```mermaid
flowchart LR
    Req[Agent Request] --> PE[Policy Engine<br/>governance/policy.py]
    PE --> YAML{YAML/JSON<br/>Rules}
    YAML -->|< 5 ms| Verdict1[allow / deny / warn<br/>require_approval / log]
    PE --> OPA[OPA/Rego<br/>governance/opa.py]
    OPA --> Verdict2[Rego Result]
    Verdict1 --> Merge[Merge Verdicts]
    Verdict2 --> Merge
    Merge --> Comp[Compliance Mapping<br/>governance/compliance.py]
    Comp --> Audit[Hash Chain Audit Chain<br/>governance/audit.py]
    Audit --> CE[CloudEvents v1.0<br/>Azure Event Grid<br/>AWS EventBridge<br/>Splunk]

    Shadow[Shadow Mode<br/>governance/shadow.py] -.->|dry-run<br/>&lt; 2 % divergence| PE
```

### Governance Submodules

| Submodule | File | Purpose |
|-----------|------|---------|
| **Policy** | `governance/policy.py` | Declarative YAML/JSON rules with rate limiting |
| **OPA** | `governance/opa.py` | Rego policy evaluation (Kubernetes-familiar) |
| **Compliance** | `governance/compliance.py` | Maps actions → EU AI Act, SOC 2, HIPAA, GDPR controls |
| **Audit** | `governance/audit.py` | hash chain tree audit chain, tamper-evident, CloudEvents export |
| **Persistent Audit** | `governance/persistent_audit.py` | Durable audit log storage |
| **Shadow** | `governance/shadow.py` | Test new policies in parallel; batch replay support |

### Policy Evaluation Order

```mermaid
sequenceDiagram
    participant Agent
    participant Policy as policy.py
    participant OPA as opa.py
    participant Audit as audit.py

    Agent->>Policy: evaluate(request)
    Policy->>Policy: match YAML/JSON rules<br/>(rate limit check)
    Policy->>OPA: forward to Rego<br/>(if configured)
    OPA-->>Policy: rego verdict
    Policy->>Policy: merge verdicts<br/>(most restrictive wins)
    Policy-->>Agent: allow | deny | warn
    Policy->>Audit: append to hash chain
```

---

## 6. Protocol Bridge Architecture

```mermaid
graph TB
    subgraph External Protocols
        A2A[A2A Protocol<br/>integrations/a2a/]
        MCP[MCP Protocol<br/>integrations/mcp/]
        IATP[IATP Protocol]
        ACP[ACP Protocol]
    end

    subgraph TrustBridge["TrustBridge (trust/bridge.py)"]
        VP[verify_peer]
        IPT[is_peer_trusted]
        RPT[revoke_peer_trust]
        GTP[get_trusted_peers]
    end

    subgraph "Framework Adapters"
        LF[LangFlow<br/>integrations/langflow/]
        LG[LangGraph<br/>integrations/langgraph/]
        SW[Swarm<br/>integrations/swarm/]
        FL[Flowise<br/>integrations/flowise/]
        HA[Haystack<br/>integrations/haystack/]
    end

    A2A --> VP
    MCP --> VP
    IATP --> VP
    ACP --> VP

    VP --> IPT
    IPT -->|"score ≥ 700"| GTP
    IPT -->|"score < 300"| RPT

    GTP --> LF
    GTP --> LG
    GTP --> SW
    GTP --> FL
    GTP --> HA
```

### Bridge Operations

| Operation | Method | Description |
|-----------|--------|-------------|
| Verify peer | `verify_peer()` | Core trust gate — validates identity + trust score before communication |
| Check trust | `is_peer_trusted()` | Quick boolean check against threshold (default 700) |
| Revoke trust | `revoke_peer_trust()` | Instant trust revocation, propagated across mesh |
| List trusted | `get_trusted_peers()` | Filter peers by minimum trust score |

### Integration Submodules

| Submodule | Path | Protocol |
|-----------|------|----------|
| A2A | `integrations/a2a/` | Google A2A agent-to-agent |
| MCP | `integrations/mcp/` | Anthropic Model Context Protocol |
| AI Card | `integrations/ai_card/` | Signed discovery cards |
| LangFlow | `integrations/langflow/` | LangFlow orchestration |
| LangGraph | `integrations/langgraph/` | LangGraph state machines |
| Swarm | `integrations/swarm/` | OpenAI Swarm integration |
| Flowise | `integrations/flowise/` | Flowise flow builder |
| Haystack | `integrations/haystack/` | deepset Haystack pipelines |

---

## 7. Storage Layer

```mermaid
graph TB
    subgraph Consumers
        ID[Identity Layer]
        TR[Trust Layer]
        GOV[Governance Layer]
        RW[Reward Layer]
    end

    subgraph "StorageProvider (storage/provider.py)"
        KV[Key-Value<br/>get / set / delete + TTL]
        Hash[Hash Ops<br/>structured data]
        List[List Ops<br/>audit logs, events]
        SSet[Sorted Sets<br/>trust score rankings]
        Atomic[Atomic<br/>incr / decr]
        Batch[Batch &amp; Pattern<br/>operations]
    end

    subgraph Backends
        Redis[(Redis<br/>storage/redis_provider.py)]
        PG[(PostgreSQL<br/>storage/postgres_provider.py)]
        Mem[(Memory<br/>storage/memory_provider.py)]
    end

    ID --> KV
    TR --> SSet
    GOV --> List
    RW --> Hash

    KV --> Redis
    KV --> PG
    KV --> Mem
    Hash --> Redis
    Hash --> PG
    Hash --> Mem
    List --> Redis
    List --> PG
    List --> Mem
    SSet --> Redis
    SSet --> PG
    SSet --> Mem
```

| Parameter | Default |
|-----------|---------|
| Connection timeout | 30 s |
| Pool size | 10 |

---

## 8. Cross-Repo Ecosystem

```mermaid
graph TB
    subgraph "agent-mesh"
        AM_ID[Identity Layer]
        AM_TR[Trust Layer]
        AM_GOV[Governance Layer]
        AM_RW[Reward Layer]
        AM_INT[Protocol Bridges]
    end

    subgraph "agent-os"
        AO_GK[Governance Kernel]
        AO_PE[Policy Engine]
        AO_RT[Runtime]
    end

    subgraph "agent-sre"
        AS_SLO[SLO Monitoring]
        AS_INC[Incident Management]
        AS_OBS[Observability]
    end

    AM_GOV -->|"policy sync"| AO_PE
    AM_GOV -->|"governance rules"| AO_GK
    AM_TR -->|"trust signals"| AO_RT

    AS_SLO -->|"SLO violations"| AM_TR
    AS_INC -->|"incident context"| AM_GOV
    AS_OBS -->|"metrics + traces"| AM_RW

    AM_INT -->|"agent discovery"| AO_RT
    AO_GK -->|"kernel policies"| AM_GOV
```

### Integration Points

| From | To | Data Flow |
|------|----|-----------|
| agent-mesh → agent-os | Governance → Policy Engine | Policy sync, governance rules |
| agent-mesh → agent-os | Trust → Runtime | Trust signals for agent scheduling |
| agent-mesh → agent-os | Integrations → Runtime | Agent discovery via AI Cards |
| agent-os → agent-mesh | Governance Kernel → Governance | Kernel-level policy constraints |
| agent-sre → agent-mesh | SLO Monitoring → Trust | SLO violations affect trust scores |
| agent-sre → agent-mesh | Incident Mgmt → Governance | Incident context for audit trails |
| agent-sre → agent-mesh | Observability → Reward | Metrics feed reputation engine |

---

*Related: [agent-os](https://github.com/microsoft/agent-governance-toolkit) · [agent-sre](https://github.com/microsoft/agent-governance-toolkit) · GitHub Issue: agent-os#263*
