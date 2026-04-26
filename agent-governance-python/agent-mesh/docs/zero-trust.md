# Zero-Trust Architecture in AgentMesh

AgentMesh implements zero-trust principles for agent-to-agent communication. This document explains how zero-trust works in the context of AI agents.

## What is Zero-Trust?

Zero-trust assumes that **no agent, message, or connection should be implicitly trusted**, regardless of whether it originates from inside or outside the network boundary. Every interaction must be verified.

Traditional security: "Trust but verify"  
Zero-trust security: "**Never trust, always verify**"

## Zero-Trust Principles in AgentMesh

### 1. Verify Explicitly

Every agent must present verifiable credentials for every request.

```python
# Every message includes cryptographic proof of identity
message = Message(
    from_agent="did:agentmesh:alice",
    to_agent="did:agentmesh:bob",
    payload={"request": "read_data"},
    signature=sign(payload, alice_private_key),
    timestamp=datetime.utcnow(),
)

# Recipient verifies before processing
if not verify_signature(message.signature, message.from_agent):
    raise TrustViolation("Invalid signature")
```

### 2. Use Least-Privilege Access

Agents only have permissions required for their specific task.

```yaml
# Policy: Agent can only access specific resources
agent: did:agentmesh:data-reader
permissions:
  - resource: /data/reports
    actions: [read]
    # Cannot write, cannot access other paths
```

### 3. Assume Breach

Design as if attackers are already inside. Limit blast radius.

```
┌─────────────────────────────────────────────────────────────┐
│                     AGENTMESH                               │
│                                                             │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐   │
│  │   Agent A   │────►│   Gateway   │────►│   Agent B   │   │
│  └─────────────┘     └─────────────┘     └─────────────┘   │
│        │                   │                   │            │
│        ▼                   ▼                   ▼            │
│   ┌─────────┐        ┌─────────┐        ┌─────────┐        │
│   │ Audit   │        │ Policy  │        │ Audit   │        │
│   │ Log     │        │ Check   │        │ Log     │        │
│   └─────────┘        └─────────┘        └─────────┘        │
│                                                             │
│  Every hop: Verify identity, check policy, log action      │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Details

### Decentralized Identity (DID)

Each agent has a unique, cryptographically verifiable identity:

```
did:agentmesh:production:finance-bot:v1.2.3
     ↑          ↑          ↑          ↑
  method    network    agent-name  version
```

DIDs are:
- **Self-sovereign**: Agents control their own identity
- **Verifiable**: Public keys are resolvable
- **Portable**: Work across organizations

### Mutual TLS (mTLS)

All agent-to-agent communication uses mutual TLS:

```
Agent A                  AgentMesh                  Agent B
   │                         │                         │
   │── Client Certificate ──►│                         │
   │◄── Server Certificate ──│                         │
   │                         │── Client Certificate ──►│
   │                         │◄── Server Certificate ──│
   │                         │                         │
   │◄─────── Encrypted Channel ──────────────────────►│
```

Both parties authenticate to each other. No anonymous connections.

### Trust Scoring

Every agent has a dynamic trust score based on behavior:

```python
class TrustScore:
    """Trust score calculated from agent behavior."""
    
    base_score: float = 0.5  # Start neutral
    
    # Factors that increase trust
    successful_interactions: int
    policy_compliance_rate: float
    uptime: timedelta
    
    # Factors that decrease trust
    policy_violations: int
    anomalous_behavior_count: int
    failed_authentications: int
    
    def calculate(self) -> float:
        """Calculate current trust score (0.0 - 1.0)."""
        score = self.base_score
        score += min(0.2, self.successful_interactions * 0.01)
        score += 0.2 * self.policy_compliance_rate
        score -= 0.1 * self.policy_violations
        score -= 0.05 * self.anomalous_behavior_count
        return max(0.0, min(1.0, score))
```

Trust scores affect:
- Whether requests are allowed
- Rate limits applied
- Required approval levels

### Micro-Segmentation

Agents are segmented by function and data sensitivity:

```
┌─────────────────────────────────────────────────────────┐
│                    PRODUCTION MESH                       │
│                                                          │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐ │
│  │   SEGMENT:   │   │   SEGMENT:   │   │   SEGMENT:   │ │
│  │   PUBLIC     │   │   INTERNAL   │   │   SENSITIVE  │ │
│  │              │   │              │   │              │ │
│  │  ┌───────┐   │   │  ┌───────┐   │   │  ┌───────┐   │ │
│  │  │Bot A  │   │   │  │Bot C  │   │   │  │Bot E  │   │ │
│  │  └───────┘   │   │  └───────┘   │   │  └───────┘   │ │
│  │  ┌───────┐   │   │  ┌───────┐   │   │  ┌───────┐   │ │
│  │  │Bot B  │   │   │  │Bot D  │   │   │  │Bot F  │   │ │
│  │  └───────┘   │   │  └───────┘   │   │  └───────┘   │ │
│  └──────────────┘   └──────────────┘   └──────────────┘ │
│         │                  │                  │          │
│         └──────────────────┼──────────────────┘          │
│                            │                             │
│              Policy-controlled cross-segment             │
│                       communication                      │
└─────────────────────────────────────────────────────────┘
```

Cross-segment communication requires explicit policy approval.

### Continuous Verification

Trust is not a one-time decision. AgentMesh continuously verifies:

1. **Session tokens** expire and must be refreshed
2. **Behavior monitoring** detects anomalies in real-time
3. **Policy re-evaluation** happens on every request
4. **Credential rotation** ensures compromised keys have limited impact

```python
# Example: Session-based verification
session = await mesh.create_session(agent_did, ttl=300)  # 5 min TTL

# Every 30 seconds, verify session is still valid
while session.is_active:
    if not await mesh.verify_session(session):
        raise SessionExpired()
    await asyncio.sleep(30)
```

## Comparison with Traditional Security

| Aspect | Traditional | Zero-Trust (AgentMesh) |
|--------|------------|------------------------|
| Trust boundary | Network perimeter | Every agent |
| Authentication | Login once | Every request |
| Authorization | Role-based | Attribute + context based |
| Monitoring | Perimeter logs | Full mesh observability |
| Breach response | Detect at boundary | Contain at point of failure |

## Getting Started

Enable zero-trust features in your AgentMesh configuration:

```yaml
# agentmesh.yaml
security:
  zero_trust:
    enabled: true
    
  identity:
    require_did: true
    did_method: "agentmesh"
    
  tls:
    mtls_required: true
    min_tls_version: "1.3"
    
  verification:
    continuous: true
    session_ttl_seconds: 300
    
  segmentation:
    enabled: true
    default_segment: "internal"
```

## See Also

- [Identity Management](identity.md) - DID creation and management
- [Trust Scoring Algorithm](trust-scoring.md) - How trust scores work
- [Policy Propagation](policy-propagation.md) - Mesh-wide policy enforcement
- [mTLS Configuration](mtls.md) - Setting up mutual TLS
