# Multi-Agent Customer Service System

This example demonstrates a governed multi-agent customer service system using AgentMesh for identity, delegation, trust handshakes, and collaborative scoring.

## Architecture

```
                         ┌─────────────────────────────────┐
                         │   Supervisor Agent              │
                         │   (Ticket Router)               │
                         │   Trust Score: 950/1000         │
                         └────────┬────────────────────────┘
                                  │ A2A Trust Handshake
                    ┌─────────────┼─────────────┐
                    │             │             │
         ┌──────────▼──────┐ ┌───▼────────┐ ┌─▼──────────────┐
         │ Technical Agent │ │ Billing    │ │ Escalation     │
         │ (Sub-agent)     │ │ Agent      │ │ Agent          │
         │ Score: 870/1000 │ │ Score: 920 │ │ Score: 880     │
         └─────────────────┘ └────────────┘ └────────────────┘
              │                    │                │
         Narrowed            Narrowed          Narrowed
         Capabilities       Capabilities      Capabilities
```

## What This Example Shows

1. **Delegation:** Supervisor delegates to specialist agents with narrowed capabilities
2. **A2A Trust Handshakes:** Agents verify each other's identity before communication
3. **Collaborative Trust Scoring:** Multi-agent interactions influence trust scores
4. **Capability Scoping:** Each sub-agent has precisely scoped permissions
5. **Cross-Agent Audit Trail:** All inter-agent communications are logged

## Use Case

A customer service system where:
- **Supervisor Agent** receives tickets and routes them
- **Technical Agent** handles technical support (scoped to read docs, create tickets)
- **Billing Agent** handles billing issues (scoped to read/write billing data)
- **Escalation Agent** handles complaints (scoped to notify managers)

## Key Features

### 1. Agent Delegation

```python
# Supervisor creates sub-agent with narrowed capabilities
technical_agent = supervisor.delegate(
    name="technical-support",
    capabilities=["read:docs", "write:tickets"],  # Subset of supervisor's caps
    ttl_minutes=15
)
```

### 2. Trust Handshake Before Communication

```python
# Before accepting work from supervisor
handshake_result = await technical_agent.verify_peer(
    peer_id=supervisor.did,
    required_trust_score=800
)

if not handshake_result.verified:
    raise SecurityError("Untrusted peer")
```

### 3. Collaborative Trust Scoring

Agents' scores are influenced by:
- Quality of responses
- SLA compliance
- Inter-agent cooperation
- Policy compliance

### 4. Audit Trail Across Agents

```json
{
  "timestamp": "2026-01-31T10:15:00Z",
  "from": "did:agentmesh:supervisor",
  "to": "did:agentmesh:technical-agent",
  "action": "ticket_delegation",
  "ticket_id": "T-12345",
  "status": "accepted"
}
```

## Running the Example

```bash
# Install dependencies
pip install -r requirements.txt

# Run the multi-agent system
python main.py
```

## What You'll See

1. Supervisor agent initializes with full capabilities
2. Three specialist agents are delegated with narrowed scopes
3. Incoming tickets are routed based on type
4. Trust handshakes occur before each delegation
5. Agents collaborate and update each other's trust scores
6. Audit trail shows complete inter-agent communication

## Security Features

| Feature | Implementation |
|---------|----------------|
| **Identity Hierarchy** | Supervisor → Sub-agents with delegation |
| **Narrow Delegation** | Sub-agents can only do subset of supervisor's actions |
| **Trust Handshakes** | <200ms IATP handshakes before communication |
| **Capability Isolation** | Technical agent can't access billing data |
| **Cross-Agent Audit** | Audit logs across all agents |
| **Trust Decay** | Poor collaboration lowers trust scores |

## Monitoring

```bash
# View supervisor status
agentmesh status supervisor/

# View technical agent status  
agentmesh status technical-agent/

# View cross-agent audit trail
agentmesh audit --agent did:agentmesh:supervisor --limit 100
```

## Extending This Example

### Add a New Specialist Agent

1. Create delegation in `main.py`
2. Define narrowed capabilities
3. Implement agent logic
4. Add policies in `policies/`

### Integrate with Real Ticket System

Replace simulated ticket queue with:
- Zendesk API
- Jira Service Desk
- Intercom
- Custom ticketing system

## Production Considerations

- **Scale:** Each agent can run in separate containers
- **State Management:** Use Redis or database for ticket state
- **Monitoring:** Integrate with Prometheus/Grafana
- **Alerting:** Set up alerts for trust score drops
- **Compliance:** Enable SOC 2 reporting in config

## Learn More

- [A2A Protocol Specification](https://agent-to-agent.github.io/)
- [AgentMesh Delegation](../../docs/delegation.md)
- [Trust Handshakes](../../docs/trust-handshakes.md)

---

**Production Status:** Ready for pilot deployments with proper monitoring and secret management.
