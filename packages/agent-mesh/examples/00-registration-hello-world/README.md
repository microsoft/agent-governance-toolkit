# Hello World: Agent Registration

This is the canonical "Hello World" example for AgentMesh. It demonstrates:

1. **Agent Identity Generation**: Create cryptographic keys
2. **Human Sponsor**: Link agent to human accountability
3. **Registration Handshake**: Complete the registration with AgentMesh
4. **Credential Receipt**: Receive SVID certificate and initial trust score

## What This Example Does

This example simulates an agent registering with AgentMesh for the first time:

```
┌──────────────┐                          ┌───────────────────┐
│    Agent     │                          │   AgentMesh CA    │
│  (agent-os)  │                          │  (Identity Core)  │
└──────┬───────┘                          └─────────┬─────────┘
       │                                            │
       │  1. Generate Ed25519 keypair               │
       │  2. Request sponsor signature              │
       │                                            │
       │  3. RegistrationRequest                    │
       │     ─────────────────────────────────────> │
       │        • Public key                        │
       │        • Sponsor: alice@company.com        │
       │        • Capabilities: [read:data]         │
       │                                            │
       │                     4. Validate & Issue    │
       │                                            │
       │  5. RegistrationResponse                   │
       │     <───────────────────────────────────── │
       │        • DID: did:mesh:abc123...           │
       │        • SVID certificate (15-min TTL)     │
       │        • Trust score: 500                  │
       │        • Access token                      │
       │                                            │
       │  6. Agent is now trusted!                  │
       │                                            │
```

## Prerequisites

```bash
pip install -r requirements.txt
```

## Running the Example

### Option 1: Simulated Registration (No server required)

```bash
python simulated_registration.py
```

This runs a simulated registration flow without requiring a running AgentMesh server. It demonstrates the protocol and data structures.

### Option 2: Full Registration (Requires server)

```bash
# Terminal 1: Start AgentMesh server
agentmesh server --dev

# Terminal 2: Run registration
python full_registration.py
```

## Code Walkthrough

### Step 1: Generate Identity

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
from agentmesh import AgentIdentity

# Generate keypair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Create identity
identity = AgentIdentity.create(
    name="hello-world-agent",
    sponsor="alice@company.com",
)
```

### Step 2: Register with AgentMesh

```python
from agentmesh import MeshClient

client = MeshClient(endpoint="https://mesh.example.com")

# Send registration request
response = await client.register(
    agent_name="hello-world-agent",
    public_key=public_key_bytes,
    sponsor_email="alice@company.com",
    sponsor_signature=sponsor_sig,
    capabilities=["read:data", "write:reports"],
)

print(f"✓ Registered! DID: {response.agent_did}")
print(f"✓ Trust score: {response.initial_trust_score}/1000")
print(f"✓ Credential expires: {response.svid_expires_at}")
```

### Step 3: Use the Identity

```python
# Identity is now active and can be used for:
# - mTLS connections to other agents
# - Trust handshakes (IATP)
# - Capability-scoped operations
# - Continuous trust scoring

# Example: Verify a peer before communication
verification = await client.verify_peer_trust(
    requester_did=response.agent_did,
    peer_did="did:mesh:peer-agent",
    required_trust_score=700,
)

if verification.verified:
    print(f"✓ Peer verified! Score: {verification.peer_trust_score}")
else:
    print(f"✗ Peer not trusted: {verification.rejection_reason}")
```

## Key Concepts

### 1. Human-Sponsored Identity

Every agent must have a human sponsor. This creates accountability:

```python
# Sponsor signs over agent details
sponsor_signature = sponsor_private_key.sign(
    agent_name + sponsor_email + capabilities_hash
)
```

### 2. Ephemeral Credentials (15-min TTL)

Credentials expire quickly to limit blast radius:

```python
# Credentials must be rotated before expiration
if time_until_expiry < 5_minutes:
    new_creds = client.rotate_credentials(
        agent_did=identity.did,
        refresh_token=refresh_token,
    )
```

### 3. Initial Trust Score

New agents start with a trust score of 500/1000:

```python
# Trust score dimensions
{
    "total": 500,
    "policy_compliance": 80,      # Never violated a policy
    "resource_efficiency": 50,    # No history yet
    "output_quality": 50,         # No history yet
    "security_posture": 70,       # Basic security practices
    "collaboration_health": 50,   # No peer interactions yet
}
```

The score will increase or decrease based on behavior.

### 4. Capabilities

Capabilities define what an agent can do:

```python
capabilities = [
    "read:data",          # Can read data
    "write:reports",      # Can write reports
    "execute:queries",    # Can execute database queries
]

# Attempting an action outside capabilities = DENIED
```

## Expected Output

```
🚀 AgentMesh Registration - Hello World

Step 1: Generating identity...
  ✓ Generated Ed25519 keypair
  ✓ Public key: 302a300506032b6570032100...
  ✓ Agent name: hello-world-agent
  ✓ Sponsor: alice@company.com

Step 2: Signing with sponsor...
  ✓ Sponsor signature obtained

Step 3: Registering with AgentMesh...
  → Sending RegistrationRequest...
  ← Received RegistrationResponse

Step 4: Registration successful!
  ✓ Agent DID: did:mesh:a3f8c2e1d4b6h9k2m5n7p1q4r8s2t6u9
  ✓ SVID issued (expires in 15 minutes)
  ✓ Access token received
  ✓ Trust score: 500/1000

Trust Score Breakdown:
  • Policy Compliance:      80/100 ⭐⭐⭐⭐
  • Resource Efficiency:    50/100 ⭐⭐⭐
  • Output Quality:         50/100 ⭐⭐⭐
  • Security Posture:       70/100 ⭐⭐⭐⭐
  • Collaboration Health:   50/100 ⭐⭐⭐

Next Steps:
  1. Store credentials securely
  2. Begin periodic credential rotation
  3. Start agent operations with governance enabled
  4. Trust score will adjust based on behavior

🎉 Agent is now part of the AgentMesh!
```

## What Happens Next?

After registration, the agent:

1. **Connects to AgentMesh**: Opens mTLS connection using SVID certificate
2. **Heartbeat**: Sends periodic heartbeats for trust scoring
3. **Operations**: Performs work, governed by policies
4. **Scoring**: Trust score adjusts based on behavior
5. **Rotation**: Rotates credentials every 15 minutes
6. **Revocation**: If trust score drops below threshold (e.g., 300), credentials are revoked

## Troubleshooting

### Registration Fails: "Invalid Sponsor"

Ensure the sponsor email is registered in AgentMesh:

```bash
agentmesh sponsor add alice@company.com --verified
```

### Registration Fails: "Invalid Signature"

Check that the sponsor signature is correctly computed:

```python
# Sponsor signs over: agent_name + sponsor_email + capabilities
message = f"{agent_name}{sponsor_email}{','.join(sorted(capabilities))}"
signature = sponsor_key.sign(message.encode())
```

### Certificate Expired

Certificates are short-lived (15 minutes). Rotate before expiry:

```python
# Check expiry
time_remaining = (expires_at - datetime.utcnow()).total_seconds()
if time_remaining < 300:  # Less than 5 minutes
    rotate_credentials()
```

## See Also

- [Protocol Documentation](../../proto/README.md)
- [JSON Schema](../../schemas/registration.json)
- [Integration with agent-os](../04-agent-os-integration/)
- [Multi-Agent Example](../02-customer-service/)
