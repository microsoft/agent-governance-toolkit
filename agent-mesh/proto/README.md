# AgentMesh Protocol Definitions

This directory contains Protocol Buffer definitions for the AgentMesh registration and identity management protocol.

## Overview

The AgentMesh protocol establishes a cryptographic chain of custody linking each agent back to a human sponsor. This ensures accountability, trust, and governance in agent-to-agent communications.

## Registration Handshake

The `registration.proto` file defines the core registration handshake between an agent and the AgentMesh Identity Core.

### Key Components

#### 1. RegistrationRequest

Sent by an agent to register with AgentMesh. Contains:
- **Agent Identity**: Name, description, organization
- **Cryptographic Keys**: Ed25519 public key for identity verification
- **Human Sponsor**: Email and signature for accountability
- **Capabilities**: What the agent is allowed to do (e.g., `["read:data", "write:reports"]`)
- **Protocol Support**: Which protocols the agent supports (A2A, MCP, IATP, ACP)
- **Scope Chain**: Optional parent agent for delegated identities

#### 2. RegistrationResponse

Returned by AgentMesh after successful registration. Contains:
- **Agent DID**: Unique decentralized identifier (`did:mesh:<id>`)
- **SVID Certificate**: X.509 certificate for mTLS (15-minute TTL by default)
- **Trust Score**: Initial trust score (0-1000 scale, default: 500)
- **Access Tokens**: Short-lived access and refresh tokens
- **Registry Info**: Endpoint URLs and CA certificate

#### 3. Trust Score Dimensions

Trust scores are broken down into five dimensions:
1. **Policy Compliance** (0-100): Adherence to governance policies
2. **Resource Efficiency** (0-100): Efficient use of compute/memory/network
3. **Output Quality** (0-100): Quality of outputs and responses
4. **Security Posture** (0-100): Security best practices and vulnerability management
5. **Collaboration Health** (0-100): Effective collaboration with peer agents

Total trust score = weighted sum of dimensions (configurable weights)

### Registration Flow

```
┌─────────┐                                    ┌──────────────┐
│  Agent  │                                    │  AgentMesh   │
│         │                                    │  Identity    │
│         │                                    │     Core     │
└────┬────┘                                    └──────┬───────┘
     │                                                │
     │  1. Generate Ed25519 keypair                   │
     │─────────────────────────────────────────>      │
     │                                                │
     │  2. RegistrationRequest                        │
     │     - Public key                               │
     │     - Sponsor email + signature                │
     │     - Capabilities                             │
     │────────────────────────────────────────>       │
     │                                                │
     │                3. Validate sponsor             │
     │                4. Verify signature             │
     │                5. Issue SVID                   │
     │                6. Calculate initial score      │
     │                                                │
     │  7. RegistrationResponse                       │
     │     - Agent DID                                │
     │     - SVID certificate (15-min TTL)            │
     │     - Trust score: 500                         │
     │     - Access token                             │
     │<────────────────────────────────────────       │
     │                                                │
     │  8. Store credentials securely                 │
     │  9. Begin heartbeat (trust scoring)            │
     │                                                │
```

### Credential Rotation

Credentials must be rotated before expiration (15-minute default TTL):

```python
# Pseudo-code
while agent.running:
    if time_until_expiry < 5_minutes:
        new_creds = mesh.rotate_credentials(
            agent_did=agent.did,
            refresh_token=agent.refresh_token
        )
        agent.update_credentials(new_creds)
```

### Trust Verification

Before communicating with a peer agent, verify their trust:

```python
verification = mesh.verify_peer_trust(
    requester_did="did:mesh:agent-a",
    peer_did="did:mesh:agent-b",
    required_trust_score=700,
    required_capabilities=["read:data"]
)

if verification.verified:
    # Safe to communicate
    send_message_to_peer(peer_did, message)
else:
    # Peer does not meet trust requirements
    log_warning(verification.rejection_reason)
```

## Service Definition

The `AgentMeshIdentityService` gRPC service provides three RPCs:

1. **Register**: Register a new agent
2. **RotateCredentials**: Rotate expiring credentials
3. **VerifyPeerTrust**: Check if a peer agent can be trusted

## Compiling Protocol Buffers

To generate Python code from these definitions:

```bash
# Install protobuf compiler
pip install grpcio-tools

# Compile
python -m grpc_tools.protoc \
    -I. \
    --python_out=../src/agentmesh/generated \
    --grpc_python_out=../src/agentmesh/generated \
    registration.proto
```

## Security Considerations

1. **Key Management**: Private keys must never be transmitted. Only public keys are sent in registration requests.
2. **Sponsor Signatures**: Sponsor signatures ensure human accountability for every agent.
3. **Short-lived Credentials**: 15-minute TTL limits the blast radius of credential theft.
4. **Trust Scores**: Continuous scoring enables automatic revocation when behavior degrades.
5. **mTLS**: All communication uses mutual TLS with SPIFFE/SVID certificates.

## Compliance Mapping

The registration protocol supports compliance automation:

- **EU AI Act**: Risk classification via capabilities, transparency via audit logs
- **SOC 2**: Security controls via credential management, audit via hash chain
- **HIPAA**: PHI protection via capability scoping, audit controls
- **GDPR**: Data processing transparency, right to explanation

## Examples

See the [examples directory](../examples/00-registration-hello-world/) for a complete "Hello World" registration example.

## Version History

- **v1.0.0** (2026-02-01): Initial protocol definition
  - Registration handshake
  - Credential rotation
  - Trust verification
  - Five-dimensional trust scoring

## References

- [SPIFFE Specification](https://github.com/spiffe/spiffe)
- [W3C DID Specification](https://www.w3.org/TR/did-core/)
- [IATP Protocol](https://github.com/microsoft/agent-governance-toolkit)
- [Google A2A Protocol](https://github.com/google/a2a)
- [Anthropic MCP Protocol](https://github.com/anthropics/mcp)
