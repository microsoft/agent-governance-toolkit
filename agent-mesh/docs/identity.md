# Identity Management in AgentMesh

This document details how agent identities are created, verified, revoked, and integrated with enterprise identity systems.

## Overview

AgentMesh provides a first-class identity layer for AI agents that goes beyond traditional workload identity:

```
┌─────────────────────────────────────────────────────────────────┐
│                    AGENT IDENTITY STACK                          │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4  │  Human Sponsor Binding                              │
│           │  Accountability · Audit Trail · Contact Chain       │
├───────────┼─────────────────────────────────────────────────────┤
│  Layer 3  │  Capability Scoping                                 │
│           │  Permissions · Delegation Limits · Time Bounds      │
├───────────┼─────────────────────────────────────────────────────┤
│  Layer 2  │  Agent DID (Decentralized Identifier)               │
│           │  did:mesh:{hash} · Cryptographic Binding · CMVK     │
├───────────┼─────────────────────────────────────────────────────┤
│  Layer 1  │  Workload Identity (SPIFFE/SVID)                    │
│           │  x509-SVID · JWT-SVID · mTLS · Federation           │
└───────────┴─────────────────────────────────────────────────────┘
```

## Creating Agent Identities

### Basic Identity Creation

```python
from agentmesh import AgentIdentity

# Create a new agent identity
identity = AgentIdentity.create(
    name="data-analyst-agent",
    sponsor="alice@company.com",
    capabilities=["read:customer-data", "write:reports"],
)

print(identity.did)  # did:mesh:a1b2c3d4e5f6...
print(identity.public_key)  # Ed25519 public key (base64)
```

### Identity Components

| Component | Description | Example |
|-----------|-------------|---------|
| **DID** | Decentralized identifier | `did:mesh:a1b2c3...` |
| **Public Key** | Ed25519 verification key | `MCowBQYDK2Vw...` |
| **Private Key** | Ed25519 signing key (never shared) | Stored securely |
| **Sponsor** | Human accountable for agent | `alice@company.com` |
| **Capabilities** | Allowed actions | `["read:*", "write:reports"]` |
| **Metadata** | Additional context | `{"team": "analytics"}` |

### CMVK Algorithm

AgentMesh uses **CMVK** (Cryptographic Multi-Vector Key) for identity generation:

```python
# CMVK identity generation (simplified)
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# 1. Generate Ed25519 keypair
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# 2. Create DID from public key hash
public_bytes = public_key.public_bytes_raw()
did_hash = hashlib.sha256(public_bytes).hexdigest()[:32]
did = f"did:mesh:{did_hash}"

# 3. Bind sponsor and capabilities
identity_document = {
    "did": did,
    "public_key": base64.b64encode(public_bytes).decode(),
    "sponsor": "alice@company.com",
    "capabilities": ["read:customer-data"],
    "created_at": datetime.utcnow().isoformat(),
}

# 4. Sign the identity document
signature = private_key.sign(
    json.dumps(identity_document, sort_keys=True).encode()
)
```

## SPIFFE/SVID Integration

AgentMesh integrates with SPIFFE for workload identity, adding agent-specific extensions.

### SPIFFE ID Format

```
spiffe://trust-domain/agent/{agent-did}

Example:
spiffe://company.com/agent/did:mesh:a1b2c3d4e5f6
```

### x509-SVID with Agent Extensions

```
┌─────────────────────────────────────────────────────────────────┐
│                     x509-SVID CERTIFICATE                        │
├─────────────────────────────────────────────────────────────────┤
│  Subject:                                                        │
│    CN=did:mesh:a1b2c3d4e5f6                                     │
│                                                                  │
│  SAN (Subject Alternative Name):                                │
│    URI: spiffe://company.com/agent/did:mesh:a1b2c3d4e5f6       │
│                                                                  │
│  Extensions:                                                     │
│    agentmesh.sponsor: alice@company.com                         │
│    agentmesh.capabilities: read:customer-data,write:reports     │
│    agentmesh.parent: did:mesh:parent-agent (if delegated)       │
│    agentmesh.trust_score: 0.72                                  │
│                                                                  │
│  Validity:                                                       │
│    Not Before: 2026-02-06T22:00:00Z                             │
│    Not After:  2026-02-06T22:15:00Z (15 min TTL)                │
└─────────────────────────────────────────────────────────────────┘
```

### SPIRE Integration

```yaml
# SPIRE server configuration for AgentMesh
server:
  trust_domain: "company.com"
  
  # Custom attestor for AgentMesh agents
  plugins:
    NodeAttestor:
      agentmesh:
        plugin_data:
          mesh_api: "https://mesh.company.com/api"
          
    WorkloadAttestor:
      agentmesh:
        plugin_data:
          verify_sponsor: true
          verify_capabilities: true
```

```python
# Python: Get SVID for agent
from agentmesh.spiffe import SPIFFEClient

spiffe = SPIFFEClient(socket_path="/tmp/spire-agent/public/api.sock")

# Fetch x509-SVID with agent extensions
svid = await spiffe.fetch_x509_svid(
    agent_did="did:mesh:a1b2c3d4e5f6",
    sponsor="alice@company.com",
    capabilities=["read:customer-data"],
)

# Use for mTLS
ssl_context = svid.to_ssl_context()
```

## mTLS Configuration

### Server-Side (Agent receiving connections)

```python
from agentmesh import AgentServer
from agentmesh.tls import AgentTLSConfig

# Create TLS config requiring agent certificates
tls_config = AgentTLSConfig(
    cert_file="/path/to/agent-cert.pem",
    key_file="/path/to/agent-key.pem",
    ca_file="/path/to/mesh-ca.pem",
    verify_client=True,
    require_agent_identity=True,  # Require AgentMesh identity
    min_trust_score=0.5,  # Optional: require minimum trust
)

server = AgentServer(tls_config=tls_config)

@server.on_connect
async def verify_peer(peer_identity):
    print(f"Connected: {peer_identity.did}")
    print(f"Sponsor: {peer_identity.sponsor}")
    print(f"Trust Score: {peer_identity.trust_score}")
```

### Client-Side (Agent making connections)

```python
from agentmesh import AgentClient
from agentmesh.tls import AgentTLSConfig

tls_config = AgentTLSConfig(
    cert_file="/path/to/agent-cert.pem",
    key_file="/path/to/agent-key.pem",
    ca_file="/path/to/mesh-ca.pem",
)

client = AgentClient(
    identity=my_identity,
    tls_config=tls_config,
)

# Connect with automatic mTLS
async with client.connect("did:mesh:target-agent") as conn:
    await conn.send(message)
```

### Certificate Rotation

AgentMesh uses short-lived certificates (15 minutes by default) with automatic rotation:

```python
from agentmesh.credentials import CredentialManager

creds = CredentialManager(
    identity=my_identity,
    ttl_seconds=900,  # 15 minutes
    rotation_threshold=0.8,  # Rotate at 80% of TTL
)

# Start automatic rotation
await creds.start_rotation()

# Get current certificate (auto-refreshed)
cert = creds.current_certificate
```

## Delegation and Chain of Custody

### Creating Delegated Identities

```python
# Parent agent delegates to child
child_identity = parent_identity.delegate(
    name="summarizer-subagent",
    capabilities=["read:public-data"],  # Must be subset of parent
    ttl_seconds=300,  # 5 minutes max
)

# Scope chain is recorded
print(child_identity.scope_chain)
# [
#   {"did": "did:mesh:sponsor", "type": "human"},
#   {"did": "did:mesh:parent", "type": "agent", "capabilities": ["read:*"]},
#   {"did": "did:mesh:child", "type": "agent", "capabilities": ["read:public-data"]},
# ]
```

### Verifying Scope Chains

```python
from agentmesh import verify_scope_chain

# Verify the chain is valid
result = verify_scope_chain(child_identity)

if result.valid:
    print(f"Chain valid, depth: {result.depth}")
    print(f"Root sponsor: {result.root_sponsor}")
    print(f"Effective capabilities: {result.effective_capabilities}")
else:
    print(f"Chain invalid: {result.error}")
    # Possible errors:
    # - "capability_escalation": child has more permissions than parent
    # - "chain_too_deep": exceeds max delegation depth
    # - "expired_link": intermediate identity expired
    # - "invalid_signature": cryptographic verification failed
```

### Delegation Constraints

| Constraint | Default | Description |
|------------|---------|-------------|
| `max_depth` | 3 | Maximum scope chain depth |
| `must_narrow` | true | Child capabilities must be subset of parent |
| `max_ttl` | parent TTL | Child cannot outlive parent |
| `require_audit` | true | All delegations logged |

## Identity Revocation

### Immediate Revocation

```python
from agentmesh import MeshClient

mesh = MeshClient()

# Revoke an agent identity
await mesh.revoke_identity(
    did="did:mesh:compromised-agent",
    reason="security_breach",
    revoked_by="security-team@company.com",
)

# All child identities are automatically revoked
```

### Revocation Checking

```python
# Check if identity is revoked before trusting
is_revoked = await mesh.is_revoked("did:mesh:some-agent")

# Or use the built-in verification
result = await mesh.verify_identity(peer_identity)
if result.revoked:
    print(f"Identity revoked: {result.revocation_reason}")
```

### Revocation Distribution

AgentMesh distributes revocations via:

1. **Push**: Websocket notifications to connected agents
2. **Pull**: CRL (Certificate Revocation List) endpoint
3. **OCSP**: Real-time status checking

```python
# Configure revocation checking
from agentmesh.revocation import RevocationConfig

config = RevocationConfig(
    check_crl=True,
    crl_url="https://mesh.company.com/crl",
    crl_cache_ttl=300,  # 5 minutes
    
    check_ocsp=True,
    ocsp_url="https://mesh.company.com/ocsp",
    
    fail_open=False,  # Deny if revocation check fails
)
```

## Enterprise Identity Integration

### OIDC/SAML for Sponsor Verification

```python
from agentmesh.enterprise import OIDCProvider

# Configure OIDC for sponsor verification
oidc = OIDCProvider(
    issuer="https://login.company.com",
    client_id="agentmesh",
    client_secret="...",
)

# Verify sponsor is a valid enterprise user
sponsor_verified = await oidc.verify_user("alice@company.com")
```

### Active Directory Integration

```python
from agentmesh.enterprise import ADProvider

ad = ADProvider(
    ldap_url="ldaps://ad.company.com",
    base_dn="DC=company,DC=com",
)

# Check sponsor exists and has permission to create agents
can_sponsor = await ad.check_permission(
    user="alice@company.com",
    permission="create_agents",
)
```

### Vault Integration for Key Storage

```python
from agentmesh.vault import VaultKeyStore

vault = VaultKeyStore(
    url="https://vault.company.com",
    auth_method="kubernetes",
    mount_path="agentmesh",
)

# Store agent private key securely
await vault.store_key(
    identity.did,
    identity.private_key,
    metadata={"sponsor": identity.sponsor},
)

# Retrieve for agent startup
private_key = await vault.get_key(identity.did)
```

## Identity Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                    IDENTITY LIFECYCLE                            │
│                                                                  │
│   ┌──────────┐                                                  │
│   │ CREATED  │  Identity generated, sponsor assigned            │
│   └────┬─────┘                                                  │
│        │                                                         │
│        ▼                                                         │
│   ┌──────────┐                                                  │
│   │REGISTERED│  Registered with mesh, SVID issued               │
│   └────┬─────┘                                                  │
│        │                                                         │
│        ▼                                                         │
│   ┌──────────┐                                                  │
│   │  ACTIVE  │◄──────────────────┐  Operating normally          │
│   └────┬─────┘                   │                              │
│        │                         │                              │
│        ├─────────────────────────┘  Credential rotation         │
│        │                                                         │
│        ├────────► ┌──────────┐                                  │
│        │          │SUSPENDED │  Trust score too low             │
│        │          └────┬─────┘                                  │
│        │               │                                         │
│        │               ▼  (trust recovered)                      │
│        │          ┌──────────┐                                  │
│        │          │PROBATION │  Limited capabilities            │
│        │          └────┬─────┘                                  │
│        │               │                                         │
│        │◄──────────────┘  (probation passed)                    │
│        │                                                         │
│        ▼                                                         │
│   ┌──────────┐                                                  │
│   │ REVOKED  │  Permanently disabled                            │
│   └──────────┘                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Best Practices

### 1. Always Require Human Sponsors

```python
# Good: Human sponsor required
identity = AgentIdentity.create(
    name="my-agent",
    sponsor="alice@company.com",  # Real human
)

# Bad: No accountability
identity = AgentIdentity.create(
    name="my-agent",
    sponsor="system",  # Who is responsible?
)
```

### 2. Use Short-Lived Credentials

```python
# Good: 15-minute TTL (default)
creds = CredentialManager(ttl_seconds=900)

# Risky: Long-lived credentials
creds = CredentialManager(ttl_seconds=86400)  # 24 hours
```

### 3. Scope Capabilities Narrowly

```python
# Good: Specific capabilities
capabilities = ["read:customer-data", "write:reports"]

# Bad: Overly broad
capabilities = ["*"]  # Full access
```

### 4. Verify Scope Chains

```python
# Always verify before trusting delegated identity
if not verify_scope_chain(peer_identity).valid:
    raise SecurityError("Invalid scope chain")
```

### 5. Monitor for Revocations

```python
# Enable real-time revocation checking
config = RevocationConfig(
    check_ocsp=True,
    fail_open=False,  # Deny on check failure
)
```

## API Reference

### AgentIdentity

```python
class AgentIdentity:
    did: str                    # Decentralized identifier
    public_key: bytes           # Ed25519 public key
    private_key: bytes          # Ed25519 private key (optional)
    sponsor: str                # Human sponsor email
    capabilities: List[str]     # Allowed actions
    metadata: Dict[str, Any]    # Additional context
    created_at: datetime        # Creation timestamp
    expires_at: datetime        # Expiration timestamp
    parent_did: Optional[str]   # Parent agent (if delegated)
    scope_chain: List[Dict]  # Full chain of custody
    
    @classmethod
    def create(cls, name: str, sponsor: str, capabilities: List[str], **kwargs) -> "AgentIdentity"
    
    def delegate(self, name: str, capabilities: List[str], ttl_seconds: int = None) -> "AgentIdentity"
    
    def sign(self, data: bytes) -> bytes
    
    def verify(self, data: bytes, signature: bytes) -> bool
    
    def to_dict(self) -> Dict[str, Any]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentIdentity"
```

## See Also

- [Trust Scoring Algorithm](trust-scoring.md)
- [Zero-Trust Architecture](zero-trust.md)
- [Service Mesh Comparison](service-mesh-comparison.md)
- [SPIFFE Documentation](https://spiffe.io/docs/)
