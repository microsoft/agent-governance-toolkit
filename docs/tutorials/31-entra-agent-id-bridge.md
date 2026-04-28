# Tutorial 31 — Bridging AGT Identity with Microsoft Entra Agent ID

> **Level:** Advanced · **Time:** 45 min · **Prerequisites:** Tutorial 02 (Trust & Identity), Azure subscription with Entra ID

This tutorial shows how to bridge Agent Governance Toolkit (AGT) DID-based identities with **Microsoft Entra Agent ID**, enabling enterprise lifecycle management, Conditional Access, and sponsor accountability through **Agent365**.

## Why Bridge?

AGT and Entra Agent ID solve different parts of the agent governance problem:

| Concern | AGT | Entra Agent ID / Agent365 |
|---------|-----|---------------------------|
| **Identity format** | `did:agentmesh:{hash}` (Ed25519) | Entra object ID (AAD) |
| **Policy enforcement** | Runtime — per-tool-call | Directory — Conditional Access |
| **Credential lifecycle** | Short-lived (15 min TTL), auto-rotated | OAuth 2.0 tokens, managed identity |
| **Trust scoring** | Behavioral 0–1000 score | N/A (binary active/suspended) |
| **Kill switch** | Instant agent termination | Disable account in Entra |
| **Audit** | Append-only hash-chain log | Entra sign-in + audit logs |
| **Sponsor accountability** | Per-DID sponsor binding | Per-identity sponsor in directory |
| **Shadow AI discovery** | Process/config/repo scanning | Agent registry + Purview |
| **Scope** | Any cloud, any runtime | Microsoft ecosystem + federated |

**Together they provide defense in depth:** AGT handles runtime governance (policy, trust, sandboxing) while Entra Agent ID handles enterprise identity lifecycle (provisioning, access reviews, compliance).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ENTERPRISE CONTROL PLANE                      │
│                                                                      │
│  ┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐  │
│  │  Agent365     │    │  Microsoft Entra  │    │  Microsoft       │  │
│  │  Dashboard    │◄──►│  Agent ID         │◄──►│  Purview         │  │
│  │              │    │                  │    │  (Compliance)    │  │
│  └──────┬───────┘    └────────┬─────────┘    └──────────────────┘  │
│         │                     │                                      │
│         │         ┌───────────┴───────────┐                         │
│         │         │  Entra Object ID       │                         │
│         │         │  + Sponsor             │                         │
│         │         │  + Conditional Access   │                         │
│         │         │  + API Permissions      │                         │
│         │         └───────────┬───────────┘                         │
│         │                     │                                      │
│         │              IDENTITY BRIDGE                               │
│         │         ┌───────────┴───────────┐                         │
│         │         │  EntraAgentRegistry    │                         │
│         │         │  did:mesh ↔ Entra OID  │                         │
│         │         └───────────┬───────────┘                         │
│         │                     │                                      │
│  ┌──────┴─────────────────────┴─────────────────────────────────┐  │
│  │                  AGT RUNTIME GOVERNANCE                        │  │
│  │                                                                │  │
│  │  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌──────────────────┐  │  │
│  │  │ Policy  │ │ Trust    │ │ Audit   │ │ MCP Security     │  │  │
│  │  │ Engine  │ │ Scoring  │ │ Logger  │ │ Gateway          │  │  │
│  │  └─────────┘ └──────────┘ └─────────┘ └──────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Roles and Responsibilities

### What AGT Owns

| Responsibility | Component | Details |
|---|---|---|
| **Agent DID creation** | `AgentIdentity.create()` | Ed25519 keypair + `did:agentmesh:{hash}` |
| **Runtime policy** | `PolicyEngine` | Per-tool-call allow/deny with rules |
| **Trust scoring** | `TrustEngine` | Behavioral 0–1000 score with decay |
| **Tool-call governance** | `GovernanceMiddleware` | Rate limiting, injection detection, audit |
| **MCP security** | `McpSecurityScanner`, `McpGateway` | Tool poisoning, typosquatting, payload sanitization |
| **Execution sandboxing** | `ExecutionRings` | 4-tier privilege model (Ring 0–3) |
| **Kill switch** | `KillSwitch` | Instant termination on policy violation |
| **Credential rotation** | `CredentialManager` | Short-lived bearer tokens (15 min) |
| **Delegation chains** | `delegate()` | Scoped child identities with depth limits |
| **Audit logging** | `AuditLogger` | Append-only hash-chain with tamper detection |

### What Entra Agent ID / Agent365 Owns

| Responsibility | Component | Details |
|---|---|---|
| **Directory identity** | Entra Agent ID | Object ID in tenant directory |
| **Lifecycle management** | Agent365 | Provisioning → access reviews → decommission |
| **Conditional Access** | Entra CA policies | Location, device, risk-based access |
| **Sponsor accountability** | Entra Agent ID | Human sponsor assigned per agent |
| **Access reviews** | Entra Identity Governance | Periodic attestation by sponsors |
| **OAuth 2.0 tokens** | Entra + MSAL | Managed identity, client credentials |
| **API permissions** | Entra app registrations | Scoped Graph/API access |
| **Shadow AI discovery** | Agent365 + Purview | Agent registry, compliance scanning |
| **Unified audit** | Entra sign-in logs | All auth events centralized |
| **Compliance controls** | Purview + Defender | DLP, threat protection, data governance |

### Shared Responsibilities (Bridge)

| Responsibility | AGT Side | Entra Side |
|---|---|---|
| **Identity mapping** | `EntraAgentRegistry` stores `did:mesh ↔ entra_object_id` | Entra stores agent as directory object |
| **Token exchange** | `EntraAgentID` validates Entra JWT claims | Entra issues tokens via managed identity |
| **Sponsor verification** | AGT requires sponsor at DID creation | Entra requires sponsor at identity creation |
| **Suspension** | AGT `KillSwitch` / trust score drop | Entra disables account in directory |
| **Audit correlation** | AGT logs include `entra_object_id` | Entra logs include sign-in activity |

## Step 1 — Create AGT Identity with Entra Binding

```python
from agentmesh import AgentIdentity
from agentmesh.identity.entra import EntraAgentRegistry, EntraAgentBlueprint

# 1. Set up the Entra registry for your tenant
registry = EntraAgentRegistry(tenant_id="your-tenant-id")

# 2. (Optional) Register a blueprint for consistent agent creation
registry.register_blueprint(EntraAgentBlueprint(
    display_name="Data Analyst Agent",
    description="Reads customer data and generates reports",
    default_capabilities=["read:customer-data", "write:reports"],
    require_sponsor=True,
    max_delegation_depth=2,
    conditional_access_policy="ca-policy-id-for-agents",
))

# 3. Create the AGT identity
identity = AgentIdentity.create(
    name="data-analyst-agent",
    sponsor="alice@contoso.com",
    capabilities=["read:customer-data", "write:reports"],
)
print(f"AGT DID: {identity.did}")  # did:agentmesh:a7f3b2c1...

# 4. Register the bridge mapping
#    The entra_object_id comes from your Entra Agent ID provisioning
#    (via Azure Portal, Graph API, or Agent365)
entra_identity = registry.register(
    agent_did=identity.did,
    agent_name="data-analyst-agent",
    entra_object_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",  # From Entra
    sponsor_email="alice@contoso.com",
    capabilities=["read:customer-data", "write:reports"],
    scopes=["https://graph.microsoft.com/.default"],
    blueprint_name="Data Analyst Agent",
)
```

## Step 2 — Bootstrap from Azure Managed Identity (AKS)

When running on AKS with workload identity, AGT can auto-discover the Entra binding:

```python
from agentmesh.identity.entra_agent_id import EntraAgentID

# Auto-discover from Azure IMDS (on AKS, VMs, Container Apps, etc.)
entra_agent = EntraAgentID.from_managed_identity(agent_did=identity.did)

# Or from environment variables
entra_agent = EntraAgentID.from_environment(agent_did=identity.did)

# Get the DID ↔ Entra mapping
mapping = entra_agent.to_did_mapping()
# {
#   "agent_did": "did:agentmesh:a7f3b2c1...",
#   "entra": {
#     "tenant_id": "your-tenant-id",
#     "client_id": "your-client-id"
#   },
#   "mapping_version": "1.0"
# }
```

### AKS Workload Identity Setup

```yaml
# 1. Create Kubernetes service account with Entra federated credential
apiVersion: v1
kind: ServiceAccount
metadata:
  name: agent-workload
  namespace: agents
  annotations:
    azure.workload.identity/client-id: "your-client-id"
  labels:
    azure.workload.identity/use: "true"

---
# 2. Pod spec with workload identity
apiVersion: v1
kind: Pod
metadata:
  name: data-analyst-agent
  namespace: agents
  labels:
    azure.workload.identity/use: "true"
spec:
  serviceAccountName: agent-workload
  containers:
    - name: agent
      image: your-registry.azurecr.io/data-analyst-agent:latest
      env:
        - name: AZURE_TENANT_ID
          value: "your-tenant-id"
        - name: AZURE_CLIENT_ID
          value: "your-client-id"
```

```bash
# 3. Create the federated credential in Entra
az identity federated-credential create \
  --name agent-fed-cred \
  --identity-name agent-managed-id \
  --resource-group agent-rg \
  --issuer "https://oidc.prod-aks.azure.com/your-oidc-issuer" \
  --subject "system:serviceaccount:agents:agent-workload" \
  --audiences "api://AzureADTokenExchange"
```

## Step 3 — Token Validation at the Bridge

When an agent receives an Entra token (e.g., from another service), validate it and map to the AGT identity:

```python
# Validate incoming Entra token
claims = entra_agent.validate_token(incoming_token)
# Validates: expiry, not-before, issuer (v1/v2 endpoints), audience

# Look up AGT identity from Entra object ID
agt_identity = registry.get_by_entra_id(claims["oid"])
if agt_identity and agt_identity.is_active():
    # Proceed with AGT policy enforcement using the mapped DID
    agt_identity.record_activity()
```

> **Important:** `EntraAgentID.validate_token()` performs structural and claim-level validation only. For production deployments, add cryptographic signature verification using `azure-identity` or the Entra JWKS endpoint.

## Step 4 — Lifecycle Synchronization

Keep AGT and Entra states in sync:

```python
# When Entra suspends an agent → suspend in AGT
registry.suspend_agent(
    agent_did="did:agentmesh:a7f3b2c1...",
    reason="Entra Conditional Access violation"
)

# When AGT kill switch fires → disable in Entra
# Use Graph API: PATCH /servicePrincipals/{entra_object_id}
# with { "accountEnabled": false }
# (Requires Directory.ReadWrite.All or Application.ReadWrite.All permission)

# When sponsor re-approves → reactivate
registry.reactivate_agent(agent_did="did:agentmesh:a7f3b2c1...")
```

### Audit Correlation

AGT audit events include the Entra object ID for cross-system correlation:

```python
# AGT audit record
audit_record = entra_identity.to_audit_record()
# {
#   "agent_did": "did:agentmesh:a7f3b2c1...",
#   "entra_object_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
#   "tenant_id": "your-tenant-id",
#   "sponsor_email": "alice@contoso.com",
#   "status": "active",
#   "capabilities": ["read:customer-data", "write:reports"],
#   "scopes": ["https://graph.microsoft.com/.default"],
#   "last_activity": "2026-04-16T01:00:00Z"
# }
```

## Step 5 — Access Verification with Entra Scopes

Combine AGT policy checks with Entra scope verification:

```python
from agentmesh import PolicyEngine

# Load AGT policies
policy_engine = PolicyEngine(config_path="governance.yaml")

# Combined verification: Entra scope + AGT policy
def verify_tool_call(agent_did: str, tool_name: str, params: dict) -> bool:
    # 1. Check Entra scope
    allowed, reason = registry.verify_access(
        agent_did=agent_did,
        required_scope="https://graph.microsoft.com/Files.Read"
    )
    if not allowed:
        print(f"Entra denied: {reason}")
        return False

    # 2. Check AGT policy
    decision = policy_engine.evaluate(agent_did, tool_name, params)
    if not decision.allowed:
        print(f"AGT policy denied: {decision.reason}")
        return False

    return True
```

## Step 6 — Group Membership Sync via Graph API

Automatically map Entra group memberships to AGT capabilities:

```python
from agentmesh.identity.entra_graph import EntraGraphClient, build_group_scope_map

# 1. Get a Graph API token (via managed identity, workload identity, etc.)
token = entra_agent.get_agent_token(scope="https://graph.microsoft.com/.default")

# 2. Create the Graph client
graph_client = EntraGraphClient(access_token=token)

# 3. Define group-to-capability mapping (keyed by Entra group object ID)
group_scope_map = build_group_scope_map({
    "aaaaaaaa-1111-2222-3333-444444444444": ["read:customer-data", "read:reports"],
    "bbbbbbbb-1111-2222-3333-444444444444": ["write:reports", "export:csv"],
})

# 4. Sync — fetches groups from Graph, maps to capabilities, preserves manual caps
capabilities = registry.sync_group_memberships(
    agent_did=identity.did,
    graph_client=graph_client,
    group_scope_map=group_scope_map,
)
print(f"Updated capabilities: {capabilities}")
# ['export:csv', 'manual:cap', 'read:customer-data', 'read:reports', 'write:reports']
```

> **Note:** The Graph API call requires `GroupMember.Read.All` or `Directory.Read.All` permission on the Entra application. Group sync only updates AGT **capabilities** — Entra API **scopes** remain unchanged.

## Step 7 — Validate Bridge Configuration

Before going to production, validate the bridge mapping is complete:

```python
valid, issues = registry.validate_bridge_configuration(agent_did=identity.did)
if not valid:
    print(f"Bridge configuration issues: {issues}")
    # e.g., ['Missing entra_app_id — Agent365 may not resolve the agent']
else:
    print("Bridge configuration OK — ready for enterprise deployment")
```

## Known Gaps and Limitations

| Gap | Status | Workaround |
|-----|--------|------------|
| **Graph API group membership sync** | ✅ Built | `EntraGraphClient.get_group_memberships()` + `EntraAgentRegistry.sync_group_memberships()` — maps Entra groups to AGT capabilities |
| **Agent365 native integration** | Configuration validated | `EntraAgentRegistry.validate_bridge_configuration()` checks bridge mapping completeness; end-to-end Agent365 testing pending |
| **Bidirectional lifecycle sync** | One-way (manual) | Use Azure Event Grid or Logic Apps to sync Entra state changes → AGT kill switch |
| **Graph API service principal disable** | Not in AGT | Use Graph API directly: `PATCH /servicePrincipals/{id}` with `accountEnabled: false` |
| **Entra bridge in non-Python language packages** | Python-only | TS, .NET, Rust, and Go packages need `EntraAgentRegistry` and `EntraAgentID` ported |
| **DID format inconsistency** | `did:agentmesh:*` (Python, .NET) vs `did:agentmesh:*` (TS, Rust, Go) | Both formats work; standardization planned for v4.0 |
| **Cryptographic token verification** | Claim-level only | Add `azure-identity` for JWKS-based signature verification |

## Platform Independence Note

While this tutorial focuses on Microsoft Entra, AGT's identity layer is platform-independent. The same bridging pattern applies to:

- **AWS IAM Identity Center** — map `did:agentmesh:*` ↔ IAM role ARN
- **Google Cloud Workload Identity** — map `did:agentmesh:*` ↔ service account email
- **Okta Workforce Identity** — map `did:agentmesh:*` ↔ Okta user/app ID
- **SPIFFE/SPIRE** — map `did:agentmesh:*` ↔ SPIFFE ID (see [identity docs](../../agent-governance-python/agent-mesh/docs/identity.md))

AGT's `EntraAgentRegistry` pattern can be adapted for any enterprise IdP. We welcome community contributions for AWS, GCP, and Okta adapters.

## Next Steps

- **[Tutorial 02 — Trust & Identity](02-trust-and-identity.md)** — AGT identity fundamentals
- **[Tutorial 23 — Delegation Chains](23-delegation-chains.md)** — Scoped child identities
- **[Tutorial 25 — Security Hardening](25-security-hardening.md)** — Production deployment
- **[Azure Deployment Guide](../../agent-governance-python/agent-mesh/docs/deployment/azure.md)** — AKS + workload identity
- **[Identity Architecture](../../agent-governance-python/agent-mesh/docs/identity.md)** — Full identity stack reference
- **[Entra Agent ID Docs](https://learn.microsoft.com/en-us/entra/agent-id/)** — Microsoft Entra documentation
