# APIM Governance Metadata Policy Fragment

This directory contains an APIM policy fragment and sample product policy for passing AGT governance metadata through the Citadel gateway.

## Architecture

```
Agent Runtime                    APIM Gateway                     LLM Backend
┌──────────────┐    request     ┌──────────────┐    request      ┌───────────┐
│ AGT Policy   │  + headers     │ Fragment:    │  (headers       │           │
│ Engine       ├───────────────>│ Read AGT     │   stripped)     │  Azure    │
│              │                │ metadata,    ├────────────────>│  OpenAI   │
│ Sets headers:│                │ log to trace,│                 │           │
│ X-AGT-Trust  │                │ strip before │    response     │           │
│ X-AGT-Risk   │    response    │ forwarding   │<────────────────┤           │
│ X-AGT-Bundle │<───────────────┤              │                 │           │
│ X-AGT-Version│  + X-AGT-APIM  │ Add APIM ID  │                 │           │
│ X-AGT-DecId  │    -Request-Id  │ to response  │                 └───────────┘
└──────────────┘                └──────────────┘
```

## Key Design Decision

APIM does **not** call AGT's policy endpoint on every request. That would:
- Add latency (extra network hop per request)
- Create availability coupling (APIM depends on AGT service)
- Produce split-brain decisions (two systems making allow/deny calls)

Instead, the agent runtime evaluates policies locally and passes the result as **advisory metadata** through the gateway. APIM logs this metadata for observability but does not make governance decisions based on it (unless you explicitly enable the optional trust threshold block).

## Files

| File | Description |
|------|-------------|
| `agt-governance-metadata.xml` | Policy fragment. Deploy to APIM as a reusable fragment with ID `agt-governance-metadata`. |
| `agt-governed-product-policy.xml` | Sample product policy showing how to include the fragment alongside Citadel's standard controls. |

## Header Schema

Headers set by the agent runtime before making LLM calls through the gateway:

| Header | Type | Description |
|--------|------|-------------|
| `X-AGT-Trust-Score` | Integer (0-1000) | Agent's current trust score |
| `X-AGT-Risk-Label` | String | `trusted`, `degraded`, or `untrusted` |
| `X-AGT-Policy-Bundle` | String | Policy bundle ID (e.g., `customer-support-v2`) |
| `X-AGT-Policy-Version` | String | Bundle version (e.g., `1.2.0`) |
| `X-AGT-Decision-Id` | UUID | AGT policy decision ID for correlation |

Response header added by the fragment:

| Header | Type | Description |
|--------|------|-------------|
| `X-AGT-APIM-Request-Id` | UUID | APIM request ID for cross-system trace correlation |

## Setting Headers from Agent Code

```python
import httpx
from agent_os.integrations.citadel.identity_bridge import TrustRiskLabel

headers = {
    "X-AGT-Trust-Score": str(current_trust_score),
    "X-AGT-Risk-Label": TrustRiskLabel.from_score(current_trust_score).value,
    "X-AGT-Policy-Bundle": policy_bundle.bundle_id,
    "X-AGT-Policy-Version": policy_bundle.version,
    "X-AGT-Decision-Id": decision_id,
}

response = httpx.post(
    "https://apim-gateway.azure-api.net/openai/deployments/gpt-4o/chat/completions",
    headers={**auth_headers, **headers},
    json=payload,
)

# Read back the APIM request ID for correlation
apim_request_id = response.headers.get("X-AGT-APIM-Request-Id", "")
```

## Deploying the Fragment

### Via Azure CLI

```bash
az apim api-management named-value create \
    --resource-group <rg> \
    --service-name <apim> \
    --named-value-id agt-governance-metadata \
    --display-name "AGT Governance Metadata Fragment" \
    --value "$(cat agt-governance-metadata.xml)"
```

### Via Bicep

The fragment can be deployed as part of your Citadel infrastructure:

```bicep
resource agtFragment 'Microsoft.ApiManagement/service/policyFragments@2023-09-01-preview' = {
  parent: apimService
  name: 'agt-governance-metadata'
  properties: {
    description: 'AGT governance metadata passthrough for agent trust correlation'
    format: 'rawxml'
    value: loadTextContent('policies/agt-governance-metadata.xml')
  }
}
```

## Optional: Trust Threshold Blocking

The fragment includes a commented-out section that blocks requests from agents with an `untrusted` risk label. To enable:

1. Uncomment the `<choose>` block in the inbound section of `agt-governance-metadata.xml`
2. Customize the threshold (default: block `untrusted`, allow `degraded` and `trusted`)
3. Test with a non-production subscription first

This is a **coarse-grained safety net**, not a replacement for AGT's fine-grained policy evaluation.
