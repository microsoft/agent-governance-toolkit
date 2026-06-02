# Foundry AI Gateway + Azure Functions PDP

> Status: **experimental reference sample**. Tracks
> [RFC #2470](https://github.com/microsoft/agent-governance-toolkit/issues/2470)
> and [ADR-0026](../../docs/adr/0026-foundry-ai-gateway-functions-pdp.md).

This example shows how to keep Microsoft Foundry prompt-based agent traffic
inside a single governance boundary by using:

- **AI Gateway (Azure API Management)** as the Policy Enforcement Point (PEP),
- **Azure Functions** as the Policy Decision Point (PDP),
- a small **versioned decision contract** so policy logic can evolve without
  breaking deployed gateway policy.

It is intentionally minimal: one APIM policy fragment, one Python Function,
one Bicep template, and a tiny latency harness so you can validate your own
SLO before adopting the pattern.

## Architecture

```
Foundry prompt-based agent
        │
        │ model.invoke / tool.invoke
        ▼
┌──────────────────────────┐         ┌──────────────────────────┐
│   AI Gateway (APIM)      │  POST   │  Azure Function (PDP)    │
│   - PEP                  │ ───────▶│  /api/decide             │
│   - send-request policy  │ ◀───────│  decision contract v1.0  │
│   - fail-closed default  │         └──────────────────────────┘
└─────────────┬────────────┘
              │ allow / deny / allow_with_conditions / require_approval
              ▼
        Foundry / MCP tool / model
```

MCP traffic is kept inside the gateway by registering the APIM URL as the MCP
server endpoint surfaced to Foundry, so backend tool invocations traverse the
same PEP as model traffic. See ADR-0026 for the rationale and the
non-recommended fallback (sidecar MCP proxy).

## Decision contract (v1.0)

**Request** (APIM ➜ Function):

```json
{
  "schemaVersion": "1.0",
  "agentId": "agent-7f3c",
  "callerIdentity": "user@contoso.com",
  "tenantId": "00000000-0000-0000-0000-000000000000",
  "environment": "prod",
  "operation": "tool.invoke",
  "target": "github.create_issue",
  "inputDigest": "sha256:9af1...",
  "correlationId": "c-abc123",
  "traceparent": "00-..."
}
```

`inputDigest` is a SHA-256 of the prompt or tool arguments. The raw text is
**not** sent by default; PDPs that need it must opt in explicitly and accept
the data-handling obligations.

**Response** (Function ➜ APIM):

```json
{
  "decision": "allow_with_conditions",
  "reasonCode": "tool.allowlisted.with_approval",
  "conditions": ["require_human_review"],
  "auditAnnotations": {"risk": "medium"},
  "ttlSeconds": 30
}
```

`decision` ∈ `allow` | `deny` | `allow_with_conditions` | `require_approval`.
`ttlSeconds` is a hint that the gateway may use to cache identical decisions
keyed by `(agentId, operation, target, inputDigest)`.

## Failure semantics

The gateway **fails closed** on:

- transport error or timeout to the Function,
- non-2xx response,
- response schema mismatch (missing/unknown `decision`),
- any non-`allow*` decision.

Fail-open is supported only as an explicit per-route opt-in
(`pdp-fail-open="true"` named-value) and must be scoped to non-sensitive
operations. The default policy in this sample fails closed.

## Layout

```
foundry-ai-gateway-pdp/
├── README.md                 # this file
├── azure.yaml                # azd config
├── infra/
│   └── main.bicep            # APIM + Function App + managed identity
├── policy/
│   └── pdp-callout.xml       # APIM policy fragment (send-request to PDP)
├── function/
│   ├── host.json
│   ├── requirements.txt
│   └── decide/
│       ├── __init__.py       # HTTP-triggered PDP
│       └── function.json
└── load/
    └── harness.py            # latency / SLO smoke test
```

## Run it

Prerequisites: `azd`, `func` Core Tools, Python 3.11+, an Azure subscription,
and an **Entra ID app registration** to front the PDP via Easy Auth (capture
its Application/Client ID — you'll pass it as `pdpAadAppId`).

```bash
cd examples/foundry-ai-gateway-pdp
azd env new agt-pdp-dev
azd env set PDP_AAD_APP_ID <your-entra-app-client-id>
azd up                        # provisions APIM + Function App + Easy Auth
azd deploy pdp                # deploys the PDP code

# Smoke-test the PDP directly (requires a host key + Entra token):
python load/harness.py --url https://<fn-host>/api/decide --rps 20 --duration 30
```

Expected: p50 latency under ~25 ms added by the PDP hop on a Premium plan
with a warm instance; `deny` and `require_approval` decisions surfaced as
`403` and `202` respectively at the gateway.

> **Note on APIM API wiring.** The Bicep template provisions APIM and the
> named values (`pdp-base-url`, `pdp-aad-audience`, `pdp-environment`,
> `pdp-fail-open`) consumed by [`policy/pdp-callout.xml`](policy/pdp-callout.xml).
> Importing your Foundry / model / MCP API into APIM and attaching the
> policy fragment is a deliberate manual step — production deployments
> already own that API definition, and we don't want this sample to fight
> with it. The fragment is drop-in: paste it into the `<inbound>` section
> of the API or operation policy that fronts Foundry traffic.

## Security posture

- APIM authenticates to the Function with its **system-assigned managed
  identity** and **Easy Auth (Microsoft Entra ID)**. Function keys are
  **not** used and are disabled in the Bicep template.
- Only the digest of prompt/tool input crosses the PEP/PDP boundary by
  default.
- All decisions emit an audit record with `correlationId` and
  `traceparent`, so they can be reconstructed end-to-end.

## Not in scope (tracked as follow-ups)

- A first-class `integrations/foundry-ai-gateway/` component with a typed
  PDP SDK — deferred until the contract is exercised by design partners and
  aligned with the Foundry product team.
- Sidecar MCP proxy variant for environments where APIM cannot front MCP
  directly.
- Multi-region active/active PDP with regional cache replication.
