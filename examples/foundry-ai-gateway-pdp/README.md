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

The shipped policy fragment enforces **no** conditions. It forwards
`allow_with_conditions` only when `conditions` is empty; any listed condition
is treated as unenforceable and the request is denied (`403`, decision
`deny_unenforced_conditions`). Use `require_approval` for human review, or
extend step 4 of [`pdp-callout.xml`](policy/pdp-callout.xml) before returning
conditions from your PDP.

## Failure semantics

The gateway **fails closed** on:

- transport error or timeout to the Function,
- non-2xx response,
- response schema mismatch (missing/unknown `decision`),
- any decision other than `allow` (including `allow_with_conditions` with
  conditions the gateway does not enforce).

The `pdp-fail-open="true"` named value only annotates PDP transport failures
with `x-agt-pdp-failmode: fail-open`; the shipped fragment still denies the
request because no decision was received. Enabling real fail-open requires an
explicit edit to step 4 of the fragment, scoped to non-sensitive operations.

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

## Coexistence with Agent 365 and AI Gateway protections

The Ignite 2026 wave added platform controls at the same gateway. They are
complementary to this PDP, not replacements:

| Control | Where it runs | Relationship to this PDP |
|---|---|---|
| AI Gateway **tool threat protection** (Defender + Purview; modes Disabled / Audit / Block) | APIM, on MCP tool traffic | Detects prompt injection and sensitive-data movement. Keep it on; this PDP adds deterministic, organisation-specific allow/deny decisions. |
| Foundry **guardrails** (user input, tool call, tool response, output) | Foundry agent service | Model-level content safety. Map them to ACS `input`, `pre_tool_call`, `post_tool_call` and `output` when you also run AGT inside the agent. |
| Agent 365 **Tools Gateway** (bring-your-own MCP servers registered with the A365 CLI, preview) | Agent 365 | Registers MCP servers for governed discovery. Register the **APIM URL** that carries this PDP fragment, not the raw backend, so tool calls still traverse the PEP. |
| Copilot Studio **external threat detection** | Copilot Studio orchestrator | For Copilot Studio agents, use [`agentmesh-agent365`](../../agent-governance-python/agentmesh-integrations/agent365-agentmesh/) to answer `/analyze-tool-execution` with AGT policy. |

Order the APIM policies so platform threat protection runs first and this PDP
call runs before the backend call; a request blocked by either is not
forwarded.

The PDP decision logic in `function/decide/__init__.py` is a placeholder
(hard-coded tool lists). For real policy, evaluate an ACS manifest with the
AGT policy runtime inside the Function, or call an AGT `MCPGateway` the way
`agentmesh-agent365` does.

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
