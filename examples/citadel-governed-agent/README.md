# Citadel + AGT Governed Agent Example

This example demonstrates an AI agent that uses both **Citadel** (gateway-level
governance) and **AGT** (agent-level governance) working together.

## Architecture

```
┌──────────────────────────┐       ┌──────────────────────┐
│  Agent Runtime           │       │  Citadel APIM        │
│                          │       │  Gateway             │
│  ┌────────────────────┐  │       │                      │
│  │ AGT Policy Engine  │  │       │  - Rate limiting     │
│  │ - Action allow/deny│  │       │  - Content filtering │
│  │ - Trust scoring    │  │       │  - JWT validation    │
│  │ - Audit logging    │  │       │  - Cost attribution  │
│  └────────┬───────────┘  │       └──────────┬───────────┘
│           │              │                  │
│  ┌────────▼───────────┐  │  LLM request    │
│  │ Governed Agent     ├──┼─────────────────►│──────► LLM
│  │ (OpenAI / SK)      │  │                  │
│  └────────────────────┘  │                  │
│                          │       ┌──────────┴───────────┐
│  ┌────────────────────┐  │       │  Azure Event Hub /   │
│  │ Citadel Exporter   ├──┼──────►│  App Insights        │
│  └────────────────────┘  │       └──────────────────────┘
└──────────────────────────┘
```

## What This Example Shows

1. **Policy enforcement**: Agent actions are evaluated against an AGT policy
   bundle before execution. Blocked actions are logged and denied.
2. **Gateway integration**: LLM calls route through a Citadel APIM gateway
   (or mock gateway for local testing).
3. **Audit export**: Governance events flow to Azure Event Hub / Application
   Insights via the `CitadelAuditExporter`.
4. **Policy bundle binding**: The agent loads its policy bundle from a file
   that would normally be injected by a Citadel Access Contract deployment.
5. **Trust scoring**: Trust scores change based on agent behavior and
   policy compliance.

## Prerequisites

```bash
pip install agent-governance-toolkit
```

For Azure integration (optional, not needed for local mock mode):
```bash
pip install azure-eventhub azure-monitor-opentelemetry-exporter
```

## Running the Example

### Local mode (no Azure required)

```bash
python src/agent.py --mock
```

This uses a mock gateway and mock exporter to demonstrate the governance
flow without any Azure dependencies.

### With Citadel gateway

```bash
export CITADEL_GATEWAY_URL=https://your-apim.azure-api.net
export CITADEL_API_KEY=your-subscription-key
export CITADEL_EVENTHUB_CONNECTION_STRING=Endpoint=sb://...
python src/agent.py
```

## Files

| File | Description |
|------|-------------|
| `src/agent.py` | Main governed agent with AGT policy engine |
| `src/citadel_config.py` | Citadel gateway configuration and helpers |
| `policies/agent-policy.yaml` | AGT policy bundle for this agent |
| `sample-access-contract/main.bicepparam` | Sample Citadel Access Contract with AGT binding |
| `apim-policies/agt-governance-metadata.xml` | APIM policy fragment for governance metadata passthrough |
| `apim-policies/agt-governed-product-policy.xml` | Sample product policy using the fragment |
| `apim-policies/README.md` | APIM policy deployment and usage guide |

## Policy Precedence

This example demonstrates the two-layer policy model:

1. **Citadel gateway** enforces coarse rules first:
   - Rate limits (e.g., 100 calls/hour)
   - Content safety filters
   - JWT / subscription key validation

2. **AGT policy engine** enforces fine-grained rules second:
   - Per-action allow/deny (e.g., block `delete_record` action)
   - Caller restrictions (only specific agents can invoke certain tools)
   - Data classification constraints
   - Justification requirements

Both layers must pass for an action to proceed.

## Related

- [Citadel + AGT Integration Architecture](../../docs/integrations/citadel-integration.md)
- [Foundry Citadel Platform](https://aka.ms/foundry-citadel)
- [AGT Documentation](https://github.com/microsoft/agent-governance-toolkit)
