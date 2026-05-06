# Citadel + AGT Integration Architecture

This document describes how the Agent Governance Toolkit (AGT) integrates with
the [Foundry Citadel Platform](https://aka.ms/foundry-citadel), Microsoft's
layered architecture for AI governance.

## Positioning

Citadel and AGT address **different enforcement boundaries** that are complementary,
not competing:

| Concern | Citadel (Gateway) | AGT (Agent Runtime) |
|---------|-------------------|---------------------|
| **What it governs** | Model/tool/agent access at the infrastructure perimeter | Individual agent actions, tool calls, inter-agent messages |
| **Enforcement point** | APIM gateway (centralized) | Agent runtime sidecar/library (local) |
| **Latency model** | Network hop through gateway | Sub-millisecond in-process evaluation |
| **Policy granularity** | Coarse: rate limits, content filters, quotas, JWT validation | Fine: per-action allow/deny, capability model, caller restrictions |
| **Identity model** | Entra ID / subscription keys | Ed25519 / SPIFFE cryptographic identity |
| **Audit target** | Event Hub / App Insights / Log Analytics | Hash-chain audit logs (exportable to Azure Monitor) |

## How AGT Maps to Citadel's 4 Layers

AGT is not confined to a single Citadel layer. It spans the architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Foundry Citadel Platform                      │
│                                                                 │
│  Layer 4: Security Fabric (Defender, Purview, Entra)            │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  AGT trust scores surface as risk labels in Defender    │    │
│  │  AGT data_classification aligns with Purview labels     │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  Layer 3: Agent Identity (Agent 365 / Entra)                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  AGT agent identities federate with Entra agent IDs     │    │
│  │  Entra = enterprise identity, AGT = runtime credentials │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  Layer 2: AI Control Plane (Foundry Control Plane)              │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  AGT exports governance evidence and traces             │    │
│  │  Policy decisions enrich Foundry/OTEL traces            │    │
│  │  Fleet-wide compliance visibility via Azure Monitor     │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  Layer 1: Governance Hub (APIM Gateway)                         │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Access Contracts reference AGT policy bundles          │    │
│  │  AGT metadata headers pass through APIM for correlation │    │
│  │  Gateway = coarse rules, AGT = action-level rules       │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Layer 1: Governance Hub

Citadel's APIM gateway enforces infrastructure-level controls: which models an
agent can access, at what rate, with what content safety filters. AGT integrates
through **Access Contract policy bundle binding**: when a Citadel Access Contract
provisions an agent environment, it references an AGT policy bundle ID/version.
The agent runtime loads this bundle at startup.

**Policy precedence**: Gateway rules (rate limits, content filters, JWT) are
enforced first at the APIM layer. AGT action-level policies are enforced second,
inside the agent runtime. Both must pass for an action to proceed.

### Layer 2: AI Control Plane

AGT's primary Layer 2 contribution is **governance evidence and trace enrichment**.
The `CitadelAuditExporter` sends policy decisions, trust score changes, and
action interception events to Azure Event Hub and Application Insights. These
events include correlation IDs that tie AGT decisions to APIM request traces
and Foundry execution traces, enabling unified observability dashboards.

### Layer 3: Agent Identity

Entra ID / Agent 365 remains the authoritative source for enterprise agent
identity and lifecycle management. AGT's Ed25519/SPIFFE identities remain
authoritative for runtime cryptographic credentials. The integration is
**federation, not replacement**: AGT trust scores (0-1000) surface as risk
labels in telemetry, not as primary Entra metadata.

### Layer 4: Security Fabric

AGT's `data_classification` labels on policies align with Purview sensitivity
labels. AGT trust scores can surface as risk signals in Defender for AI. This
integration is primarily through the telemetry pipeline (Layer 2 export) rather
than direct API integration.

## Data Flow

```
Agent Runtime                    Citadel Gateway              Azure Monitor
┌──────────────────┐            ┌──────────────────┐         ┌──────────────┐
│                  │            │                  │         │              │
│  Agent Code      │   LLM     │  APIM Gateway    │         │  App Insights│
│  ┌────────────┐  │  request  │  ┌────────────┐  │         │              │
│  │ AGT Policy ├──┼──────────►│  │ Rate Limit ├──┼────►LLM │  Event Hub   │
│  │ Engine     │  │           │  │ Content    │  │         │              │
│  │            │  │           │  │ JWT Auth   │  │         │  Log         │
│  │ Decision:  │  │           │  └────────────┘  │         │  Analytics   │
│  │ allow/deny │  │           │                  │         │              │
│  └─────┬──────┘  │           └──────────────────┘         └──────┬───────┘
│        │         │                                               │
│  ┌─────▼──────┐  │           ┌──────────────────┐               │
│  │ Citadel    ├──┼──────────►│  Event Hub /      │───────────────┘
│  │ Audit      │  │  events   │  App Insights     │
│  │ Exporter   │  │           └──────────────────┘
│  └────────────┘  │
└──────────────────┘
```

1. Agent action triggers AGT policy evaluation (sub-millisecond, in-process)
2. If allowed, the request passes through the Citadel APIM gateway
3. APIM enforces gateway-level policies (rate limit, content filter, JWT)
4. AGT audit exporter sends governance events to Azure Event Hub / App Insights
5. Events include correlation IDs linking AGT decision to APIM request trace

## Policy Bundle Binding

Citadel Access Contracts use `.bicepparam` files to declare what resources an
agent environment can access. AGT extends this with a policy bundle reference:

```bicep
// In the Access Contract .bicepparam file
param agtPolicyBundle object = {
  bundleId: 'customer-support-v2'
  version: '1.3.0'
  source: 'https://vault.azure.net/secrets/agt-policy-bundle'
}
```

At deployment time, the policy bundle is fetched and injected into the agent
environment. The AGT runtime loads it at startup via `PolicyBundleResolver`.

## Coverage Boundaries

Understanding what each system handles avoids duplication:

| Concern | Handled By |
|---------|-----------|
| LLM model access control | Citadel Layer 1 (APIM products/subscriptions) |
| Token rate limiting | Citadel Layer 1 (APIM policies) |
| Content safety filtering | Citadel Layer 1 (Azure Content Safety) |
| PII detection at gateway | Citadel Layer 1 (Azure Language Service) |
| Per-action policy evaluation | AGT Policy Engine |
| Tool call allow/deny | AGT Capability Model |
| Agent-to-agent trust | AGT Trust Layer (Ed25519, SPIFFE) |
| Trust scoring (0-1000) | AGT AgentMesh |
| Hash-chain audit logs | AGT Audit System |
| Fleet observability | Citadel Layer 2 + AGT Exporter |
| Agent enterprise identity | Citadel Layer 3 (Entra) |
| Agent runtime credentials | AGT (Ed25519/SPIFFE) |
| Threat detection | Citadel Layer 4 (Defender) |
| Data governance labels | Citadel Layer 4 (Purview) + AGT data_classification |

## Failure Modes

| Component Unavailable | Behavior |
|----------------------|----------|
| Azure Event Hub / App Insights | AGT continues operating. Events queue locally and retry on reconnection. Fail-open for telemetry. |
| Citadel APIM Gateway | Agent cannot reach LLM/tools. AGT policy engine still operational locally. |
| AGT Policy Engine | Agent actions proceed ungoverned (fail-open by default, configurable to fail-closed). |
| Entra ID | AGT uses local cryptographic identity. Enterprise identity federation paused. |

## Getting Started

1. **Deploy Citadel Governance Hub**: Follow the [Citadel quickstart](https://github.com/Azure-Samples/ai-hub-gateway-solution-accelerator/tree/citadel-v1)
2. **Install AGT**: `pip install agent-governance-toolkit`
3. **Configure the exporter**: Set `CITADEL_EVENTHUB_CONNECTION_STRING` and `CITADEL_APPINSIGHTS_CONNECTION_STRING`
4. **See the example**: [`examples/citadel-governed-agent/`](../../examples/citadel-governed-agent/)

## References

- [Foundry Citadel Platform](https://aka.ms/foundry-citadel): Full 4-layer architecture
- [Citadel Governance Hub](https://github.com/Azure-Samples/ai-hub-gateway-solution-accelerator/tree/citadel-v1): Layer 1 reference implementation
- [Citadel Access Contracts](https://github.com/Azure-Samples/ai-hub-gateway-solution-accelerator/tree/citadel-v1/bicep/infra/citadel-access-contracts): Contract-based onboarding
- [Agent 365 / Entra Agent Governance](https://learn.microsoft.com/en-us/entra/id-governance/agent-id-governance-overview): Layer 3
- [AGT Architecture](../ARCHITECTURE.md): AGT system design
