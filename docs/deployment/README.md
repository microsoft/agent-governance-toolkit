# Azure Deployment Guides

Deploy the Agent Governance Toolkit on Azure for production-grade runtime security governance of AI agents.

> **Quick start:** `pip install agent-governance-toolkit[full]` — see the [main README](../../README.md) for local development.

---

## Deployment Options

| Scenario | Guide | Best For |
|----------|-------|----------|
| **Azure Kubernetes Service (AKS)** | [AKS Sidecar Deployment](../../packages/agent-mesh/docs/deployment/azure.md) | Production workloads needing full control over infrastructure, multi-agent systems, enterprise-grade HA |
| **Azure AI Foundry Agent Service** | [Foundry Integration](azure-foundry-agent-service.md) | Teams building agents with Azure AI Foundry who want governance as middleware |
| **Azure Container Apps** | [Container Apps Deployment](azure-container-apps.md) | Serverless container workloads, rapid prototyping, scale-to-zero scenarios |
| **OpenClaw on AKS** | [OpenClaw Sidecar](openclaw-sidecar.md) | Securing OpenClaw autonomous agents with governance guardrails |

---

## Architecture Overview

The toolkit supports three primary deployment patterns on Azure:

```
┌─────────────────────────────────────────────────────────────────┐
│  Azure                                                          │
│                                                                 │
│  ┌─────────────────┐  ┌──────────────────┐  ┌───────────────┐  │
│  │ AKS             │  │ Container Apps   │  │ Foundry Agent │  │
│  │                 │  │                  │  │ Service       │  │
│  │ ┌─────┐┌─────┐ │  │ ┌─────┐┌──────┐ │  │               │  │
│  │ │Agent││Gov  │ │  │ │Agent││Gov   │ │  │  ┌─────────┐  │  │
│  │ │     ││Side-│ │  │ │     ││Init/ │ │  │  │Governance│  │  │
│  │ │     ││car  │ │  │ │     ││Side  │ │  │  │Middleware│  │  │
│  │ └─────┘└─────┘ │  │ └─────┘└──────┘ │  │  └─────────┘  │  │
│  │  Pod            │  │  Container Group │  │   In-Process  │  │
│  └─────────────────┘  └──────────────────┘  └───────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Shared: Azure Key Vault │ Azure Monitor │ Managed ID    │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Which Option Should I Choose?

**Choose AKS if:**
- You need full control over networking, scaling, and pod configuration
- You're running multi-agent systems with sidecar-per-agent governance
- You require enterprise features: managed identity, Key Vault, zone-redundant HA
- You're deploying OpenClaw or other containerized autonomous agents

**Choose Azure AI Foundry Agent Service if:**
- You're already building agents with Azure AI Foundry
- You want governance as in-process middleware (no sidecar overhead)
- You prefer a managed service over managing Kubernetes infrastructure

**Choose Azure Container Apps if:**
- You want serverless scaling (including scale-to-zero)
- You're running single-agent or small-scale multi-agent scenarios
- You want a simpler operational model than Kubernetes
- You're prototyping before moving to AKS for production

---

## Other Cloud Platforms

| Cloud | Guide |
|-------|-------|
| AWS (EKS/ECS) | [AWS Deployment](../../packages/agent-mesh/docs/deployment/aws.md) |
| GCP (GKE) | [GCP Deployment](../../packages/agent-mesh/docs/deployment/gcp.md) |
| Generic Kubernetes | [Kubernetes Guide](../../packages/agent-mesh/docs/deployment/kubernetes.md) |

---

## Common Azure Resources

All deployment options benefit from these Azure services:

- **Azure Key Vault** — Store agent private keys, DID secrets, and policy signing keys
- **Azure Monitor / Container Insights** — Collect governance metrics via OpenTelemetry
- **Managed Identity** — Authenticate to Azure services without credentials in code
- **Azure Event Grid** — React to governance events (policy violations, trust score changes)

See the [AKS guide](../../packages/agent-mesh/docs/deployment/azure.md) for detailed setup of each.
