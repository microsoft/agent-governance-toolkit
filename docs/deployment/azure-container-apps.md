# Azure Container Apps Deployment

Deploy the Agent Governance Toolkit on Azure Container Apps for serverless, scale-to-zero agent governance.

> **See also:** [Deployment Overview](README.md) | [AKS Deployment](../../agent-governance-python/agent-mesh/docs/deployment/azure.md) | [Foundry Integration](azure-foundry-agent-service.md)

---

## Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Environment Setup](#environment-setup)
- [Deploy the Governance Sidecar](#deploy-the-governance-sidecar)
- [Configure Policies](#configure-policies)
- [Monitoring](#monitoring)
- [Scaling Configuration](#scaling-configuration)
- [Comparison with AKS](#comparison-with-aks)

---

## Architecture

Azure Container Apps runs the governance toolkit as a sidecar container alongside your agent container within a Container Apps Environment. Both containers share a network namespace and communicate over `localhost`.

```
┌─────────────────────────────────────────────────────┐
│  Container Apps Environment                          │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │  Container App                                 │  │
│  │  ┌──────────────────┐  ┌────────────────────┐ │  │
│  │  │  Agent Container  │  │  Governance        │ │  │
│  │  │                   │  │  Sidecar           │ │  │
│  │  │  Your AI agent    │  │  agent-os +        │ │  │
│  │  │  (any framework)  │  │  agentmesh +       │ │  │
│  │  │                   │  │  agent-sre         │ │  │
│  │  │  localhost:8080 ──────► localhost:8081     │ │  │
│  │  └──────────────────┘  └────────────────────┘ │  │
│  └────────────────────────────────────────────────┘  │
│                                                      │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────┐  │
│  │ Key Vault   │ │ Log Analytics│ │ Container    │  │
│  │             │ │ Workspace    │ │ Registry     │  │
│  └─────────────┘ └──────────────┘ └──────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## Prerequisites

- Azure CLI 2.60+ with the `containerapp` extension
- An Azure Container Registry (ACR) or access to a container registry
- Docker (for building images locally)

```bash
# Install/update the Container Apps extension
az extension add --name containerapp --upgrade
az provider register --namespace Microsoft.App
az provider register --namespace Microsoft.OperationalInsights
```

---

## Environment Setup

### 1. Create the Container Apps Environment

```bash
RESOURCE_GROUP="rg-agent-governance"
LOCATION="eastus"
ENVIRONMENT="agent-gov-env"
REGISTRY="agentgovregistry"

# Resource group
az group create --name $RESOURCE_GROUP --location $LOCATION

# Container registry
az acr create --name $REGISTRY --resource-group $RESOURCE_GROUP --sku Basic --admin-enabled true

# Log Analytics workspace (for governance metrics)
az monitor log-analytics workspace create \
  --resource-group $RESOURCE_GROUP \
  --workspace-name agent-gov-logs

LOG_ANALYTICS_ID=$(az monitor log-analytics workspace show \
  --resource-group $RESOURCE_GROUP \
  --workspace-name agent-gov-logs \
  --query customerId -o tsv)

LOG_ANALYTICS_KEY=$(az monitor log-analytics workspace get-shared-keys \
  --resource-group $RESOURCE_GROUP \
  --workspace-name agent-gov-logs \
  --query primarySharedKey -o tsv)

# Container Apps environment
az containerapp env create \
  --name $ENVIRONMENT \
  --resource-group $RESOURCE_GROUP \
  --logs-workspace-id $LOG_ANALYTICS_ID \
  --logs-workspace-key $LOG_ANALYTICS_KEY \
  --location $LOCATION
```

### 2. Build and Push the Governance Sidecar Image

```bash
# From the repo root
cd agent-os

# Build the governance sidecar image
docker build -t $REGISTRY.azurecr.io/agent-governance-sidecar:latest .

# Push to ACR
az acr login --name $REGISTRY
docker push $REGISTRY.azurecr.io/agent-governance-sidecar:latest
```

---

## Deploy the Governance Sidecar

### 3. Deploy with Sidecar Pattern

Azure Container Apps supports [sidecar containers](https://learn.microsoft.com/azure/container-apps/containers#sidecar-containers) natively. The governance toolkit runs as a sidecar alongside your agent.

```bash
az containerapp create \
  --name my-governed-agent \
  --resource-group $RESOURCE_GROUP \
  --environment $ENVIRONMENT \
  --image your-registry.azurecr.io/your-agent:latest \
  --target-port 8080 \
  --ingress external \
  --min-replicas 0 \
  --max-replicas 10 \
  --registry-server $REGISTRY.azurecr.io \
  --yaml container-app.yaml
```

**`container-app.yaml`:**

```yaml
properties:
  configuration:
    ingress:
      external: true
      targetPort: 8080
    registries:
      - server: agentgovregistry.azurecr.io
        identity: system
  template:
    containers:
      # Primary: Your AI agent
      - name: agent
        image: agentgovregistry.azurecr.io/your-agent:latest
        resources:
          cpu: 1.0
          memory: 2Gi
        env:
          - name: GOVERNANCE_ENDPOINT
            value: http://localhost:8081
          - name: AGENT_ID
            value: my-agent-001

      # Sidecar: Governance toolkit
      - name: governance-sidecar
        image: agentgovregistry.azurecr.io/agent-governance-sidecar:latest
        resources:
          cpu: 0.25
          memory: 0.5Gi
        env:
          - name: POLICY_DIR
            value: /policies
          - name: OTEL_EXPORTER_OTLP_ENDPOINT
            value: http://localhost:4318
          - name: TRUST_SCORE_THRESHOLD
            value: "0.6"
          - name: RATE_LIMIT_PER_MINUTE
            value: "100"
        volumeMounts:
          - volumeName: policy-volume
            mountPath: /policies

    scale:
      minReplicas: 0
      maxReplicas: 10
      rules:
        - name: http-rule
          http:
            metadata:
              concurrentRequests: "50"

    volumes:
      - name: policy-volume
        storageType: AzureFile
        storageName: policy-share
```

---

## Configure Policies

### 4. Mount Policies via Azure Files

Store governance policies in Azure Files and mount them into the sidecar:

```bash
# Create storage account and file share
az storage account create \
  --name agentgovpolicies \
  --resource-group $RESOURCE_GROUP \
  --sku Standard_LRS

az storage share create \
  --name policies \
  --account-name agentgovpolicies

# Upload your policy files
az storage file upload-batch \
  --destination policies \
  --source ./policies/ \
  --account-name agentgovpolicies

# Link storage to Container Apps environment
az containerapp env storage set \
  --name $ENVIRONMENT \
  --resource-group $RESOURCE_GROUP \
  --storage-name policy-share \
  --azure-file-account-name agentgovpolicies \
  --azure-file-account-key $(az storage account keys list --account-name agentgovpolicies --query '[0].value' -o tsv) \
  --azure-file-share-name policies \
  --access-mode ReadOnly
```

### Example Policy (`policies/default.yaml`)

```yaml
version: "1.0"
policies:
  - name: rate-limit
    type: rate_limit
    max_calls: 100
    window: 1m

  - name: read-only
    type: capability
    allowed_actions:
      - "read_*"
      - "search_*"
      - "list_*"
    denied_actions:
      - "delete_*"
      - "write_production_*"

  - name: content-safety
    type: pattern
    blocked_patterns:
      - "ignore previous instructions"
      - "DROP TABLE"
      - "rm -rf"
```

---

## Monitoring

### 5. Governance Metrics in Log Analytics

The sidecar exports OpenTelemetry metrics to the Container Apps environment's Log Analytics workspace automatically.

**Query governance events:**

```kql
ContainerAppConsoleLogs_CL
| where ContainerName_s == "governance-sidecar"
| where Log_s contains "policy_decision"
| project TimeGenerated, Log_s
| order by TimeGenerated desc
| take 100
```

**Query policy violations:**

```kql
ContainerAppConsoleLogs_CL
| where ContainerName_s == "governance-sidecar"
| where Log_s contains "DENIED"
| summarize ViolationCount = count() by bin(TimeGenerated, 1h)
| render timechart
```

---

## Scaling Configuration

Container Apps scales both the agent and governance sidecar together. Key scaling considerations:

| Setting | Recommendation | Notes |
|---------|---------------|-------|
| `minReplicas` | `0` for dev, `2` for prod | Scale-to-zero saves cost in dev |
| `maxReplicas` | Based on load | Each replica includes both containers |
| Sidecar CPU | `0.25` cores | Governance adds < 0.1ms p99 latency |
| Sidecar Memory | `512Mi` | Sufficient for policy engine + trust scoring |

---

## Comparison with AKS

| Capability | Container Apps | AKS |
|-----------|---------------|-----|
| Operational complexity | Low (serverless) | Higher (cluster management) |
| Scale-to-zero | ✅ Native | ❌ Requires KEDA |
| Helm chart support | ❌ YAML only | ✅ Full Helm |
| Custom networking | Limited | Full VNet control |
| Multi-agent mesh | Basic | ✅ Full AgentMesh with IATP |
| Best for | Single agents, prototyping | Production multi-agent systems |

For production multi-agent systems with full AgentMesh identity and IATP, we recommend [AKS deployment](../../agent-governance-python/agent-mesh/docs/deployment/azure.md).

---

## Next Steps

- [Configure governance policies](../../agent-governance-python/agent-os/docs/policy-schema.md)
- [Set up AgentMesh identity](../../agent-governance-python/agent-mesh/README.md)
- [Enable SLO monitoring](../../agent-governance-python/agent-sre/README.md)
- [AKS deployment](../../agent-governance-python/agent-mesh/docs/deployment/azure.md) for production multi-agent scenarios
