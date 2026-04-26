# Azure Deployment Guide

Deploying AgentMesh on Microsoft Azure using AKS, Managed Identity, Key Vault, and Azure Monitor.

> **See also:** [Kubernetes Guide](kubernetes.md) for general K8s patterns, [AWS](aws.md) and [GCP](gcp.md) for other clouds.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [AKS Cluster Setup](#aks-cluster-setup)
- [Managed Identity Integration](#managed-identity-integration)
- [Secrets Management with Key Vault](#secrets-management-with-key-vault)
- [Monitoring with Azure Monitor](#monitoring-with-azure-monitor)
- [High Availability Topology](#high-availability-topology)
- [Network Security](#network-security)
- [Common Patterns](#common-patterns)

---

## Architecture Overview

```
┌──────────────────────────────────────────────────┐
│  Azure Region                                    │
│  ┌────────────────────────────────────────────┐  │
│  │  VNet                                      │  │
│  │  ┌──────────────┐  ┌────────────────────┐ │  │
│  │  │ AKS Cluster  │  │ Azure Cache for    │ │  │
│  │  │              │  │ Redis              │ │  │
│  │  │ ┌──────────┐ │  └────────────────────┘ │  │
│  │  │ │AgentMesh │ │  ┌────────────────────┐ │  │
│  │  │ │ Server   │ │  │ Azure Database for │ │  │
│  │  │ ├──────────┤ │  │ PostgreSQL         │ │  │
│  │  │ │AgentMesh │ │  └────────────────────┘ │  │
│  │  │ │ Sidecar  │ │                         │  │
│  │  │ └──────────┘ │  ┌────────────────────┐ │  │
│  │  └──────────────┘  │ Azure Key Vault    │ │  │
│  │                     └────────────────────┘ │  │
│  │                     ┌────────────────────┐ │  │
│  │                     │ Azure Monitor /    │ │  │
│  │                     │ Event Grid         │ │  │
│  │                     └────────────────────┘ │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

---

## Prerequisites

- **Azure CLI** (`az`) configured with appropriate subscription
- **kubectl** configured for your AKS cluster
- **Helm 3.x** for chart-based deployment

## Container Images

All AgentMesh container images are published to GitHub Container Registry (GHCR) and support `linux/amd64` and `linux/arm64`:

| Component | Image | Port |
|-----------|-------|------|
| Trust Engine | `ghcr.io/microsoft/agentmesh/trust-engine` | 8443 |
| Policy Server | `ghcr.io/microsoft/agentmesh/policy-server` | 8444 |
| Audit Collector | `ghcr.io/microsoft/agentmesh/audit-collector` | 8445 |
| API Gateway | `ghcr.io/microsoft/agentmesh/api-gateway` | 8446 |
| Governance Sidecar | `ghcr.io/microsoft/agentmesh/governance-sidecar` | 8081 |

```bash
# Pull images (use specific version tags in production)
docker pull ghcr.io/microsoft/agentmesh/trust-engine:latest
docker pull ghcr.io/microsoft/agentmesh/governance-sidecar:latest
```

> **Using your own ACR?** Mirror the images: `az acr import --name <your-acr> --source ghcr.io/microsoft/agentmesh/trust-engine:latest`

---

## AKS Cluster Setup

### Create Resource Group and Cluster

```bash
# Create resource group
az group create \
  --name agentmesh-rg \
  --location eastus

# Create AKS cluster with managed identity
az aks create \
  --resource-group agentmesh-rg \
  --name agentmesh-prod \
  --node-count 3 \
  --node-vm-size Standard_D4s_v5 \
  --enable-managed-identity \
  --enable-workload-identity \
  --enable-oidc-issuer \
  --network-plugin azure \
  --network-policy calico \
  --zones 1 2 3 \
  --generate-ssh-keys
```

### Recommended Node Configuration

| Component | VM Size | Min Nodes | Required? |
|-----------|---------|-----------|-----------|
| AgentMesh Server | Standard_D4s_v5 | 2 | Yes (full cluster) / No (sidecar) |
| AgentMesh Sidecar | Runs in agent pods | — | Yes (sidecar mode) |
| Redis | Azure Cache Premium P1 | 1 | Optional — for shared session state |
| PostgreSQL | General Purpose D4s_v3 | 1 | Optional — for persistent audit logs |

> **Which components do I need?** For the **sidecar pattern** (one governance instance per agent pod), you only need the sidecar container and a policy ConfigMap — no Redis, no PostgreSQL, no separate server. For the **full cluster pattern** (centralized governance serving many agents), deploy all components.

---

## Managed Identity Integration

Use [AKS Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview) to authenticate AgentMesh pods to Azure services without storing credentials.

### 1. Create User-Assigned Managed Identity

```bash
az identity create \
  --resource-group agentmesh-rg \
  --name agentmesh-identity
```

### 2. Create Federated Credential

```bash
AKS_OIDC_ISSUER=$(az aks show \
  --resource-group agentmesh-rg \
  --name agentmesh-prod \
  --query "oidcIssuerProfile.issuerUrl" -o tsv)

az identity federated-credential create \
  --name agentmesh-fed-cred \
  --identity-name agentmesh-identity \
  --resource-group agentmesh-rg \
  --issuer "$AKS_OIDC_ISSUER" \
  --subject system:serviceaccount:agentmesh:agentmesh-sa \
  --audience api://AzureADTokenExchange
```

### 3. Create Kubernetes Service Account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: agentmesh-sa
  namespace: agentmesh
  annotations:
    azure.workload.identity/client-id: "<MANAGED_IDENTITY_CLIENT_ID>"
  labels:
    azure.workload.identity/use: "true"
```

### 4. Grant Roles

```bash
IDENTITY_PRINCIPAL_ID=$(az identity show \
  --resource-group agentmesh-rg \
  --name agentmesh-identity \
  --query principalId -o tsv)

# Key Vault access
az role assignment create \
  --assignee "$IDENTITY_PRINCIPAL_ID" \
  --role "Key Vault Secrets User" \
  --scope /subscriptions/SUB_ID/resourceGroups/agentmesh-rg/providers/Microsoft.KeyVault/vaults/agentmesh-kv

# Event Grid publisher
az role assignment create \
  --assignee "$IDENTITY_PRINCIPAL_ID" \
  --role "EventGrid Data Sender" \
  --scope /subscriptions/SUB_ID/resourceGroups/agentmesh-rg
```

---

## Secrets Management with Key Vault

### What Secrets Go in Key Vault?

| Secret | Purpose | Required? |
|---|---|---|
| **Ed25519 agent private keys** | Agent DID identity — signing trust handshakes | Yes, if using DID identity |
| **TLS cert/key** | mTLS between AgentMesh components | Yes, if TLS enabled |
| **Redis connection string** | Shared session cache for HA deployment | Only for full cluster mode |
| **PostgreSQL credentials** | Persistent audit log storage | Only for full cluster mode |

> **Sidecar-only deployments** (e.g., OpenClaw sidecar) typically need only the agent private key — or no secrets at all if you're using policy-only enforcement without DID identity.

### Create Key Vault

```bash
az keyvault create \
  --resource-group agentmesh-rg \
  --name agentmesh-kv \
  --location eastus \
  --enable-rbac-authorization
```

### Store Agent Private Keys

```bash
# Store Ed25519 private key (base64-encoded)
az keyvault secret set \
  --vault-name agentmesh-kv \
  --name agent-alpha-private-key \
  --value "<base64-encoded-ed25519-key>"
```

### Use Azure Key Vault CSI Driver

```yaml
# SecretProviderClass for AKS
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: agentmesh-secrets
  namespace: agentmesh
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    useVMManagedIdentity: "false"
    clientID: "<MANAGED_IDENTITY_CLIENT_ID>"
    keyvaultName: agentmesh-kv
    tenantId: "<TENANT_ID>"
    objects: |
      array:
        - |
          objectName: agent-alpha-private-key
          objectType: secret
```

---

## Monitoring with Azure Monitor

### Enable Container Insights

```bash
az aks enable-addons \
  --resource-group agentmesh-rg \
  --name agentmesh-prod \
  --addons monitoring \
  --workspace-resource-id /subscriptions/SUB_ID/resourceGroups/agentmesh-rg/providers/Microsoft.OperationalInsights/workspaces/agentmesh-logs
```

### Prometheus Metrics to Azure Monitor

AKS supports [managed Prometheus](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/prometheus-metrics-overview) with Azure Monitor workspace.

### Key Metrics to Monitor

| Metric | Alert Condition |
|--------|----------------|
| `agentmesh_trust_score` | Any agent drops below 300 |
| `agentmesh_policy_violations_total` | > 10 violations/min |
| `agentmesh_anomaly_detections_total` | Any HIGH severity detection |
| `agentmesh_credential_rotations_total` | Rotation failure |
| `agentmesh_handshake_duration_seconds` | p99 > 500 ms |

### Audit Log Export via Event Grid

```yaml
# AgentMesh config
audit:
  export:
    type: cloudevents
    target: azure_event_grid
    topic: /subscriptions/SUB_ID/resourceGroups/agentmesh-rg/providers/Microsoft.EventGrid/topics/agentmesh-audit
```

---

## High Availability Topology

### Multi-Zone Deployment

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│    Zone 1    │  │    Zone 2    │  │    Zone 3    │
│              │  │              │  │              │
│ AgentMesh    │  │ AgentMesh    │  │ AgentMesh    │
│ Server (1)   │  │ Server (1)   │  │ Server (1)   │
│              │  │              │  │              │
│ Redis Primary│  │ Redis Replica│  │              │
│ PG Primary   │  │ PG Standby   │  │ PG Read      │
└──────────────┘  └──────────────┘  └──────────────┘
```

- **AgentMesh Server:** ≥ 2 replicas with zone-aware pod anti-affinity
- **Redis:** Azure Cache Premium with zone redundancy
- **PostgreSQL:** Azure Database for PostgreSQL Flexible Server with zone-redundant HA

### Helm Values for HA

```yaml
replicaCount: 3

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          topologyKey: topology.kubernetes.io/zone
          labelSelector:
            matchLabels:
              app: agentmesh-server

resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: "1"
    memory: 1Gi
```

---

## Network Security

### VNet Configuration

- AKS nodes in **private subnets** with Azure NAT Gateway
- Redis and PostgreSQL in **private subnets** with Private Endpoints
- Use **Private Link** for Key Vault, Event Grid, and Azure Monitor

### Network Security Groups

| Component | Inbound | Outbound |
|-----------|---------|----------|
| AgentMesh Server | 8080 (API), 9090 (metrics) from VNet | Redis 6380, PostgreSQL 5432, Key Vault 443 |
| AgentMesh Sidecar | 8081 from localhost only | AgentMesh Server 8080 |
| Redis | 6380 from AKS subnet | — |
| PostgreSQL | 5432 from AKS subnet | — |

### Kubernetes Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agentmesh-server
  namespace: agentmesh
spec:
  podSelector:
    matchLabels:
      app: agentmesh-server
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              agentmesh-access: "true"
      ports:
        - port: 8080
        - port: 9090
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 6380
        - port: 5432
        - port: 443
```

---

## Common Patterns

### Identity Integration

Use Workload Identity so AgentMesh pods authenticate to Azure services without static credentials:

```
AgentMesh DID → K8s ServiceAccount → Azure Managed Identity (via Workload Identity)
```

### Secret Management

- **Agent private keys:** Azure Key Vault + CSI driver mount
- **Redis/PostgreSQL credentials:** Key Vault with automatic rotation
- **TLS certificates:** Azure-managed certificates for external; SPIFFE for mesh-internal

### Cost Optimization

- Use Azure Spot VMs for non-critical agent workloads
- Right-size Azure Cache and PostgreSQL based on agent count
- Use Log Analytics data retention tiers for audit log cost management

---

*See also: [AWS Deployment](aws.md) · [GCP Deployment](gcp.md) · [Kubernetes Guide](kubernetes.md)*
