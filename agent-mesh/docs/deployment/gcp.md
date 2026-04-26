# GCP Deployment Guide

Deploying AgentMesh on Google Cloud Platform using GKE, Workload Identity, Cloud KMS, and Cloud Monitoring.

> **See also:** [Kubernetes Guide](kubernetes.md) for general K8s patterns, [AWS](aws.md) and [Azure](azure.md) for other clouds.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [GKE Cluster Setup](#gke-cluster-setup)
- [Workload Identity Integration](#workload-identity-integration)
- [Secrets Management with Cloud KMS](#secrets-management-with-cloud-kms)
- [Monitoring with Cloud Monitoring](#monitoring-with-cloud-monitoring)
- [High Availability Topology](#high-availability-topology)
- [Network Security](#network-security)
- [Common Patterns](#common-patterns)

---

## Architecture Overview

```
┌──────────────────────────────────────────────────┐
│  GCP Region                                      │
│  ┌────────────────────────────────────────────┐  │
│  │  VPC                                       │  │
│  │  ┌──────────────┐  ┌────────────────────┐ │  │
│  │  │ GKE Cluster  │  │ Memorystore        │ │  │
│  │  │              │  │ (Redis)            │ │  │
│  │  │ ┌──────────┐ │  └────────────────────┘ │  │
│  │  │ │AgentMesh │ │  ┌────────────────────┐ │  │
│  │  │ │ Server   │ │  │ Cloud SQL          │ │  │
│  │  │ ├──────────┤ │  │ (PostgreSQL)       │ │  │
│  │  │ │AgentMesh │ │  └────────────────────┘ │  │
│  │  │ │ Sidecar  │ │                         │  │
│  │  │ └──────────┘ │  ┌────────────────────┐ │  │
│  │  └──────────────┘  │ Cloud KMS          │ │  │
│  │                     └────────────────────┘ │  │
│  │                     ┌────────────────────┐ │  │
│  │                     │ Cloud Monitoring / │ │  │
│  │                     │ Eventarc           │ │  │
│  │                     └────────────────────┘ │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

---

## Prerequisites

- **gcloud CLI** configured with appropriate project
- **kubectl** configured for your GKE cluster
- **Helm 3.x** for chart-based deployment

---

## GKE Cluster Setup

### Create Cluster

```bash
gcloud container clusters create agentmesh-prod \
  --region us-central1 \
  --num-nodes 1 \
  --machine-type e2-standard-4 \
  --enable-autoscaling \
  --min-nodes 2 \
  --max-nodes 5 \
  --workload-pool=PROJECT_ID.svc.id.goog \
  --enable-network-policy \
  --release-channel regular
```

### Recommended Node Configuration

| Component | Machine Type | Min Nodes | Notes |
|-----------|-------------|-----------|-------|
| AgentMesh Server | e2-standard-4 | 2 | CPU-bound trust scoring |
| AgentMesh Sidecar | Runs in agent pods | — | ~128 MB RAM per sidecar |
| Redis (Memorystore) | M1 Standard, 5 GB | 1 | Standard tier for HA |
| PostgreSQL (Cloud SQL) | db-custom-4-16384 | 1 | HA with regional availability |

---

## Workload Identity Integration

Use [GKE Workload Identity](https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity) to authenticate AgentMesh pods to GCP services without static credentials.

### 1. Create GCP Service Account

```bash
gcloud iam service-accounts create agentmesh-sa \
  --display-name "AgentMesh Service Account"
```

### 2. Grant Roles

```bash
PROJECT_ID=$(gcloud config get-value project)

# Cloud KMS access
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member "serviceAccount:agentmesh-sa@$PROJECT_ID.iam.gserviceaccount.com" \
  --role "roles/cloudkms.cryptoKeyEncrypterDecrypter"

# Secret Manager access
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member "serviceAccount:agentmesh-sa@$PROJECT_ID.iam.gserviceaccount.com" \
  --role "roles/secretmanager.secretAccessor"

# Cloud Monitoring metrics writer
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member "serviceAccount:agentmesh-sa@$PROJECT_ID.iam.gserviceaccount.com" \
  --role "roles/monitoring.metricWriter"

# Eventarc publisher
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member "serviceAccount:agentmesh-sa@$PROJECT_ID.iam.gserviceaccount.com" \
  --role "roles/eventarc.publisher"
```

### 3. Bind to Kubernetes Service Account

```bash
gcloud iam service-accounts add-iam-policy-binding \
  agentmesh-sa@$PROJECT_ID.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:$PROJECT_ID.svc.id.goog[agentmesh/agentmesh-sa]"
```

### 4. Create Kubernetes Service Account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: agentmesh-sa
  namespace: agentmesh
  annotations:
    iam.gke.io/gcp-service-account: agentmesh-sa@PROJECT_ID.iam.gserviceaccount.com
```

---

## Secrets Management with Cloud KMS

### Create Key Ring and Key

```bash
gcloud kms keyrings create agentmesh \
  --location us-central1

gcloud kms keys create agent-key-encryption \
  --location us-central1 \
  --keyring agentmesh \
  --purpose encryption
```

### Store Agent Private Keys in Secret Manager

```bash
# Store Ed25519 private key
echo -n "<base64-encoded-ed25519-key>" | \
  gcloud secrets create agent-alpha-private-key \
  --data-file=-
```

### Use GCP Secret Store CSI Driver

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: agentmesh-secrets
  namespace: agentmesh
spec:
  provider: gcp
  parameters:
    secrets: |
      - resourceName: "projects/PROJECT_ID/secrets/agent-alpha-private-key/versions/latest"
        path: "agent-alpha-private-key"
```

---

## Monitoring with Cloud Monitoring

### Enable GKE Monitoring

GKE clusters with Cloud Operations enabled automatically export metrics. For Prometheus-format metrics, use [Google Cloud Managed Service for Prometheus](https://cloud.google.com/stackdriver/docs/managed-prometheus).

```bash
gcloud container clusters update agentmesh-prod \
  --region us-central1 \
  --enable-managed-prometheus
```

### Create PodMonitoring Resource

```yaml
apiVersion: monitoring.googleapis.com/v1
kind: PodMonitoring
metadata:
  name: agentmesh-server
  namespace: agentmesh
spec:
  selector:
    matchLabels:
      app: agentmesh-server
  endpoints:
    - port: metrics
      interval: 30s
```

### Key Metrics to Monitor

| Metric | Alert Condition |
|--------|----------------|
| `agentmesh_trust_score` | Any agent drops below 300 |
| `agentmesh_policy_violations_total` | > 10 violations/min |
| `agentmesh_anomaly_detections_total` | Any HIGH severity detection |
| `agentmesh_credential_rotations_total` | Rotation failure |
| `agentmesh_handshake_duration_seconds` | p99 > 500 ms |

### Audit Log Export via Eventarc

```yaml
# AgentMesh config
audit:
  export:
    type: cloudevents
    target: gcp_eventarc
    project: PROJECT_ID
    region: us-central1
```

---

## High Availability Topology

### Regional GKE Cluster

GKE regional clusters automatically distribute nodes across zones.

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  Zone a      │  │  Zone b      │  │  Zone c      │
│              │  │              │  │              │
│ AgentMesh    │  │ AgentMesh    │  │ AgentMesh    │
│ Server (1)   │  │ Server (1)   │  │ Server (1)   │
│              │  │              │  │              │
│ Redis Primary│  │ Redis Replica│  │              │
│ SQL Primary  │  │ SQL Standby  │  │ SQL Read     │
└──────────────┘  └──────────────┘  └──────────────┘
```

- **AgentMesh Server:** ≥ 2 replicas with topology spread constraints
- **Redis:** Memorystore Standard tier (automatic failover)
- **PostgreSQL:** Cloud SQL HA with regional availability and read replicas

### Helm Values for HA

```yaml
replicaCount: 3

topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: DoNotSchedule
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

### VPC Configuration

- GKE nodes in **private subnets** with Cloud NAT for outbound
- Memorystore and Cloud SQL with **Private Service Connect** (no public IP)
- Use **VPC Service Controls** for additional boundary protection

### Firewall Rules

| Component | Inbound | Outbound |
|-----------|---------|----------|
| AgentMesh Server | 8080 (API), 9090 (metrics) from VPC | Redis 6379, Cloud SQL 5432, KMS/Secret Manager APIs |
| AgentMesh Sidecar | 8081 from localhost only | AgentMesh Server 8080 |
| Redis | 6379 from GKE subnet | — |
| Cloud SQL | 5432 from GKE subnet | — |

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
        - port: 6379
        - port: 5432
        - port: 443
```

---

## Common Patterns

### Identity Integration

Use Workload Identity so AgentMesh pods authenticate to GCP services without static credentials:

```
AgentMesh DID → K8s ServiceAccount → GCP Service Account (via Workload Identity)
```

### Secret Management

- **Agent private keys:** Secret Manager + Cloud KMS envelope encryption + CSI driver mount
- **Redis/Cloud SQL credentials:** Secret Manager with automatic rotation
- **TLS certificates:** Google-managed certificates for external; SPIFFE for mesh-internal

### Cost Optimization

- Use Spot VMs for non-critical agent workloads
- Right-size Memorystore and Cloud SQL based on agent count
- Use Cloud Monitoring log exclusion filters and retention policies for audit log cost management

---

*See also: [AWS Deployment](aws.md) · [Azure Deployment](azure.md) · [Kubernetes Guide](kubernetes.md)*
