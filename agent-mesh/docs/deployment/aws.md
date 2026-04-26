# AWS Deployment Guide

Deploying AgentMesh on Amazon Web Services using EKS, IAM, KMS, and CloudWatch.

> **See also:** [Kubernetes Guide](kubernetes.md) for general K8s patterns, [Azure](azure.md) and [GCP](gcp.md) for other clouds.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [EKS Cluster Setup](#eks-cluster-setup)
- [IAM Roles for Service Accounts](#iam-roles-for-service-accounts)
- [Secrets Management with KMS](#secrets-management-with-kms)
- [Monitoring with CloudWatch](#monitoring-with-cloudwatch)
- [High Availability Topology](#high-availability-topology)
- [Network Security](#network-security)
- [Common Patterns](#common-patterns)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│  AWS Region                                     │
│  ┌───────────────────────────────────────────┐  │
│  │  VPC                                      │  │
│  │  ┌─────────────┐  ┌─────────────────────┐│  │
│  │  │ EKS Cluster │  │ ElastiCache (Redis) ││  │
│  │  │             │  └─────────────────────┘│  │
│  │  │ ┌─────────┐ │  ┌─────────────────────┐│  │
│  │  │ │AgentMesh│ │  │ RDS (PostgreSQL)    ││  │
│  │  │ │ Server  │ │  └─────────────────────┘│  │
│  │  │ ├─────────┤ │                          │  │
│  │  │ │AgentMesh│ │  ┌─────────────────────┐│  │
│  │  │ │ Sidecar │ │  │ AWS KMS             ││  │
│  │  │ └─────────┘ │  └─────────────────────┘│  │
│  │  └─────────────┘                          │  │
│  │                    ┌─────────────────────┐│  │
│  │                    │ CloudWatch          ││  │
│  │                    └─────────────────────┘│  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

---

## Prerequisites

- **AWS CLI** v2 configured with appropriate credentials
- **eksctl** v0.160+ or Terraform for cluster provisioning
- **kubectl** configured for your EKS cluster
- **Helm 3.x** for chart-based deployment

---

## EKS Cluster Setup

### Create Cluster with eksctl

```bash
eksctl create cluster \
  --name agentmesh-prod \
  --region us-east-1 \
  --version 1.29 \
  --nodegroup-name workers \
  --node-type m5.large \
  --nodes 3 \
  --nodes-min 2 \
  --nodes-max 5 \
  --managed
```

### Recommended Node Configuration

| Component | Instance Type | Min Nodes | Notes |
|-----------|--------------|-----------|-------|
| AgentMesh Server | m5.large | 2 | CPU-bound trust scoring |
| AgentMesh Sidecar | Runs in agent pods | — | ~128 MB RAM per sidecar |
| Redis (ElastiCache) | cache.r6g.large | 2 | Multi-AZ for HA |
| PostgreSQL (RDS) | db.r6g.large | 2 | Multi-AZ with read replica |

---

## IAM Roles for Service Accounts

Use [IRSA (IAM Roles for Service Accounts)](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) to grant AgentMesh pods fine-grained AWS permissions without static credentials.

### 1. Create OIDC Provider

```bash
eksctl utils associate-iam-oidc-provider \
  --cluster agentmesh-prod \
  --region us-east-1 \
  --approve
```

### 2. Create IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:ACCOUNT_ID:key/KEY_ID"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:us-east-1:ACCOUNT_ID:log-group:/agentmesh/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "events:PutEvents"
      ],
      "Resource": "arn:aws:events:us-east-1:ACCOUNT_ID:event-bus/agentmesh-audit"
    }
  ]
}
```

### 3. Create Service Account with IRSA

```bash
eksctl create iamserviceaccount \
  --cluster agentmesh-prod \
  --namespace agentmesh \
  --name agentmesh-sa \
  --attach-policy-arn arn:aws:iam::ACCOUNT_ID:policy/AgentMeshPolicy \
  --approve
```

### 4. Reference in Helm Values

```yaml
serviceAccount:
  create: false
  name: agentmesh-sa
```

---

## Secrets Management with KMS

### Encrypt Agent Ed25519 Private Keys

AgentMesh agent private keys should be encrypted at rest using AWS KMS envelope encryption.

```bash
# Create a KMS key for AgentMesh
aws kms create-key \
  --description "AgentMesh agent key encryption" \
  --key-usage ENCRYPT_DECRYPT \
  --origin AWS_KMS

# Store encrypted key in Secrets Manager
aws secretsmanager create-secret \
  --name agentmesh/agent-keys/agent-alpha \
  --kms-key-id alias/agentmesh-keys \
  --secret-string '{"private_key": "<base64-encoded-ed25519-key>"}'
```

### Use AWS Secrets Store CSI Driver

```yaml
# SecretProviderClass for mounting KMS-encrypted secrets
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: agentmesh-secrets
  namespace: agentmesh
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "agentmesh/agent-keys/agent-alpha"
        objectType: "secretsmanager"
```

---

## Monitoring with CloudWatch

### Prometheus Metrics to CloudWatch

Use the [CloudWatch Agent](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights-Prometheus.html) or [ADOT Collector](https://aws-otel.github.io/) to scrape AgentMesh Prometheus metrics and forward to CloudWatch.

### Key Metrics to Monitor

| Metric | Source Port | CloudWatch Alarm |
|--------|------------|-----------------|
| `agentmesh_trust_score` | 9090 | Alarm when any agent drops below 300 |
| `agentmesh_policy_violations_total` | 9090 | Alarm on > 10 violations/min |
| `agentmesh_anomaly_detections_total` | 9090 | Alarm on any HIGH severity |
| `agentmesh_credential_rotations_total` | 9090 | Alert if rotation fails |
| `agentmesh_handshake_duration_seconds` | 9090 | Alarm if p99 > 500 ms |

### CloudWatch Audit Log Export

Configure AgentMesh CloudEvents to forward audit events to EventBridge:

```yaml
# AgentMesh config
audit:
  export:
    type: cloudevents
    target: aws_eventbridge
    event_bus: agentmesh-audit
    region: us-east-1
```

---

## High Availability Topology

### Multi-AZ Deployment

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│    AZ-1a     │  │    AZ-1b     │  │    AZ-1c     │
│              │  │              │  │              │
│ AgentMesh    │  │ AgentMesh    │  │ AgentMesh    │
│ Server (1)   │  │ Server (1)   │  │ Server (1)   │
│              │  │              │  │              │
│ Redis Primary│  │ Redis Replica│  │              │
│ RDS Primary  │  │ RDS Standby  │  │ RDS Read     │
└──────────────┘  └──────────────┘  └──────────────┘
```

- **AgentMesh Server:** Run ≥ 2 replicas across AZs with pod anti-affinity
- **Redis:** ElastiCache Multi-AZ with automatic failover
- **PostgreSQL:** RDS Multi-AZ with read replicas for audit queries

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

### VPC Configuration

- Place EKS nodes in **private subnets** with NAT Gateway for outbound
- Place RDS and ElastiCache in **private subnets** with no public access
- Use **VPC endpoints** for AWS service access (KMS, Secrets Manager, CloudWatch, EventBridge)

### Security Groups

| Component | Inbound | Outbound |
|-----------|---------|----------|
| AgentMesh Server | 8080 (API), 9090 (metrics) from VPC | Redis 6379, RDS 5432, KMS/Secrets Manager endpoints |
| AgentMesh Sidecar | 8081 from localhost only | AgentMesh Server 8080 |
| Redis | 6379 from AgentMesh SG | — |
| RDS | 5432 from AgentMesh SG | — |

### Network Policies

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
```

---

## Common Patterns

### Identity Integration

Use IRSA so AgentMesh pods authenticate to AWS services without static credentials. Map each agent identity to an IAM role for fine-grained access:

```
AgentMesh DID → K8s ServiceAccount → IAM Role (via IRSA)
```

### Secret Management

- **Agent private keys:** AWS Secrets Manager + KMS envelope encryption + CSI driver mount
- **Redis/RDS credentials:** Secrets Manager with automatic rotation
- **TLS certificates:** ACM (AWS Certificate Manager) for external; SPIFFE for mesh-internal

### Cost Optimization

- Use Spot instances for non-critical agent workloads
- Right-size ElastiCache and RDS based on agent count
- Use CloudWatch Logs Insights instead of full log retention for audit queries

---

*See also: [Azure Deployment](azure.md) · [GCP Deployment](gcp.md) · [Kubernetes Guide](kubernetes.md)*
