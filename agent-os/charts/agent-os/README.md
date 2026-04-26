# Agent OS Helm Chart

Production-ready Helm chart for deploying Agent OS governance kernel on Kubernetes.

## Installation

```bash
# Add and install
helm install agent-os ./charts/agent-os

# Install with custom values
helm install agent-os ./charts/agent-os -f my-values.yaml

# Upgrade
helm upgrade agent-os ./charts/agent-os
```

## Components

| Component | Description | Default Replicas |
|-----------|-------------|-----------------|
| **Kernel** | Stateless governance kernel | 2 |
| **Policy Server** | YAML policy evaluation server | 2 |
| **Audit Collector** | Audit log aggregation with persistent storage | 1 |

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `kernel.replicas` | Kernel replica count | `2` |
| `kernel.image.repository` | Kernel image | `agent-os/kernel` |
| `kernel.image.tag` | Kernel image tag | `0.3.0` |
| `kernel.resources.requests.cpu` | CPU request | `250m` |
| `kernel.resources.requests.memory` | Memory request | `256Mi` |
| `kernel.resources.limits.cpu` | CPU limit | `1` |
| `kernel.resources.limits.memory` | Memory limit | `512Mi` |
| `kernel.autoscaling.enabled` | Enable HPA | `true` |
| `kernel.autoscaling.minReplicas` | HPA min replicas | `2` |
| `kernel.autoscaling.maxReplicas` | HPA max replicas | `10` |
| `policyServer.replicas` | Policy server replica count | `2` |
| `policyServer.policyMount.enabled` | Mount policies from ConfigMap | `true` |
| `auditCollector.replicas` | Audit collector replica count | `1` |
| `auditCollector.persistence.enabled` | Enable persistent storage | `true` |
| `auditCollector.persistence.size` | PVC size | `10Gi` |
| `monitoring.enabled` | Enable Prometheus annotations | `true` |
| `podDisruptionBudget.enabled` | Enable PDB | `true` |
| `networkPolicy.enabled` | Enable NetworkPolicy | `true` |

## High Availability

The chart is HA-ready by default:

- **Kernel**: 2 replicas with HPA (scales to 10) and PDB
- **Policy Server**: 2 replicas with PDB
- **Audit Collector**: 1 replica with persistent storage

To increase availability:

```yaml
kernel:
  replicas: 3
  autoscaling:
    minReplicas: 3
    maxReplicas: 20

policyServer:
  replicas: 3

podDisruptionBudget:
  minAvailable: 2
```

## Monitoring

Prometheus scrape annotations are enabled by default on all pods. Configure your Prometheus to scrape the `/metrics` endpoint on port `9090`.
