# AgentMesh Helm Chart

Trust, identity, and governance infrastructure for AI agent ecosystems.

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Kubernetes  | 1.24+   |
| Helm        | 3+      |

## Quick Start

```bash
helm install agentmesh ./charts/agentmesh
```

Or from a custom namespace:

```bash
helm install agentmesh ./charts/agentmesh \
  --namespace agentmesh \
  --create-namespace
```

## Architecture

The chart deploys four core components:

| Component          | Description                                      | Default Replicas |
|--------------------|--------------------------------------------------|------------------|
| **Trust Engine**   | Computes and manages agent trust scores          | 2                |
| **Policy Server**  | Evaluates governance policies (YAML-based)       | 2                |
| **Audit Collector**| Immutable audit log ingestion and retention      | 1                |
| **API Gateway**    | External entry point with rate limiting and TLS  | 2                |

## Configuration

### Global

| Parameter                     | Description                        | Default              |
|-------------------------------|------------------------------------|----------------------|
| `global.namespace`            | Target namespace                   | `agentmesh`          |
| `global.imageTag`             | Default image tag for all components | `0.3.0`            |
| `global.tls.enabled`          | Enable TLS across all services     | `true`               |
| `global.tls.certSecretName`   | TLS certificate secret name        | `agentmesh-tls`      |
| `global.spiffe.enabled`       | Enable SPIFFE/SPIRE integration    | `false`              |
| `global.spiffe.trustDomain`   | SPIFFE trust domain                | `agentmesh.local`    |

### Trust Engine

| Parameter                          | Description            | Default                    |
|------------------------------------|------------------------|----------------------------|
| `trustEngine.replicas`             | Replica count          | `2`                        |
| `trustEngine.image.repository`     | Image repository       | `ghcr.io/microsoft/agentmesh/trust-engine`   |
| `trustEngine.service.port`         | Service port           | `8443`                     |
| `trustEngine.resources.requests.cpu` | CPU request          | `100m`                     |
| `trustEngine.resources.requests.memory` | Memory request    | `256Mi`                    |
| `trustEngine.resources.limits.cpu` | CPU limit              | `500m`                     |
| `trustEngine.resources.limits.memory` | Memory limit        | `512Mi`                    |

### Policy Server

| Parameter                           | Description                 | Default                    |
|-------------------------------------|-----------------------------|----------------------------|
| `policyServer.replicas`             | Replica count               | `2`                        |
| `policyServer.image.repository`     | Image repository            | `ghcr.io/microsoft/agentmesh/policy-server`  |
| `policyServer.service.port`         | Service port                | `8444`                     |
| `policyServer.policyMountPath`      | Policy YAML mount path      | `/etc/agentmesh/policies`  |

### Audit Collector

| Parameter                              | Description             | Default                        |
|----------------------------------------|-------------------------|--------------------------------|
| `auditCollector.replicas`              | Replica count           | `1`                            |
| `auditCollector.image.repository`      | Image repository        | `ghcr.io/microsoft/agentmesh/audit-collector`    |
| `auditCollector.service.port`          | Service port            | `8445`                         |
| `auditCollector.persistence.enabled`   | Enable persistent storage | `true`                       |
| `auditCollector.persistence.size`      | PVC size                | `10Gi`                         |
| `auditCollector.retentionDays`         | Audit log retention     | `90`                           |

### API Gateway

| Parameter                          | Description             | Default                    |
|------------------------------------|-------------------------|----------------------------|
| `apiGateway.replicas`              | Replica count           | `2`                        |
| `apiGateway.image.repository`      | Image repository        | `ghcr.io/microsoft/agentmesh/api-gateway`    |
| `apiGateway.service.type`          | Service type            | `LoadBalancer`             |
| `apiGateway.service.port`          | Service port            | `443`                      |
| `apiGateway.rateLimitPerMinute`    | Rate limit (req/min)    | `1000`                     |

### Autoscaling

| Parameter                                     | Description          | Default |
|-----------------------------------------------|----------------------|---------|
| `autoscaling.enabled`                         | Enable HPA           | `true`  |
| `autoscaling.minReplicas`                     | Minimum replicas     | `2`     |
| `autoscaling.maxReplicas`                     | Maximum replicas     | `10`    |
| `autoscaling.targetCPUUtilizationPercentage`  | CPU utilization target | `70`  |

### Pod Disruption Budget

| Parameter                        | Description       | Default |
|----------------------------------|-------------------|---------|
| `podDisruptionBudget.enabled`    | Enable PDB        | `true`  |
| `podDisruptionBudget.minAvailable` | Minimum available | `1`   |

### Network Policy

| Parameter               | Description                                  | Default |
|-------------------------|----------------------------------------------|---------|
| `networkPolicy.enabled` | Restrict ingress to API Gateway only         | `true`  |

### Monitoring

| Parameter                           | Description                    | Default |
|-------------------------------------|--------------------------------|---------|
| `monitoring.prometheus.enabled`     | Enable Prometheus annotations  | `true`  |
| `monitoring.serviceMonitor.enabled` | Create ServiceMonitor CRD      | `false` |

## High-Availability Deployment

For production HA, override the following:

```bash
helm install agentmesh ./charts/agentmesh \
  --set trustEngine.replicas=3 \
  --set policyServer.replicas=3 \
  --set apiGateway.replicas=3 \
  --set autoscaling.minReplicas=3 \
  --set autoscaling.maxReplicas=20 \
  --set podDisruptionBudget.minAvailable=2
```

Distribute pods across availability zones with topology-aware affinity:

```yaml
trustEngine:
  affinity:
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        - labelSelector:
            matchLabels:
              app.kubernetes.io/component: trust-engine
          topologyKey: topology.kubernetes.io/zone
```

## TLS / mTLS Configuration

TLS is enabled by default. Provide a Kubernetes TLS secret:

```bash
kubectl create secret tls agentmesh-tls \
  --cert=tls.crt \
  --key=tls.key \
  -n agentmesh
```

For full mTLS with SPIFFE/SPIRE:

```bash
helm install agentmesh ./charts/agentmesh \
  --set global.spiffe.enabled=true \
  --set global.spiffe.trustDomain=your-domain.example.com
```

## Monitoring with Prometheus & Grafana

All pods are annotated for Prometheus scraping by default. If you use the
prometheus-operator, enable ServiceMonitor creation:

```bash
helm install agentmesh ./charts/agentmesh \
  --set monitoring.serviceMonitor.enabled=true
```

Import the bundled Grafana dashboards from `dashboards/` in the repo root.

## Uninstall

```bash
helm uninstall agentmesh -n agentmesh
```
