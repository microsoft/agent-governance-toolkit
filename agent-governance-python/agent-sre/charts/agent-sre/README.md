# Agent SRE Helm Chart

Helm chart for deploying Agent SRE on Kubernetes with all five engines:
SLO Engine, Chaos Engine, Delivery Controller, Cost Guard, and Incident Manager.

## Installation

```bash
helm install agent-sre ./charts/agent-sre
```

## With Custom Values

```bash
helm install agent-sre ./charts/agent-sre \
  --set sloEngine.replicas=3 \
  --set monitoring.grafana.enabled=true \
  --set autoscaling.enabled=true
```

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Container image | `ghcr.io/microsoft/agent-sre` |
| `image.tag` | Image tag | `appVersion` |
| `sloEngine.replicas` | SLO Engine replicas | `2` |
| `chaosEngine.replicas` | Chaos Engine replicas | `1` |
| `deliveryController.replicas` | Delivery Controller replicas | `1` |
| `costGuard.replicas` | Cost Guard replicas | `1` |
| `incidentManager.replicas` | Incident Manager replicas | `1` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `8080` |
| `monitoring.prometheus.enabled` | Enable Prometheus metrics | `true` |
| `monitoring.prometheus.port` | Prometheus metrics port | `9090` |
| `monitoring.grafana.enabled` | Enable Grafana dashboards | `false` |
| `autoscaling.enabled` | Enable HPA | `false` |
| `autoscaling.maxReplicas` | Max HPA replicas | `5` |
| `podDisruptionBudget.enabled` | Enable PDB | `true` |
| `networkPolicy.enabled` | Enable NetworkPolicy | `false` |

## Uninstall

```bash
helm uninstall agent-sre
```
