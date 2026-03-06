# Agent-SRE Helm Chart

Helm chart for deploying Agent-SRE on Kubernetes.

## Install

```bash
helm install agent-sre ./deployments/helm/agent-sre
```

## With custom values

```bash
helm install agent-sre ./deployments/helm/agent-sre \
  --set otel.enabled=true \
  --set otel.endpoint=http://otel-collector:4317
```

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Container image | `ghcr.io/microsoft/agent-sre` |
| `image.tag` | Image tag | `appVersion` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `8080` |
| `api.enabled` | Enable REST API | `true` |
| `otel.enabled` | Enable OTEL export | `false` |
| `otel.endpoint` | OTLP endpoint | `""` |
| `fleet.enabled` | Enable fleet management | `true` |
| `crd.install` | Install AgentRollout CRD | `true` |

## CRD Usage

Once installed, create an `AgentRollout` resource:

```yaml
apiVersion: agent-sre.io/v1alpha1
kind: AgentRollout
metadata:
  name: my-agent-v2
spec:
  strategy: canary
  current:
    name: my-agent
    version: v1
  candidate:
    name: my-agent
    version: v2
  steps:
    - name: canary-5
      weight: 0.05
      durationSeconds: 3600
    - name: canary-50
      weight: 0.50
      durationSeconds: 7200
    - name: full
      weight: 1.0
  rollbackConditions:
    - metric: error_rate
      threshold: 0.05
      operator: gte
```
