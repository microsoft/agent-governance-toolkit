# Agent-SRE Kubernetes Operator

Kubernetes Custom Resource Definitions (CRDs) for managing Agent SRE resources declaratively.

## CRDs

### AgentSLO

Defines SLO objectives for AI agents:

```yaml
apiVersion: sre.agent-os.dev/v1alpha1
kind: AgentSLO
metadata:
  name: my-agent-slo
spec:
  agentId: agent-1
  target: 0.995
  indicators:
    - name: success-rate
      target: 0.99
  errorBudget:
    windowDays: 30
    burnRateAlert: 2.0
    burnRateCritical: 10.0
```

### CostBudget

Defines cost budgets for AI agents:

```yaml
apiVersion: sre.agent-os.dev/v1alpha1
kind: CostBudget
metadata:
  name: my-agent-budget
spec:
  agentId: agent-1
  budgetUsd: 100.0
  windowDays: 30
  alertThresholdPercent: 80
```

## Installation

Apply the CRDs to your cluster:

```bash
kubectl apply -f operator/crds/
```
