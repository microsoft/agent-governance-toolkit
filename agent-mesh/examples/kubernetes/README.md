# Kubernetes Examples for AgentMesh

This directory contains example Kubernetes manifests for deploying governed agents using AgentMesh.

## Prerequisites

1. Kubernetes cluster with AgentMesh installed
2. GovernedAgent CRD installed
3. kubectl configured

## Install AgentMesh

```bash
# Install AgentMesh with Helm
helm install agentmesh ../../charts/agentmesh \
  --namespace agentmesh \
  --create-namespace \
  --set redis.auth.password=your-password
```

## Deploy a Governed Agent

```bash
# Deploy the example data processor agent
kubectl apply -f governed-agent-example.yaml

# Check the agent status
kubectl get governedagents -n my-app
kubectl describe governedagent data-processor -n my-app

# View agent pods
kubectl get pods -n my-app -l agentmesh.ai/agent=data-processor

# View agent logs
kubectl logs -n my-app -l agentmesh.ai/agent=data-processor -f
```

## Examples

### 1. Data Processor Agent (`governed-agent-example.yaml`)

A general-purpose data processing agent with:
- Read access to S3
- Access to analytics API
- Strict policy enforcement
- Trust score monitoring

### 2. Customer Service Agent (`customer-service-agent.yaml`)

A customer service agent with:
- Access to CRM and ticketing systems
- Standard policy
- Higher replica count for load handling

### 3. Healthcare Agent (`healthcare-agent.yaml`)

A HIPAA-compliant healthcare agent with:
- Read-only access to patient data
- Strict compliance policy
- Full observability enabled

## Policy Types

- `standard` - Default policy, balanced security
- `strict` - Maximum security, minimal permissions
- `permissive` - Relaxed security for development
- `custom` - User-defined policy (requires PolicyConfig)

## Monitoring

View agent metrics:

```bash
# Port-forward Prometheus
kubectl port-forward -n agentmesh svc/agentmesh 9090:9090

# View metrics for a specific agent
curl "http://localhost:9090/api/v1/query?query=agentmesh_trust_score_gauge{agent_did=~'.*data-processor.*'}"
```

View agent in Grafana:

```bash
# Port-forward Grafana
kubectl port-forward -n agentmesh svc/grafana 3000:3000

# Access Grafana at http://localhost:3000
# Default credentials: admin/agentmesh
```

## Troubleshooting

Check agent status:

```bash
kubectl get governedagent data-processor -n my-app -o yaml
```

Check sidecar logs:

```bash
kubectl logs -n my-app <pod-name> -c agentmesh-sidecar
```

Check agent container logs:

```bash
kubectl logs -n my-app <pod-name> -c agent
```
