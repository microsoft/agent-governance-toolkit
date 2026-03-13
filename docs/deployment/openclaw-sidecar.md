# Securing OpenClaw with the Agent Governance Toolkit

Deploy OpenClaw as an autonomous agent with the Agent Governance Toolkit as a sidecar on Azure Kubernetes Service (AKS) for runtime policy enforcement, identity verification, and SLO monitoring.

> **See also:** [Deployment Overview](README.md) | [AKS Deployment](../../packages/agent-mesh/docs/deployment/azure.md) | [OpenClaw on ClawHub](https://clawhub.ai/microsoft/agentmesh-governance)

---

## Table of Contents

- [Why Govern OpenClaw?](#why-govern-openclaw)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start with Docker Compose](#quick-start-with-docker-compose)
- [Production Deployment on AKS](#production-deployment-on-aks)
- [Governance Policies for OpenClaw](#governance-policies-for-openclaw)
- [Monitoring and SLOs](#monitoring-and-slos)
- [Troubleshooting](#troubleshooting)

---

## Why Govern OpenClaw?

OpenClaw is a powerful autonomous agent capable of executing code, calling APIs, browsing the web, and managing files. That autonomy is precisely what makes governance critical:

- **Tool misuse** — OpenClaw can execute arbitrary shell commands; policy enforcement constrains which commands are allowed
- **Rate limiting** — Prevent runaway API calls or resource consumption
- **Audit trail** — Log every action for compliance and post-incident analysis
- **Trust scoring** — Dynamic trust levels based on behavioral patterns
- **Circuit breakers** — Automatic shutdown if safety SLOs are violated

The governance sidecar intercepts all of OpenClaw's tool calls before execution, enforcing policies transparently without modifying OpenClaw itself.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  AKS Pod: openclaw-governed                                   │
│                                                               │
│  ┌─────────────────────────┐  ┌────────────────────────────┐ │
│  │  OpenClaw Container      │  │  Governance Sidecar        │ │
│  │                          │  │                            │ │
│  │  Autonomous agent        │  │  Agent OS (policy engine)  │ │
│  │  Code execution          │  │  AgentMesh (identity)      │ │
│  │  Web browsing            │  │  Agent SRE (SLOs)          │ │
│  │  File management         │  │  Agent Runtime (rings)     │ │
│  │                          │  │                            │ │
│  │  Tool calls ─────────────────► Policy check              │ │
│  │              ◄─────────────── Allow / Deny               │ │
│  │                          │  │                            │ │
│  │  localhost:8080          │  │  localhost:8081 (proxy)     │ │
│  │                          │  │  localhost:9091 (metrics)   │ │
│  └─────────────────────────┘  └────────────────────────────┘ │
│                                                               │
└──────────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
   External APIs               Azure Monitor / Prometheus
```

---

## Prerequisites

- Docker and Docker Compose (for local development)
- Azure CLI with AKS credentials (for production)
- Helm 3.x (for AKS deployment)
- An AKS cluster (see [AKS setup guide](../../packages/agent-mesh/docs/deployment/azure.md#aks-cluster-setup))

---

## Quick Start with Docker Compose

For local development and testing:

**`docker-compose.yaml`:**

```yaml
version: "3.8"

services:
  openclaw:
    image: ghcr.io/openclaw/openclaw:latest
    ports:
      - "8080:8080"
    environment:
      - GOVERNANCE_PROXY=http://governance-sidecar:8081
    depends_on:
      - governance-sidecar
    networks:
      - agent-net

  governance-sidecar:
    build:
      context: ../../packages/agent-os
      dockerfile: Dockerfile
    ports:
      - "8081:8081"
      - "9091:9091"
    environment:
      - POLICY_DIR=/policies
      - LOG_LEVEL=INFO
      - TRUST_SCORE_INITIAL=0.5
      - EXECUTION_RING=3
    volumes:
      - ./policies:/policies:ro
    networks:
      - agent-net

networks:
  agent-net:
    driver: bridge
```

```bash
# Start OpenClaw with governance
docker compose up -d

# Verify governance sidecar is running
curl http://localhost:8081/health

# Check governance metrics
curl http://localhost:9091/metrics
```

---

## Production Deployment on AKS

### Helm Values

Use the AgentMesh Helm chart with OpenClaw-specific configuration:

**`values-openclaw.yaml`:**

```yaml
global:
  namespace: openclaw-governed
  imageTag: "0.3.0"
  tls:
    enabled: true
    certSecretName: openclaw-tls

# OpenClaw as the primary workload
openclaw:
  enabled: true
  image:
    repository: ghcr.io/openclaw/openclaw
    tag: latest
  resources:
    requests:
      cpu: "1.0"
      memory: "2Gi"
    limits:
      cpu: "2.0"
      memory: "4Gi"
  env:
    - name: GOVERNANCE_PROXY
      value: http://localhost:8081

# Governance sidecar
sidecar:
  enabled: true
  image:
    repository: agentmesh/governance-sidecar
    tag: "0.3.0"
  resources:
    requests:
      cpu: "0.25"
      memory: "256Mi"
    limits:
      cpu: "0.5"
      memory: "512Mi"
  ports:
    proxy: 8081
    metrics: 9091
  env:
    - name: POLICY_DIR
      value: /policies
    - name: TRUST_SCORE_INITIAL
      value: "0.5"
    - name: EXECUTION_RING
      value: "3"
    - name: OTEL_EXPORTER_OTLP_ENDPOINT
      value: http://otel-collector:4318

# Policy ConfigMap
policies:
  configMapName: openclaw-policies

# Monitoring
monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
    interval: 15s
  prometheusRule:
    enabled: true
```

### Deploy

```bash
# Create namespace
kubectl create namespace openclaw-governed

# Create policy ConfigMap
kubectl create configmap openclaw-policies \
  --from-file=policies/ \
  -n openclaw-governed

# Deploy with Helm
helm install openclaw-governed \
  packages/agent-mesh/charts/agentmesh \
  -f values-openclaw.yaml \
  -n openclaw-governed

# Verify
kubectl get pods -n openclaw-governed
kubectl logs -l app=openclaw-governed -c governance-sidecar -n openclaw-governed
```

---

## Governance Policies for OpenClaw

OpenClaw's broad capabilities require carefully scoped policies. Here's a recommended starting configuration:

**`policies/openclaw-default.yaml`:**

```yaml
version: "1.0"
agent: openclaw
description: Default governance policy for OpenClaw autonomous operations

policies:
  # Rate limiting — prevent runaway API consumption
  - name: rate-limit
    type: rate_limit
    max_calls: 100
    window: 1m

  # Shell command restrictions
  - name: shell-safety
    type: capability
    allowed_actions:
      - "shell:ls"
      - "shell:cat"
      - "shell:grep"
      - "shell:find"
      - "shell:echo"
      - "shell:python"
      - "shell:pip"
      - "shell:git"
    denied_actions:
      - "shell:rm -rf /*"
      - "shell:dd"
      - "shell:mkfs"
      - "shell:shutdown"
      - "shell:reboot"
      - "shell:chmod 777"

  # Content safety — block prompt injection patterns
  - name: content-safety
    type: pattern
    blocked_patterns:
      - "ignore previous instructions"
      - "ignore all prior"
      - "you are now"
      - "new system prompt"
      - "DROP TABLE"
      - "UNION SELECT"
      - "rm -rf /"
      - "; curl "

  # File system boundaries
  - name: filesystem-scope
    type: capability
    allowed_actions:
      - "file:read:/workspace/*"
      - "file:write:/workspace/*"
    denied_actions:
      - "file:read:/etc/shadow"
      - "file:read:/etc/passwd"
      - "file:write:/etc/*"
      - "file:write:/usr/*"
      - "file:write:/root/*"

  # Network restrictions
  - name: network-policy
    type: capability
    allowed_actions:
      - "http:GET:*"
      - "http:POST:api.openai.com/*"
      - "http:POST:api.anthropic.com/*"
    denied_actions:
      - "http:*:169.254.169.254/*"    # Block cloud metadata
      - "http:*:localhost:*"            # Block localhost access
      - "http:*:10.*"                   # Block internal network

  # Approval required for destructive operations
  - name: destructive-approval
    type: approval
    actions:
      - "delete_*"
      - "shell:rm *"
      - "file:write:/workspace/.env"
    min_approvals: 1
    approval_timeout_minutes: 15
```

---

## Monitoring and SLOs

### Recommended SLOs for OpenClaw

```yaml
# Agent SRE configuration
slos:
  - name: openclaw-safety
    description: Percentage of actions that comply with policy
    target: 99.0
    window: 1h
    sli:
      metric: policy_decisions_allowed
      total: policy_decisions_total

  - name: openclaw-latency
    description: Governance overhead latency
    target: 99.9
    window: 1h
    sli:
      metric: governance_latency_ms
      threshold: 1.0

  - name: openclaw-availability
    description: Governance sidecar availability
    target: 99.95
    window: 24h
    sli:
      metric: health_check_success
      total: health_check_total

# Actions when SLO is breached
breach_actions:
  openclaw-safety:
    - downgrade_ring: 3        # Move to most restricted ring
    - alert: oncall            # Page the on-call engineer
    - circuit_breaker: open    # Block new requests until reviewed
```

### Grafana Dashboard

Import the pre-built dashboard for OpenClaw governance metrics:

```bash
# Port-forward Grafana
kubectl port-forward svc/grafana 3000:3000 -n monitoring

# Import dashboard from repo
# Dashboard JSON: packages/agent-mesh/deployments/grafana/dashboards/
```

Key panels:
- **Policy decisions/sec** — Allowed vs. denied over time
- **Trust score trend** — OpenClaw's trust score with decay visualization
- **Execution ring** — Current ring assignment and transition history
- **SLO burn rate** — Safety SLO remaining error budget
- **Top blocked actions** — Most frequently denied tool calls

---

## Troubleshooting

### Governance sidecar not intercepting calls

```bash
# Check sidecar is running
kubectl logs <pod> -c governance-sidecar -n openclaw-governed

# Verify the proxy endpoint
kubectl exec <pod> -c openclaw -- curl http://localhost:8081/health

# Check policy files are mounted
kubectl exec <pod> -c governance-sidecar -- ls /policies/
```

### OpenClaw actions being incorrectly blocked

```bash
# Check recent policy decisions
kubectl logs <pod> -c governance-sidecar -n openclaw-governed | grep DENIED

# Review the specific policy that triggered
kubectl logs <pod> -c governance-sidecar -n openclaw-governed | grep policy_name
```

### Trust score decaying too fast

Adjust trust decay settings in the sidecar configuration:

```yaml
env:
  - name: TRUST_DECAY_RATE
    value: "0.01"          # Slower decay (default: 0.05)
  - name: TRUST_DECAY_INTERVAL
    value: "3600"          # Decay every hour (default: 300s)
```

---

## Next Steps

- [Full AKS deployment guide](../../packages/agent-mesh/docs/deployment/azure.md) for enterprise features (managed identity, Key Vault, HA)
- [Agent SRE documentation](../../packages/agent-sre/README.md) for SLO configuration
- [AgentMesh identity](../../packages/agent-mesh/README.md) for multi-agent scenarios with OpenClaw
- [Chaos engineering templates](../../packages/agent-sre/README.md) for testing governance under failure conditions
