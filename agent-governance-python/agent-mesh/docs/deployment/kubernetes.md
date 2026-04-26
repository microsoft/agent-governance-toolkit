# Kubernetes Deployment Guide

This guide covers deploying AgentMesh on Kubernetes as a standalone service or as a sidecar alongside your agent containers.

> **See also:** The root [DEPLOYMENT.md](../../DEPLOYMENT.md) for Docker Compose and Helm-based quick starts, and the [charts/agentmesh](../../charts/agentmesh/) Helm chart for production deployments.

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Standalone Deployment](#standalone-deployment)
- [Sidecar Pattern](#sidecar-pattern)
- [Configuration](#configuration)
- [Secrets Management](#secrets-management)
- [Health Checks](#health-checks)
- [Scaling](#scaling)
- [Monitoring](#monitoring)
- [Complete Example](#complete-example)

---

## Overview

AgentMesh can be deployed in two primary patterns on Kubernetes:

| Pattern | Use Case | Description |
|---------|----------|-------------|
| **Standalone** | Shared trust proxy | A central AgentMesh Deployment + Service that multiple agents connect to over the network |
| **Sidecar** | Per-agent governance | An AgentMesh container injected into each agent Pod, providing local trust enforcement via `localhost` |

**Standalone** is simpler to operate and works well when agents are HTTP-based services. **Sidecar** provides stronger isolation and lower latency since the proxy runs in the same Pod as the agent.

### Port Reference

| Port | Service | Purpose |
|------|---------|---------|
| 8080 | Server | AgentMesh API and trust operations |
| 8081 | Sidecar | MCP proxy for agent traffic |
| 9090 | Server | Prometheus metrics |
| 9091 | Sidecar | Prometheus metrics |

---

## Prerequisites

- **Kubernetes cluster** — v1.24 or later
- **kubectl** — configured to access your cluster
- **Helm 3.x** — optional, for chart-based deployment (see [charts/agentmesh](../../charts/agentmesh/))
- **Container images** — `agentmesh/server:1.0.0-alpha1` and `agentmesh/sidecar:1.0.0-alpha1`

```bash
# Verify cluster access
kubectl cluster-info
kubectl version --client
```

---

## Standalone Deployment

Deploy AgentMesh as a central service that agents connect to over the cluster network.

### Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: agentmesh
  labels:
    app.kubernetes.io/part-of: agentmesh
```

### Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agentmesh-server
  namespace: agentmesh
  labels:
    app.kubernetes.io/name: agentmesh
    app.kubernetes.io/component: server
spec:
  replicas: 3
  selector:
    matchLabels:
      app.kubernetes.io/name: agentmesh
      app.kubernetes.io/component: server
  template:
    metadata:
      labels:
        app.kubernetes.io/name: agentmesh
        app.kubernetes.io/component: server
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      serviceAccountName: agentmesh
      containers:
        - name: agentmesh
          image: agentmesh/server:1.0.0-alpha1
          ports:
            - name: api
              containerPort: 8080
              protocol: TCP
            - name: metrics
              containerPort: 9090
              protocol: TCP
          envFrom:
            - configMapRef:
                name: agentmesh-config
          env:
            - name: AGENTMESH_AGENT_PRIVATE_KEY
              valueFrom:
                secretKeyRef:
                  name: agentmesh-agent-keys
                  key: private-key
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
            limits:
              cpu: 1000m
              memory: 1Gi
          securityContext:
            capabilities:
              drop: ["ALL"]
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
          livenessProbe:
            httpGet:
              path: /health
              port: api
            initialDelaySeconds: 10
            periodSeconds: 15
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /ready
              port: api
            initialDelaySeconds: 5
            periodSeconds: 10
            failureThreshold: 3
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
```

### Service

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: agentmesh
  namespace: agentmesh
  labels:
    app.kubernetes.io/name: agentmesh
    app.kubernetes.io/component: server
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: agentmesh
    app.kubernetes.io/component: server
  ports:
    - name: api
      port: 8080
      targetPort: api
      protocol: TCP
    - name: metrics
      port: 9090
      targetPort: metrics
      protocol: TCP
```

### ServiceAccount

```yaml
# serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: agentmesh
  namespace: agentmesh
  labels:
    app.kubernetes.io/name: agentmesh
```

### Apply standalone resources

```bash
kubectl apply -f namespace.yaml
kubectl apply -f serviceaccount.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# Verify
kubectl get pods -n agentmesh
kubectl get svc -n agentmesh
```

---

## Sidecar Pattern

Inject AgentMesh as a sidecar container in your agent Pods. The agent communicates with the sidecar over `localhost:8081`, and the sidecar enforces trust policies before forwarding traffic.

```yaml
# agent-with-sidecar.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-agent
  namespace: my-app
  labels:
    app.kubernetes.io/name: my-agent
spec:
  replicas: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: my-agent
  template:
    metadata:
      labels:
        app.kubernetes.io/name: my-agent
        agentmesh-inject: enabled
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9091"
        prometheus.io/path: "/metrics"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        # Your agent container
        - name: agent
          image: my-company/my-agent:v1.0.0
          ports:
            - name: http
              containerPort: 3000
              protocol: TCP
          env:
            # Point the agent at the local sidecar proxy
            - name: AGENTMESH_PROXY_URL
              value: "http://localhost:8081"
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
            limits:
              cpu: 1000m
              memory: 1Gi

        # AgentMesh sidecar container
        - name: agentmesh-sidecar
          image: agentmesh/sidecar:1.0.0-alpha1
          ports:
            - name: proxy
              containerPort: 8081
              protocol: TCP
            - name: metrics
              containerPort: 9091
              protocol: TCP
          envFrom:
            - configMapRef:
                name: agentmesh-config
          env:
            - name: AGENTMESH_AGENT_PRIVATE_KEY
              valueFrom:
                secretKeyRef:
                  name: agentmesh-agent-keys
                  key: private-key
            - name: AGENTMESH_POLICY
              value: "strict"
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          securityContext:
            capabilities:
              drop: ["ALL"]
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
          livenessProbe:
            exec:
              command:
                - cat
                - /var/run/agentmesh/healthy
            initialDelaySeconds: 10
            periodSeconds: 15
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /health
              port: proxy
            initialDelaySeconds: 5
            periodSeconds: 10
            failureThreshold: 3
          volumeMounts:
            - name: agentmesh-health
              mountPath: /var/run/agentmesh
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: agentmesh-health
          emptyDir: {}
        - name: tmp
          emptyDir: {}
```

> **Tip:** The Helm chart supports automatic sidecar injection via a mutating webhook when `sidecarInjector.enabled: true` is set. Label your namespace with `agentmesh-inject: enabled` to opt in. See [charts/agentmesh/values.yaml](../../charts/agentmesh/values.yaml).

---

## Configuration

Use a ConfigMap to manage AgentMesh settings across all Pods.

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: agentmesh-config
  namespace: agentmesh
  labels:
    app.kubernetes.io/name: agentmesh
data:
  # Storage backend: memory, redis, or postgres
  AGENTMESH_STORAGE_BACKEND: "redis"
  AGENTMESH_CACHE_ENABLED: "true"
  AGENTMESH_CACHE_TTL: "300"

  # Redis connection (when using redis backend)
  AGENTMESH_REDIS_HOST: "agentmesh-redis-master"
  AGENTMESH_REDIS_PORT: "6379"

  # Trust configuration
  AGENTMESH_TRUST_INITIAL_SCORE: "800"
  AGENTMESH_TRUST_DECAY_RATE: "2.0"
  AGENTMESH_TRUST_DECAY_FLOOR: "100"
  AGENTMESH_TRUST_MIN_THRESHOLD: "300"

  # Delegation
  AGENTMESH_DELEGATION_MAX_DEPTH: "5"

  # Governance
  AGENTMESH_GOVERNANCE_DEFAULT_POLICY: "standard"
  AGENTMESH_GOVERNANCE_SHADOW_MODE: "false"
  AGENTMESH_GOVERNANCE_AUDIT_RETENTION_DAYS: "90"

  # Observability
  AGENTMESH_LOG_LEVEL: "INFO"
  AGENTMESH_LOG_FORMAT: "json"
  AGENTMESH_OTEL_ENABLED: "true"
  AGENTMESH_OTEL_ENDPOINT: "http://otel-collector:4317"

  # Policy for proxy/sidecar
  AGENTMESH_POLICY: "strict"
```

Apply the ConfigMap before deploying the server or sidecar:

```bash
kubectl apply -f configmap.yaml
```

---

## Secrets Management

Store agent private keys in Kubernetes Secrets. **Never store private keys in ConfigMaps, environment variables in plain YAML, or container images.**

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: agentmesh-agent-keys
  namespace: agentmesh
  labels:
    app.kubernetes.io/name: agentmesh
type: Opaque
data:
  # Base64-encoded Ed25519 private key
  # Generate with: agentmesh identity generate --output-key | base64
  private-key: <base64-encoded-private-key>
```

### Generating a key and creating the Secret imperatively

```bash
# Generate a key pair
agentmesh identity generate --output-key > /tmp/agent-key.pem

# Create the Secret from the file
kubectl create secret generic agentmesh-agent-keys \
  --namespace agentmesh \
  --from-file=private-key=/tmp/agent-key.pem

# Clean up the local key file immediately
rm /tmp/agent-key.pem
```

### Using external secret managers

For production, consider integrating with an external secret manager:

- **Azure Key Vault** via the [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/)
- **HashiCorp Vault** via the [Vault Agent Injector](https://developer.hashicorp.com/vault/docs/platform/k8s)
- **AWS Secrets Manager** via the [AWS Secrets Manager CSI Driver](https://docs.aws.amazon.com/secretsmanager/latest/userguide/integrating_csi_driver.html)

---

## Health Checks

AgentMesh exposes health endpoints for Kubernetes probes.

### Server (standalone)

| Endpoint | Port | Purpose |
|----------|------|---------|
| `/health` | 8080 | Liveness — is the process alive? |
| `/ready`  | 8080 | Readiness — can it accept traffic? |

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 15
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3
```

### Sidecar

The sidecar uses a file-based liveness check and HTTP readiness:

```yaml
livenessProbe:
  exec:
    command:
      - cat
      - /var/run/agentmesh/healthy
  initialDelaySeconds: 10
  periodSeconds: 15
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health
    port: 8081
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3
```

---

## Scaling

Use a HorizontalPodAutoscaler to scale the standalone deployment based on CPU and memory usage.

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: agentmesh-server
  namespace: agentmesh
  labels:
    app.kubernetes.io/name: agentmesh
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: agentmesh-server
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Pods
          value: 1
          periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 30
      policies:
        - type: Pods
          value: 2
          periodSeconds: 60
```

> **Note:** For the sidecar pattern, scaling is handled by the agent's own HPA since the sidecar scales with the agent Pod.

---

## Monitoring

### ServiceMonitor (Prometheus Operator)

If you are running the [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator), create a ServiceMonitor to scrape AgentMesh metrics. This integrates with the Prometheus metrics added in [#123](https://github.com/microsoft/agent-governance-toolkit/issues/123).

```yaml
# servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: agentmesh
  namespace: agentmesh
  labels:
    app.kubernetes.io/name: agentmesh
    release: prometheus
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: agentmesh
  namespaceSelector:
    matchNames:
      - agentmesh
  endpoints:
    - port: metrics
      interval: 15s
      path: /metrics
      scrapeTimeout: 10s
```

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `agentmesh_handshake_total` | Counter | Trust handshake count |
| `agentmesh_trust_score_gauge` | Gauge | Current trust scores |
| `agentmesh_policy_violation_count` | Counter | Policy violation count |
| `agentmesh_registry_size` | Gauge | Agent registry size |
| `agentmesh_api_request_duration_seconds` | Histogram | API request latency |

### Prometheus Alerts

```yaml
# prometheusrule.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: agentmesh-alerts
  namespace: agentmesh
  labels:
    app.kubernetes.io/name: agentmesh
    release: prometheus
spec:
  groups:
    - name: agentmesh
      rules:
        - alert: AgentMeshHighPolicyViolations
          expr: rate(agentmesh_policy_violation_count[5m]) > 10
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "High policy violation rate in AgentMesh"
            description: "More than 10 violations/sec over the last 5 minutes."

        - alert: AgentMeshLowTrustScore
          expr: avg(agentmesh_trust_score_gauge) < 400
          for: 10m
          labels:
            severity: critical
          annotations:
            summary: "Average trust score below safe threshold"
            description: "Average trust score is {{ $value }}, below the 400 threshold."

        - alert: AgentMeshPodNotReady
          expr: kube_pod_status_ready{namespace="agentmesh", condition="true"} == 0
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "AgentMesh pod not ready"
```

---

## Complete Example

This section brings all the manifests together into a single deployable example. Save each block to the indicated file, then apply in order.

### Directory structure

```
k8s/
├── namespace.yaml
├── serviceaccount.yaml
├── configmap.yaml
├── secret.yaml          # ← generate with kubectl create secret
├── deployment.yaml
├── service.yaml
├── hpa.yaml
├── servicemonitor.yaml
└── prometheusrule.yaml
```

### Apply all resources

```bash
# Create namespace and RBAC
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/serviceaccount.yaml

# Configuration and secrets
kubectl apply -f k8s/configmap.yaml
# Create secret imperatively (see Secrets Management section)
kubectl create secret generic agentmesh-agent-keys \
  --namespace agentmesh \
  --from-file=private-key=/tmp/agent-key.pem

# Core workloads
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/hpa.yaml

# Monitoring (requires Prometheus Operator)
kubectl apply -f k8s/servicemonitor.yaml
kubectl apply -f k8s/prometheusrule.yaml

# Verify deployment
kubectl get pods -n agentmesh -w
```

### Verify it works

```bash
# Check all pods are running
kubectl get pods -n agentmesh
# NAME                                READY   STATUS    RESTARTS   AGE
# agentmesh-server-5d4f8b7c9-abc12   1/1     Running   0          30s
# agentmesh-server-5d4f8b7c9-def34   1/1     Running   0          30s
# agentmesh-server-5d4f8b7c9-ghi56   1/1     Running   0          30s

# Test health endpoint
kubectl port-forward -n agentmesh svc/agentmesh 8080:8080 &
curl http://localhost:8080/health
# {"status": "healthy"}

curl http://localhost:8080/ready
# {"status": "ready"}

# Check metrics
kubectl port-forward -n agentmesh svc/agentmesh 9090:9090 &
curl -s http://localhost:9090/metrics | head -20
```

### Using Helm instead

For a production-ready deployment with all dependencies (Redis, PostgreSQL), use the Helm chart in [charts/agentmesh](../../charts/agentmesh/):

```bash
helm install agentmesh ./charts/agentmesh \
  --namespace agentmesh \
  --create-namespace \
  --set redis.auth.password=your-secure-password \
  --set storage.backend=redis
```

See [DEPLOYMENT.md](../../DEPLOYMENT.md) for full Helm configuration options.
