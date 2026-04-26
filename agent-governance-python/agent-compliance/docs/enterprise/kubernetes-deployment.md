# Kubernetes Deployment Guide

Step-by-step guide to deploying the Agent Governance stack on Kubernetes.

---

## Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|-----------------|-------|
| Kubernetes | 1.27+ | EKS, GKE, AKS, or self-managed |
| Helm | 3.12+ | For chart installation |
| kubectl | 1.27+ | Configured for your cluster |
| cert-manager | 1.12+ | For TLS/mTLS certificate management |
| Postgres | 14+ | For audit log storage (production) |

Verify your environment:

```bash
kubectl version --client
helm version
kubectl cluster-info
```

---

## Namespace Isolation

Create a dedicated namespace for governance components. This enables resource quotas, network policies, and RBAC scoping.

```bash
kubectl create namespace agent-governance

# Apply resource quota
kubectl apply -f - <<EOF
apiVersion: v1
kind: ResourceQuota
metadata:
  name: governance-quota
  namespace: agent-governance
spec:
  hard:
    requests.cpu: "8"
    requests.memory: 16Gi
    limits.cpu: "16"
    limits.memory: 32Gi
    pods: "50"
EOF
```

---

## Helm Chart Values

Create a `values.yaml` for your deployment:

```yaml
# values.yaml — Agent Governance Helm Chart
global:
  namespace: agent-governance
  imageRegistry: ghcr.io/microsoft
  imagePullPolicy: IfNotPresent

agentOS:
  enabled: true
  replicas: 3
  image:
    repository: agent-os
    tag: latest
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: "1"
      memory: 1Gi
  config:
    logLevel: info
    policyPath: /etc/agent-governance-python/agent-os/policies
    auditEnabled: true
  service:
    type: ClusterIP
    port: 8080

agentMesh:
  enabled: true
  replicas: 2
  image:
    repository: agent-mesh
    tag: latest
  resources:
    requests:
      cpu: 250m
      memory: 256Mi
    limits:
      cpu: 500m
      memory: 512Mi
  config:
    mtlsEnabled: true
    trustScoreThreshold: 0.7

runtime:
  enabled: true
  replicas: 2
  image:
    repository: agent-runtime
    tag: latest
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: "1"
      memory: 1Gi
  config:
    maxAgentsPerPod: 50
    executionTimeout: 30s
    killSwitchEnabled: true

agentSRE:
  enabled: true
  replicas: 1
  image:
    repository: agent-sre
    tag: latest
  resources:
    requests:
      cpu: 250m
      memory: 256Mi
    limits:
      cpu: 500m
      memory: 512Mi
  config:
    otelEndpoint: http://otel-collector.observability:4317
    sloEvaluationInterval: 60s
    chaosEnabled: false  # Enable after initial deployment

auditStore:
  enabled: true
  type: postgres
  host: postgres.agent-governance.svc.cluster.local
  port: 5432
  database: agent_audit
  existingSecret: governance-db-credentials
  retentionDays: 90

ingress:
  enabled: true
  className: nginx
  host: governance.internal.example.com
  tls:
    enabled: true
    secretName: governance-tls

networkPolicy:
  enabled: true
  allowedNamespaces:
    - agent-workloads
    - monitoring
```

---

## Deployment Steps

### 1. Add the Helm Repository

```bash
helm repo add agent-governance https://microsoft.github.io/agent-governance-toolkit
helm repo update
```

### 2. Create Secrets

```bash
# Database credentials
kubectl create secret generic governance-db-credentials \
  --namespace agent-governance \
  --from-literal=username=governance \
  --from-literal=password=$(openssl rand -base64 32)

# API authentication key
kubectl create secret generic governance-api-key \
  --namespace agent-governance \
  --from-literal=api-key=$(openssl rand -hex 32)
```

### 3. Install the Chart

```bash
helm install agent-governance agent-governance/agent-governance \
  --namespace agent-governance \
  --values values.yaml \
  --wait \
  --timeout 5m
```

### 4. Verify Deployment

```bash
# Check all pods are running
kubectl get pods -n agent-governance

# Check services
kubectl get svc -n agent-governance

# Test the governance API
kubectl port-forward svc/agent-os 8080:8080 -n agent-governance &
curl http://localhost:8080/healthz
```

---

## Resource Requests and Limits

Recommended resource configurations by deployment size:

| Component | Starter (≤20 agents) | Growth (≤200 agents) | Enterprise (200+) |
|-----------|----------------------|----------------------|--------------------|
| Agent OS | 250m/256Mi → 500m/512Mi | 500m/512Mi → 1/1Gi | 1/1Gi → 2/2Gi |
| AgentMesh | 100m/128Mi → 250m/256Mi | 250m/256Mi → 500m/512Mi | 500m/512Mi → 1/1Gi |
| Agent Runtime | 250m/256Mi → 500m/512Mi | 500m/512Mi → 1/1Gi | 1/1Gi → 2/2Gi |
| Agent SRE | 100m/128Mi → 250m/256Mi | 250m/256Mi → 500m/512Mi | 500m/512Mi → 1/1Gi |

> Format: `requests.cpu/requests.memory → limits.cpu/limits.memory`

---

## Network Policies

Restrict the governance API to internal traffic only:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: governance-api-policy
  namespace: agent-governance
spec:
  podSelector:
    matchLabels:
      app: agent-os
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Allow traffic from agent workload namespaces
    - from:
        - namespaceSelector:
            matchLabels:
              governance-access: "true"
      ports:
        - protocol: TCP
          port: 8080
    # Allow traffic from monitoring namespace
    - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring
      ports:
        - protocol: TCP
          port: 9090  # Metrics
  egress:
    # Allow DNS
    - to: []
      ports:
        - protocol: UDP
          port: 53
    # Allow audit store
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
    # Allow OTEL collector
    - to:
        - namespaceSelector:
            matchLabels:
              name: observability
      ports:
        - protocol: TCP
          port: 4317
```

Label namespaces that should access the governance API:

```bash
kubectl label namespace agent-workloads governance-access=true
```

---

## PersistentVolumeClaim for Audit Logs

For environments using file-based audit storage (non-production or alongside Postgres):

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: audit-logs
  namespace: agent-governance
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: gp3  # Adjust for your cloud provider
  resources:
    requests:
      storage: 50Gi
---
# Mount in the Agent OS deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent-os
  namespace: agent-governance
spec:
  template:
    spec:
      containers:
        - name: agent-os
          volumeMounts:
            - name: audit-logs
              mountPath: /var/log/agent-governance/audit
              readOnly: false
      volumes:
        - name: audit-logs
          persistentVolumeClaim:
            claimName: audit-logs
```

---

## Ingress Configuration

Expose the governance API internally using an Ingress resource:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: governance-ingress
  namespace: agent-governance
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    # Internal-only: restrict to private subnets
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8,172.16.0.0/12"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - governance.internal.example.com
      secretName: governance-tls
  rules:
    - host: governance.internal.example.com
      http:
        paths:
          - path: /api/
            pathType: Prefix
            backend:
              service:
                name: agent-os
                port:
                  number: 8080
          - path: /healthz
            pathType: Exact
            backend:
              service:
                name: agent-os
                port:
                  number: 8080
```

---

## TLS/mTLS Setup with cert-manager

### Install cert-manager (if not already installed)

```bash
helm repo add jetstack https://charts.jetstack.io
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set installCRDs=true
```

### Create a ClusterIssuer

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: governance-ca-issuer
spec:
  selfSigned: {}
---
# For production, use Let's Encrypt or your internal CA
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: governance-prod-issuer
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: platform-team@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - http01:
          ingress:
            class: nginx
```

### Request Certificates for mTLS

```yaml
# Server certificate for the governance API
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: governance-server-cert
  namespace: agent-governance
spec:
  secretName: governance-tls
  issuerRef:
    name: governance-ca-issuer
    kind: ClusterIssuer
  commonName: governance.internal.example.com
  dnsNames:
    - governance.internal.example.com
    - agent-os.agent-governance.svc.cluster.local
  duration: 8760h  # 1 year
  renewBefore: 720h  # 30 days

---
# Client certificate for agents (mTLS)
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: agent-client-cert
  namespace: agent-workloads
spec:
  secretName: agent-mtls-cert
  issuerRef:
    name: governance-ca-issuer
    kind: ClusterIssuer
  commonName: agent-client
  usages:
    - client auth
  duration: 2160h  # 90 days
  renewBefore: 360h  # 15 days
```

---

## Next Steps

- Apply the [Security Hardening Checklist](security-hardening.md) before production
- Review the [Scaling Guide](scaling-guide.md) for right-sizing
- Set up monitoring with the [Agent SRE](https://github.com/microsoft/agent-governance-toolkit) component

---

*Part of the [Enterprise Deployment Guide](README.md)*
