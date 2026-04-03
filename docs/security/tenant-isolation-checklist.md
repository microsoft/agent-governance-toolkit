<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Tenant Isolation Checklist

Multi-tenant deployment security guidance for the Agent Governance Toolkit.

## Pre-Deployment Checklist

### Kubernetes Namespace Isolation

- [ ] Create dedicated namespace per tenant (`kubectl create ns tenant-<id>`)
- [ ] Apply NetworkPolicy restricting cross-namespace traffic
- [ ] RBAC roles scoped to tenant namespace (no cluster-wide bindings)
- [ ] Pod Security Standards set to `restricted` profile
- [ ] Resource quotas per tenant namespace (CPU, memory, pod count)
- [ ] Secret encryption at rest enabled (etcd encryption provider)

```yaml
# NetworkPolicy: deny all cross-namespace ingress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-cross-namespace
  namespace: tenant-acme
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {}  # same namespace only
```

### Trust Store Separation

- [ ] Separate trust store per tenant (no shared state)
- [ ] Trust scores scoped by tenant namespace
- [ ] No cross-tenant trust propagation without explicit federation

```yaml
# Per-tenant trust store config
apiVersion: v1
kind: ConfigMap
metadata:
  name: agt-trust-config
  namespace: tenant-acme
data:
  AGT_TRUST_PERSIST_PATH: "/data/trust/tenant-acme.json"
  AGT_TRUST_THRESHOLD: "500"
```

### Audit Log Separation

- [ ] Per-tenant audit log streams
- [ ] Audit sink routing by namespace label
- [ ] Cross-tenant audit queries blocked by RBAC

```yaml
# Fluent Bit filter for tenant-scoped log routing
[FILTER]
    Name    grep
    Match   kube.*
    Regex   kubernetes.namespace_name ^tenant-acme$

[OUTPUT]
    Name    azure_blob
    Match   kube.*
    Account_name    ${STORAGE_ACCOUNT}
    Container_name  audit-tenant-acme
    Shared_key      ${STORAGE_KEY}
    Path            audit/
```

## Data Residency

### Node Affinity for Region Pinning

```yaml
# Pin tenant workloads to specific region
apiVersion: v1
kind: Pod
metadata:
  name: agt-sidecar
  namespace: tenant-acme
spec:
  nodeSelector:
    topology.kubernetes.io/region: eastus
    data-residency: us-east
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
          - matchExpressions:
              - key: topology.kubernetes.io/zone
                operator: In
                values: [eastus-1, eastus-2]
```

### PersistentVolume Topology Constraints

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: agt-audit-pvc
  namespace: tenant-acme
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: managed-premium-zrs
  resources:
    requests:
      storage: 10Gi
  # Ensure storage stays in tenant's region
  volumeMode: Filesystem
```

## Multi-Tenant Policy Engine

### Tenant-Scoped Policies

```yaml
# Policy scoped to tenant namespace
apiVersion: "1.0"
version: "1.0"
name: tenant-acme-policy
scope: tenant
agent: "*"
rules:
  - name: restrict-data-access
    condition: "tenant_id == 'acme'"
    ruleAction: deny
    description: "Block cross-tenant data access"
    priority: 100

  - name: rate-limit-per-tenant
    condition: "tenant_id == 'acme'"
    ruleAction: rate_limit
    limit: "100/minute"
```

### Cross-Tenant Communication Rules

```python
from agentmesh import PolicyEngine

engine = PolicyEngine()

# Load tenant-specific policy
engine.load_from_yaml(f"policies/tenant-{tenant_id}.yaml")

# Evaluate with tenant context
decision = engine.evaluate(
    action="data.read",
    context={"tenant_id": "acme", "source_tenant": "acme", "target_tenant": "acme"}
)

# Cross-tenant requests denied by default
cross_tenant = engine.evaluate(
    action="data.read",
    context={"tenant_id": "acme", "source_tenant": "acme", "target_tenant": "contoso"}
)
assert cross_tenant.label() == "deny"
```

## Egress Controls

- [ ] Egress NetworkPolicy restricting outbound traffic
- [ ] DNS policy limiting resolution to approved domains
- [ ] Data exfiltration prevention via egress proxy

```yaml
# Egress NetworkPolicy: allow only governance API + DNS
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: tenant-acme
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: agt-system
      ports:
        - port: 443
    - to:  # DNS
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
```
