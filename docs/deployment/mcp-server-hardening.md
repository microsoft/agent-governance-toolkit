# MCP Server Hardening Guide

Deployment guidance for running MCP tool servers securely, aligned with
[OWASP MCP Security Cheat Sheet §3 — Sandbox & Isolate MCP Servers](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).

## Transport: prefer stdio over HTTP

When the MCP server runs on the same host as the agent, use **stdio** transport
rather than HTTP/SSE. This eliminates the network attack surface entirely —
no open ports, no TLS configuration, no SSRF vectors.

```yaml
# docker-compose.yml — stdio transport
services:
  mcp-server:
    image: myregistry/mcp-tools:1.2.3@sha256:abc...
    stdin_open: true
    read_only: true
    security_opt: ["no-new-privileges"]
```

For HTTP transport, require mTLS between agent and server (see §6).

## Kubernetes: securityContext

Every MCP server pod should run as a non-root user with a read-only root
filesystem and all capabilities dropped:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mcp-server
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534          # nobody
    runAsGroup: 65534
    fsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: mcp-tools
      image: myregistry/mcp-tools:1.2.3@sha256:abc...
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          cpu: "500m"
          memory: "256Mi"
      volumeMounts:
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: tmp
      emptyDir:
        sizeLimit: 50Mi
```

## Network Isolation: NetworkPolicy

Restrict MCP servers so they can **only** communicate with the agent
orchestrator and required backends (database, blob storage). Block all
egress to the public internet and to the cloud metadata service:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mcp-server-policy
spec:
  podSelector:
    matchLabels:
      app: mcp-server
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: agent-orchestrator
      ports:
        - port: 8080
          protocol: TCP
  egress:
    # Allow DNS
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
          protocol: UDP
    # Allow specific backends
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - port: 5432
          protocol: TCP
    # Block cloud metadata (SSRF protection)
    # Azure IMDS: 169.254.169.254
    # AWS IMDS: 169.254.169.254
    # GCP metadata: metadata.google.internal (100.100.100.200)
    # These are blocked by default when no egress rule matches.
```

## gVisor / Kata Containers for Untrusted Servers

For MCP servers that execute arbitrary code (code interpreters, shell tools),
use a sandbox runtime like [gVisor](https://gvisor.dev/) or
[Kata Containers](https://katacontainers.io/):

```yaml
# AKS with gVisor runtime class
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
---
apiVersion: v1
kind: Pod
metadata:
  name: mcp-code-interpreter
spec:
  runtimeClassName: gvisor
  containers:
    - name: interpreter
      image: myregistry/code-interpreter:1.0@sha256:def...
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
```

On **Azure Kubernetes Service (AKS)**:
- Enable the [AKS Kata Containers documentation](https://learn.microsoft.com/azure/aks/) for VM-level isolation guidance.
- Use [Azure Container Instances (ACI)](https://learn.microsoft.com/azure/container-instances/) with Hyper-V isolation for per-tool ephemeral sandboxes.

## File System Restrictions

MCP tools should only access explicitly mounted paths:

```yaml
volumeMounts:
  - name: workspace
    mountPath: /workspace
    readOnly: false          # only if tool needs write
  - name: config
    mountPath: /config
    readOnly: true
```

Combine with the `.NET SDK path traversal sanitization pattern`
(`SanitizationDefaults.AllPatterns` detects `../` sequences) to prevent
escape even if mounts are misconfigured.

## Resource Limits

Prevent a compromised tool from consuming cluster resources:

| Resource | Recommendation |
|----------|---------------|
| CPU | 500m limit per tool pod |
| Memory | 256Mi limit (512Mi for code interpreters) |
| Ephemeral storage | 50Mi via emptyDir sizeLimit |
| Process count | `pids-limit` cgroup (64 for simple tools) |
| Network bandwidth | Use Cilium/Calico bandwidth annotations |

## Checklist

- [ ] Non-root user (`runAsNonRoot: true`)
- [ ] Read-only root filesystem
- [ ] All capabilities dropped
- [ ] seccomp profile enabled (`RuntimeDefault`)
- [ ] NetworkPolicy restricts ingress + egress
- [ ] Cloud metadata IPs blocked (169.254.169.254)
- [ ] Resource limits set (CPU, memory, storage)
- [ ] gVisor/Kata for code execution tools
- [ ] stdio transport where possible
- [ ] Container images use SHA digest tags
- [ ] `.NET SDK McpGateway` sanitization + response scanning enabled

## Related

- [McpGateway](../../packages/agent-governance-dotnet/README.md#mcp-protocol-support) — 5-stage governance pipeline
- [McpSecurityScanner](../../packages/agent-governance-dotnet/README.md#mcp-protocol-support) — tool definition scanning
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
