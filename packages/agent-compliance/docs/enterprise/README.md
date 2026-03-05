# Enterprise Deployment Guide

This guide helps organizations deploy the Agent Governance stack in production environments.

Whether you're a single team getting started with AI agent governance or a large enterprise managing hundreds of agents across business units, these guides provide battle-tested patterns for running the stack at scale.

---

## Guides

| Guide | Description |
|-------|-------------|
| [Reference Architecture](reference-architecture.md) | Deployment patterns from single-team to full enterprise — with architecture diagrams |
| [Kubernetes Deployment](kubernetes-deployment.md) | Helm charts, namespace isolation, resource configs, and step-by-step K8s deployment |
| [Security Hardening](security-hardening.md) | Production security checklist — mTLS, RBAC, audit logging, container hardening |
| [Scaling Guide](scaling-guide.md) | Horizontal scaling, benchmarks, resource sizing, caching, and rate limiting |

---

## Prerequisites

- **Agent Governance** installed: `pip install ai-agent-governance[full]`
- Familiarity with the [Agent Governance architecture](../../README.md#architecture)
- For Kubernetes guides: K8s 1.27+, Helm 3.x, kubectl configured

## Stack Components

| Component | Role |
|-----------|------|
| **Agent OS** | Governance kernel — policy enforcement, capability security, audit trails |
| **AgentMesh** | Zero-trust communication — mTLS, encrypted channels, trust scoring |
| **Agent Hypervisor** | Runtime supervisor — execution rings, resource limits, kill switches |
| **Agent SRE** | Reliability engineering — SLOs, health monitoring, chaos engineering |

## Getting Started

1. Start with the [Reference Architecture](reference-architecture.md) to choose your deployment pattern
2. Follow the [Kubernetes Deployment](kubernetes-deployment.md) guide for your target environment
3. Apply the [Security Hardening](security-hardening.md) checklist before going to production
4. Use the [Scaling Guide](scaling-guide.md) to right-size your deployment

---

*Part of the [Agent Governance](https://github.com/microsoft/agent-governance-toolkit) ecosystem*
