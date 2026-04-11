# Governed AI Agent in OpenShell Sandbox

Demonstrates the **Agent Governance Toolkit** providing policy enforcement, trust scoring, and audit logging inside an **NVIDIA OpenShell** sandbox.

```
┌──────────────────────────────────────────────────────────┐
│  OpenShell Sandbox                                        │
│                                                           │
│  ┌─────────────────┐    ┌──────────────────────────────┐ │
│  │  AI Agent        │    │  Governance Skill (AGT)      │ │
│  │                  │    │                              │ │
│  │  "shell:rm -rf"  ├────►  Policy check  → ❌ DENIED   │ │
│  │  "shell:python"  ├────►  Policy check  → ✅ ALLOWED  │ │
│  │                  │    │  Trust scoring → 0.55        │ │
│  │                  │    │  Audit trail   → logged      │ │
│  └─────────────────┘    └──────────────────────────────┘ │
│                                                           │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  OpenShell Engine: Landlock + seccomp + OPA proxy    │ │
│  └──────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# From the repo root
python examples/openshell-governed/demo.py
```

## What You'll See

The demo simulates 6 agent actions through the governance layer:

| # | Action | Result | Why |
|---|--------|--------|-----|
| 1 | Read `/workspace/main.py` | ✅ Allowed | File reads permitted |
| 2 | Run `python` | ✅ Allowed | Safe shell command |
| 3 | Run `git` | ✅ Allowed | Safe shell command |
| 4 | `rm -rf /tmp/data` | ❌ Denied | Destructive command blocked |
| 5 | Access `169.254.169.254` | ❌ Denied | Cloud metadata blocked |
| 6 | Write to `/etc/shadow` | ❌ Denied | Outside workspace |

Trust score decays from 1.00 → ~0.55 as violations accumulate.

## Policy

See [`policies/sandbox-policy.yaml`](policies/sandbox-policy.yaml) for the governance rules.

## Learn More

- [OpenShell Integration Guide](../../docs/integrations/openshell.md) — Full architecture
- [OpenClaw Sidecar Deployment](../../docs/deployment/openclaw-sidecar.md) — AKS + Docker Compose
- [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) — The sandbox runtime
