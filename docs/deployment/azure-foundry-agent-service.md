# Azure AI Foundry Agent Service Integration

Use the Agent Governance Toolkit as middleware within Azure AI Foundry Agent Service for in-process policy enforcement, capability sandboxing, and audit logging.

> **See also:** [Deployment Overview](README.md) | [AKS Deployment](../../packages/agent-mesh/docs/deployment/azure.md) | [Container Apps Deployment](azure-container-apps.md)

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Middleware Reference](#middleware-reference)
- [Policy Configuration](#policy-configuration)
- [Monitoring in Azure](#monitoring-in-azure)
- [Combining with AKS Sidecar](#combining-with-aks-sidecar)

---

## Overview

Azure AI Foundry Agent Service uses the Microsoft Agent Framework (MAF) under the hood. The Agent Governance Toolkit provides native MAF middleware that plugs directly into Foundry's middleware pipeline — no sidecar or external service required.

```
┌──────────────────────────────────────────────────────────┐
│  Azure AI Foundry Agent Service                          │
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Agent                                             │  │
│  │                                                    │  │
│  │  User Request                                      │  │
│  │       │                                            │  │
│  │       ▼                                            │  │
│  │  ┌──────────────────────┐                          │  │
│  │  │ GovernancePolicyMW   │ ← Policy enforcement     │  │
│  │  ├──────────────────────┤                          │  │
│  │  │ CapabilityGuardMW    │ ← Tool allow/deny lists  │  │
│  │  ├──────────────────────┤                          │  │
│  │  │ AuditTrailMW         │ ← Tamper-proof logging   │  │
│  │  ├──────────────────────┤                          │  │
│  │  │ RogueDetectionMW     │ ← Behavioral anomaly     │  │
│  │  └──────────────────────┘                          │  │
│  │       │                                            │  │
│  │       ▼                                            │  │
│  │  Agent Logic → Tool Calls → Response               │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

---

## How It Works

The toolkit's MAF adapter (`agent_os.integrations.maf_adapter`) provides four composable middleware layers:

| Middleware | MAF Type | What It Does |
|-----------|----------|-------------|
| **GovernancePolicyMiddleware** | `AgentMiddleware` | Enforces declarative policies: token limits, rate limiting, blocked patterns, content safety |
| **CapabilityGuardMiddleware** | `FunctionMiddleware` | Tool-level allow/deny lists and capability sandboxing |
| **AuditTrailMiddleware** | `AgentMiddleware` | Tamper-proof audit logging of every agent action |
| **RogueDetectionMiddleware** | `FunctionMiddleware` | Behavioral anomaly detection with configurable risk thresholds |

Each middleware works independently. Use any combination based on your requirements.

---

## Prerequisites

- Azure AI Foundry workspace with Agent Service enabled
- Python 3.10+
- The Agent Governance Toolkit packages

---

## Installation

```bash
# Install the governance toolkit with MAF support
pip install agent-governance-toolkit[full]

# Or install individual packages
pip install agent-os-kernel agentmesh-platform agent-sre
```

---

## Quick Start

### Minimal Example — Add Governance to a Foundry Agent

```python
from agent_framework import Agent
from agent_os.integrations.maf_adapter import create_governance_middleware

# Create governance middleware with sensible defaults
middleware = create_governance_middleware(
    policy_directory="policies/",
    allowed_tools=["web_search", "file_read", "calculator"],
    enable_rogue_detection=True,
)

# Create your Foundry agent with governance middleware
agent = Agent(
    name="research-assistant",
    instructions="You are a research assistant. Search the web and summarize findings.",
    middleware=middleware,
)
```

That's it. Every tool call the agent makes now passes through the governance pipeline — policy checks, capability guards, audit logging, and rogue detection — before execution.

### Full Example — Custom Policy Configuration

```python
from agent_framework import Agent
from agent_os.integrations.maf_adapter import (
    GovernancePolicyMiddleware,
    CapabilityGuardMiddleware,
    AuditTrailMiddleware,
    RogueDetectionMiddleware,
)

# 1. Policy enforcement
policy_mw = GovernancePolicyMiddleware(
    policy_directory="policies/",
    max_tokens_per_turn=4096,
    rate_limit_per_minute=60,
    blocked_patterns=[
        "ignore previous instructions",
        "DROP TABLE",
        "rm -rf /",
    ],
)

# 2. Capability sandboxing
capability_mw = CapabilityGuardMiddleware(
    allowed_tools=["web_search", "file_read", "calculator"],
    denied_tools=["file_write", "shell_execute", "database_delete"],
)

# 3. Audit trail
audit_mw = AuditTrailMiddleware(
    log_directory="audit_logs/",
    include_tool_args=True,
    include_responses=False,  # Don't log sensitive response data
)

# 4. Rogue agent detection
rogue_mw = RogueDetectionMiddleware(
    risk_threshold=0.7,
    window_size=50,       # Analyze last 50 actions
    alert_callback=lambda alert: print(f"⚠️ Rogue alert: {alert}"),
)

# Compose middleware — order matters (outermost runs first)
agent = Agent(
    name="financial-analyst",
    instructions="You analyze financial data and produce reports.",
    middleware=[policy_mw, capability_mw, audit_mw, rogue_mw],
)
```

---

## Middleware Reference

### GovernancePolicyMiddleware

Enforces declarative policies loaded from YAML files or configured inline.

```python
GovernancePolicyMiddleware(
    policy_directory="policies/",     # Path to YAML policy files
    max_tokens_per_turn=4096,         # Token limit per agent turn
    rate_limit_per_minute=100,        # Max tool calls per minute
    blocked_patterns=[...],           # Strings/regex to block
    enable_content_safety=True,       # Enable semantic content safety
)
```

### CapabilityGuardMiddleware

Controls which tools the agent can invoke.

```python
CapabilityGuardMiddleware(
    allowed_tools=["tool_a", "tool_b"],   # Allowlist (if set, only these)
    denied_tools=["dangerous_tool"],       # Denylist (always blocked)
)
```

### AuditTrailMiddleware

Logs every agent action to a tamper-proof audit trail.

```python
AuditTrailMiddleware(
    log_directory="audit_logs/",
    include_tool_args=True,
    include_responses=True,
    log_format="json",                     # "json" or "structured"
)
```

### RogueDetectionMiddleware

Detects behavioral anomalies indicating an agent is operating outside its intended boundaries.

```python
RogueDetectionMiddleware(
    risk_threshold=0.7,          # 0.0-1.0, higher = more sensitive
    window_size=50,              # Number of recent actions to analyze
    alert_callback=my_handler,   # Called when anomaly detected
)
```

---

## Policy Configuration

Store policies as YAML files in your policy directory:

**`policies/financial-agent.yaml`:**

```yaml
version: "1.0"
agent: financial-analyst
policies:
  - name: rate-limit
    type: rate_limit
    max_calls: 60
    window: 1m

  - name: read-only-data
    type: capability
    allowed_actions:
      - "read_*"
      - "search_*"
      - "calculate_*"
    denied_actions:
      - "delete_*"
      - "write_*"
      - "execute_*"

  - name: content-safety
    type: pattern
    blocked_patterns:
      - "ignore previous instructions"
      - "DROP TABLE"
      - "UNION SELECT"
```

---

## Monitoring in Azure

### Export Governance Metrics to Azure Monitor

```python
from opentelemetry.sdk.metrics import MeterProvider
from azure.monitor.opentelemetry.exporter import AzureMonitorMetricExporter

# Configure Azure Monitor export
exporter = AzureMonitorMetricExporter(
    connection_string="InstrumentationKey=your-key-here"
)

# The governance middleware automatically emits metrics:
# - agent_governance.policy_decisions (counter)
# - agent_governance.tool_calls_blocked (counter)
# - agent_governance.trust_score (gauge)
# - agent_governance.governance_latency_ms (histogram)
```

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `policy_decisions` | Counter | Total policy decisions (allowed/denied) |
| `tool_calls_blocked` | Counter | Tool calls blocked by capability guard |
| `trust_score` | Gauge | Current agent trust score (0–1000) |
| `governance_latency_ms` | Histogram | Overhead per governance check (p99 < 0.1ms) |
| `rogue_alerts` | Counter | Behavioral anomaly detections |

---

## Combining with AKS Sidecar

For defense-in-depth, combine in-process Foundry middleware with an AKS sidecar:

```
┌─────────────────────────────────────────────┐
│  AKS Pod                                     │
│  ┌─────────────────────┐  ┌───────────────┐ │
│  │ Foundry Agent        │  │ Governance    │ │
│  │                      │  │ Sidecar       │ │
│  │ ┌──────────────────┐ │  │               │ │
│  │ │ MAF Middleware    │ │  │ Network-level │ │
│  │ │ (in-process)     │ │  │ policy        │ │
│  │ └──────────────────┘ │  │ enforcement   │ │
│  │                      │  │               │ │
│  │ Application-level ──────► Network-level │ │
│  │ governance           │  │ governance    │ │
│  └─────────────────────┘  └───────────────┘ │
└─────────────────────────────────────────────┘
```

The middleware handles application-level policy enforcement (tool capability, content safety), while the sidecar handles network-level governance (inter-agent trust, rate limiting at the infrastructure layer).

See the [AKS deployment guide](../../packages/agent-mesh/docs/deployment/azure.md) for sidecar setup.

---

## Next Steps

- [Governance policy schema reference](../../packages/agent-os/docs/policy-schema.md)
- [MAF adapter source code](../../packages/agent-os/src/agent_os/integrations/maf_adapter.py)
- [AgentMesh identity for multi-agent scenarios](../../packages/agent-mesh/README.md)
- [AKS deployment](../../packages/agent-mesh/docs/deployment/azure.md) for infrastructure-level governance
