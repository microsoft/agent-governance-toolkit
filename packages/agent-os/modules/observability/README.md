# Agent OS Observability

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

Production-ready observability stack for Agent OS kernel.

## Status: Alpha

This package provides metrics, tracing, and dashboards for monitoring Agent OS deployments.

## Features

- **Prometheus Metrics**: Kernel, agent, and CMVK metrics
- **OpenTelemetry Tracing**: Distributed tracing for agent operations
- **Grafana Dashboards**: Pre-built dashboards for SOC, ML Ops, and SRE teams
- **Prometheus Alerts**: Safety, performance, and availability alerts

## Quick Start

### Install Package

```bash
pip install agent-os-observability
```

### Basic Usage

```python
from agent_os_observability import KernelMetrics, KernelTracer

# Initialize metrics
metrics = KernelMetrics()

# Record policy check
with metrics.policy_check_latency():
    result = policy_engine.check(action)

# Record violation
if not result.allowed:
    metrics.record_violation(agent_id, action, policy="data-access", severity="high")
    metrics.record_blocked(agent_id, action)

# CMVK metrics
metrics.record_cmvk_verification(
    result="verified",
    confidence=0.95,
    drift_score=0.08,
    duration_seconds=2.3,
    model_count=3
)

# Expose /metrics endpoint (FastAPI example)
from fastapi import FastAPI, Response

app = FastAPI()

@app.get("/metrics")
def get_metrics():
    return Response(
        content=metrics.export(),
        media_type=metrics.content_type()
    )
```

### Full Observability Stack (Docker)

```bash
cd packages/observability
docker-compose up -d

# Open dashboards
open http://localhost:3000  # Grafana (admin/admin)
open http://localhost:16686 # Jaeger
open http://localhost:9090  # Prometheus
```

## Metrics Reference

### Kernel Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `agent_os_violations_total` | Counter | Policy violations by agent, action, policy, severity |
| `agent_os_violations_blocked_total` | Counter | Violations blocked (SIGKILL issued) |
| `agent_os_violation_rate` | Gauge | Violations per 1000 requests |
| `agent_os_policy_check_duration_seconds` | Histogram | Policy check latency |
| `agent_os_signals_total` | Counter | Signals sent by type and reason |
| `agent_os_sigkill_total` | Counter | SIGKILL signals by agent and reason |
| `agent_os_mttr_seconds` | Histogram | Mean Time To Recovery |
| `agent_os_kernel_uptime_seconds` | Gauge | Kernel uptime |

### CMVK Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `agent_os_cmvk_verifications_total` | Counter | Verifications by result (verified/flagged/rejected) |
| `agent_os_cmvk_consensus_ratio` | Gauge | Current model agreement (0.0-1.0) |
| `agent_os_cmvk_model_disagreements_total` | Counter | Disagreements by model pair |
| `agent_os_cmvk_drift_score` | Histogram | Drift score distribution |
| `agent_os_cmvk_verification_duration_seconds` | Histogram | Verification latency |
| `agent_os_cmvk_model_latency_seconds` | Histogram | Per-model response latency |

### Agent Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `agent_os_agent_llm_calls_total` | Counter | LLM API calls by agent and model |
| `agent_os_agent_errors_total` | Counter | Errors by agent and type |
| `agent_os_agent_execution_duration_seconds` | Histogram | Task execution time |

## Dashboards

### agent-os-overview (10 panels)
Main dashboard for SOC teams: violation rate, SIGKILL count, latency, throughput.

### agent-os-cmvk (12 panels)
ML Ops dashboard: consensus rate, drift scores, model latency, verification results.

### agent-os-amb (13 panels)
AMB (Agent Message Bus): throughput, queue depth, backpressure, delivery latency.

### agent-os-safety (1 panel)
CISO dashboard: 30-day violation count.

### Export Dashboards

```bash
python scripts/export_dashboards.py
```

This creates JSON files in `grafana/dashboards/` for Grafana provisioning.

## Alerts

Alert rules are defined in `alerts/agent-os-alerts.yaml`:

### Critical Alerts (Page Immediately)
- `AgentOSHighViolationRate`: Violation rate >1%
- `AgentOSSIGKILLSpike`: >5 SIGKILL in 5 minutes
- `AgentOSKernelCrash`: Kernel panic

### Warning Alerts
- `AgentOSHighPolicyLatency`: p99 latency >10ms
- `CMVKLowConsensus`: Consensus <80%
- `CMVKHighDrift`: p95 drift >0.25

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Application                          │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │   Agent OS       │  │   KernelMetrics  │                 │
│  │   Kernel         │──│   .export()      │───► /metrics    │
│  └──────────────────┘  └──────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 Docker Compose Stack                         │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │ Prometheus │─►│  Grafana   │  │   Jaeger   │            │
│  │   :9090    │  │   :3000    │  │  :16686    │            │
│  └────────────┘  └────────────┘  └────────────┘            │
│         │               ▲               ▲                   │
│         ▼               │               │                   │
│  ┌────────────┐        │        ┌────────────┐             │
│  │AlertManager│        │        │   OTEL     │             │
│  │   :9093    │        │        │ Collector  │             │
│  └────────────┘        │        └────────────┘             │
│         │              │               ▲                    │
│         ▼              │               │                    │
│  [Slack/PagerDuty]     └───────────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

## Development

```bash
# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Export dashboards
python scripts/export_dashboards.py
```

## License

MIT
