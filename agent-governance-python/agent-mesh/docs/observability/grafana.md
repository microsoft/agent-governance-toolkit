# Grafana & Prometheus Setup Guide

This guide covers how to expose AgentMesh metrics via Prometheus and visualise
them in Grafana.

## Prerequisites

* Python ≥ 3.11
* `prometheus-client` installed (`pip install agentmesh-platform[observability]`)
* A running **Prometheus** server
* A running **Grafana** instance (≥ 9.x recommended)

## 1. Enable the Prometheus exporter

```python
from agentmesh.observability.prometheus_exporter import (
    MeshMetricsExporter,
    start_http_server,
)

exporter = MeshMetricsExporter()

# Start the /metrics HTTP endpoint on port 9090
start_http_server(port=9090)
```

The exporter exposes the following metrics:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `agentmesh_trust_handshakes_total` | Counter | `result` | Total trust handshakes |
| `agentmesh_trust_score` | Gauge | `agent_did` | Per-agent trust score |
| `agentmesh_policy_violations_total` | Counter | `policy_id` | Policy violations |
| `agentmesh_active_agents` | Gauge | — | Active agent count |
| `agentmesh_handshake_latency_seconds` | Histogram | — | Handshake latency |
| `agentmesh_delegation_depth` | Histogram | — | Scope chain depth |
| `agentmesh_audit_entries_total` | Counter | `event_type` | Audit log entries |

## 2. Configure Prometheus

Add a scrape target to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: agentmesh
    scrape_interval: 15s
    static_configs:
      - targets: ["localhost:9090"]
```

Restart or reload Prometheus to pick up the change.

## 3. Import the Grafana dashboard

1. Open Grafana → **Dashboards** → **Import**.
2. Upload `dashboards/grafana/mesh-overview.json`.
3. Select your Prometheus data source when prompted.

The dashboard includes:

* **Active Agents** — stat panel
* **Trust Handshakes / min** — time series
* **Policy Violations / min** — time series
* **Trust Score Distribution** — histogram
* **Top 10 Most Trusted Agents** — table
* **Handshake Latency p50 / p95 / p99** — time series
* **Scope Chain Depth** — histogram

## 4. Import alerting rules

1. Open Grafana → **Alerting** → **Alert rules** → **Import**.
2. Upload `dashboards/grafana/alerts.yaml`.

Configured alerts:

| Alert | Condition | For |
|-------|-----------|-----|
| High policy violation rate | > 10 violations/min | 2 min |
| Trust score below threshold | score < 0.3 | 5 min |
| Handshake latency spike | p99 > 5 s | 3 min |

## 5. Graceful degradation

If `prometheus-client` is not installed the exporter disables itself
automatically — all recording methods become no-ops and the application
continues to function normally.

```python
exporter = MeshMetricsExporter()
print(exporter.enabled)  # False when prometheus-client is missing
```
