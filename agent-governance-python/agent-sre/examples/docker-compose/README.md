# Docker Compose Observability Demo

Full monitoring stack for Agent SRE with Prometheus and Grafana.

## Architecture

```
┌──────────────┐     events     ┌──────────────┐
│ sample-agent │───────────────▶│  agent-sre   │
└──────────────┘                │  :8080       │
                                │  /metrics    │
                                └──────┬───────┘
                                       │ scrape
                                ┌──────▼───────┐
                                │  prometheus  │
                                │  :9090       │
                                └──────┬───────┘
                                       │ query
                                ┌──────▼───────┐
                                │   grafana    │
                                │  :3000       │
                                └──────────────┘
```

## Quick Start

```bash
docker compose up -d
```

## Access

| Service    | URL                      | Credentials   |
|------------|--------------------------|---------------|
| Agent SRE  | http://localhost:8080     | —             |
| Prometheus | http://localhost:9090     | —             |
| Grafana    | http://localhost:3000     | admin / admin |

## What's Running

- **agent-sre** — FastAPI server exposing `/metrics` (Prometheus format), SLO, cost, chaos, and incident APIs
- **sample-agent** — Generates SLO events and cost records every 5 seconds to simulate a monitored agent
- **prometheus** — Scrapes `/metrics` from agent-sre every 15 seconds
- **grafana** — Pre-loaded dashboard with SLO compliance, error budget burn rate, cost tracking, incident timeline, and circuit breaker status

## Dashboard Panels

1. **SLO Compliance** — Gauge showing percentage of healthy SLOs
2. **Error Budget Burn Rate** — Time series of budget consumption
3. **Active Incidents** — Count of open incidents
4. **Agent Latency** — Request rate and trend patterns
5. **Cost Tracking** — Organization spend over time
6. **Incident Timeline** — Bar chart of open incidents
7. **Circuit Breaker Status** — State timeline derived from SLO health

## Endpoints

```bash
# Health check
curl http://localhost:8080/health

# Prometheus metrics
curl http://localhost:8080/metrics

# SRE stats
curl http://localhost:8080/api/v1/stats

# List SLOs
curl http://localhost:8080/api/v1/slos
```

## Cleanup

```bash
docker compose down -v
```
