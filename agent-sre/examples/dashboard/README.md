# Agent SRE Dashboard

Interactive Streamlit dashboard for monitoring AI agent reliability, cost, chaos experiments, incidents, and progressive delivery.

## Quick Start

```bash
# Install dependencies
pip install -r examples/dashboard/requirements.txt

# Run the dashboard
streamlit run examples/dashboard/app.py
```

The dashboard opens at `http://localhost:8501` and works standalone with simulated data. If `agent-sre` is installed, it uses the real SDK types for richer display.

## Tabs

| Tab | What it shows |
|-----|--------------|
| **SLO Health** | Error budgets, burn rates, compliance timelines, indicator breakdown |
| **Cost Management** | Per-agent budgets, cost trends, alerts, top spenders |
| **Chaos Engineering** | Experiments, resilience radar, fault injection timeline |
| **Incidents** | Active incidents by severity, MTTR, signal correlation |
| **Progressive Delivery** | Staged rollout progress, preview test match rates |

## Configuration

Use the sidebar to select a time range and filter by agent. The "Run Chaos Test" button in the Chaos tab triggers a simulated fault injection with live metric updates.
