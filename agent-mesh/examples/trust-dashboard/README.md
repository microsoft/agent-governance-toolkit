# Trust Score Visualization Dashboard

A self-contained HTML dashboard for visualizing AgentMesh trust scores,
history, and tier distribution. Uses only the Python standard library and
Chart.js (loaded from CDN) — no external Python packages required.

## Quick Start

```bash
cd examples/trust-dashboard
python demo.py
```

Then open <http://localhost:8050> in your browser.

The demo creates sample agents with varying trust scores, starts the
dashboard server, and simulates trust score changes every few seconds so
you can watch the charts update in real time.

## Running the Dashboard Standalone

```bash
python dashboard.py            # default port 8050
python dashboard.py --port 9090  # custom port
```

## Features

| Feature | Description |
|---|---|
| **Agent Scores** | Horizontal bar chart of current trust scores for every registered agent |
| **Score History** | Line chart showing how each agent's score evolved over time |
| **Tier Distribution** | Doughnut chart of trust-tier counts (Verified Partner → Untrusted) |
| **Auto-Refresh** | Page polls `/api/data` every 5 seconds and re-renders charts |

## Trust Tiers

| Tier | Score Range |
|---|---|
| Verified Partner | 900 – 1000 |
| Trusted | 700 – 899 |
| Standard | 500 – 699 |
| Probationary | 300 – 499 |
| Untrusted | 0 – 299 |

## Architecture

```
demo.py          — creates agents, starts dashboard, simulates changes
dashboard.py     — http.server serving HTML + JSON API (/api/data)
```

Both files are pure Python 3.9+ stdlib. The HTML page loads
[Chart.js](https://www.chartjs.org/) from a CDN for rendering.
