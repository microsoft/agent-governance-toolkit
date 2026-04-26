# Trust Score Dashboard

A Streamlit dashboard for monitoring agent trust networks, credential lifecycles, protocol traffic, and compliance posture across an AgentMesh deployment.

> **Production starting point.** This dashboard uses simulated data out of
> the box but is designed to plug into the live
> [`agentmesh.dashboard.DashboardAPI`](../../src/agentmesh/dashboard/api.py)
> backend. Replace the data generators with `DashboardAPI` calls for
> real-time monitoring. For a fleet-level overview (shadow agents, lifecycle,
> policy feed), see [`demo/governance-dashboard/`](../../../../demo/governance-dashboard/).

## What It Does

This example launches an interactive dashboard with five tabs:

1. **Trust Network** — Force-directed graph of agent relationships, colored and sized by trust score. Hover for DID, protocol, and score details.
2. **Trust Scores** — Leaderboard, per-agent radar breakdown across five dimensions (Competence, Integrity, Availability, Security, Compliance), historical score timeline, and trust decay simulation showing projected score erosion without activity.
3. **Credential Lifecycle** — Status table of all agent credentials (x509-mTLS, VC-JWT, DID-Auth, OAuth2, API-Key), TTL countdown gauges, expiry distribution, and rotation timeline.
4. **Protocol Traffic** — Message throughput by protocol (A2A, MCP, IATP), distribution breakdown, trust verification pass/fail rates, and top communication pairs by trust weight.
5. **Compliance** — Framework status (EU AI Act, SOC 2, HIPAA, GDPR), per-agent compliance checklist, audit log with severity levels, audit chain verification, and compliance score heatmap.

The dashboard uses simulated data to demonstrate the visualization patterns. Replace the data generators with live AgentMesh queries for production use.

## Prerequisites

- Python 3.10+
- Dependencies listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

Key packages: `streamlit`, `plotly`, `pandas`, `numpy`, `networkx`.

## How to Run

```bash
cd agent-governance-python/agent-mesh/examples/06-trust-score-dashboard
streamlit run trust_dashboard.py
```

The dashboard opens at `http://localhost:8501`. Use the sidebar to filter by agent, time range, and protocol.

## Expected Output

A dark-themed multi-tab dashboard showing:
- 10 simulated agents with W3C DIDs (`did:web:*.mesh.io`)
- Trust scores from 0-1000 on a red-yellow-green gradient
- 15 trust relationships with weighted edges
- Credential status (active/expired/expiring-soon)
- Protocol traffic across A2A, MCP, and IATP
- Compliance scores across four regulatory frameworks
