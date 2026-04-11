# AGT Governance Dashboard

Reference **Streamlit** dashboard for the Agent Governance Toolkit (AGT).
Provides a single-pane-of-glass view into your autonomous-agent fleet:
fleet overview, shadow agent detection, lifecycle monitoring, policy
evaluation feed, and agent-to-agent trust heatmap.

## Quick Start

```bash
pip install -r requirements.txt
streamlit run app.py
```

Open <http://localhost:8501> in your browser.

## Pages

| Page | What it shows |
|---|---|
| **Fleet Overview** | KPI cards, agents by type / state / risk / owner, full agent table |
| **Shadow Agents** | Agents without identity, risk breakdown, recommended actions |
| **Lifecycle Monitor** | Provisioning funnel, credential status, orphan candidates, event timeline |
| **Policy Feed** | Allow / deny / escalate metrics, action breakdown, top denied actions |
| **Trust Heatmap** | Agent-to-agent trust score matrix and trust-tier distribution |

## Docker

```bash
docker compose up --build
```

The dashboard is available at <http://localhost:8501>.

## Project Structure

```
governance-dashboard/
├── app.py              # Streamlit application
├── demo_data.py        # Synthetic data generators
├── requirements.txt    # Python dependencies
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## License

See the repository root for license details.
