# Agent-SRE Examples

Examples demonstrating SLO monitoring, cost guardrails, incident detection, and reliability engineering for AI agents.

## Quickstart

The fastest way to see Agent-SRE in action:

```bash
pip install -e "agent-sre[dev]"
python agent-governance-python/agent-sre/examples/quickstart.py
```

This simulates 100 agent tasks with a 93% success rate (below the 95% target) and 8% hallucination rate (above the 5% target), then shows SLO status, error budget consumption, cost tracking, and burn rate alerts.

## Examples

| Example | Description |
|---------|-------------|
| `quickstart.py` | SLOs, cost budgets, and incidents in 30 lines |
| `slo_alerting.py` | Multi-window burn rate alerting (1h, 6h, 24h, 72h) |
| `cost_guard.py` | Per-task, per-agent, and org-wide cost limits |
| `cost_guardrails.py` | Cost guardrails with automatic throttling |
| `canary_rollout.py` | Canary deployment for model upgrades with automatic rollback |
| `chaos_test.py` | Chaos testing — inject failures and measure agent resilience |
| `langchain_monitor.py` | LangChain callback integration for SLO tracking |
| `dashboard/` | Streamlit SRE dashboard for real-time monitoring |
| `chaos/` | Extended chaos engineering scenarios |
| `chaos-chatbot/` | Chaos testing for conversational agents |
| `canary-model-upgrade/` | Full canary pipeline for swapping underlying models |
| `langchain-monitoring/` | LangChain integration with custom metrics |
| `docker-compose/` | Docker setup for running the monitoring stack |

## Key Concepts

- **SLO (Service Level Objective):** Define reliability targets for your agent — success rate, cost per task, hallucination rate. Agent-SRE measures compliance continuously.
- **Error Budget:** A fixed allowance for failures. When exhausted, deployments should freeze. Burn rate alerts fire when the budget is being consumed too fast.
- **Cost Guard:** Per-task, per-agent, and organization-wide spending limits. Tasks that would exceed the budget are blocked before execution.
- **Incident Detection:** Correlates signals (budget exhaustion, SLO breaches, anomalies) into incidents with severity classification.

## Prerequisites

- Python 3.10+
- `pip install -e "agent-sre[dev]"`
- For the dashboard: `pip install streamlit plotly`
- For LangChain examples: `pip install langchain`
