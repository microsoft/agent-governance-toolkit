# Tutorial: Set up SLOs for a LangChain Agent

Monitor a LangChain agent with **Service Level Objectives**, **error budgets**, and **alerts** using [Agent SRE](https://github.com/microsoft/agent-governance-toolkit).

> **Time:** ~15 minutes  
> **Prerequisites:** Python 3.10+  
> **API keys required:** None (demo uses mocked LangChain components)

---

## Quick Start

```bash
pip install agent-sre langchain
cd tutorials/langchain-slo-setup
python demo.py
```

---

## Step 1: Create a LangChain Agent

In production, you create a LangChain agent as usual. Agent SRE integrates via a **callback handler** — no changes to your agent code.

```python
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI
from langchain.tools import Tool

llm = ChatOpenAI(model="gpt-4o-mini")

tools = [
    Tool(name="vector_search", func=search_docs, description="Search documents"),
]

agent = create_openai_tools_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)
```

For this tutorial, `demo.py` includes a `MockLangChainAgent` that simulates the callback lifecycle so everything runs without API keys.

---

## Step 2: Define SLOs (Latency, Accuracy, Cost)

Define what "reliable" means for your agent. Agent SRE provides built-in SLI types for AI workloads:

```python
from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import (
    TaskSuccessRate,
    ResponseLatency,
    ToolCallAccuracy,
    CostPerTask,
    HallucinationRate,
)
from agent_sre.slo.objectives import ExhaustionAction

# SLI indicators — each with a target and measurement window
success_rate   = TaskSuccessRate(target=0.95, window="24h")
latency        = ResponseLatency(target_ms=5000.0, percentile=0.95, window="1h")
tool_accuracy  = ToolCallAccuracy(target=0.98, window="24h")
cost           = CostPerTask(target_usd=0.50, window="24h")
hallucination  = HallucinationRate(target=0.05, window="24h")

# Combine into an SLO with an error budget
slo = SLO(
    name="langchain-rag-agent",
    description="Production RAG agent reliability targets",
    indicators=[success_rate, latency, tool_accuracy, cost, hallucination],
    error_budget=ErrorBudget(
        total=0.05,                                    # 5% error budget
        burn_rate_alert=2.0,                           # Warn at 2× burn
        burn_rate_critical=10.0,                       # Critical at 10× burn
        exhaustion_action=ExhaustionAction.FREEZE_DEPLOYMENTS,
    ),
)
```

You can also define SLOs in YAML — see [`slo-config.yaml`](slo-config.yaml).

---

## Step 3: Attach Agent SRE Monitoring

Wire up the `AgentSRECallback` and record metrics as the agent runs:

```python
from agent_sre.integrations.langchain.callback import AgentSRECallback
from agent_sre.slo.dashboard import SLODashboard

# LangChain callback handler
sre_callback = AgentSRECallback()

# In production, pass it to your agent:
#   executor = AgentExecutor(agent=agent, tools=tools, callbacks=[sre_callback])

# Dashboard for aggregate reporting
dashboard = SLODashboard()
dashboard.register_slo(slo)
```

After each agent call, record the results into SLIs:

```python
result = executor.invoke({"input": query})

success_rate.record_task(success=result["success"])
latency.record_latency(result["latency_ms"])
cost.record_cost(cost_usd=result["cost_usd"])
hallucination.record_evaluation(hallucinated=result["hallucinated"])
tool_accuracy.record_call(correct=result["tool_correct"])

# Count against the error budget
slo.record_event(good=result["success"] and not result["hallucinated"])
```

---

## Step 4: Run Traffic and See SLO Dashboards

Run the demo to process 100 simulated calls:

```bash
python demo.py
```

After the run completes, you'll see output like:

```
  SLO Compliance Report

  SLO:    langchain-rag-agent
  Status: WARNING

  Indicator Results:
    ❌ task_success_rate        value=0.930  target=0.95  compliance=93.0%
    ✅ response_latency         value=2015   target=5000  compliance=99.0%
    ✅ tool_call_accuracy        value=0.968  target=0.98  compliance=96.8%
    ✅ cost_per_task             value=0.065  target=0.50  compliance=100.0%
    ❌ hallucination_rate        value=0.070  target=0.05  compliance=93.0%
```

Use the dashboard for aggregate health:

```python
dashboard.take_snapshot()
health = dashboard.health_summary()
print(health)
# {'total_slos': 1, 'slos': {'langchain-rag-agent': 'WARNING'}}
```

---

## Step 5: Set Up Alerts for SLO Breaches

Agent SRE tracks **burn rate** — how fast the error budget is being consumed. Configure alert thresholds when creating the `ErrorBudget`:

```python
budget = ErrorBudget(
    total=0.05,
    burn_rate_alert=2.0,       # Warning: budget burning 2× faster than expected
    burn_rate_critical=10.0,   # Critical: budget burning 10× faster
    exhaustion_action=ExhaustionAction.FREEZE_DEPLOYMENTS,
)
```

Check for firing alerts at any time:

```python
for alert in slo.error_budget.firing_alerts():
    print(f"🔔 {alert.severity}: {alert.name} — burn rate {alert.rate:.1f}×")
```

Integrate with your incident workflow:

```python
from agent_sre.incidents.detector import IncidentDetector, Signal, SignalType

detector = IncidentDetector(correlation_window_seconds=60)

if slo.error_budget.is_exhausted:
    signal = Signal(
        signal_type=SignalType.ERROR_BUDGET_EXHAUSTED,
        source="langchain-rag-agent",
        message="Error budget consumed — freeze deployments",
    )
    incident = detector.ingest_signal(signal)
    if incident:
        print(f"🚨 Incident: {incident.title} (severity: {incident.severity.value})")
```

---

## Step 6: Review Error Budget

The error budget tells you how much room you have for unreliability before violating your SLO:

```python
status = slo.evaluate()
print(f"Status:          {status.value}")         # HEALTHY / WARNING / CRITICAL / EXHAUSTED
print(f"Budget Left:     {slo.error_budget.remaining_percent:.1f}%")
print(f"Exhausted:       {slo.error_budget.is_exhausted}")
print(f"Burn Rate (1h):  {slo.error_budget.burn_rate(3600):.1f}×")
```

Use the error budget to make decisions:

| Status | Action |
|--------|--------|
| `HEALTHY` | Ship features, run experiments |
| `WARNING` | Slow down deployments, investigate |
| `CRITICAL` | Stop non-critical changes, focus on reliability |
| `EXHAUSTED` | Freeze deployments, trigger incident response |

---

## Project Structure

```
tutorials/langchain-slo-setup/
├── README.md          ← This guide
├── demo.py            ← Runnable demo (no API keys needed)
└── slo-config.yaml    ← Example SLO config in YAML format
```

---

## Next Steps

- **Add cost guardrails** — see [`examples/cost_guard.py`](../../examples/cost_guard.py)
- **Run chaos tests** — see [`examples/chaos_test.py`](../../examples/chaos_test.py)
- **Export to Datadog/Prometheus** — see the [integration guide](../../docs/integration-guide.md)
- **Full SLI reference** — see [`docs/slo-reference.md`](../../docs/slo-reference.md)
