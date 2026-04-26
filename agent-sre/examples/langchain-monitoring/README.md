# LangChain Agent Monitoring with Agent SRE

This example demonstrates how to monitor a LangChain agent using Agent SRE's
callback handler, SLI collection, and SLO compliance checking.

## What it shows

1. **AgentSRECallback** — a LangChain callback handler that automatically
   records SLIs (latency, success rate, cost, tool accuracy) from chain
   execution events.
2. **SLI collection** — built-in indicators (`TaskSuccessRate`,
   `ResponseLatency`, `CostPerTask`, `ToolCallAccuracy`, `HallucinationRate`)
   that aggregate metrics in real time.
3. **SLO evaluation** — an `SLO` object with an error budget that transitions
   through HEALTHY → WARNING → CRITICAL → EXHAUSTED as reliability degrades.
4. **LLM-as-Judge evaluation** — a rules-based `RulesJudge` scores every
   successful response for correctness, hallucination, relevance, and safety.
5. **Dashboard health** — an `SLODashboard` that snapshots and summarises
   overall agent health.

## Prerequisites

```bash
pip install agent-sre
```

No API keys or external services are required — the demo uses mocked LangChain
components and a rules-based judge.

## Running

```bash
cd examples/langchain-monitoring
python demo.py
```

## Expected output

```
Agent-SRE + LangChain Monitoring Demo
============================================================

  [1/50] ✓ "What are the key features of Python 3.12?"  1842ms  $0.04
  [2/50] ✓ "How does vector search work in RAG systems?" 623ms  $0.09
  ...
  [50/50] ✗ "Explain Kubernetes pod autoscaling"  FAILED

SLO Compliance Report
────────────────────────────────────────────────────────────
  SLO Status:         HEALTHY
  Error Budget:       72.0% remaining
  ...
```

Exact numbers vary because the simulation uses randomised latency and failure
rates.

## How to use with a real LangChain agent

```python
from langchain.chat_models import ChatOpenAI
from langchain.agents import AgentExecutor
from agent_sre.integrations.langchain.callback import AgentSRECallback

sre_callback = AgentSRECallback(
    cost_per_1k_input=0.003,
    cost_per_1k_output=0.015,
)

# Pass as a callback to any LangChain chain or agent
agent_executor = AgentExecutor(agent=..., tools=..., callbacks=[sre_callback])
result = agent_executor.invoke({"input": "..."})

# Inspect collected SLIs
print(sre_callback.get_sli_snapshot())
```
