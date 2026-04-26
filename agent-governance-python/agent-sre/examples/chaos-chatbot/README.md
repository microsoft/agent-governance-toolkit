# Chaos Engineering for AI Chatbot Agents

> Inject failures into a chatbot agent and watch SLOs, error budgets, and
> circuit breakers respond — no API keys required.

## What is chaos engineering for AI agents?

Traditional chaos engineering breaks *infrastructure* on purpose — kill a
server, inject network latency, corrupt a disk.  **Agent chaos engineering**
does the same thing to the AI layer:

| Infrastructure chaos          | Agent chaos                       |
|-------------------------------|-----------------------------------|
| Kill a VM                     | Simulate full LLM outage          |
| Add network latency           | Spike LLM response time to 8 s   |
| Corrupt a disk                | Overflow the context window       |
| Rate-limit an API             | Exhaust token-per-minute quota    |
| Return HTTP 500               | Return hallucinated answers       |

The goal is identical: **discover weaknesses before your users do**.

## Why test agent resilience?

LLM-based agents have failure modes that don't exist in traditional software:

1. **Latency variance** — LLM response times can jump from 200 ms to 10 s
   without warning.
2. **Partial outages** — A provider may succeed for some prompts but fail for
   others (rate limits, content filters, model overload).
3. **Token exhaustion** — Hitting per-minute or per-day token caps silently
   degrades throughput.
4. **Context window overflow** — Conversations that exceed the context window
   produce truncated or nonsensical replies.
5. **Quality drift** — The model may start hallucinating more frequently after
   a provider-side update.

Without proactive testing you only learn about these when users complain.

## How the demo works

```
python demo.py
```

The demo runs four phases — all in-process, all simulated, zero API keys:

### Phase 1 — Baseline (normal traffic)

50 simulated chatbot requests with realistic latency and accuracy.  The SLO
starts **HEALTHY** and the error budget is full.

### Phase 2 — Chaos injection

Four fault scenarios run back-to-back:

| Scenario               | What it does                              |
|------------------------|-------------------------------------------|
| LLM API latency spike  | 70 % of calls take 3-8 s instead of ~0.5 s |
| Partial outage         | 50 % of calls return errors               |
| Token exhaustion       | 80 % of calls hit rate-limit errors       |
| Context window overflow| Oversize prompts cause failures           |

Each scenario records events against the SLO and shows the resulting status
and error budget consumption in real time.

### Phase 3 — Circuit breaker

When the error budget is exhausted the demo activates a circuit breaker that
blocks further calls, preventing cascading damage.

### Phase 4 — Recovery

Normal traffic resumes.  The SLO gradually recovers and the demo prints
a final resilience summary.

## How to inject failures

agent-sre provides a `Fault` class with factory methods for common failure
types:

```python
from agent_sre.chaos.engine import Fault

# Slow responses
Fault.latency_injection("llm_provider", delay_ms=8000, rate=0.7)

# Errors on half of calls
Fault.error_injection("llm_provider", error="service_unavailable", rate=0.5)

# Complete outage
Fault.error_injection("llm_provider", error="service_unavailable", rate=1.0)
```

You can also define scenarios declaratively in
[`chaos-scenarios.yaml`](chaos-scenarios.yaml) and load them with
`agent_sre.chaos.loader`.

## How to measure impact on SLOs

An SLO combines **Service Level Indicators** (SLIs) with an **Error Budget**:

```python
from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import TaskSuccessRate, ResponseLatency, CostPerTask

slo = SLO(
    name="chatbot",
    indicators=[
        TaskSuccessRate(target=0.95),
        ResponseLatency(target_ms=2000),
        CostPerTask(target_usd=0.10),
    ],
    error_budget=ErrorBudget(total=0.05),
)
```

During chaos, record every request outcome:

```python
slo.record_event(good=succeeded)
```

Then inspect:

```python
slo.evaluate()                       # → SLOStatus.WARNING / CRITICAL / EXHAUSTED
slo.error_budget.remaining_percent   # → 42.0  (% of budget left)
slo.error_budget.burn_rate()         # → 6.2x  (how fast budget is burning)
slo.error_budget.firing_alerts()     # → [BurnRateAlert("burn_rate_critical", ...)]
```

## Pre-built chaos scenarios

See [`chaos-scenarios.yaml`](chaos-scenarios.yaml) for five ready-to-use
experiments:

| ID                   | Severity | Description                        |
|----------------------|----------|------------------------------------|
| `api_latency_spike`  | medium   | 70 % of calls delayed 8 s         |
| `partial_outage`     | high     | 50 % of calls return 503          |
| `full_outage`        | critical | 100 % of calls fail               |
| `token_exhaustion`   | high     | 80 % rate-limit errors            |
| `hallucination_spike`| medium   | 30 % hallucinated responses       |

## Further reading

- [agent-sre quickstart](../quickstart.py)
- [Chaos engine source](../../src/agent_sre/chaos/engine.py)
- [SLO indicators](../../src/agent_sre/slo/indicators.py)
