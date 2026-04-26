# Canary Rollout for AI Model Upgrades

> Safely upgrade from GPT-3.5 to GPT-4 using progressive delivery with
> SLO-gated promotion and automatic rollback — no API keys required.

## Why canary deployments for model upgrades?

Swapping an AI model in production is risky.  A newer model may be smarter,
but it can also be **slower**, **more expensive**, or **less reliable** than
the model it replaces.  A canary rollout lets you prove the new model meets
your Service Level Objectives (SLOs) before exposing all users to it.

| Risk                     | How canary rollout mitigates it                |
|--------------------------|------------------------------------------------|
| Latency regression       | SLO gate checks p95 latency at each stage      |
| Cost explosion           | Cost-per-call threshold blocks promotion        |
| Quality degradation      | Hallucination rate checked before each ramp     |
| Availability drop        | Error-rate threshold triggers automatic rollback|

## How the demo works

```
cd examples/canary-model-upgrade
python demo.py
```

The demo runs **two scenarios** end-to-end — no API keys, no external
services, everything is simulated in-process:

### Scenario A — Successful upgrade

The "good" GPT-4 variant has lower hallucination and error rates than
GPT-3.5 while staying within latency and cost SLOs.

```
Phase 1  →  Baseline: 100% traffic to GPT-3.5
Phase 2  →  Canary:     5% traffic to GPT-4       ✅ SLOs met
Phase 3  →  Ramp:      25% traffic to GPT-4       ✅ SLOs met
             Ramp:      50% traffic to GPT-4       ✅ SLOs met
             Full:     100% traffic to GPT-4       ✅ Promoted
```

### Scenario B — Failed upgrade (automatic rollback)

The "bad" GPT-4 variant has a latency regression (p95 > 5 s) and elevated
cost.  The canary rollout detects the SLO breach and rolls back
automatically.

```
Phase 1  →  Baseline: 100% traffic to GPT-3.5
Phase 2  →  Canary:     5% traffic to GPT-4       🛑 SLO breach
Phase 3  →  Rollback:  100% traffic to GPT-3.5    ✅ Zero user impact
```

## Progressive delivery stages

The rollout is configured with four stages.  At each stage the system
collects metrics from the canary traffic and evaluates rollback conditions
before advancing:

| Stage | Traffic to GPT-4 | What happens                          |
|-------|-------------------|---------------------------------------|
| 1     | 5 %               | Small canary, collect initial metrics |
| 2     | 25 %              | Ramp up if SLOs hold                  |
| 3     | 50 %              | Larger exposure, validate at scale    |
| 4     | 100 %             | Full promotion                        |

### Rollback conditions

If **any** of these thresholds are breached at any stage, the rollout is
automatically rolled back:

| Metric               | Threshold   | Comparator |
|----------------------|-------------|------------|
| `error_rate`         | ≥ 10 %      | `gte`      |
| `hallucination_rate` | ≥ 8 %       | `gte`      |
| `p95_latency_ms`     | ≥ 5 000 ms  | `gte`      |
| `avg_cost_usd`       | ≥ $0.10     | `gte`      |

## Key agent-sre APIs used

### CanaryRollout

```python
from agent_sre.delivery.rollout import CanaryRollout, RollbackCondition, RolloutStep

rollout = CanaryRollout(
    name="model-upgrade",
    steps=[
        RolloutStep(weight=0.05, duration_seconds=30, name="5% canary"),
        RolloutStep(weight=0.25, duration_seconds=30, name="25% ramp"),
        RolloutStep(weight=0.50, duration_seconds=30, name="50% ramp"),
        RolloutStep(weight=1.00, duration_seconds=0,  name="100% full rollout"),
    ],
    rollback_conditions=[
        RollbackCondition(metric="error_rate",        threshold=0.10,   comparator="gte"),
        RollbackCondition(metric="hallucination_rate", threshold=0.08,   comparator="gte"),
        RollbackCondition(metric="p95_latency_ms",    threshold=5000.0, comparator="gte"),
        RollbackCondition(metric="avg_cost_usd",      threshold=0.10,   comparator="gte"),
    ],
)
```

### SLO monitoring

```python
from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import (
    TaskSuccessRate, ResponseLatency, CostPerTask, HallucinationRate,
)

slo = SLO(
    name="canary",
    indicators=[
        TaskSuccessRate(target=0.95, window="1h"),
        ResponseLatency(target_ms=2000.0, percentile=0.95, window="1h"),
        CostPerTask(target_usd=0.10, window="1h"),
        HallucinationRate(target=0.05, window="1h"),
    ],
    error_budget=ErrorBudget(total=0.05),
)

# Record events
slo.record_event(good=True)

# Evaluate
slo.evaluate()                       # → SLOStatus.HEALTHY
slo.error_budget.remaining_percent   # → 98.2
```

### Rollback loop

```python
rollout.start()
while rollout.current_step is not None:
    metrics = collect_metrics_from_canary()
    if rollout.check_rollback(metrics):
        rollout.rollback(reason="SLO breach")
        break
    rollout.advance()
```

## Adapting for production

To use this pattern with real models:

1. **Replace `SimulatedModel`** with your actual LLM client (OpenAI,
   Anthropic, etc.) and route traffic using a load balancer or feature flag.
2. **Connect SLIs to real telemetry** — record latency, cost, and quality
   scores from your observability pipeline (Prometheus, Datadog, etc.).
3. **Add manual gates** — set `manual_gate=True` on critical `RolloutStep`s
   to require human approval before promoting past a threshold.
4. **Integrate with CI/CD** — trigger the rollout from your deployment
   pipeline and gate merges on the rollout outcome.

## Further reading

- [Canary rollout example](../canary_rollout.py) — agent version rollout
- [Chaos chatbot demo](../chaos-chatbot/) — fault injection and circuit breakers
- [Rollout engine source](../../src/agent_sre/delivery/rollout.py)
- [SLO indicators](../../src/agent_sre/slo/indicators.py)
