# OpenLit — Agent SRE OTel Instrumentation

**Issue:** [openlit/openlit#1003](https://github.com/openlit/openlit/issues/1003)
**PR:** [openlit/openlit#1037](https://github.com/openlit/openlit/pull/1037)
**Status:** PR open — awaiting review (invited by @amanagarwal042)
**Type:** New instrumentation (auto-instrumentation via `openlit.init()`)
**Date Submitted:** March 2, 2026

---

## Summary

Auto-instrumentation for [Agent SRE](https://github.com/microsoft/agent-governance-toolkit), an AI-native SRE framework (1,071+ tests), that captures SLI/SLO tracking, chaos testing, and error budget operations as OpenTelemetry spans and metrics in OpenLit.

## Integration Rationale

OpenLit is OpenTelemetry-native with 50+ LLM provider integrations. Agent SRE complements this by adding the **SRE discipline layer** — SLO health, chaos resilience, and error budget tracking alongside LLM traces.

## What's Instrumented

| Operation | Span Name | Key Attributes |
|-----------|-----------|----------------|
| `SLO.evaluate()` | `slo.evaluate {name}` | status, error_budget_remaining, burn_rate, is_exhausted |
| `ErrorBudget.record_event()` | `error_budget.record {good\|bad}` | total, consumed, remaining_percent |
| `ChaosExperiment.start()` | `chaos.start {name}` | target_agent, fault_count, blast_radius |
| `ChaosExperiment.complete()` | `chaos.complete {name}` | resilience_score, resilience_passed, duration |
| `ChaosExperiment.abort()` | `chaos.abort {name}` | abort_reason, injection_count |
| `SLI.record()` (detailed) | `sli.record {name}` | value, target, window |

## Implementation Details

### Architecture
Since Agent SRE already exports native OTel metrics and traces, the instrumentation wraps core methods using `wrapt` (same pattern as CrewAI, LangChain, etc.) to automatically capture SRE telemetry when `openlit.init()` is called.

No OpenLit-specific code needed in agent-sre — the instrumentation monkey-patches at import time.

### Files

| File | Purpose |
|------|---------|
| `instrumentation/agent_sre/__init__.py` | `AgentSREInstrumentor` class (BaseInstrumentor) |
| `instrumentation/agent_sre/agent_sre.py` | 5 sync wrappers for all operations |
| `instrumentation/agent_sre/utils.py` | Span attribute helpers + metrics recording |
| `_instrumentors.py` | Registered `agent-sre` in MODULE_NAME_MAP + INSTRUMENTOR_MAP |

### OTel Conventions

All metrics are prefixed `agent.sre.*`:
- `agent.sre.sli.value` — SLI measurement value
- `agent.sre.burn_rate` — SLO burn rate
- `agent.sre.chaos.resilience_score` — Chaos experiment resilience score
- `agent.sre.chaos.experiment_id` — Experiment identifier

## Use Cases

With this instrumentation, OpenLit users running agent-sre can see:

1. **SLO Health Dashboards** — Real-time error budget burn rate, SLI compliance across agent systems
2. **Chaos Experiment Traces** — Fault injection events, resilience scores, abort conditions alongside LLM calls they affect
3. **Error Budget Consumption** — Track good/bad events against budget to decide when to deploy new features vs focus on reliability
4. **Canary Metrics** — During progressive rollouts of new LLM models/prompts, track canary vs baseline performance

## Companion Integration

The toolkit also includes an `OpenLitExporter` convenience class in Agent SRE that pre-configures OTel SDK for OpenLit's OTLP endpoint:

```python
from agent_sre.integrations.openlit import OpenLitExporter

exporter = OpenLitExporter(
    endpoint="http://localhost:4318",
    service_name="my-ai-service"
)
exporter.record_slo("latency-p99", slo_result)
exporter.record_chaos_experiment("failover-test", experiment)
```

## Links

- [Agent SRE](https://github.com/microsoft/agent-governance-toolkit) — 1,071+ tests
- [OpenLit](https://github.com/openlit/openlit) — OpenTelemetry-native observability
- [OpenLit Issue #1003](https://github.com/openlit/openlit/issues/1003) — Original integration proposal
- [OpenLit PR #1037](https://github.com/openlit/openlit/pull/1037) — Implementation
