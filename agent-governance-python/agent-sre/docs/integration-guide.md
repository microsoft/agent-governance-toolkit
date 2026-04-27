# Integration Guide

## Agent-OS Integration

Agent-SRE monitors agent behavior. [Agent-OS](https://github.com/microsoft/agent-governance-toolkit) enforces governance. Together: measure reliability + enforce policies.

```python
from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import TaskSuccessRate, PolicyCompliance
from agent_sre.replay.capture import TraceCapture, SpanKind

# Define SLO that tracks kernel policy compliance
compliance = PolicyCompliance(target=1.0, window="24h")
success = TaskSuccessRate(target=0.95, window="24h")

slo = SLO(
    name="governed-agent",
    indicators=[success, compliance],
    error_budget=ErrorBudget(total=0.01),  # Zero tolerance: 1% budget
)

# Capture execution traces through Agent-OS kernel
with TraceCapture(agent_id="governed-agent", task_input="process payment") as capture:
    span = capture.start_span("policy_check", SpanKind.POLICY_CHECK)
    # Agent-OS kernel checks policy here
    span.finish(output={"decision": "ALLOW"})
    compliance.record_check(compliant=True)

    span = capture.start_span("tool_call", SpanKind.TOOL_CALL, 
                              input_data={"tool": "payment_api"})
    # Agent executes tool
    span.finish(output={"status": "success"}, cost_usd=0.15)
    success.record_task(success=True)
```

The trace captures every decision point: policy checks, tool calls, LLM inferences. When something goes wrong, replay the exact sequence.

## AgentMesh Integration

[AgentMesh](https://github.com/microsoft/agent-governance-toolkit) provides cross-agent trust. Agent-SRE monitors trust health.

```python
from agent_sre.slo.indicators import TaskSuccessRate
from agent_sre.replay.capture import TraceCapture, SpanKind

# Track trust handshake success as an SLI
trust_handshake = TaskSuccessRate(target=0.999, window="1h")

with TraceCapture(agent_id="payment-agent", task_input="verify peer") as capture:
    span = capture.start_span("trust_handshake", SpanKind.DELEGATION,
                              input_data={"peer": "shipping-agent"})
    # AgentMesh IATP handshake happens here
    handshake_success = True
    span.finish(output={"trust_score": 847, "verified": True})
    trust_handshake.record_task(success=handshake_success)
```

## OpenTelemetry Export

Agent-SRE traces are compatible with OpenTelemetry:

```python
from agent_sre.integrations.otel import OTelExporter

# Export agent traces alongside infrastructure traces
exporter = OTelExporter(endpoint="http://localhost:4317")
```

This means agent-level traces appear in the same Grafana/Jaeger dashboards as your infrastructure traces — but with agent-specific attributes like `agent.trust_score`, `agent.decision`, and `agent.policy_result`.

## Sentry Integration

Agent SRE includes a native [Sentry](https://sentry.io) exporter for capturing
incidents, exceptions, and SLO breaches. The integration supports two modes:

- **Live mode**: Sends events to Sentry via DSN or a provided client instance.
- **Offline mode**: Stores events in memory for testing and inspection without
  network calls.

### Installation

Install Agent SRE with the Sentry optional dependency:

```bash
pip install agent-sre[sentry]
```

### Quick start (live mode)

```python
from agent_sre.integrations.sentry import SentryExporter

# Initialize with your Sentry DSN
exporter = SentryExporter(
    dsn="https://your-public-key@o0.ingest.sentry.io/0",  # replace with your DSN
    environment="production",
    release="agent-v1.2.0",
)

# Capture an incident
exporter.capture_incident(
    title="Agent task timeout exceeded 30s threshold",
    severity="warning",
    tags={"agent_id": "payment-agent", "task": "process_refund"},
    context={"timeout_ms": 31200, "retry_count": 3},
)

# Capture an exception
try:
    result = agent.execute(task)
except Exception as e:
    exporter.capture_exception(
        error=e,
        tags={"agent_id": "payment-agent"},
        context={"task_input": task.summary},
    )
```

### Quick start (offline mode)

Omit the DSN to run in offline mode. Events are stored in memory and accessible
via the `events` property:

```python
from agent_sre.integrations.sentry import SentryExporter

exporter = SentryExporter()  # No DSN = offline mode
assert exporter.is_offline

exporter.capture_incident(title="Test incident", severity="info")
assert len(exporter.events) == 1
assert exporter.events[0].message == "Test incident"
```

### Capturing SLO breaches

When an SLO is breached, capture it with structured context including burn rate
and budget remaining:

```python
from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import TaskSuccessRate
from agent_sre.integrations.sentry import SentryExporter

slo = SLO(
    name="payment-agent-success",
    indicators=[TaskSuccessRate(target=0.99, window="1h")],
    error_budget=ErrorBudget(total=0.01),
)

exporter = SentryExporter(dsn="https://...")

# When SLO breaches, capture with full context
exporter.capture_slo_breach(
    slo=slo,
    agent_id="payment-agent",
    tags={"team": "payments", "tier": "critical"},
)
# Event includes: slo name, status, budget_remaining, burn_rate
```

### Using a custom client

You can provide your own Sentry-compatible client instead of relying on
`sentry_sdk` auto-initialization. The client must implement `capture_exception`
and `capture_message` methods:

```python
import sentry_sdk

sentry_sdk.init(dsn="https://...", traces_sample_rate=0.1)
exporter = SentryExporter(client=sentry_sdk)
```

### Exporter statistics

Check the exporter state at any time:

```python
stats = exporter.get_stats()
# {"is_offline": False, "total_events": 12, "environment": "production", "release": "v1.2.0"}
```

### Clearing events

In test scenarios, clear captured events between test cases:

```python
exporter.clear()
assert len(exporter.events) == 0
```
