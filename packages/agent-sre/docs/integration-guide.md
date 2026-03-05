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
