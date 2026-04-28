# Tutorial 40: OpenTelemetry Observability for Agent Governance

> **Time**: 10 minutes · **Level**: Intermediate · **Prerequisites**: Tutorial 36 (govern basics)

## What You'll Build

Full observability for your governed agents: traces showing every policy evaluation, metrics for deny rates and latency, and integration with your existing monitoring stack (Datadog, Grafana, Azure Monitor).

## Why This Matters

When agents run in production, you need to answer:
- How many actions is the policy engine evaluating per second?
- What's the P99 evaluation latency?
- Which rules deny the most actions?
- Which agents trigger the most approvals?

AGT's OTel integration answers all of these with zero custom code.

---

## Step 1: Enable OTel (One Line)

```python
from agentmesh.governance import enable_otel

enable_otel(service_name="customer-service-agent")
```

That's it. All governance operations now emit OTel spans and metrics.

## Step 2: What Gets Emitted

### Spans

Every governance operation creates a span with rich attributes:

```
Span: agt.policy.evaluate
  ├── agt.agent.id = "customer-service-agent-1"
  ├── agt.policy.stage = "pre_tool"
  ├── agt.policy.action = "deny"
  ├── agt.policy.rule = "block-pii-export"
  └── agt.policy.name = "org-baseline"

Span: agt.approval.request
  ├── agt.agent.id = "financial-agent-2"
  ├── agt.policy.rule = "approve-large-transfer"
  ├── agt.approval.outcome = "approved"
  └── agt.approval.approver = "jane@company.com"

Span: agt.trust.verify
  ├── agt.agent.id = "partner-agent-x"
  ├── agt.trust.score = 0.85
  └── agt.trust.tier = "trusted"
```

### Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `agt.policy.evaluations` | Counter | action, stage | Total evaluations |
| `agt.policy.denials` | Counter | rule, tool, stage | Denial count |
| `agt.policy.latency_ms` | Histogram | action, stage | Evaluation latency |
| `agt.approval.requests` | Counter | rule, outcome | Approval workflow count |

## Step 3: Use in Your Agent Code

```python
from agentmesh.governance import (
    enable_otel,
    govern,
    trace_policy_evaluation,
    trace_trust_verification,
    record_denial,
)

# Enable at startup
enable_otel(service_name="my-agent")

# govern() automatically emits spans for every call
safe_tool = govern(my_tool, policy="policy.yaml")
safe_tool(action="read")   # → span emitted with action=allow
safe_tool(action="export")  # → span emitted with action=deny, denial metric recorded
```

## Step 4: Manual Tracing (Advanced)

For custom governance code outside `govern()`:

```python
from agentmesh.governance import trace_policy_evaluation, trace_trust_verification

# Trace a custom policy evaluation
with trace_policy_evaluation(agent_id="agent-1", stage="pre_tool") as result:
    decision = engine.evaluate("agent-1", context, stage="pre_tool")
    result["action"] = decision.action
    result["rule"] = decision.matched_rule
    result["allowed"] = decision.allowed
# Span automatically closed with attributes populated

# Trace a trust verification
with trace_trust_verification(agent_id="partner-agent") as result:
    score = trust_manager.verify("partner-agent")
    result["score"] = score.value
    result["tier"] = score.tier
```

## Step 5: Connect to Your Backend

### Grafana / Prometheus

```python
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.prometheus import PrometheusMetricReader

# Prometheus scrape endpoint at :8000/metrics
reader = PrometheusMetricReader()
```

### Azure Monitor

```python
from azure.monitor.opentelemetry import configure_azure_monitor

configure_azure_monitor(connection_string="InstrumentationKey=...")
enable_otel(service_name="my-agent")
```

### Datadog

```python
# Set environment variables:
# OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
# DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT=0.0.0.0:4317

enable_otel(service_name="my-agent")
```

## Step 6: Example Dashboard Queries

### PromQL: Deny Rate by Rule (Last Hour)

```promql
sum(rate(agt_policy_denials_total[1h])) by (agt_policy_rule)
```

### PromQL: P99 Evaluation Latency

```promql
histogram_quantile(0.99, rate(agt_policy_latency_ms_bucket[5m]))
```

### PromQL: Approval Rate

```promql
sum(rate(agt_approval_requests_total{agt_approval_outcome="approved"}[1h]))
/
sum(rate(agt_approval_requests_total[1h]))
```

## Zero Overhead When Disabled

If you don't call `enable_otel()`, all tracing functions are no-ops:

```python
# This works fine — no spans, no metrics, no performance impact
with trace_policy_evaluation(agent_id="a") as r:
    r["action"] = "allow"
# Context manager completes, result dict populated, zero OTel overhead
```

---

## Semantic Attributes Reference

| Attribute | Type | Description |
|-----------|------|-------------|
| `agt.agent.id` | string | Agent identifier |
| `agt.policy.rule` | string | Matched rule name |
| `agt.policy.action` | string | allow / deny / warn / require_approval |
| `agt.policy.stage` | string | pre_input / pre_tool / post_tool / pre_output |
| `agt.policy.name` | string | Policy name |
| `agt.trust.score` | float | Trust verification score (0.0–1.0) |
| `agt.trust.tier` | string | Trust tier (untrusted / provisional / trusted / verified) |
| `agt.tool.name` | string | Tool that triggered the evaluation |
| `agt.approval.outcome` | string | approved / rejected |
| `agt.approval.approver` | string | Identity of the approver |

---

## What to Try Next

- **Tutorial 41**: Advisory layer with OTel tracing (see advisory decisions in your dashboard)
- **Tutorial 37**: Multi-stage pipeline (trace each stage independently)
