# Tutorial 13 — Observability & Distributed Tracing

> **Package:** `agentmesh-runtime` · **Time:** 30 minutes · **Prerequisites:** Python 3.11+

---

## What You'll Learn

- Causal trace IDs for hierarchical event tracking
- Event bus for structured, immutable event streaming
- Prometheus metrics and ring-level collectors
- OpenTelemetry-compatible span export

---

**Instrument autonomous agents with structured events, causal trace IDs, Prometheus metrics, and OpenTelemetry-compatible span export.**

See also: [Tutorial 05 — Agent Reliability](05-agent-reliability.md) | [Tutorial 06 — Execution Sandboxing](06-execution-sandboxing.md) | [Deployment Guide](../deployment/README.md)

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation](#2-installation)
3. [Quick Start: Emit and Query Events](#3-quick-start-emit-and-query-events)
4. [CausalTraceId: Hierarchical Trace IDs](#4-causaltraceid-hierarchical-trace-ids)
5. [HypervisorEventBus: Structured Event Store](#5-hypervisoreventbus-structured-event-store)
6. [RingMetricsCollector: Prometheus Metrics](#6-ringmetricscollector-prometheus-metrics)
7. [SagaSpanExporter: Distributed Tracing Spans](#7-sagaspanexporter-distributed-tracing-spans)
8. [Integration with OpenTelemetry](#8-integration-with-opentelemetry)
9. [.NET Governance Metrics](#9-net-governance-metrics)
10. [Prometheus & Grafana Dashboard](#10-prometheus--grafana-dashboard)
11. [Next Steps](#11-next-steps)

---

## 1. Introduction

Traditional application monitoring tracks request latency, error rates, and
resource consumption. Autonomous agents introduce new observability challenges:

| Challenge | Why It's Hard | What You Need |
|---|---|---|
| **Multi-agent causality** | Agent A spawns Agent B which delegates to Agent C — who caused the failure? | Hierarchical trace IDs that encode the full spawn tree |
| **Ring transitions** | Agents move between privilege levels dynamically — did an elevation expire? | Counters and gauges for every ring transition and breach |
| **Saga rollbacks** | A five-step transaction fails at step 3 — what compensated? | Span-level tracing of every saga step with timing |
| **Behavioral drift** | An agent starts behaving differently after a model update | Structured events with type-based filtering and time-range queries |
| **Cross-language stacks** | Python hypervisor + .NET governance kernel in the same deployment | OpenTelemetry-compatible metrics and traces in both languages |

The **Agent Hypervisor** observability module provides four composable
primitives that solve all of these:

```
┌────────────────────────────────────────────────────────────┐
│                    HypervisorEventBus                      │
│   Append-only structured event store with pub/sub          │
│   40+ typed events · session/agent/time indexes            │
├──────────────────────┬─────────────────────────────────────┤
│  RingMetricsCollector│       SagaSpanExporter              │
│  Subscribes to ring  │       Subscribes to saga            │
│  events → Prometheus │       events → OTel spans           │
│  counters & gauges   │       with SpanSink protocol        │
├──────────────────────┴─────────────────────────────────────┤
│                     CausalTraceId                          │
│   Hierarchical trace/span IDs for multi-agent causality    │
│   Format: {trace_id}/{span_id}[/{parent_span_id}]         │
└────────────────────────────────────────────────────────────┘
```

---

## 2. Installation

```bash
# Python — hypervisor with observability built in
pip install agent-hypervisor

# .NET — governance with OpenTelemetry metrics
dotnet add package AgentGovernance
```

### Prerequisites

- Python ≥ 3.11
- .NET 8+ (for .NET metrics only)
- Optional: Prometheus + Grafana for dashboards
- Optional: an OpenTelemetry collector for span export

All observability components are **zero-dependency** — they use protocols and
duck typing to avoid hard imports on Prometheus client libraries or the
OpenTelemetry SDK. You connect exporters at the edges.

---

## 3. Quick Start: Emit and Query Events

Get observability running in under 15 lines:

```python
from hypervisor.observability import (
    HypervisorEventBus,
    HypervisorEvent,
    EventType,
    CausalTraceId,
)

# 1. Create the event bus — the central nervous system
bus = HypervisorEventBus()

# 2. Create a causal trace for this workflow
trace = CausalTraceId()
print(f"Trace started: {trace.full_id}")
# e.g. "a1b2c3d4e5f6/01234567"

# 3. Emit a structured event
bus.emit(HypervisorEvent(
    event_type=EventType.SESSION_CREATED,
    session_id="session-001",
    agent_did="did:mesh:data-analyst",
    causal_trace_id=trace.full_id,
    payload={"model": "gpt-4o", "ring": 3},
))

# 4. Query it back
events = bus.query_by_session("session-001")
print(f"Events for session-001: {len(events)}")   # 1
print(events[0].to_dict())
```

### Subscribe to events in real time

```python
# Type-specific subscriber — only ring breaches
def on_breach(event: HypervisorEvent) -> None:
    print(f"🚨 BREACH: agent={event.agent_did} payload={event.payload}")

bus.subscribe(event_type=EventType.RING_BREACH_DETECTED, handler=on_breach)

# Wildcard subscriber — receives ALL events
bus.subscribe(event_type=None, handler=lambda e: print(f"[audit] {e.event_type.value}"))

# This triggers both subscribers
bus.emit(HypervisorEvent(
    event_type=EventType.RING_BREACH_DETECTED,
    agent_did="did:mesh:rogue-bot",
    session_id="session-001",
    payload={"attempted_tool": "shell_exec", "ring": 3},
))
```

---

## 4. CausalTraceId: Hierarchical Trace IDs

When Agent A spawns Agent B, and Agent B delegates to Agent C, you need to
trace the full causal chain. `CausalTraceId` encodes the entire spawn tree in a
compact string format.

### Format

```
{trace_id}/{span_id}[/{parent_span_id}]
```

- **trace_id** — 12-char hex, shared across the entire trace tree
- **span_id** — 8-char hex, unique to this span
- **parent_span_id** — 8-char hex, present only for non-root spans

### Creating traces

```python
from hypervisor.observability import CausalTraceId

# Root trace — generated automatically
root = CausalTraceId()
print(root.full_id)        # "a1b2c3d4e5f6/01234567"
print(root.depth)          # 0
print(root.parent_span_id) # None

# Child span — same trace, new span, parent linked
child = root.child()
print(child.full_id)        # "a1b2c3d4e5f6/89abcdef/01234567"
print(child.depth)          # 1
print(child.parent_span_id) # "01234567" (root's span_id)

# Sibling span — parallel work at the same depth
sibling = child.sibling()
print(sibling.depth)          # 1 (same as child)
print(sibling.parent_span_id) # "01234567" (same parent)
print(sibling.span_id)        # new unique ID

# Deep nesting — each child() increments depth
grandchild = child.child()
print(grandchild.depth)  # 2
```

### Parsing traces from strings

```python
parsed = CausalTraceId.from_string("a1b2c3d4e5f6/89abcdef/01234567")
print(parsed.trace_id)        # "a1b2c3d4e5f6"
print(parsed.span_id)         # "89abcdef"
print(parsed.parent_span_id)  # "01234567"

# Root traces (no parent) parse cleanly
root_parsed = CausalTraceId.from_string("a1b2c3d4e5f6/01234567")
print(root_parsed.parent_span_id)  # None

# Invalid format raises ValueError
CausalTraceId.from_string("invalid")  # → ValueError
```

### Multi-agent delegation pattern

```python
orchestrator_trace = CausalTraceId()
researcher_trace = orchestrator_trace.child()
writer_trace = orchestrator_trace.child()
tool_agent_trace = researcher_trace.child()

# Attach trace IDs to events for full causality
bus.emit(HypervisorEvent(
    event_type=EventType.SESSION_CREATED,
    agent_did="did:mesh:tool-agent",
    causal_trace_id=tool_agent_trace.full_id,
))
# Trace tree: orchestrator(0) → researcher(1) → tool-agent(2)
#                              → writer(1)
```

### Ancestry queries

`is_ancestor_of()` checks same `trace_id` AND `other.depth > self.depth`:

```python
root = CausalTraceId()
child = root.child()
grandchild = child.child()

print(root.is_ancestor_of(grandchild))  # True
print(child.is_ancestor_of(root))       # False
print(root.is_ancestor_of(root))        # False (same depth)
```

### Sibling spans for parallel work

```python
worker_1 = orchestrator_trace.child()
worker_2 = worker_1.sibling()  # Same parent, same depth, new span_id

assert worker_1.parent_span_id == worker_2.parent_span_id  # True
assert worker_1.trace_id == worker_2.trace_id               # True
```

---

## 5. HypervisorEventBus: Structured Event Store

The `HypervisorEventBus` is an append-only event log with built-in indexing
and pub/sub. Every component in the hypervisor emits events here — ring
transitions, saga steps, security incidents, audit records, and more.

### Event types

The bus supports 40+ typed events organized into categories:

| Category | Event Types | Examples |
|---|---|---|
| **Session** | 5 | `SESSION_CREATED`, `SESSION_TERMINATED`, `SESSION_ARCHIVED` |
| **Ring** | 5 | `RING_ASSIGNED`, `RING_ELEVATED`, `RING_BREACH_DETECTED` |
| **Liability** | 6 | `VOUCH_CREATED`, `SLASH_EXECUTED`, `QUARANTINE_ENTERED` |
| **Saga** | 10 | `SAGA_CREATED`, `SAGA_STEP_COMMITTED`, `SAGA_ESCALATED` |
| **VFS** | 5 | `VFS_WRITE`, `VFS_SNAPSHOT`, `VFS_CONFLICT` |
| **Security** | 4 | `RATE_LIMITED`, `AGENT_KILLED`, `IDENTITY_VERIFIED` |
| **Audit** | 3 | `AUDIT_DELTA_CAPTURED`, `AUDIT_COMMITTED` |
| **Verification** | 2 | `BEHAVIOR_DRIFT`, `HISTORY_VERIFIED` |

### The HypervisorEvent dataclass

Every event is an immutable (frozen) dataclass with auto-generated ID and
timestamp:

```python
event = HypervisorEvent(
    event_type=EventType.SLASH_EXECUTED,
    session_id="session-042",
    agent_did="did:mesh:rogue-agent",
    causal_trace_id="abc123/def456",
    payload={"severity": "critical", "stake_slashed": 150},
)

print(event.event_id)    # Auto-generated 16-char UUID hex
print(event.timestamp)   # datetime.now(UTC)

# Serialize to JSON-compatible dict
d = event.to_dict()
print(d["event_type"])   # "liability.slash_executed"
print(d["timestamp"])    # "2025-01-15T10:30:00+00:00" (ISO format)
```

### Emitting events

```python
bus = HypervisorEventBus()

bus.emit(HypervisorEvent(
    event_type=EventType.RING_ASSIGNED,
    session_id="s1", agent_did="did:mesh:agent-alpha",
    payload={"ring": 3},
))
bus.emit(HypervisorEvent(
    event_type=EventType.RING_ELEVATED,
    session_id="s1", agent_did="did:mesh:agent-alpha",
    payload={"from_ring": 3, "to_ring": 1, "reason": "admin vouch"},
))

print(f"Total events: {bus.event_count}")  # 2
print(bus.type_counts())  # {"ring.assigned": 1, "ring.elevated": 1}
```

### Querying events

The bus provides indexed lookups by type, session, agent, time range, and
multi-filter combinations:

```python
from datetime import datetime, timedelta, UTC

# By type, session, or agent
sessions = bus.query_by_type(EventType.SESSION_CREATED)
s1_events = bus.query_by_session("s1")
agent_events = bus.query_by_agent("did:mesh:agent-alpha")

# By time range
recent = bus.query_by_time_range(start=datetime.now(UTC) - timedelta(hours=1))

# Combined (AND) with limit
results = bus.query(
    event_type=EventType.RING_ASSIGNED,
    session_id="s1",
    agent_did="did:mesh:analyst",
    limit=10,
)

# Statistics
print(bus.event_count)    # Total events
print(bus.type_counts())  # {"ring.assigned": 1, ...}
all_events = bus.all_events  # Full log (copy)
```

---

## 6. RingMetricsCollector: Prometheus Metrics

The `RingMetricsCollector` subscribes to the event bus and automatically
maintains Prometheus-compatible counters and gauges for ring enforcement. See
[Tutorial 06 — Execution Sandboxing](06-execution-sandboxing.md) for the ring
model itself.

### Setting up the collector

```python
from hypervisor.observability import (
    HypervisorEventBus, HypervisorEvent, EventType, RingMetricsCollector,
)

bus = HypervisorEventBus()
collector = RingMetricsCollector(bus)  # Auto-subscribes to all ring events

bus.emit(HypervisorEvent(
    event_type=EventType.RING_ASSIGNED,
    session_id="s1", agent_did="did:mesh:analyst",
    payload={"ring": 3},
))
bus.emit(HypervisorEvent(
    event_type=EventType.RING_ELEVATED,
    session_id="s1", agent_did="did:mesh:analyst",
    payload={"from_ring": 3, "to_ring": 1},
))
bus.emit(HypervisorEvent(
    event_type=EventType.RING_BREACH_DETECTED,
    session_id="s1", agent_did="did:mesh:analyst",
    payload={"attempted_tool": "shell_exec"},
))
```

### Collecting metric snapshots

```python
snapshot = collector.collect()

# Transition counters — keyed by (event_type, agent_did, session_id)
print(snapshot["agent_hypervisor_ring_transitions_total"][("ring.assigned", "did:mesh:analyst", "s1")])  # 1

# Breach counters — keyed by (agent_did, session_id)
print(snapshot["agent_hypervisor_ring_breaches_total"][("did:mesh:analyst", "s1")])  # 1

# Current ring gauge — keyed by agent_did
print(snapshot["agent_hypervisor_ring_current"]["did:mesh:analyst"])  # 1

print(snapshot["events_processed"])  # 3
```

### Metrics reference

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `agent_hypervisor_ring_transitions_total` | Counter | `event_type`, `agent_did`, `session_id` | Ring assignments, elevations, demotions, expirations |
| `agent_hypervisor_ring_breaches_total` | Counter | `agent_did`, `session_id` | Capability boundary violations |
| `agent_hypervisor_ring_current` | Gauge | `agent_did` | Current ring level (0=root, 3=sandbox) |
| `agent_hypervisor_ring_elevation_duration_seconds` | Gauge | `agent_did` | Time spent at elevated privilege |

### Elevation duration tracking

The collector tracks how long an agent stays at an elevated ring level:

```python
import time

bus.emit(HypervisorEvent(
    event_type=EventType.RING_ELEVATED,
    agent_did="did:mesh:analyst", session_id="s1",
    payload={"to_ring": 1},
))
time.sleep(2)
bus.emit(HypervisorEvent(
    event_type=EventType.RING_DEMOTED,
    agent_did="did:mesh:analyst", session_id="s1",
    payload={"to_ring": 3},
))

duration = collector.collect()["agent_hypervisor_ring_elevation_duration_seconds"]
print(f"Elevation lasted {duration['did:mesh:analyst']:.1f}s")  # ≈ 2.0s
```

### Exporting to Prometheus

The collector uses a `PrometheusExporterProtocol` to avoid a hard dependency on
the Prometheus client library. Any object implementing `set_gauge()` and
`inc_counter()` works:

```python
class MyPrometheusExporter:
    """Bridge to prometheus_client or agent-sre exporter."""
    def set_gauge(self, name, value, labels=None, help_text=""):
        print(f"GAUGE {name}={value} labels={labels}")

    def inc_counter(self, name, value=1.0, labels=None, help_text=""):
        print(f"COUNTER {name} +={value} labels={labels}")

exporter = MyPrometheusExporter()
collector.export_to_prometheus(exporter)
```

> **Note:** The `agent-sre` package includes a production-ready
> `PrometheusExporter` that implements this protocol. See
> [Tutorial 05 — Agent Reliability](05-agent-reliability.md).

---

## 7. SagaSpanExporter: Distributed Tracing Spans

The `SagaSpanExporter` subscribes to saga lifecycle events and produces
OpenTelemetry-compatible span records. Every saga step becomes a span with
timing, status, and rich attributes. See [Tutorial 06 — Execution
Sandboxing](06-execution-sandboxing.md) for saga orchestration itself.

### Setting up the exporter

```python
from hypervisor.observability import (
    HypervisorEventBus, HypervisorEvent, EventType,
    SagaSpanExporter, SagaSpanRecord,
)

bus = HypervisorEventBus()
exporter = SagaSpanExporter(bus)  # Auto-subscribes to all SAGA_* events
```

### Tracing a saga step

```python
import time

bus.emit(HypervisorEvent(
    event_type=EventType.SAGA_CREATED,
    session_id="s1",
    agent_did="did:mesh:orchestrator",
    payload={"saga_id": "deploy-v2"},
))

bus.emit(HypervisorEvent(
    event_type=EventType.SAGA_STEP_STARTED,
    session_id="s1",
    agent_did="did:mesh:orchestrator",
    payload={"saga_id": "deploy-v2", "step_id": "validate-config", "step_action": "validate"},
))

time.sleep(0.5)  # Simulate work

bus.emit(HypervisorEvent(
    event_type=EventType.SAGA_STEP_COMMITTED,
    session_id="s1",
    agent_did="did:mesh:orchestrator",
    payload={
        "saga_id": "deploy-v2", "step_id": "validate-config",
        "step_action": "validate", "result": "all checks passed",
    },
))

span = exporter.completed_spans[0]
print(f"Name:     {span.name}")            # "saga.step.validate"
print(f"Status:   {span.status}")           # "ok"
print(f"Duration: {span.duration_seconds:.2f}s")  # ≈ 0.50s
print(f"Attrs:    {span.attributes}")
# {'agent.saga.id': 'deploy-v2', 'agent.saga.step_id': 'validate-config',
#  'agent.saga.step_action': 'validate', 'agent.saga.state': 'ok',
#  'agent.saga.result': 'all checks passed', 'agent.did': 'did:mesh:orchestrator',
#  'session.id': 's1'}
```

### Tracing failures and compensations

```python
# A step fails
bus.emit(HypervisorEvent(
    event_type=EventType.SAGA_STEP_STARTED,
    payload={"saga_id": "deploy-v2", "step_id": "run-migrations", "step_action": "migrate"},
))
bus.emit(HypervisorEvent(
    event_type=EventType.SAGA_STEP_FAILED,
    payload={
        "saga_id": "deploy-v2", "step_id": "run-migrations", "step_action": "migrate",
        "error": "connection_timeout", "reason": "database unreachable after 30s",
    },
))

# Compensation kicks in
bus.emit(HypervisorEvent(
    event_type=EventType.SAGA_COMPENSATING,
    payload={"saga_id": "deploy-v2", "step_id": "rollback-config", "step_action": "rollback"},
))

error_span = [s for s in exporter.completed_spans if s.status == "error"][-1]
print(error_span.attributes["agent.saga.error"])   # "connection_timeout"

comp_span = [s for s in exporter.completed_spans if s.status == "compensating"][-1]
print(comp_span.name)  # "saga.compensate.rollback"
```

### Saga-level spans

When a saga completes or escalates, a top-level span covers the entire
saga duration:

```python
bus.emit(HypervisorEvent(
    event_type=EventType.SAGA_COMPLETED,
    payload={"saga_id": "deploy-v2"},
))

saga_span = [s for s in exporter.completed_spans if "completed" in s.name][-1]
print(f"Duration: {saga_span.duration_seconds:.2f}s, Status: {saga_span.status}")  # "ok"

# Escalated sagas produce error spans:
# EventType.SAGA_ESCALATED → span.status == "error", name == "saga.escalated.{id}"
```

### Using SpanSink for real-time export

The `SpanSink` protocol lets you forward spans to any backend — Jaeger, Zipkin,
Azure Monitor, or a custom store:

```python
from hypervisor.observability import SpanSink

class JaegerSink:
    """Forward saga spans to a Jaeger backend."""
    def record_span(self, name, start_time, end_time, attributes, status):
        duration_ms = (end_time - start_time) * 1000
        print(f"→ Jaeger: {name} [{status}] {duration_ms:.0f}ms")

sink = JaegerSink()
exporter.attach_sink(sink)   # Spans now go to both buffer AND sink
# ... emit saga events ...
exporter.detach_sink()       # Stop real-time forwarding
```

> **Note:** Spans are always buffered in `completed_spans` regardless of
> whether a sink is attached. The sink adds real-time forwarding on top.

---

## 8. Integration with OpenTelemetry

The observability module is designed to plug into standard OpenTelemetry
pipelines without requiring OTEL as a dependency in the hypervisor itself.

### Bridging SagaSpanExporter to OpenTelemetry

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter
from hypervisor.observability import HypervisorEventBus, SagaSpanExporter, SpanSink

provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
trace.set_tracer_provider(provider)
tracer = trace.get_tracer("agent-hypervisor")

class OTelSpanSink:
    """Bridge hypervisor saga spans to OpenTelemetry."""
    def record_span(self, name, start_time, end_time, attributes, status):
        with tracer.start_as_current_span(name) as span:
            for key, value in attributes.items():
                span.set_attribute(key, str(value))
            if status == "error":
                span.set_status(trace.StatusCode.ERROR, attributes.get("agent.saga.error", ""))

bus = HypervisorEventBus()
exporter = SagaSpanExporter(bus, sink=OTelSpanSink())
# Every saga step now appears as an OTel span in your tracing backend
```

### Span attribute conventions

The `SagaSpanExporter` follows OpenTelemetry semantic conventions with
`agent.*` namespace attributes:

| Attribute | Type | Description |
|---|---|---|
| `agent.saga.id` | string | Unique saga identifier |
| `agent.saga.step_id` | string | Step identifier within the saga |
| `agent.saga.step_action` | string | Action name (e.g., `"validate"`, `"deploy"`) |
| `agent.saga.state` | string | `"ok"`, `"error"`, or `"compensating"` |
| `agent.saga.error` | string | Error message (failures only) |
| `agent.saga.reason` | string | Failure/escalation reason |
| `agent.saga.result` | string | Step result (successes only) |
| `agent.did` | string | Agent DID that executed the step |
| `session.id` | string | Session ID where the step ran |

### Bridging RingMetricsCollector to OpenTelemetry Metrics

```python
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader

reader = PeriodicExportingMetricReader(ConsoleMetricExporter(), export_interval_millis=5000)
metrics.set_meter_provider(MeterProvider(metric_readers=[reader]))
meter = metrics.get_meter("agent-hypervisor")

ring_transitions = meter.create_counter("agent_hypervisor_ring_transitions_total")
ring_breaches = meter.create_counter("agent_hypervisor_ring_breaches_total")

class OTelPrometheusExporter:
    def set_gauge(self, name, value, labels=None, help_text=""):
        pass  # Map to OTel gauge instruments
    def inc_counter(self, name, value=1.0, labels=None, help_text=""):
        if "transitions" in name:
            ring_transitions.add(value, labels or {})
        elif "breaches" in name:
            ring_breaches.add(value, labels or {})

collector.export_to_prometheus(OTelPrometheusExporter())
```

---

## 9. .NET Governance Metrics

The .NET `AgentGovernance` package includes `GovernanceMetrics` — an
OpenTelemetry-compatible metrics class using `System.Diagnostics.Metrics`.
These metrics complement the Python hypervisor metrics for mixed-language
deployments.

### Setting up .NET metrics

```csharp
using AgentGovernance.Telemetry;
using OpenTelemetry;
using OpenTelemetry.Metrics;

// Register the governance meter with OpenTelemetry
using var meterProvider = Sdk.CreateMeterProviderBuilder()
    .AddMeter(GovernanceMetrics.MeterName)  // "AgentGovernance"
    .AddPrometheusExporter()                // Or any OTEL exporter
    .Build();

var metrics = new GovernanceMetrics();
```

### Recording governance decisions

```csharp
// Record an allowed decision
metrics.RecordDecision(
    allowed: true,
    agentId: "did:mesh:data-analyst",
    toolName: "file_read",
    evaluationMs: 0.05
);

// Record a blocked decision
metrics.RecordDecision(
    allowed: false,
    agentId: "did:mesh:untrusted",
    toolName: "shell_exec",
    evaluationMs: 0.12
);

// Record a rate-limited request
metrics.RecordDecision(
    allowed: false,
    agentId: "did:mesh:noisy-agent",
    toolName: "api_call",
    evaluationMs: 0.01,
    rateLimited: true
);
```

### Registering observable gauges

```csharp
// Trust score gauge — callback invoked on each Prometheus scrape
metrics.RegisterTrustScoreGauge(() => new[]
{
    new Measurement<double>(850.0,
        new KeyValuePair<string, object?>("agent_id", "did:mesh:trusted")),
    new Measurement<double>(320.0,
        new KeyValuePair<string, object?>("agent_id", "did:mesh:suspicious")),
});

metrics.RegisterActiveAgentsGauge(() => agentRegistry.Count);
```

### .NET metrics reference

| Metric | Type | Unit | Description |
|---|---|---|---|
| `agent_governance.policy_decisions` | Counter | — | Total governance evaluations |
| `agent_governance.tool_calls_allowed` | Counter | — | Tool calls permitted by policy |
| `agent_governance.tool_calls_blocked` | Counter | — | Tool calls denied by policy |
| `agent_governance.rate_limit_hits` | Counter | — | Requests rejected by rate limiter |
| `agent_governance.evaluation_latency_ms` | Histogram | ms | Governance evaluation latency |
| `agent_governance.trust_score` | Gauge | 0–1000 | Current agent trust score |
| `agent_governance.active_agents` | Gauge | — | Number of active governed agents |
| `agent_governance.audit_events` | Counter | — | Audit events emitted |

### Cross-language metric correlation

Both Python and .NET use the same `agent_*` metric naming and label patterns,
so a single Prometheus instance can scrape both and correlate in Grafana.

---

## 10. Prometheus & Grafana Dashboard

### Prometheus scrape configuration

```yaml
# prometheus.yml
scrape_configs:
  # Python hypervisor metrics
  - job_name: "agent-hypervisor"
    scrape_interval: 15s
    static_configs:
      - targets: ["localhost:8000"]
    metrics_path: /metrics

  # .NET governance metrics
  - job_name: "agent-governance"
    scrape_interval: 15s
    static_configs:
      - targets: ["localhost:5000"]
    metrics_path: /metrics
```

### Useful PromQL queries

```promql
# Ring breach rate (breaches per minute)
rate(agent_hypervisor_ring_breaches_total[5m]) * 60

# Ring transition rate by type
sum by (event_type) (rate(agent_hypervisor_ring_transitions_total[5m]))

# Governance policy denial rate
rate(agent_governance_tool_calls_blocked_total[5m])
  / rate(agent_governance_policy_decisions_total[5m])

# P99 governance evaluation latency
histogram_quantile(0.99, agent_governance_evaluation_latency_ms)
```

### Grafana dashboard layout

```
┌─────────────────────────────────────────────────────────────────┐
│                    Agent Observability Dashboard                │
├────────────────────┬──────────────────┬─────────────────────────┤
│  Ring Transitions  │  Breach Rate     │  Current Ring Levels    │
│  (time series)     │  (stat panel)    │  (table)                │
├────────────────────┼──────────────────┼─────────────────────────┤
│  Elevation Duration│  Policy Decisions│  Trust Scores           │
│  (histogram)       │  (pie chart)     │  (gauge panel)          │
├────────────────────┴──────────────────┴─────────────────────────┤
│  Saga Span Timeline (Jaeger/Tempo embedded)                     │
│  deploy-v2 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 12.3s           │
│    ├─ validate    ━━━━━ 2.1s [ok]                               │
│    ├─ migrate     ━━━━━━━━━ 4.5s [ok]                           │
│    └─ deploy      ━━━━━━━━━━━━ 5.2s [ok]                       │
└─────────────────────────────────────────────────────────────────┘
```

### Alert rules

```yaml
groups:
  - name: agent-governance
    rules:
      - alert: HighRingBreachRate
        expr: rate(agent_hypervisor_ring_breaches_total[5m]) > 0.5
        for: 2m
        annotations:
          summary: "Agent {{ $labels.agent_did }} breaching ring boundaries"

      - alert: ElevationTooLong
        expr: agent_hypervisor_ring_elevation_duration_seconds > 300
        for: 1m
        annotations:
          summary: "Agent {{ $labels.agent_did }} elevated for over 5 minutes"

      - alert: GovernanceLatencyHigh
        expr: histogram_quantile(0.99, agent_governance_evaluation_latency_ms) > 50
        for: 5m
        annotations:
          summary: "Governance evaluation P99 latency exceeds 50ms"
```

---

## 11. Next Steps

You now have the tools to observe every aspect of agent behavior at runtime.
Here's where to go next:

| Goal | Resource |
|---|---|
| Understand the ring model that generates ring events | [Tutorial 06 — Execution Sandboxing](06-execution-sandboxing.md) |
| Set up saga orchestration that generates saga spans | [Tutorial 06 — Execution Sandboxing](06-execution-sandboxing.md) |
| Add circuit breakers and SLOs alongside metrics | [Tutorial 05 — Agent Reliability](05-agent-reliability.md) |
| Configure audit logging for compliance | [Tutorial 04 — Audit & Compliance](04-audit-and-compliance.md) |
| Set up trust scoring that feeds the trust gauge | [Tutorial 02 — Trust & Identity](02-trust-and-identity.md) |
| Deploy with Prometheus and Grafana in production | [Deployment Guide](../deployment/README.md) |

### Key takeaways

1. **Event bus is the single source of truth** — every hypervisor action emits a
   typed, immutable event with causal trace linkage.
2. **Metrics collectors are subscribers** — `RingMetricsCollector` and
   `SagaSpanExporter` attach to the bus via pub/sub, keeping components
   decoupled.
3. **Protocols over hard dependencies** — `PrometheusExporterProtocol` and
   `SpanSink` let you plug in any backend without importing it in the hypervisor.
4. **Causal trace IDs encode the full spawn tree** — parent, child, and sibling
   relationships let you trace multi-agent failures back to their root cause.
5. **Cross-language consistency** — Python and .NET metrics share naming
   conventions so a single dashboard can correlate both.

---

## Next Steps

- **Kill Switch:** [Tutorial 14 — Kill Switch & Rate Limiting](14-kill-switch-and-rate-limiting.md)
- **Agent Reliability:** [Tutorial 05 — Agent Reliability Engineering](05-agent-reliability.md)
- **Saga Orchestration:** [Tutorial 11 — Saga Orchestration](11-saga-orchestration.md)
