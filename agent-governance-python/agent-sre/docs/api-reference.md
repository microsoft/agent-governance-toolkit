# API Reference

Complete reference for all public classes in `agent-sre`.

- [Core SLO](#core-slo)
- [Alerting](#alerting)
- [Chaos Engineering](#chaos-engineering)
- [Circuit Breaker](#circuit-breaker)
- [Cost Management](#cost-management)
- [Replay & Tracing](#replay--tracing)
- [Fleet Management](#fleet-management)
- [Delivery](#delivery)
- [Framework Adapters](#framework-adapters)
- [Integrations](#integrations)

---

## Core SLO

### `SLO`

**Module:** `agent_sre.slo.objectives`

Service Level Objective for an AI agent. Combines multiple SLIs with targets and an error budget to define what "reliable" means.

```python
from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import TaskSuccessRate

slo = SLO(
    name="my-agent",
    indicators=[TaskSuccessRate(target=0.95)],
    error_budget=ErrorBudget(total=0.05),
    description="Production agent SLO",
    labels={"team": "platform"},
    agent_id="agent-1",
)

slo.record_event(good=True)
status = slo.evaluate()   # SLOStatus.HEALTHY
print(slo.to_dict())
```

#### Constructor

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | `str` | *required* | Unique SLO name |
| `indicators` | `list[SLI]` | *required* | Service level indicators to track |
| `error_budget` | `ErrorBudget \| None` | `None` | Error budget configuration; auto-derived from strictest indicator target if omitted |
| `description` | `str` | `""` | Human-readable description |
| `labels` | `dict[str, str] \| None` | `None` | Key-value labels for filtering |
| `alert_manager` | `AlertManager \| None` | `None` | Alert manager for automatic breach notifications |
| `agent_id` | `str` | `""` | Agent identifier for alerts |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `evaluate()` | `SLOStatus` | Evaluate current SLO health. Returns `HEALTHY`, `WARNING`, `CRITICAL`, `EXHAUSTED`, or `UNKNOWN` |
| `record_event(good: bool)` | `None` | Record a good or bad event and re-evaluate status |
| `indicator_summary()` | `list[dict]` | Summary of all indicator values |
| `to_dict()` | `dict` | Serialize SLO state including status, budget, and indicators |

---

### `ErrorBudget`

**Module:** `agent_sre.slo.objectives`

Tracks error budget consumption and burn rate alerting.

```python
from agent_sre import ErrorBudget
from agent_sre.slo.objectives import ExhaustionAction

budget = ErrorBudget(
    total=0.05,
    burn_rate_alert=2.0,
    burn_rate_critical=10.0,
    exhaustion_action=ExhaustionAction.FREEZE_DEPLOYMENTS,
)

budget.record_event(good=False)
print(budget.remaining_percent)   # Remaining budget as %
print(budget.burn_rate())         # Current burn rate
print(budget.is_exhausted)        # True if budget consumed
```

#### Constructor

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `total` | `float` | `0.0` | Total error budget (typically `1 - target`) |
| `consumed` | `float` | `0.0` | Already consumed budget |
| `window_seconds` | `int` | `2592000` | Budget window (default 30 days) |
| `burn_rate_alert` | `float` | `2.0` | Burn rate threshold for warning alerts |
| `burn_rate_critical` | `float` | `10.0` | Burn rate threshold for critical alerts |
| `exhaustion_action` | `ExhaustionAction` | `ALERT` | Action when budget exhausted (`ALERT`, `FREEZE_DEPLOYMENTS`, `CIRCUIT_BREAK`, `THROTTLE`) |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `remaining` | `float` | Remaining budget as fraction (0.0–1.0) |
| `remaining_percent` | `float` | Remaining budget as percentage |
| `is_exhausted` | `bool` | True when budget fully consumed |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `record_event(good: bool)` | `None` | Record a good or bad event |
| `burn_rate(window_seconds: int \| None)` | `float` | Current burn rate; `1.0` = consuming at expected rate, `>1.0` = faster |
| `firing_alerts()` | `list[BurnRateAlert]` | Alerts currently firing |
| `to_dict()` | `dict` | Serialize budget state |

---

### `SLI` (Abstract Base)

**Module:** `agent_sre.slo.indicators`

Base class for all Service Level Indicators. Subclass this to define custom measurements.

#### Constructor

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | `str` | *required* | Indicator name |
| `target` | `float` | *required* | Target value |
| `window` | `TimeWindow \| str` | *required* | Aggregation window (`"1h"`, `"6h"`, `"24h"`, `"7d"`, `"30d"`) |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `collect()` | `SLIValue` | *(abstract)* Collect a new measurement |
| `record(value, metadata)` | `SLIValue` | Record a measurement value |
| `values_in_window()` | `list[SLIValue]` | Measurements within current time window |
| `current_value()` | `float \| None` | Aggregated value within window |
| `compliance()` | `float \| None` | Fraction of measurements meeting the target |
| `to_dict()` | `dict` | Serialize indicator state |

---

### Built-in SLI Classes

All built-in SLIs extend `SLI` and are available from `agent_sre.slo.indicators`.

#### `TaskSuccessRate`

Measures the fraction of tasks completed successfully.

```python
from agent_sre.slo.indicators import TaskSuccessRate

sli = TaskSuccessRate(target=0.95, window="24h")
sli.record_task(success=True)
sli.record_task(success=False)
print(sli.current_value())  # 0.5
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `float` | `0.995` | Success rate target |
| `window` | `TimeWindow \| str` | `"30d"` | Measurement window |

**Key method:** `record_task(success: bool, metadata: dict | None) → SLIValue`

#### `ToolCallAccuracy`

Measures the fraction of tool calls that selected the correct tool.

```python
from agent_sre.slo.indicators import ToolCallAccuracy

sli = ToolCallAccuracy(target=0.99, window="7d")
sli.record_call(correct=True)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `float` | `0.999` | Accuracy target |
| `window` | `TimeWindow \| str` | `"7d"` | Measurement window |

**Key method:** `record_call(correct: bool, metadata: dict | None) → SLIValue`

#### `ResponseLatency`

Measures response latency at a given percentile.

```python
from agent_sre.slo.indicators import ResponseLatency

sli = ResponseLatency(target_ms=5000.0, percentile=0.95, window="1h")
sli.record_latency(latency_ms=1200.0)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target_ms` | `float` | `5000.0` | Latency target in milliseconds |
| `percentile` | `float` | `0.95` | Percentile to measure (e.g. 0.95 for p95) |
| `window` | `TimeWindow \| str` | `"1h"` | Measurement window |

**Key method:** `record_latency(latency_ms: float, metadata: dict | None) → SLIValue`

#### `CostPerTask`

Measures the average cost per task in USD.

```python
from agent_sre.slo.indicators import CostPerTask

sli = CostPerTask(target_usd=0.50, window="24h")
sli.record_cost(cost_usd=0.35)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target_usd` | `float` | `0.50` | Cost target in USD |
| `window` | `TimeWindow \| str` | `"24h"` | Measurement window |

**Key method:** `record_cost(cost_usd: float, metadata: dict | None) → SLIValue`

#### `HallucinationRate`

Measures hallucination rate via LLM-as-judge evaluation. Lower is better.

```python
from agent_sre.slo.indicators import HallucinationRate

sli = HallucinationRate(target=0.05, window="24h")
sli.record_evaluation(hallucinated=False, confidence=0.95)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `float` | `0.05` | Maximum hallucination rate |
| `window` | `TimeWindow \| str` | `"24h"` | Measurement window |

**Key method:** `record_evaluation(hallucinated: bool, confidence: float, metadata: dict | None) → SLIValue`

#### `PolicyCompliance`

Measures adherence to policies (100% target by default).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | `float` | `1.0` | Compliance target |
| `window` | `TimeWindow \| str` | `"24h"` | Measurement window |

**Key method:** `record_check(compliant: bool, metadata: dict | None) → SLIValue`

#### `DelegationChainDepth`

Measures scope chain depth (lower is better).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_depth` | `int` | `3` | Maximum acceptable depth |
| `window` | `TimeWindow \| str` | `"24h"` | Measurement window |

**Key method:** `record_depth(depth: int, metadata: dict | None) → SLIValue`

---

### `SLIRegistry`

**Module:** `agent_sre.slo.indicators`

Registry for discovering and managing SLI types and instances.

```python
from agent_sre import SLIRegistry
from agent_sre.slo.indicators import TaskSuccessRate

registry = SLIRegistry()
sli = TaskSuccessRate(target=0.95)
registry.register_instance("agent-1", sli)
registry.collect_all("agent-1")
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `register_type(sli_class)` | `None` | Register a custom SLI type |
| `register_instance(agent_id, sli)` | `None` | Register an SLI instance for an agent |
| `get_type(name)` | `type[SLI] \| None` | Look up SLI type by name |
| `get_instances(agent_id)` | `list[SLI]` | Get all SLIs for an agent |
| `list_types()` | `list[str]` | List all registered SLI type names |
| `collect_all(agent_id)` | `list[SLIValue]` | Collect current values for all SLIs of an agent |

---

### `SLOSpec`

**Module:** `agent_sre.slo.spec`

Pydantic model for declarative SLO specifications. Supports YAML serialization.

```python
from agent_sre.slo.spec import SLOSpec

spec = SLOSpec.from_yaml("slo.yaml")
spec.to_yaml("slo-out.yaml")
```

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | SLO name |
| `description` | `str` | Human-readable description |
| `service` | `str` | Service/agent name |
| `target` | `float` | SLO target |
| `window` | `str` | Time window |
| `error_budget_policy` | `ErrorBudgetPolicy` | Budget policy configuration |
| `labels` | `dict` | Metadata labels |
| `inherits_from` | `str \| None` | Parent SLO spec for inheritance |

---

## Alerting

### `AlertManager`

**Module:** `agent_sre.alerts`

Manages alert channels and dispatches alerts with deduplication. Supports Slack, PagerDuty, OpsGenie, Microsoft Teams, generic webhooks, and in-process callbacks.

```python
from agent_sre.alerts import AlertManager, Alert, AlertSeverity, ChannelConfig, AlertChannel

manager = AlertManager(dedup_window_seconds=300)
manager.add_channel(ChannelConfig(
    channel_type=AlertChannel.SLACK,
    name="ops-slack",
    url="https://hooks.slack.com/services/...",
))

manager.send(Alert(
    title="SLO Breach",
    message="Error budget exhausted for agent-1",
    severity=AlertSeverity.CRITICAL,
    agent_id="agent-1",
    slo_name="my-slo",
    dedup_key="agent-1:my-slo",
))
```

#### Constructor

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `dedup_window_seconds` | `float` | `300.0` | Suppress duplicate alerts within this window |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `add_channel(config: ChannelConfig)` | `None` | Register an alert channel |
| `remove_channel(name: str)` | `None` | Remove a channel by name |
| `list_channels()` | `list[str]` | List registered channel names |
| `send(alert: Alert)` | `list[DeliveryResult]` | Send alert to all matching channels |
| `get_stats()` | `dict` | Delivery statistics |
| `clear_history()` | `None` | Clear delivery history |

---

### `PersistentAlertManager`

**Module:** `agent_sre.alerts`

Extends `AlertManager` with SQLite-backed alert persistence for audit trails.

```python
from agent_sre.alerts import PersistentAlertManager

manager = PersistentAlertManager(db_path="alerts.db")
results = manager.query_alerts(agent_id="agent-1", severity="critical")
```

#### Constructor

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `db_path` | `str` | `"agent_sre_alerts.db"` | SQLite database path |
| `dedup_window_seconds` | `float` | `300.0` | Deduplication window |

#### Additional Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `query_alerts(agent_id, severity, limit)` | `list[dict]` | Query persisted alerts |
| `alert_count()` | `int` | Total persisted alert count |

---

### `Alert`

**Module:** `agent_sre.alerts`

Dataclass representing an alert to be sent to external systems.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `title` | `str` | *required* | Alert title |
| `message` | `str` | *required* | Alert body |
| `severity` | `AlertSeverity` | `WARNING` | `INFO`, `WARNING`, `CRITICAL`, or `RESOLVED` |
| `source` | `str` | `"agent-sre"` | Alert source |
| `agent_id` | `str` | `""` | Agent identifier |
| `slo_name` | `str` | `""` | Related SLO |
| `metadata` | `dict` | `{}` | Additional context |
| `dedup_key` | `str` | `""` | Key for deduplication |

---

### `ChannelConfig`

**Module:** `agent_sre.alerts`

Configuration for an alert channel.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `channel_type` | `AlertChannel` | *required* | `SLACK`, `PAGERDUTY`, `GENERIC_WEBHOOK`, `CALLBACK`, `OPSGENIE`, `TEAMS` |
| `name` | `str` | *required* | Channel name |
| `url` | `str` | `""` | Webhook URL |
| `token` | `str` | `""` | Auth token (PagerDuty routing key, OpsGenie API key) |
| `callback` | `Callable \| None` | `None` | In-process callback for `CALLBACK` type |
| `min_severity` | `AlertSeverity` | `WARNING` | Minimum severity to deliver |
| `enabled` | `bool` | `True` | Whether channel is active |

---

## Chaos Engineering

### `ChaosExperiment`

**Module:** `agent_sre.chaos.engine`

A chaos engineering experiment that injects faults into agent systems.

```python
from agent_sre.chaos.engine import ChaosExperiment, Fault, AbortCondition

experiment = ChaosExperiment(
    name="tool-timeout-test",
    target_agent="agent-1",
    faults=[Fault.timeout_injection("search-tool", delay_ms=30000)],
    duration_seconds=600,
    abort_conditions=[AbortCondition(metric="success_rate", threshold=0.5)],
    blast_radius=0.5,
)

experiment.start()
# ... run agent workload ...
experiment.check_abort({"success_rate": 0.8})
score = experiment.calculate_resilience(
    baseline_success_rate=0.99,
    experiment_success_rate=0.95,
)
experiment.complete(resilience=score)
```

#### Constructor

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | `str` | *required* | Experiment name |
| `target_agent` | `str` | *required* | Agent to target |
| `faults` | `list[Fault]` | *required* | Faults to inject |
| `duration_seconds` | `int` | `1800` | Maximum duration |
| `abort_conditions` | `list[AbortCondition] \| None` | `None` | Safety abort conditions |
| `blast_radius` | `float` | `1.0` | Fraction of traffic affected (0.0–1.0) |
| `description` | `str` | `""` | Human-readable description |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `elapsed_seconds` | `float` | Time since start |
| `remaining_seconds` | `float` | Time remaining |
| `is_expired` | `bool` | Whether duration exceeded |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `start()` | `None` | Start the experiment |
| `inject_fault(fault, applied, details)` | `None` | Record a fault injection event |
| `check_abort(metrics: dict)` | `bool` | Check abort conditions; returns `True` if experiment should stop |
| `abort(reason: str)` | `None` | Abort the experiment |
| `complete(resilience)` | `None` | Mark experiment as completed |
| `calculate_resilience(baseline_success_rate, experiment_success_rate, ...)` | `ResilienceScore` | Calculate resilience score |
| `to_dict()` | `dict` | Serialize experiment state |

---

### `Fault`

**Module:** `agent_sre.chaos.engine`

A fault to inject during a chaos experiment.

```python
from agent_sre.chaos.engine import Fault

# Static factory methods
latency = Fault.latency_injection("llm-provider", delay_ms=5000, rate=0.5)
error = Fault.error_injection("search-tool", error="internal_error")
timeout = Fault.timeout_injection("api-tool", delay_ms=30000)
```

#### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `fault_type` | `FaultType` | *required* | `LATENCY_INJECTION`, `ERROR_INJECTION`, or `TIMEOUT_INJECTION` |
| `target` | `str` | *required* | Tool name, agent ID, or provider name |
| `rate` | `float` | `1.0` | Fraction of calls affected (0.0–1.0) |
| `params` | `dict` | `{}` | Fault-specific parameters |

#### Static Factory Methods

| Method | Description |
|--------|-------------|
| `latency_injection(target, delay_ms=5000, rate=1.0)` | Inject latency |
| `error_injection(target, error="internal_error", rate=1.0)` | Inject errors |
| `timeout_injection(target, delay_ms=30000, rate=1.0)` | Inject timeouts |

---

### `AbortCondition`

**Module:** `agent_sre.chaos.engine`

Safety condition that stops a chaos experiment.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `metric` | `str` | *required* | Metric name to monitor |
| `threshold` | `float` | *required* | Threshold value |
| `comparator` | `str` | `"lte"` | `"lte"` (abort when ≤) or `"gte"` (abort when ≥) |

**Key method:** `should_abort(value: float) → bool`

---

### `ExperimentTemplate`

**Module:** `agent_sre.chaos.library`

Reusable chaos experiment template.

```python
from agent_sre.chaos.library import ChaosLibrary

library = ChaosLibrary()
templates = library.list_templates()
experiment = templates[0].instantiate(target_agent="agent-1")
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `instantiate(target_agent, **overrides)` | `ChaosExperiment` | Create experiment from template |
| `to_dict()` | `dict` | Serialize template |

---

### `ChaosLibrary`

**Module:** `agent_sre.chaos.library`

Registry of reusable experiment templates.

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `register_template(template)` | `None` | Register a template |
| `get_template(template_id)` | `ExperimentTemplate \| None` | Look up template |
| `list_templates()` | `list[ExperimentTemplate]` | List all templates |

---

## Circuit Breaker

### `CircuitBreaker`

**Module:** `agent_sre.cascade.circuit_breaker`

Per-agent circuit breaker that prevents cascading failures (OWASP ASI08). Transitions through CLOSED → OPEN → HALF_OPEN states.

```python
from agent_sre.cascade.circuit_breaker import CircuitBreaker, CircuitBreakerConfig

cb = CircuitBreaker(
    agent_id="agent-1",
    config=CircuitBreakerConfig(
        failure_threshold=5,
        recovery_timeout_seconds=30.0,
        half_open_max_calls=1,
    ),
)

# Wrap calls through the circuit breaker
result = cb.call(my_function, arg1, arg2, fallback="default")

# Or record manually
cb.record_success()
cb.record_failure()
print(cb.state)  # "CLOSED", "OPEN", or "HALF_OPEN"
```

#### Constructor

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `agent_id` | `str` | *required* | Agent identifier |
| `config` | `CircuitBreakerConfig \| None` | `None` | Configuration (uses defaults if omitted) |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `state` | `str` | Current state: `"CLOSED"`, `"OPEN"`, or `"HALF_OPEN"` |
| `failure_count` | `int` | Current consecutive failure count |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `call(func, *args, fallback=None, **kwargs)` | `T \| Any` | Execute function through the circuit breaker; uses fallback when open |
| `record_success()` | `None` | Record a successful call |
| `record_failure()` | `None` | Record a failed call |
| `reset()` | `None` | Manually reset to CLOSED state |

**Raises:** `CircuitOpenError` when circuit is open and no fallback is provided.

---

### `CircuitBreakerConfig`

**Module:** `agent_sre.cascade.circuit_breaker`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `failure_threshold` | `int` | `5` | Failures before opening circuit |
| `recovery_timeout_seconds` | `float` | `30.0` | Seconds before attempting recovery |
| `half_open_max_calls` | `int` | `1` | Trial calls allowed in HALF_OPEN |

---

### `CascadeDetector`

**Module:** `agent_sre.cascade.circuit_breaker`

Detects cascading failures across multiple agents by monitoring circuit breaker states.

```python
from agent_sre.cascade.circuit_breaker import CascadeDetector

detector = CascadeDetector(
    agents=["agent-1", "agent-2", "agent-3", "agent-4"],
    cascade_threshold=3,
)

breaker = detector.get_breaker("agent-1")
breaker.record_failure()

if detector.check_cascade():
    print("Cascade detected!", detector.get_affected_agents())
```

#### Constructor

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `agents` | `list[str]` | *required* | Agent IDs to monitor |
| `cascade_threshold` | `int` | `3` | Open circuits needed to declare cascade |
| `config` | `CircuitBreakerConfig \| None` | `None` | Shared config for all breakers |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `get_breaker(agent_id)` | `CircuitBreaker` | Get breaker for an agent |
| `check_cascade()` | `bool` | True if cascade detected |
| `get_affected_agents()` | `list[str]` | Agent IDs with open circuits |
| `reset_all()` | `None` | Reset all circuit breakers |

---

## Cost Management

### `CostGuard`

**Module:** `agent_sre.cost.guard`

Cost tracking, budgeting, anomaly detection, and auto-throttling for agents.

```python
from agent_sre.cost.guard import CostGuard

guard = CostGuard(
    per_task_limit=2.0,
    per_agent_daily_limit=100.0,
    org_monthly_budget=5000.0,
    auto_throttle=True,
)

# Check before running a task
allowed, reason = guard.check_task("agent-1", estimated_cost=0.50)
if allowed:
    # ... run task ...
    alerts = guard.record_cost("agent-1", "task-123", cost_usd=0.45)

print(guard.summary())
```

#### Constructor

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `per_task_limit` | `float` | `2.0` | Maximum cost per task (USD) |
| `per_agent_daily_limit` | `float` | `100.0` | Daily budget per agent (USD) |
| `org_monthly_budget` | `float` | `5000.0` | Organization monthly budget (USD) |
| `anomaly_detection` | `bool` | `True` | Enable Z-score anomaly detection |
| `auto_throttle` | `bool` | `True` | Auto-throttle/kill agents exceeding budgets |
| `kill_switch_threshold` | `float` | `0.95` | Budget utilization to kill agent |
| `alert_thresholds` | `list[float] \| None` | `[0.50, 0.75, 0.90, 0.95]` | Budget utilization alert thresholds |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `org_spent_month` | `float` | Total org spend this month |
| `org_remaining_month` | `float` | Remaining org budget |
| `alerts` | `list[CostAlert]` | All generated alerts |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `get_budget(agent_id)` | `AgentBudget` | Get or create budget for an agent |
| `check_task(agent_id, estimated_cost)` | `tuple[bool, str]` | Check if task is allowed (`allowed`, `reason`) |
| `record_cost(agent_id, task_id, cost_usd, breakdown)` | `list[CostAlert]` | Record cost and return triggered alerts |
| `reset_daily(agent_id)` | `None` | Reset daily budgets (call at start of day) |
| `summary()` | `dict` | Cost summary across all agents |

---

### `AgentBudget`

**Module:** `agent_sre.cost.guard`

Budget state for a single agent.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `agent_id` | `str` | *required* | Agent identifier |
| `daily_limit_usd` | `float` | `100.0` | Daily limit |
| `per_task_limit_usd` | `float` | `2.0` | Per-task limit |
| `spent_today_usd` | `float` | `0.0` | Amount spent today |
| `throttled` | `bool` | `False` | Whether agent is throttled |
| `killed` | `bool` | `False` | Whether agent is killed |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `remaining_today_usd` | `float` | Remaining daily budget |
| `utilization_percent` | `float` | Budget utilization percentage |
| `avg_cost_per_task` | `float` | Average cost per task today |

---

## Replay & Tracing

### `ProtocolTracer`

**Module:** `agent_sre.tracing`

Distributed tracing for A2A and MCP protocol calls with W3C Trace Context propagation.

```python
from agent_sre.tracing import ProtocolTracer

tracer = ProtocolTracer(agent_id="agent-1")

# Trace an A2A call
span = tracer.a2a_call(
    target_agent="agent-2",
    task="summarize",
    target_url="https://agent-2/api",
)
span.set_response(response={"result": "done"}, cost_usd=0.05)

# Trace an MCP tool call
span = tracer.mcp_call(
    server_id="search-server",
    tool="web_search",
    params={"query": "test"},
)

report = tracer.report()
```

#### Constructor

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `agent_id` | `str` | *required* | Agent identifier |
| `parent_context` | `TraceContext \| None` | `None` | Parent trace context for distributed tracing |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `a2a_call(target_agent, task, target_url, message_id)` | `ProtocolSpan` | Start an A2A protocol span |
| `mcp_call(server_id, tool, params, request_id)` | `ProtocolSpan` | Start an MCP protocol span |
| `inject(pspan)` | `dict` | Inject trace context into outgoing headers |
| `extract(headers)` | `TraceContext` | Extract trace context from incoming headers |
| `report()` | `TracingReport` | Generate tracing report |

---

### `TraceContext`

**Module:** `agent_sre.tracing`

W3C Trace Context for distributed tracing.

| Field | Type | Description |
|-------|------|-------------|
| `trace_id` | `str` | Unique trace identifier |
| `span_id` | `str` | Current span identifier |
| `parent_span_id` | `str \| None` | Parent span identifier |
| `sampled` | `bool` | Whether trace is sampled |
| `baggage` | `dict` | Propagated key-value pairs |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `to_traceparent()` | `str` | Serialize to W3C traceparent header |
| `from_traceparent(value)` | `TraceContext` | *(static)* Parse traceparent header |
| `child()` | `TraceContext` | Create child context |
| `to_headers()` | `dict` | Generate propagation headers |
| `from_headers(headers)` | `TraceContext` | *(static)* Extract from headers |

---

### `ReplayEngine`

**Module:** `agent_sre.replay.engine`

Replays recorded traces for regression testing and golden-trace validation.

```python
from agent_sre.replay.engine import ReplayEngine

engine = ReplayEngine(golden_traces=golden_suite.traces)
result = engine.replay_trace(recorded_trace)
suite_result = engine.run_suite(golden_suite)
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `replay_trace(trace)` | `ReplayResult` | Replay a single trace |
| `run_suite(suite)` | `GoldenSuiteResult` | Run all traces in a golden suite |

---

## Fleet Management

### `FleetManager`

**Module:** `agent_sre.fleet`

Manages a fleet of agents with heartbeats, health monitoring, and SLO tracking.

```python
from agent_sre.fleet import FleetManager

fleet = FleetManager(heartbeat_timeout=60.0, success_rate_threshold=0.95)

fleet.register("agent-1", tags={"team": "platform"})
fleet.heartbeat("agent-1")
fleet.record_event("agent-1", success=True, latency_ms=120, cost_usd=0.05)

health = fleet.agent_health("agent-1")
status = fleet.status()
print(status.to_dict())
```

#### Constructor

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `heartbeat_timeout` | `float` | *required* | Seconds before agent is unresponsive |
| `success_rate_threshold` | `float` | *required* | Success rate below which agent is degraded |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `register(agent_id, tags, slo, heartbeat_timeout)` | `AgentRegistration` | Register an agent |
| `heartbeat(agent_id)` | `bool` | Record heartbeat |
| `record_event(agent_id, success, latency_ms, cost_usd, metadata)` | `bool` | Record an agent event |
| `agent_health(agent_id)` | `AgentHealth \| None` | Get agent health status |
| `status()` | `FleetStatus` | Get fleet-wide status |

---

## Delivery

### `BlueGreenManager`

**Module:** `agent_sre.delivery.blue_green`

Blue-green deployment manager for agent version rollouts.

```python
from agent_sre.delivery.blue_green import BlueGreenManager

manager = BlueGreenManager()
env = manager.deploy(version="v2.0.0")
if manager.validate():
    manager.switch()
else:
    manager.rollback()
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `deploy(version)` | `AgentEnvironment` | Deploy a new version to inactive environment |
| `validate()` | `bool` | Validate deployment health |
| `switch()` | `None` | Switch traffic to new version |
| `rollback()` | `None` | Rollback to previous version |
| `get_active()` | `AgentEnvironment` | Get active environment |
| `get_inactive()` | `AgentEnvironment` | Get inactive environment |

---

## Framework Adapters

**Module:** `agent_sre.adapters`

Lightweight wrappers that instrument popular agent frameworks with SLO monitoring, cost tracking, and evaluation. All adapters are duck-typed — no framework imports required.

### `LangGraphAdapter`

```python
from agent_sre.adapters import LangGraphAdapter

adapter = LangGraphAdapter()
task = adapter.on_graph_start("my-graph")
adapter.on_node_start("retriever")
adapter.on_tool_call("search", error="")
adapter.on_llm_call(input_tokens=100, output_tokens=50, cost_usd=0.01)
adapter.on_node_end("retriever")
task = adapter.on_graph_end(success=True)

print(adapter.get_sli_snapshot())
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `on_graph_start(graph_name)` | `TaskRecord` | Start tracking a graph execution |
| `on_node_start(node_name)` | `None` | Record node start |
| `on_node_end(node_name, error)` | `None` | Record node end |
| `on_llm_call(input_tokens, output_tokens, cost_usd)` | `None` | Record LLM call |
| `on_tool_call(tool_name, error)` | `None` | Record tool call |
| `on_graph_end(success, error)` | `TaskRecord` | Finish tracking |
| `get_sli_snapshot()` | `dict` | Get SLI metrics snapshot |
| `clear()` | `None` | Reset all recorded data |

#### SLI Properties

| Property | Type | Description |
|----------|------|-------------|
| `task_success_rate` | `float` | Fraction of tasks succeeded |
| `total_cost_usd` | `float` | Total cost across all tasks |
| `avg_duration_ms` | `float` | Average task duration |
| `tool_accuracy` | `float` | Tool call success rate |

---

### `CrewAIAdapter`

```python
from agent_sre.adapters import CrewAIAdapter

adapter = CrewAIAdapter()
adapter.on_crew_start("research-crew", num_agents=3)
adapter.on_agent_task("researcher", "Find papers")
adapter.on_agent_complete("researcher", success=True, cost_usd=0.05)
adapter.on_crew_end(success=True)
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `on_crew_start(crew_name, num_agents)` | `TaskRecord` | Start crew run |
| `on_agent_task(agent_role, task_description)` | `None` | Record agent task |
| `on_agent_complete(agent_role, success, cost_usd)` | `None` | Record agent completion |
| `on_tool_use(tool_name, error)` | `None` | Record tool use |
| `on_crew_end(success, error)` | `TaskRecord` | Finish crew run |

---

### `AutoGenAdapter`

```python
from agent_sre.adapters import AutoGenAdapter

adapter = AutoGenAdapter()
adapter.on_conversation_start("user-proxy")
adapter.on_message("assistant", "Hello!")
adapter.on_function_call("search")
adapter.on_conversation_end(success=True)
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `on_conversation_start(initiator)` | `TaskRecord` | Start conversation |
| `on_message(sender, content)` | `None` | Record a message |
| `on_function_call(function_name, error)` | `None` | Record function call |
| `on_llm_call(input_tokens, output_tokens, cost_usd)` | `None` | Record LLM call |
| `on_conversation_end(success, error)` | `TaskRecord` | End conversation |

---

### `OpenAIAgentsAdapter`

```python
from agent_sre.adapters import OpenAIAgentsAdapter

adapter = OpenAIAgentsAdapter()
adapter.on_run_start("triage-agent")
adapter.on_tool_call("file_search")
adapter.on_handoff("triage-agent", "specialist-agent")
adapter.on_guardrail_check("content-filter", passed=True)
adapter.on_run_end(success=True)
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `on_run_start(agent_name)` | `TaskRecord` | Start run |
| `on_tool_call(tool_name, error)` | `None` | Record tool call |
| `on_handoff(from_agent, to_agent)` | `None` | Record agent handoff |
| `on_guardrail_check(guardrail_name, passed)` | `None` | Record guardrail check |
| `on_llm_call(input_tokens, output_tokens, cost_usd)` | `None` | Record LLM call |
| `on_run_end(success, error)` | `TaskRecord` | End run |

---

### `SemanticKernelAdapter`

```python
from agent_sre.adapters import SemanticKernelAdapter

adapter = SemanticKernelAdapter()
adapter.on_kernel_start("my-kernel")
adapter.on_plugin_call("WebSearchPlugin", "search")
adapter.on_function_result("WebSearchPlugin", "search", success=True)
adapter.on_kernel_end(success=True)
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `on_kernel_start(kernel_name)` | `TaskRecord` | Start kernel execution |
| `on_plugin_call(plugin_name, function_name, error)` | `None` | Record plugin call |
| `on_function_result(plugin_name, function_name, success, cost_usd)` | `None` | Record function result |
| `on_plan_step(step_name)` | `None` | Record planner step |
| `on_llm_call(input_tokens, output_tokens, cost_usd)` | `None` | Record LLM call |
| `on_kernel_end(success, error)` | `TaskRecord` | End kernel execution |

---

### `DifyAdapter`

```python
from agent_sre.adapters import DifyAdapter

adapter = DifyAdapter()
adapter.on_workflow_start("my-workflow")
adapter.on_node_start("llm-1", node_type="llm")
adapter.on_node_end("llm-1")
adapter.on_workflow_end(success=True)
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `on_workflow_start(workflow_name)` | `TaskRecord` | Start workflow |
| `on_node_start(node_id, node_type)` | `None` | Record node start |
| `on_node_end(node_id, error)` | `None` | Record node end |
| `on_tool_call(tool_name, error)` | `None` | Record tool call |
| `on_llm_call(input_tokens, output_tokens, cost_usd)` | `None` | Record LLM call |
| `on_http_request(url, status_code, error)` | `None` | Record HTTP request |
| `on_workflow_end(success, error)` | `TaskRecord` | End workflow |

---

## Integrations

### `AgentSRECallback` (LangChain)

**Module:** `agent_sre.integrations.langchain.callback`

LangChain callback handler for automatic SLI collection.

```python
from agent_sre.integrations.langchain.callback import AgentSRECallback

callback = AgentSRECallback(cost_per_1k_input=0.003, cost_per_1k_output=0.015)
# Pass to LangChain: chain.invoke(input, config={"callbacks": [callback]})

print(callback.task_success_rate)
print(callback.total_cost_usd)
print(callback.get_sli_snapshot())
```

---

### `AgentSRELlamaIndexHandler` (LlamaIndex)

**Module:** `agent_sre.integrations.llamaindex.handler`

LlamaIndex event handler for SLI collection.

```python
from agent_sre.integrations.llamaindex.handler import AgentSRELlamaIndexHandler

handler = AgentSRELlamaIndexHandler(cost_per_1k_input=0.003, cost_per_1k_output=0.015)
print(handler.get_sli_snapshot())
```

---

### `PrometheusExporter`

**Module:** `agent_sre.integrations.prometheus.exporter`

Exports SLO metrics in Prometheus exposition format.

```python
from agent_sre.integrations.prometheus.exporter import PrometheusExporter

exporter = PrometheusExporter()
exporter.export_slo(slo, agent_id="agent-1")
print(exporter.render())  # Prometheus text format
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `set_gauge(name, value, labels, help_text)` | `None` | Set a gauge metric |
| `inc_counter(name, value, labels, help_text)` | `None` | Increment a counter |
| `export_slo(slo, agent_id)` | `None` | Export SLO as Prometheus metrics |
| `render()` | `str` | Render in Prometheus text format |
| `clear()` | `None` | Clear all metrics |

---

### `DatadogExporter`

**Module:** `agent_sre.integrations.datadog.exporter`

Exports metrics and events to Datadog.

```python
from agent_sre.integrations.datadog.exporter import DatadogExporter

exporter = DatadogExporter(api_key="your-key")
exporter.export_slo(slo, agent_id="agent-1")
exporter.export_cost("agent-1", cost_usd=0.45)
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `submit_metric(metric_name, value, tags, metric_type)` | `DatadogMetric` | Submit a metric |
| `submit_event(title, text, alert_type, tags)` | `DatadogEvent` | Submit an event |
| `export_slo(slo, agent_id)` | `list[DatadogMetric]` | Export SLO metrics |
| `export_cost(agent_id, cost_usd, task_id, tags)` | `DatadogMetric` | Export cost metric |

---

### `LangfuseExporter`

**Module:** `agent_sre.integrations.langfuse.exporter`

Exports SLO scores and cost observations to Langfuse.

```python
from agent_sre.integrations.langfuse.exporter import LangfuseExporter

exporter = LangfuseExporter()
exporter.score_slo("trace-id", slo)
exporter.record_cost("trace-id", "agent-1", cost_usd=0.50)
```

---

### `LangSmithExporter`

**Module:** `agent_sre.integrations.langsmith.exporter`

Exports runs and SLO feedback to LangSmith.

```python
from agent_sre.integrations.langsmith.exporter import LangSmithExporter

exporter = LangSmithExporter(api_key="your-key", project_name="my-project")
run = exporter.create_run("my-chain", run_type="chain")
exporter.end_run(run.run_id, outputs={"result": "done"})
exporter.export_slo(slo, run_id=run.run_id)
```

---

### `PhoenixExporter` (Arize)

**Module:** `agent_sre.integrations.arize.exporter`

Exports SLO evaluations and incidents to Arize Phoenix.

```python
from agent_sre.integrations.arize.exporter import PhoenixExporter

exporter = PhoenixExporter()
exporter.export_slo_evaluation("my-slo", status="healthy", budget_remaining=0.95, burn_rate=0.5)
exporter.export_cost_record("agent-1", "task-1", cost_usd=0.30)
```

---

### `BraintrustExporter`

**Module:** `agent_sre.integrations.braintrust.exporter`

Exports evaluations and experiments to Braintrust.

---

### `WandBExporter`

**Module:** `agent_sre.integrations.wandb.exporter`

Exports runs and SLO metrics to Weights & Biases.

---

### `MLflowExporter`

**Module:** `agent_sre.integrations.mlflow.exporter`

Exports runs, SLO metrics, and artifacts to MLflow.

---

### `AgentOpsExporter`

**Module:** `agent_sre.integrations.agentops.exporter`

Exports sessions and events to AgentOps.

---

### `HeliconeHeaders`

**Module:** `agent_sre.integrations.helicone.headers`

Generates Helicone proxy headers for LLM cost tracking.

```python
from agent_sre.integrations.helicone.headers import HeliconeHeaders

helicone = HeliconeHeaders(api_key="your-key", agent_id="agent-1")
headers = helicone.get_headers(session_name="my-session")
# Add headers to your LLM API calls
```

---

### `DriftDetector` (MCP)

**Module:** `agent_sre.integrations.mcp`

Detects schema drift in MCP tool definitions between versions.

```python
from agent_sre.integrations.mcp import DriftDetector

detector = DriftDetector()
detector.set_baseline(baseline_snapshot)
report = detector.compare(current_snapshot)
print(report)  # Shows added, removed, and changed tools
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `set_baseline(snapshot)` | `None` | Set baseline tool snapshot |
| `get_baseline(server_id)` | `ToolSnapshot \| None` | Get baseline for a server |
| `compare(current)` | `DriftReport` | Compare current vs baseline |
| `update_baseline(snapshot)` | `None` | Update baseline |
