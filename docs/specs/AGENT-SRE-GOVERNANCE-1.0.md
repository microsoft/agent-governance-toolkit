<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Agent SRE Governance -- Version 1.0

> **Status:** Draft · **Date:** 2025-07-28 · **Authors:** Agent Governance Toolkit team
>
> This specification defines the Site Reliability Engineering (SRE)
> governance layer for autonomous AI agents, including Service Level
> Objectives, error budgets, circuit breakers, chaos engineering,
> alerting, incident detection, trace replay, artifact signing, and
> OpenTelemetry integration. All SDK implementations MUST conform to
> this specification.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in
[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) and
[RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174).

---

## Table of Contents

1.  [Introduction](#1-introduction)
2.  [Terminology](#2-terminology)
3.  [SLO Objectives](#3-slo-objectives)
4.  [Service Level Indicators](#4-service-level-indicators)
5.  [Error Budgets](#5-error-budgets)
6.  [Circuit Breakers](#6-circuit-breakers)
7.  [Chaos Engineering](#7-chaos-engineering)
8.  [Alerting](#8-alerting)
9.  [Persistent Alerting](#9-persistent-alerting)
10. [Replay and Capture](#10-replay-and-capture)
11. [Golden Traces](#11-golden-traces)
12. [Distributed Replay](#12-distributed-replay)
13. [Artifact Signing](#13-artifact-signing)
14. [Incident Detection](#14-incident-detection)
15. [Incident Response](#15-incident-response)
16. [OTEL Integration](#16-otel-integration)
17. [Failure Semantics](#17-failure-semantics)
18. [Security Considerations](#18-security-considerations)
19. [Conformance Requirements](#19-conformance-requirements)
20. [Worked Examples](#20-worked-examples)
21. [Edge Cases](#21-edge-cases)
22. [References](#22-references)

---

## 1. Introduction

### 1.1 Purpose

The Agent SRE governance layer brings Site Reliability Engineering
disciplines to autonomous AI agents. Just as traditional SRE applies
error budgets, SLOs, and incident management to software services,
Agent SRE applies these same principles to AI agent operations --
treating agent reliability as a measurable, enforceable, and
continuously improvable property.

### 1.2 Scope

This specification covers:

- **Service Level Objectives:** Defining what "reliable" means for an
  agent via composable SLIs and targets.
- **Error Budgets:** SRE-style reliability accounting with burn rate
  alerts and exhaustion actions.
- **Circuit Breakers:** Automatic agent isolation on sustained failure.
- **Chaos Engineering:** Fault injection and adversarial resilience
  testing for agent systems.
- **Alerting:** Multi-channel alert dispatch with deduplication and
  persistent storage.
- **Trace Replay:** Deterministic capture and replay of agent
  execution traces with golden-trace regression suites.
- **Artifact Signing:** Ed25519-based signing and verification of
  agent build artifacts and SBOMs.
- **Incident Detection:** Automated incident creation from reliability
  signals with severity classification and response actions.
- **OpenTelemetry Integration:** Semantic conventions, metric
  instruments, and span helpers for agent observability.

### 1.3 Relationship to Other Specifications

| Specification | Relationship |
| --- | --- |
| Agent Hypervisor Execution Control 1.0 | Circuit breaker state feeds the Hypervisor kill switch; SRE Witness required for Ring 0 |
| Agent OS Policy Engine 1.0 | PolicyCompliance SLI tracks adherence to policy decisions |
| AgentMesh Identity and Trust 1.0 | Agent DIDs used as identifiers in spans, alerts, and incidents; trust scores drive DelegationChainDepth SLI |

### 1.4 Design Principles

1. **Measure everything.** Every agent operation SHOULD produce SLI
   measurements that feed SLO evaluation.
2. **Fail closed.** All enforcement and detection components MUST deny
   or isolate on internal error, never silently permit.
3. **Budget-driven decisions.** Deployment, throttling, and circuit
   breaking decisions MUST be driven by error budget state, not ad-hoc
   thresholds.
4. **Deterministic replay.** Traces MUST capture sufficient detail to
   allow deterministic re-execution and regression detection.
5. **Append-only audit.** Trace hashes, alert histories, and incident
   records MUST be tamper-evident.

---

## 2. Terminology

| Term | Definition |
| --- | --- |
| **SLO** | Service Level Objective -- a target reliability level for an agent, combining one or more SLIs with an error budget. |
| **SLI** | Service Level Indicator -- a quantitative measure of one aspect of agent reliability (e.g., task success rate, tool call accuracy). |
| **Error Budget** | The allowable amount of unreliability over a measurement window, computed as `1 - SLO target`. |
| **Burn Rate** | The rate at which error budget is being consumed relative to the expected rate. A burn rate of 1.0 means consuming at exactly the allowed pace. |
| **Circuit Breaker** | A state machine that isolates a failing agent by transitioning from CLOSED (healthy) to OPEN (rejecting calls) upon sustained failure. |
| **Chaos Experiment** | A controlled fault injection exercise that tests agent resilience by introducing latency, errors, timeouts, or adversarial attacks. |
| **Blast Radius** | The fraction of agent traffic or operations affected by a chaos experiment, clamped to [0.0, 1.0]. |
| **Golden Trace** | A captured agent execution trace marked as the expected-correct reference for regression testing. |
| **Span** | A single unit of work in an agent trace (tool call, LLM inference, delegation, policy check). |
| **Trace** | A complete agent execution trace containing all spans from a single task execution. |
| **Content Hash** | A SHA-256 digest of trace metadata used for content-addressable deduplication. |
| **Artifact Signer** | An Ed25519 key pair used to sign agent build artifacts and SBOMs. |
| **SignatureBundle** | A portable envelope containing an Ed25519 signature, public key, artifact hash, and timestamp. |
| **Incident** | A detected reliability event requiring investigation, classified by severity (P1--P4). |
| **Signal** | A reliability observation (SLO breach, cost anomaly, etc.) that MAY trigger incident creation. |
| **Dedup Window** | The time period during which duplicate alerts or signals are suppressed to prevent alert storms. |
| **OTEL** | OpenTelemetry -- the observability framework used for metrics, traces, and spans. |

---

## 3. SLO Objectives

### 3.1 SLO Model

An SLO MUST combine one or more SLIs with an error budget to define
agent reliability. **[Pure Specification]**

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `name` | string | Yes | -- | Non-empty, unique within a deployment |
| `indicators` | list\[SLI\] | Yes | -- | At least one SLI |
| `error_budget` | ErrorBudget | No | auto-computed | If omitted, derived from strictest indicator |
| `description` | string | No | `""` | Free-form text |
| `labels` | dict\[str, str\] | No | `{}` | Arbitrary key-value metadata |
| `alert_manager` | AlertManager | No | `None` | If set, alerts fire on status transitions |
| `agent_id` | string | No | `""` | DID or identifier of the owning agent |

### 3.2 SLOStatus Enum

Implementations MUST define the following SLO health states:

| Value | Meaning |
| --- | --- |
| `HEALTHY` | Within budget, no alerts firing |
| `WARNING` | Burn rate elevated, warning-level alert firing |
| `CRITICAL` | Burn rate critical, budget at risk |
| `EXHAUSTED` | Error budget fully consumed |
| `UNKNOWN` | Insufficient data to evaluate |

**[Pure Specification]**

### 3.3 Status Severity Ordering

Status values MUST be totally ordered for comparison:

```
HEALTHY (0) < UNKNOWN (1) < WARNING (2) < CRITICAL (3) < EXHAUSTED (4)
```

Alert transitions MUST fire only when severity increases (worsens) or
when the SLO recovers to HEALTHY from a non-HEALTHY state.
**[Pure Specification]**

### 3.4 SLO Evaluation

The `evaluate()` method MUST determine status using the following
precedence:

1. If `error_budget.is_exhausted` is true --> `EXHAUSTED`
2. If any firing alert has severity `"critical"` --> `CRITICAL`
3. If any firing alert has severity `"warning"` --> `WARNING`
4. If no indicator has a non-None `current_value()` --> `UNKNOWN`
5. Otherwise --> `HEALTHY`

**[Pure Specification]**

### 3.5 ExhaustionAction Enum

When the error budget is fully consumed, the SLO engine MUST support
the following exhaustion actions:

| Value | Meaning |
| --- | --- |
| `ALERT` | Send an alert only |
| `FREEZE_DEPLOYMENTS` | Halt new agent deployments |
| `CIRCUIT_BREAK` | Open the agent's circuit breaker |
| `THROTTLE` | Reduce the agent's request rate |

**[Pure Specification]**

### 3.6 Auto-Budget Derivation

When no explicit ErrorBudget is provided, the SLO MUST derive the
total budget from the strictest (lowest-target) indicator:

```
error_budget.total = 1.0 - min(sli.target for sli in indicators)
```

**[Default Implementation]**

---

## 4. Service Level Indicators

### 4.1 SLI Base Class

All SLIs MUST extend a common base providing:

| Method | Description |
| --- | --- |
| `collect()` | Collect a new measurement (abstract) |
| `record(value, metadata)` | Record a measurement value with timestamp |
| `values_in_window()` | Return measurements within the configured TimeWindow |
| `current_value()` | Aggregated value within the window (mean by default) |
| `compliance()` | Fraction of measurements meeting the target |
| `to_dict()` | Serialize to dictionary |

**[Pure Specification]**

### 4.2 TimeWindow Enum

Implementations MUST support the following standard time windows:

| Value | Label | Seconds |
| --- | --- | --- |
| `HOUR_1` | `"1h"` | 3 600 |
| `HOUR_6` | `"6h"` | 21 600 |
| `DAY_1` | `"24h"` | 86 400 |
| `DAY_7` | `"7d"` | 604 800 |
| `DAY_30` | `"30d"` | 2 592 000 |

**[Pure Specification]**

### 4.3 SLIValue Record

Each measurement MUST be captured as an SLIValue:

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `name` | string | Yes | -- | SLI name |
| `value` | float | Yes | -- | Measured value |
| `timestamp` | float | No | `time.time()` | UNIX epoch |
| `metadata` | dict | No | `{}` | Includes `target` for `is_good` check |

The `is_good` property MUST return `True` when `value >= target`
(for rate-based SLIs). Inverted SLIs (lower-is-better) MUST override
`compliance()` to use `value <= target`. **[Pure Specification]**

### 4.4 Built-in SLI Types

Implementations MUST provide the following SLI types with their
default targets:

| SLI Type | Metric Name | Default Target | Default Window | Semantics |
| --- | --- | --- | --- | --- |
| `TaskSuccessRate` | `task_success_rate` | 0.995 (99.5%) | 30d | Fraction of tasks completed successfully |
| `ToolCallAccuracy` | `tool_call_accuracy` | 0.999 (99.9%) | 7d | Fraction of tool calls selecting the correct tool |
| `ResponseLatency` | `response_latency_p{N}` | 5000 ms | 1h | Response latency at a configurable percentile (default p95) |
| `CostPerTask` | `cost_per_task` | $0.50 | 24h | Average cost per task in USD |
| `PolicyCompliance` | `policy_compliance` | 1.0 (100%) | 24h | Adherence to Agent OS governance policies |
| `DelegationChainDepth` | `scope_chain_depth` | 3 (max depth) | 24h | Maximum allowed delegation chain depth; lower is better |
| `HallucinationRate` | `hallucination_rate` | 0.05 (5%) | 24h | Hallucination rate via LLM-as-judge; lower is better |
| `CalibrationDeltaSLI` | `calibration_delta` | 0.05 | 30d | Gap between predicted confidence and actual success rate; lower is better |

**[Default Implementation]**

### 4.5 Inverted SLIs

For SLIs where lower values indicate better performance
(`DelegationChainDepth`, `HallucinationRate`, `CalibrationDeltaSLI`),
the `compliance()` method MUST return the fraction of measurements
where `value <= target`, not `value >= target`.
**[Pure Specification]**

### 4.6 ResponseLatency Percentile

The `ResponseLatency` SLI MUST compute `current_value()` as the
configured percentile of recorded latencies, NOT as the mean.
The percentile index MUST be computed as:

```
idx = min(int(len(sorted_values) * percentile), len(sorted_values) - 1)
```

**[Pure Specification]**

### 4.7 CalibrationDeltaSLI Aggregation

The `CalibrationDeltaSLI` MUST track a running aggregate
`|mean_predicted_confidence - mean_actual_success_rate|` across all
predictions. The `current_value()` method MUST return the most recent
aggregate delta (the last recorded value in the window), NOT the mean
of all window measurements. **[Pure Specification]**

### 4.8 SLI Registry

Implementations SHOULD provide an `SLIRegistry` for discovering and
managing SLI types. The registry MUST auto-register all built-in SLI
types. Custom SLI types MAY be registered at runtime.
**[Default Implementation]**

---

## 5. Error Budgets

### 5.1 Error Budget Model

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `total` | float | No | 0.0 | Set from SLO target: `1.0 - target` |
| `consumed` | float | No | 0.0 | Incremented on bad events |
| `window_seconds` | int | No | 2 592 000 (30d) | Measurement window |
| `burn_rate_alert` | float | No | 2.0 | Warning threshold multiplier |
| `burn_rate_critical` | float | No | 10.0 | Critical threshold multiplier |
| `exhaustion_action` | ExhaustionAction | No | `ALERT` | Action on exhaustion |
| `max_events` | int | No | 100 000 | Bounded deque size |

**[Default Implementation]**

### 5.2 Budget Computation

Remaining budget MUST be computed as:

```
remaining = max(0.0, 1.0 - (consumed / total))
```

If `total <= 0`, remaining MUST be `0.0`.
The budget is exhausted when `consumed >= total`.
**[Pure Specification]**

### 5.3 Burn Rate Computation

Burn rate within a time window MUST be computed as:

```
actual_error_rate = errors_in_window / total_events_in_window
allowed_error_rate = budget_total / window_seconds
burn_rate = actual_error_rate / allowed_error_rate
```

A burn rate of 1.0 means consuming budget at exactly the expected
rate. A burn rate > 1.0 indicates faster-than-expected consumption.

If `total_events_in_window == 0`, burn rate MUST be `0.0`.
If `allowed_error_rate <= 0` and errors exist, burn rate MUST be
`+infinity`. **[Pure Specification]**

### 5.4 Event Recording

Events MUST be stored in a bounded buffer (deque with `maxlen`).
When the buffer is full, the oldest events MUST be silently evicted.
Each event records `{"good": bool, "timestamp": monotonic_clock}`.
**[Default Implementation]**

### 5.5 BurnRateAlert Model

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `name` | string | Yes | -- | Alert name |
| `rate` | float | Yes | -- | Burn rate threshold |
| `severity` | string | No | `"warning"` | `"warning"`, `"critical"`, or `"page"` |
| `window_seconds` | int | No | 3 600 (1h) | Fast-burn detection window |

An alert MUST fire when `current_burn_rate >= rate`.
**[Pure Specification]**

### 5.6 Default Alerts

Each ErrorBudget MUST produce two default burn rate alerts:

| Alert | Rate | Severity | Window |
| --- | --- | --- | --- |
| `burn_rate_warning` | `burn_rate_alert` (default 2.0) | warning | 86 400s (24h) |
| `burn_rate_critical` | `burn_rate_critical` (default 10.0) | critical | 86 400s (24h) |

**[Default Implementation]**

---

## 6. Circuit Breakers

### 6.1 CircuitState Enum

Implementations MUST define the following circuit breaker states:

| Value | Meaning |
| --- | --- |
| `CLOSED` | Normal operation -- track failures |
| `OPEN` | Agent isolated -- reject all calls |
| `HALF_OPEN` | Reserved for future auto-recovery; NOT entered in Public Preview |

> **Public Preview Note:** The `HALF_OPEN` state is wired through the
> enum, config knobs (`success_threshold`, `half_open_max_calls`), and
> registry summaries for forward compatibility. However, **no code path
> transitions to HALF_OPEN** in Public Preview. Recovery MUST be
> performed manually via `force_close()` or `reset()`.

**[Pure Specification]**

### 6.2 CircuitBreakerConfig

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `failure_threshold` | int | No | 5 | Consecutive failures before OPEN |
| `success_threshold` | int | No | 3 | Reserved: successes in HALF_OPEN before CLOSED |
| `timeout_seconds` | float | No | 60.0 | Reserved: seconds in OPEN before HALF_OPEN |
| `half_open_max_calls` | int | No | 3 | Reserved: max test calls in HALF_OPEN |

**[Default Implementation]**

### 6.3 State Transitions

The circuit breaker MUST implement the following transition rules:

```
CLOSED -> OPEN:    failure_count >= failure_threshold
OPEN -> CLOSED:    force_close() or reset() (manual only in Public Preview)
```

When transitioning to OPEN, the breaker MUST:
1. Record the transition time (`opened_at`).
2. Increment `total_trips`.
3. Emit a `CircuitEvent` with `from_state`, `to_state`, and `reason`.

When transitioning to CLOSED, the breaker MUST:
1. Reset `failure_count`, `success_count`, and `half_open_calls` to 0.
2. Clear `opened_at`.

**[Pure Specification]**

### 6.4 Success and Failure Recording

- On `record_success()` while CLOSED: decrement `failure_count` by 1
  (floor at 0).
- On `record_failure()` while CLOSED: increment `failure_count` by 1;
  if `failure_count >= failure_threshold`, transition to OPEN.
- On `record_failure()` or `record_success()` while OPEN: no state
  change (calls are rejected).

**[Pure Specification]**

### 6.5 Availability Check

`is_available` MUST return `True` only when `state == CLOSED`.
Any component querying whether an agent can accept calls MUST use
this property. **[Pure Specification]**

### 6.6 CircuitBreakerRegistry

Implementations SHOULD provide a `CircuitBreakerRegistry` for
managing breakers across agents. The registry MUST:

- Lazily create breakers on first access via `get(agent_id)`.
- Expose `open_breakers` listing all non-CLOSED breakers.
- Produce a `summary()` with counts of OPEN and HALF_OPEN circuits.

**[Default Implementation]**

### 6.7 Event History

Each state transition MUST be recorded as a `CircuitEvent`:

| Field | Type | Description |
| --- | --- | --- |
| `from_state` | CircuitState | Previous state |
| `to_state` | CircuitState | New state |
| `reason` | string | Human-readable cause |
| `timestamp` | float | UNIX epoch of the transition |

The `to_dict()` serializer MUST include the last 10 events.
**[Pure Specification]**

---

## 7. Chaos Engineering

### 7.1 FaultType Enum

Implementations MUST support the following fault types:

**Infrastructure faults:**

| Value | Description |
| --- | --- |
| `LATENCY_INJECTION` | Add artificial latency to a target |
| `ERROR_INJECTION` | Force error responses from a target |
| `TIMEOUT_INJECTION` | Force timeout on a target |

**Adversarial faults:**

| Value | Description |
| --- | --- |
| `PROMPT_INJECTION` | Test prompt injection resilience |
| `POLICY_BYPASS` | Attempt to bypass governance policies |
| `PRIVILEGE_ESCALATION` | Attempt privilege escalation |
| `DATA_EXFILTRATION` | Simulate data exfiltration attempts |
| `TOOL_ABUSE` | Simulate abuse of dangerous tools |
| `IDENTITY_SPOOFING` | Simulate identity spoofing attacks |

**Behavioral faults:**

| Value | Description |
| --- | --- |
| `DEADLOCK_INJECTION` | Simulate circular dependency deadlock between agents |
| `CONTRADICTORY_INSTRUCTION` | Inject conflicting directives to test conflict resolution |
| `TRUST_PERTURBATION` | Dynamically change an agent's trust score during execution |

**[Pure Specification]**

### 7.2 ExperimentState Enum

| Value | Meaning |
| --- | --- |
| `PENDING` | Experiment created but not started |
| `RUNNING` | Experiment actively injecting faults |
| `COMPLETED` | Experiment finished normally |
| `ABORTED` | Experiment stopped by abort condition or operator |
| `FAILED` | Experiment encountered an internal error |

**[Pure Specification]**

### 7.3 Fault Model

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `fault_type` | FaultType | Yes | -- | One of the defined fault types |
| `target` | string | Yes | -- | Tool name, agent ID, or provider name |
| `rate` | float | No | 1.0 | Fraction of calls affected, [0.0, 1.0] |
| `params` | dict | No | `{}` | Fault-specific parameters |

Implementations MUST provide factory methods for common fault
configurations (e.g., `Fault.latency_injection(target, delay_ms)`,
`Fault.prompt_injection(target, technique)`).
**[Default Implementation]**

### 7.4 ChaosExperiment Model

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `experiment_id` | string | Auto | UUID hex[:12] | Unique experiment identifier |
| `name` | string | Yes | -- | Human-readable experiment name |
| `target_agent` | string | Yes | -- | Agent under test |
| `faults` | list\[Fault\] | Yes | -- | At least one fault |
| `duration_seconds` | int | No | 1800 (30 min) | Maximum experiment duration |
| `abort_conditions` | list\[AbortCondition\] | No | `[]` | Safety abort rules |
| `blast_radius` | float | No | 1.0 | Fraction of traffic affected |
| `description` | string | No | `""` | Free-form description |

**[Default Implementation]**

### 7.5 Blast Radius Clamping

The `blast_radius` MUST be clamped to [0.0, 1.0] at construction:

```
blast_radius = min(max(blast_radius, 0.0), 1.0)
```

**[Pure Specification]**

### 7.6 Abort Conditions

An `AbortCondition` defines a safety boundary:

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `metric` | string | Yes | -- | Name of the metric to monitor |
| `threshold` | float | Yes | -- | Threshold value |
| `comparator` | string | No | `"lte"` | `"lte"` (abort when <=) or `"gte"` (abort when >=) |

At each evaluation interval, the experiment MUST check all abort
conditions. If any condition triggers, the experiment MUST transition
to `ABORTED` with the reason recorded. **[Pure Specification]**

### 7.7 Resilience Scoring

After an experiment completes, a `ResilienceScore` MUST be computed:

| Field | Type | Description |
| --- | --- | --- |
| `overall` | float | 0--100 score, clamped |
| `passed` | bool | True if experiment success rate >= 90% of baseline |

The resilience score MUST be computed as:

```
passed = experiment_success_rate >= (baseline_success_rate * 0.9)
overall = clamp((experiment_success_rate / baseline_success_rate) * 100, 0, 100)
```

**[Default Implementation]**

### 7.8 Experiment Lifecycle

1. `start()`: Set state to RUNNING, record `started_at`.
2. `inject_fault(fault)`: Record a `FaultInjectionEvent`.
3. `check_abort(metrics)`: Evaluate abort conditions; abort if triggered.
4. `complete(resilience)`: Set state to COMPLETED, record `ended_at`.
5. `abort(reason)`: Set state to ABORTED, record `ended_at` and reason.

**[Pure Specification]**

---

## 8. Alerting

### 8.1 AlertChannel Enum

Implementations MUST support the following alert channel types:

| Value | Description |
| --- | --- |
| `SLACK` | Slack incoming webhook |
| `PAGERDUTY` | PagerDuty Events API v2 |
| `GENERIC_WEBHOOK` | Generic JSON webhook POST |
| `CALLBACK` | In-process callback function (for testing) |
| `OPSGENIE` | OpsGenie Alert API |
| `TEAMS` | Microsoft Teams incoming webhook (Adaptive Card) |

**[Pure Specification]**

### 8.2 AlertSeverity Enum

| Value | Meaning |
| --- | --- |
| `INFO` | Informational, no action required |
| `WARNING` | Elevated risk, attention recommended |
| `CRITICAL` | Immediate action required |
| `RESOLVED` | Previously firing alert has cleared |

**[Pure Specification]**

### 8.3 Alert Model

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `title` | string | Yes | -- | Alert title |
| `message` | string | Yes | -- | Alert body |
| `severity` | AlertSeverity | No | `WARNING` | Severity level |
| `source` | string | No | `"agent-sre"` | Alert source |
| `agent_id` | string | No | `""` | Affected agent |
| `slo_name` | string | No | `""` | Related SLO |
| `metadata` | dict | No | `{}` | Arbitrary key-value data |
| `timestamp` | float | No | `time.time()` | UNIX epoch |
| `dedup_key` | string | No | `""` | Deduplication key |

**[Pure Specification]**

### 8.4 ChannelConfig Model

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `channel_type` | AlertChannel | Yes | -- | Channel type |
| `name` | string | Yes | -- | Unique channel name |
| `url` | string | No | `""` | Webhook URL |
| `token` | string | No | `""` | Auth token (e.g., PagerDuty routing key) |
| `callback` | callable | No | `None` | In-process callback for CALLBACK type |
| `min_severity` | AlertSeverity | No | `WARNING` | Minimum severity to dispatch |
| `enabled` | bool | No | `True` | Whether channel is active |

### 8.5 AlertManager

The `AlertManager` MUST:

1. Maintain a set of named channels.
2. Dispatch alerts to all matching channels (enabled, meets
   `min_severity`).
3. Deduplicate alerts by `dedup_key` within a configurable window.
4. Clear dedup cache when a RESOLVED alert arrives for a given key.

**[Pure Specification]**

### 8.6 Deduplication

The default dedup window MUST be **300 seconds** (5 minutes).

When an alert has a `dedup_key`:
- If a non-RESOLVED alert with the same key was sent within the dedup
  window, the alert MUST be suppressed and `suppressed_count` incremented.
- If the alert severity is RESOLVED, the dedup cache entry for that
  key MUST be cleared (to allow re-triggering).

**[Default Implementation]**

### 8.7 Channel-Specific Formatters

Implementations MUST provide the following formatters:

| Channel | Format |
| --- | --- |
| SLACK | Block Kit with severity emoji, agent/SLO fields |
| PAGERDUTY | Events API v2 with `event_action`, `dedup_key`, severity mapping |
| GENERIC_WEBHOOK | Raw `alert.to_dict()` JSON |
| OPSGENIE | Alert API with priority mapping (INFO->P5, WARNING->P3, CRITICAL->P1) |
| TEAMS | Adaptive Card v1.4 with severity color, FactSet for agent/SLO |

**[Default Implementation]**

### 8.8 Delivery Result

Each alert delivery attempt MUST produce a `DeliveryResult`:

| Field | Type | Description |
| --- | --- | --- |
| `channel_name` | string | Which channel was targeted |
| `success` | bool | Whether delivery succeeded |
| `status_code` | int | HTTP status code (0 if N/A) |
| `error` | string | Error message on failure |
| `timestamp` | float | Delivery attempt time |

**[Pure Specification]**

---

## 9. Persistent Alerting

### 9.1 PersistentAlertManager

Implementations SHOULD provide a `PersistentAlertManager` that
extends `AlertManager` with SQLite-backed alert history for audit
trail and post-incident analysis. **[Default Implementation]**

### 9.2 Database Schema

The persistent alert store MUST use the following schema:

**`alerts` table:**

| Column | Type | Description |
| --- | --- | --- |
| `id` | INTEGER PRIMARY KEY | Auto-increment |
| `title` | TEXT | Alert title |
| `message` | TEXT | Alert body |
| `severity` | TEXT | Severity value |
| `source` | TEXT | Alert source |
| `agent_id` | TEXT | Agent identifier |
| `slo_name` | TEXT | Related SLO name |
| `dedup_key` | TEXT | Dedup key |
| `metadata` | TEXT | JSON-serialized metadata |
| `timestamp` | REAL | UNIX epoch |

**`delivery_results` table:**

| Column | Type | Description |
| --- | --- | --- |
| `id` | INTEGER PRIMARY KEY | Auto-increment |
| `alert_id` | INTEGER | Foreign key to alerts |
| `channel_name` | TEXT | Channel name |
| `success` | INTEGER | 1 for success, 0 for failure |
| `status_code` | INTEGER | HTTP status code |
| `error` | TEXT | Error message |
| `timestamp` | REAL | UNIX epoch |

### 9.3 Persistence Behavior

- Alerts MUST be persisted after dispatch (or on unsuppressed
  no-dedup-key alerts).
- Delivery results MUST be linked to their parent alert via
  `alert_id`.
- The `query_alerts()` method MUST support filtering by `agent_id`
  and `severity` with a configurable `limit` (default 100).

**[Default Implementation]**

---

## 10. Replay and Capture

### 10.1 SpanKind Enum

Implementations MUST support the following span kinds:

| Value | Description |
| --- | --- |
| `AGENT_TASK` | A top-level agent task execution |
| `TOOL_CALL` | A tool invocation by the agent |
| `LLM_INFERENCE` | An LLM API call |
| `DELEGATION` | Delegation to another agent |
| `POLICY_CHECK` | A governance policy evaluation |
| `INTERNAL` | Internal processing step |

**[Pure Specification]**

### 10.2 SpanStatus Enum

| Value | Description |
| --- | --- |
| `OK` | Span completed successfully |
| `ERROR` | Span completed with an error |
| `TIMEOUT` | Span exceeded its time limit |

**[Pure Specification]**

### 10.3 Span Model

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `span_id` | string | Auto | UUID hex[:16] | Unique span identifier |
| `parent_id` | string or null | No | `None` | Parent span for tree structure |
| `trace_id` | string | No | `""` | Owning trace |
| `kind` | SpanKind | No | `INTERNAL` | Span type |
| `name` | string | No | `""` | Human-readable name |
| `start_time` | float | Auto | `time.time()` | UNIX epoch |
| `end_time` | float or null | No | `None` | Set on `finish()` |
| `status` | SpanStatus | No | `OK` | Outcome |
| `attributes` | dict | No | `{}` | Arbitrary key-value attributes |
| `input_data` | dict | No | `{}` | Captured input for replay |
| `output_data` | dict | No | `{}` | Captured output for replay |
| `error` | string or null | No | `None` | Error message if applicable |
| `cost_usd` | float | No | 0.0 | Cost in USD |

### 10.4 Span Finish Semantics

Calling `finish()` MUST:
1. Set `end_time` to `time.time()`.
2. If `error` is provided, set `status` to `ERROR`.
3. Record `output_data` and `cost_usd`.

The `duration_ms` property MUST return
`(end_time - start_time) * 1000` or `None` if `end_time` is not set.
**[Pure Specification]**

### 10.5 Trace Model

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `trace_id` | string | Auto | UUID hex (32 chars) | Unique trace identifier |
| `agent_id` | string | No | `""` | Owning agent DID |
| `task_input` | string | No | `""` | Task prompt or input |
| `task_output` | string or null | No | `None` | Final output |
| `spans` | list\[Span\] | No | `[]` | Ordered span list |
| `start_time` | float | Auto | `time.time()` | UNIX epoch |
| `end_time` | float or null | No | `None` | Completion time |
| `metadata` | dict | No | `{}` | Arbitrary metadata |
| `total_cost_usd` | float | No | 0.0 | Sum of span costs |
| `success` | bool or null | No | `None` | Overall success |

### 10.6 Content Hash Chain

The Trace `content_hash` MUST be computed as:

```
SHA-256(json_dumps({"agent_id": ..., "task_input": ..., "trace_id": ...}, sort_keys=True))[:16]
```

This hash enables content-addressable deduplication across trace
stores. **[Pure Specification]**

### 10.7 TraceCapture Context Manager

The `TraceCapture` class MUST provide a context manager that:

1. Creates a new `Trace` on `__enter__`.
2. Supports `start_span()` which auto-parents to the current span
   stack.
3. Supports `end_span()` which pops and finishes the current span.
4. Calls `trace.finish()` on `__exit__`, setting `success` based on
   whether an exception occurred.

**[Pure Specification]**

### 10.8 TraceStore

The `TraceStore` MUST provide persistent storage with:

- `save(trace, redact)`: Save a trace to disk as JSON. If `redact` is
  true, sensitive data (passwords, emails, phone numbers) MUST be
  replaced with redaction tokens (`[REDACTED]`, `[EMAIL_REDACTED]`,
  `[PHONE_REDACTED]`).
- `load(trace_id)`: Load a trace by ID.
- `list_traces(agent_id, limit)`: List stored traces with optional
  filtering.
- `delete(trace_id)`: Delete a trace.

**[Default Implementation]**

### 10.9 Path Traversal Prevention

The TraceStore MUST reject trace IDs containing path separators
(`/`, `\`) or parent-directory components (`..`). The resolved file
path MUST start with the storage directory. Violations MUST raise
`ValueError`. **[Pure Specification]**

### 10.10 PII Redaction

Before persisting, traces MUST be redacted using pattern-based rules:

| Pattern | Replacement |
| --- | --- |
| `password`, `secret`, `token`, `api_key`, `authorization` JSON values | `[REDACTED]` |
| Email addresses | `[EMAIL_REDACTED]` |
| Phone numbers (US format) | `[PHONE_REDACTED]` |

**[Default Implementation]**

---

## 11. Golden Traces

### 11.1 GoldenTrace Model

A golden trace represents the expected-correct reference for
regression testing:

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `id` | string | Auto | UUID hex[:16] | Unique identifier |
| `name` | string | Yes | -- | Human-readable name |
| `description` | string | No | `""` | Free-form description |
| `trace` | dict | Yes | -- | `Trace.to_dict()` serialized form |
| `expected_output` | string | Yes | -- | Expected task output |
| `tolerance` | float | No | 0.0 | Allowed deviation threshold |
| `labels` | list\[string\] | No | `[]` | Categorization labels |
| `created_at` | string | Auto | ISO-8601 UTC | Creation timestamp |
| `source` | TraceSource | No | `PRODUCTION` | `PRODUCTION` or `SYNTHETIC` |

**[Default Implementation]**

### 11.2 GoldenTraceSuite

A named collection of golden traces with a CI pass threshold:

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `name` | string | Yes | -- | Suite name |
| `traces` | list\[GoldenTrace\] | No | `[]` | Golden traces |
| `pass_threshold` | float | No | 0.95 | Minimum pass rate for CI |

Suites MUST support YAML serialization via `to_yaml()` and
`from_yaml()`. YAML loading MUST use `yaml.safe_load()`.
**[Default Implementation]**

### 11.3 Comparison Engine

The replay engine MUST support comparing a replayed trace against a
golden trace, producing `TraceDiff` records of type:

| DiffType | Description |
| --- | --- |
| `OUTPUT_MISMATCH` | Task output differs from golden |
| `TOOL_SEQUENCE_DIFF` | Tool call sequence diverged |
| `MISSING_SPAN` | Expected span not found in replay |
| `EXTRA_SPAN` | Unexpected span appeared in replay |
| `STATUS_CHANGE` | Span status differs (e.g., OK vs ERROR) |
| `COST_CHANGE` | Cost exceeded tolerance |
| `LATENCY_CHANGE` | Latency exceeded tolerance |

**[Pure Specification]**

### 11.4 GoldenSuiteResult

Running a golden-trace suite MUST produce an aggregate result:

| Field | Type | Description |
| --- | --- | --- |
| `suite_name` | string | Suite name |
| `total` | int | Total traces in suite |
| `passed` | int | Traces that matched |
| `failed` | int | Traces that diverged |
| `pass_rate` | float | `passed / total` |
| `results` | list\[GoldenTraceResult\] | Per-trace results |
| `ci_passed` | bool | `pass_rate >= pass_threshold` |

**[Pure Specification]**

---

## 12. Distributed Replay

### 12.1 Purpose

Distributed replay extends trace replay to multi-agent scenarios,
reconstructing the full execution flow across delegation boundaries.
**[Pure Specification]**

### 12.2 DistributedReplayEngine

The engine MUST support:

- `add_agent_trace(agent_id, trace, role)`: Register a trace for an
  agent with a role (`initiator`, `responder`, `delegate`).
- `link_delegation(from_agent, to_agent, from_span_id, to_trace_id)`:
  Manually link a delegation span to the delegated agent's trace.
- `discover_links()`: Auto-discover delegation links by scanning
  traces for `DELEGATION` spans and matching
  `output_data["delegated_trace_id"]` to registered agent traces.
- `replay()`: Replay all registered traces in execution order and
  check cross-agent consistency.
- `execution_order()`: Topologically sort agents by delegation links.

**[Pure Specification]**

### 12.3 MeshReplayState Enum

| Value | Meaning |
| --- | --- |
| `PENDING` | Replay not started |
| `RUNNING` | Replay in progress |
| `COMPLETED` | All agents replayed successfully |
| `FAILED` | No agents could be replayed |
| `PARTIAL` | Some agents replayed, some failed |

**[Pure Specification]**

### 12.4 Cross-Agent Consistency

After per-agent replay, the engine MUST verify delegation boundaries:

- For each delegation link, check that the delegation span exists in
  the source agent's trace.
- Check that the delegated trace succeeded.
- Record `TraceDiff` entries of type `MISSING_SPAN` or
  `STATUS_CHANGE` for any inconsistencies.

**[Pure Specification]**

### 12.5 DistributedReplayResult

| Field | Type | Description |
| --- | --- | --- |
| `session_id` | string | Unique replay session ID |
| `state` | MeshReplayState | Replay outcome |
| `agent_results` | dict\[str, ReplayResult\] | Per-agent replay results |
| `cross_agent_diffs` | list\[TraceDiff\] | Cross-boundary inconsistencies |
| `agents_completed` | int | Number of agents successfully replayed |
| `agents_total` | int | Total agents registered |

The `success` property MUST return `True` only when
`state == COMPLETED` and `all_diffs` is empty.
**[Pure Specification]**

---

## 13. Artifact Signing

### 13.1 Signing Algorithm

Implementations MUST use **Ed25519** for artifact signing. Only
Ed25519 private keys are accepted; loading a non-Ed25519 key MUST
raise `TypeError`. **[Pure Specification]**

### 13.2 ArtifactSigner

The `ArtifactSigner` MUST support:

- **Key generation:** If no `private_key_path` is provided, generate
  an ephemeral Ed25519 key pair.
- **Key loading:** If `private_key_path` is provided, load the PEM
  file. Path traversal (`..` in path components) MUST raise
  `ValueError`.
- `sign_artifact(artifact_path)`: Sign a file and return a
  `SignatureBundle`.
- `verify_artifact(artifact_path, signature, public_key)`: Verify a
  signature against a file and public key. Return `True` on valid
  signature, `False` on `InvalidSignature`.
- `sign_sbom(sbom)`: Sign an `AgentSBOM`'s SPDX payload and return an
  envelope containing the payload and `SignatureBundle`.

**[Pure Specification]**

### 13.3 SignatureBundle Model

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `signature` | bytes | Yes | -- | Ed25519 signature |
| `public_key` | bytes | Yes | -- | Raw 32-byte Ed25519 public key |
| `artifact_hash` | string | Yes | -- | SHA-256 hex digest of the artifact |
| `timestamp` | string | Yes | -- | ISO-8601 UTC timestamp |
| `signer_did` | string or null | No | `None` | DID of the signer (optional) |

The bundle MUST support round-trip serialization via `to_dict()` and
`from_dict()`. Signature and public key MUST be hex-encoded in the
dictionary representation. **[Pure Specification]**

### 13.4 SBOM Signing

When signing an SBOM, the signer MUST:

1. Serialize the SPDX payload to JSON with `sort_keys=True`.
2. Sign the UTF-8-encoded JSON bytes.
3. Compute the SHA-256 hash of the payload bytes.
4. Return an envelope with `{"payload": spdx_dict, "signature": bundle_dict}`.

**[Pure Specification]**

### 13.5 Key Export

The `export_private_key_pem()` method MUST return the private key in
PKCS8 PEM format with no encryption, suitable for persisting to disk
for later reuse. **[Pure Specification]**

---

## 14. Incident Detection

### 14.1 IncidentSeverity Enum

| Value | Meaning | Response |
| --- | --- | --- |
| `P1` | Page immediately | Auto-response + circuit break |
| `P2` | Alert team | Auto-response |
| `P3` | Notify | Log and monitor |
| `P4` | Log only | Informational |

**[Pure Specification]**

### 14.2 IncidentState Lifecycle

Incidents MUST follow this lifecycle:

```
DETECTED -> ACKNOWLEDGED -> INVESTIGATING -> MITIGATING -> RESOLVED
```

| State | Meaning |
| --- | --- |
| `DETECTED` | Signal ingested, incident created |
| `ACKNOWLEDGED` | Human or automation has acknowledged |
| `INVESTIGATING` | Root cause analysis in progress |
| `MITIGATING` | Fix being applied |
| `RESOLVED` | Incident closed |

Transitions MUST be forward-only (no regression to earlier states).
**[Pure Specification]**

### 14.3 SignalType Enum

Implementations MUST support the following signal types:

| Value | Default Severity Hint |
| --- | --- |
| `SLO_BREACH` | P2 |
| `ERROR_BUDGET_EXHAUSTED` | P1 |
| `COST_ANOMALY` | P2 |
| `POLICY_VIOLATION` | P1 |
| `TRUST_REVOCATION` | P1 |
| `TOOL_FAILURE_SPIKE` | P3 |
| `LATENCY_SPIKE` | P2 |

Severity hints MUST be computed as:
- `{ERROR_BUDGET_EXHAUSTED, POLICY_VIOLATION, TRUST_REVOCATION}` --> P1
- `{SLO_BREACH, COST_ANOMALY, LATENCY_SPIKE}` --> P2
- All others --> P3

**[Pure Specification]**

### 14.4 Signal Model

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `signal_type` | SignalType | Yes | -- | Signal category |
| `source` | string | Yes | -- | Agent ID, SLO name, etc. |
| `value` | float | No | 0.0 | Observed metric value |
| `threshold` | float | No | 0.0 | Threshold that was crossed |
| `message` | string | No | `""` | Human-readable description |
| `timestamp` | float | Auto | `time.time()` | UNIX epoch |
| `metadata` | dict | No | `{}` | Arbitrary key-value data |

### 14.5 IncidentDetector

The `IncidentDetector` MUST:

1. Accept signals via `ingest_signal(signal)`.
2. Create incidents only for P1 and P2 severity signals.
3. Deduplicate: if an incident for the same source and signal type
   was created within the `dedup_window_seconds` (default 600s), the
   signal MUST be suppressed.
4. Correlate: if multiple signals from the same source arrive within
   the `correlation_window_seconds` (default 300s), they MUST be
   grouped into a single correlated incident with the highest severity.
5. Prune old signals outside `2 * correlation_window`.

**[Pure Specification]**

### 14.6 Incident Model

| Field | Type | Description |
| --- | --- | --- |
| `incident_id` | string | UUID hex[:12] |
| `title` | string | Generated from signal type and source |
| `severity` | IncidentSeverity | Severity classification |
| `state` | IncidentState | Current lifecycle state |
| `agent_id` | string | Affected agent |
| `signals` | list\[Signal\] | Triggering signals |
| `actions` | list\[ResponseAction\] | Response actions taken |
| `detected_at` | float | Detection timestamp |
| `resolved_at` | float or null | Resolution timestamp |
| `notes` | list\[string\] | Operator notes |

The `duration_seconds` property MUST return elapsed time since
detection (using current time if not yet resolved).
**[Pure Specification]**

---

## 15. Incident Response

### 15.1 Auto-Response Actions

Implementations MUST support registering automatic response actions
for specific signal types via
`register_response(signal_type, actions)`.

When an incident is created, all registered actions for the
triggering signal type MUST be executed automatically and recorded as
`ResponseAction` entries with `executed=True` and
`result="auto-triggered"`. **[Pure Specification]**

### 15.2 ResponseAction Model

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `action_type` | string | Yes | -- | e.g., `rollback`, `circuit_breaker`, `generate_postmortem` |
| `executed` | bool | No | `False` | Whether the action was executed |
| `result` | string | No | `""` | Execution result |
| `timestamp` | float | Auto | `time.time()` | UNIX epoch |

### 15.3 Correlated Incident Response

When creating a correlated incident from multiple signals, the
detector MUST apply auto-response actions for **all** signal types in
the group, deduplicating action types to avoid double-execution.
**[Pure Specification]**

### 15.4 Escalation

Incident escalation SHOULD follow this pattern:

| Severity | Escalation |
| --- | --- |
| P1 | Immediate page via PagerDuty/OpsGenie + circuit break |
| P2 | Alert to Slack/Teams + throttle |
| P3 | Log to persistent store + dashboard notification |
| P4 | Log only |

Implementations MAY customize escalation via the AlertManager
channel configuration. **[Default Implementation]**

---

## 16. OTEL Integration

### 16.1 Semantic Conventions

Agent SRE MUST use the following custom OpenTelemetry attribute names
under the `agent.*` namespace:

| Attribute | Type | Description |
| --- | --- | --- |
| `agent.did` | string | Decentralised identifier for the agent |
| `agent.trust_score` | float | Current trust score |
| `agent.task.success` | bool | Whether the task succeeded |
| `agent.task.name` | string | Human-readable task name |
| `agent.tool.name` | string | Name of the tool being called |
| `agent.tool.result` | string | Tool call result |
| `agent.model.name` | string | LLM model name (e.g., `gpt-4`) |
| `agent.model.provider` | string | LLM provider (e.g., `openai`) |
| `agent.delegation.from` | string | DID of the delegating agent |
| `agent.delegation.to` | string | DID of the delegate agent |
| `agent.policy.name` | string | Policy being evaluated |
| `agent.policy.decision` | string | Policy decision result |

**[Pure Specification]**

### 16.2 Span Kind Constants

Logical span types for agent operations:

| Constant | Value | Usage |
| --- | --- | --- |
| `AGENT_TASK` | `"AGENT_TASK"` | Top-level agent task spans |
| `TOOL_CALL` | `"TOOL_CALL"` | Tool invocation spans |
| `LLM_INFERENCE` | `"LLM_INFERENCE"` | LLM API call spans |
| `DELEGATION` | `"DELEGATION"` | Delegation spans |
| `POLICY_CHECK` | `"POLICY_CHECK"` | Policy evaluation spans |

These MUST be set on the `agent.span.kind` attribute.
**[Pure Specification]**

### 16.3 Span Helpers

Implementations SHOULD provide helper functions that create
properly-attributed spans:

| Helper | Span Name | Required Attributes |
| --- | --- | --- |
| `start_agent_task_span` | `agent_task:{task_name}` | `agent.did`, `agent.task.name` |
| `start_tool_call_span` | `tool_call:{tool_name}` | `agent.did`, `agent.tool.name` |
| `start_llm_inference_span` | `llm_inference:{model_name}` | `agent.model.name`, `agent.model.provider` |
| `start_delegation_span` | `delegation:{from}->{to}` | `agent.delegation.from`, `agent.delegation.to` |
| `start_policy_check_span` | `policy_check:{policy_name}` | `agent.did`, `agent.policy.name` |

**[Default Implementation]**

### 16.4 Metric Instruments

Implementations MUST expose the following metric instruments via an
OpenTelemetry `Meter`:

| Metric Name | Type | Unit | Description |
| --- | --- | --- | --- |
| `agent.tasks.total` | Counter | `1` | Total agent tasks executed |
| `agent.tool_calls.total` | Counter | `1` | Total tool calls made |
| `agent.policy.violations` | Counter | `1` | Policy violations detected |
| `agent.task.duration` | Histogram | `ms` | Task duration distribution |
| `agent.llm.latency` | Histogram | `ms` | LLM inference latency |
| `agent.tool.latency` | Histogram | `ms` | Tool call latency |
| `agent.active_tasks` | UpDownCounter | `1` | Currently active tasks |
| `agent.trust_score` | ObservableGauge | `1` | Agent trust score (optional, callback-driven) |

Metric names MUST follow Prometheus naming conventions.
**[Pure Specification]**

### 16.5 Exporter Configuration

Implementations SHOULD provide convenience functions for configuring
OTLP exporters:

| Function | Transport | Default Endpoint |
| --- | --- | --- |
| `configure_otlp_grpc` | gRPC | `localhost:4317` |
| `configure_otlp_http` | HTTP | `http://localhost:4318/v1/traces` |
| `configure_console_exporter` | stdout | N/A |

All exporters MUST use `BatchSpanProcessor` for production and MAY
use `SimpleSpanProcessor` for console/debug output.
**[Default Implementation]**

---

## 17. Failure Semantics

### 17.1 Fail Closed

All enforcement and detection operations MUST fail closed:

| Component | Operation | Failure Behavior |
| --- | --- | --- |
| Circuit Breaker | `is_available` check | Return `False` (deny) |
| Circuit Breaker | `record_failure()` internal error | Transition to OPEN |
| AlertManager | Channel delivery failure | Record `DeliveryResult(success=False)`, continue to next channel |
| AlertManager | Formatter error | Record failure, do not suppress alert |
| TraceStore | Save/load error | Raise exception, do not silently discard |
| TraceStore | Path traversal attempt | Raise `ValueError` |
| IncidentDetector | Signal ingestion error | Create incident (do not suppress) |
| ArtifactSigner | Invalid key format | Raise `TypeError` |
| ArtifactSigner | Path traversal in key path | Raise `ValueError` |
| ArtifactSigner | Signature verification failure | Return `False` |
| ChaosExperiment | Abort condition triggered | Transition to ABORTED, halt all fault injection |
| SLO | Evaluation error | Return `UNKNOWN` status |
| PersistentAlertManager | SQLite write failure | Raise exception, do not lose alert data silently |

### 17.2 No Silent Failures

Implementations MUST NOT silently swallow exceptions in any
reliability-critical path. If a component cannot determine the safe
state, it MUST default to the most restrictive behavior:

- Circuit breakers default to OPEN.
- Alerts default to dispatched.
- Incidents default to created.
- Signature verification defaults to `False`.

**[Pure Specification]**

### 17.3 Bounded Resource Usage

- Error budget event buffers MUST use bounded deques (`maxlen`). When
  full, oldest events are silently evicted.
- Circuit breaker event history MUST be bounded (last 10 events in
  serialized output).
- Alert dedup caches MUST be pruned based on the dedup window.
- Incident detector pending signals MUST be pruned based on
  `2 * correlation_window`.

**[Pure Specification]**

---

## 18. Security Considerations

### 18.1 Key Material Protection

Private keys used by `ArtifactSigner` MUST be stored with appropriate
filesystem permissions. Implementations MUST NOT log or serialize
private key material. The `export_private_key_pem()` method is
provided for explicit key persistence only.

### 18.2 Path Traversal Prevention

Both `TraceStore` and `ArtifactSigner` MUST validate paths to prevent
directory traversal attacks. Paths containing `..` components MUST be
rejected. Resolved paths MUST be verified to reside within the
expected directory.

### 18.3 PII in Traces

Traces MUST be redacted before persistence to remove passwords, API
keys, email addresses, and phone numbers. Custom redaction patterns
MAY be added by implementations.

### 18.4 Webhook Security

Alert webhook URLs are loaded from configuration. Implementations
MUST NOT allow agent-controlled input to specify webhook URLs at
runtime. Webhook calls MUST use a timeout (default 10 seconds) to
prevent resource exhaustion.

### 18.5 Chaos Experiment Safety

Chaos experiments MUST support abort conditions to prevent
uncontrolled damage. Adversarial fault types (prompt injection,
privilege escalation, etc.) MUST only be executed in controlled
environments with explicit operator approval. Blast radius MUST be
clamped to [0.0, 1.0].

### 18.6 SQLite Injection Prevention

The `PersistentAlertManager` and any SQLite-backed stores MUST use
parameterized queries. String interpolation in SQL MUST NOT be used.

### 18.7 Credential Handling in Alerts

Alert formatters MUST NOT include raw credentials or tokens in
alert payloads. PagerDuty routing keys and OpsGenie API keys are
sent as authentication headers or payload fields per the vendor API
spec, never in the alert body.

---

## 19. Conformance Requirements

### 19.1 MUST Requirements

An implementation is conformant if it satisfies all MUST requirements:

1. SLO evaluation follows the specified precedence rules.
2. SLOStatus enum contains all five states with correct ordering.
3. ExhaustionAction enum contains all four values.
4. All eight built-in SLI types are implemented with correct defaults.
5. Inverted SLIs use `value <= target` for compliance.
6. CalibrationDeltaSLI returns the latest aggregate, not the mean.
7. Error budget remaining computation matches the formula.
8. Burn rate computation handles zero and infinite cases correctly.
9. CircuitState enum contains CLOSED, OPEN, and HALF_OPEN.
10. Circuit breaker transitions follow the specified rules.
11. HALF_OPEN is not auto-entered in Public Preview.
12. All twelve FaultType values are defined.
13. Blast radius is clamped to [0.0, 1.0].
14. Abort conditions halt experiments when triggered.
15. All six AlertChannel types are supported.
16. Alert deduplication respects the dedup window.
17. RESOLVED alerts clear the dedup cache.
18. All six SpanKind values are defined.
19. Trace content hash uses SHA-256.
20. TraceStore rejects path traversal.
21. PII redaction is applied before trace persistence.
22. ArtifactSigner uses Ed25519 exclusively.
23. SignatureBundle supports round-trip serialization.
24. IncidentDetector creates incidents only for P1/P2 signals.
25. Signal deduplication and correlation windows are enforced.
26. All OTEL semantic conventions use the `agent.*` namespace.
27. All metric instruments follow Prometheus naming conventions.
28. All components fail closed on internal error.

### 19.2 Test Coverage

Conformance tests MUST cover:

- SLO evaluation across all five status values.
- Error budget exhaustion and burn rate computation.
- BurnRateAlert firing logic.
- Circuit breaker state transitions (CLOSED -> OPEN, manual recovery).
- ChaosExperiment lifecycle (start, inject, abort, complete).
- Resilience score computation.
- Alert dispatch to all channel types.
- Alert deduplication and suppression.
- Persistent alert storage and querying.
- Trace capture, redaction, and storage.
- Golden trace comparison and suite results.
- Distributed replay with delegation link discovery.
- Artifact signing and verification round-trip.
- SBOM signing envelope structure.
- Incident creation from P1/P2 signals.
- Signal correlation and correlated incident creation.
- OTEL span helper attribute assignment.
- Metric instrument creation.

---

## 20. Worked Examples

### 20.1 SLO Evaluation

```
Given: SLO with TaskSuccessRate(target=0.995) and ErrorBudget(total=0.005)
       10 events recorded: 9 good, 1 bad
When:  slo.evaluate()
Then:  consumed = 1.0, remaining = max(0, 1.0 - (1.0 / 0.005)) = 0.0
       error_budget.is_exhausted = True (1.0 >= 0.005)
       SLO status = EXHAUSTED
```

### 20.2 Burn Rate Calculation

```
Given: ErrorBudget(total=0.005, window_seconds=2592000)
       In a 1-hour window: 100 events, 5 errors
When:  burn_rate(window_seconds=3600)
Then:  actual_error_rate = 5 / 100 = 0.05
       allowed_error_rate = 0.005 / 2592000 ≈ 1.93e-9
       burn_rate = 0.05 / 1.93e-9 ≈ 25,906,735
       (Very high -- budget consumed almost instantly)
```

### 20.3 Circuit Breaker Trip

```
Given: CircuitBreaker(agent_id="agent-1", config=CircuitBreakerConfig(failure_threshold=5))
       state = CLOSED, failure_count = 0
When:  5 consecutive record_failure() calls
Then:  failure_count increments: 1, 2, 3, 4, 5
       At failure_count == 5: transition CLOSED -> OPEN
       is_available = False
       total_trips = 1
```

### 20.4 Chaos Experiment with Abort

```
Given: ChaosExperiment(
         name="latency-test",
         target_agent="agent-1",
         faults=[Fault.latency_injection("tool-a", delay_ms=5000)],
         abort_conditions=[AbortCondition(metric="success_rate", threshold=0.5, comparator="lte")]
       )
When:  experiment.start()
       experiment.check_abort({"success_rate": 0.4})
Then:  state = ABORTED
       abort_reason = "success_rate = 0.4 (threshold: 0.5)"
```

### 20.5 Alert Deduplication

```
Given: AlertManager(dedup_window_seconds=300)
       Channel "ops-slack" configured
When:  alert_1 = Alert(title="SLO Breach", dedup_key="agent-1:slo-1", severity=CRITICAL)
       manager.send(alert_1) -- dispatched
       alert_2 = Alert(title="SLO Breach", dedup_key="agent-1:slo-1", severity=CRITICAL)
       manager.send(alert_2) at T + 60s -- suppressed (within 300s window)
       alert_3 = Alert(dedup_key="agent-1:slo-1", severity=RESOLVED)
       manager.send(alert_3) -- dispatched, clears dedup cache
       alert_4 = Alert(title="SLO Breach", dedup_key="agent-1:slo-1", severity=CRITICAL)
       manager.send(alert_4) -- dispatched (cache was cleared)
```

### 20.6 Incident Correlation

```
Given: IncidentDetector(correlation_window_seconds=300)
       register_response("slo_breach", ["circuit_breaker"])
       register_response("cost_anomaly", ["throttle"])
When:  ingest_signal(Signal(type=SLO_BREACH, source="agent-1"))  -- creates Incident A
       ingest_signal(Signal(type=COST_ANOMALY, source="agent-1")) at T + 30s
Then:  Second signal correlates with the SLO_BREACH from same source
       Creates a single correlated incident:
         title = "Correlated: cost_anomaly, slo_breach from agent-1"
         severity = P1 (highest of P2 SLO_BREACH and P2 COST_ANOMALY)
         actions = ["circuit_breaker", "throttle"] (from both signal types)
```

### 20.7 Artifact Signing Round-Trip

```
Given: signer = ArtifactSigner()  -- ephemeral key pair
When:  bundle = signer.sign_artifact("agent-v1.0.whl")
       valid = signer.verify_artifact("agent-v1.0.whl", bundle.signature, bundle.public_key)
Then:  valid = True
       bundle.artifact_hash = SHA-256 of file contents
       bundle.timestamp = ISO-8601 UTC
```

---

## 21. Edge Cases

### 21.1 Empty SLI Windows

When an SLI has no measurements in its window:
- `current_value()` MUST return `None`.
- `compliance()` MUST return `None`.
- SLO evaluation MUST return `UNKNOWN` if no indicator has a
  non-None value.

### 21.2 Zero Error Budget

When `error_budget.total == 0`:
- `remaining` MUST return `0.0`.
- `is_exhausted` MUST return `True` if `consumed >= 0`.
- Implementations MUST NOT divide by zero.

### 21.3 Circuit Breaker Already in Target State

If `force_open()` is called when already OPEN, or `force_close()` when
already CLOSED, the transition MUST be a no-op (no event recorded).

### 21.4 Blast Radius Boundaries

- `blast_radius = -0.5` MUST be clamped to `0.0`.
- `blast_radius = 1.5` MUST be clamped to `1.0`.
- `blast_radius = 0.0` means no traffic is affected.

### 21.5 Concurrent Signal Deduplication

If two identical P1 signals arrive for the same source within the
dedup window, only the first MUST create an incident. The second MUST
be suppressed.

### 21.6 Trace with No Spans

A Trace with an empty span list is valid. `root_spans()` MUST return
an empty list. `total_cost_usd` MUST be `0.0`.

### 21.7 Dedup Cache and RESOLVED Alerts

A RESOLVED alert MUST clear the dedup cache entry even if the original
alert was never deduplicated. This prevents stale cache entries from
blocking future alerts.

### 21.8 CalibrationDeltaSLI with Zero Predictions

When `_count == 0`, `collect()` MUST return a measurement with
value `0.0`. `current_value()` returns based on stored values in the
window, not the running aggregate.

### 21.9 Signing Non-Existent Files

`sign_artifact()` called with a non-existent path MUST raise a
filesystem error (e.g., `FileNotFoundError`). Implementations MUST
NOT return a bundle with empty or zero-length signature.

### 21.10 Event Buffer Eviction

When the error budget event buffer reaches `max_events`, new events
MUST cause the oldest to be evicted. The `consumed` counter MUST NOT
be decremented when old events are evicted -- it tracks total
historical consumption, not windowed consumption.

---

## 22. References

- [RFC 2119: Key words for use in RFCs](https://datatracker.ietf.org/doc/html/rfc2119)
- [RFC 8174: Ambiguity of Uppercase vs Lowercase in RFC 2119](https://datatracker.ietf.org/doc/html/rfc8174)
- [Agent Hypervisor Execution Control Specification v1.0](./AGENT-HYPERVISOR-EXECUTION-CONTROL-1.0.md)
- [Agent OS Policy Engine Specification v1.0](./AGENT-OS-POLICY-ENGINE-1.0.md)
- [AgentMesh Identity and Trust Specification v1.0](./AGENTMESH-IDENTITY-TRUST-1.0.md)
- [Google SRE Book -- Service Level Objectives](https://sre.google/sre-book/service-level-objectives/)
- [OpenTelemetry Specification](https://opentelemetry.io/docs/specs/)
- [Ed25519: High-speed high-security signatures](https://ed25519.cr.yp.to/)
- [SPDX 2.3 Specification](https://spdx.github.io/spdx-spec/v2.3/)
- [Principles of Chaos Engineering](https://principlesofchaos.org/)
