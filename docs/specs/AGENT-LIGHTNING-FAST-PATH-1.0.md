<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Agent Lightning Fast-Path -- Version 1.0

> **Status:** Draft · **Date:** 2025-07-28 · **Authors:** Agent Governance Toolkit team
>
> This specification defines the RL training governance layer for
> Agent Lightning, including governed runners, policy violation
> handling, reward shaping, governed environments, flight recorder
> emission, and failure semantics. All SDK implementations MUST
> conform to this specification.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in
[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) and
[RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174).

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Governed Runner](#3-governed-runner)
4. [Policy Violations](#4-policy-violations)
5. [Governed Rollout](#5-governed-rollout)
6. [Reward Shaping](#6-reward-shaping)
7. [Policy Penalty Function](#7-policy-penalty-function)
8. [Composite Reward](#8-composite-reward)
9. [Governed Environment](#9-governed-environment)
10. [Environment State](#10-environment-state)
11. [Flight Recorder Emitter](#11-flight-recorder-emitter)
12. [Span Export](#12-span-export)
13. [Runner Lifecycle](#13-runner-lifecycle)
14. [Violation Rate and Stats](#14-violation-rate-and-stats)
15. [Factory Functions](#15-factory-functions)
16. [Failure Semantics](#16-failure-semantics)
17. [Security Considerations](#17-security-considerations)
18. [Conformance Requirements](#18-conformance-requirements)
19. [Worked Examples](#19-worked-examples)
20. [References](#20-references)

---

## 1. Introduction

### 1.1 Purpose

Agent Lightning is the RL training governance layer for the Agent
Governance Toolkit. It wraps RL frameworks to inject policy enforcement
into training loops, converting policy violations into learning signals
that teach agents to respect governance constraints during
reinforcement learning.

By intercepting each training step at the kernel boundary, Agent
Lightning ensures that every rollout is subject to the same policy
evaluation that governs production execution -- but instead of merely
blocking unsafe actions, the layer converts violations into negative
reward signals that steer the RL optimiser away from policy-violating
behaviour.

### 1.2 Scope

This specification covers:

- **Governed Runner:** A generic runner that wraps RL kernels with
  policy enforcement, capturing violations and signals per rollout.
- **Policy Violations:** A typed violation model with severity-based
  penalties and enumerated violation categories.
- **Governed Rollout:** A rollout record that bundles task I/O with
  governance metadata (violations, signals, penalty, timing).
- **Reward Shaping:** Reward functions that integrate policy compliance
  into RL training objectives via additive or multiplicative penalties.
- **Governed Environment:** A Gymnasium-style training environment that
  enforces policies on every step and converts violations to rewards.
- **Flight Recorder Emitter:** An adapter that exports Flight Recorder
  audit logs as Lightning spans for unified training and compliance
  telemetry.
- **Failure Semantics:** Fail-closed behaviour for critical violations,
  exception containment, and error propagation rules.

### 1.3 Relationship to Other Specifications

| Specification | Relationship |
| --- | --- |
| Agent OS Policy Engine 1.0 | Kernel policies are evaluated on each runner step and environment step |
| AgentMesh Identity and Trust 1.0 | Agent DIDs identify runners; trust scores may inform reward weighting |
| Agent Hypervisor Execution Control 1.0 | Ring enforcement MAY gate runner instantiation; kill switch MAY terminate runners |

### 1.4 Design Principles

1. **Policy violations are learning signals.** Blocked actions are not
   just errors -- they become negative rewards that shape RL behaviour.
2. **Governance is transparent to the trainer.** The governed runner
   exposes the same `step`/`iter` interface as unmodified runners;
   trainers need not know about policy enforcement internals.
3. **Fail closed on critical violations.** When
   `fail_on_violation = True`, a blocked action MUST raise
   `PolicyViolationError`, halting the rollout.
4. **Reward penalties are configurable.** Operators control the mapping
   from severity to penalty magnitude via `RewardConfig`.
5. **Audit is always-on.** Every rollout emits governance spans to the
   Flight Recorder for compliance traceability.

---

## 2. Terminology

| Term | Definition |
| --- | --- |
| **Governed Runner** | A generic runner (`Generic[T_task]`) that wraps an Agent OS kernel and collects policy violations during RL training rollouts. |
| **Governed Rollout** | A single execution pass through the kernel, bundling task input, task output, success flag, violations, signals, total penalty, and execution time. |
| **Policy Violation** | A record of a governance rule infraction during execution, categorised by type and severity. |
| **PolicyViolationType** | An enum classifying how the kernel responded to a policy infraction: BLOCKED, MODIFIED, WARNED, or SIGNAL_SENT. |
| **PolicyViolationError** | An exception raised when `fail_on_violation` is enabled and a violation blocks execution. |
| **Severity** | One of four levels -- critical, high, medium, low -- each mapped to a default penalty value. |
| **PolicyReward** | A reward function wrapper that subtracts policy violation penalties from a base reward, creating a compliance-aware training signal. |
| **RewardConfig** | Configuration dataclass controlling penalty magnitudes, clean-execution bonuses, multiplicative mode, and reward clamping bounds. |
| **CompositeReward** | A weighted combiner that sums multiple reward functions (including PolicyReward) with configurable weights. |
| **GovernedEnvironment** | A Gymnasium-compatible training environment that wraps an Agent OS kernel, enforcing policies on each `step()` call. |
| **EnvironmentConfig** | Configuration for the governed environment including max steps, violation penalties, termination rules, and reward shaping parameters. |
| **EnvironmentState** | A snapshot of the environment's current episode: step count, total reward, accumulated violations, and termination flags. |
| **FlightRecorderEmitter** | An adapter that converts Agent OS Flight Recorder entries into LightningSpan objects for ingestion by LightningStore. |
| **LightningSpan** | A span record compatible with Agent Lightning's telemetry format, carrying span ID, trace ID, name, timestamps, attributes, and events. |
| **Flight Recorder** | The Agent OS audit log subsystem whose entries are the input to the emitter. |
| **LightningStore** | The Agent Lightning persistence layer that receives emitted spans. |
| **Kernel** | An Agent OS KernelSpace instance with loaded policies, the execution boundary through which all governed actions pass. |
| **Clean Bonus** | An additive reward granted when a rollout completes with zero violations. |

---

## 3. Governed Runner

### 3.1 Overview

The GovernedRunner wraps agent execution in an Agent OS kernel,
enforcing policies and collecting violation data that can be used as RL
training signals. It is generic over the task type (`Generic[T_task]`)
and exposes `step()` and `iter()` as the primary training entry points.

**[Pure Specification]**

### 3.2 Constructor Parameters

A GovernedRunner MUST accept the following parameters:

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `kernel` | KernelSpace | (required) | Agent OS kernel with loaded policies |
| `fail_on_violation` | bool | `False` | If `True`, raise `PolicyViolationError` when a violation blocks execution |
| `log_violations` | bool | `True` | If `True`, log all violations at WARNING level |
| `violation_callback` | Callable or None | `None` | Optional callback invoked for each violation |

**[Pure Specification]**

### 3.3 Step Method

The `step()` method MUST:

1. Bind per-step violation and signal lists to the current async
   context (context variables) so that concurrent `step()` calls on
   the same runner do not share violation or signal buffers.
2. Start a high-resolution timer.
3. Attempt execution through the kernel (`execute_async` preferred,
   falling back to `execute`, then direct agent call).
4. Catch `PolicyViolationError` -- set `success = False` and
   `result = None`.
5. Catch all other exceptions -- set `success = False` and
   `result = None`, log the full traceback via `logger.exception`.
6. Reset context variables in a `finally` block.
7. Compute execution time in milliseconds.
8. Construct and return a `GovernedRollout`.
9. Emit governance spans (Section 11).

**[Pure Specification]**

### 3.4 Step Signature

```
async step(
    input: T_task,
    *,
    resources: Any | None = None,
    mode: str | None = None,
    event: Any | None = None,
) -> GovernedRollout
```

The `mode` parameter SHOULD accept `"train"` or `"eval"` to
distinguish training rollouts from evaluation passes.
**[Pure Specification]**

### 3.5 Iter Method

The `iter()` method MUST:

1. Accept an optional cooperative stop signal (`event`).
2. Loop: fetch the next task from the store, execute via `step()`,
   submit the rollout to the store.
3. Stop when the event is set or no more tasks are available.

**[Pure Specification]**

### 3.6 Context Variable Isolation

Per-step state MUST be stored in `contextvars.ContextVar` instances:

| Variable | Purpose |
| --- | --- |
| `_active_violations_ctx` | List of `PolicyViolation` for the active step |
| `_active_signals_ctx` | List of signal strings for the active step |

Each `step()` call MUST set fresh lists before invoking the kernel
and MUST reset the context variables in a `finally` block. When a
violation or signal arrives outside an active `step()` context, the
handler MUST fall back to instance-level lists for backward
compatibility. **[Pure Specification]**

### 3.7 Kernel Hook Registration

On `init()`, the runner MUST register hooks on the kernel:

1. If the kernel exposes `on_policy_violation`, register the violation
   handler.
2. If the kernel exposes `on_signal`, register the signal handler.

**[Pure Specification]**

---

## 4. Policy Violations

### 4.1 PolicyViolationType Enum

Implementations MUST define the following violation types:

| Value | String | Description |
| --- | --- | --- |
| `BLOCKED` | `"blocked"` | Action was blocked entirely by the policy engine |
| `MODIFIED` | `"modified"` | Action was modified before execution to satisfy policy constraints |
| `WARNED` | `"warned"` | Warning issued but the action was allowed to proceed |
| `SIGNAL_SENT` | `"signal_sent"` | A kernel signal was dispatched (e.g., SIGSTOP) |

**[Pure Specification]**

### 4.2 PolicyViolation Dataclass

A PolicyViolation record MUST contain:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `violation_type` | PolicyViolationType | (required) | Category of the violation |
| `policy_name` | string | (required) | Name of the policy that was violated |
| `description` | string | (required) | Human-readable description of the violation |
| `severity` | string | (required) | One of: `"critical"`, `"high"`, `"medium"`, `"low"` |
| `timestamp` | datetime | `now(UTC)` | When the violation occurred |
| `action_blocked` | bool | `False` | Whether the action was prevented from executing |
| `penalty` | float or None | `None` | Numeric penalty; derived from severity if not supplied |

**[Pure Specification]**

### 4.3 Severity Penalties

The `SEVERITY_PENALTIES` mapping MUST define the following default
penalty values:

| Severity | Penalty |
| --- | --- |
| `"critical"` | 100.0 |
| `"high"` | 50.0 |
| `"medium"` | 10.0 |
| `"low"` | 1.0 |

**[Default Implementation]**

### 4.4 Penalty Derivation

On construction, if the caller does not supply an explicit `penalty`,
the penalty MUST be derived from the `severity` field via the
`SEVERITY_PENALTIES` mapping. If the severity is not found in the
mapping, the fallback penalty MUST be 10.0 (the medium-severity
value).

If the caller supplies an explicit `penalty`, that value MUST be
preserved. Implementations MUST NOT unconditionally overwrite a
caller-supplied penalty from the severity table. **[Pure Specification]**

### 4.5 PolicyViolationError

`PolicyViolationError` MUST:

1. Be a subclass of `Exception`.
2. Accept a `PolicyViolation` instance in its constructor.
3. Store the violation as `self.violation`.
4. Format its message as `"Policy violation: {violation.description}"`.

**[Pure Specification]**

### 4.6 Violation Handler Behaviour

When a violation is received by `_handle_violation`:

1. Construct a `PolicyViolation` from the callback arguments.
2. Append to the context-local list (if an active step exists) or the
   instance-level fallback list.
3. Increment the total violation counter.
4. If `log_violations` is `True`, log at WARNING level with policy
   name, description, severity, and blocked status.
5. If `violation_callback` is not `None`, invoke it with the violation.
6. If `fail_on_violation` is `True` and the action was blocked, raise
   `PolicyViolationError`.

**[Pure Specification]**

---

## 5. Governed Rollout

### 5.1 GovernedRollout Dataclass

A GovernedRollout record MUST contain:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `task_input` | Any | (required) | The input provided to the runner |
| `task_output` | Any | (required) | The result returned by the kernel (or `None` on failure) |
| `success` | bool | (required) | Whether the execution completed without fatal error |
| `violations` | list[PolicyViolation] | `[]` | Policy violations recorded during this rollout |
| `signals_sent` | list[str] | `[]` | Kernel signals dispatched during this rollout |
| `total_penalty` | float | 0.0 | Sum of all violation penalties |
| `execution_time_ms` | float | 0.0 | Wall-clock execution time in milliseconds |

**[Pure Specification]**

### 5.2 Auto-Computed Total Penalty

On construction (`__post_init__`), the `total_penalty` field MUST be
recomputed as the sum of `v.penalty` for all violations in the
`violations` list. Any caller-supplied value for `total_penalty` is
overwritten. **[Pure Specification]**

### 5.3 Governance Span Emission

After constructing a rollout, the runner MUST attempt to emit
governance annotations. If the `agentlightning.emitter` module is
importable, the runner SHOULD emit:

1. A violation summary annotation containing violation count, total
   penalty, violation type values, and the distinct set of violated
   policy names.
2. A signal summary annotation containing the list of signals sent.

If the emitter module is not available, the runner MUST silently
continue (no error raised). **[Default Implementation]**

---

## 6. Reward Shaping

### 6.1 Overview

The PolicyReward class wraps any base reward function and subtracts
penalties for policy violations, creating a learning signal that
discourages unsafe behaviour during RL training. It supports both
additive and multiplicative penalty modes, clean-execution bonuses,
and configurable reward clamping.

### 6.2 RewardConfig

A RewardConfig MUST define the following fields:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `critical_penalty` | float | -100.0 | Penalty for each critical-severity violation |
| `high_penalty` | float | -50.0 | Penalty for each high-severity violation |
| `medium_penalty` | float | -10.0 | Penalty for each medium-severity violation |
| `low_penalty` | float | -1.0 | Penalty for each low-severity violation |
| `clean_bonus` | float | 5.0 | Bonus added when a rollout has zero violations |
| `multiplicative` | bool | `False` | Use multiplicative penalty mode instead of additive |
| `multiplicative_factor` | float | 0.5 | Factor to multiply reward by when violations occur (multiplicative mode) |
| `min_reward` | float or None | -100.0 | Minimum reward floor; `None` disables clamping |
| `max_reward` | float or None | 100.0 | Maximum reward ceiling; `None` disables clamping |

**[Default Implementation]**

### 6.3 PolicyReward Constructor

A PolicyReward MUST accept:

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `kernel` | KernelSpace | (required) | Agent OS kernel for policy checking |
| `base_reward_fn` | Callable or None | `None` | Base reward function; defaults to success-based reward |
| `config` | RewardConfig or None | `None` | Reward configuration; defaults to `RewardConfig()` |

**[Pure Specification]**

### 6.4 Default Base Reward

When no `base_reward_fn` is provided, the default MUST return:

- `1.0` if the rollout has `success == True`.
- `0.0` if the rollout has `success == False`.
- If neither attribute is available, fall back to checking
  `task_output is not None` (1.0) vs `None` (0.0).

**[Default Implementation]**

### 6.5 Reward Computation

When `PolicyReward.__call__` is invoked with a rollout:

1. Compute the base reward from `base_reward_fn(rollout)`.
2. Extract violations from the rollout (via `rollout.violations` or
   `kernel.get_recent_violations()`).
3. Calculate the total penalty via the severity mapping.
4. If `config.multiplicative` is `True` and violations exist, compute:
   `final_reward = base_reward * config.multiplicative_factor`.
5. Otherwise, compute: `final_reward = base_reward + penalty`.
6. If no violations exist, add `config.clean_bonus` to `final_reward`.
7. Apply `min_reward` floor (if not `None`):
   `final_reward = max(final_reward, min_reward)`.
8. Apply `max_reward` ceiling (if not `None`):
   `final_reward = min(final_reward, max_reward)`.
9. Update internal statistics.
10. If `emit` is `True`, emit the reward to Agent Lightning.
11. Return `final_reward`.

**[Pure Specification]**

### 6.6 Reward Emission

When emitting rewards, the implementation SHOULD produce a
multi-dimensional reward object:

| Key | Value |
| --- | --- |
| `"final"` | The clamped final reward |
| `"base"` | The base reward before penalties |
| `"policy_penalty"` | The total penalty value |

With attributes:

| Attribute | Value |
| --- | --- |
| `agent_os.violation_count` | Number of violations |
| `agent_os.policy_compliant` | `True` if zero violations |

If the Agent Lightning emitter is not importable, emission MUST be
silently skipped. **[Default Implementation]**

### 6.7 Reward Statistics

`PolicyReward.get_stats()` MUST return:

| Key | Type | Description |
| --- | --- | --- |
| `total_rewards` | int | Number of reward computations |
| `total_penalties` | float | Cumulative penalty value |
| `avg_penalty` | float | Mean penalty per computation |
| `violation_rate` | float | Fraction of computations with violations |
| `clean_rate` | float | Fraction of computations without violations |

`reset_stats()` MUST zero all counters. **[Pure Specification]**

---

## 7. Policy Penalty Function

### 7.1 Standalone Penalty Computation

The `policy_penalty` function provides a lightweight utility for
computing penalties outside the full `PolicyReward` class. It MUST
accept:

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `violations` | list[Any] | (required) | List of PolicyViolation objects |
| `critical_penalty` | float | -100.0 | Penalty for critical violations |
| `high_penalty` | float | -50.0 | Penalty for high-severity violations |
| `medium_penalty` | float | -10.0 | Penalty for medium-severity violations |
| `low_penalty` | float | -1.0 | Penalty for low-severity violations |

**[Pure Specification]**

### 7.2 Severity Mapping

The function MUST build the following mapping and sum penalties:

```
severity_penalties = {
    "critical": critical_penalty,
    "high":     high_penalty,
    "medium":   medium_penalty,
    "low":      low_penalty,
}

total_penalty = 0.0
for violation in violations:
    severity = violation.severity  (default "medium" if absent)
    total_penalty += severity_penalties.get(severity, medium_penalty)
```

**[Pure Specification]**

### 7.3 Unknown Severity Fallback

If a violation's severity is not one of `"critical"`, `"high"`,
`"medium"`, or `"low"`, the implementation MUST fall back to the
`medium_penalty` value. **[Pure Specification]**

### 7.4 Return Value

The function MUST return the total penalty as a negative float (or
zero if no violations are present). **[Pure Specification]**

---

## 8. Composite Reward

### 8.1 Overview

`CompositeReward` combines multiple reward functions with weights,
enabling operators to blend task-completion rewards, policy-compliance
penalties, and efficiency metrics into a single scalar signal.

### 8.2 Constructor

A CompositeReward MUST accept:

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `components` | list[tuple[Callable, float]] | (required) | List of (reward_fn, weight) tuples |
| `normalize` | bool | `False` | If `True`, normalise weights to sum to 1.0 |

**[Pure Specification]**

### 8.3 Weight Normalisation

If `normalize` is `True`, the constructor MUST divide each weight by
the sum of all weights:

```
total_weight = sum(w for _, w in components)
components = [(fn, w / total_weight) for fn, w in components]
```

**[Pure Specification]**

### 8.4 Computation

`CompositeReward.__call__(rollout)` MUST compute:

```
total = sum(weight * reward_fn(rollout) for reward_fn, weight in components)
```

and return `total`. **[Pure Specification]**

### 8.5 Example

```python
reward = CompositeReward([
    (accuracy_reward,  1.0),
    (policy_reward,    0.5),
    (efficiency_reward, 0.3),
])
score = reward(rollout)  # weighted sum of three signals
```

---

## 9. Governed Environment

### 9.1 Overview

The GovernedEnvironment wraps an Agent OS kernel as a Gymnasium-style
training environment. On each `step()`, the environment executes an
action through the kernel, enforces policies, converts violations to
negative rewards, and optionally terminates the episode on critical
violations.

### 9.2 Compatibility

The environment MUST be compatible with:

- Agent Lightning trainers
- OpenAI Gym / Gymnasium (`reset`/`step`/`close` interface)
- Stable Baselines3
- Any framework that consumes the five-tuple
  `(next_state, reward, terminated, truncated, info)` return

**[Pure Specification]**

### 9.3 EnvironmentConfig

An EnvironmentConfig MUST define:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `max_steps` | int | 100 | Maximum steps per episode before truncation |
| `violation_penalty` | float | -10.0 | Base penalty for each policy violation |
| `terminate_on_critical` | bool | `True` | Terminate the episode immediately on a critical violation |
| `step_penalty` | float | -0.1 | Small penalty per step to encourage efficiency |
| `success_bonus` | float | 10.0 | Reward bonus for a successful, violation-free step |
| `reset_kernel_state` | bool | `True` | Whether to call `kernel.reset()` on episode reset |

**[Default Implementation]**

### 9.4 Constructor

A GovernedEnvironment MUST accept:

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `kernel` | KernelSpace | (required) | Agent OS kernel with loaded policies |
| `task_generator` | Callable or None | `None` | Function to generate initial states |
| `reward_fn` | Callable or None | `None` | Custom reward function; defaults to success-based |
| `config` | EnvironmentConfig or None | `None` | Environment configuration |

The constructor MUST be generic over state and action types:
`GovernedEnvironment(Generic[T_state, T_action])`.
**[Pure Specification]**

### 9.5 Reset Method

`reset()` MUST:

1. Reinitialise `EnvironmentState` to default values.
2. Clear the current violations list.
3. Increment the total episode counter.
4. If `config.reset_kernel_state` is `True` and the kernel exposes a
   `reset()` method, call it.
5. If a `task_generator` is provided, generate the initial task.
6. Return `(initial_state, info)` where `info` contains the episode
   number and loaded policy names.

**[Pure Specification]**

### 9.6 Step Method

`step(action)` MUST:

1. Clear per-step violations.
2. Increment step counter and total step counter.
3. Execute the action through the kernel (via `kernel.execute()`).
4. If no callback hook was wired, pull violations from the kernel via
   `kernel.get_recent_violations()`.
5. Compute the base reward from the reward function.
6. Add the step penalty (`config.step_penalty`).
7. For each violation, add a scaled violation penalty:
   - Critical: `violation_penalty * 10`
   - High: `violation_penalty * 5`
   - All others: `violation_penalty * 1`
8. Accumulate the reward into `EnvironmentState.total_reward`.
9. Check termination: if `terminate_on_critical` and any violation has
   severity `"critical"`, set `terminated = True`.
10. Check truncation: if `step_count >= max_steps`, set
    `truncated = True`.
11. If the step succeeded with zero violations, add `success_bonus`.
12. Return `(next_state, reward, terminated, truncated, info)`.

**[Pure Specification]**

### 9.7 Violation Penalty Scaling

The violation penalty multiplier MUST follow:

| Severity | Multiplier | Effective Penalty (default config) |
| --- | --- | --- |
| `"critical"` | 10x | -100.0 |
| `"high"` | 5x | -50.0 |
| `"medium"` | 1x | -10.0 |
| `"low"` | 1x | -10.0 |

**[Default Implementation]**

### 9.8 Kernel Violation Polling

If the kernel does not expose `on_policy_violation` (i.e., the push
callback could not be wired), the environment MUST poll
`kernel.get_recent_violations()` after each action execution. The poll
results MUST be normalised from either dict or object form:

| Source (dict key or attribute) | Target field |
| --- | --- |
| `"policy"` or `"policy_name"` | policy_name |
| `"description"` | description |
| `"severity"` (default `"low"`) | severity |
| `"blocked"` or `"action_blocked"` | blocked |

**[Pure Specification]**

### 9.9 Close Method

`close()` MUST log the environment metrics and release resources.
**[Pure Specification]**

---

## 10. Environment State

### 10.1 EnvironmentState Dataclass

An EnvironmentState record MUST contain:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `step_count` | int | 0 | Number of steps taken in the current episode |
| `total_reward` | float | 0.0 | Cumulative reward for the current episode |
| `violations` | list | `[]` | All violations accumulated in the current episode |
| `terminated` | bool | `False` | Whether the episode ended due to a terminal condition (e.g., critical violation) |
| `truncated` | bool | `False` | Whether the episode ended due to step limit |
| `info` | dict | `{}` | Additional metadata from the most recent step |

**[Pure Specification]**

### 10.2 Terminated Property

The environment MUST expose a `terminated` property that returns
`True` if the state is either terminated or truncated.
**[Pure Specification]**

### 10.3 Episode Metrics

`get_metrics()` MUST return:

| Key | Type | Description |
| --- | --- | --- |
| `total_episodes` | int | Number of episodes completed |
| `total_steps` | int | Total steps across all episodes |
| `total_violations` | int | Total violations across all episodes |
| `successful_episodes` | int | Episodes with at least one violation-free, successful step |
| `success_rate` | float | `successful_episodes / max(total_episodes, 1)` |
| `violations_per_episode` | float | `total_violations / max(total_episodes, 1)` |
| `steps_per_episode` | float | `total_steps / max(total_episodes, 1)` |

**[Pure Specification]**

---

## 11. Flight Recorder Emitter

### 11.1 Overview

The FlightRecorderEmitter adapts Agent OS Flight Recorder entries to
Agent Lightning's span format. This enables:

1. Complete audit trail from training to production.
2. RL algorithms learning from policy violations.
3. Compliance-friendly training logs.

### 11.2 LightningSpan

A LightningSpan record MUST contain:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `span_id` | string | (required) | Unique span identifier |
| `trace_id` | string | (required) | Trace identifier linking related spans |
| `name` | string | (required) | Span name (e.g., `"agent_os.policy_check"`) |
| `start_time` | datetime | (required) | When the span started |
| `end_time` | datetime or None | `None` | When the span ended |
| `attributes` | dict[str, Any] | `{}` | Key-value metadata |
| `events` | list[dict] | `[]` | Discrete events within the span |

**[Pure Specification]**

### 11.3 Serialisation

LightningSpan MUST support:

- `to_dict()`: Returns a dictionary with all fields; datetime values
  serialised to ISO 8601.
- `to_json()`: Returns a JSON string via `json.dumps(to_dict())`.

**[Pure Specification]**

### 11.4 Constructor Parameters

A FlightRecorderEmitter MUST accept:

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `flight_recorder` | FlightRecorder | (required) | Agent OS Flight Recorder instance |
| `include_policy_checks` | bool | `True` | Include policy check spans |
| `include_signals` | bool | `True` | Include signal dispatch spans |
| `include_tool_calls` | bool | `True` | Include tool call spans |
| `trace_id_prefix` | string | `"agentos"` | Prefix for generated trace IDs |

**[Pure Specification]**

### 11.5 Entry Type Filtering

The emitter MUST filter entries by type according to its configuration:

| Entry Type | Filter Flag | Included by Default |
| --- | --- | --- |
| `policy_check` | `include_policy_checks` | Yes |
| `signal` | `include_signals` | Yes |
| `tool_call` | `include_tool_calls` | Yes |

If the corresponding flag is `False`, entries of that type MUST be
silently dropped. **[Pure Specification]**

### 11.6 Entry Conversion

For each included entry, the emitter MUST produce a LightningSpan with:

- `span_id`: Derived from `entry.id`, `entry.entry_id`, or the
  emitted count.
- `trace_id`: `"{trace_id_prefix}-{agent_id}"`.
- `name`: `"agent_os.{entry_type}"`.
- `start_time` and `end_time`: Both set to the entry's timestamp.

**[Pure Specification]**

### 11.7 Type-Specific Attributes

Depending on the entry type, the following attributes MUST be set:

**All entries:**

| Attribute | Value |
| --- | --- |
| `agent_os.entry_type` | Entry type string |
| `agent_os.agent_id` | Agent identifier |

**policy_check entries:**

| Attribute | Value |
| --- | --- |
| `agent_os.policy_name` | Name of the evaluated policy |
| `agent_os.policy_result` | Result of the policy check |
| `agent_os.policy_violated` | Boolean -- whether the policy was violated |

**signal entries:**

| Attribute | Value |
| --- | --- |
| `agent_os.signal_type` | Signal type string |
| `agent_os.signal_target` | Target of the signal |

**tool_call entries:**

| Attribute | Value |
| --- | --- |
| `agent_os.tool_name` | Name of the tool invoked |
| `agent_os.tool_args` | String representation of arguments (truncated to 1000 chars) |
| `agent_os.tool_result` | String representation of result (truncated to 1000 chars) |

**[Pure Specification]**

### 11.8 Metadata Propagation

If the entry has a `metadata` dict, all key-value pairs MUST be
copied into the span attributes with an `agent_os.` prefix.
**[Pure Specification]**

### 11.9 Incremental Span Cursor

The emitter MUST maintain a `_last_position` cursor into the
recorder's entry list. The `get_new_spans()` method MUST only convert
entries added since the last call, avoiding O(n) full-list walks on
every poll. **[Pure Specification]**

---

## 12. Span Export

### 12.1 emit_to_store

`emit_to_store(store)` MUST:

1. Get all spans via `get_spans()`.
2. For each span, call `store.emit_span(span.to_dict())` or
   `store.add_span(span.to_dict())`.
3. If the store has no recognised span emitter, log a warning and
   stop.
4. If an individual span emission fails, log the error and continue
   with the next span.
5. Return the total number of spans emitted.

**[Pure Specification]**

### 12.2 export_to_file

`export_to_file(filepath)` MUST:

1. Get all spans via `get_spans()`.
2. Write the list of span dicts to the filepath as a JSON array with
   2-space indentation.
3. Return the number of spans exported.

**[Pure Specification]**

### 12.3 Streaming via AsyncIterator

The `stream()` method MUST:

1. Accept an optional `stop_event` (`asyncio.Event`) and a
   `poll_interval` (default 0.1 seconds).
2. In a loop, call `get_new_spans()` and yield each span.
3. Sleep for `poll_interval` between polls.
4. If `stop_event` is set, drain the current poll and exit.
5. If no `stop_event` is provided, the caller MUST cancel the
   consuming task to terminate the stream.

The return type MUST be `AsyncIterator[LightningSpan]`.
**[Pure Specification]**

---

## 13. Runner Lifecycle

### 13.1 Lifecycle Methods

The GovernedRunner MUST implement the following lifecycle methods:

| Method | When Called | Purpose |
| --- | --- | --- |
| `init(agent, **kwargs)` | Once during setup | Store the agent reference and register kernel hooks |
| `init_worker(worker_id, store, **kwargs)` | Once per distributed worker | Store worker ID and LightningStore reference |
| `teardown()` | Once during shutdown | Log final rollout and violation counts |
| `teardown_worker(worker_id)` | Once per worker shutdown | Release worker-local resources |

**[Pure Specification]**

### 13.2 Worker ID Management

`init_worker()` MUST store the `worker_id` and `store` as instance
attributes for later use by `step()` and `iter()`.
**[Pure Specification]**

### 13.3 Teardown Logging

`teardown()` MUST log a summary including the total number of
rollouts and total number of violations observed during the runner's
lifetime. **[Pure Specification]**

---

## 14. Violation Rate and Stats

### 14.1 get_violation_rate

`get_violation_rate()` MUST return:

```
if total_rollouts == 0:
    return 0.0
return total_violations / total_rollouts
```

**[Pure Specification]**

### 14.2 GovernedRunner.get_stats

`GovernedRunner.get_stats()` MUST return:

| Key | Type | Description |
| --- | --- | --- |
| `total_rollouts` | int | Number of rollouts executed |
| `total_violations` | int | Number of violations observed |
| `violation_rate` | float | `total_violations / total_rollouts` |

**[Pure Specification]**

### 14.3 GovernedEnvironment.get_metrics

`GovernedEnvironment.get_metrics()` MUST return the fields specified
in Section 10.3. **[Pure Specification]**

### 14.4 FlightRecorderEmitter.get_violation_summary

`get_violation_summary()` MUST return:

| Key | Type | Description |
| --- | --- | --- |
| `total_entries` | int | Total spans scanned |
| `total_violations` | int | Spans where `agent_os.policy_violated` is `True` |
| `violation_rate` | float | `total_violations / max(total_entries, 1)` |
| `policies_violated` | dict[str, int] | Map of policy name to violation count |

**[Pure Specification]**

### 14.5 FlightRecorderEmitter.get_stats

`FlightRecorderEmitter.get_stats()` MUST return:

| Key | Type | Description |
| --- | --- | --- |
| `emitted_count` | int | Total spans emitted |
| `last_position` | int | Current cursor position in the entry list |

**[Pure Specification]**

---

## 15. Factory Functions

### 15.1 create_policy_reward

```python
create_policy_reward(
    kernel,
    *,
    base_reward_fn=None,
    severity_penalties=None,
    clean_bonus=5.0,
    multiplicative=False,
) -> PolicyReward
```

This factory MUST:

1. Construct a `RewardConfig` with `clean_bonus` and `multiplicative`.
2. If `severity_penalties` is provided (a dict mapping severity names
   to float values), override the corresponding fields on the config:
   - `"critical"` -> `config.critical_penalty`
   - `"high"` -> `config.high_penalty`
   - `"medium"` -> `config.medium_penalty`
   - `"low"` -> `config.low_penalty`
3. Return `PolicyReward(kernel, base_reward_fn=base_reward_fn, config=config)`.

**[Pure Specification]**

### 15.2 create_governed_env

```python
create_governed_env(kernel, **kwargs) -> GovernedEnvironment
```

This factory MUST:

1. Construct a default `EnvironmentConfig`.
2. For each key-value pair in `kwargs`, if the key matches a field on
   `EnvironmentConfig`, set that field.
3. Return `GovernedEnvironment(kernel, config=config)`.

**[Pure Specification]**

### 15.3 create_emitter

```python
create_emitter(flight_recorder, **kwargs) -> FlightRecorderEmitter
```

This factory MUST pass `flight_recorder` and all `kwargs` directly to
the `FlightRecorderEmitter` constructor. **[Pure Specification]**

---

## 16. Failure Semantics

### 16.1 Fail Closed on Critical Violations

When `fail_on_violation` is `True` and a policy violation blocks an
action, the GovernedRunner MUST raise `PolicyViolationError`. The
rollout MUST record the violation with `success = False` and
`task_output = None`. **[Pure Specification]**

### 16.2 Exception Containment in Runner

The `step()` method MUST catch all exceptions (not just
`PolicyViolationError`). Unexpected exceptions MUST be logged via
`logger.exception` (preserving the full traceback) and result in a
rollout with `success = False`. The runner MUST NOT propagate
unexpected kernel exceptions to the trainer. **[Pure Specification]**

### 16.3 Exception Swallowing in Emitter

The FlightRecorderEmitter MUST NOT propagate exceptions from:

- `emit_to_store()` -- individual span emission failures are logged
  and the next span is attempted.
- `_convert_entry()` -- entries that cannot be converted are silently
  skipped.
- Import of `agentlightning.emitter` -- `ImportError` is caught and
  emission is silently skipped.

**[Pure Specification]**

### 16.4 Exception Swallowing in Environment

The GovernedEnvironment MUST catch exceptions from `kernel.execute()`
and set `success = False`, `result = None`. The environment MUST NOT
propagate kernel execution errors to the trainer.
**[Pure Specification]**

### 16.5 Violation Polling Resilience

If `kernel.get_recent_violations()` raises an exception during
polling, the environment MUST log the error at DEBUG level and
continue with zero violations for that step. **[Pure Specification]**

### 16.6 Error Types

Implementations MUST define the following error type:

| Error | Context |
| --- | --- |
| `PolicyViolationError` | Raised when `fail_on_violation` is `True` and a policy blocks execution |

**[Pure Specification]**

### 16.7 Failure Behaviour Summary

| Operation | Failure Behaviour |
| --- | --- |
| Runner step (policy blocks) | `PolicyViolationError` if `fail_on_violation`; else `success = False` |
| Runner step (unexpected error) | `success = False`, logged via `logger.exception` |
| Emitter span emission | Log error, continue to next span |
| Emitter import failure | Silently skip emission |
| Environment step (kernel error) | `success = False`, `result = None` |
| Environment violation poll | Log at DEBUG, zero violations for step |
| Reward emission import failure | Silently skip emission |

**[Pure Specification]**

---

## 17. Security Considerations

### 17.1 Violation Callback Injection

The `violation_callback` parameter allows arbitrary code execution on
every violation. Implementations SHOULD validate that the callback is
callable and SHOULD document that the callback runs in the same
execution context as the runner. Malicious callbacks could suppress
violations or exfiltrate data.

### 17.2 Reward Manipulation

Custom `base_reward_fn` and `violation_callback` functions could be
crafted to override penalty signals and train agents to ignore
governance constraints. Operators MUST audit reward configurations in
production training pipelines.

### 17.3 Kernel Trust Boundary

The GovernedRunner trusts the kernel to faithfully report violations.
A compromised kernel could suppress violation callbacks, allowing
unsafe actions to generate clean-bonus rewards. The Flight Recorder
provides a secondary audit trail that SHOULD be reconciled against
runner-observed violations.

### 17.4 Span Data Sensitivity

LightningSpan attributes may contain tool arguments and results,
which could include sensitive data. The emitter truncates tool_args
and tool_result to 1000 characters, but implementations SHOULD apply
additional redaction for sensitive fields before emitting to external
stores.

### 17.5 File Export Security

`export_to_file()` writes span data (potentially including sensitive
attributes) to the filesystem. Callers MUST ensure the output path
is in a secure, access-controlled directory. Implementations MUST
NOT follow symlinks to prevent path traversal attacks.

### 17.6 Concurrent Step Isolation

Context variable isolation (Section 3.6) is critical for preventing
violation cross-contamination between concurrent rollouts. If
context variables are not properly reset in the `finally` block, a
leaked context could cause violations from one rollout to be
attributed to another, corrupting training signals.

### 17.7 CORS and Network Exposure

If the governed environment or emitter exposes an HTTP API for span
ingestion, wildcard CORS origins (`*`) MUST be rejected when
credentials are enabled. Span ingestion endpoints SHOULD require
authentication.

---

## 18. Conformance Requirements

### 18.1 MUST Requirements

An implementation is conformant if it satisfies all MUST requirements:

1. GovernedRunner accepts `kernel`, `fail_on_violation`,
   `log_violations`, and `violation_callback` parameters.
2. `step()` isolates violations and signals per call via context
   variables.
3. `step()` catches `PolicyViolationError` and general exceptions
   without propagating to the trainer.
4. `step()` returns a `GovernedRollout` with all required fields.
5. GovernedRollout auto-computes `total_penalty` from violations on
   construction.
6. PolicyViolationType defines exactly BLOCKED, MODIFIED, WARNED,
   and SIGNAL_SENT values.
7. PolicyViolation derives penalty from severity when not
   caller-supplied; preserves caller-supplied penalty.
8. PolicyViolationError stores the violation and formats the message
   correctly.
9. `policy_penalty` falls back to medium penalty for unknown
   severities.
10. PolicyReward supports both additive and multiplicative penalty
    modes.
11. PolicyReward clamps rewards to `[min_reward, max_reward]`.
12. CompositeReward computes weighted sums and supports normalisation.
13. GovernedEnvironment returns the Gymnasium five-tuple from `step()`.
14. GovernedEnvironment terminates on critical violations when
    configured.
15. GovernedEnvironment polls kernel violations when no push hook is
    wired.
16. FlightRecorderEmitter filters entries by type configuration.
17. FlightRecorderEmitter maintains an incremental cursor for
    `get_new_spans()`.
18. LightningSpan supports `to_dict()` and `to_json()` serialisation.
19. All lifecycle methods (`init`, `init_worker`, `teardown`,
    `teardown_worker`) are implemented.
20. All failure semantics follow fail-closed principles.

### 18.2 Test Coverage

Conformance tests MUST cover:

- GovernedRunner step with zero violations (clean rollout).
- GovernedRunner step with violations (penalty computation).
- GovernedRunner step with `fail_on_violation = True` (exception raised).
- Context variable isolation across concurrent steps.
- PolicyViolation penalty derivation from severity.
- PolicyViolation caller-supplied penalty preservation.
- PolicyViolationType enum values.
- PolicyViolationError message formatting.
- `policy_penalty` with known and unknown severities.
- PolicyReward additive mode computation.
- PolicyReward multiplicative mode computation.
- PolicyReward clean bonus application.
- PolicyReward min/max clamping.
- CompositeReward weighted sum computation.
- CompositeReward weight normalisation.
- GovernedEnvironment reset and step lifecycle.
- GovernedEnvironment critical violation termination.
- GovernedEnvironment violation penalty scaling.
- GovernedEnvironment kernel violation polling.
- FlightRecorderEmitter entry filtering.
- FlightRecorderEmitter incremental cursor.
- FlightRecorderEmitter span attribute population.
- LightningSpan serialisation.
- `emit_to_store` and `export_to_file` export.
- Factory functions with default and custom parameters.
- Violation rate and stats computation.

---

## 19. Worked Examples

### 19.1 Basic Governed Training

```
Given: kernel with SQLPolicy(deny=["DROP", "DELETE"])
       runner = GovernedRunner(kernel)
       agent attempts: "DROP TABLE users"

When:  rollout = await runner.step("DROP TABLE users")

Then:  rollout.success == False
       rollout.violations == [PolicyViolation(
           violation_type=BLOCKED,
           policy_name="SQLPolicy",
           severity="critical",
           action_blocked=True,
           penalty=100.0,
       )]
       rollout.total_penalty == 100.0
```

### 19.2 Reward Computation -- Additive Mode

```
Given: config = RewardConfig(
           critical_penalty=-100.0,
           clean_bonus=5.0,
           multiplicative=False,
       )
       base_reward_fn returns 1.0 for success
       rollout has 1 critical violation

When:  reward = policy_reward(rollout)

Then:  base_reward       = 1.0
       penalty           = -100.0
       final_reward      = 1.0 + (-100.0) = -99.0
       (no clean bonus -- violations exist)
       clamped           = max(-99.0, -100.0) = -99.0
       result            = -99.0
```

### 19.3 Reward Computation -- Multiplicative Mode

```
Given: config = RewardConfig(
           multiplicative=True,
           multiplicative_factor=0.5,
       )
       base_reward_fn returns 10.0
       rollout has 1 low violation

When:  reward = policy_reward(rollout)

Then:  final_reward = 10.0 * 0.5 = 5.0
       clamped      = min(max(5.0, -100.0), 100.0) = 5.0
       result       = 5.0
```

### 19.4 Clean Execution Bonus

```
Given: config = RewardConfig(clean_bonus=5.0)
       base_reward_fn returns 1.0
       rollout has 0 violations

When:  reward = policy_reward(rollout)

Then:  base_reward  = 1.0
       penalty      = 0.0
       clean_bonus  = 5.0
       final_reward = 1.0 + 0.0 + 5.0 = 6.0
       result       = 6.0
```

### 19.5 Environment Critical Termination

```
Given: env = GovernedEnvironment(kernel, config=EnvironmentConfig(
           terminate_on_critical=True,
           violation_penalty=-10.0,
       ))
       state, info = env.reset()

When:  agent submits action that triggers critical violation
       state, reward, terminated, truncated, info = env.step(action)

Then:  terminated == True
       reward includes: violation_penalty * 10 = -100.0
       info["violations"] contains the critical violation record
```

### 19.6 Incremental Span Emission

```
Given: emitter = FlightRecorderEmitter(recorder)
       recorder has 5 entries

When:  spans1 = emitter.get_new_spans()
Then:  len(spans1) == 5, emitter._last_position == 5

When:  recorder receives 3 more entries
       spans2 = emitter.get_new_spans()
Then:  len(spans2) == 3, emitter._last_position == 8
       (only new entries converted -- no O(n) re-scan)
```

### 19.7 Policy Penalty with Unknown Severity

```
Given: violations = [
           PolicyViolation(severity="unknown_level", ...),
           PolicyViolation(severity="critical", ...),
       ]

When:  penalty = policy_penalty(violations)

Then:  penalty = medium_penalty + critical_penalty
               = (-10.0) + (-100.0) = -110.0
       ("unknown_level" falls back to medium_penalty)
```

---

## 20. References

- [RFC 2119: Key words for use in RFCs](https://datatracker.ietf.org/doc/html/rfc2119)
- [RFC 8174: Ambiguity of Uppercase vs Lowercase in RFC 2119](https://datatracker.ietf.org/doc/html/rfc8174)
- [Agent OS Policy Engine Specification v1.0](./AGENT-OS-POLICY-ENGINE-1.0.md)
- [AgentMesh Identity and Trust Specification v1.0](./AGENTMESH-IDENTITY-TRUST-1.0.md)
- [Agent Hypervisor Execution Control Specification v1.0](./AGENT-HYPERVISOR-EXECUTION-CONTROL-1.0.md)
- [OpenAI Gymnasium API](https://gymnasium.farama.org/)
