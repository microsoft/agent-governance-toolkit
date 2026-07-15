---
title: "Dynamic Policy Conditions 1.0"
last_reviewed: 2026-06-14
owner: agt-maintainers
---

# Dynamic Policy Conditions 1.0

Status: Draft (v1)

## 1. Overview

This specification defines additive dynamic condition support for the Python Agent-OS policy engine. Dynamic conditions are evaluated alongside existing static `field/operator/value` rule conditions and enable runtime-aware policy decisions.

Version 1.0 scope is intentionally narrow:

- Temporal conditions:
  - `time_window`
  - `day_of_week`
- Budget conditions:
  - `token_count_per_window`
  - `cost_per_window`

## 2. Data Model

A rule MAY include an optional `dynamic_condition` object.

```yaml
rules:
  - name: deny_after_hours
    condition:
      field: action_type
      operator: eq
      value: tool_call
    dynamic_condition:
      type: time_window
      timezone: America/New_York
      start_time: "09:00"
      end_time: "17:00"
      days_of_week: [1, 2, 3, 4, 5]
    action: deny
```

`dynamic_condition.type` values:

- `time_window`
- `day_of_week`
- `token_count_per_window`
- `cost_per_window`

## 3. Evaluation Semantics

### 3.1 Ordering

For each rule, evaluation order is:

1. Evaluate static `condition`.
2. If static condition is true and `dynamic_condition` exists, evaluate dynamic condition.
3. Rule matches only if both are true.
4. Rule selection still follows existing priority sorting and first-match-wins semantics.

### 3.2 Runtime Context Input

`PolicyEvaluator.evaluate(context, dynamic_context=None)` accepts optional runtime data.

- Existing `context` behavior is unchanged.
- `dynamic_context` is optional and additive.

### 3.3 Temporal Conditions

#### `time_window`

Required fields:

- `start_time` (HH:MM, inclusive)
- `end_time` (HH:MM, exclusive)

Optional fields:

- `timezone` (IANA timezone string; default `UTC`)
- `days_of_week` (`[1..7]`, ISO weekday numbers)

Behavior:

- Times are interpreted in local time of `timezone`.
- If `start_time <= end_time`, window is same-day interval.
- If `start_time > end_time`, window wraps midnight.
- If `days_of_week` is supplied, local weekday MUST be in set.

#### `day_of_week`

Required fields:

- `days_of_week` (`[1..7]`, ISO weekday numbers)

Optional fields:

- `timezone` (IANA timezone string; default `UTC`)

Behavior:

- Condition is true if local weekday in configured set.

### 3.4 Timezone and DST

- Runtime timestamp is interpreted as UTC and converted to local timezone for temporal checks.
- Daylight Saving Time transitions MUST be handled by timezone-aware conversion using IANA zone data.
- Spring-forward and fall-back behavior is derived from local civil time produced by conversion; no custom DST tables are used.

### 3.5 Budget Conditions

#### `token_count_per_window`

Required fields:

- `window` (`<int><unit>`, unit in `m|h|d`)
- `limit` (numeric, inclusive)

Runtime input:

- `dynamic_context.budget.token_count` (numeric amount consumed by current evaluation event)

#### `cost_per_window`

Required fields:

- `window` (`<int><unit>`, unit in `m|h|d`)
- `limit` (numeric, inclusive)

Runtime input:

- `dynamic_context.budget.cost` (numeric amount consumed by current evaluation event)

Window semantics:

- Window alignment is epoch-bucketed by configured duration.
- State is tracked in-memory per evaluator instance and per `(rule, metric, window)` tuple.
- On bucket rollover, accumulated usage resets for that tuple.

V1 Implementation Note:

- Budget window counters are maintained in-memory, process-local, and non-persistent.
- Counters reset on process restart and do not provide cross-process consistency.
- Durable quota accounting is out of scope for v1.

Boundary semantics:

- Decision is allowed while cumulative usage is `<= limit`.
- Once cumulative usage exceeds limit, condition evaluates false.

## 4. Audit Semantics

When a rule with dynamic condition is evaluated, audit metadata SHOULD include:

- `dynamic_condition` (serialized condition config) — always present when the rule has a `dynamic_condition`.
- `evaluated_budget` — present only for budget conditions (`token_count_per_window`, `cost_per_window`). Records a minimal summary of the budget check: `{metric, window, limit, amount}`. No other fields from `dynamic_context` are recorded.
- existing static context snapshot and timestamp fields

The full `dynamic_context` provided to `PolicyEvaluator.evaluate` is intentionally NOT persisted in audit entries. Hosts that need the full runtime context should record it at a layer that has its own redaction policy.

## 5. Failure Semantics

- Unknown timezone, invalid time format, invalid window format, or malformed runtime budget values cause dynamic condition evaluation to return false for that rule.
- Global evaluator fail-closed behavior remains unchanged for unexpected internal errors.

## 6. Backward Compatibility

- `dynamic_condition` is optional.
- Existing policies without dynamic conditions remain valid and unchanged.
- Existing `evaluate(context)` call sites remain valid because `dynamic_context` is optional.

## 7. Out Of Scope For v1

- Quota conditions.
- System and behavior signal conditions.
- Composite conditions.
- Geo-based conditions.
- External signal sources.
