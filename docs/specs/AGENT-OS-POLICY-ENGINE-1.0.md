<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Agent OS Policy Engine -- Version 1.0

> **Status:** Draft · **Date:** 2026-05-16 · **Authors:** Agent Governance Toolkit team
>
> This specification defines the policy evaluation engine for Agent OS.
> All SDK implementations (Python, TypeScript, Rust, .NET, Go) MUST
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
3. [Policy Document Schema](#3-policy-document-schema)
4. [Policy Rule Schema](#4-policy-rule-schema)
5. [Condition Operators](#5-condition-operators)
6. [Policy Actions](#6-policy-actions)
7. [Evaluation Semantics](#7-evaluation-semantics)
8. [Integration-Layer Policy (GovernancePolicy)](#8-integration-layer-policy-governancepolicy)
9. [Pattern Matching](#9-pattern-matching)
10. [Tool Call Interception](#10-tool-call-interception)
11. [Policy Merge (Folder-Level Hierarchy)](#11-policy-merge-folder-level-hierarchy)
12. [Policy Discovery](#12-policy-discovery)
13. [Conflict Resolution](#13-conflict-resolution)
14. [External Policy Backends](#14-external-policy-backends)
15. [Concurrency and Backpressure](#15-concurrency-and-backpressure)
16. [Failure Semantics](#16-failure-semantics)
17. [Audit and Observability](#17-audit-and-observability)
18. [Policy Composability](#18-policy-composability)
19. [Serialization](#19-serialization)
20. [Conformance Requirements](#20-conformance-requirements)
21. [Worked Examples](#21-worked-examples)
22. [Security Considerations](#22-security-considerations)
23. [References](#23-references)

---

## 1. Introduction

### 1.1 Purpose

This document specifies the behavioral contract for the Agent OS policy
engine: the component that evaluates governance policies against agent
actions and returns structured allow/deny decisions with full audit
metadata.

The policy engine is the single enforcement point through which all
governed agent actions flow. It operates at two layers:

- **Declarative layer:** YAML/JSON `PolicyDocument` files evaluated
  by the `PolicyEvaluator` against execution context dictionaries.
- **Integration layer:** `GovernancePolicy` objects applied by framework
  adapters (OpenAI, LangChain, CrewAI, etc.) to intercept tool calls,
  enforce token limits, and check blocked patterns at runtime.

### 1.2 Scope

This specification covers:

- Policy document structure, rule schemas, and condition operators
- Evaluation order, priority semantics, and default actions
- Folder-level policy discovery, inheritance, and merge
- Multi-policy conflict resolution strategies
- External policy backend integration (OPA/Rego, Cedar)
- Tool call interception and pattern matching
- Failure semantics and fail-closed behavior
- Concurrency control and backpressure
- Audit entry structure and observability hooks

This specification does NOT cover:

- Identity and trust scoring (see future Identity and Trust spec)
- Execution ring enforcement (see future Hypervisor spec)
- Multi-agent coordination policies (see future AgentMesh Trust spec)
- SLO/SLI governance (see future Agent SRE spec)

### 1.3 Notation

This specification uses two markers to distinguish normative requirements
from implementation guidance:

- **[Pure Specification]** marks behavioral requirements that all
  conforming implementations MUST satisfy.
- **[Default Implementation]** marks behaviors that the reference
  implementation provides but that other implementations MAY vary,
  provided they satisfy the surrounding pure-specification constraints.

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| **PolicyDocument** | A declarative governance policy file (YAML/JSON) containing rules, defaults, and metadata. |
| **PolicyRule** | A single condition-action pair within a PolicyDocument. |
| **PolicyCondition** | A field-operator-value triple that matches against execution context. |
| **PolicyAction** | The prescribed outcome when a rule matches: `allow`, `deny`, `audit`, or `block`. |
| **PolicyEvaluator** | The engine that evaluates PolicyDocuments against execution contexts. |
| **GovernancePolicy** | Integration-layer policy object enforced by framework adapters at runtime. |
| **ExecutionContext** | Runtime state (agent ID, session ID, call count, token usage) passed through the governance layer. |
| **PolicyDecision** | Structured result of evaluating policies: allowed/denied with rule, reason, and audit metadata. |
| **Conflict Resolution** | The strategy for resolving disagreements when multiple rules or policies match. |
| **External Backend** | A pluggable policy evaluator using a third-party language (OPA/Rego, Cedar). |

---

## 3. Policy Document Schema

### 3.1 Structure

**[Pure Specification]**

A PolicyDocument MUST contain the following fields:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `version` | string | No | `"1.0"` | Schema version identifier. |
| `name` | string | No | `"unnamed"` | Human-readable policy name for audit logs. |
| `description` | string | No | `""` | Free-form description. |
| `rules` | array | No | `[]` | Ordered list of PolicyRule objects. |
| `defaults` | object | No | See 3.2 | Default settings when no rule matches. |
| `inherit` | boolean | No | `true` | Whether parent policies are loaded during discovery. |
| `scope` | string or null | No | `null` | Glob pattern restricting which action paths this policy applies to. |

### 3.2 Defaults

**[Pure Specification]**

The `defaults` object MUST support the following fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `action` | PolicyAction | `"allow"` | Default action when no rule matches. |
| `max_tokens` | integer | `4096` | Maximum tokens per request. |
| `max_tool_calls` | integer | `10` | Maximum tool invocations per request. |
| `confidence_threshold` | float | `0.8` | Minimum confidence score (0.0-1.0). |

Implementations MAY support additional default fields for sandbox
resource constraints (`max_cpu`, `max_memory_mb`, `timeout_seconds`,
`network_default`). These fields are consumed by sandbox providers and
MUST be ignored by the rule engine itself.

### 3.3 Serialization Formats

**[Pure Specification]**

Conforming implementations MUST support loading PolicyDocuments from
YAML. Implementations SHOULD also support JSON.

YAML files MUST use `.yaml` or `.yml` extensions. JSON files MUST use
`.json` extension.

---

## 4. Policy Rule Schema

### 4.1 Structure

**[Pure Specification]**

Each PolicyRule MUST contain:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | Yes | -- | Unique rule identifier within the document. |
| `condition` | PolicyCondition | Yes | -- | The matching condition. |
| `action` | PolicyAction | Yes | -- | Action to take when condition matches. |
| `priority` | integer | No | `0` | Evaluation priority. Higher values are evaluated first. |
| `message` | string | No | `""` | Human-readable explanation included in decisions and audit entries. |
| `override` | boolean | No | `false` | If true, replaces a parent rule with the same name during folder-level merge. |

### 4.2 PolicyCondition

**[Pure Specification]**

A PolicyCondition MUST contain exactly three fields:

| Field | Type | Description |
|-------|------|-------------|
| `field` | string | Dot-path into the execution context (e.g., `"tool_name"`, `"token_count"`). |
| `operator` | PolicyOperator | Comparison operator. |
| `value` | any | Target value for comparison. |

---

## 5. Condition Operators

### 5.1 Operator Definitions

**[Pure Specification]**

Conforming implementations MUST support all of the following operators:

| Operator | Semantics | Example |
|----------|-----------|---------|
| `eq` | Context value equals target value. | `tool_name eq "execute_code"` |
| `ne` | Context value does not equal target value. | `agent_id ne "admin"` |
| `gt` | Context value is greater than target. | `token_count gt 4096` |
| `lt` | Context value is less than target. | `priority lt 5` |
| `gte` | Context value is greater than or equal to target. | `confidence gte 0.8` |
| `lte` | Context value is less than or equal to target. | `retries lte 3` |
| `in` | Context value is a member of target collection. | `tool_name in ["read", "write"]` |
| `contains` | Target value is contained within context value. | `arguments contains "password"` |
| `matches` | Context value matches target regex pattern. | `tool_name matches "^exec_.*"` |

### 5.2 Missing Fields

**[Pure Specification]**

If the condition references a context field that does not exist (returns
null/None), the condition MUST evaluate to `false`. A missing field MUST
NOT cause an error or exception.

### 5.3 Type Coercion

**[Pure Specification]**

For the `matches` operator, both the context value and the target value
MUST be coerced to strings before regex evaluation. For all other
operators, no implicit type coercion is performed. If the types are
incompatible (e.g., comparing a string with `gt`), the behavior is
implementation-defined, but the implementation MUST NOT raise an
unhandled exception.

---

## 6. Policy Actions

### 6.1 Action Definitions

**[Pure Specification]**

| Action | Allowed | Semantics |
|--------|---------|-----------|
| `allow` | Yes | The action is permitted. |
| `deny` | No | The action is blocked. The agent MUST NOT proceed. |
| `audit` | Yes | The action is permitted but MUST be logged for review. |
| `block` | No | Alias for `deny`. The action is blocked. |

An action is considered "allowing" if it is `allow` or `audit`. An
action is considered "denying" if it is `deny` or `block`.

---

## 7. Evaluation Semantics

### 7.1 Evaluation Order

**[Pure Specification]**

When evaluating a set of rules against an execution context:

1. Rules MUST be sorted by `priority` in descending order (highest
   priority first).
2. Rules MUST be evaluated in sorted order.
3. The first rule whose condition matches the context determines the
   decision. Subsequent rules are NOT evaluated.
4. If no rule matches and external backends are registered, backends
   MUST be consulted in registration order. The first backend that
   returns a non-error result determines the decision.
5. If no rule matches and no backend produces a result, the default
   action from the policy's `defaults` object is applied.

### 7.2 Scoped vs. Flat Evaluation

**[Pure Specification]**

When a `root_dir` is configured and the execution context contains a
`path` field:

- The evaluator MUST use folder-scoped evaluation (see
  [Section 12](#12-policy-discovery)).
- Governance files are discovered from the action path up to the root,
  loaded, filtered by scope, and merged before evaluation.

When no `root_dir` is configured or the context lacks a `path` field:

- The evaluator MUST use flat evaluation against the loaded policy list.

### 7.3 Default Action Determination

**[Pure Specification]**

When using flat evaluation, if no rule matches, the default action MUST
be taken from the first loaded PolicyDocument's `defaults.action` field.
If no PolicyDocument is loaded, the default action MUST be `allow`.

When using scoped evaluation, the default action MUST be taken from the
most specific (last) PolicyDocument in the merged chain.

---

## 8. Integration-Layer Policy (GovernancePolicy)

### 8.1 Overview

**[Pure Specification]**

The `GovernancePolicy` is the runtime policy object used by framework
adapters. It provides direct constraint checking without requiring
PolicyDocument evaluation. Framework adapters MUST enforce
GovernancePolicy constraints on every governed agent action.

### 8.2 Fields

**[Pure Specification]**

| Field | Type | Default | Constraints |
|-------|------|---------|-------------|
| `name` | string | `"default"` | Non-empty. |
| `max_tokens` | integer | `4096` | MUST be > 0. |
| `max_tool_calls` | integer | `10` | MUST be >= 0. 0 disables tool calls. |
| `allowed_tools` | string[] | `[]` | Empty list means all tools permitted. |
| `blocked_patterns` | array | `[]` | Each entry is a string or (string, PatternType) tuple. |
| `require_human_approval` | boolean | `false` | When true, tool calls require human approval. |
| `timeout_seconds` | integer | `300` | MUST be > 0. |
| `confidence_threshold` | float | `0.8` | MUST be in [0.0, 1.0]. |
| `drift_threshold` | float | `0.15` | MUST be in [0.0, 1.0]. |
| `log_all_calls` | boolean | `true` | Whether all calls are audit-logged. |
| `checkpoint_frequency` | integer | `5` | MUST be > 0. Create checkpoint every N calls. |
| `max_concurrent` | integer | `10` | MUST be > 0. |
| `backpressure_threshold` | integer | `8` | MUST be > 0. |
| `version` | string | `"1.0.0"` | MUST be non-empty. |

### 8.3 Validation

**[Pure Specification]**

Policy validation MUST occur at construction time. Implementations MUST
reject invalid policies with a clear error message. The following
invariants MUST hold:

- `max_tokens`, `timeout_seconds`, `max_concurrent`,
  `backpressure_threshold`, `checkpoint_frequency` MUST be positive
  integers.
- `max_tool_calls` MUST be a non-negative integer.
- `confidence_threshold` and `drift_threshold` MUST be floats in
  [0.0, 1.0].
- Every entry in `allowed_tools` MUST be a string.
- Every entry in `blocked_patterns` MUST be a string (substring match)
  or a (string, PatternType) tuple.
- `version` MUST be a non-empty string.

### 8.4 Conflict Detection

**[Default Implementation]**

Implementations SHOULD provide a `detect_conflicts()` method that
returns warnings for contradictory settings:

- `backpressure_threshold >= max_concurrent` (backpressure never triggers)
- `max_tool_calls == 0` with non-empty `allowed_tools` (tools allowed but no calls permitted)
- `confidence_threshold == 0.0` (confidence checking effectively disabled)
- `timeout_seconds < 5` (unreasonably low timeout)

### 8.5 Strictness Comparison

**[Pure Specification]**

A policy A is "stricter than" policy B if and only if:

1. ALL of the following hold:
   - `A.max_tokens <= B.max_tokens`
   - `A.max_tool_calls <= B.max_tool_calls`
   - `A.timeout_seconds <= B.timeout_seconds`
   - `A.max_concurrent <= B.max_concurrent`
   - `A.backpressure_threshold <= B.backpressure_threshold`
   - `A.confidence_threshold >= B.confidence_threshold`
   - `A.checkpoint_frequency <= B.checkpoint_frequency`
   - `len(A.blocked_patterns) >= len(B.blocked_patterns)`
   - If B requires human approval, A must also require it.

2. AND at least one field is strictly more restrictive (not merely equal).

---

## 9. Pattern Matching

### 9.1 Pattern Types

**[Pure Specification]**

Three pattern types MUST be supported:

| Type | Semantics |
|------|-----------|
| `substring` | Case-insensitive substring search. The pattern is a plain string. |
| `regex` | Case-insensitive regular expression search (PCRE-compatible). |
| `glob` | Case-insensitive glob pattern (e.g., `*.exe`), internally converted to regex. |

### 9.2 Default Pattern Type

**[Pure Specification]**

When a blocked pattern is specified as a plain string (not a tuple), it
MUST be treated as a `substring` pattern.

### 9.3 Compilation

**[Default Implementation]**

Regex and glob patterns SHOULD be compiled at policy construction time.
Invalid regex patterns MUST cause a validation error at construction
time, not at match time.

### 9.4 Match Behavior

**[Pure Specification]**

- Substring matching MUST be case-insensitive.
- Regex matching MUST use search semantics (not full-match). The pattern
  need not match the entire input string.
- Glob matching MUST follow POSIX glob semantics as implemented by
  `fnmatch`, with case-insensitive comparison.
- The `matches_pattern(text)` method MUST return ALL patterns that match,
  not just the first.

---

## 10. Tool Call Interception

### 10.1 ToolCallRequest

**[Pure Specification]**

A tool call request MUST carry:

| Field | Type | Description |
|-------|------|-------------|
| `tool_name` | string | Name of the tool being invoked. |
| `arguments` | dict | Arguments passed to the tool. |
| `call_id` | string | Optional unique call identifier. |
| `agent_id` | string | Optional agent identifier. |
| `metadata` | dict | Optional metadata (e.g., content hashes). |

### 10.2 ToolCallResult

**[Pure Specification]**

A tool call interception result MUST carry:

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | boolean | Whether the call is permitted. |
| `reason` | string or null | Explanation for denial. |
| `modified_arguments` | dict or null | Sanitized arguments (if the interceptor rewrites them). |
| `audit_entry` | dict or null | Structured audit metadata. |

### 10.3 PolicyInterceptor Enforcement Order

**[Pure Specification]**

The default `PolicyInterceptor` MUST check constraints in the following
order. The first failing check short-circuits evaluation:

1. **Human approval:** If `require_human_approval` is true, DENY.
2. **Allowed tools:** If `allowed_tools` is non-empty and the tool name
   is not in the list, DENY.
3. **Blocked patterns:** If the string representation of the arguments
   matches any blocked pattern, DENY.
4. **Call count:** If the current call count >= `max_tool_calls`, DENY.

If all checks pass, ALLOW.

### 10.4 CompositeInterceptor

**[Pure Specification]**

A composite interceptor chains multiple interceptors. ALL interceptors
MUST allow the call for it to proceed. The first interceptor that denies
terminates the chain immediately (short-circuit deny).

### 10.5 Content Hash Interceptor

**[Default Implementation]**

Implementations SHOULD provide a `ContentHashInterceptor` that verifies
tool identity via SHA-256 content hashing. In strict mode, tools with no
registered hash MUST be blocked. In non-strict mode, unknown tools
SHOULD be allowed with a warning.

---

## 11. Policy Merge (Folder-Level Hierarchy)

### 11.1 Merge Semantics

**[Pure Specification]**

When multiple PolicyDocuments are discovered in a folder hierarchy, they
MUST be merged into a single flat rule list following these rules:

1. PolicyDocuments are provided in **root-first order** (root at index 0,
   most specific directory last).
2. Rules from all levels are collected.
3. When a child rule has `override: true` and the same `name` as a parent
   rule:
   - If the parent rule has action `deny`: the child override MUST be
     **dropped**. Parent deny rules are immutable. This is a security
     invariant.
   - Otherwise: the child rule replaces the parent rule.
4. When a child rule has the same `name` as a parent rule but
   `override: false` (or omitted): the child rule MUST be **dropped**.
   The parent version is kept.
5. Rules with unique names are appended normally.
6. The final merged list MUST be sorted by priority descending.

### 11.2 Deny Immutability Invariant

**[Pure Specification]**

A parent deny rule MUST NOT be overridden by a child rule. This
invariant ensures that security-critical deny rules set at higher levels
of the hierarchy cannot be circumvented by more specific policies. This
matches Azure Policy semantics where deny assignments cannot be
overridden.

**Rationale:** Without this invariant, a child policy could set
`override: true` and a higher priority on a rule of the same name,
effectively defeating the parent deny at evaluation time.

### 11.3 Effective Defaults

**[Pure Specification]**

When multiple PolicyDocuments are merged, the effective defaults MUST
come from the most specific (last) PolicyDocument in the chain.

---

## 12. Policy Discovery

### 12.1 Governance File Discovery

**[Pure Specification]**

Policy discovery walks the directory tree from the action path upward
to the configured root directory:

1. At each directory level, check for `governance.yaml` or
   `governance.yml` (in that order). If found, add to the candidate list.
2. Stop when the root directory is reached or no parent exists.
3. Reverse the candidate list to produce root-first order.

### 12.2 Inheritance

**[Pure Specification]**

If a PolicyDocument declares `inherit: false`, all parent policies above
that level MUST be excluded from the chain. The policy with
`inherit: false` becomes the new effective root.

Inheritance is checked from most specific to least specific. The first
`inherit: false` encountered determines the cut point.

### 12.3 Scope Filtering

**[Pure Specification]**

If a PolicyDocument declares a `scope` glob pattern, the document MUST
only apply when the action path (relative to root, forward-slash
normalized) matches the glob pattern. Documents with `scope: null` apply
to all action paths under their directory.

### 12.4 Path Traversal Protection

**[Pure Specification]**

If the resolved action path is NOT relative to the configured root
directory (e.g., due to symlinks, `..` segments, or attacker-influenced
path fields), the evaluator MUST refuse to discover policies and MUST
return an empty policy chain. This prevents path-traversal attacks on
the policy chain.

---

## 13. Conflict Resolution

### 13.1 Overview

**[Pure Specification]**

When multiple policies produce competing decisions for the same agent
action, a conflict resolution strategy determines the final outcome.

### 13.2 Strategies

**[Pure Specification]**

Conforming implementations MUST support the following strategies:

#### 13.2.1 DENY_OVERRIDES

If ANY candidate decision is a deny, the action is denied. Among
multiple denies, the highest-priority deny wins. If no deny exists,
the highest-priority allow wins.

This is the safest strategy and aligns with XACML deny-overrides
semantics.

#### 13.2.2 ALLOW_OVERRIDES

If ANY candidate decision is an allow, the action is allowed. Among
multiple allows, the highest-priority allow wins. If no allow exists,
the highest-priority deny wins.

Use this for exception-based governance where explicit allow rules
should override default-deny policies.

#### 13.2.3 PRIORITY_FIRST_MATCH

Candidates are sorted by priority descending. The highest-priority
candidate wins regardless of action type.

This is the default strategy and preserves backward compatibility.

#### 13.2.4 MOST_SPECIFIC_WINS

Candidates are ranked by scope specificity (Agent > Organization >
Tenant > Global). Within the same scope, priority breaks ties.

### 13.3 Policy Scopes

**[Pure Specification]**

Four scope levels are defined, ordered from least to most specific:

| Scope | Specificity | Description |
|-------|-------------|-------------|
| `global` | 0 | Organization-wide defaults. |
| `tenant` | 1 | Tenant or team scoped. |
| `organization` | 2 | Organization unit scoped. |
| `agent` | 3 | Specific agent instance. |

### 13.4 Resolution Result

**[Pure Specification]**

A conflict resolution result MUST include:

- The winning decision
- The strategy that was used
- Number of candidates evaluated
- Whether a genuine conflict was detected (mix of allow and deny)
- A trace of the resolution logic (for audit purposes)

### 13.5 Empty Candidates

**[Pure Specification]**

If zero candidates are provided for resolution, the resolver MUST raise
an error. This is a programming error, not a policy decision.

---

## 14. External Policy Backends

### 14.1 Backend Protocol

**[Pure Specification]**

External policy backends MUST implement:

- A `name` property returning a human-readable identifier.
- An `evaluate(context)` method accepting an execution context dict
  and returning a `BackendDecision`.

### 14.2 BackendDecision

**[Pure Specification]**

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | boolean | Whether the action is permitted. |
| `action` | string | The policy action (default: `"allow"`). |
| `reason` | string | Human-readable explanation. |
| `backend` | string | Backend identifier for audit. |
| `evaluation_ms` | float or null | Evaluation time in milliseconds. |
| `error` | string or null | Error message if evaluation failed. |

### 14.3 Evaluation Priority

**[Pure Specification]**

External backends are consulted only when no YAML/JSON rule matches.
Backends are evaluated in registration order. The first backend that
returns a result with `error == null` determines the decision.

If a backend returns a result with a non-null `error`, the evaluator
MUST skip that backend and try the next. If all backends error, the
evaluator MUST fall through to the default action.

### 14.4 Supported Backends

**[Default Implementation]**

The reference implementation provides:

- **OPABackend:** Evaluates Rego policies via the OPA CLI or library.
- **CedarBackend:** Evaluates Cedar policies via the Cedar CLI or library.

Implementations MAY provide additional backends.

---

## 15. Concurrency and Backpressure

### 15.1 Bounded Semaphore

**[Pure Specification]**

Implementations MUST enforce concurrency limits:

- When active executions reach `max_concurrent`, new requests MUST be
  rejected.
- When active executions reach `backpressure_threshold` (which SHOULD be
  less than `max_concurrent`), implementations SHOULD begin applying
  backpressure (e.g., throttling, queuing, or adding latency).

### 15.2 Slot Acquisition

**[Pure Specification]**

Slot acquisition MUST be atomic (no TOCTOU races). The response MUST
indicate whether the slot was acquired and, if not, the reason for
rejection.

---

## 16. Failure Semantics

### 16.1 Fail-Closed Principle

**[Pure Specification]**

If the policy engine encounters an unhandled exception during
evaluation, it MUST deny the action. The engine MUST NOT allow an action
when it cannot determine whether the action is permitted.

This applies to:

- Errors during condition matching
- Errors during policy loading or parsing
- Errors communicating with external backends
- Any other unexpected exception

### 16.2 Error Decision

**[Pure Specification]**

The fail-closed decision MUST include:

- `allowed: false`
- `action: "deny"`
- A reason indicating policy evaluation error
- An audit entry with `error: true`

### 16.3 Logging

**[Pure Specification]**

All fail-closed events MUST be logged at ERROR level with full exception
context (stack trace, original context snapshot).

---

## 17. Audit and Observability

### 17.1 Audit Entry Structure

**[Pure Specification]**

Every policy decision MUST produce an audit entry containing:

| Field | Required | Description |
|-------|----------|-------------|
| `policy` | Yes | Name of the policy or `"folder-scoped"`. |
| `rule` | Yes | Name of the matched rule, or null. |
| `action` | Yes | The action taken (`allow`, `deny`, `audit`, `block`). |
| `context_snapshot` | Yes | The execution context at decision time. |
| `timestamp` | Yes | ISO 8601 UTC timestamp. |

Scoped evaluations MUST also include:

| Field | Description |
|-------|-------------|
| `policy_chain` | Ordered list of policy names in the merge chain. |

Backend evaluations MUST also include:

| Field | Description |
|-------|-------------|
| `backend` | Backend name. |
| `evaluation_ms` | Backend evaluation time. |

### 17.2 Governance Events

**[Pure Specification]**

The policy engine MUST emit the following event types:

| Event | When |
|-------|------|
| `policy_check` | Every policy evaluation. |
| `policy_violation` | A rule or constraint is violated. |
| `tool_call_blocked` | A tool call is denied by an interceptor. |
| `checkpoint_created` | A governance checkpoint is created. |
| `drift_detected` | Semantic drift exceeds the configured threshold. |

---

## 18. Policy Composability

### 18.1 Composition Model

**[Pure Specification]**

Policy composition follows these rules:

- **Additive deny:** Deny rules from multiple sources accumulate. A deny
  from any source blocks the action.
- **Immutable parent deny:** Parent deny rules cannot be overridden by
  children (see [Section 11.2](#112-deny-immutability-invariant)).
- **Last-specific-wins for defaults:** In a merge chain, the most
  specific policy's defaults take precedence.
- **Most-restrictive for limits:** When comparing policies via
  `is_stricter_than()`, the comparison is per-field and all fields must
  be at least as restrictive.

### 18.2 Version Tracking

**[Pure Specification]**

Every GovernancePolicy MUST carry a `version` string. Policy version
changes MUST be auditable. Implementations MUST support comparing two
policy versions and reporting field-level diffs.

---

## 19. Serialization

### 19.1 YAML Round-Trip

**[Pure Specification]**

A GovernancePolicy serialized to YAML and deserialized back MUST produce
a semantically equivalent policy. The round-trip MUST NOT lose any field
values.

### 19.2 Dictionary Round-Trip

**[Pure Specification]**

A GovernancePolicy serialized to a dictionary via `to_dict()` and
reconstructed via `from_dict()` MUST produce a semantically equivalent
policy.

### 19.3 Unknown Fields

**[Pure Specification]**

When deserializing, unknown fields MUST be silently ignored. This
enables forward compatibility when newer policy versions add fields.

---

## 20. Conformance Requirements

### 20.1 Minimum Conformance

A conforming implementation MUST:

1. Support the full PolicyDocument schema (Section 3).
2. Support all nine condition operators (Section 5).
3. Support all four policy actions (Section 6).
4. Implement priority-ordered, first-match evaluation (Section 7).
5. Implement folder-level policy discovery and merge (Sections 11-12).
6. Enforce the deny immutability invariant (Section 11.2).
7. Implement path traversal protection (Section 12.4).
8. Support all four conflict resolution strategies (Section 13).
9. Support the ExternalPolicyBackend protocol (Section 14).
10. Enforce fail-closed semantics on all evaluation errors (Section 16).
11. Produce structured audit entries for every decision (Section 17).
12. Support YAML serialization for PolicyDocuments (Section 19).

### 20.2 Integration-Layer Conformance

Framework adapters that use GovernancePolicy MUST additionally:

1. Validate policies at construction time (Section 8.3).
2. Support all three pattern types (Section 9).
3. Enforce the tool call interception order (Section 10.3).
4. Enforce concurrency limits (Section 15).

---

## 21. Worked Examples

### 21.1 Basic Tool Blocking

**Policy:**
```yaml
version: "1.0"
name: "no-code-execution"
rules:
  - name: block-execute
    condition:
      field: tool_name
      operator: eq
      value: execute_code
    action: deny
    priority: 100
    message: "Code execution is not permitted in this environment"
defaults:
  action: allow
```

**Context:**
```json
{"tool_name": "execute_code", "agent_id": "assistant-1"}
```

**Expected Decision:**
- `allowed: false`
- `matched_rule: "block-execute"`
- `action: "deny"`
- `reason: "Code execution is not permitted in this environment"`

### 21.2 Folder-Level Merge with Deny Override Attempt

**Root `governance.yaml`:**
```yaml
version: "1.0"
name: "org-security"
rules:
  - name: no-delete
    condition:
      field: tool_name
      operator: eq
      value: delete_resource
    action: deny
    priority: 200
    message: "Deletion blocked by org policy"
```

**Subfolder `governance.yaml`:**
```yaml
version: "1.0"
name: "dev-environment"
rules:
  - name: no-delete
    condition:
      field: tool_name
      operator: eq
      value: delete_resource
    action: allow
    priority: 300
    override: true
    message: "Dev environment allows deletion"
```

**Expected Behavior:** The child's override attempt MUST be dropped
because the parent rule is a deny. The `no-delete` deny rule from the
root MUST remain in effect regardless of the child's higher priority.

### 21.3 External Backend Fallthrough

**Scenario:** YAML rules have no match. An OPA backend is registered.

**Expected Behavior:**
1. YAML rules evaluated first: no match.
2. OPA backend consulted: returns `{allowed: true, action: "allow"}`.
3. Decision: allowed, with audit entry including `backend: "opa"`.

### 21.4 Fail-Closed on Exception

**Scenario:** A regex pattern in a condition is somehow malformed at
evaluation time (should have been caught at construction, but edge case).

**Expected Behavior:**
- Decision: `allowed: false`, `action: "deny"`
- Reason: "Policy evaluation error -- access denied (fail closed)"
- Audit entry includes `error: true`
- Exception logged at ERROR level

### 21.5 Conflict Resolution: DENY_OVERRIDES

**Candidates:**
1. Rule "allow-read" from agent-scope policy: `action: allow, priority: 50`
2. Rule "block-all" from global policy: `action: deny, priority: 10`

**Strategy:** DENY_OVERRIDES

**Expected Result:**
- Winner: "block-all" (deny overrides regardless of priority)
- `conflict_detected: true`
- Trace: `["DENY_OVERRIDES: 1 deny rule(s) found", "Winner: block-all ..."]`

---

## 22. Security Considerations

### 22.1 Path Traversal

Policy discovery walks the filesystem. Implementations MUST validate
that action paths are within the configured root to prevent loading
policies from arbitrary locations (see Section 12.4).

### 22.2 Pattern Injection

Regex patterns in `blocked_patterns` and `matches` conditions are
compiled from user-provided strings. Implementations MUST catch
compilation errors at construction time. Implementations SHOULD consider
ReDoS (Regular Expression Denial of Service) when accepting patterns
from untrusted sources.

### 22.3 Context Tampering

The execution context is supplied by the framework adapter. If the
adapter runs in the same process as the agent, a compromised agent
could tamper with its own context. Implementations SHOULD use
out-of-process policy evaluation or signed context fields for
high-security deployments.

### 22.4 Fail-Closed as Security Boundary

The fail-closed behavior (Section 16) is a deliberate security design.
Systems that default to allow on error create exploitable failure modes.
Never change the default to fail-open.

---

## 23. References

- [RFC 2119: Key words for use in RFCs](https://datatracker.ietf.org/doc/html/rfc2119)
- [RFC 8174: Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words](https://datatracker.ietf.org/doc/html/rfc8174)
- [XACML 3.0: Combining Algorithms](https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html)
- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/)
- [Cedar Policy Language](https://www.cedarpolicy.com/)
- [Azure Policy: Deny Assignments](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects)
