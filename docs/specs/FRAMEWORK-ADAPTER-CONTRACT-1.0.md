<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Framework Adapter Contract -- Version 1.0

> **Status:** Draft · **Date:** 2025-07-28 · **Authors:** Agent Governance Toolkit team
>
> This specification defines the contract that all framework adapters
> MUST implement to integrate third-party AI agent frameworks with
> Agent OS governance. It covers the base integration abstract class,
> governance policy model, interceptor chain, native hook patterns,
> per-framework adapter requirements, health checks, deprecation
> strategy, audit surfaces, and failure semantics.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in
[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) and
[RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174).

---

## Table of Contents

1.  [Introduction](#1-introduction)
2.  [Terminology](#2-terminology)
3.  [Base Integration Contract](#3-base-integration-contract)
4.  [Governance Policy Model](#4-governance-policy-model)
5.  [Policy Interceptor Chain](#5-policy-interceptor-chain)
6.  [Native Hook Pattern](#6-native-hook-pattern)
7.  [LangChain Adapter](#7-langchain-adapter)
8.  [CrewAI Adapter](#8-crewai-adapter)
9.  [AutoGen Adapter](#9-autogen-adapter)
10. [OpenAI Assistants Adapter](#10-openai-assistants-adapter)
11. [Anthropic Adapter](#11-anthropic-adapter)
12. [Google ADK Adapter](#12-google-adk-adapter)
13. [Semantic Kernel Adapter](#13-semantic-kernel-adapter)
14. [OpenAI Agents SDK Adapter](#14-openai-agents-sdk-adapter)
15. [PydanticAI Adapter](#15-pydanticai-adapter)
16. [smolagents Adapter](#16-smolagents-adapter)
17. [Health Check Contract](#17-health-check-contract)
18. [Deprecation Pattern](#18-deprecation-pattern)
19. [Audit and Stats](#19-audit-and-stats)
20. [Failure Semantics](#20-failure-semantics)
21. [Security Considerations](#21-security-considerations)
22. [Conformance Requirements](#22-conformance-requirements)

---

## 1. Introduction

### 1.1 Purpose

Agent Governance Toolkit (AGT) integrates with 10+ AI agent frameworks
through a common adapter pattern. Each adapter extends a single
abstract base class -- `BaseIntegration` -- and maps the target
framework's native extensibility surface (middleware, hooks, handlers,
filters, plugins, callbacks, or capabilities) onto a unified
governance contract. This specification formalises that contract so
that new adapters can be written against a stable interface and
existing adapters can be validated for correctness.

### 1.2 Scope

This specification covers:

- **Base integration:** The `BaseIntegration` abstract class, its
  abstract and concrete methods, event system, and signal system.
- **Governance policy:** The `GovernancePolicy` dataclass, its
  validation rules, serialisation, and comparison semantics.
- **Execution context:** The `ExecutionContext` dataclass and its
  per-session lifecycle.
- **Interceptor chain:** `ToolCallRequest`, `ToolCallResult`,
  `PolicyInterceptor`, `ContentHashInterceptor`, and
  `CompositeInterceptor`.
- **Native hook pattern:** The recommended integration surface for
  each supported framework.
- **Per-framework adapters:** LangChain, CrewAI, AutoGen, OpenAI
  Assistants, Anthropic, Google ADK, Semantic Kernel, OpenAI Agents
  SDK, PydanticAI, and smolagents.
- **Cross-cutting concerns:** Health checks, deprecation, audit,
  failure semantics, and security.

### 1.3 Relationship to Other Specifications

| Specification | Relationship |
| --- | --- |
| Agent Hypervisor Execution Control 1.0 | Hypervisor may demote or quarantine agents governed by adapters |
| Agent OS Policy Engine 1.0 | Cedar/OPA evaluator is consumed by `BaseIntegration._evaluate_policy` |
| AgentMesh Identity and Trust 1.0 | Agent DIDs and trust scores may enrich `ExecutionContext` |

### 1.4 Design Principles

1. **Framework-native integration.** Adapters SHOULD use each
   framework's own extensibility mechanism (middleware, hooks,
   filters, plugins) rather than monkey-patching or proxying.
2. **Single base class.** All adapters inherit `BaseIntegration` to
   guarantee a uniform governance surface.
3. **Fail closed.** Any policy evaluation error MUST result in denial,
   never silent permission.
4. **Policy pinning.** Execution contexts deep-copy the active policy
   at creation time so that mid-session policy mutations never leak
   into running sessions.
5. **Graceful degradation.** Adapters MUST be importable even when
   their target SDK is not installed. Runtime operations MUST raise
   a clear `ImportError` with installation instructions.
6. **Deprecation over removal.** Legacy `wrap()`/`unwrap()` methods
   are deprecated in favour of native hook factories but MUST remain
   functional for at least two minor releases.

---

## 2. Terminology

| Term | Definition |
| --- | --- |
| **BaseIntegration** | Abstract base class that all framework adapters extend. Provides policy evaluation, event/signal systems, and execution context management. |
| **GovernancePolicy** | Dataclass defining the complete set of constraints, thresholds, and audit settings enforced on agent behaviour. |
| **ExecutionContext** | Per-session state object tracking call counts, token usage, drift baselines, and checkpoints. |
| **ToolCallRequest** | Vendor-neutral representation of a tool/function call submitted for interception. |
| **ToolCallResult** | Decision object returned by an interceptor: allowed/denied with reason and optional argument modifications. |
| **PolicyInterceptor** | Default interceptor that enforces `GovernancePolicy` rules against a `ToolCallRequest`. |
| **ContentHashInterceptor** | Interceptor that verifies tool identity via SHA-256 content hashing to defeat aliasing attacks. |
| **CompositeInterceptor** | Chain of interceptors evaluated in order; all MUST allow for the call to proceed. |
| **Native Hook** | The framework's own extensibility mechanism (middleware, hook, handler, filter, plugin, capability, or callback). |
| **Adapter Kernel** | A concrete `BaseIntegration` subclass for a specific framework (e.g. `LangChainKernel`, `CrewAIKernel`). |
| **PolicyViolationError** | Exception raised when a governance check fails. |
| **PolicyCheckResult** | Structured result from `pre_execute_check` / `post_execute_check` with category, reason, and allowed flag. |
| **Cedar Backend** | Declarative policy evaluation via Cedar policy language, consumed through `PolicyEvaluator`. |
| **Drift Detection** | Post-execution comparison of output against a baseline using `SequenceMatcher` to compute semantic drift. |
| **Deep Hooks** | Legacy integration pattern that monkey-patches tool registries, memory writes, and sub-agent spawn detection. |
| **Backpressure** | Concurrency throttling that begins when active executions reach `backpressure_threshold`. |

---

## 3. Base Integration Contract

### 3.1 Class Hierarchy

All adapter kernels MUST extend `BaseIntegration`:

```
BaseIntegration (ABC)
├── LangChainKernel
├── CrewAIKernel
├── AutoGenKernel
├── OpenAIKernel
├── AnthropicKernel
├── GoogleADKKernel
├── SemanticKernelWrapper
├── OpenAIAgentsKernel
├── PydanticAIKernel
└── SmolagentsKernel
```

**[Pure Specification]**

### 3.2 Constructor

The `BaseIntegration.__init__` method MUST accept:

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `policy` | `GovernancePolicy \| None` | `None` | Governance policy; defaults to `GovernancePolicy()` when `None`. |
| `evaluator` | `Any \| None` | `None` | Optional `PolicyEvaluator` for Cedar/OPA policy evaluation. |

The constructor MUST initialise:

| Attribute | Type | Description |
| --- | --- | --- |
| `policy` | `GovernancePolicy` | Active governance policy (never `None`). |
| `_evaluator` | `Any \| None` | Policy evaluator reference. |
| `contexts` | `dict[str, ExecutionContext]` | Map of agent ID to execution context. |
| `_signal_handlers` | `dict[str, Callable]` | Map of signal name to handler. |
| `_event_listeners` | `dict[GovernanceEventType, list[Callable]]` | Map of event type to listener list. |

**[Pure Specification]**

### 3.3 Abstract Methods

Adapters MUST implement:

| Method | Signature | Description |
| --- | --- | --- |
| `wrap` | `(agent: Any) -> Any` | Wrap an agent with governance. Returns a governed version. |
| `unwrap` | `(governed_agent: Any) -> Any` | Remove governance wrapper and return the original agent. |

**[Pure Specification]**

### 3.4 Factory Method -- `from_cedar`

`BaseIntegration` MUST provide a classmethod `from_cedar` that:

1. Accepts `policy_path` (file path), `policy_content` (inline Cedar),
   and `entities` (Cedar entities list).
2. Creates a `PolicyEvaluator` with a `CedarBackend`.
3. Passes the evaluator to `cls.__init__` via `**kwargs`.
4. Returns a fully configured adapter instance.

All subclasses inherit this factory without overriding it.
**[Pure Specification]**

### 3.5 Execution Context Management

The `create_context(agent_id: str) -> ExecutionContext` method MUST:

1. Deep-copy `self.policy` to pin the session policy.
2. Generate a unique `session_id` (truncated UUID).
3. Store the context in `self.contexts[agent_id]`.
4. Return the new `ExecutionContext`.

**[Pure Specification]**

### 3.6 Pre-Execution Checks

#### 3.6.1 Structured Result -- `pre_execute_check`

`pre_execute_check(ctx, input_data) -> PolicyCheckResult` MUST
evaluate checks in this order:

1. **Cedar/OPA gate:** If `_evaluator` is set, build a Cedar context
   via `_build_cedar_context` and call `_evaluate_policy`. Deny on
   failure. **[Pure Specification]**
2. **Call count:** Deny if `ctx.call_count >= policy.max_tool_calls`.
   **[Pure Specification]**
3. **Timeout:** Deny if elapsed wall-clock time exceeds
   `policy.timeout_seconds`. **[Pure Specification]**
4. **Blocked patterns:** Deny if `policy.matches_pattern(str(input_data))`
   returns any matches. **[Pure Specification]**
5. **Human approval:** Deny if `policy.require_human_approval` is
   `True`. **[Pure Specification]**
6. **Confidence threshold:** Deny if `input_data.confidence` is below
   `policy.confidence_threshold`. **[Pure Specification]**

Each denial MUST emit a `GovernanceEventType` event.

#### 3.6.2 Legacy Tuple -- `pre_execute`

`pre_execute(ctx, input_data) -> tuple[bool, str | None]` MUST
delegate to `pre_execute_check` and call `.to_legacy_tuple()` on
the result. **[Pure Specification]**

### 3.7 Post-Execution Checks

#### 3.7.1 Structured Result -- `post_execute_check`

`post_execute_check(ctx, output_data) -> PolicyCheckResult` MUST:

1. Increment `ctx.call_count`.
2. If `policy.drift_threshold > 0.0`, compute drift via
   `compute_drift(ctx, output_data)`. On the first call, store the
   baseline. On subsequent calls, compare via `SequenceMatcher`.
   If drift score exceeds threshold, emit `DRIFT_DETECTED`.
3. If `ctx.call_count` is a multiple of `policy.checkpoint_frequency`,
   append a checkpoint ID and emit `CHECKPOINT_CREATED`.

**[Pure Specification]**

#### 3.7.2 Legacy Tuple -- `post_execute`

`post_execute(ctx, output_data) -> tuple[bool, str | None]` MUST
delegate to `post_execute_check` and call `.to_legacy_tuple()`.
**[Pure Specification]**

### 3.8 Async Variants

The following async methods MUST exist and MUST delegate to their
synchronous counterparts:

| Async Method | Delegates To |
| --- | --- |
| `async_pre_execute_check` | `pre_execute_check` |
| `async_pre_execute` | `async_pre_execute_check` then `.to_legacy_tuple()` |
| `async_post_execute_check` | `post_execute_check` |
| `async_post_execute` | `async_post_execute_check` then `.to_legacy_tuple()` |

**[Pure Specification]**

### 3.9 Event System

#### 3.9.1 `on(event_type, callback)`

Register a callback for a `GovernanceEventType`. Multiple callbacks
per event type MUST be supported. **[Pure Specification]**

#### 3.9.2 `emit(event_type, data)`

Fire all registered callbacks for the given event type. Callback
exceptions MUST be caught and logged -- they MUST NOT interrupt the
governance flow. **[Pure Specification]**

#### 3.9.3 Event Types

| Event Type | Emitted When |
| --- | --- |
| `POLICY_CHECK` | Pre-execution policy check begins |
| `POLICY_VIOLATION` | A policy constraint is violated |
| `TOOL_CALL_BLOCKED` | A tool call is denied by policy or Cedar |
| `CHECKPOINT_CREATED` | A governance checkpoint is created |
| `DRIFT_DETECTED` | Output drift exceeds the configured threshold |

**[Pure Specification]**

### 3.10 Signal System

#### 3.10.1 `on_signal(signal, handler)`

Register a handler for a named signal. Only one handler per signal
name is stored (last-write-wins). **[Pure Specification]**

#### 3.10.2 `signal(agent_id, signal)`

Dispatch the named signal to the registered handler, passing
`agent_id` as the argument. If no handler is registered, the signal
is silently ignored. **[Pure Specification]**

### 3.11 Cedar Policy Integration

#### 3.11.1 `_build_cedar_context`

Build a context dict for `PolicyEvaluator` / `CedarBackend`:

| Field | Source |
| --- | --- |
| `agent_id` | From parameter |
| `action_type` | `"tool_call"`, `"model_call"`, or `"handoff"` |
| `tool_name` | Name of the tool being invoked |
| `tool_args` | Tool arguments dict |

Subclasses SHOULD override to add framework-specific fields.
**[Default Implementation]**

#### 3.11.2 `_evaluate_policy`

Consult the `PolicyEvaluator` if configured:

- If no evaluator is set, return `(True, "")`.
- If the evaluator returns `decision.allowed == False`, return
  `(False, decision.reason)`.
- If the evaluator raises an exception, **fail closed** and return
  `(False, "Policy evaluation error (fail-closed): {exc}")`.

**[Pure Specification]**

### 3.12 Drift Detection

`compute_drift(ctx, output_data) -> DriftResult | None` is a static
method that:

1. Serialises `output_data` to string and computes its SHA-256 hash.
2. On the first call (no baseline), stores the hash and text in `ctx`
   and returns `None`.
3. On subsequent calls, uses `SequenceMatcher` to compute similarity.
   Drift score = `1.0 - similarity` (0.0 = identical, 1.0 = completely
   different).
4. Returns a `DriftResult` with `score`, `exceeded`, `threshold`,
   `baseline_hash`, and `current_hash`.

**[Pure Specification]**

---

## 4. Governance Policy Model

### 4.1 GovernancePolicy Fields

| Field | Type | Default | Validation |
| --- | --- | --- | --- |
| `name` | `str` | `"default"` | Non-empty string |
| `max_tokens` | `int` | `4096` | Positive integer (> 0) |
| `max_tool_calls` | `int` | `10` | Non-negative integer (>= 0) |
| `allowed_tools` | `list[str]` | `[]` | List of strings; empty = all tools permitted |
| `blocked_patterns` | `list[str \| tuple[str, PatternType]]` | `[]` | Each entry is a substring string or `(pattern, PatternType)` tuple |
| `require_human_approval` | `bool` | `False` | -- |
| `timeout_seconds` | `int` | `300` | Positive integer (> 0) |
| `confidence_threshold` | `float` | `0.8` | Float in [0.0, 1.0] |
| `drift_threshold` | `float` | `0.15` | Float in [0.0, 1.0] |
| `log_all_calls` | `bool` | `True` | -- |
| `checkpoint_frequency` | `int` | `5` | Positive integer (> 0) |
| `max_concurrent` | `int` | `10` | Positive integer (> 0) |
| `backpressure_threshold` | `int` | `8` | Positive integer (> 0) |
| `version` | `str` | `"1.0.0"` | Non-empty string |

**[Pure Specification]**

### 4.2 Validation -- `__post_init__`

`GovernancePolicy.__post_init__` MUST call `validate()` which:

1. Validates positive integers: `max_tokens`, `timeout_seconds`,
   `max_concurrent`, `backpressure_threshold`, `checkpoint_frequency`.
2. Validates non-negative integers: `max_tool_calls`.
3. Validates float thresholds in [0.0, 1.0]: `confidence_threshold`,
   `drift_threshold`.
4. Validates `allowed_tools` is a list of strings.
5. Validates `blocked_patterns` entries and precompiles regex/glob
   patterns. `PatternType.REGEX` patterns are compiled with
   `re.IGNORECASE`. `PatternType.GLOB` patterns are translated via
   `fnmatch.translate` and compiled.
6. Validates `version` is a non-empty string.

Invalid inputs MUST raise `ValueError`. **[Pure Specification]**

### 4.3 Pattern Matching -- `matches_pattern`

`matches_pattern(text: str) -> list[str]` MUST:

1. Iterate compiled patterns.
2. For `SUBSTRING`: case-insensitive containment check.
3. For `REGEX` / `GLOB`: use the precompiled regex `.search()`.
4. Return a list of all matching pattern strings.

**[Pure Specification]**

### 4.4 Serialisation

| Method | Direction | Format |
| --- | --- | --- |
| `to_dict()` | Policy -> dict | Standard Python dict |
| `from_dict(data)` | dict -> Policy | Classmethod; filters unknown keys |
| `to_yaml()` | Policy -> YAML string | Via `yaml.dump` |
| `from_yaml(yaml_str)` | YAML string -> Policy | Via `yaml.safe_load`; MUST NOT use `yaml.load` |
| `save(filepath)` | Policy -> YAML file | Writes via `to_yaml()` |
| `load(filepath)` | YAML file -> Policy | Reads via `from_yaml()` |

**[Pure Specification]**

### 4.5 Policy Comparison

#### 4.5.1 `diff(other)`

Returns a dict mapping field names to `(self_value, other_value)`
tuples for fields that differ. **[Pure Specification]**

#### 4.5.2 `is_stricter_than(other)`

Returns `True` if this policy is more restrictive. Stricter means:
lower `max_tokens`, lower `max_tool_calls`, lower `timeout_seconds`,
lower `max_concurrent`, higher `confidence_threshold`, more
`blocked_patterns`, fewer `allowed_tools`, and `require_human_approval`
enabled. At least one field MUST actually differ.
**[Pure Specification]**

#### 4.5.3 `compare_versions(other)`

Returns a dict with `old_version`, `new_version`, `versions_differ`,
and `changes` (from `diff`). **[Pure Specification]**

### 4.6 Conflict Detection -- `detect_conflicts`

Returns a list of warning strings for contradictory settings:

| Conflict | Description |
| --- | --- |
| `backpressure_threshold >= max_concurrent` | Backpressure will never trigger |
| `max_tool_calls == 0` with non-empty `allowed_tools` | Tools allowed but no calls permitted |
| `confidence_threshold == 0.0` | Confidence checking effectively disabled |
| `timeout_seconds < 5` | May not allow reasonable execution time |

**[Default Implementation]**

---

## 5. Policy Interceptor Chain

### 5.1 ToolCallRequest

Vendor-neutral representation of a tool/function call:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `tool_name` | `str` | -- | Name of the tool being called |
| `arguments` | `dict[str, Any]` | -- | Arguments passed to the tool |
| `call_id` | `str` | `""` | Unique call identifier |
| `agent_id` | `str` | `""` | Agent making the call |
| `metadata` | `dict[str, Any]` | `{}` | Framework-specific metadata (e.g. `content_hash`) |

**[Pure Specification]**

### 5.2 ToolCallResult

Decision returned by an interceptor:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `allowed` | `bool` | -- | Whether the call is permitted |
| `reason` | `str \| None` | `None` | Human-readable denial reason |
| `modified_arguments` | `dict[str, Any] \| None` | `None` | Sanitised arguments (for argument rewriting) |
| `audit_entry` | `dict[str, Any] \| None` | `None` | Optional audit record |

**[Pure Specification]**

### 5.3 ToolCallInterceptor Protocol

Any object implementing the `intercept(request: ToolCallRequest) ->
ToolCallResult` method satisfies this protocol. The same interceptor
works across all framework adapters. **[Pure Specification]**

### 5.4 PolicyInterceptor

Default interceptor that enforces `GovernancePolicy` rules. Checks
are evaluated in order:

1. **Human approval:** If `policy.require_human_approval` is `True`,
   deny immediately.
2. **Allowed tools:** If `policy.allowed_tools` is non-empty and
   `request.tool_name` is not in the list, deny.
3. **Blocked patterns:** If `policy.matches_pattern(str(request.arguments))`
   returns matches, deny.
4. **Call count:** If `context.call_count >= policy.max_tool_calls`,
   deny.

All denials MUST return a `ToolCallResult(allowed=False, reason=...)`.
**[Pure Specification]**

### 5.5 ContentHashInterceptor

Verifies tool identity via SHA-256 content hashing:

| Mode | Behaviour |
| --- | --- |
| Strict (default) | Tools with no registered hash are denied |
| Non-strict | Tools with no registered hash are allowed with a warning |

The interceptor:

1. Looks up the expected hash for `request.tool_name`.
2. Reads the actual hash from `request.metadata["content_hash"]`.
3. If hashes mismatch, denies with a reason indicating possible
   tampering or wrapping.

**[Pure Specification]**

### 5.6 CompositeInterceptor

Chains multiple interceptors. Evaluation order:

1. Iterate interceptors in insertion order.
2. Call `interceptor.intercept(request)` on each.
3. If any interceptor returns `allowed=False`, return that result
   immediately (short-circuit).
4. If all interceptors allow, return `ToolCallResult(allowed=True)`.

The `add(interceptor)` method MUST return `self` for fluent chaining.
**[Pure Specification]**

---

## 6. Native Hook Pattern

### 6.1 Principle

Each framework provides its own extensibility mechanism. Adapters
MUST expose a factory method that returns an object compatible with
the framework's native hook registration system. The factory method
name SHOULD reflect the framework's terminology.

### 6.2 Framework Hook Mapping

| Framework | Factory Method | Returns | Framework Registration |
| --- | --- | --- | --- |
| LangChain | `as_middleware()` | `GovernanceMiddleware` | `create_agent(middleware=[...])` |
| CrewAI | `as_hooks()` | `GovernanceHooks` | Global hook decorators (`@before_tool_call`, etc.) |
| AutoGen | `as_handler()` | `GovernanceInterventionHandler` | `SingleThreadedAgentRuntime(intervention_handlers=[...])` |
| OpenAI Assistants | `wrap(assistant, client)` | `GovernedAssistant` | Proxy pattern (API wrapping) |
| Anthropic | `as_message_hook()` | `GovernanceMessageHook` | Non-invasive hook on `messages.create()` |
| Google ADK | `as_plugin()` | `GovernancePlugin` | `Runner(plugins=[...])` |
| Semantic Kernel | `as_filter()` | `GovernanceFunctionFilter` | `kernel.add_filter("function_invocation", ...)` |
| OpenAI Agents SDK | `as_hooks()` | `GovernanceRunHooks` | `Runner.run(hooks=...)` |
| PydanticAI | `as_capability()` | `GovernanceCapability` | `Agent(capabilities=[...])` |
| smolagents | `as_step_callback()` | `GovernanceStepCallback` | `Agent(step_callbacks=[...])` |

**[Pure Specification]**

### 6.3 Graceful Import

Each adapter MUST attempt to import its target framework at module
load time. If the import fails:

- A module-level flag (e.g. `_HAS_MIDDLEWARE`, `_HOOKS_AVAILABLE`)
  MUST be set to `False`.
- The adapter kernel class MUST remain importable.
- The native hook factory method MUST raise `RuntimeError` with a
  message indicating the required package and installation command.

**[Pure Specification]**

---

## 7. LangChain Adapter

### 7.1 LangChainKernel

Extends `BaseIntegration` with LangChain-specific governance.

#### 7.1.1 Constructor Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `policy` | `GovernancePolicy \| None` | `None` | Governance policy |
| `timeout_seconds` | `float` | `300.0` | Default timeout for async operations |
| `deep_hooks_enabled` | `bool` | `True` | Enable tool registry, memory, and sub-agent interception |
| `evaluator` | `Any` | `None` | Optional Cedar/OPA evaluator |

**[Default Implementation]**

#### 7.1.2 Internal State

| Attribute | Type | Description |
| --- | --- | --- |
| `_wrapped_agents` | `dict[int, Any]` | `id(wrapped)` -> original agent |
| `_tool_invocations` | `list[dict]` | Audit log of tool invocations |
| `_memory_audit_log` | `list[dict]` | Audit log of memory writes |
| `_delegation_chains` | `list[dict]` | Sub-agent delegation records |

### 7.2 `as_middleware()` -- GovernanceMiddleware

The `as_middleware()` factory returns a `GovernanceMiddleware` instance
implementing the LangChain `AgentMiddleware` interface. This is the
**recommended** integration path.

#### 7.2.1 Middleware Callbacks

| Callback | Intercepts | Governance Action |
| --- | --- | --- |
| `wrap_tool_call` | Tool invocations | Allowlist/blocklist check, blocked-pattern scan on arguments, Cedar/OPA gate |
| `wrap_model_call` | LLM invocations | Content filter on input messages, blocked-pattern scan on output |

**[Pure Specification]**

### 7.3 Deep Hooks (Legacy)

When `deep_hooks_enabled` is `True` and `wrap()` is called, the
adapter MUST apply:

1. **Tool registry interception:** Replace each tool's `_run` and
   `_arun` methods with governed wrappers that check allowlists,
   blocked patterns, and record invocations.
2. **Memory write interception:** Replace `memory.save_context` with
   a wrapper that validates against PII patterns and blocked patterns.
3. **Sub-agent spawn detection:** Monitor `invoke` calls for
   delegation patterns and enforce depth limits.

**[Default Implementation]**

### 7.4 PII Patterns

LangChain (and several other adapters) MUST scan for:

| Pattern | Detects |
| --- | --- |
| `\b\d{3}-\d{2}-\d{4}\b` | Social Security Numbers |
| Email regex | Email addresses |
| `password\|passwd\|secret\|token\|api[_-]?key` followed by `[:=]` | Credential leaks |

**[Default Implementation]**

---

## 8. CrewAI Adapter

### 8.1 CrewAIKernel

Extends `BaseIntegration` for CrewAI crews and agents.

### 8.2 `as_hooks()` -- GovernanceHooks

Returns a `GovernanceHooks` instance that registers four global
execution hooks with CrewAI (requires CrewAI 0.80+):

| Hook | Decorator | Governance Action |
| --- | --- | --- |
| `before_tool_call` | `@before_tool_call` | Allowlist/blocklist, blocked-pattern scan, Cedar/OPA `pre_execute` gate |
| `after_tool_call` | `@after_tool_call` | Blocked-pattern scan on tool output, drift detection via `post_execute` |
| `before_llm_call` | `@before_llm_call` | Content filter on input messages |
| `after_llm_call` | `@after_llm_call` | Blocked-pattern scan on LLM response |

**[Pure Specification]**

### 8.3 Hook Lifecycle

CrewAI hooks are **global** -- they apply to every crew in the
current process. The `GovernanceHooks` class MUST support:

| Method | Description |
| --- | --- |
| `register()` | Register the four hooks with CrewAI. Returns `self` for chaining. Raises `RuntimeError` if `crewai.hooks` is unavailable. |
| `unregister()` | Deactivate the hooks. |

Only one `GovernanceHooks` instance SHOULD be active at a time.
**[Pure Specification]**

### 8.4 Legacy `wrap()`

`wrap(crew)` is deprecated. It intercepts `kickoff()` on the crew
object to apply governance. Callers SHOULD migrate to `as_hooks()`.
**[Default Implementation]**

---

## 9. AutoGen Adapter

### 9.1 AutoGenKernel

Extends `BaseIntegration` for Microsoft AutoGen agents.

### 9.2 `as_handler()` -- GovernanceInterventionHandler

Returns a `GovernanceInterventionHandler` that intercepts all message
traffic through the AutoGen runtime (requires AutoGen v0.4+ with
`autogen_core`).

#### 9.2.1 Handler Methods

| Method | Intercepts | Governance Action |
| --- | --- | --- |
| `on_send` | Direct messages between agents | Tool call governance (`FunctionCall` messages) -- allowlist, blocked-pattern scan; content governance; Cedar/OPA `pre_execute` gate |
| `on_publish` | Broadcast messages | Blocked-pattern scan, PII detection |
| `on_response` | Agent responses | Blocked-pattern scan on output, `post_execute` drift detection |

**[Pure Specification]**

### 9.3 Message Blocking -- `DropMessage`

When a policy violation is detected in `on_send` or `on_publish`,
the handler MUST return `DropMessage` (from `autogen_core`) to
silently block the message from reaching its target. The violation
is recorded in the audit log. **[Pure Specification]**

### 9.4 FunctionCall Detection

If `autogen_core.FunctionCall` is importable, the handler MUST
detect `FunctionCall` instances in `on_send` and apply tool-specific
governance (allowlist, blocklist, argument scanning). When
`FunctionCall` is not available, tool-level governance is skipped
and only content-level scanning applies. **[Default Implementation]**

### 9.5 Legacy `govern()`

`govern(agent1, agent2, ...)` is deprecated. It patches agent
`send` methods directly. Callers SHOULD migrate to `as_handler()`.
**[Default Implementation]**

---

## 10. OpenAI Assistants Adapter

### 10.1 OpenAIKernel

Extends `BaseIntegration` for the OpenAI Assistants API.

#### 10.1.1 Constructor Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `policy` | `GovernancePolicy \| None` | `None` | Governance policy |
| `max_retries` | `int` | `3` | Retry attempts for transient errors |
| `timeout_seconds` | `float` | `300.0` | Default operation timeout |

**[Default Implementation]**

### 10.2 `wrap(assistant, client)` -- GovernedAssistant

Unlike other adapters, OpenAI Assistants require both an assistant
object and a client. The `wrap` method:

1. Creates an `AssistantContext` (extends `ExecutionContext` with
   `assistant_id`, `thread_ids`, `run_ids`, `function_calls`,
   `prompt_tokens`, `completion_tokens`).
2. Returns a `GovernedAssistant` proxy.

The `client` parameter is REQUIRED; omitting it MUST raise
`TypeError`. **[Pure Specification]**

### 10.3 GovernedAssistant

The proxy MUST implement:

| Method | Description |
| --- | --- |
| `register_tool(name, func)` | Register a tool function for automatic execution |
| `create_thread(**kwargs)` | Create a new conversation thread |
| `add_message(thread_id, content, **kwargs)` | Add a message to a thread |
| `run(thread_id, **kwargs)` | Execute a governed run |
| `run_stream(thread_id, **kwargs)` | Execute a governed streaming run |

**[Pure Specification]**

### 10.4 Run Cancellation (SIGKILL / SIGSTOP)

| Method | Description |
| --- | --- |
| `cancel_run(thread_id, run_id, client)` | Cancel a run via the OpenAI API (SIGKILL equivalent). Best-effort; errors are silently logged. |
| `is_cancelled(run_id)` | Check whether a run has been cancelled. |

The adapter MUST maintain a `_cancelled_runs: set[str]` to track
cancelled run IDs. **[Pure Specification]**

### 10.5 Retry with Backoff

`retry_with_backoff(fn, *args, max_retries=3, base_delay=1.0,
max_delay=30.0)` MUST:

1. Call `fn(*args, **kwargs)`.
2. On transient errors (`RateLimitError`, `APIConnectionError`,
   `Timeout`, `APITimeoutError`), retry with exponential backoff
   plus jitter.
3. On non-transient errors or after exhausting retries, re-raise.

**[Default Implementation]**

---

## 11. Anthropic Adapter

### 11.1 AnthropicKernel

Extends `BaseIntegration` for the Anthropic Messages API.

#### 11.1.1 Constructor Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `policy` | `GovernancePolicy \| None` | `None` | Governance policy |
| `max_retries` | `int` | `3` | Retry attempts |
| `timeout_seconds` | `float` | `300.0` | Default timeout |
| `evaluator` | `Any` | `None` | Optional Cedar/OPA evaluator |

**[Default Implementation]**

### 11.2 `as_message_hook()` -- GovernanceMessageHook

The recommended integration pattern. Returns a `GovernanceMessageHook`
that governs `messages.create()` calls without wrapping or proxying
the Anthropic client. **[Pure Specification]**

### 11.3 `wrap(client)` -- GovernedAnthropicClient

Legacy proxy that intercepts all `client.messages.create()` calls.

The adapter creates an `AnthropicContext` (extends `ExecutionContext`
with `model`, `message_ids`, `tool_use_calls`, `prompt_tokens`,
`completion_tokens`). **[Default Implementation]**

### 11.4 Request Cancellation

The adapter MUST maintain a `_cancelled_requests: set[str]` for
tracking cancelled message requests. A `RequestCancelledException`
is raised when a cancelled request is detected.
**[Pure Specification]**

---

## 12. Google ADK Adapter

### 12.1 GoogleADKKernel

Extends `BaseIntegration` for Google Agent Development Kit workflows.

### 12.2 PolicyConfig

ADK-specific policy configuration:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `max_tool_calls` | `int` | `50` | Maximum tool invocations |
| `max_agent_calls` | `int` | `20` | Maximum agent lifecycle events |
| `timeout_seconds` | `int` | `300` | Global timeout |
| `allowed_tools` | `list[str]` | `[]` | Tool allowlist |
| `blocked_tools` | `list[str]` | `[]` | Tool blocklist |
| `blocked_patterns` | `list[str]` | `[]` | Content blocklist |
| `pii_detection` | `bool` | `True` | Enable PII scanning |
| `log_all_calls` | `bool` | `True` | Audit all calls |
| `require_human_approval` | `bool` | `False` | Require approval for sensitive tools |
| `sensitive_tools` | `list[str]` | `[]` | Tools requiring explicit approval |
| `max_budget` | `float \| None` | `None` | Optional cost budget |

**[Default Implementation]**

### 12.3 `as_plugin()` -- GovernancePlugin

Returns a `GovernancePlugin` (extends ADK `BasePlugin` when
available) for runner-scoped governance. This is the **recommended**
integration pattern.

#### 12.3.1 Plugin Callbacks

| Callback | Lifecycle Point | Governance Action |
| --- | --- | --- |
| `before_tool_callback` | Before each tool execution | Allowlist/blocklist, blocked-pattern scan, human approval check |
| `after_tool_callback` | After each tool execution | Output scan, drift detection |
| `before_agent_callback` | Before agent lifecycle event | Agent call budget check |
| `after_agent_callback` | After agent lifecycle event | Agent call count tracking |

**[Pure Specification]**

### 12.4 Budget Limits

The `GovernancePlugin` MUST enforce:

- `max_tool_calls`: Total tool invocations across the run.
- `max_agent_calls`: Total agent lifecycle events across the run.

When either limit is reached, further calls MUST be denied.
**[Pure Specification]**

### 12.5 ADKExecutionContext

Extends `ExecutionContext` with:

| Field | Type | Description |
| --- | --- | --- |
| `invocation_id` | `str` | Current ADK invocation identifier |
| `agent_names` | `list[str]` | Agent names encountered during the run |
| (token tracking) | `int` | Cumulative token usage fields |

**[Default Implementation]**

---

## 13. Semantic Kernel Adapter

### 13.1 SemanticKernelWrapper

Extends `BaseIntegration` for Microsoft Semantic Kernel.

#### 13.1.1 Constructor Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `kernel` | `Any \| None` | `None` | Optional SK instance (can be provided via `wrap`) |
| `policy` | `GovernancePolicy \| None` | `None` | Governance policy |
| `timeout_seconds` | `float` | `300.0` | Default timeout |
| `evaluator` | `Any` | `None` | Optional Cedar/OPA evaluator |

**[Default Implementation]**

### 13.2 `as_filter()` -- GovernanceFunctionFilter

Returns a `GovernanceFunctionFilter` compatible with Semantic Kernel's
native `add_filter()` API. This is the **recommended** integration
pattern:

```python
kernel.add_filter("auto_function_invocation", wrapper.as_filter())
kernel.add_filter("function_invocation", wrapper.as_filter())
```

The filter intercepts function invocations and applies governance
checks before and after execution. **[Pure Specification]**

### 13.3 Signal Support

The `SemanticKernelWrapper` MUST support POSIX-style signals:

| Signal | Method | Behaviour |
| --- | --- | --- |
| SIGSTOP | `signal_stop()` | Pause execution; sets `_stopped = True` |
| SIGCONT | `signal_continue()` | Resume execution; sets `_stopped = False` |
| SIGKILL | `signal_kill()` | Terminate execution; sets `_killed = True` |

Governed operations MUST check `_stopped` and `_killed` flags before
proceeding. **[Pure Specification]**

### 13.4 SKContext

Extends `ExecutionContext` with:

| Field | Type | Description |
| --- | --- | --- |
| `kernel_id` | `str` | Unique kernel instance identifier |
| `plugins_loaded` | `list[str]` | Names of loaded plugins |
| `functions_invoked` | `list[dict]` | Function invocation audit log |
| `memory_operations` | `list[dict]` | Memory save/search audit log |
| `prompt_tokens` | `int` | Cumulative prompt tokens |
| `completion_tokens` | `int` | Cumulative completion tokens |

**[Default Implementation]**

### 13.5 Legacy `wrap(kernel)` -- GovernedSemanticKernel

Deprecated. Returns a `GovernedSemanticKernel` proxy. Callers SHOULD
migrate to `as_filter()`. **[Default Implementation]**

---

## 14. OpenAI Agents SDK Adapter

### 14.1 OpenAIAgentsKernel

Extends `BaseIntegration` for the OpenAI Agents SDK.

#### 14.1.1 Constructor Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `policy` | `GovernancePolicy \| None` | `None` | Governance policy (or built from convenience kwargs) |
| `on_violation` | `Callable \| None` | `None` | Optional violation callback |
| `evaluator` | `Any` | `None` | Optional Cedar/OPA evaluator |
| `max_tool_calls` | `int` | `50` | Max tool invocations |
| `max_handoffs` | `int` | `5` | Max agent handoffs |
| `timeout_seconds` | `int` | `300` | Global timeout |
| `allowed_tools` | `list[str] \| None` | `None` | Tool allowlist |
| `blocked_tools` | `list[str] \| None` | `None` | Tool blocklist |
| `blocked_patterns` | `list[str] \| None` | `None` | Content blocklist |
| `require_human_approval` | `bool` | `False` | Require approval |

When `policy` is `None`, a `GovernancePolicy` is constructed from
the convenience kwargs. **[Default Implementation]**

### 14.2 `as_hooks()` -- GovernanceRunHooks

Returns a `GovernanceRunHooks` instance implementing the SDK's
native `RunHooks` lifecycle. This is the **recommended** integration
path, passed directly to `Runner.run(hooks=...)`.

#### 14.2.1 Lifecycle Callbacks

| Callback | Lifecycle Point | Governance Action |
| --- | --- | --- |
| `on_agent_start` | Agent begins processing | Content filter on input |
| `on_agent_end` | Agent finishes processing | Output audit |
| `on_tool_start` | Before tool execution | Allowlist/blocklist enforcement via tool name check |
| `on_tool_end` | After tool execution | Output scan, drift detection |
| `on_handoff` | Agent-to-agent handoff | Handoff count enforcement against `max_handoffs` |

**[Pure Specification]**

### 14.3 `create_tool_guard`

Factory that wraps a tool function with governance checks. The
guarded tool checks allowlists, blocklists, and blocked patterns
before delegating to the original function. **[Default Implementation]**

### 14.4 `create_guardrail`

Factory that creates an input/output guardrail function compatible
with the Agents SDK guardrail system. **[Default Implementation]**

### 14.5 Handoff Limit -- `max_handoffs`

The adapter MUST track handoff count per run. When `max_handoffs`
is reached, the `on_handoff` callback MUST raise
`PolicyViolationError`. **[Pure Specification]**

### 14.6 Legacy `wrap()` / `wrap_runner()`

Both are deprecated. `wrap(agent)` returns a governed agent proxy.
`wrap_runner(Runner)` returns a governed runner class. Callers SHOULD
migrate to `as_hooks()`. **[Default Implementation]**

---

## 15. PydanticAI Adapter

### 15.1 PydanticAIKernel

Extends `BaseIntegration` for PydanticAI agent workflows.

#### 15.1.1 Constructor Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `policy` | `GovernancePolicy \| None` | `None` | Governance policy |
| `approval_callback` | `Callable[[str, dict], bool] \| None` | `None` | Human approval callback |
| `evaluator` | `Any` | `None` | Optional Cedar/OPA evaluator |

**[Default Implementation]**

### 15.2 `as_capability()` -- GovernanceCapability

Returns a `GovernanceCapability` for PydanticAI's native hook system.
Passed to `Agent(capabilities=[...])`. This is the **recommended**
integration pattern.

The capability intercepts tool calls through PydanticAI's
`Hooks`/`Capability` system, enforcing governance without
monkey-patching tool functions. **[Pure Specification]**

### 15.3 Human Approval Flow

When `policy.require_human_approval` is `True` or a tool is in the
sensitive tools list:

1. The adapter raises `HumanApprovalRequired(tool_name, arguments)`.
2. If `approval_callback` is set, the callback is invoked with
   `(tool_name, arguments)`. If it returns `False`, execution is
   denied.
3. `HumanApprovalRequired` extends `PolicyViolationError`.

**[Pure Specification]**

### 15.4 Audit Log

The adapter MUST maintain an `_audit_log: list[dict]` with entries
containing:

| Field | Type | Description |
| --- | --- | --- |
| `timestamp` | `str` | ISO 8601 UTC timestamp |
| `event_type` | `str` | Event category |
| `tool_name` | `str` | Tool involved |
| `allowed` | `bool` | Decision |
| `reason` | `str` | Denial reason (empty if allowed) |
| `arguments` | `dict` | Tool arguments |
| `agent_id` | `str` | Agent identifier |

Entries are recorded only when `policy.log_all_calls` is `True`.
**[Default Implementation]**

### 15.5 Legacy `wrap(agent)`

Deprecated. Wraps `run` and `run_sync` on the PydanticAI agent.
Callers SHOULD migrate to `as_capability()`.
**[Default Implementation]**

---

## 16. smolagents Adapter

### 16.1 SmolagentsKernel

Extends `BaseIntegration` for HuggingFace smolagents (`CodeAgent`,
`ToolCallingAgent`).

#### 16.1.1 Constructor Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `policy` | `PolicyConfig \| None` | `None` | ADK-style policy config (or built from convenience kwargs) |
| `on_violation` | `Callable \| None` | `None` | Violation callback |
| `evaluator` | `Any` | `None` | Optional Cedar/OPA evaluator |
| `max_tool_calls` | `int` | `50` | Max tool invocations |
| `max_agent_calls` | `int` | `20` | Max agent calls |
| `timeout_seconds` | `int` | `300` | Global timeout |
| `allowed_tools` | `list[str] \| None` | `None` | Tool allowlist |
| `blocked_tools` | `list[str] \| None` | `None` | Tool blocklist |
| `blocked_patterns` | `list[str] \| None` | `None` | Content blocklist |
| `require_human_approval` | `bool` | `False` | Require approval |
| `sensitive_tools` | `list[str] \| None` | `None` | Tools needing approval |
| `max_budget` | `float \| None` | `None` | Cost budget |

A `GovernancePolicy` is derived from `PolicyConfig` and passed to
`BaseIntegration.__init__`. **[Default Implementation]**

### 16.2 `as_step_callback()` -- GovernanceStepCallback

Returns a `GovernanceStepCallback` compatible with smolagents'
native `step_callbacks` system. This is the **recommended**
integration pattern:

```python
agent = CodeAgent(
    tools=[...],
    model=model,
    step_callbacks=[kernel.as_step_callback()],
)
```

The callback is invoked after each agent step and applies governance
checks to the step's tool calls and outputs. **[Pure Specification]**

### 16.3 Approval Queue

The adapter MUST support a human-in-the-loop approval workflow:

| Method | Description |
| --- | --- |
| `approve(call_id)` | Approve a pending tool call |
| `deny(call_id)` | Deny a pending tool call |
| `get_pending_approvals()` | Return all pending approval requests |

Internal state:

| Attribute | Type | Description |
| --- | --- | --- |
| `_pending_approvals` | `dict[str, dict]` | Pending approval requests keyed by call ID |
| `_approved_calls` | `dict[str, bool]` | Approval decisions keyed by call ID |

**[Pure Specification]**

### 16.4 Legacy `wrap(agent)`

Deprecated. Intercepts each tool's `forward` method with a governed
wrapper. The original `forward` is stored in `_original_forwards`
for restoration via `unwrap()`. Callers SHOULD migrate to
`as_step_callback()`. **[Default Implementation]**

### 16.5 Tool Extraction

The adapter MUST extract tools from the smolagents agent via:

1. `agent.toolbox.tools` (if `toolbox` has a `.tools` dict).
2. `agent.toolbox` directly (if it is a plain dict).
3. Empty dict if no toolbox is found.

**[Default Implementation]**

---

## 17. Health Check Contract

### 17.1 Method Signature

Each adapter kernel SHOULD implement:

```python
def health_check(self) -> dict[str, Any]:
```

### 17.2 Response Schema

| Field | Type | Description |
| --- | --- | --- |
| `status` | `str` | `"healthy"`, `"degraded"`, or `"unhealthy"` |
| `backend` | `str` | Framework name (e.g. `"openai"`, `"langchain"`) |
| `backend_connected` | `bool` | Whether the backend client is connected |
| `last_error` | `str \| None` | Last recorded error message |
| `uptime_seconds` | `float` | Seconds since adapter instantiation |

**[Default Implementation]**

### 17.3 Status Derivation

| Condition | Status |
| --- | --- |
| `_last_error` is set | `"degraded"` |
| No clients / no errors | `"healthy"` |
| Backend unreachable | `"unhealthy"` |

**[Default Implementation]**

### 17.4 `_last_error` State

Adapters MUST maintain a `_last_error: str | None` attribute. It
is set to `None` on construction and updated whenever a backend
operation fails. It is NOT automatically cleared -- it reflects the
most recent error. **[Pure Specification]**

---

## 18. Deprecation Pattern

### 18.1 Principle

All adapters follow the same deprecation trajectory: the legacy
`wrap()` / `unwrap()` proxy-based integration is deprecated in
favour of native hook factory methods. The legacy methods MUST remain
functional for backward compatibility but MUST emit
`DeprecationWarning` on every call.

### 18.2 Per-Adapter Deprecation

| Adapter | Deprecated Method | Replacement |
| --- | --- | --- |
| `LangChainKernel` | `wrap(chain)` | `as_middleware()` |
| `CrewAIKernel` | `wrap(crew)` | `as_hooks()` |
| `AutoGenKernel` | `govern(agent1, ...)` | `as_handler()` |
| `OpenAIKernel` | `wrap_assistant(assistant, client)` | `wrap(assistant, client)` |
| `AnthropicKernel` | `wrap(client)` | `as_message_hook()` |
| `GoogleADKKernel` | `wrap(agent)` | `as_plugin()` |
| `SemanticKernelWrapper` | `wrap(kernel)` | `as_filter()` |
| `OpenAIAgentsKernel` | `wrap(agent)`, `wrap_runner(Runner)` | `as_hooks()` |
| `PydanticAIKernel` | `wrap(agent)` | `as_capability()` |
| `SmolagentsKernel` | `wrap(agent)` | `as_step_callback()` |

### 18.3 Warning Format

All deprecation warnings MUST use `stacklevel=2` and include the
replacement method name:

```python
warnings.warn(
    "XKernel.wrap() is deprecated. Use as_native_hook() ...",
    DeprecationWarning,
    stacklevel=2,
)
```

**[Pure Specification]**

---

## 19. Audit and Stats

### 19.1 Audit Log Pattern

Adapters that maintain an audit log MUST expose it via a read-only
property or method:

| Method / Property | Returns | Description |
| --- | --- | --- |
| `audit_log` (property) | `list[dict]` | Full audit log as a shallow copy |
| `get_audit_log()` | `list[dict]` | Equivalent method form |

Each audit entry MUST contain at minimum:

| Field | Type | Description |
| --- | --- | --- |
| `timestamp` | `str` | ISO 8601 timestamp |
| `event_type` | `str` | Event category |
| `tool_name` | `str` | Tool involved (empty string if N/A) |
| `allowed` | `bool` | Whether the action was permitted |
| `reason` | `str` | Denial reason (empty if allowed) |

**[Pure Specification]**

### 19.2 Violations Pattern

Adapters that track violations MUST store them in a
`_violations: list[PolicyViolationError]` attribute. The list
SHOULD be accessible via:

```python
def get_violations(self) -> list[PolicyViolationError]:
    return list(self._violations)
```

**[Default Implementation]**

### 19.3 Stats Pattern

Adapters SHOULD expose operational statistics via a `get_stats()`
method returning a dict with at least:

| Field | Type | Description |
| --- | --- | --- |
| `total_tool_calls` | `int` | Total tool invocations |
| `total_violations` | `int` | Total policy violations |
| `uptime_seconds` | `float` | Time since adapter creation |

Additional framework-specific fields (e.g. `total_handoffs`,
`total_agent_calls`, `budget_spent`) MAY be included.
**[Default Implementation]**

---

## 20. Failure Semantics

### 20.1 Fail Closed

All policy evaluation operations MUST fail closed:

| Operation | Failure Behaviour |
| --- | --- |
| Cedar/OPA evaluation error | Deny access |
| `PolicyInterceptor` exception | Deny access |
| `ContentHashInterceptor` missing hash (strict) | Deny access |
| `CompositeInterceptor` any interceptor denies | Deny access (short-circuit) |
| Timeout exceeded | Deny further operations |
| Call count exceeded | Deny further tool calls |
| Event listener exception | Log warning, continue governance flow |

**[Pure Specification]**

### 20.2 PolicyViolationError

Adapters MUST raise `PolicyViolationError` (from
`agent_os.exceptions`) when a governance check fails during a
governed operation. The exception MUST carry a human-readable
message describing the violation.

Framework-specific subclasses (e.g. `HumanApprovalRequired` in
PydanticAI, `RequestCancelledException` in Anthropic) MAY extend
`PolicyViolationError`. **[Pure Specification]**

### 20.3 Timeout Handling

When `policy.timeout_seconds` is exceeded:

1. `pre_execute_check` MUST return a denial result with the elapsed
   time and configured timeout in the reason.
2. The adapter MUST emit a `POLICY_VIOLATION` event.
3. Framework-specific cancellation (e.g. OpenAI run cancellation,
   Anthropic request cancellation) SHOULD be triggered if applicable.

**[Pure Specification]**

### 20.4 Graceful Import Failures

When a framework SDK is not installed:

- The adapter kernel MUST be importable without error.
- Calling the native hook factory MUST raise `RuntimeError` with
  installation instructions.
- Calling `wrap()` SHOULD raise `ImportError` with installation
  instructions.

**[Pure Specification]**

---

## 21. Security Considerations

### 21.1 Content Hash Verification

The `ContentHashInterceptor` defeats tool-wrapping and aliasing
attacks by verifying that the callable behind a tool name has the
same SHA-256 source hash that was recorded at registration time. In
strict mode (default), tools without a registered hash are blocked.
Adapters SHOULD populate `request.metadata["content_hash"]` when
constructing `ToolCallRequest` objects.

### 21.2 PII and Secrets Detection

Adapters MUST NOT log raw argument values when PII patterns match.
The PII patterns (SSN, email, credential leak) are defined at module
scope and applied during memory write interception (LangChain),
content scanning (AutoGen `on_publish`), and tool argument validation.

### 21.3 Policy Pinning

`create_context` deep-copies the active policy so that policy
mutations after session creation do not weaken the constraints on
running sessions. This prevents a time-of-check/time-of-use (TOCTOU)
vulnerability where an attacker mutates `kernel.policy` after
context creation.

### 21.4 Blocked Pattern Bypass

Pattern matching is case-insensitive for all `PatternType` variants.
Implementations MUST NOT allow case-sensitivity bypass. Regex
patterns are compiled with `re.IGNORECASE` and glob patterns are
translated and compiled with `re.IGNORECASE`.

### 21.5 Fail-Closed Policy Evaluation

The `_evaluate_policy` method catches all exceptions from the
evaluator and denies access. This ensures that a misconfigured or
crashing policy engine never silently permits an action.

### 21.6 Lazy Import Isolation

Framework adapters are loaded lazily via `__getattr__` in the
`integrations/__init__.py` module to avoid a 40-60 second cold-start
penalty from eagerly importing heavy SDKs. This also isolates import
failures -- an unavailable framework does not prevent importing other
adapters.

### 21.7 Signal Handler Isolation

Signal handlers registered via `on_signal` are stored per-instance.
A compromised adapter instance cannot inject signal handlers into
other instances.

---

## 22. Conformance Requirements

### 22.1 MUST Requirements

An adapter implementation is conformant if it satisfies all MUST
requirements:

1.  Extends `BaseIntegration`.
2.  Implements `wrap(agent) -> Any` (abstract method).
3.  Implements `unwrap(governed_agent) -> Any` (abstract method).
4.  Constructor accepts `policy` and `evaluator` parameters and
    forwards them to `BaseIntegration.__init__`.
5.  `create_context` deep-copies the policy.
6.  `pre_execute_check` evaluates checks in the specified order and
    emits events on denial.
7.  `post_execute_check` increments call count and performs drift
    detection when configured.
8.  Cedar/OPA evaluation fails closed on exception.
9.  Event listener exceptions do not interrupt governance flow.
10. Native hook factory raises `RuntimeError` when the target SDK is
    not installed.
11. Deprecated methods emit `DeprecationWarning` with `stacklevel=2`.
12. `PolicyViolationError` is raised on governance failures during
    governed operations.
13. Timeout and call-count limits are enforced in pre-execution
    checks.
14. Blocked-pattern matching is case-insensitive.

### 22.2 SHOULD Requirements

1.  Expose a native hook factory method (`as_middleware`, `as_hooks`,
    `as_handler`, `as_filter`, `as_plugin`, `as_capability`,
    `as_step_callback`, or `as_message_hook`).
2.  Implement `health_check()` returning the standard response schema.
3.  Maintain `_last_error` state.
4.  Provide `get_audit_log()`, `get_violations()`, and `get_stats()`
    methods.
5.  Support PII pattern detection in memory writes and content scans.
6.  Populate `content_hash` in `ToolCallRequest.metadata` when
    constructing requests.

### 22.3 Test Coverage

Conformance tests MUST cover:

- `BaseIntegration` subclass relationship.
- `wrap` / `unwrap` round-trip identity.
- `pre_execute_check` denial for each check type (call count,
  timeout, blocked pattern, human approval, confidence threshold).
- `post_execute_check` call count increment and checkpoint creation.
- Drift detection baseline storage and threshold enforcement.
- `CompositeInterceptor` short-circuit behaviour.
- `ContentHashInterceptor` strict and non-strict modes.
- `GovernancePolicy` validation (positive integers, float ranges,
  pattern compilation).
- `GovernancePolicy` serialisation round-trip (`to_yaml` /
  `from_yaml`, `to_dict` / `from_dict`).
- `is_stricter_than` comparison semantics.
- Event emission and listener error isolation.
- Signal registration and dispatch.
- Native hook factory `RuntimeError` when SDK is missing.
- Deprecation warning emission from legacy methods.
- Health check response schema.
- `from_cedar` factory method.

---

## References

- [Cedar Policy Language](https://www.cedarpolicy.com/)
- [RFC 2119 -- Key words for use in RFCs](https://datatracker.ietf.org/doc/html/rfc2119)
- [RFC 8174 -- Ambiguity of Uppercase vs Lowercase](https://datatracker.ietf.org/doc/html/rfc8174)
- Agent OS Policy Engine 1.0 (companion specification)
- Agent Hypervisor Execution Control 1.0 (companion specification)
