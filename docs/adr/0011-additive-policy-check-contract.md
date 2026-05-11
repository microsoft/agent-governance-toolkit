# ADR 0011: Additive Policy Check Contract

- Status: proposed
- Date: 2026-04-29

## Context

AGT currently exposes policy outcomes through several independent contracts. The
same denial can appear as a declarative `PolicyDecision`, a legacy
`BaseIntegration` `(allowed, reason)` tuple, or an adapter-raised
`PolicyViolationError`. Those paths have different message shapes, different
exception identities, and different levels of detail. Declarative policy rules
can be safe when authors provide a user-facing message, but integration and
adapter paths often interpolate internal policy values such as regex patterns,
allow-lists, limits, or timeouts into strings that hosts may surface to users.

The verified reproductions showed this split clearly. `PolicyEvaluator.evaluate`
can return a safe authored reason for an SSN-blocking rule, while
`BaseIntegration.pre_execute` returns a reason that includes the raw SSN regex.
Adapter-level tool checks raise yet another error string that also includes the
matched pattern and adds tool context. The result is both a disclosure issue and
a migration problem: hosts cannot reliably catch or classify governance denials
without substring-matching free-form English, and adapters duplicate their own
exception classes instead of using the canonical one.

This ADR does not supersede ADR 0009. ADR 0009 covers RFC 9334 RATS architecture
alignment and remains independent of policy error sanitization.

## Decision

Add a structured, additive policy-check contract for integration-layer policy
outcomes while preserving every existing public shape.

Introduce a new `agent_os.policies.decision` module containing
`ViolationCategory` and `PolicyCheckResult`. `ViolationCategory` is the stable,
typed denial taxonomy for hosts and adapters. `PolicyCheckResult` carries the
legacy allow/deny outcome plus separate fields for safe public text, restricted
detail, matched policy internals, optional matched user text, scope, operation,
tool name, and audit metadata. It also provides serializers for the two intended
views: `to_legacy_tuple()` for existing callers and `to_public_dict()` for host
responses.

Introduce `agent_os.policies.decision_factory` as the only place integration
policy denial results are constructed. The factory set includes
`deny_blocked_pattern_input`, `deny_blocked_pattern_tool`,
`deny_blocked_pattern_output`, `deny_blocked_pattern_memory`,
`deny_blocked_tool`, `deny_not_allowed_tool`, `deny_max_tool_calls`,
`deny_timeout`, `deny_human_approval`, `deny_confidence_threshold`, and generic
policy-error builders. Each factory sets a fixed `public_message` keyed by
category and places sensitive values only in restricted fields such as `detail`,
`matched_pattern`, and `audit_entry`.

Extend the canonical `agent_os.exceptions.PolicyViolationError` with an
additive `from_check_result` classmethod. The existing constructor forms remain
valid, `str(e)` remains based on `args[0]`, and legacy instances have
`e.check_result is None`. Exceptions created from a `PolicyCheckResult` surface
only the sanitized `public_message` through `str(e)` while retaining structured
details for server-side audit.

Add opt-in `BaseIntegration` check methods beside the existing tuple methods:
`pre_execute_check`, `post_execute_check`, `async_pre_execute_check`, and
`async_post_execute_check`. These return `PolicyCheckResult`. Existing
`pre_execute`, `post_execute`, `async_pre_execute`, and `async_post_execute`
signatures and return types are preserved and are implemented as wrappers that
return `result.to_legacy_tuple()`.

The change is purely additive. No existing signature, return type, import path,
exception constructor, declarative `PolicyDecision` field, or event payload is
removed or renamed. Legacy reason strings remain byte-identical for callers of
the tuple APIs, so existing tests and substring-based compatibility behavior
continue to work during the migration window.

Adapter conversion is intentionally sequenced after the foundation. Each
adapter or surface should move in its own PR, replacing direct string-built
denials with `decision_factory` results and
`PolicyViolationError.from_check_result(...)`. Adapter-local
`PolicyViolationError` symbols become re-exports of the canonical class rather
than deleted symbols. A parametrized parity harness tracks every surface from
the discovery inventory, starts with expected failures, and removes each xfail
as one surface is converted.

### Host Migration Guide

Hosts should treat `str(e)` as the only end-user-safe message for
`PolicyViolationError`. For typed behavior, dispatch on
`e.check_result.category` when it is present. Hosts must not surface
`e.details["detail"]` to end users because it intentionally carries restricted
audit information, including the matched policy pattern, allow-list, limit, or
other internal value that caused the denial.

Mixed-version hosts must tolerate older AGT versions and legacy exception
construction. If `e.check_result` is `None`, fall back to
`e.details.get("category")` when available, and then to the host's existing
substring matcher until all deployed adapters have moved to the structured
contract.

Clients that still substring-match during the migration window can map old
message fragments to the new categories as follows:

| Legacy message fragment | New `ViolationCategory` |
|---|---|
| `Blocked pattern detected` in input checks | `BLOCKED_PATTERN_INPUT` |
| `Blocked pattern` and `tool` / `arguments` | `BLOCKED_PATTERN_TOOL` |
| `matches blocked pattern` for tool names | `BLOCKED_TOOL` |
| `not in allowed list` | `NOT_ALLOWED_TOOL` |
| `Max tool calls exceeded` | `MAX_TOOL_CALLS` |
| `Timeout exceeded` | `TIMEOUT` |
| `requires human approval` | `HUMAN_APPROVAL` |
| `Memory write blocked` | `BLOCKED_PATTERN_MEMORY` |
| `Confidence below threshold` | `CONFIDENCE_THRESHOLD` |
| Any unclassified policy denial | `POLICY_ERROR` |

Before, a host sanitized by substring-matching free-form text:

```python
except Exception as e:
    msg = str(e)
    if "blocked by policy" in msg or "Blocked pattern" in msg:
        return "This action was blocked by governance policy."
```

After, it can dispatch on the structured category and surface the already-safe
exception text:

```python
from agent_os.exceptions import PolicyViolationError
from agent_os.policies.decision import ViolationCategory

try:
    ...
except PolicyViolationError as e:
    result = e.check_result
    category = result.category if result else None
    message = str(e)
    if category == ViolationCategory.BLOCKED_PATTERN_TOOL:
        route = "tool_policy_denial"
    else:
        route = "policy_denial"
    sse_emit("tool_error", {"message": message, "category": category.value if category else None})
```

Existing defense-in-depth sanitizers may remain during the migration. They
should become no-ops for converted adapters because the exception message is
already sanitized at the source.

## Consequences

Backward compatibility is preserved for legacy callers. Tuple-returning
integration methods keep their signatures and byte-identical reason strings,
legacy `PolicyViolationError(...)` construction keeps working, and declarative
policy evaluation remains unchanged.

Converted surfaces eliminate policy-internal leaks by construction because
public messages are fixed by category and sensitive values live only in
restricted structured fields. Audit fidelity is preserved through `detail`,
`matched_pattern`, optional `matched_text`, and `audit_entry`, but those fields
are explicitly server-side data.

Defense in depth still applies. Hosts can retain existing sanitizers while they
roll out typed dispatch, and server-side logging controls must still protect
restricted details.

## Alternatives considered

### Pure string sanitization

Rejected. Sanitizing exception strings at the edge addresses the symptom but not
the cause. It leaves each adapter free to build unsafe strings and requires
consumers to keep guessing which substrings are policy internals.

### Breaking-API unification

Rejected. Replacing the tuple APIs, renaming existing `PolicyDecision` types, or
changing exception constructors would be cleaner in isolation but too costly for
existing hosts, adapters, and tests. The additive contract gets the safety
benefit without a flag day.

### Host-side filters only

Rejected. Requiring every consumer to maintain its own deny-message sanitizer
duplicates effort and produces inconsistent behavior. AGT should provide a safe
contract at the source while hosts keep filters only as defense in depth.

## References

- `agent-governance-python/agent-os/AGENTS.md` — opt-in snippet for adapter authors
