---
title: "2026-06-12 - PolicyEvaluator Backend Error Fail-Closed"
last_reviewed: 2026-06-13
owner: agt-maintainers
---

# 2026-06-12 - PolicyEvaluator Backend Error Fail-Closed

PR: to be linked after filing

Fixes #2992.

## What changed and why

`PolicyEvaluator._evaluate_flat` and `_evaluate_rules` both iterated over
registered external backends with:

```python
for backend in self._backends:
    result = backend.evaluate(context)
    if result.error is None:
        return PolicyDecision(...)
```

When `result.error` was not None the backend was silently skipped. If every
registered backend errored, the loop exited and evaluation fell through to the
configurable default action, which can be `allow`. A transient failure in the
policy enforcement layer could therefore produce a permit decision.

The fix inverts the condition: when `result.error is not None` the evaluator
immediately returns a fail-closed deny `PolicyDecision` with `error: True` and
`error_detail` in the audit entry, and does not consult any subsequent backends.
A backend that returns a valid (non-error) `BackendDecision` is handled on the
next line, unchanged.

**Why now:** This is a silent fail-open on the enforcement path. A transient
network error, a misconfigured OPA/Cedar backend, or a malicious backend crash
could all convert what should be a deny into an allow. The fix matches the
already-existing fail-closed behavior in `_evaluate_scoped`.

## Threat model impact

This change **strengthens** the deny path only. It does not add new attack
surface, identity, trust, or cryptographic code.

| Dimension | Direction |
|---|---|
| Policy bypass surface | **Reduced.** A backend error no longer falls through to the configurable default, which can be allow. |
| Fail-open risk | **Reduced.** Any backend returning a non-None error now produces an immediate deny with audit evidence. |
| Information leakage | **No new exposure.** The error detail is in `audit_entry["error_detail"]` (structured log), not the caller-facing `reason`. |
| Privilege boundaries | **Unchanged.** Only the error-handling path of the external backend loop is modified. |
| Authentication / identity | **Unchanged.** No identity, signing, or trust code is modified. |
| New trust assumptions | **None.** The inputs trusted by the evaluator are unchanged. |
| Backward compatibility | **Preserved for correct callers.** Backends that return valid decisions (error=None) behave identically to before. Only the previously-silently-skipped error path changes behavior. |

### Specific mitigations applied

- **Immediate fail-closed on error.** `result.error is not None` triggers a deny
  `PolicyDecision` with `audit_entry["error"] = True` and
  `audit_entry["error_detail"] = str(result.error)` before any subsequent backend
  is consulted.
- **Structured audit evidence.** The error detail is captured in the audit entry
  for post-incident investigation without leaking it to the caller-facing reason.
- **Consistent across both code paths.** Both `_evaluate_flat` and
  `_evaluate_rules` receive the same fix.

## Test coverage

| File | Purpose |
|---|---|
| `tests/test_policy_backends.py::test_backend_error_fails_closed_not_fallthrough` | A backend returning `error="..."` produces a deny, not a fallthrough to the default allow. |
| `tests/test_policy_backends.py::test_backend_error_does_not_consult_subsequent_backends` | Once a backend errors, later backends in the list are not called. |
| `tests/test_policy_backends.py::test_healthy_backend_after_yaml_miss_still_allows` | A healthy backend (error=None) after a YAML miss still returns its allow decision correctly. |

All targeted tests pass and the full `evaluator` selection shows no regressions
beyond the pre-existing `test_crewai_hooks::test_cedar_evaluator_passed_through`
failure (unrelated: `ModuleNotFoundError: No module named 'agt'` -- compiled Rust
extension absent from the test environment).
