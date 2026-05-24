# Error Handling Guide

> How to handle errors, exceptions, and policy violations in the Agent Governance Toolkit.

## Overview

Every error returned by the Agent Governance Toolkit includes a structured `GovernanceError` that describes what happened, which policy was involved, and what action was taken. This lets callers implement retry logic, user-facing messaging, and audit logging consistently.

## Error Types

### PolicyViolationError

Raised when an agent action is denied by a policy rule.

```python
from agent_os.exceptions import PolicyViolationError

try:
    result = evaluator.evaluate({"tool_name": "delete_file"})
except PolicyViolationError as e:
    print(f"Action '{e.action}' on tool '{e.tool_name}' was denied by rule '{e.rule_id}'")
    print(f"Policy: {e.policy_name} v{e.policy_version}")
    print(f"Timestamp: {e.timestamp}")
```

**Attributes:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `action` | `str` | The action that was denied (e.g., `"tool_call"`) |
| `tool_name` | `str` | Name of the tool the agent tried to call |
| `rule_id` | `str` | ID of the specific rule that triggered the denial |
| `policy_name` | `str` | Name of the policy document containing the rule |
| `policy_version` | `str` | Version of the policy document |
| `timestamp` | `datetime` | When the violation occurred |
| `agent_id` | `str\|None` | Identity of the agent that attempted the action |
| `context` | `dict` | Additional context fields matched by the rule |

### PolicyLoadError

Raised when a policy document fails to parse or validate.

```python
from agent_os.exceptions import PolicyLoadError

try:
    policies = PolicyDocument.load_from_file("policies/my-policy.yaml")
except PolicyLoadError as e:
    print(f"Failed to load policy: {e.message}")
    print(f"File: {e.filename}")
    print(f"Line: {e.line_number}")
    print(f"Schema violations: {e.schema_errors}")
```

### AuditWriteError

Raised when the audit log fails to persist. The governance engine continues operating (fail-open for audit) but records the failure.

```python
from agent_os.exceptions import AuditWriteError

try:
    auditor.record(event)
except AuditWriteError as e:
    logger.warning(f"Audit write failed: {e.backend}, falling back to local buffer")
    # Governance continues — audit is best-effort
```

### TrustScoreError

Raised when trust scoring computation encounters an invalid state.

```python
from agent_os.trust import TrustScoreError

try:
    score = trust_engine.compute_score(agent_id, action_context)
except TrustScoreError as e:
    print(f"Trust computation failed: {e.reason}")
    # Fall back to deny-or-allow default for this agent
```

## Error Handling Patterns

### Pattern 1: Validate Before Evaluate

Catch policy load errors at startup to fail fast with a clear message.

```python
import yaml

def load_policies(policy_paths: list[str]) -> list[PolicyDocument]:
    policies = []
    for path in policy_paths:
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            policies.append(PolicyDocument.from_dict(data))
        except PolicyLoadError as e:
            raise RuntimeError(f"Policy load failed for '{path}': {e.message}") from e
    return policies
```

### Pattern 2: Graceful Degradation on Audit Failure

Audit writes should not block policy enforcement.

```python
from agent_os.audit import AuditLogger
import logging

audit = AuditLogger(backend="cloud-watch", fail_open=True)

def execute_with_governance(agent, action):
    result = evaluator.evaluate({"tool_name": action.tool_name, "agent_id": agent.id})
    if result.effect == "deny":
        try:
            audit.log_violation(agent.id, action, result.rule)
        except AuditWriteError:
            pass  # fail-open: governance decision stands
        raise PermissionError(f"Action '{action.tool_name}' denied by policy")
    return agent.execute(action)
```

### Pattern 3: Retry on Transient Errors

Use exponential backoff for recoverable errors (network, rate limiting).

```python
import time

def evaluate_with_retry(evaluator, context, max_retries=3, base_delay=0.1):
    last_error = None
    for attempt in range(max_retries):
        try:
            return evaluator.evaluate(context)
        except TransientGovernanceError as e:
            last_error = e
            if attempt < max_retries - 1:
                time.sleep(base_delay * (2 ** attempt))
            continue
    raise last_error
```

### Pattern 4: Per-Agent Fallback Policies

When a trust score cannot be computed, apply a fallback rule specific to the agent tier.

```python
def evaluate_agent_action(agent_id, action, trust_engine, evaluator):
    try:
        return evaluator.evaluate({"tool_name": action, "agent_id": agent_id})
    except TrustScoreError:
        # Tier-based fallback
        tier = agent_tier_map.get(agent_id, "standard")
        fallback_rule = fallback_policies[tier]
        return PolicyResult(effect=fallback_rule, source="trust-fallback")
```

## Structured Error Logging

All governance errors should be logged with consistent structured fields for observability.

```python
import json
import logging

logger = logging.getLogger("governance.errors")

def log_policy_violation(error: PolicyViolationError):
    logger.warning(
        "policy_violation",
        extra={
            "event_type": "policy_violation",
            "agent_id": error.agent_id,
            "action": error.action,
            "tool_name": error.tool_name,
            "rule_id": error.rule_id,
            "policy_name": error.policy_name,
            "policy_version": error.policy_version,
            "context": error.context,
            "timestamp": error.timestamp.isoformat(),
        }
    )
```

## Suppressing Known Violations

In testing or controlled environments, you may need to suppress specific policy violations for known-trusted agents.

```python
from agent_os.policies import suppress_rule

# Suppress the delete_file rule for the ci-test agent
suppress_rule(
    rule_id="block-dangerous-tools",
    agent_id="did:mesh:ci-test-agent",
    reason="E2E test fixture — controlled environment",
    expires_at="2026-12-31T23:59:59Z",
)
```

> **Note:** Suppressions are audit-logged even when the action is allowed. Do not use suppressions in production unless explicitly required and documented in your runbook.

## Error Code Reference

| Code | Name | Description |
|------|------|-------------|
| `GOV001` | `POLICY_NOT_FOUND` | Referenced policy does not exist |
| `GOV002` | `RULE_EVALUATION_FAILED` | Rule condition could not be evaluated |
| `GOV003` | `TRUST_SCORE_UNAVAILABLE` | Trust engine returned no score |
| `GOV004` | `AUDIT_BACKEND_UNAVAILABLE` | Audit log write failed |
| `GOV005` | `INVALID_POLICY_DOCUMENT` | Policy YAML failed schema validation |
| `GOV006` | `AGENT_IDENTITY_INVALID` | Agent DID could not be verified |

## Getting Help

- **Docs:** [Architecture](ARCHITECTURE.md) · [Policy Reference](../agent-governance-python/agent-os/src/agent_os/policies/) · [FAQ](FAQ.md)
- **Issues:** Open a GitHub issue with the `error-handling` label
- **Security:** For CVEs, follow [SECURITY.md](../SECURITY.md) disclosure process