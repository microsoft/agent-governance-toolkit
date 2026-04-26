# Tutorial 01 — Policy Engine

> **Package:** `agent-os-kernel` · **Time:** 30 minutes · **Prerequisites:** Python 3.10+

---

## What You'll Learn

- YAML rules for declarative governance policies
- Operators for matching agent context and tool calls
- Conflict resolution strategies for competing rules
- Middleware integration with AI frameworks

---

The policy engine is the governance backbone of the Agent Governance Toolkit. It
evaluates declarative YAML rules against runtime context and returns
allow/deny/audit/block decisions—before an agent ever touches a tool or sends a
response.

**What you'll learn:**

| Section | Topic |
|---------|-------|
| [Quick Start](#quick-start) | Evaluate your first policy in 5 lines |
| [Policy YAML Syntax](#policy-yaml-syntax) | Full rule and operator reference |
| [GovernancePolicy Dataclass](#governancepolicy-dataclass) | Programmatic policy configuration |
| [Conflict Resolution](#conflict-resolution-strategies) | 4 strategies for competing rules |
| [Advanced Patterns](#advanced-patterns) | Regex/glob blocking, policy composition |
| [Middleware Integration](#integration-with-middleware) | Wire policies into an MAF agent |

---

## Installation

```bash
pip install agent-os-kernel            # core package
pip install agent-os-kernel[nexus]     # adds YAML policy support
pip install agent-os-kernel[full]      # everything (recommended for tutorials)
```

---

## Quick Start

```python
from agent_os.policies import PolicyEvaluator

evaluator = PolicyEvaluator()
evaluator.load_policies("./policies/")          # loads every .yaml/.yml in the dir
decision = evaluator.evaluate({"tool_name": "execute_code", "token_count": 500})
print(decision.allowed, decision.reason)        # False, "Code execution is blocked …"
```

That's it. Four moving parts: **load → build context → evaluate → act on
decision**.

---

## Policy YAML Syntax

Every policy file follows the same schema:

```yaml
version: "1.0"
name: my-policy
description: What this policy enforces

rules:
  - name: rule-name
    condition:
      field: <context-key>
      operator: <operator>
      value: <comparison-value>
    action: allow | deny | audit | block
    priority: 100          # higher = evaluated first
    message: Human-readable explanation

defaults:
  action: allow            # fallback when no rule matches
  max_tokens: 4096
  max_tool_calls: 10
  confidence_threshold: 0.8
```

### Actions

| Action | Behaviour |
|--------|-----------|
| `allow` | Permit the request. `decision.allowed = True`. |
| `deny` | Reject the request. `decision.allowed = False`. |
| `audit` | Permit but log. `decision.allowed = True`, entry written to audit trail. |
| `block` | Hard block with message. `decision.allowed = False`, message surfaced to caller. |

### Operators — Complete Reference

#### `eq` — Equality

```yaml
- name: block-code-execution
  condition:
    field: tool_name
    operator: eq
    value: execute_code
  action: block
  priority: 100
  message: Code execution is blocked in production
```

#### `ne` — Not Equal

```yaml
- name: audit-non-search-tools
  condition:
    field: tool_name
    operator: ne
    value: ""
  action: audit
  priority: 50
  message: Auditing tool call for compliance
```

#### `gt` — Greater Than

```yaml
- name: token-limit
  condition:
    field: token_count
    operator: gt
    value: 4096
  action: deny
  priority: 100
  message: Token count exceeds the default limit of 4096
```

#### `lt` — Less Than

```yaml
- name: low-confidence
  condition:
    field: confidence
    operator: lt
    value: 0.8
  action: deny
  priority: 90
  message: Confidence score is below the minimum threshold of 0.8
```

#### `gte` — Greater Than or Equal

```yaml
- name: audit-all-messages
  condition:
    field: message_count
    operator: gte
    value: 0
  action: audit
  priority: 10
  message: All agent actions are audit-logged
```

#### `lte` — Less Than or Equal

```yaml
- name: allow-small-requests
  condition:
    field: token_count
    operator: lte
    value: 256
  action: allow
  priority: 80
  message: Small requests are always allowed
```

#### `in` — Value In List

```yaml
- name: allow-safe-tools
  condition:
    field: tool_name
    operator: in
    value: [web_search, read_file, summarize]
  action: allow
  priority: 70
  message: Tool is on the approved list
```

#### `contains` — Substring Match

```yaml
- name: block-secrets-access
  condition:
    field: message
    operator: contains
    value: "secrets"
  action: deny
  priority: 100
  message: Access to secret resources is restricted by governance policy
```

#### `matches` — Regex Match

```yaml
- name: block-sql-injection
  condition:
    field: message
    operator: matches
    value: "(?i)(drop|delete|truncate)\\s+table"
  action: block
  priority: 100
  message: Potential SQL injection detected
```

### Real-World Policy Files

**Production — strict.yaml**

```yaml
version: "1.0"
name: strict
description: Production safety policy with tight limits and audit requirements

rules:
  - name: max_tokens
    condition:
      field: token_count
      operator: gt
      value: 2048
    action: deny
    priority: 100
    message: Token count exceeds production limit of 2048

  - name: max_tool_calls
    condition:
      field: tool_call_count
      operator: gt
      value: 5
    action: deny
    priority: 99
    message: Tool call count exceeds production limit of 5

  - name: block_exec
    condition:
      field: tool_name
      operator: eq
      value: execute_code
    action: block
    priority: 98
    message: Code execution is blocked in production

  - name: block_shell
    condition:
      field: tool_name
      operator: eq
      value: run_shell
    action: block
    priority: 97
    message: Shell access is blocked in production

  - name: confidence_threshold
    condition:
      field: confidence
      operator: lt
      value: 0.95
    action: deny
    priority: 90
    message: Confidence score is below the production threshold of 0.95

  - name: audit_all_tool_calls
    condition:
      field: tool_name
      operator: ne
      value: ""
    action: audit
    priority: 50
    message: Auditing tool call for compliance

defaults:
  action: deny
  max_tokens: 2048
  max_tool_calls: 5
  confidence_threshold: 0.95
```

**Development — development.yaml**

```yaml
version: "1.0"
name: development
description: Relaxed policy for local development and experimentation

rules:
  - name: max_tokens
    condition:
      field: token_count
      operator: gt
      value: 16384
    action: deny
    priority: 100
    message: Token count exceeds generous dev limit of 16384

  - name: max_tool_calls
    condition:
      field: tool_call_count
      operator: gt
      value: 50
    action: deny
    priority: 99
    message: Tool call count exceeds dev limit of 50

defaults:
  action: allow
  max_tokens: 16384
  max_tool_calls: 50
  confidence_threshold: 0.5
```

---

## Building Policies in Python

You don't have to use YAML. Build policies programmatically when you need
dynamic rules:

```python
from agent_os.policies import (
    PolicyDocument,
    PolicyRule,
    PolicyCondition,
    PolicyAction,
    PolicyOperator,
    PolicyDefaults,
    PolicyEvaluator,
)

rule = PolicyRule(
    name="block_code_execution",
    condition=PolicyCondition(
        field="tool_name",
        operator=PolicyOperator.EQ,
        value="execute_code",
    ),
    action=PolicyAction.DENY,
    priority=100,
    message="Code execution is blocked in production",
)

policy = PolicyDocument(
    name="production_safety",
    description="Safe production policy",
    rules=[rule],
    defaults=PolicyDefaults(
        action=PolicyAction.ALLOW,
        max_tokens=2048,
        max_tool_calls=5,
        confidence_threshold=0.95,
    ),
)

# Serialize to YAML for version control
policy.to_yaml("policies/production_safety.yaml")

# Or evaluate directly
evaluator = PolicyEvaluator([policy])
decision = evaluator.evaluate({"tool_name": "execute_code"})
assert not decision.allowed
print(decision.reason)  # "Code execution is blocked in production"
```

### PolicyDecision Object

Every call to `evaluator.evaluate()` returns a `PolicyDecision`:

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | `bool` | Whether the action is permitted. Default `True`. |
| `matched_rule` | `str \| None` | Name of the rule that fired. `None` if defaults applied. |
| `action` | `str` | The action taken: `allow`, `deny`, `audit`, or `block`. |
| `reason` | `str` | Human-readable explanation. |
| `audit_entry` | `dict` | Structured audit data (policy name, timestamp, context snapshot). |

```python
decision = evaluator.evaluate(context)

# Audit entry structure
# {
#     "policy": "production_safety",
#     "rule": "block_code_execution",
#     "action": "deny",
#     "context_snapshot": { ... },
#     "timestamp": "2025-01-15T10:30:00Z",
#     "error": False,
# }
```

---

## GovernancePolicy Dataclass

`GovernancePolicy` is a higher-level dataclass in `agent_os.integrations.base`
that bundles constraints, thresholds, and audit settings into a single
configuration object. Use it when you need more than rule-based evaluation—
tool allowlists, pattern blocking, drift detection, and concurrency controls.

```python
from agent_os.integrations.base import GovernancePolicy, PatternType

policy = GovernancePolicy(
    name="production",
    max_tokens=2048,
    max_tool_calls=5,
    allowed_tools=["web_search", "read_file"],
    blocked_patterns=[
        "password",                            # substring match (default)
        ("rm\\s+-rf", PatternType.REGEX),      # regex match
        ("*.exe", PatternType.GLOB),           # glob match
    ],
    require_human_approval=False,
    timeout_seconds=120,
    confidence_threshold=0.95,
    drift_threshold=0.10,
    log_all_calls=True,
    checkpoint_frequency=3,
    max_concurrent=5,
    backpressure_threshold=4,
    version="2.0.0",
)

# Validate the policy (raises ValueError on invalid config)
policy.validate()
```

### Full Field Reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `str` | `"default"` | Policy identifier |
| `max_tokens` | `int` | `4096` | Max tokens per request (must be > 0) |
| `max_tool_calls` | `int` | `10` | Max tool invocations per request (≥ 0) |
| `allowed_tools` | `list[str]` | `[]` | Tool allowlist; empty = all allowed |
| `blocked_patterns` | `list[str \| tuple[str, PatternType]]` | `[]` | Content patterns to block |
| `require_human_approval` | `bool` | `False` | Require human sign-off before execution |
| `timeout_seconds` | `int` | `300` | Max wall-clock time (> 0) |
| `confidence_threshold` | `float` | `0.8` | Minimum confidence score \[0.0–1.0\] |
| `drift_threshold` | `float` | `0.15` | Maximum semantic drift \[0.0–1.0\] |
| `log_all_calls` | `bool` | `True` | Log every tool call to audit trail |
| `checkpoint_frequency` | `int` | `5` | Checkpoint every N tool calls (> 0) |
| `max_concurrent` | `int` | `10` | Max simultaneous executions (> 0) |
| `backpressure_threshold` | `int` | `8` | Start throttling at this level (> 0, < `max_concurrent`) |
| `version` | `str` | `"1.0.0"` | Semantic version for policy tracking |

### PatternType Enum

| Value | Behaviour |
|-------|-----------|
| `PatternType.SUBSTRING` | Simple substring match (default when you pass a plain `str`). |
| `PatternType.REGEX` | Compiled regex, case-insensitive. |
| `PatternType.GLOB` | Glob pattern (e.g., `*.exe`, `secret_*`). |

### Key Methods

```python
# Check for pattern matches in text
matches = policy.matches_pattern("please run rm -rf /tmp")
# Returns: ["rm\\s+-rf"]

# Detect conflicting settings
warnings = policy.detect_conflicts()
# e.g., ["backpressure_threshold >= max_concurrent"]

# Compare policies
base = GovernancePolicy()
print(policy.is_stricter_than(base))  # True
print(policy.format_diff(base))       # Human-readable diff

# Serialize / deserialize
policy.save("policies/production.yaml")
loaded = GovernancePolicy.load("policies/production.yaml")

yaml_str = policy.to_yaml()
restored = GovernancePolicy.from_yaml(yaml_str)
```

---

## Conflict Resolution Strategies

When multiple policies apply to the same request, their rules can conflict. The
`PolicyConflictResolver` in `agentmesh.governance.conflict_resolution` resolves
these with one of four strategies.

```python
from agentmesh.governance.conflict_resolution import (
    PolicyConflictResolver,
    ConflictResolutionStrategy,
    CandidateDecision,
    PolicyScope,
)
```

### The Four Strategies

#### 1. `deny_overrides` — Safety First

Any deny wins. Among multiple denies, highest priority wins.

**Use when:** You want a default-allow posture with hard deny guardrails. This
is the safest choice for most enterprise deployments.

```python
resolver = PolicyConflictResolver(ConflictResolutionStrategy.DENY_OVERRIDES)

candidates = [
    CandidateDecision(
        action="allow", priority=50,
        scope=PolicyScope.GLOBAL, rule_name="allow_web_search",
    ),
    CandidateDecision(
        action="deny", priority=10,
        scope=PolicyScope.AGENT, rule_name="block_internal_access",
    ),
]

result = resolver.resolve(candidates)
assert result.winning_decision.action == "deny"   # deny always wins
assert result.conflict_detected is True
```

#### 2. `allow_overrides` — Permissive with Exceptions

Any allow wins. Among multiple allows, highest priority wins.

**Use when:** Your baseline is deny-all and you grant explicit exceptions per
agent or team.

```python
resolver = PolicyConflictResolver(ConflictResolutionStrategy.ALLOW_OVERRIDES)

candidates = [
    CandidateDecision(action="deny", priority=100, scope=PolicyScope.GLOBAL, rule_name="deny_all"),
    CandidateDecision(action="allow", priority=50, scope=PolicyScope.AGENT, rule_name="research_exception"),
]

result = resolver.resolve(candidates)
assert result.winning_decision.action == "allow"  # allow overrides
```

#### 3. `priority_first_match` — Highest Priority Wins

The candidate with the highest numeric priority wins, regardless of action.
This is the **default strategy** and mirrors how `PolicyEvaluator` resolves
rules within a single policy.

**Use when:** You want predictable, priority-ordered evaluation across
policies.

```python
resolver = PolicyConflictResolver(ConflictResolutionStrategy.PRIORITY_FIRST_MATCH)

candidates = [
    CandidateDecision(action="allow", priority=50, rule_name="general_allow"),
    CandidateDecision(action="deny", priority=100, rule_name="high_priority_deny"),
]

result = resolver.resolve(candidates)
assert result.winning_decision.rule_name == "high_priority_deny"
```

#### 4. `most_specific_wins` — Scope-Based Resolution

More specific scopes override broader ones: **Agent > Tenant > Global**.
Priority breaks ties within the same scope.

**Use when:** You have a multi-tenant setup where team-level or agent-level
policies should override organization-wide defaults.

```python
resolver = PolicyConflictResolver(ConflictResolutionStrategy.MOST_SPECIFIC_WINS)

candidates = [
    CandidateDecision(
        action="deny", priority=100,
        scope=PolicyScope.GLOBAL, rule_name="org_wide_deny",
    ),
    CandidateDecision(
        action="allow", priority=50,
        scope=PolicyScope.AGENT, rule_name="agent_exception",
    ),
]

result = resolver.resolve(candidates)
assert result.winning_decision.rule_name == "agent_exception"  # agent scope wins
```

### ResolutionResult

Every `resolve()` call returns a `ResolutionResult`:

| Field | Type | Description |
|-------|------|-------------|
| `winning_decision` | `CandidateDecision` | The decision that prevailed. |
| `strategy_used` | `ConflictResolutionStrategy` | Which strategy was applied. |
| `candidates_evaluated` | `int` | Number of candidates considered. |
| `conflict_detected` | `bool` | `True` if there was a mix of allow and deny candidates. |
| `resolution_trace` | `list[str]` | Step-by-step log of the resolution logic. |

```python
for line in result.resolution_trace:
    print(line)
# "Evaluating 2 candidates with deny_overrides strategy"
# "Found 1 deny candidate(s) — deny overrides"
# "Winner: block_internal_access (deny, priority=10, scope=agent)"
```

### Strategy Selection Guide

| Scenario | Recommended Strategy |
|----------|---------------------|
| Enterprise default with deny guardrails | `deny_overrides` |
| Zero-trust baseline with explicit grants | `allow_overrides` |
| Single-policy system or backward compat | `priority_first_match` |
| Multi-tenant with org → team → agent layering | `most_specific_wins` |

---

## Advanced Patterns

### Blocked Patterns with Regex and Glob

`GovernancePolicy.blocked_patterns` accepts plain strings (substring), regex
tuples, and glob tuples. All three can be mixed in a single policy.

```python
from agent_os.integrations.base import GovernancePolicy, PatternType

policy = GovernancePolicy(
    name="content-filter",
    blocked_patterns=[
        # Substring — matches anywhere in text
        "password",
        "api_key",

        # Regex — case-insensitive compiled pattern
        (r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", PatternType.REGEX),   # JWT tokens
        (r"rm\s+-rf\s+/", PatternType.REGEX),                       # destructive commands
        (r"(?i)drop\s+table", PatternType.REGEX),                   # SQL injection

        # Glob — shell-style wildcards
        ("*.exe", PatternType.GLOB),
        ("secret_*", PatternType.GLOB),
    ],
)

# Check if text triggers any pattern
matches = policy.matches_pattern("please delete Bearer eyJhbGciOi... from the cache")
print(matches)  # ["Bearer\\s+[A-Za-z0-9\\-._~+/]+=*"]
```

### Policy Composition and Comparison

Create a base policy and derive stricter variants. Use `diff()` and
`is_stricter_than()` to verify invariants in CI:

```python
base = GovernancePolicy(name="base", max_tokens=4096, max_tool_calls=10)

production = GovernancePolicy(
    name="production",
    max_tokens=2048,
    max_tool_calls=5,
    allowed_tools=["web_search", "read_file"],
    confidence_threshold=0.95,
    require_human_approval=True,
)

# Verify production is stricter
assert production.is_stricter_than(base)

# Show what changed
diff = production.diff(base)
for field, (prod_val, base_val) in diff.items():
    print(f"  {field}: {base_val} → {prod_val}")
# max_tokens: 4096 → 2048
# max_tool_calls: 10 → 5
# confidence_threshold: 0.8 → 0.95
# require_human_approval: False → True
# allowed_tools: [] → ['web_search', 'read_file']
```

### Loading Policies from Multiple Directories

`PolicyEvaluator.load_policies()` can be called multiple times. Rules from all
loaded documents are merged and sorted by priority:

```python
evaluator = PolicyEvaluator()
evaluator.load_policies("./policies/global/")
evaluator.load_policies("./policies/team-specific/")
evaluator.load_policies("./policies/agent-overrides/")

# All rules from all directories are evaluated together.
# Highest-priority rule across all files wins.
decision = evaluator.evaluate(context)
```

---

## Integration with Middleware

The `GovernancePolicyMiddleware` plugs into the Microsoft Agent Framework (MAF)
middleware pipeline. Every agent invocation passes through the middleware stack
before execution.

### Quick Middleware Setup

```python
from agent_os.policies import PolicyEvaluator
from agent_os.integrations.maf_adapter import GovernancePolicyMiddleware

evaluator = PolicyEvaluator()
evaluator.load_policies("./policies/")

middleware = GovernancePolicyMiddleware(evaluator=evaluator)
```

### Full Governance Stack with Factory

`create_governance_middleware()` assembles the complete stack in the correct
order:

```python
from agent_os.integrations.maf_adapter import create_governance_middleware

stack = create_governance_middleware(
    policy_directory="./policies/",
    allowed_tools=["web_search", "read_file"],
    denied_tools=["execute_code", "run_shell"],
    agent_id="research-agent",
    enable_rogue_detection=True,
)
```

The factory returns an ordered list of middleware (evaluated bottom-up):

| Order | Middleware | Purpose |
|-------|-----------|---------|
| 1 | `AuditTrailMiddleware` | Pre/post execution audit entries with timing |
| 2 | `GovernancePolicyMiddleware` | Declarative YAML policy evaluation |
| 3 | `CapabilityGuardMiddleware` | Tool allow/deny list enforcement |
| 4 | `RogueDetectionMiddleware` | Anomaly detection on tool invocations |

### Wiring into an Agent

```python
from agent_framework import Agent
from agent_os.integrations.maf_adapter import create_governance_middleware

stack = create_governance_middleware(
    policy_directory="./policies/",
    allowed_tools=["web_search", "read_file"],
    denied_tools=["execute_code"],
    agent_id="research-agent",
    enable_rogue_detection=True,
)

agent = Agent(
    name="researcher",
    instructions="You are a research assistant.",
    middleware=stack,
)
```

### What Happens at Runtime

1. Agent receives an invocation.
2. **AuditTrailMiddleware** writes a pre-execution audit entry.
3. **GovernancePolicyMiddleware** builds a context dict from the incoming
   message (`{agent, message, timestamp, stream, message_count}`) and calls
   `evaluator.evaluate(context)`.
   - If **denied**: sets an `AgentResponse` with the denial reason, logs to
     audit, and raises `MiddlewareTermination`. The agent never executes.
   - If **allowed**: stores the `PolicyDecision` in
     `context.metadata["governance_decision"]` and proceeds.
4. **CapabilityGuardMiddleware** checks each tool call against `allowed_tools`
   and `denied_tools`. Denied tools are blocked (`denied_tools` takes
   precedence over `allowed_tools`).
5. **RogueDetectionMiddleware** feeds each tool invocation to
   `RogueAgentDetector` and blocks high-risk calls.
6. **AuditTrailMiddleware** writes a post-execution entry with timing.

### Accessing Governance Decisions Downstream

After middleware runs, the decision is available in context metadata:

```python
decision = context.metadata.get("governance_decision")
if decision:
    print(f"Policy: {decision.action}, Rule: {decision.matched_rule}")
```

---

## Source Files

| Component | Location |
|-----------|----------|
| Schema models | `agent-governance-python/agent-os/src/agent_os/policies/schema.py` |
| Evaluator | `agent-governance-python/agent-os/src/agent_os/policies/evaluator.py` |
| GovernancePolicy | `agent-governance-python/agent-os/src/agent_os/integrations/base.py` |
| MAF middleware | `agent-governance-python/agent-os/src/agent_os/integrations/maf_adapter.py` |
| Conflict resolution | `agent-governance-python/agent-mesh/src/agentmesh/governance/conflict_resolution.py` |
| Policy examples | `agent-governance-python/agent-os/examples/policies/` |
| Research demo | `demo/policies/research_policy.yaml` |

---

## Next Steps

- **Trust & Identity:** [Tutorial 02 — Trust and Identity](02-trust-and-identity.md)
- **Framework Integrations:** [Tutorial 03 — Framework Integrations](03-framework-integrations.md)
- **Audit & Compliance:** [Tutorial 04 — Audit Logging & Compliance](04-audit-and-compliance.md)
