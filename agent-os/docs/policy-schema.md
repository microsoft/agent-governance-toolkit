# Policy Schema Reference

This document describes how to define policies for Agent-OS governance. There are two ways to define policies:

1. **YAML Configuration** (`.agents/security.md`) - Declarative, file-based
2. **Python API** (`PolicyEngine`) - Programmatic, code-based

---

## JSON Schema for Policies

For tools that need to validate policy definitions, use this JSON Schema:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://agent-os.dev/schemas/policy-v1.json",
  "title": "Agent-OS Policy Schema",
  "description": "Schema for defining governance policies in Agent-OS",
  "type": "object",
  "definitions": {
    "condition": {
      "type": "object",
      "description": "ABAC condition for attribute-based access control",
      "required": ["attribute_path", "operator", "value"],
      "properties": {
        "attribute_path": {
          "type": "string",
          "description": "Dot-notation path to attribute (e.g., 'args.amount', 'context.user_role')",
          "examples": ["user_status", "args.amount", "context.time_of_day"]
        },
        "operator": {
          "type": "string",
          "enum": ["eq", "ne", "gt", "lt", "gte", "lte", "in", "not_in", "contains", "starts_with", "not_starts_with", "not_contains"],
          "description": "Comparison operator"
        },
        "value": {
          "description": "Value to compare against (type depends on operator)"
        }
      }
    },
    "conditional_permission": {
      "type": "object",
      "description": "Permission with ABAC conditions",
      "required": ["tool_name"],
      "properties": {
        "tool_name": {
          "type": "string",
          "description": "Name of the tool this permission applies to"
        },
        "conditions": {
          "type": "array",
          "items": { "$ref": "#/definitions/condition" },
          "description": "List of conditions that must be met"
        },
        "require_all": {
          "type": "boolean",
          "default": true,
          "description": "If true, ALL conditions must pass (AND). If false, ANY condition passes (OR)"
        }
      }
    },
    "resource_quota": {
      "type": "object",
      "description": "Rate limits and resource quotas for an agent",
      "properties": {
        "max_requests_per_minute": {
          "type": "integer",
          "minimum": 0,
          "default": 60
        },
        "max_requests_per_hour": {
          "type": "integer", 
          "minimum": 0,
          "default": 1000
        },
        "max_execution_time_seconds": {
          "type": "number",
          "minimum": 0,
          "default": 30
        },
        "max_concurrent_executions": {
          "type": "integer",
          "minimum": 1,
          "default": 5
        },
        "allowed_action_types": {
          "type": "array",
          "items": {
            "type": "string",
            "enum": ["code_execution", "file_read", "file_write", "api_call", "database_query", "database_write", "workflow_trigger"]
          }
        }
      }
    },
    "risk_policy": {
      "type": "object",
      "description": "Risk-based enforcement thresholds",
      "properties": {
        "max_risk_score": {
          "type": "number",
          "minimum": 0,
          "maximum": 1,
          "default": 0.8,
          "description": "Actions above this score are denied"
        },
        "require_approval_above": {
          "type": "number",
          "minimum": 0,
          "maximum": 1,
          "default": 0.5,
          "description": "Actions above this score require human approval"
        },
        "deny_above": {
          "type": "number",
          "minimum": 0,
          "maximum": 1,
          "default": 0.9,
          "description": "Actions above this score are automatically denied"
        },
        "high_risk_patterns": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Regex patterns that indicate high-risk actions"
        },
        "allowed_domains": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Domains allowed for API calls"
        },
        "blocked_domains": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Domains blocked for API calls"
        }
      }
    },
    "policy_rule": {
      "type": "object",
      "description": "Custom policy rule with validator function",
      "required": ["rule_id", "name", "action_types"],
      "properties": {
        "rule_id": {
          "type": "string",
          "description": "Unique identifier for this rule"
        },
        "name": {
          "type": "string",
          "description": "Human-readable name"
        },
        "description": {
          "type": "string",
          "description": "What this rule enforces"
        },
        "action_types": {
          "type": "array",
          "items": {
            "type": "string",
            "enum": ["code_execution", "file_read", "file_write", "api_call", "database_query", "database_write", "workflow_trigger"]
          }
        },
        "priority": {
          "type": "integer",
          "default": 0,
          "description": "Higher priority rules are checked first"
        }
      }
    }
  },
  "properties": {
    "version": {
      "type": "string",
      "const": "1.0"
    },
    "agent_constraints": {
      "type": "object",
      "description": "Map of agent_id to allowed tools (allow-list approach)",
      "additionalProperties": {
        "type": "array",
        "items": { "type": "string" }
      }
    },
    "conditional_permissions": {
      "type": "object",
      "description": "Map of agent_id to conditional permissions",
      "additionalProperties": {
        "type": "array",
        "items": { "$ref": "#/definitions/conditional_permission" }
      }
    },
    "quotas": {
      "type": "object",
      "description": "Map of agent_id to resource quota",
      "additionalProperties": { "$ref": "#/definitions/resource_quota" }
    },
    "risk_policies": {
      "type": "object",
      "description": "Map of policy_id to risk policy",
      "additionalProperties": { "$ref": "#/definitions/risk_policy" }
    },
    "custom_rules": {
      "type": "array",
      "items": { "$ref": "#/definitions/policy_rule" }
    }
  }
}
```

---

## Python API Reference

### PolicyEngine

The `PolicyEngine` is the core policy enforcement component.

```python
from agent_control_plane.policy_engine import (
    PolicyEngine,
    Condition,
    ConditionalPermission,
    ResourceQuota,
    RiskPolicy,
)

# Initialize
engine = PolicyEngine()
```

### Adding Constraints (Allow-List)

The most secure approach - only explicitly allowed tools can be used:

```python
# Agent "data-analyst" can only use these tools
engine.add_constraint("data-analyst", [
    "file_read",
    "database_query",
    "api_call",
])

# Agent "admin" can use more tools
engine.add_constraint("admin", [
    "file_read",
    "file_write",
    "database_query",
    "database_write",
    "code_execution",
])
```

### Adding Conditional Permissions (ABAC)

For fine-grained, context-aware access control:

```python
# Allow refunds only for verified users, up to $1000
refund_permission = ConditionalPermission(
    tool_name="refund_user",
    conditions=[
        Condition(
            attribute_path="user_status",
            operator="eq",
            value="verified"
        ),
        Condition(
            attribute_path="args.amount",
            operator="lte",
            value=1000
        ),
    ],
    require_all=True  # Both conditions must pass
)
engine.add_conditional_permission("support-agent", refund_permission)

# Set context for the agent
engine.set_agent_context("support-agent", {
    "user_status": "verified",
    "department": "customer-service"
})
```

### Setting Resource Quotas

Rate limiting and resource constraints:

```python
quota = ResourceQuota(
    max_requests_per_minute=60,
    max_requests_per_hour=1000,
    max_execution_time_seconds=30,
    max_concurrent_executions=5,
    allowed_action_types=[
        ActionType.FILE_READ,
        ActionType.API_CALL,
    ]
)
engine.set_quota("my-agent", quota)
```

### Setting Risk Policies

Risk-based enforcement:

```python
risk_policy = RiskPolicy(
    max_risk_score=0.8,
    require_approval_above=0.5,
    deny_above=0.9,
    high_risk_patterns=[
        r"\brm\s+-rf\b",
        r"\bdrop\s+table\b",
    ],
    allowed_domains=["api.internal.com", "api.trusted.com"],
    blocked_domains=["*.malware.com"]
)
engine.set_risk_policy("production", risk_policy)
```

### Checking Violations

```python
# Returns None if allowed, or error message if blocked
violation = engine.check_violation(
    agent_role="data-analyst",
    tool_name="file_write",  # Not in allow-list!
    args={"path": "/data/output.csv"}
)

if violation:
    print(f"Blocked: {violation}")
    # Output: "Blocked: Role data-analyst cannot use tool file_write"
```

---

## Condition Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Equal | `amount == 100` |
| `ne` | Not equal | `status != "banned"` |
| `gt` | Greater than | `amount > 100` |
| `lt` | Less than | `amount < 1000` |
| `gte` | Greater or equal | `age >= 18` |
| `lte` | Less or equal | `amount <= 500` |
| `in` | In list | `role in ["admin", "manager"]` |
| `not_in` | Not in list | `category not in ["restricted"]` |
| `contains` | String contains | `path contains "/safe/"` |
| `starts_with` | String starts with | `path starts with "/workspace/"` |
| `not_starts_with` | Doesn't start with | `path not starts with "/etc/"` |
| `not_contains` | Doesn't contain | `command not contains "rm -rf"` |

---

## Built-in Protections

PolicyEngine includes built-in safety checks that are always active:

### Path Traversal Protection
```python
# Automatically blocked:
# - Paths containing ".."
# - Paths to system directories: /etc/, /sys/, /proc/, /dev/
# - Windows system paths: C:\Windows\System32
```

### Dangerous Code Patterns
```python
# Automatically blocked in code_execution:
# - rm -rf
# - format (disk formatting)
# - DROP TABLE / DROP DATABASE
# - TRUNCATE TABLE
# - DELETE FROM (without WHERE)
```

### SQL Injection Prevention
```python
# Automatically sanitized:
# - Comments stripped
# - Multiple statements detected
# - Destructive operations blocked
```

---

## Example: Complete Policy Configuration

```python
from agent_control_plane.policy_engine import (
    PolicyEngine, Condition, ConditionalPermission, 
    ResourceQuota, RiskPolicy
)
from agent_control_plane.agent_kernel import ActionType

# Initialize
engine = PolicyEngine()

# 1. Define allow-lists for each agent role
engine.add_constraint("reader", ["file_read", "database_query"])
engine.add_constraint("writer", ["file_read", "file_write", "database_query", "database_write"])
engine.add_constraint("admin", ["*"])  # All tools

# 2. Add ABAC conditions for sensitive operations
engine.add_conditional_permission("writer", ConditionalPermission(
    tool_name="database_write",
    conditions=[
        Condition("args.table", "not_in", ["users", "credentials", "audit_log"]),
    ]
))

# 3. Set quotas
engine.set_quota("reader", ResourceQuota(
    max_requests_per_minute=100,
    max_requests_per_hour=2000,
))

engine.set_quota("writer", ResourceQuota(
    max_requests_per_minute=30,
    max_requests_per_hour=500,
    max_concurrent_executions=2,
))

# 4. Set risk policies
engine.set_risk_policy("default", RiskPolicy(
    max_risk_score=0.7,
    require_approval_above=0.5,
    blocked_domains=["*.evil.com"],
))

# 5. Wire to KernelSpace
from agent_control_plane.kernel_space import KernelSpace
from agent_control_plane.flight_recorder import FlightRecorder

kernel = KernelSpace(
    policy_engine=engine,
    flight_recorder=FlightRecorder("audit.db"),
)

# 6. Register tools
kernel.register_tool("file_read", my_file_read_function)
kernel.register_tool("database_query", my_db_query_function)

# 7. Create agent and execute
ctx = kernel.create_agent_context("reader")
# Now all syscalls go through policy enforcement
```

---

## Migration from YAML to Python

If you have `.agents/security.md` and want to use the Python API:

```python
import yaml

def load_yaml_policies(path: str, engine: PolicyEngine):
    """Convert YAML security config to PolicyEngine calls."""
    with open(path) as f:
        config = yaml.safe_load(f)
    
    for policy in config.get("policies", []):
        action = policy["action"]
        effect = policy.get("effect", "allow")
        
        if effect == "deny":
            # Don't add to allow-list (implicit deny)
            continue
        
        # Add to default allow-list
        engine.add_constraint("default", [action])
        
        # Add rate limits if specified
        if "rate_limit" in policy:
            count, period = policy["rate_limit"].split("/")
            if period == "hour":
                quota = ResourceQuota(max_requests_per_hour=int(count))
            elif period == "minute":
                quota = ResourceQuota(max_requests_per_minute=int(count))
            engine.set_quota("default", quota)
```

---

## See Also

- [Security Specification](security-spec.md) - YAML format for `.agents/security.md`
- [Kernel Internals](kernel-internals.md) - How policies are enforced
- [Architecture](architecture.md) - System overview
