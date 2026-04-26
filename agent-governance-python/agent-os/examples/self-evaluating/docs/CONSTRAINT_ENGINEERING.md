# Constraint Engineering (The Logic Firewall)

## The Problem with Pure Prompt Engineering

**The Old World:**
> "Prompt Engineering. We need to find the perfect magic words to tell the AI not to delete the database."

**The Reality:**
- Prompting is fragile
- A "jailbreak" can bypass your polite instructions in seconds
- We cannot rely on the AI's "self-control" for safety
- One wrong token and your production database is gone

## The Engineering Solution: Logic Firewall

Instead of hoping the AI behaves, we build a **deterministic safety layer** between the AI and your infrastructure.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AI Agent Flow                         │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  1. Brain (LLM)                                          │
│     └─► Generates Plan                                   │
│         "I will query the DB and email the user"         │
│                                                           │
│  2. Firewall (Constraint Engine) ◄── YOU ARE HERE       │
│     └─► Deterministic Python Code                        │
│         ├─ Check: DROP TABLE in SQL?                     │
│         ├─ Check: User allowed to email this domain?     │
│         ├─ Check: Cost of action < $0.05?                │
│         └─ Decision: APPROVE or BLOCK                    │
│                                                           │
│  3. Hand (Executor)                                      │
│     └─► Execute (only if approved)                       │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

## Key Principles

### 1. Separation of Concerns

- **Brain (LLM)**: Creative, high-temperature, generates plans
- **Firewall (Python)**: Deterministic, strict, validates plans
- **Hand (Executor)**: Dumb, only executes approved plans

### 2. Never Trust the AI

The AI should NEVER have direct access to:
- Database operations
- File system operations
- Network operations
- Payment systems
- User data

### 3. Human-Built Walls

> **"The Human builds the walls; the AI plays inside them."**

You define the constraints in code. The AI cannot argue with `if` statements.

## Implementation

### Core Components

#### 1. Constraint Rules

Each rule is a Python class that validates one aspect of safety:

```python
class SQLInjectionRule(ConstraintRule):
    """Detects dangerous SQL operations."""
    
    DANGEROUS_PATTERNS = [
        r'\bDROP\s+TABLE\b',
        r'\bDELETE\s+FROM\b.*\bWHERE\s+1\s*=\s*1\b',
        r';\s*DROP\b',  # SQL injection
    ]
    
    def validate(self, plan: Dict[str, Any]) -> List[ConstraintViolation]:
        # Deterministic checking - no LLM involved
        if plan.get("action_type") == "sql_query":
            query = plan.get("action_data", {}).get("query", "")
            for pattern in self.DANGEROUS_PATTERNS:
                if re.search(pattern, query, re.IGNORECASE):
                    return [ConstraintViolation(...)]
        return []
```

#### 2. Constraint Engine

The firewall that sits between AI and execution:

```python
engine = ConstraintEngine(rules=[
    SQLInjectionRule(),
    FileOperationRule(),
    CostLimitRule(max_cost_per_action=0.05),
    EmailDomainRule(allowed_domains=["company.com"]),
])

# Validate before execution
result = engine.validate_plan(ai_generated_plan)

if result.approved:
    execute(plan)
else:
    log_security_violation(result.violations)
```

#### 3. Violation Severity

Not all violations are equal:

- **CRITICAL**: Immediate danger (e.g., `DROP TABLE`) → Block
- **HIGH**: Serious risk (e.g., delete system files) → Block
- **MEDIUM**: Policy violation (e.g., wrong email domain) → Block
- **LOW**: Warning (e.g., approaching cost limit) → Allow with warning

## Built-in Safety Rules

### 1. SQL Injection Prevention

Blocks:
- `DROP TABLE/DATABASE`
- `DELETE FROM ... WHERE 1=1`
- SQL injection patterns (`;`, `--`, `/* */`)
- `TRUNCATE TABLE`
- `ALTER TABLE ... DROP`

Allows:
- Parameterized SELECT queries
- Safe INSERT/UPDATE with proper conditions

### 2. File Operation Safety

Blocks:
- `rm -rf /` (and variants)
- Operations on protected paths (`/etc`, `/sys`, `/boot`, `C:\Windows`)
- Mass deletion commands
- Disk formatting operations

Allows:
- Operations in user directories
- Safe file reads and writes

### 3. Cost Limit Enforcement

Blocks:
- Actions exceeding configured cost limit (default: $0.05)

Warns:
- Actions approaching the cost limit (>80%)

Allows:
- Cost-effective operations

### 4. Email Domain Restriction

Blocks:
- Emails to unapproved domains

Allows:
- Emails only to whitelisted domains

### 5. Rate Limiting

Blocks:
- Actions exceeding rate limits

Allows:
- Operations within rate limits

## Usage

### Basic Usage

```python
from constraint_engine import create_default_engine

# Create firewall with sensible defaults
engine = create_default_engine(
    max_cost=0.05,
    allowed_domains=["example.com", "company.com"]
)

# AI generates a plan (could be dangerous)
ai_plan = {
    "action_type": "sql_query",
    "action_data": {
        "query": "DROP TABLE users"  # Dangerous!
    }
}

# Firewall intercepts and validates
result = engine.validate_plan(ai_plan, verbose=True)

if result.approved:
    execute_action(ai_plan)
else:
    print("🚫 Blocked by firewall!")
    for violation in result.violations:
        print(f"  - {violation.message}")
```

### Integration with Agent

```python
from agent import DoerAgent
from constraint_engine import ConstraintEngine, create_default_engine

class SafeAgent(DoerAgent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.firewall = create_default_engine()
    
    def execute_with_firewall(self, plan):
        # Intercept all actions through firewall
        result = self.firewall.validate_plan(plan)
        
        if not result.approved:
            return {
                "success": False,
                "error": "Blocked by firewall",
                "violations": [v.message for v in result.violations]
            }
        
        # Safe to execute
        return self.execute(plan)
```

### Custom Rules

Add your own domain-specific rules:

```python
from constraint_engine import ConstraintRule, ConstraintViolation, ViolationSeverity

class PaymentLimitRule(ConstraintRule):
    def __init__(self, max_amount: float = 100.0):
        super().__init__("payment_limit", "Limits payment amounts")
        self.max_amount = max_amount
    
    def validate(self, plan):
        if plan.get("action_type") == "payment":
            amount = plan.get("action_data", {}).get("amount", 0)
            if amount > self.max_amount:
                return [ConstraintViolation(
                    rule_name=self.name,
                    severity=ViolationSeverity.HIGH,
                    message=f"Payment ${amount} exceeds limit ${self.max_amount}",
                    blocked_action=f"Payment of ${amount}"
                )]
        return []

# Add to engine
engine = ConstraintEngine()
engine.add_rule(PaymentLimitRule(max_amount=100.0))
```

## Key Benefits

### 1. Use Creative AI Safely

You can use high-temperature models (0.9) for creativity because the firewall provides deterministic safety:

```python
# OLD: Low temperature to avoid mistakes (boring)
model_temperature = 0.1

# NEW: High temperature for creativity (safe)
model_temperature = 0.9
# Firewall catches mistakes deterministically
```

### 2. Defense in Depth

Multiple layers of validation:
- SQL injection patterns
- File path restrictions
- Cost limits
- Domain whitelists
- Rate limits

### 3. Auditability

Every blocked action is logged:
```python
for violation in result.violations:
    logger.warning(f"Security violation: {violation.message}")
    logger.warning(f"Blocked action: {violation.blocked_action}")
```

### 4. Extensibility

Easy to add new rules for your domain:
- PII detection
- Compliance checks (GDPR, HIPAA)
- Business logic validation
- Custom security policies

## Testing

Run the test suite:
```bash
python test_constraint_engineering.py
```

Run the demonstration:
```bash
python example_constraint_engineering.py
```

## Examples

See `example_constraint_engineering.py` for demonstrations of:
1. Blocking dangerous SQL operations
2. Blocking dangerous file operations
3. Enforcing cost limits
4. Restricting email domains
5. Approving safe operations
6. Using creative AI with firewall safety

## Architecture Philosophy

### The Lesson

> **"Never let the AI touch the infrastructure directly."**
> 
> **"The Human builds the walls; the AI plays inside them."**

### Why This Matters

1. **Prompt Engineering is Fragile**: A jailbreak can bypass your instructions
2. **Constraint Engineering is Deterministic**: Python code doesn't negotiate
3. **Trust but Verify**: Use powerful AI, but verify with code
4. **Safety by Design**: Build safety into the architecture, not the prompt

### The Future

As AI becomes more powerful, we need **stronger walls**, not better prompts:

- Prompts can be manipulated
- Code cannot be negotiated
- The firewall is always on duty
- Safety is deterministic, not probabilistic

## Related Concepts

This approach is inspired by:
- **Principle of Least Privilege**: Only grant necessary permissions
- **Defense in Depth**: Multiple layers of security
- **Fail-Safe Defaults**: Default to denying dangerous actions
- **Separation of Concerns**: AI generates, code validates, executor runs

## Future Enhancements

Potential additions to the constraint engine:
1. **PII Detection**: Block exposure of sensitive data
2. **Compliance Rules**: Enforce GDPR, HIPAA, SOC2
3. **Business Logic**: Validate against business rules
4. **ML-based Anomaly Detection**: Learn normal patterns
5. **Policy as Code**: Define policies in configuration files
6. **Real-time Monitoring**: Dashboard for blocked actions
7. **Adaptive Thresholds**: Learn safe limits over time

## Conclusion

The Constraint Engine (Logic Firewall) is a deterministic safety layer that:
- ✅ Blocks dangerous operations before execution
- ✅ Enables use of creative/high-temperature AI models
- ✅ Provides auditability and logging
- ✅ Is extensible for custom rules
- ✅ Makes safety a first-class architectural concern

**Remember**: The Human builds the walls; the AI plays inside them.
