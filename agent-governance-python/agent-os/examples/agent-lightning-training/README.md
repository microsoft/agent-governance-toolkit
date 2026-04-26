# Agent-Lightning Training Examples

Training examples that demonstrate Agent OS governance during RL training.

## Examples

### 1. SQL Agent (`sql_agent.py`)

Train a SQL agent that:
- Generates accurate SQL queries
- Never violates safety policies (no DROP/DELETE)
- Stays within cost limits

```bash
python sql_agent.py
```

## How It Works

1. **GovernedRunner** wraps agent execution with policy checks
2. **PolicyReward** converts violations to negative RL rewards
3. Agent learns to avoid policy violations during training
4. Result: Safe agent from day one

## Requirements

```bash
pip install agent-os-kernel agentlightning
```

## Expected Output

```
SQL Agent Training with Agent-Lightning + Agent OS
==================================================

✓ Kernel initialized with policies
✓ GovernedRunner initialized
✓ PolicyReward function created

Episode 1: SELECT * FROM users...
  Status: ✅ SUCCESS
  Violations: 0
  Reward: 5.85

Episode 3: DROP TABLE users...
  Status: ❌ BLOCKED
  Violations: 1
  ⚠️  SQLPolicy: Dangerous SQL operation blocked
  Reward: -100.00

Training Summary:
  Violation rate: 33.3%
  Clean rate: 66.7%
```
