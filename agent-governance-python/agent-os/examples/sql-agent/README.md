# SQL Agent with Financial Controls

AI-powered natural language to SQL agent with built-in cost controls, dangerous query prevention, and audit logging.

## Features

- **Natural Language to SQL**: Convert plain English to SQL queries
- **Cost Controls**: Prevent runaway queries with configurable limits
- **Dangerous Query Prevention**: Block DROP, DELETE, TRUNCATE without approval
- **Multi-Model Verification**: Validate queries across multiple LLMs
- **Full Audit Trail**: Log every query for compliance

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL=postgresql://user:pass@localhost/db
export OPENAI_API_KEY=your_openai_key  # For NL to SQL

# Run the demo
python main.py
```

## Usage

### Basic Query

```python
from sql_agent import SQLAgent

agent = SQLAgent(
    database_url="postgresql://...",
    max_cost_usd=100,
    require_approval_for=["DELETE", "DROP", "TRUNCATE"]
)

# Natural language query
result = await agent.query("Show me top 10 customers by revenue")
print(result.data)
```

### With Cost Controls

```python
agent = SQLAgent(
    max_cost_usd=50,          # Max $50 per query
    max_rows=10000,           # Max 10K rows returned
    max_execution_time=30,    # 30 second timeout
    require_explain=True      # Always run EXPLAIN first
)

# This will check estimated cost before executing
result = await agent.query("Get all transactions from last year")

if result.blocked:
    print(f"Query blocked: {result.block_reason}")
    print(f"Estimated cost: ${result.estimated_cost}")
```

### With Approval Workflow

```python
# Dangerous operations require human approval
result = await agent.query("Delete inactive users from last year")

if result.requires_approval:
    print("⚠️ This query requires approval:")
    print(f"  SQL: {result.sql}")
    print(f"  Affected rows: ~{result.estimated_rows}")
    
    # In production, this would go to an approval queue
    if get_human_approval():
        result = await agent.execute_approved(result.approval_token)
```

## Cost Estimation

The agent estimates query cost using:

1. **EXPLAIN ANALYZE** - Get actual execution plan
2. **Row estimates** - Based on table statistics
3. **Historical data** - Learn from past queries

```
📊 Query Cost Estimate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Query: SELECT * FROM transactions WHERE year = 2023
Estimated Rows: 1,247,832
Estimated Time: 12.4s
Estimated Cost: $2.14 (based on compute time)
Budget Remaining: $47.86

Status: ✅ APPROVED (within limits)
```

## Dangerous Query Prevention

These patterns trigger approval requirements:

| Pattern | Risk Level | Default Action |
|---------|------------|----------------|
| `DROP TABLE` | CRITICAL | Block + Alert |
| `DELETE FROM` (no WHERE) | CRITICAL | Block |
| `TRUNCATE` | HIGH | Require Approval |
| `DELETE FROM` (with WHERE) | MEDIUM | Require Approval |
| `UPDATE` (no WHERE) | CRITICAL | Block |
| `ALTER TABLE` | MEDIUM | Require Approval |

## Multi-Model Verification

For high-risk queries, the agent validates with multiple LLMs:

```python
agent = SQLAgent(
    verification_models=["gpt-4", "claude-3", "gemini-pro"],
    consensus_threshold=0.8  # 80% agreement required
)

# Query is validated by all models before execution
result = await agent.query("Calculate total revenue by region")
print(f"Consensus: {result.verification.consensus_score}")
print(f"Models agreed: {result.verification.models_agreed}")
```

## Audit Trail

Every query is logged for compliance:

```json
{
  "timestamp": "2024-02-05T14:32:15Z",
  "query_id": "QRY-2024-00123",
  "user_id": "analyst_jane",
  "natural_language": "Show top customers",
  "generated_sql": "SELECT * FROM customers ORDER BY revenue DESC LIMIT 10",
  "estimated_cost": 0.02,
  "actual_cost": 0.01,
  "rows_returned": 10,
  "execution_time_ms": 45,
  "status": "success",
  "verification": {
    "models": ["gpt-4", "claude-3"],
    "consensus": 1.0
  }
}
```

## Metrics

```
📊 SQL Agent Dashboard (Last 7 Days)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Queries Executed:      847
Total Cost:         $12.34
Queries Blocked:        12  🚫
Approvals Required:      8  ⏳
Avg Response Time:   1.2s  ⚡
Cost Savings:      $18.7K  💰
  (from blocked runaway queries)
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                Natural Language Input                    │
│         "Show me top 10 customers by revenue"           │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│              NL to SQL (LLM)                             │
│   "SELECT name, revenue FROM customers                   │
│    ORDER BY revenue DESC LIMIT 10"                       │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│              Agent OS Kernel                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │
│  │   Policy    │  │    Cost     │  │   CMVK      │      │
│  │   Check     │  │  Estimator  │  │  Verify     │      │
│  └─────────────┘  └─────────────┘  └─────────────┘      │
└─────────────────────┬───────────────────────────────────┘
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│   ✅ EXECUTE    │     │   🚫 BLOCK/     │
│   (Safe Query)  │     │   ⏳ APPROVE    │
└─────────────────┘     └─────────────────┘
```
