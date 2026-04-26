# Concepts

## Why Agent Reliability Is Different

Traditional services fail in predictable ways: crashes, timeouts, out-of-memory. You monitor latency, error rate, uptime.

AI agents fail differently:

| Traditional Service | AI Agent |
|---|---|
| Crash → HTTP 500 | Hallucinate → HTTP 200 (looks fine!) |
| Predictable failures | Same input, different output |
| Stack trace tells you why | No stack trace for "wrong answer" |
| Retry usually works | Retry might give same wrong answer |
| Infrastructure problem | Reasoning problem |

Your APM dashboard says "everything is green" while your agent approves a fraudulent transaction.

## Agent-Specific SLIs

Agent-SRE introduces SLIs that measure **agent behavior**, not infrastructure:

### Task Success Rate
Did the agent complete the task correctly?

```python
# Infrastructure SLI: "Did the HTTP request succeed?"
# Agent SLI: "Did the agent give the right answer?"

success = TaskSuccessRate(target=0.95, window="24h")
success.record_task(success=True)  # Based on your evaluation logic
```

### Hallucination Rate
How often does the agent generate incorrect or fabricated information?

```python
hallucination = HallucinationRate(target=0.05, window="24h")
hallucination.record_evaluation(hallucinated=True, confidence=0.9)
```

### Cost Per Task
How much does each agent task cost in LLM inference?

```python
cost = CostPerTask(target_usd=0.50, window="24h")
cost.record_cost(cost_usd=0.35)
```

### Policy Compliance
Is the agent following governance rules?

```python
compliance = PolicyCompliance(target=1.0, window="24h")
compliance.record_check(compliant=True)
```

## Error Budgets for Non-Deterministic Systems

Traditional error budgets assume deterministic systems: a request either succeeds or fails. Agent error budgets account for uncertainty:

```python
budget = ErrorBudget(
    total=0.05,              # 5% error budget (95% reliability target)
    burn_rate_alert=2.0,     # Alert if burning 2x faster than sustainable
    burn_rate_critical=10.0, # Page if burning 10x faster
)
```

**Burn rate** is how fast you're consuming your error budget. A burn rate of 1.0 means you'll exhaust the budget exactly at the end of the window. A burn rate of 10.0 means you'll exhaust it in 1/10th the time — something is wrong.

## The Agent-SRE Stack

```
Your Agent Code
    ↓ instrument with SLIs
Agent-SRE (this library)
    ├── SLO Engine        — "Is my agent reliable enough?"
    ├── Cost Guard        — "Is my agent too expensive?"
    ├── Staged Rollout    — "Is agent v2 better than v1?"
    ├── Chaos Engine      — "What happens when tools fail?"
    ├── Replay Engine     — "What exactly happened 3 hours ago?"
    └── Incident Detector — "Something went wrong, what do we do?"
    ↓ integrates with
Agent-OS (kernel)       — Deterministic policy enforcement
AgentMesh (trust)       — Cross-agent identity and trust scoring
```

Agent-SRE sits between your agent code and the infrastructure. It answers the question: **"Is my agent making good decisions?"** — not "Is my server up?"
