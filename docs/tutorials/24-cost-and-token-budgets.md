<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Tutorial 24 — Cost and Token Budgets

Control agent spend by enforcing per-session token limits and context budget
allocation. This tutorial covers the `TokenBudgetTracker` for tracking
consumption against hard limits and the `ContextScheduler` for kernel-level
budget enforcement with the "scale by subtraction" philosophy — 90% lookup,
10% reasoning.

> **Package:** `agent-os-kernel`
> **Modules:** `agent_os.integrations.token_budget`, `agent_os.context_budget`
> **Concept:** The kernel owns the budget; agents cannot exceed it

---

## What you'll learn

| Section | Topic |
|---------|-------|
| [Why Token Budgets Matter](#why-token-budgets-matter) | Cost control and reliability |
| [TokenBudgetTracker](#tokenbudgettracker) | Per-agent token tracking with warnings |
| [ContextScheduler](#contextscheduler) | Kernel-level budget allocation and enforcement |
| [Budget Enforcement in Governance](#budget-enforcement-in-governance) | Integrating with the policy pipeline |
| [Monitoring Budget Utilisation](#monitoring-budget-utilisation) | Progress bars, health reports, signal handlers |
| [Full Example](#full-example-capped-research-agent) | Cap a research agent at 100K tokens |
| [Cross-Reference](#cross-reference) | Related tutorials |

---

## Prerequisites

- **Python 3.10+**
- `pip install agent-os-kernel`
- Recommended: read [Tutorial 01 — Policy Engine](01-policy-engine.md)

---

## Why Token Budgets Matter

Without budget enforcement, agents can:

1. **Exhaust API credits** — A runaway reasoning loop can burn thousands of
   dollars in minutes
2. **Starve other agents** — One greedy agent consumes the entire context
   window, leaving nothing for peers
3. **Degrade quality** — Overly long contexts dilute relevant information with
   noise

Token budgets enforce the principle that **the kernel owns resources, not the
agent**. Agents request allocations; the kernel decides how much to grant.

---

## TokenBudgetTracker

The `TokenBudgetTracker` provides per-agent token tracking with configurable
warning thresholds and callbacks.

### §2.1 Basic Usage

```python
from agent_os.integrations.token_budget import TokenBudgetTracker

# Create a tracker with a 10,000 token budget
tracker = TokenBudgetTracker(max_tokens=10_000)

# Record token usage
status = tracker.record_usage(
    agent_id="researcher",
    prompt_tokens=500,
    completion_tokens=200,
)

print(status.used)        # 700
print(status.remaining)   # 9300
print(status.percentage)  # 0.07
print(status.is_warning)  # False
print(status.is_exceeded) # False
```

### §2.2 Warning Thresholds

The `warning_threshold` parameter (0.0–1.0) controls when `is_warning`
activates:

```python
tracker = TokenBudgetTracker(
    max_tokens=10_000,
    warning_threshold=0.8,  # warn at 80% usage
)

# Simulate usage approaching the limit
tracker.record_usage("agent-x", prompt_tokens=4000, completion_tokens=0)
status = tracker.record_usage("agent-x", prompt_tokens=4500, completion_tokens=0)
print(status.is_warning)  # True — 85% used
print(status.is_exceeded) # False

# Exceed the budget
status = tracker.record_usage("agent-x", prompt_tokens=2000, completion_tokens=0)
print(status.is_exceeded) # True — 105% used
```

### §2.3 Warning Callbacks

Register a callback to be notified when the warning threshold is crossed:

```python
def on_budget_warning(agent_id: str, status):
    print(f"⚠️  Agent '{agent_id}' at {status.percentage:.0%} budget "
          f"({status.used:,}/{status.limit:,} tokens)")

tracker = TokenBudgetTracker(
    max_tokens=100_000,
    warning_threshold=0.8,
    on_warning=on_budget_warning,
)

# This triggers the callback when crossing 80%
for _ in range(9):
    tracker.record_usage("researcher", prompt_tokens=10_000, completion_tokens=0)

# Output: ⚠️  Agent 'researcher' at 80% budget (80,000/100,000 tokens)
```

### §2.4 Checking Budget Status

```python
# Check without recording usage
status = tracker.get_usage("researcher")
print(status.used)       # current total
print(status.remaining)  # tokens left

# Alias
status = tracker.check_budget("researcher")
```

### §2.5 Resetting Budgets

```python
# Reset an agent's usage (e.g., start of new session)
tracker.reset("researcher")
status = tracker.get_usage("researcher")
print(status.used)  # 0
```

### §2.6 CLI-Friendly Progress Bar

```python
print(tracker.format_status("researcher"))
# [████████░░] 82% (82,000/100,000 tokens)
```

### §2.7 Integrating with GovernancePolicy

The tracker can read its default `max_tokens` from a `GovernancePolicy`:

```python
from agent_os.integrations.base import GovernancePolicy

policy = GovernancePolicy(max_tokens=50_000)
tracker = TokenBudgetTracker(policy=policy)

# Budget limit comes from the policy
status = tracker.get_usage("agent-y")
print(status.limit)  # 50000
```

---

## ContextScheduler

The `ContextScheduler` is a kernel-level primitive that allocates context
windows to agents, enforces the 90/10 lookup/reasoning split, and emits
signals when budgets are crossed.

### §3.1 Creating a Scheduler

```python
from agent_os.context_budget import ContextScheduler, ContextPriority

scheduler = ContextScheduler(
    total_budget=128_000,    # total token pool across all agents
    lookup_ratio=0.90,       # 90% for retrieval, 10% for reasoning
    warn_threshold=0.85,     # SIGWARN at 85% usage
)
```

### §3.2 Allocating Context Windows

```python
# Allocate a context window for an agent
window = scheduler.allocate(
    agent_id="researcher",
    task="analyse quarterly reports",
    priority=ContextPriority.HIGH,
)

print(window.total)             # allocated tokens
print(window.lookup_budget)     # 90% for retrieval
print(window.reasoning_budget)  # 10% for reasoning
print(window.lookup_ratio)      # 0.9
print(window.reasoning_ratio)   # 0.1
```

### §3.3 Priority-Based Allocation

The scheduler scales allocations based on task priority:

| Priority | Minimum Tokens | Allocation Strategy |
|----------|---------------|---------------------|
| `CRITICAL` | 4,000 | Full allocation even if pool is tight |
| `HIGH` | 2,000 | Large allocation |
| `NORMAL` | 1,000 | Standard allocation |
| `LOW` | 500 | Smallest possible allocation |

```python
# Critical task gets priority
critical_window = scheduler.allocate(
    agent_id="incident-responder",
    task="investigate production outage",
    priority=ContextPriority.CRITICAL,
)

# Low-priority task gets less
low_window = scheduler.allocate(
    agent_id="background-indexer",
    task="re-index documentation",
    priority=ContextPriority.LOW,
)
```

### §3.4 Explicit Token Caps

Override the scheduler's allocation with an explicit cap:

```python
window = scheduler.allocate(
    agent_id="capped-agent",
    task="quick lookup",
    priority=ContextPriority.NORMAL,
    max_tokens=5_000,  # never allocate more than 5K
)
print(window.total)  # ≤ 5000
```

### §3.5 Recording Usage

```python
# Record lookup token usage
record = scheduler.record_usage(
    agent_id="researcher",
    lookup_tokens=1_000,
    reasoning_tokens=0,
)
print(record.total_used)    # 1000
print(record.remaining)     # window.total - 1000
print(record.utilization)   # fraction of window used

# Record reasoning token usage
record = scheduler.record_usage(
    agent_id="researcher",
    lookup_tokens=0,
    reasoning_tokens=500,
)
```

### §3.6 Budget Enforcement (SIGSTOP)

When an agent exceeds its allocated budget, the scheduler raises
`BudgetExceeded`:

```python
from agent_os.context_budget import BudgetExceeded

try:
    # Exceed the allocated window
    scheduler.record_usage(
        agent_id="researcher",
        lookup_tokens=999_999,
    )
except BudgetExceeded as e:
    print(f"Stopped: {e}")
    # "Agent researcher exceeded context budget: 1000999/32000 tokens"
    print(e.agent_id)  # "researcher"
    print(e.budget)    # allocated total
    print(e.used)      # actual usage
```

### §3.7 Signal Handlers

Register handlers for kernel signals:

```python
from agent_os.context_budget import AgentSignal

def on_warning(agent_id, signal):
    print(f"⚠️  {agent_id} approaching budget limit")

def on_stop(agent_id, signal):
    print(f"🛑 {agent_id} budget exceeded — halting")

scheduler.on_signal(AgentSignal.SIGWARN, on_warning)
scheduler.on_signal(AgentSignal.SIGSTOP, on_stop)
```

| Signal | Trigger | Description |
|--------|---------|-------------|
| `SIGWARN` | `utilization ≥ warn_threshold` | Budget nearing limit |
| `SIGSTOP` | `utilization ≥ 1.0` | Budget exceeded — agent halted |
| `SIGRESUME` | Budget replenished | Agent can resume (manual) |

### §3.8 Releasing Allocations

When a task completes, release the allocation to return tokens to the pool:

```python
record = scheduler.release("researcher")
print(record.total_used)  # final usage
print(record.utilization)  # final utilization

# Tokens are now available for other agents
print(scheduler.available_tokens)
```

### §3.9 Health Reports

```python
report = scheduler.get_health_report()
print(report)
# {
#     "total_budget": 128000,
#     "available": 96000,
#     "utilization": 0.25,
#     "active_agents": 2,
#     "lookup_ratio": 0.9,
#     "agents": {
#         "incident-responder": {
#             "task": "investigate production outage",
#             "allocated": 32000,
#             "used": 5000,
#             "remaining": 27000,
#             "stopped": false
#         }
#     },
#     "history_count": 1
# }
```

---

## Budget Enforcement in Governance

Integrate token budgets with the governance pipeline to enforce spend limits
as part of policy evaluation:

```python
from agent_os.integrations.token_budget import TokenBudgetTracker
from agent_os.context_budget import ContextScheduler, ContextPriority

class GovernedAgent:
    """Agent with integrated budget enforcement."""

    def __init__(self, agent_id: str, session_budget: int = 100_000):
        self.agent_id = agent_id
        self.token_tracker = TokenBudgetTracker(
            max_tokens=session_budget,
            warning_threshold=0.8,
            on_warning=self._on_budget_warning,
        )
        self.scheduler = ContextScheduler(
            total_budget=session_budget,
            lookup_ratio=0.90,
        )

    def execute(self, task: str, priority=ContextPriority.NORMAL):
        # 1. Check budget before starting
        status = self.token_tracker.check_budget(self.agent_id)
        if status.is_exceeded:
            return {"error": "Session budget exceeded", "used": status.used}

        # 2. Allocate context window
        window = self.scheduler.allocate(
            self.agent_id, task, priority=priority,
        )

        # 3. Execute task (simulate LLM call)
        prompt_tokens = 500
        completion_tokens = 200

        # 4. Record usage
        self.token_tracker.record_usage(
            self.agent_id, prompt_tokens, completion_tokens,
        )
        self.scheduler.record_usage(
            self.agent_id,
            lookup_tokens=prompt_tokens,
            reasoning_tokens=completion_tokens,
        )

        # 5. Release allocation
        self.scheduler.release(self.agent_id)

        return {
            "task": task,
            "tokens_used": prompt_tokens + completion_tokens,
            "budget_remaining": self.token_tracker.get_usage(self.agent_id).remaining,
        }

    def _on_budget_warning(self, agent_id, status):
        print(f"⚠️  Budget warning: {status.percentage:.0%} used")
```

---

## Monitoring Budget Utilisation

### Progress Bar

```python
tracker = TokenBudgetTracker(max_tokens=100_000)

# Simulate incremental usage
for i in range(8):
    tracker.record_usage("agent", prompt_tokens=10_000, completion_tokens=0)
    print(tracker.format_status("agent"))

# Output:
# [█░░░░░░░░░] 10% (10,000/100,000 tokens)
# [██░░░░░░░░] 20% (20,000/100,000 tokens)
# [███░░░░░░░] 30% (30,000/100,000 tokens)
# [████░░░░░░] 40% (40,000/100,000 tokens)
# [█████░░░░░] 50% (50,000/100,000 tokens)
# [██████░░░░] 60% (60,000/100,000 tokens)
# [███████░░░] 70% (70,000/100,000 tokens)
# [████████░░] 80% (80,000/100,000 tokens)
```

### Scheduler Health Dashboard

```python
scheduler = ContextScheduler(total_budget=200_000)

scheduler.allocate("agent-a", "research", ContextPriority.HIGH)
scheduler.allocate("agent-b", "indexing", ContextPriority.LOW)

print(f"Pool utilisation: {scheduler.utilization:.0%}")
print(f"Available tokens: {scheduler.available_tokens:,}")
print(f"Active agents:    {scheduler.active_count}")
```

---

## Full Example: Capped Research Agent

Cap a research agent at 100K tokens per session:

```python
from agent_os.integrations.token_budget import TokenBudgetTracker
from agent_os.context_budget import (
    ContextScheduler, ContextPriority, AgentSignal, BudgetExceeded,
)

# ── Configuration ──
SESSION_BUDGET = 100_000
AGENT_ID = "research-agent"

# ── Set up budget tracking ──
tracker = TokenBudgetTracker(
    max_tokens=SESSION_BUDGET,
    warning_threshold=0.8,
    on_warning=lambda aid, s: print(
        f"⚠️  {aid} at {s.percentage:.0%} ({s.used:,}/{s.limit:,} tokens)"
    ),
)

scheduler = ContextScheduler(
    total_budget=SESSION_BUDGET,
    lookup_ratio=0.90,
    warn_threshold=0.85,
)

# Register signal handlers
scheduler.on_signal(AgentSignal.SIGWARN,
    lambda aid, sig: print(f"⚠️  Context warning for {aid}"))
scheduler.on_signal(AgentSignal.SIGSTOP,
    lambda aid, sig: print(f"🛑 Context budget exceeded for {aid}"))

# ── Simulate research tasks ──
tasks = [
    ("Analyse Q1 earnings",     ContextPriority.HIGH,   15_000, 3_000),
    ("Summarise competitor reports", ContextPriority.NORMAL, 20_000, 5_000),
    ("Extract key metrics",     ContextPriority.NORMAL, 10_000, 2_000),
    ("Generate final report",   ContextPriority.HIGH,   25_000, 8_000),
    ("Deep-dive appendix",      ContextPriority.LOW,    20_000, 5_000),
]

for task_name, priority, lookup_tok, reasoning_tok in tasks:
    # Check budget
    status = tracker.check_budget(AGENT_ID)
    if status.is_exceeded:
        print(f"\n🛑 Budget exceeded — skipping '{task_name}'")
        break

    print(f"\n📋 Task: {task_name}")
    print(f"   Budget: {tracker.format_status(AGENT_ID)}")

    # Allocate context
    window = scheduler.allocate(AGENT_ID, task_name, priority)
    print(f"   Allocated: {window.total:,} tokens "
          f"(lookup: {window.lookup_budget:,}, reasoning: {window.reasoning_budget:,})")

    # Record usage
    try:
        scheduler.record_usage(AGENT_ID, lookup_tok, reasoning_tok)
    except BudgetExceeded:
        print(f"   🛑 Context window exceeded")

    scheduler.release(AGENT_ID)

    # Track against session budget
    tracker.record_usage(AGENT_ID, lookup_tok, reasoning_tok)
    status = tracker.get_usage(AGENT_ID)
    print(f"   Used: {status.used:,} / {status.limit:,} "
          f"({status.percentage:.0%})")

# ── Final summary ──
print(f"\n{'='*50}")
print(f"Session summary for {AGENT_ID}:")
final = tracker.get_usage(AGENT_ID)
print(f"  Total used:    {final.used:,} tokens")
print(f"  Remaining:     {final.remaining:,} tokens")
print(f"  Utilisation:   {final.percentage:.0%}")
print(f"  Warning:       {final.is_warning}")
print(f"  Exceeded:      {final.is_exceeded}")
```

---

## Cross-Reference

| Concept | Tutorial |
|---------|----------|
| Policy engine integration | [Tutorial 01 — Policy Engine](./01-policy-engine.md) |
| Rate limiting | [Tutorial 14 — Kill Switch & Rate Limiting](./14-kill-switch-and-rate-limiting.md) |
| Observability | [Tutorial 13 — Observability & Tracing](./13-observability-and-tracing.md) |
| Agent reliability (SRE) | [Tutorial 05 — Agent Reliability](./05-agent-reliability.md) |

---

## Source Files

| Component | Location |
|-----------|----------|
| `TokenBudgetTracker` | `agent-governance-python/agent-os/src/agent_os/integrations/token_budget.py` |
| `ContextScheduler` | `agent-governance-python/agent-os/src/agent_os/context_budget.py` |
| `BudgetExceeded` | `agent-governance-python/agent-os/src/agent_os/context_budget.py` |
| `AgentSignal` | `agent-governance-python/agent-os/src/agent_os/context_budget.py` |

---

## Next Steps

- **Set per-agent budgets** based on your API pricing to avoid cost overruns
- **Combine with rate limiting** ([Tutorial 14](./14-kill-switch-and-rate-limiting.md))
  for both token and request-rate controls
- **Export budget metrics** to Prometheus or OpenTelemetry for dashboards
- **Use `ContextPriority.CRITICAL`** for incident response agents that need
  guaranteed allocation
- **Implement budget rollover** for agents that consistently under-utilise their
  allocation
