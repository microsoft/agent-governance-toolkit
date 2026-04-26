# SLO Reference for AI Agents

> Complete reference for defining, configuring, and operating Service Level Objectives for AI agent systems.

---

## Table of Contents

- [Overview](#overview)
- [SLI Types](#sli-types)
- [SLO Configuration](#slo-configuration)
- [Error Budget Configuration](#error-budget-configuration)
- [SLO Templates](#slo-templates)
  - [Customer Support Agent](#customer-support-agent)
  - [Code Generation Agent](#code-generation-agent)
  - [Data Analysis Agent](#data-analysis-agent)
  - [RAG / Knowledge Agent](#rag--knowledge-agent)
  - [Multi-Agent Orchestrator](#multi-agent-orchestrator)
  - [Content Moderation Agent](#content-moderation-agent)
  - [Autonomous Task Agent](#autonomous-task-agent)
- [Choosing Targets](#choosing-targets)
- [Alerting on SLOs](#alerting-on-slos)
- [SLO-Driven Workflows](#slo-driven-workflows)

---

## Overview

An SLO (Service Level Objective) defines how reliable your AI agent needs to be. It combines:

- **SLIs** (Service Level Indicators) — The metrics you measure
- **Targets** — The thresholds those metrics must meet
- **Error Budget** — How much failure is acceptable
- **Actions** — What happens when the budget runs out

```python
from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import TaskSuccessRate, CostPerTask, HallucinationRate

slo = SLO(
    name="my-agent",
    description="Production reliability targets",
    indicators=[
        TaskSuccessRate(target=0.95, window="24h"),
        CostPerTask(target_usd=0.50, window="24h"),
        HallucinationRate(target=0.05, window="24h"),
    ],
    error_budget=ErrorBudget(total=0.05),
)
```

---

## SLI Types

Agent SRE ships seven SLI types designed for AI agent workloads:

### TaskSuccessRate

Measures whether the agent completed tasks correctly.

```python
from agent_sre.slo.indicators import TaskSuccessRate

sli = TaskSuccessRate(target=0.95, window="24h")
sli.record_task(success=True)
sli.record_task(success=False)

print(sli.current_value())   # 0.5
print(sli.compliance())      # 0.5 (fraction of window meeting target)
```

**When to use:** Every agent should track task success. This is the most fundamental SLI.

**How to evaluate success:** Use your own evaluation logic — LLM-as-judge, human review, automated checks, or ground truth comparison.

### HallucinationRate

Measures how often the agent fabricates information.

```python
from agent_sre.slo.indicators import HallucinationRate

sli = HallucinationRate(target=0.05, window="24h")
sli.record_evaluation(hallucinated=True, confidence=0.9)
sli.record_evaluation(hallucinated=False, confidence=0.95)
```

**When to use:** Any agent that generates factual claims — support bots, research agents, RAG systems.

**How to detect hallucinations:** Compare against source documents, use a separate evaluator model, or check factual claims against a knowledge base.

### CostPerTask

Measures LLM inference cost per agent task.

```python
from agent_sre.slo.indicators import CostPerTask

sli = CostPerTask(target_usd=0.50, window="24h")
sli.record_cost(cost_usd=0.35)
```

**When to use:** Any agent calling paid LLM APIs. Prevents cost runaway and catches inefficient prompts.

### Latency

Measures agent response time.

```python
from agent_sre.slo.indicators import Latency

sli = Latency(target_ms=3000, window="24h", percentile=0.99)
sli.record_latency(duration_ms=1200)
```

**When to use:** User-facing agents where response time matters. Less critical for batch/async agents.

### PolicyCompliance

Measures whether the agent follows governance rules.

```python
from agent_sre.slo.indicators import PolicyCompliance

sli = PolicyCompliance(target=1.0, window="24h")
sli.record_check(compliant=True)
```

**When to use:** Regulated industries, agents with safety-critical outputs, or when using [Agent OS](https://github.com/microsoft/agent-governance-toolkit) governance policies.

### ToolCallSuccess

Measures whether agent tool calls succeed.

```python
from agent_sre.slo.indicators import ToolCallSuccess

sli = ToolCallSuccess(target=0.98, window="24h")
sli.record_call(success=True)
```

**When to use:** Agents with external tool dependencies (APIs, databases, search). Helps isolate whether failures come from the agent's reasoning or its tools.

### UserSatisfaction

Measures explicit or implicit user feedback.

```python
from agent_sre.slo.indicators import UserSatisfaction

sli = UserSatisfaction(target=4.0, window="24h", scale=5.0)
sli.record_rating(rating=4.5)
```

**When to use:** Customer-facing agents with feedback mechanisms. Use thumbs up/down, star ratings, or implicit signals like retry rate.

---

## SLO Configuration

### Python API

```python
from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import TaskSuccessRate, HallucinationRate

slo = SLO(
    name="support-agent",
    description="Customer support agent reliability",
    indicators=[
        TaskSuccessRate(target=0.95, window="24h"),
        HallucinationRate(target=0.05, window="24h"),
    ],
    error_budget=ErrorBudget(
        total=0.05,
        burn_rate_alert=2.0,
        burn_rate_critical=10.0,
    ),
)
```

### YAML Configuration

Agent SRE supports YAML-based SLO specs with inheritance:

```yaml
# slos/base.yaml — shared defaults
name: base
description: Base SLO template
window: 30d
error_budget:
  total: 0.05
  burn_rate_alert: 2.0
  burn_rate_critical: 10.0
  exhaustion_action: FREEZE_DEPLOYMENTS

# slos/support-agent.yaml — inherits from base
name: support-agent
inherits: base
description: Customer support agent
indicators:
  - type: task_success_rate
    target: 0.95
  - type: hallucination_rate
    target: 0.03
  - type: cost_per_task
    target_usd: 0.40
```

Load YAML specs:

```python
from agent_sre.slo.spec import load_slo_specs, resolve_inheritance

specs = load_slo_specs("slos/")
resolved = resolve_inheritance(specs)
```

### SLO Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `str` | Unique identifier for the SLO |
| `description` | `str` | Human-readable description |
| `indicators` | `list[SLI]` | SLIs that this SLO tracks |
| `error_budget` | `ErrorBudget` | Error budget configuration |
| `window` | `str` | Rolling window (e.g., `"24h"`, `"7d"`, `"30d"`) |

---

## Error Budget Configuration

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `total` | `float` | — | Total error budget as fraction (0.05 = 5%) |
| `burn_rate_alert` | `float` | `2.0` | Alert when burn rate exceeds this multiple |
| `burn_rate_critical` | `float` | `10.0` | Page when burn rate exceeds this multiple |

### Exhaustion Actions

What happens when the error budget is fully consumed:

| Action | Description | Use When |
|--------|-------------|----------|
| `ALERT` | Send notification to team | Low-risk agents, advisory SLOs |
| `FREEZE_DEPLOYMENTS` | Block new agent versions | Production agents with staged rollout |
| `CIRCUIT_BREAK` | Open circuit breakers | Multi-agent systems with fallbacks |
| `THROTTLE` | Reduce agent traffic or capabilities | High-volume agents where partial service is better than none |

### Burn Rate Alerts

Configure multi-window burn rate alerts for early warning:

```python
budget = ErrorBudget(
    total=0.05,
    burn_rate_alert=2.0,      # 2x → budget gone in 15 days (30-day window)
    burn_rate_critical=10.0,  # 10x → budget gone in 3 days
)

# Check current burn rate
rate = budget.burn_rate(window_seconds=3600)  # Last 1 hour

# Get all firing alerts
for alert in budget.firing_alerts():
    print(f"{alert.name}: {alert.rate:.1f}x burn rate")
```

---

## SLO Templates

Copy-paste templates for common agent types. Adjust targets based on your requirements.

### Customer Support Agent

High accuracy, low hallucination, moderate cost tolerance.

```python
from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import (
    TaskSuccessRate, HallucinationRate, CostPerTask,
    Latency, PolicyCompliance, UserSatisfaction,
)

support_slo = SLO(
    name="customer-support",
    description="Customer-facing support agent — accuracy is critical",
    indicators=[
        TaskSuccessRate(target=0.95, window="24h"),
        HallucinationRate(target=0.03, window="24h"),      # Strict: < 3%
        CostPerTask(target_usd=0.40, window="24h"),
        Latency(target_ms=3000, window="24h", percentile=0.99),
        PolicyCompliance(target=1.0, window="24h"),
        UserSatisfaction(target=4.0, window="7d", scale=5.0),
    ],
    error_budget=ErrorBudget(
        total=0.05,
        burn_rate_alert=2.0,
        burn_rate_critical=10.0,
    ),
)
```

**Key considerations:**
- Hallucination target is strict (3%) because wrong answers erode customer trust
- Policy compliance is 100% — support agents must not violate safety rules
- User satisfaction measured over 7 days for statistical significance

### Code Generation Agent

Quality over speed, higher cost tolerance, low hallucination.

```python
code_gen_slo = SLO(
    name="code-generator",
    description="Code generation agent — correctness over speed",
    indicators=[
        TaskSuccessRate(target=0.90, window="24h"),         # Code is hard
        HallucinationRate(target=0.05, window="24h"),
        CostPerTask(target_usd=1.00, window="24h"),        # Higher budget
        Latency(target_ms=10000, window="24h", percentile=0.99),  # 10s OK
    ],
    error_budget=ErrorBudget(
        total=0.10,              # 10% budget — code gen is harder
        burn_rate_alert=3.0,
        burn_rate_critical=10.0,
    ),
)
```

**Key considerations:**
- Lower success target (90%) — code generation is inherently harder
- Higher cost tolerance — complex code may need multiple LLM calls
- Generous latency — users expect code generation to take time
- Larger error budget reflects the difficulty of the task

### Data Analysis Agent

Accuracy critical, moderate latency, cost scales with data volume.

```python
analysis_slo = SLO(
    name="data-analyst",
    description="Data analysis agent — accuracy is paramount",
    indicators=[
        TaskSuccessRate(target=0.97, window="24h"),         # High accuracy
        HallucinationRate(target=0.02, window="24h"),       # Very strict
        CostPerTask(target_usd=2.00, window="24h"),        # Data-heavy
        Latency(target_ms=30000, window="24h", percentile=0.99),  # 30s OK
    ],
    error_budget=ErrorBudget(
        total=0.03,              # 3% budget — wrong analysis is costly
        burn_rate_alert=2.0,
        burn_rate_critical=5.0,
    ),
)
```

**Key considerations:**
- Tight hallucination threshold (2%) — fabricated data insights are dangerous
- Higher cost per task — analysis often requires multiple queries and large contexts
- Generous latency — analysis tasks are expected to take longer
- Small error budget — wrong analysis leads to bad business decisions

### RAG / Knowledge Agent

Grounding is everything, latency matters, cost moderate.

```python
rag_slo = SLO(
    name="knowledge-agent",
    description="RAG agent — grounded answers from source documents",
    indicators=[
        TaskSuccessRate(target=0.93, window="24h"),
        HallucinationRate(target=0.03, window="24h"),       # Must stay grounded
        CostPerTask(target_usd=0.30, window="24h"),
        Latency(target_ms=5000, window="24h", percentile=0.99),
        ToolCallSuccess(target=0.99, window="24h"),         # Retrieval must work
    ],
    error_budget=ErrorBudget(
        total=0.07,
        burn_rate_alert=2.0,
        burn_rate_critical=10.0,
    ),
)
```

**Key considerations:**
- Tool call success is critical — if retrieval fails, the agent can't ground its answers
- Hallucination threshold is strict — the whole point of RAG is grounded answers
- Moderate cost — retrieval adds overhead but keeps generation costs down

### Multi-Agent Orchestrator

Coordinates multiple agents, cascade protection critical.

```python
from agent_sre.cascade.breaker import CircuitBreaker, CircuitBreakerConfig

orchestrator_slo = SLO(
    name="orchestrator",
    description="Multi-agent orchestrator — cascade protection is critical",
    indicators=[
        TaskSuccessRate(target=0.92, window="24h"),
        CostPerTask(target_usd=3.00, window="24h"),        # Multi-agent is expensive
        Latency(target_ms=15000, window="24h", percentile=0.99),
    ],
    error_budget=ErrorBudget(
        total=0.08,              # 8% budget — multi-agent is complex
        burn_rate_alert=2.0,
        burn_rate_critical=5.0,
    ),
)

# Each downstream agent gets a circuit breaker
research_breaker = CircuitBreaker(
    agent_id="research-agent",
    config=CircuitBreakerConfig(failure_threshold=5, recovery_timeout_seconds=30),
)

writer_breaker = CircuitBreaker(
    agent_id="writer-agent",
    config=CircuitBreakerConfig(failure_threshold=3, recovery_timeout_seconds=60),
)
```

**Key considerations:**
- Lower success target — orchestration is harder than single-agent tasks
- Higher cost — multiple agents means multiple LLM calls
- Circuit breakers on every downstream agent to prevent cascading failures
- Wider error budget acknowledges the complexity of multi-agent coordination

### Content Moderation Agent

Safety is non-negotiable, false negatives are worse than false positives.

```python
moderation_slo = SLO(
    name="content-moderator",
    description="Content moderation — safety over speed",
    indicators=[
        TaskSuccessRate(target=0.99, window="24h"),         # Must catch violations
        HallucinationRate(target=0.01, window="24h"),       # Near-zero tolerance
        CostPerTask(target_usd=0.10, window="24h"),        # High volume, low cost
        Latency(target_ms=1000, window="24h", percentile=0.99),  # Must be fast
        PolicyCompliance(target=1.0, window="24h"),
    ],
    error_budget=ErrorBudget(
        total=0.01,              # 1% budget — safety-critical
        burn_rate_alert=1.5,
        burn_rate_critical=3.0,
    ),
)
```

**Key considerations:**
- Very tight targets across the board — moderation failures have real consequences
- Low cost per task — moderation is high-volume, must be cheap
- Fast latency — moderation should not be the bottleneck
- Tiny error budget with sensitive burn rate alerts

### Autonomous Task Agent

Long-running tasks, reliability over speed, cost visibility critical.

```python
from agent_sre.cost.guard import CostGuard

autonomous_slo = SLO(
    name="autonomous-task-agent",
    description="Autonomous agent — completes tasks without supervision",
    indicators=[
        TaskSuccessRate(target=0.90, window="24h"),
        HallucinationRate(target=0.05, window="24h"),
        CostPerTask(target_usd=5.00, window="24h"),         # Complex tasks
        PolicyCompliance(target=1.0, window="24h"),
    ],
    error_budget=ErrorBudget(
        total=0.10,
        burn_rate_alert=3.0,
        burn_rate_critical=10.0,
    ),
)

# Autonomous agents MUST have cost guardrails
guard = CostGuard(
    per_task_limit=10.00,           # Hard limit per task
    per_agent_daily_limit=100.0,    # Daily cap
    org_monthly_budget=5000.0,      # Monthly cap
)
```

**Key considerations:**
- Lower success target — autonomous tasks are complex and multi-step
- High cost tolerance but strict cost guardrails — prevent runaway spending
- Policy compliance is 100% — unsupervised agents must follow rules
- Generous error budget with aggressive burn rate alerts for early warning

---

## Choosing Targets

Setting the right SLO targets is more art than science. Here are guidelines:

### Start Loose, Tighten Over Time

1. **Week 1:** Measure your current baseline without targets
2. **Week 2:** Set targets at your current performance level
3. **Month 2:** Tighten targets by 2-5 percentage points
4. **Ongoing:** Tighten as you improve, but never target 100%

### The "100% Is Wrong" Rule

Never set a 100% target for task success or 0% for hallucination rate. You'll either:
- Exhaust your error budget immediately and ignore it
- Never deploy anything because you can't afford a single failure

### Target Guidelines by Risk Level

| Risk Level | Task Success | Hallucination | Error Budget | Example |
|-----------|-------------|---------------|-------------|---------|
| **Safety-critical** | ≥ 99% | ≤ 1% | 1% | Medical, financial, legal |
| **Customer-facing** | ≥ 95% | ≤ 3% | 5% | Support, sales, onboarding |
| **Internal tool** | ≥ 90% | ≤ 5% | 10% | Code gen, analysis, search |
| **Experimental** | ≥ 80% | ≤ 10% | 20% | Research, prototypes |

### Cost Target Guidelines

| Agent Type | Cost Per Task | Daily Budget | Rationale |
|-----------|--------------|-------------|-----------|
| Simple Q&A | $0.01–$0.10 | $10–$50 | Single LLM call, short context |
| Support agent | $0.20–$0.50 | $50–$200 | Multi-turn, tool calls |
| Code generation | $0.50–$2.00 | $100–$500 | Long context, multiple attempts |
| Data analysis | $1.00–$5.00 | $200–$1000 | Large data, multiple queries |
| Autonomous agent | $2.00–$10.00 | $500–$2000 | Multi-step, multi-tool |

---

## Alerting on SLOs

### Multi-Channel Alert Routing

Route SLO alerts to the right channels based on severity:

```python
from agent_sre.alerts.manager import AlertManager
from agent_sre.alerts.channels import ChannelConfig

manager = AlertManager()

# P1/P2 → PagerDuty
manager.add_channel(ChannelConfig(
    name="pagerduty",
    channel_type="pagerduty",
    min_severity="P2",
    config={"routing_key": "your-pagerduty-key"},
))

# P3+ → Slack
manager.add_channel(ChannelConfig(
    name="slack-alerts",
    channel_type="slack",
    min_severity="P3",
    config={"webhook_url": "https://hooks.slack.com/..."},
))
```

### Burn Rate Alert Windows

Use multi-window burn rate alerts for reliable early warning with low false-positive rates:

| Window | Burn Rate | Detects | Alert Delay |
|--------|-----------|---------|-------------|
| 1 hour | 14.4x | Fast-burning incidents | ~5 minutes |
| 6 hours | 6.0x | Moderate degradation | ~30 minutes |
| 24 hours | 3.0x | Slow drift | ~2 hours |
| 72 hours | 1.0x | Long-term trends | ~6 hours |

---

## SLO-Driven Workflows

### Development Workflow

```
Code Change → Run Tests → Check SLO Impact → Deploy Canary → Monitor Burn Rate → Full Rollout
                              ↓
                         Budget exhausted?
                              ↓
                     Yes → Block deploy, fix first
```

### Incident Response Workflow

```
Burn Rate Alert → Check SLO Dashboard → Identify Root Cause → Execute Runbook → Verify Recovery
    ↓
Signal correlated with cost anomaly?
    ↓
Yes → Check CostGuard → Throttle if needed
```

### Continuous Improvement

1. **Weekly:** Review SLO dashboard, check burn rate trends
2. **Monthly:** Review error budget consumption, adjust targets if needed
3. **Quarterly:** Review SLO definitions, add/remove indicators
4. **After incidents:** Update SLOs based on lessons learned

---

## Related Documentation

- [SRE Concepts for AI Engineers](sre-concepts-for-ai-engineers.md) — Introduction to SRE for AI teams
- [Getting Started](getting-started.md) — Install and define your first SLO
- [Concepts](concepts.md) — How agent SLIs differ from infrastructure metrics
- [Integration Guide](integration-guide.md) — Framework adapters and observability platforms
