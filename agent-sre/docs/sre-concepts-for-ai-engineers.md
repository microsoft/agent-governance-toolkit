# SRE Concepts for AI Engineers

> A practical guide to Site Reliability Engineering for teams building and operating AI agents. If you know AI but not SRE, start here.

---

## Table of Contents

- [What Is SRE?](#what-is-sre)
- [Why AI Agents Need SRE](#why-ai-agents-need-sre)
- [Key SRE Concepts Applied to AI Agents](#key-sre-concepts-applied-to-ai-agents)
  - [SLIs — Service Level Indicators](#slis--service-level-indicators)
  - [SLOs — Service Level Objectives](#slos--service-level-objectives)
  - [Error Budgets](#error-budgets)
  - [Burn Rate](#burn-rate)
  - [Chaos Testing](#chaos-testing)
  - [Canary Deployments](#canary-deployments)
  - [Circuit Breakers](#circuit-breakers)
  - [Incident Management](#incident-management)
- [Mapping Traditional SRE to Agent SRE](#mapping-traditional-sre-to-agent-sre)
- [Quick Start with Agent SRE](#quick-start-with-agent-sre)
- [Further Reading](#further-reading)

---

## What Is SRE?

Site Reliability Engineering (SRE) is a discipline created at Google that applies software engineering to operations problems. Instead of hoping a system stays up, SRE defines measurable reliability targets, budgets for acceptable failure, and automated responses when things go wrong.

The core philosophy is simple: **100% reliability is the wrong target.** Every system fails. The question is how much failure your users can tolerate, and how you spend that failure budget to move fast without breaking trust.

SRE gives you three things:

1. **A shared language** for reliability — SLIs, SLOs, and error budgets replace vague notions of "it should work" with measurable contracts.
2. **Automated guardrails** — Circuit breakers, canary deployments, and chaos tests catch problems before users do.
3. **Incident discipline** — When things break (they will), you have runbooks, alerting, and postmortems to recover fast and prevent recurrence.

---

## Why AI Agents Need SRE

Traditional services fail in ways your APM catches — crashes, timeouts, 500 errors. AI agents fail differently, and these failures are far more dangerous because they're invisible.

### Agents fail silently

Your monitoring says "HTTP 200, all green" while your agent just hallucinated a medical dosage, approved a fraudulent transaction, or fabricated a citation. There's no stack trace for "wrong answer."

### No error budgets

Most teams have zero tolerance for agent errors in theory, but no measurement in practice. Without an error budget, you can't make rational trade-offs between velocity and reliability. Every bug becomes a crisis, or worse, every bug gets ignored.

### No SLOs for AI

Traditional SLOs measure uptime and latency. But an agent that responds in 200ms with a hallucinated answer isn't reliable — it's fast and wrong. AI agents need SLOs that measure **decision quality**, not just availability.

### Cascading failures in multi-agent systems

When Agent A calls Agent B, which calls Agent C, a failure in C can cascade backward. Without circuit breakers, one flaky tool or one overloaded model can take down your entire agent workflow. This is [OWASP ASI08 — Cascading Failures](https://github.com/microsoft/agent-governance-toolkit/blob/master/docs/owasp-agentic-top10-mapping.md).

### Cost runaway without guardrails

An agent stuck in a retry loop can burn through thousands of dollars in API calls in minutes. Without cost guardrails, a single bad prompt or infinite loop can exhaust your monthly budget before anyone notices.

---

## Key SRE Concepts Applied to AI Agents

### SLIs — Service Level Indicators

**Traditional SRE:** SLIs are the metrics you measure — request latency, error rate, throughput.

**Agent SRE:** SLIs measure agent *behavior*, not infrastructure. The question isn't "Did the server respond?" but "Did the agent give a good answer?"

Agent SRE defines seven SLI types purpose-built for AI agents:

| SLI | What It Measures | Example |
|-----|-----------------|---------|
| **Task Success Rate** | Did the agent complete the task correctly? | 95% of tasks completed successfully |
| **Hallucination Rate** | How often does the agent fabricate information? | < 5% of responses contain hallucinations |
| **Cost Per Task** | How much does each agent task cost? | Average cost under $0.50 per task |
| **Latency** | Time to first token and total response time | p99 latency under 3 seconds |
| **Policy Compliance** | Is the agent following governance rules? | 100% compliance with safety policies |
| **Tool Call Success** | Are the agent's tool calls succeeding? | > 98% tool calls return valid results |
| **User Satisfaction** | Explicit or implicit user feedback | > 4.0/5.0 average rating |

```python
from agent_sre.slo.indicators import TaskSuccessRate, CostPerTask, HallucinationRate

# Define what you measure
success = TaskSuccessRate(target=0.95, window="24h")
cost = CostPerTask(target_usd=0.50, window="24h")
hallucination = HallucinationRate(target=0.05, window="24h")

# Record observations after each agent task
success.record_task(success=True)
cost.record_cost(cost_usd=0.35)
hallucination.record_evaluation(hallucinated=False)
```

### SLOs — Service Level Objectives

**Traditional SRE:** "99.9% of requests must complete in under 200ms."

**Agent SRE:** "99.5% of agent responses must be accurate, and 95% of tasks must cost under $0.50."

An SLO combines your SLIs into a reliability target with a time window. It answers the question: **"Is my agent reliable enough?"**

```python
from agent_sre import SLO, ErrorBudget

slo = SLO(
    name="customer-support-agent",
    description="Production support agent reliability targets",
    indicators=[success, cost, hallucination],
    error_budget=ErrorBudget(total=0.05),  # 5% error budget
)

# After each task, record whether it was a "good" event
slo.record_event(good=True)

# Evaluate SLO health
status = slo.evaluate()  # HEALTHY | WARNING | CRITICAL | EXHAUSTED
```

SLO status levels:

| Status | Meaning | Action |
|--------|---------|--------|
| **HEALTHY** | Within budget, all indicators meeting targets | Continue deploying |
| **WARNING** | Budget burning faster than sustainable | Investigate, slow down deploys |
| **CRITICAL** | Budget almost exhausted | Stop feature work, fix reliability |
| **EXHAUSTED** | No budget remaining | Freeze deployments until budget recovers |

### Error Budgets

**Traditional SRE:** "We can tolerate 0.1% downtime per month (43 minutes). If we've used 40 minutes, stop deploying risky changes."

**Agent SRE:** "We can tolerate 5% bad responses this month. If we've used 4.5% of our budget, freeze model upgrades and prompt changes until the budget recovers."

Error budgets turn reliability from a binary "good/bad" into a spendable resource. They let you make rational trade-offs:

- **Budget remaining?** Ship that new prompt template.
- **Budget exhausted?** Focus on reliability. No new features until quality recovers.

```python
budget = ErrorBudget(
    total=0.05,              # 5% error budget (95% reliability target)
    burn_rate_alert=2.0,     # Alert if burning 2x faster than sustainable
    burn_rate_critical=10.0, # Page if burning 10x faster
)

# Check budget status
print(f"Budget remaining: {budget.remaining_percent:.1f}%")
print(f"Exhausted: {budget.is_exhausted}")
```

**Exhaustion actions** — what happens when the budget runs out:

| Action | Description |
|--------|-------------|
| `ALERT` | Notify the team |
| `FREEZE_DEPLOYMENTS` | Block new agent versions |
| `CIRCUIT_BREAK` | Open circuit breakers to reduce blast radius |
| `THROTTLE` | Reduce agent traffic or capabilities |

### Burn Rate

**Traditional SRE:** "At the current error rate, we'll exhaust our monthly budget in 3 days."

**Agent SRE:** "At the current hallucination rate, our error budget will be gone in 6 hours."

Burn rate measures how fast you're consuming your error budget. A burn rate of 1.0 means you'll exhaust the budget exactly at the end of the window. Higher is worse.

| Burn Rate | Meaning | Time to Exhaustion (30-day budget) |
|-----------|---------|-----------------------------------|
| 1.0x | Sustainable | 30 days |
| 2.0x | Concerning | 15 days |
| 5.0x | Bad | 6 days |
| 10.0x | Critical | 3 days |
| 30.0x | Outage | 1 day |

```python
# Check burn rate over the last hour
rate = slo.error_budget.burn_rate(window_seconds=3600)
print(f"Burn rate (1h): {rate:.1f}x")

# Check for firing alerts
for alert in slo.error_budget.firing_alerts():
    print(f"⚠️  {alert.name}: burn rate = {alert.rate:.1f}x")
```

### Chaos Testing

**Traditional SRE:** "We randomly kill servers to prove the system can handle failures."

**Agent SRE:** "We inject failures into agent dependencies — slow LLM responses, tool errors, corrupted context — to prove agents degrade gracefully."

Chaos testing for AI agents goes beyond infrastructure failures. You need to test what happens when:

- The LLM responds with 5-second latency instead of 500ms
- A tool call returns an error or garbage data
- Context is truncated or corrupted
- The agent's memory is unavailable
- A downstream agent in a chain is unreachable

```python
from agent_sre.chaos.engine import ChaosExperiment, Fault, AbortCondition

# Define the experiment
experiment = ChaosExperiment(
    name="llm-latency-spike",
    description="What happens when the LLM takes 5x longer?",
    duration_seconds=300,
    blast_radius=0.5,  # Affect 50% of requests
    abort_conditions=[
        AbortCondition(metric="success_rate", threshold=0.80, comparator="lte"),
    ],
)

# Define faults to inject
latency_fault = Fault.latency_injection(
    target="llm-provider",
    delay_ms=5000,
    rate=0.5,
)

# Run the experiment
experiment.start()
experiment.inject_fault(latency_fault, applied=True, details="5s latency added")

# Evaluate resilience
score = experiment.calculate_resilience(
    baseline_success_rate=0.95,
    experiment_success_rate=0.88,
)
print(f"Resilience score: {score.score}/100 ({'PASS' if score.passed else 'FAIL'})")
```

### Canary Deployments

**Traditional SRE:** "Route 5% of traffic to the new server version. If error rates spike, roll back."

**Agent SRE:** "Route 5% of traffic to the new model/prompt. If hallucination rate increases or accuracy drops, roll back automatically."

Canary deployments are essential for AI agents because model upgrades and prompt changes can cause unpredictable regressions. A model that scores better on benchmarks might perform worse on your specific workload.

```python
from agent_sre.delivery.rollout import CanaryRollout, RollbackCondition, RolloutStep

rollout = CanaryRollout(
    name="assistant-v2",
    steps=[
        RolloutStep(weight=0.05, duration_seconds=60,  name="5% canary"),
        RolloutStep(weight=0.25, duration_seconds=120, name="25% ramp"),
        RolloutStep(weight=1.0,  duration_seconds=0,   name="full rollout"),
    ],
    rollback_conditions=[
        RollbackCondition(metric="error_rate", threshold=0.10, comparator="gte"),
        RollbackCondition(metric="hallucination_rate", threshold=0.08, comparator="gte"),
    ],
)

rollout.start()

# At each stage, evaluate the candidate
metrics = evaluate_new_version()
if rollout.check_rollback(metrics):
    rollout.rollback(reason="Hallucination rate exceeded threshold")
else:
    rollout.advance()
```

### Circuit Breakers

**Traditional SRE:** "If a downstream service fails 5 times, stop calling it for 30 seconds."

**Agent SRE:** "If an agent fails 5 times, stop routing tasks to it and use a fallback."

Circuit breakers prevent cascading failures in multi-agent systems. When Agent A depends on Agent B, and Agent B starts failing, the circuit breaker stops Agent A from hammering Agent B with requests that will fail, and instead returns a fallback response.

Three states:

```
CLOSED (normal) → failures exceed threshold → OPEN (blocking)
                                                    ↓
                                              timeout expires
                                                    ↓
                                              HALF_OPEN (testing)
                                              ↓              ↓
                                         success           failure
                                              ↓              ↓
                                           CLOSED          OPEN
```

```python
from agent_sre.cascade.breaker import CircuitBreaker, CircuitBreakerConfig

breaker = CircuitBreaker(
    agent_id="research-agent",
    config=CircuitBreakerConfig(
        failure_threshold=5,           # Open after 5 failures
        recovery_timeout_seconds=30,   # Try again after 30s
        half_open_max_calls=1,         # Allow 1 test call
    ),
)

# Wrap agent calls with the circuit breaker
result = breaker.call(
    func=research_agent.run,
    query="summarize this paper",
    fallback="Unable to process request. Please try again later.",
)

# The circuit breaker automatically:
# - Tracks successes and failures
# - Opens the circuit after 5 consecutive failures
# - Raises CircuitOpenError (or returns fallback) when open
# - Lets a test call through after 30s to check recovery
```

### Incident Management

**Traditional SRE:** "PagerDuty alert → On-call engineer → Runbook → Postmortem."

**Agent SRE:** "SLO breach detected → Signal correlated → Incident created → Automated runbook executes → Team notified."

Agent SRE detects incidents by correlating multiple signals — an SLO breach plus a cost spike plus a latency increase is likely one incident, not three separate alerts.

```python
from agent_sre.incidents.detector import IncidentDetector, Signal, SignalType

detector = IncidentDetector(correlation_window_seconds=60)

# Ingest signals from different sources
signal = Signal(
    signal_type=SignalType.SLO_BREACH,
    source="customer-support-agent",
    message="Task success rate dropped below 95% target",
)

incident = detector.ingest_signal(signal)
if incident:
    print(f"🚨 Incident: {incident.title}")
    print(f"   Severity: {incident.severity.value}")  # P1, P2, P3, P4
    incident.acknowledge()
    # ... run remediation ...
    incident.resolve()
```

Signal types Agent SRE monitors:

| Signal | Trigger |
|--------|---------|
| `SLO_BREACH` | SLO target violated |
| `ERROR_BUDGET_EXHAUSTED` | Error budget fully consumed |
| `COST_ANOMALY` | Spending exceeds z-score threshold |
| `LATENCY_SPIKE` | Response time exceeds baseline |
| `TOOL_FAILURE_SPIKE` | Tool call failure rate spikes |
| `POLICY_VIOLATION` | Agent violated a governance policy |
| `TRUST_REVOCATION` | Agent trust score dropped (via AgentMesh) |

---

## Mapping Traditional SRE to Agent SRE

| Traditional SRE | Agent SRE | Why It's Different |
|-----------------|-----------|-------------------|
| **Uptime** (is the server running?) | **Response quality** (is the answer correct?) | A 200 OK with a hallucinated answer isn't "up" |
| **Request latency** (p50, p99) | **Token latency** (time to first token, total generation) | LLM inference has different latency profiles than CRUD APIs |
| **Error rate** (5xx responses) | **Hallucination rate** (fabricated information) | No HTTP status code for "made up a fake citation" |
| **Throughput** (requests/sec) | **Task completion rate** (tasks/hour) | Agent tasks are multi-step, not single request-response |
| **CPU/Memory** | **Token usage / Cost per task** | The expensive resource is LLM inference, not compute |
| **Deployment rollback** | **Model/prompt rollback** | Rolling back a prompt change, not a binary artifact |
| **Circuit breaker** (service→service) | **Circuit breaker** (agent→agent) | Agent failures are semantic, not just timeouts |
| **Canary deployment** (5% of servers) | **Canary deployment** (5% of traffic to new model) | Test new models on real traffic before full rollout |
| **Chaos testing** (kill a server) | **Chaos testing** (inject LLM latency, tool errors) | Test agent resilience to dependency failures |
| **Runbook** (restart service, scale up) | **Runbook** (switch model, disable tool, throttle) | Remediation is model/prompt-level, not infrastructure |
| **SLO** (99.9% uptime) | **SLO** (95% task success, < 5% hallucination) | Multi-dimensional: quality + cost + safety |
| **Error budget** (43 min downtime/month) | **Error budget** (5% bad responses/month) | Budget spent on bad answers, not downtime |
| **On-call rotation** | **Agent-aware on-call** | Alerts include agent context, traces, and decision logs |

---

## Quick Start with Agent SRE

A complete example — define SLOs, set cost guardrails, and detect incidents in 30 lines:

```python
"""Monitor an AI agent with SRE best practices."""

from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import TaskSuccessRate, CostPerTask, HallucinationRate
from agent_sre.cost.guard import CostGuard
from agent_sre.cascade.breaker import CircuitBreaker, CircuitBreakerConfig
from agent_sre.incidents.detector import IncidentDetector, Signal, SignalType

# ── 1. Define what "reliable" means ────────────────────────────────────

success = TaskSuccessRate(target=0.95, window="24h")
cost = CostPerTask(target_usd=0.50, window="24h")
hallucination = HallucinationRate(target=0.05, window="24h")

slo = SLO(
    name="my-agent",
    indicators=[success, cost, hallucination],
    error_budget=ErrorBudget(total=0.05, burn_rate_critical=10.0),
)

# ── 2. Set cost guardrails ─────────────────────────────────────────────

guard = CostGuard(
    per_task_limit=2.00,
    per_agent_daily_limit=50.0,
    org_monthly_budget=1000.0,
)

# ── 3. Add circuit breaker for downstream agents ──────────────────────

breaker = CircuitBreaker(
    agent_id="my-agent",
    config=CircuitBreakerConfig(failure_threshold=5, recovery_timeout_seconds=30),
)

# ── 4. Wire up incident detection ─────────────────────────────────────

detector = IncidentDetector(correlation_window_seconds=60)

# ── 5. Run your agent with SRE guardrails ──────────────────────────────

def run_agent_task(query: str):
    # Check cost budget
    allowed, reason = guard.check_task("my-agent", estimated_cost=0.50)
    if not allowed:
        return f"Blocked: {reason}"

    # Execute with circuit breaker
    result = breaker.call(
        func=your_agent.run,
        query=query,
        fallback="Service temporarily unavailable.",
    )

    # Record SLI observations
    is_good = evaluate_response(result)
    success.record_task(success=is_good)
    slo.record_event(good=is_good)
    guard.record_cost("my-agent", "task-1", cost_usd=0.35)

    # Check SLO health
    status = slo.evaluate()
    if status.value == "EXHAUSTED":
        signal = Signal(
            signal_type=SignalType.ERROR_BUDGET_EXHAUSTED,
            source="my-agent",
            message="Error budget consumed — freeze deployments",
        )
        detector.ingest_signal(signal)

    return result
```

Install and run:

```bash
pip install agent-sre
python examples/quickstart.py
```

---

## Further Reading

### SRE Foundations

- [Google SRE Book](https://sre.google/sre-book/table-of-contents/) — The definitive guide to Site Reliability Engineering
- [Google SRE Workbook](https://sre.google/workbook/table-of-contents/) — Practical examples and exercises
- [The Art of SLOs](https://sre.google/resources/practices-and-processes/art-of-slos/) — How to set meaningful SLOs

### Agent SRE Documentation

- [Getting Started](getting-started.md) — Install and define your first SLO
- [Concepts](concepts.md) — How agent SLIs differ from infrastructure metrics
- [SLO Reference](slo-reference.md) — Complete SLO configuration guide with templates
- [Integration Guide](integration-guide.md) — Use with LangChain, CrewAI, LangGraph, and more
- [Deployment Guide](deployment.md) — Production deployment patterns
- [Security](security.md) — Security considerations for agent reliability

### Ecosystem

- [Agent OS](https://github.com/microsoft/agent-governance-toolkit) — Governance kernel for AI agents
- [AgentMesh](https://github.com/microsoft/agent-governance-toolkit) — Identity and trust for multi-agent systems
- [Agent Runtime](https://github.com/microsoft/agent-governance-toolkit) — Runtime session management
- [OWASP Agentic Security Mapping](https://github.com/microsoft/agent-governance-toolkit/blob/master/docs/owasp-agentic-top10-mapping.md) — How Agent SRE addresses OWASP ASI08

### Examples

- [`quickstart.py`](../examples/quickstart.py) — Full working example in 30 lines
- [`canary_rollout.py`](../examples/canary_rollout.py) — Safe model upgrades with automatic rollback
- [`cost_guard.py`](../examples/cost_guard.py) — Budget enforcement and anomaly detection
- [`chaos_test.py`](../examples/chaos_test.py) — Fault injection for agent dependencies
- [`slo_alerting.py`](../examples/slo_alerting.py) — Multi-channel alert routing
