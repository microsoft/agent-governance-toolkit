# Tutorial 05 — Agent Reliability Engineering

> **Windows users:** If characters appear corrupted in your terminal, run `chcp 65001` before starting, or use Windows Terminal / VS Code terminal which support UTF-8 by default.
> **Package:** `agent-sre` · **Time:** 30 minutes · **Prerequisites:** Python 3.10+

---

## What You'll Learn

- SLOs and error budgets for autonomous agents
- Circuit breakers and automatic recovery
- Chaos testing for agent resilience
- Cost controls and rogue agent detection

---

Site Reliability Engineering (SRE) practices adapted for autonomous AI agents —
rogue detection, circuit breakers, SLOs, chaos testing, and cost controls.

> **Install:** `pip install agent-sre`
>
> **See also:** [Deployment Guides](../deployment/README.md) | [OWASP ASI Reference](https://owaspai.org/)

---

## Table of Contents

- [Why SRE for AI Agents?](#why-sre-for-ai-agents)
- [Quick Start: Rogue Detection](#quick-start-rogue-detection)
- [Circuit Breaker Pattern](#circuit-breaker-pattern)
- [SLO Tracking](#slo-tracking)
- [Chaos Testing](#chaos-testing)
- [Cost Controls](#cost-controls)
- [Putting It Together](#putting-it-together)

---

## Why SRE for AI Agents?

Traditional services fail in predictable ways — timeouts, crashes, resource
exhaustion. Agents add new failure modes:

| Failure Mode | Traditional Service | AI Agent |
|---|---|---|
| **Runaway loops** | Process hangs | Agent calls tools in an infinite loop, burning tokens |
| **Behavioral drift** | Bug in new deploy | Model update changes decision patterns silently |
| **Cost explosion** | Resource leak | Single task consumes $500 in API calls |
| **Rogue behavior** | Compromised service | Agent uses unauthorized tools or exfiltrates data |
| **Cascading failure** | Service dependency down | Agent A fails → Agent B retries → Agent C overloaded |

`agent-sre` gives you the building blocks to detect, contain, and recover from
all of these.

---

## Quick Start: Rogue Detection

The `RogueAgentDetector` (OWASP ASI-10) combines three signals to flag
compromised or malfunctioning agents:

1. **Tool-call frequency** — z-score spike detection over a sliding window
2. **Action entropy** — flags both suspiciously repetitive and chaotic behavior
3. **Capability violations** — tools used outside the agent's allowed profile

### Basic setup

```python
from agent_sre.anomaly import RogueAgentDetector, RogueDetectorConfig, RiskLevel

# Configure detection thresholds
config = RogueDetectorConfig(
    frequency_window_seconds=60.0,   # Sliding window for frequency analysis
    frequency_z_threshold=2.5,       # Standard deviations before flagging
    entropy_low_threshold=0.3,       # Too repetitive (possible loop)
    entropy_high_threshold=3.5,      # Too chaotic (possible compromise)
    quarantine_risk_level=RiskLevel.HIGH,  # Auto-quarantine at this level
)

detector = RogueAgentDetector(config=config)
```

### Define what each agent is allowed to do

```python
# Register allowed tools per agent
detector.register_capability_profile(
    agent_id="support-agent",
    allowed_tools=["search_kb", "create_ticket", "send_email"],
)

detector.register_capability_profile(
    agent_id="code-reviewer",
    allowed_tools=["read_file", "search_code", "post_comment"],
)
```

### Feed actions and assess risk

```python
import time

# Simulate normal behavior
for i in range(20):
    detector.record_action(
        agent_id="support-agent",
        action="search",
        tool_name="search_kb",
        timestamp=time.time() + i,
    )

# Assess risk
assessment = detector.assess("support-agent")
print(f"Risk: {assessment.risk_level.value}")          # "low"
print(f"Composite score: {assessment.composite_score}") # ~0.0
print(f"Quarantine? {assessment.quarantine_recommended}")  # False
```

### Detect a compromised agent

```python
# Agent starts using unauthorized tools rapidly
base = time.time() + 100
for i in range(50):
    detector.record_action(
        agent_id="support-agent",
        action="exfiltrate",
        tool_name="shell_exec",       # Not in allowed tools!
        timestamp=base + i * 0.5,     # 2 calls/second (frequency spike)
    )

assessment = detector.assess("support-agent", timestamp=base + 25)
print(f"Risk: {assessment.risk_level.value}")          # "high" or "critical"
print(f"Frequency score: {assessment.frequency_score}") # Elevated
print(f"Capability score: {assessment.capability_score}")  # >0 (violations)
print(f"Quarantine? {assessment.quarantine_recommended}")  # True

if assessment.quarantine_recommended:
    print(f"⚠ QUARANTINE agent '{assessment.agent_id}'")
```

---

## Circuit Breaker Pattern

When an agent starts failing, you don't want it to keep hammering downstream
services. The circuit breaker isolates failing agents automatically.

```
CLOSED ──(failures >= threshold)──→ OPEN ──(timeout elapsed)──→ HALF_OPEN
  ↑                                                                │
  └──────────(success)────────────────────────────────────────────←─┘
                                                   (failure) ──→ OPEN
```

### Using the cascade circuit breaker

```python
from agent_sre.cascade.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitOpenError,
)

# Configure: open after 3 failures, test recovery after 30s
config = CircuitBreakerConfig(
    failure_threshold=3,
    recovery_timeout_seconds=30.0,
    half_open_max_calls=1,
)

breaker = CircuitBreaker(agent_id="data-analyst", config=config)
```

### Wrap agent calls

```python
def run_agent_task(task: dict) -> str:
    """Your agent's main function."""
    # ... agent logic ...
    return "result"

# The circuit breaker wraps the call
try:
    result = breaker.call(run_agent_task, {"query": "revenue Q3"})
    print(f"Result: {result}")
except CircuitOpenError as e:
    print(f"Agent isolated: {e}")
    print(f"Retry after: {e.retry_after:.0f}s")
```

### Manual failure tracking

```python
# If you manage the call yourself:
try:
    result = run_agent_task(task)
    breaker.record_success()
except Exception:
    breaker.record_failure()
    raise

# Check state
print(f"State: {breaker.state}")            # CLOSED, OPEN, or HALF_OPEN
print(f"Failures: {breaker.failure_count}")

# Manual reset (e.g., after deploying a fix)
breaker.reset()
```

### Circuit breaker for multiple agents

```python
class AgentFleetBreakers:
    """Manage circuit breakers for a fleet of agents."""

    def __init__(self, config: CircuitBreakerConfig | None = None):
        self._config = config or CircuitBreakerConfig()
        self._breakers: dict[str, CircuitBreaker] = {}

    def get(self, agent_id: str) -> CircuitBreaker:
        if agent_id not in self._breakers:
            self._breakers[agent_id] = CircuitBreaker(agent_id, self._config)
        return self._breakers[agent_id]

    def open_circuits(self) -> list[str]:
        return [aid for aid, cb in self._breakers.items() if cb.state == "OPEN"]

fleet = AgentFleetBreakers(
    config=CircuitBreakerConfig(failure_threshold=5, recovery_timeout_seconds=60.0),
)

# Use per-agent breakers
cb = fleet.get("summarizer-agent")
cb.record_failure()
print(f"Open circuits: {fleet.open_circuits()}")
```

---

## SLO Tracking

Define what "reliable" means for your agents with Service Level Objectives
backed by error budgets and burn rate alerts.

### Available SLI types

| SLI Type | What It Measures | Example Target |
|---|---|---|
| Latency | Task completion time | p99 < 10s |
| Error rate | Fraction of failed tasks | < 1% |
| Cost | Per-task spend | < $0.50/task |
| Token usage | Tokens per completion | < 4096 |
| Hallucination | Factual accuracy score | > 95% |
| Tool success | Tool call success rate | > 99% |
| Human feedback | User satisfaction score | > 4.0/5.0 |

### Define an SLI and SLO

```python
from agent_sre.slo import SLI, SLIValue, SLO, ErrorBudget
from agent_sre.slo.indicators import TimeWindow
from agent_sre.slo.objectives import BurnRateAlert, ExhaustionAction

# Create a concrete SLI by subclassing
class TaskSuccessRateSLI(SLI):
    """Tracks task success rate."""

    def collect(self) -> SLIValue:
        values = self.values_in_window()
        if not values:
            return self.record(1.0)
        good = sum(1 for v in values if v.is_good)
        return self.record(good / len(values))

# 99.5% success rate target over a 24h window
success_sli = TaskSuccessRateSLI(
    name="task_success_rate",
    target=0.995,
    window="24h",
)

# Create the SLO with error budget
slo = SLO(
    name="code-reviewer-reliability",
    indicators=[success_sli],
    error_budget=ErrorBudget(
        total=0.005,                               # 0.5% error budget (1 - 0.995)
        window_seconds=2_592_000,                   # 30-day window
        burn_rate_alert=2.0,                        # Warn at 2× burn rate
        burn_rate_critical=10.0,                    # Critical at 10× burn rate
        exhaustion_action=ExhaustionAction.THROTTLE, # Auto-throttle on exhaustion
    ),
    agent_id="code-reviewer",
)
```

### Record events and check status

```python
# Record outcomes as they happen
for _ in range(95):
    slo.error_budget.record_event(good=True)

for _ in range(5):
    slo.error_budget.record_event(good=False)

# Check error budget
budget = slo.error_budget
print(f"Budget remaining: {budget.remaining_percent:.1f}%")
print(f"Exhausted: {budget.is_exhausted}")

# Check burn rate (are we burning budget too fast?)
burn_rate = budget.burn_rate(window_seconds=3600)  # Last hour
print(f"1h burn rate: {burn_rate:.2f}x")

# Check for firing alerts
for alert in budget.firing_alerts():
    print(f"🔥 {alert.name}: burn rate {burn_rate:.1f}x (threshold: {alert.rate}x)")
```

### SLO status reporting

```python
# Serialize for dashboards / alerting
status = slo.error_budget.to_dict()
# {
#   "total": 0.005,
#   "consumed": 5.0,
#   "remaining_percent": ...,
#   "is_exhausted": False,
#   "burn_rate": ...,
#   "exhaustion_action": "throttle",
#   "firing_alerts": ["burn_rate_critical"]
# }
```

---

## Chaos Testing

Inject faults into your agent pipeline to verify resilience *before*
production incidents find the gaps for you.

### Define an experiment

```python
from agent_sre.chaos import (
    ChaosExperiment,
    Fault,
    FaultType,
    AbortCondition,
    ResilienceScore,
)

# Create faults to inject
faults = [
    Fault.latency_injection("openai-api", delay_ms=5000, rate=0.3),
    Fault.error_injection("search_tool", error="timeout", rate=0.1),
    Fault.timeout_injection("database", delay_ms=30000, rate=0.05),
]

# Safety: abort if success rate drops below 50%
abort_conditions = [
    AbortCondition(metric="success_rate", threshold=0.5, comparator="lte"),
]

experiment = ChaosExperiment(
    name="llm-latency-resilience",
    target_agent="code-reviewer",
    faults=faults,
    duration_seconds=1800,       # 30 minutes
    abort_conditions=abort_conditions,
    blast_radius=0.3,            # Affect 30% of traffic
    description="Verify code-reviewer handles LLM latency gracefully",
)
```

### Run the experiment

```python
# Start the experiment
experiment.start()
print(f"State: {experiment.state.value}")  # "running"

# In your agent middleware, inject faults
for fault in experiment.faults:
    experiment.inject_fault(fault, applied=True)

# Periodically check abort conditions
metrics = {"success_rate": 0.85, "latency_p99": 8500}
if experiment.check_abort(metrics):
    print(f"Aborted: {experiment.abort_reason}")
else:
    # Experiment completed normally
    score = experiment.calculate_resilience(
        baseline_success_rate=0.99,
        experiment_success_rate=0.85,
    )
    experiment.complete(resilience=score)

print(f"Resilience: {experiment.resilience.overall:.0f}/100")
print(f"Passed: {experiment.resilience.passed}")
```

### Adversarial chaos testing

Test your agent's security boundaries with adversarial fault types:

```python
# Security-focused faults
security_faults = [
    Fault.prompt_injection("code-reviewer", technique="direct_override"),
    Fault.privilege_escalation("code-reviewer", target_role="admin"),
    Fault.tool_abuse("code-reviewer", tool_name="shell_exec"),
]

security_experiment = ChaosExperiment(
    name="security-boundary-test",
    target_agent="code-reviewer",
    faults=security_faults,
    duration_seconds=600,
    description="Verify agent rejects adversarial inputs",
)
```

### Use the chaos library for templates

```python
from agent_sre.chaos import ChaosLibrary, ExperimentTemplate

library = ChaosLibrary()

# List available templates
for template in library.list_templates():
    print(f"  {template.name}: {template.description}")

# Serialize experiment results for reporting
report = experiment.to_dict()
# Includes: experiment_id, state, faults, injection_count, resilience scores
```

---

## Cost Controls

Prevent runaway spending with per-task budgets, auto-throttle, and a
kill-switch.

### Set up cost guard

```python
from agent_sre.cost import CostGuard, AgentBudget, BudgetAction

guard = CostGuard(
    per_task_limit=2.00,          # Max $2 per task
    per_agent_daily_limit=50.00,  # Max $50/day per agent
    org_monthly_budget=5000.00,   # Org-wide cap
    auto_throttle=True,           # Throttle at 85% daily budget
    kill_switch_threshold=0.95,   # Kill agent at 95% daily budget
    anomaly_detection=True,       # Detect cost spikes
)
```

### Pre-flight checks

```python
# Before running an expensive task, check if budget allows it
allowed, reason = guard.check_task("research-agent", estimated_cost=1.50)
if not allowed:
    print(f"Blocked: {reason}")
else:
    # Run the task...
    pass
```

### Record costs and handle alerts

```python
# After each task, record the actual cost
alerts = guard.record_cost(
    agent_id="research-agent",
    task_id="task-001",
    cost_usd=0.45,
    breakdown={"input_tokens": 0.15, "output_tokens": 0.25, "tool_calls": 0.05},
)

for alert in alerts:
    print(f"[{alert.severity.value}] {alert.message}")
    if alert.action == BudgetAction.KILL:
        print("🛑 Agent killed — stop all tasks immediately")
    elif alert.action == BudgetAction.THROTTLE:
        print("⚠ Agent throttled — reduce task rate")
```

### Monitor budget utilization

```python
budget = guard.get_budget("research-agent")
print(f"Spent today: ${budget.spent_today_usd:.2f}")
print(f"Remaining:   ${budget.remaining_today_usd:.2f}")
print(f"Utilization: {budget.utilization_percent:.0f}%")
print(f"Avg/task:    ${budget.avg_cost_per_task:.4f}")
print(f"Throttled:   {budget.throttled}")
print(f"Killed:      {budget.killed}")
```

### Cost anomaly detection

```python
from agent_sre.cost import CostAnomalyDetector

anomaly_detector = CostAnomalyDetector()

# Feed historical cost data to build a baseline
for cost in [0.40, 0.42, 0.38, 0.45, 0.41, 0.39, 0.43, 0.40, 0.42, 0.38]:
    anomaly_detector.ingest(cost, agent_id="research-agent")

# Check a new data point for anomalies
result = anomaly_detector.ingest(4.50, agent_id="research-agent")
if result and result.is_anomaly:
    print(f"🚨 Cost anomaly: ${result.value:.2f} (expected {result.expected_range})")
    print(f"   Severity: {result.severity.value}, Score: {result.score:.1f}")
```

---

## Putting It Together

Here's a production-ready SRE pipeline that combines all the components:

```python
"""Production SRE pipeline for AI agents."""

import time

from agent_sre.anomaly import RogueAgentDetector, RogueDetectorConfig, RiskLevel
from agent_sre.cascade.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitOpenError,
)
from agent_sre.slo import SLI, SLIValue, SLO, ErrorBudget
from agent_sre.slo.indicators import TimeWindow
from agent_sre.slo.objectives import ExhaustionAction
from agent_sre.cost import CostGuard, BudgetAction


# ── 1. Configure all components ─────────────────────────────────────

AGENT_ID = "production-agent"

# Rogue detection
rogue_detector = RogueAgentDetector(
    config=RogueDetectorConfig(
        frequency_z_threshold=3.0,
        quarantine_risk_level=RiskLevel.HIGH,
    ),
)
rogue_detector.register_capability_profile(
    AGENT_ID,
    allowed_tools=["search", "read_file", "write_file", "run_tests"],
)

# Circuit breaker
breaker = CircuitBreaker(
    agent_id=AGENT_ID,
    config=CircuitBreakerConfig(
        failure_threshold=5,
        recovery_timeout_seconds=60.0,
    ),
)

# SLO tracking
class SuccessRateSLI(SLI):
    def collect(self) -> SLIValue:
        values = self.values_in_window()
        if not values:
            return self.record(1.0)
        good = sum(1 for v in values if v.is_good)
        return self.record(good / len(values))

slo = SLO(
    name=f"{AGENT_ID}-reliability",
    indicators=[SuccessRateSLI(name="success_rate", target=0.995, window="24h")],
    error_budget=ErrorBudget(
        total=0.005,
        exhaustion_action=ExhaustionAction.CIRCUIT_BREAK,
    ),
    agent_id=AGENT_ID,
)

# Cost guard
cost_guard = CostGuard(
    per_task_limit=2.00,
    per_agent_daily_limit=100.00,
    auto_throttle=True,
    kill_switch_threshold=0.95,
)


# ── 2. Agent execution wrapper ──────────────────────────────────────

def execute_task(agent_id: str, task: dict) -> dict:
    """Run a task through the full SRE pipeline."""

    # Pre-flight: cost check
    allowed, reason = cost_guard.check_task(agent_id, estimated_cost=task.get("est_cost", 0))
    if not allowed:
        return {"status": "blocked", "reason": reason}

    # Pre-flight: rogue check
    assessment = rogue_detector.assess(agent_id)
    if assessment.quarantine_recommended:
        return {
            "status": "quarantined",
            "risk_level": assessment.risk_level.value,
            "score": assessment.composite_score,
        }

    # Execute through circuit breaker
    try:
        result = breaker.call(_run_agent, agent_id, task)
    except CircuitOpenError as e:
        return {"status": "circuit_open", "retry_after": e.retry_after}
    except Exception as exc:
        slo.error_budget.record_event(good=False)
        return {"status": "error", "error": str(exc)}

    # Post-flight: record success + cost
    slo.error_budget.record_event(good=True)
    cost_alerts = cost_guard.record_cost(
        agent_id=agent_id,
        task_id=task["id"],
        cost_usd=result.get("cost", 0),
    )

    # Record action for rogue detection
    for tool in result.get("tools_used", []):
        rogue_detector.record_action(agent_id, action="tool_call", tool_name=tool)

    # Check for critical alerts
    for alert in cost_alerts:
        if alert.action == BudgetAction.KILL:
            breaker.record_failure()  # Trip the circuit breaker too

    return {"status": "success", "result": result, "alerts": [a.to_dict() for a in cost_alerts]}


def _run_agent(agent_id: str, task: dict) -> dict:
    """Placeholder for your actual agent logic."""
    return {
        "output": "task completed",
        "cost": 0.35,
        "tools_used": ["search", "read_file"],
    }


# ── 3. Run tasks ────────────────────────────────────────────────────

tasks = [
    {"id": "t1", "query": "Review PR #42", "est_cost": 0.50},
    {"id": "t2", "query": "Summarize docs", "est_cost": 0.30},
    {"id": "t3", "query": "Run test suite", "est_cost": 1.00},
]

for task in tasks:
    result = execute_task(AGENT_ID, task)
    print(f"Task {task['id']}: {result['status']}")

# Report SRE health
print(f"\nCircuit state: {breaker.state}")
print(f"Error budget remaining: {slo.error_budget.remaining_percent:.1f}%")
budget = cost_guard.get_budget(AGENT_ID)
print(f"Cost today: ${budget.spent_today_usd:.2f} / ${budget.daily_limit_usd:.2f}")
```

### What this pipeline gives you

| Layer | Component | Protection |
|---|---|---|
| **Pre-flight** | `CostGuard.check_task` | Blocks tasks that would exceed budget |
| **Pre-flight** | `RogueAgentDetector.assess` | Quarantines compromised agents |
| **Execution** | `CircuitBreaker.call` | Isolates failing agents |
| **Post-flight** | `ErrorBudget.record_event` | Tracks reliability over time |
| **Post-flight** | `CostGuard.record_cost` | Detects cost anomalies, auto-throttles |
| **Post-flight** | `RogueAgentDetector.record_action` | Builds behavioral baseline |

---

## Next Steps

- **Progressive delivery:** Use `agent_sre.delivery.BlueGreenManager` to
  safely roll out new agent versions with validation and auto-rollback.
- **Alerting:** Connect `agent_sre.alerts.AlertManager` to your notification
  system (PagerDuty, Slack, Teams).
- **Dashboards:** Export SLO data via `agent_sre.slo.dashboard` for real-time
  visibility.
- **Scheduled chaos:** Use `agent_sre.chaos.ChaosScheduler` for recurring
  resilience tests with blackout windows.
