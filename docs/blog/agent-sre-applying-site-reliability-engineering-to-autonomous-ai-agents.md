# Agent SRE: Applying Site Reliability Engineering to Autonomous AI Agents

**Imran Siddique** | Principal Group Engineering Manager, Agentic AI Architect | Microsoft

> [!NOTE]
> This is Part 4 of the Agent Governance Toolkit blog series on
> [Microsoft Tech Community — Linux and Open Source Blog](https://techcommunity.microsoft.com/category/linux-and-open-source/blog/linuxandopensourceblog).
> Code examples in this post are simplified for readability and may not
> match the exact public API signatures. See the
> [agent-sre package documentation](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agent-sre)
> for the current API reference.

---

If you practice SRE, you already have a mental model for running reliable production systems. You define SLOs. You track error budgets. You use circuit breakers to stop cascading failures. You run chaos experiments to find weaknesses before customers do. You treat every operational decision as a tradeoff between reliability and velocity.

That mental model transfers directly to AI agents. It just needs four new ideas.

In the [architecture deep dive](https://techcommunity.microsoft.com/blog/linuxandopensourceblog/agent-governance-toolkit-architecture-deep-dive-policy-engines-trust-and-sre-for/4510105), we covered Agent SRE briefly as one of AGT's nine packages: SLOs, error budgets, circuit breakers, chaos engineering, and progressive delivery, adapted from the patterns your SRE team already applies to microservices. Several teams asked for the full story. This is it.

Agent SRE is one of the more novel parts of the toolkit. The policy engine, zero-trust identity, and execution sandboxing have clear analogs in existing security practice. Agent SRE explores newer ground. Established patterns for defining SLOs for AI agent behavior, building chaos experiments for LLM provider failures, or applying error budgets to agent autonomy are still emerging across the industry. We built these capabilities because running agents in production without them is the equivalent of running a fleet of microservices without circuit breakers, health checks, or an on-call runbook.

This post is for SRE teams, platform engineers, and anyone responsible for running AI agents in production. You do not need to be an AI specialist. If you know what a burn rate is, you are ready for this.

---

## The Problem: Agents Fail in Ways Your Existing SRE Tooling Cannot See

When a service fails, your observability stack tells you: latency went up, error rate crossed the SLO threshold, the circuit breaker opened. You page the on-call engineer. They look at traces and find the slow database query.

When an AI agent fails, your observability stack is silent. The agent returned HTTP 200. Latency was normal. Error rate was zero. But the agent quietly approved a transaction it was not authorized to approve, hallucinated a database path and wrote to the wrong table, or got stuck in a reasoning loop that consumed $800 of LLM API budget before anyone noticed.

These are not infrastructure failures. They are behavioral failures. And they are invisible to monitoring tools built for stateless, deterministic services, because those tools only watch for crashes and timeouts. They do not watch for *wrong behavior*.

This gap is the problem Agent SRE was designed to solve. The solution borrows everything from the SRE playbook and adds one concept that extends it: the **Safety SLI**.

---

## The Safety SLI: A New Reliability Dimension

Traditional SLIs measure system behavior from the user's perspective: latency, availability, error rate, throughput. They answer: *did the service respond correctly?*

For AI agents, correctness is not enough. An agent that responds correctly but acts outside its authorized scope has not succeeded. It has failed in a way that none of your existing SLIs can detect.

The Safety SLI answers a different question: *did the agent act within policy?*

```python
from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import PolicyComplianceRate

# Define a safety SLO: 99% of agent actions must comply with policy
safety_slo = SLO(
    name="safety-compliance",
    indicators=[
        PolicyComplianceRate(
            target=0.99,
            evaluation_window="7d",
        ),
    ],
    error_budget=ErrorBudget(
        total=0.01,                      # 1% budget (1 - 0.99 target)
        window_seconds=2592000,          # 30-day window
        burn_rate_alert=2.0,             # warn at 2x sustainable rate
        burn_rate_critical=5.0,          # page at 5x sustainable rate
    ),
)
```

When an agent's policy compliance rate drops below 99%, the error budget starts burning. Exactly as with a latency SLO, the system can respond at configurable thresholds:

```python
from agent_sre.slo.objectives import ExhaustionAction

# Configure graduated response as budget burns
# 2x burn rate: reduce agent autonomy
safety_slo.on_burn_rate(
    rate=2.0,
    action="restrict",
    config={
        "restrict_capabilities": ["write.*", "delete.*"],
        "require_human_approval": ["high_risk_*"],
        "alert_channel": "teams://sre-agents",
    },
)

# 5x burn rate: page on-call, restrict further
safety_slo.on_burn_rate(
    rate=5.0,
    action="restrict",
    config={
        "restrict_capabilities": [".*"],      # read-only until budget recovers
        "require_human_approval": [".*"],
        "page_oncall": True,
        "alert_channel": "pagerduty://agent-sre",
    },
)

# Budget exhausted: suspend agent
safety_slo.on_exhaustion(
    action=ExhaustionAction.CIRCUIT_BREAK,
    config={
        "suspend_agent": True,
        "preserve_state": True,
        "notify": "incident://severity-1",
    },
)
```

This is the governance dial from the other direction. The error budget is not just a metric: it is the mechanism that automatically narrows agent autonomy as safety evidence degrades, and widens it again as evidence accumulates. An agent with a clean 30-day safety record earns autonomy. An agent that starts misbehaving loses it, automatically, without waiting for a human to notice.

There are two SLI dimensions built into Agent SRE. Safety SLIs and Performance SLIs track different aspects of the same agent:

| SLI Type | What It Measures | Target Pattern | When Budget Burns |
|---|---|---|---|
| **Safety SLI** | `policy_compliance_rate` — fraction of actions within authorized scope | ≥ 99% | Restrict capabilities, increase human oversight |
| **Performance SLI** | `task_completion_rate`, `p95_latency`, `cost_per_task` | Configurable per workload | Alert, throttle, or circuit-break LLM provider |

Both SLOs feed into the same error budget dashboard. An agent can have excellent performance but a degrading safety record, or perfect safety compliance and terrible cost efficiency. You need both dimensions to understand whether an agent is production-ready.

---

## Circuit Breakers: Governing Agent Failure Modes That Don't Exist in Microservices

Circuit breakers for services protect against one failure mode: a backend that is slow or unreachable. The pattern is `CLOSED → OPEN → HALF_OPEN`. You know it well.

Agent SRE implements the same state machine for failure modes that are specific to autonomous reasoning systems and do not exist in traditional microservice architectures:

```python
from agent_sre.cascade.circuit_breaker import CircuitBreakerConfig
from agent_sre.chaos.engine import FaultType

breaker = CircuitBreakerConfig(
    failure_threshold=5,              # Open after 5 failures in the window
    recovery_timeout_seconds=60,      # Stay OPEN for 60s before HALF_OPEN
    half_open_max_calls=3,            # Allow 3 probes in HALF_OPEN
)

# Failure modes tracked by the circuit breaker:
tracked_faults = [
    FaultType.POLICY_BYPASS,           # Agent exceeds authorized scope
    FaultType.ERROR_INJECTION,         # Upstream model API fails
    FaultType.TIMEOUT_INJECTION,       # Tool calls exceed time budget
    FaultType.TRUST_PERTURBATION,      # Agent trust score falls below threshold
    FaultType.DEADLOCK_INJECTION,      # Agent stuck in iterative reasoning
]
```

Each failure mode has different circuit-breaking semantics:

| Failure Mode | What Triggers It | Circuit-Break Behavior |
|---|---|---|
| Policy bypass | Action denied by policy engine | Count toward threshold; log with full context |
| LLM provider error | HTTP 5xx from model API | Immediately open; route to fallback model if configured |
| Tool timeout | Tool call exceeds `timeout_ms` | Count toward threshold; cancel in-flight call |
| Trust score degradation | Agent trust score drops below configured floor | Open; escalate to Ring 3 (untrusted) until score recovers |
| Reasoning loop / deadlock | Token or iteration count exceeds budget | Open; trigger human review before resuming |

The reasoning loop breaker deserves attention. A microservice cannot get stuck reasoning. An AI agent absolutely can, and when it does, the failure is not an error code: it is an agent that keeps calling tools, consuming tokens, and generating audit events indefinitely. The circuit breaker detects this pattern from the iteration count and token budget and terminates the loop:

```python
# Reasoning loop detection configuration
loop_detection_config = {
    "max_iterations": 15,             # Hard stop after 15 reasoning steps
    "max_tokens_per_session": 50000,  # Hard stop on token consumption
    "repetition_threshold": 0.85,     # Stop if >85% of recent actions repeat prior ones
    "on_detection": "circuit_break_and_escalate",
}
```

The state machine behaves identically to what you know from Hystrix or Resilience4j. What changes is the definition of "failure."

```
CLOSED (serving)
  │
  │  failure_threshold crossed for any tracked fault
  ▼
OPEN (rejecting — agent action denied, fallback or human-in-loop fires)
  │
  │  recovery_timeout expires
  ▼
HALF_OPEN (probe — limited requests allowed through)
  │
  ├── success_threshold met ──► CLOSED
  └── any failure          ──► OPEN (reset timeout)
```

---

## Chaos Engineering for Agents: Fault Injection for Autonomous Systems

The only way to know if your agent system is resilient is to break it intentionally. Traditional chaos engineering targets infrastructure: kill a pod, inject network latency, saturate a disk. Agent chaos engineering targets the failure modes specific to autonomous reasoning systems.

Agent SRE ships fault injection templates that cover the failure modes teams consistently underestimate until they hit production:

```python
from agent_sre.chaos.engine import ChaosEngine, Fault, FaultType

chaos = ChaosEngine()

# Experiment 1: LLM provider degrades — model returns valid responses but with
# increased latency and occasional malformed outputs
experiment = chaos.create_experiment(
    name="llm-degradation-resilience",
    description="Test agent behavior under degraded LLM provider",
    faults=[
        Fault.latency_injection(target="llm-provider", delay_ms=8000),
        Fault.error_injection(target="llm-provider", rate=0.05),
    ],
    duration_seconds=300,
    agent_id="analyst-agent-001",
)

# Experiment 2: Trust score manipulation — simulates an agent receiving
# messages from a peer with a spoofed trust score
trust_experiment = chaos.create_experiment(
    name="trust-manipulation-resilience",
    faults=[
        Fault(
            fault_type=FaultType.TRUST_PERTURBATION,
            target="did:mesh:orchestrator-001",
            params={"spoofed_score": 950},
        ),
    ],
    duration_seconds=120,
)

# Experiment 3: Tool timeout cascade — multiple tools time out simultaneously,
# testing whether the agent abandons gracefully or enters a reasoning loop
cascade_experiment = chaos.create_experiment(
    name="tool-timeout-cascade",
    faults=[
        Fault.timeout_injection(target="database.read", delay_ms=30000),
        Fault.timeout_injection(target="api.call", delay_ms=30000),
    ],
    duration_seconds=180,
)
```

Additional fault types built into the chaos engine cover: prompt injection attempts, privilege escalation, data exfiltration attempts, identity spoofing, deadlock injection, and contradictory instruction scenarios. Each maps to a `FaultType` enum value and can be composed into multi-fault experiments.

> **Important**: The chaos engine records that a fault was injected and
> triggers the governance response pipeline. Actual infrastructure-level
> fault injection (network partition, process kill) should be implemented
> using your existing chaos tooling (Chaos Mesh, Gremlin, Azure Chaos
> Studio, or similar). Agent SRE governs the agent's behavioral response
> to faults; it does not own infrastructure manipulation. These two
> layers are designed to compose.

Each chaos experiment produces a structured resilience report:

```bash
$ agt chaos run --template llm-degraded --agent analyst-agent-001 --duration 5m

Running chaos experiment: llm-degradation-resilience
Agent: did:mesh:analyst-agent-001
Duration: 5 minutes
...

Resilience Report
─────────────────────────────────────────────────
Circuit breaker state transitions:  2 (CLOSED → OPEN → HALF_OPEN)
Policy violations during fault:     0
Actions completed successfully:     47 / 52 (90.4%)
Actions routed to fallback:         5 (LLM_PROVIDER_ERROR)
Reasoning loops detected:           1 (terminated at iteration 12)
Budget burned during experiment:    0.34% of 30-day error budget
Human escalations triggered:        1

SLO impact: Safety SLI held at 100%. Performance SLI degraded to 86.2%.
Verdict: RESILIENT under LLM degradation. Performance SLO breach at sustained fault.
Recommendation: Configure fallback model for LLM_PROVIDER_ERROR; current MTTR is 48s.
─────────────────────────────────────────────────
```

This output answers the question that every agent production deployment team eventually asks: *what happens to my agent when the model API goes down?* The chaos experiment answers it before your customers do.

---

## Replay Debugging: Reproduce Behavioral Failures Exactly

Infrastructure incidents are reproducible because infrastructure is deterministic. AI agent incidents are hard to reproduce because agent behavior depends on model state, context window content, and the sequence of tool call results, none of which are preserved by default after a session ends.

Agent SRE's replay engine records every agent session as a replayable artifact: the full trace at each step, every tool call with its inputs and outputs, every policy evaluation with its decision, and every trust score at the time of each inter-agent message.

```python
from agent_sre.replay.capture import TraceStore
from agent_sre.replay.engine import ReplayEngine, ReplayMode

# Traces are captured automatically when SRE tracing is active
store = TraceStore(
    backend="azure_blob",
    retention_days=30,
)

# When an incident occurs, replay the session exactly
engine = ReplayEngine(store=store)

# Full replay: re-run the session against the same recorded inputs
# Uses recorded tool outputs — no live tool calls — so replay is deterministic
result = await engine.replay(
    trace_id="trace_2026_05_a7f3b2",
    mode=ReplayMode.FULL,
)

for step in result.steps:
    print(f"Step {step.index}: {step.action} → {step.decision}")

# Divergence analysis: replay with a policy change applied
# Shows exactly which actions would have been blocked under the new policy
diff_result = await engine.diff(
    trace_id="trace_2026_05_a7f3b2",
    policy_override="policies/stricter-v2.yaml",
)

for diff in diff_result.diffs:
    if diff.description:
        print(f"Step {diff.span_name}: was {diff.original}, "
              f"would be {diff.replayed} under new policy")
```

The divergence analysis is the feature teams use most. When a policy change is proposed, you replay recent production traces against the new policy to see how many actions would have been blocked, which sessions would have failed, and what the error budget impact would have been. Policy changes stop being guesswork.

---

## Progressive Delivery: Safely Rolling Out New Agent Capabilities

When you ship a new service version, you do not send it to all traffic at once. You use canary deployments, feature flags, or traffic splitting. You watch the SLOs. If they degrade, you roll back.

Agent SRE brings the same discipline to agent capability rollout. When you expand an agent's authorized scope, giving it write access it did not have, connecting it to a new tool, or raising its trust floor, you do not expand to the full fleet immediately. You expand progressively, with automated SLO gates controlling each stage.

```python
from agent_sre.delivery.rollout import (
    AnalysisCriterion,
    DeploymentStrategy,
    RolloutStage,
    StagedRollout,
)

rollout = StagedRollout(
    name="database-write-capability",
    strategy=DeploymentStrategy.CANARY,
    stages=[
        RolloutStage(
            name="canary",
            traffic_percent=5,             # 5% of agents get the new capability
            duration_seconds=86400,        # 24 hours
            criteria=[
                AnalysisCriterion(metric="safety_sli", threshold=0.995),
                AnalysisCriterion(metric="performance_sli", threshold=0.90),
                AnalysisCriterion(
                    metric="error_budget_consumed",
                    threshold=0.10,
                    comparator="lte",      # canary can burn at most 10%
                ),
            ],
        ),
        RolloutStage(
            name="early-adopters",
            traffic_percent=25,
            duration_seconds=172800,       # 48 hours
            criteria=[
                AnalysisCriterion(metric="safety_sli", threshold=0.990),
                AnalysisCriterion(metric="performance_sli", threshold=0.88),
            ],
        ),
        RolloutStage(
            name="general-availability",
            traffic_percent=100,
            duration_seconds=604800,       # 1 week of full observation
            criteria=[
                AnalysisCriterion(metric="safety_sli", threshold=0.990),
                AnalysisCriterion(metric="performance_sli", threshold=0.85),
            ],
        ),
    ],
    auto_rollback=True,                    # Automatic rollback if any gate fails
)

# Start the rollout — SLO gates evaluate automatically
await rollout.start()
```

The SLO gate at each stage is the same mechanism as a CI/CD quality gate, but measured on live production behavior rather than test results. An agent capability that degrades the safety SLI during canary does not promote to the next stage. This is the mechanism that makes it operationally safe to expand agent autonomy: every expansion is measurable, every measurement gates the next expansion, and rollback is automatic.

---

## Health Checks and Backpressure

Traditional health checks answer: *is the service alive?* For agents, alive is not enough. A healthy agent is one that is alive, operating within policy, consuming resources within budget, and maintaining a trust score above the Ring threshold it was assigned.

```python
# Agent health check covering multiple dimensions
health = await agent_health_check(
    agent_id="analyst-agent-001",
    dimensions=[
        "liveness",            # Is the agent process running?
        "policy_compliance",   # Is safety SLI above threshold?
        "trust_score",         # Is trust score above Ring floor?
        "resource_budget",     # Is token/API spend within limits?
        "tool_availability",   # Are the tools the agent needs reachable?
    ],
)

# health.status: "healthy" | "degraded" | "unhealthy"
# health.dimensions: per-dimension pass/fail with values
# health.recommended_action: "none" | "restrict" | "suspend" | "terminate"
```

When health checks report degradation, backpressure controls engage before the circuit breaker opens. Backpressure is the earlier, softer response: accept fewer concurrent tasks, reject low-priority work, drain in-flight tasks gracefully before the situation escalates.

```python
# Backpressure configuration
backpressure_config = {
    "backpressure_threshold": 0.80,    # Engage when resource utilization > 80%
    "max_concurrent": 5,               # Hard cap on simultaneous agent tasks
    "priority_shedding": True,         # Drop low-priority tasks first
    "drain_timeout_seconds": 30,       # Allow in-flight tasks to complete
}
```

The ordering matters: backpressure first, then circuit breaker, then suspension. Each stage is recoverable. Each stage preserves more agent state than the next. The SRE principle of graduated response applies to agents exactly as it applies to services.

---

## Observability: Governance Metrics Flow Into Your Existing Stack

Agent SRE does not ask you to adopt a new observability platform. Governance metrics are exported through the same adapters your infrastructure monitoring already uses, including OpenTelemetry, Prometheus, Datadog, and others.

```python
from agent_sre.tracing.exporters import configure_exporters

configure_exporters(
    backends=[
        {"type": "prometheus", "endpoint": "http://prometheus:9090"},
        {"type": "opentelemetry", "endpoint": "http://otel-collector:4317"},
    ],
    include_metrics=[
        "slo.safety_sli",               # Per-agent safety compliance rate
        "slo.error_budget_remaining",    # Error budget in percentage
        "slo.burn_rate",                 # Current burn rate vs sustainable
        "circuit_breaker.state",         # CLOSED / OPEN / HALF_OPEN
        "circuit_breaker.failure_count",
        "trust_score.current",           # Agent trust score (0-1000)
        "trust_score.ring",              # Current execution ring
        "chaos.experiments_run",         # Chaos experiment telemetry
        "health.status",                 # Aggregate health status
        "backpressure.load",             # Current load vs threshold
    ],
)
```

Key governance metrics available in your existing dashboards:

| Metric | What It Tells You | Alert Condition |
|---|---|---|
| `slo.safety_sli` | Fraction of agent actions within policy | < 0.99 |
| `slo.burn_rate` | Rate at which error budget is consumed | > 2.0 (warn), > 5.0 (page) |
| `slo.error_budget_remaining` | Budget left for the SLO window | < 20% |
| `circuit_breaker.state` | Current breaker state per agent | `OPEN` or `HALF_OPEN` |
| `trust_score.ring` | Execution ring (privilege level) | Ring 3 (untrusted) |
| `health.status` | Aggregate health across all dimensions | `degraded` or `unhealthy` |

If you are already running Grafana dashboards for your services, a governance dashboard for your agent fleet is a new data source and a new set of panels, not a new monitoring stack.

---

## The SRE Mental Model for Agents: Four New Concepts

Everything in Agent SRE is built on the SRE mental model you already have, extended with four concepts that adapt traditional reliability thinking for autonomous systems:

| Traditional SRE | Agent SRE Equivalent | What Changes |
|---|---|---|
| Latency SLI | Safety SLI | Correctness of *action*, not speed of *response* |
| Error budget | Autonomy budget | Burns on policy violations, not just errors |
| Circuit breaker | Behavioral circuit breaker | Opens on wrong *behavior*, not just failure codes |
| Canary deployment | Capability rollout | Rolls out *scope*, not just code |

The governance insight is that error budgets work in both directions for agents. A service's error budget only decreases. An agent's autonomy is also a budget: it grows when the safety SLI is strong and shrinks when it degrades. The error budget mechanism becomes the operational mechanism for expanding and contracting agent autonomy in response to evidence, which is exactly what regulated industries and risk-averse enterprise teams need before they will trust an autonomous agent with consequential actions.

---

## Getting Started with Agent SRE

```bash
pip install agent-sre
```

A minimal Agent SRE integration requires three things: a safety SLO definition, a circuit breaker, and a health check. The progressive delivery and chaos engineering features layer on top when you are ready for them.

```python
from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import TaskSuccessRate
from agent_sre.cascade.circuit_breaker import CircuitBreakerConfig, AgentCircuitBreaker

# Step 1: Define your safety SLO
slo = SLO(
    name="production-safety",
    indicators=[TaskSuccessRate(target=0.99)],
    error_budget=ErrorBudget(total=0.01, burn_rate_alert=2.0, burn_rate_critical=5.0),
)

# Step 2: Configure a circuit breaker
breaker_config = CircuitBreakerConfig(
    failure_threshold=5,
    recovery_timeout_seconds=60,
    half_open_max_calls=3,
)
breaker = AgentCircuitBreaker(agent_id="my-agent", config=breaker_config)

# Step 3: Wire into your existing agent loop
async def governed_agent_loop(agent, task):
    # Check health first
    if not await agent_is_healthy(agent.id):
        return {"error": "agent suspended", "reason": "health check failed"}

    # Run within circuit breaker protection
    async with breaker:
        result = await agent.run(task)
        slo.record_event(good=result.policy_compliant)
        return result
```

The quickstart in the repository walks through a complete setup with a multi-agent travel planner, the same example from the [App Service governance post](https://techcommunity.microsoft.com/blog/appsonazureblog/govern-ai-agents-on-app-service-with-the-microsoft-agent-governance-toolkit/4510962), with safety SLOs, circuit breakers, and a Prometheus dashboard export, in under 50 lines.

---

## Why This Matters

Most AI observability tools today focus on what you might call *model quality*: hallucination rate, latency, token cost, task completion. These are useful metrics. They are not SRE metrics. They do not answer whether the agent acted within its authorized scope, whether its behavioral error budget is burning at a dangerous rate, or whether it would survive the LLM provider going down.

Agent SRE answers those questions using the operational vocabulary that SRE teams already understand: SLOs, error budgets, circuit breakers, chaos experiments, and health checks. The goal is not to replace your observability stack. It is to make agent governance visible inside it.

The reliability of an autonomous agent is not a property of the model. It is a property of the governance infrastructure around it. Agent SRE is that infrastructure.

---

## Resources

- **GitHub**: [github.com/microsoft/agent-governance-toolkit](https://aka.ms/agent-governance-toolkit)
- **Install**: `pip install agent-sre`
- **Tutorials**: [40+ tutorials](https://aka.ms/agt-tutorials) including dedicated Agent SRE walkthroughs for SLO setup, chaos experiments, and progressive delivery
- **Architecture reference**: [ARCHITECTURE.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/ARCHITECTURE.md)
- **OWASP compliance mapping**: [OWASP-COMPLIANCE.md](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/OWASP-COMPLIANCE.md) — Agent SRE addresses ASI06 (cascading failures) and ASI07 (resource exhaustion) directly
- **Part 1 — Runtime governance**: [Policy engines, trust, and SRE overview](https://techcommunity.microsoft.com/blog/linuxandopensourceblog/agent-governance-toolkit-architecture-deep-dive-policy-engines-trust-and-sre-for/4510105)
- **Part 2 — Shift-left governance**: [Catching violations before production](https://techcommunity.microsoft.com/blog/linuxandopensourceblog/shift-left-governance-for-ai-agents-how-the-agent-governance-toolkit-helps-you-c/4516481)
- **Part 3 — Post-hoc accountability**: [After the agent acts](https://techcommunity.microsoft.com/blog/linuxandopensourceblog/after-the-agent-acts-proving-what-happened-and-who-authorized-it/4519826)

---

*The Agent Governance Toolkit is an open-source project released under the MIT License. All features described in this post are available in the public repository. The `agent-sre` package is currently in public preview; APIs may change before general availability.*

*Questions about Agent SRE in your environment? Open an issue at [aka.ms/agent-governance-toolkit](https://aka.ms/agent-governance-toolkit) or start a discussion in the comments below.*
