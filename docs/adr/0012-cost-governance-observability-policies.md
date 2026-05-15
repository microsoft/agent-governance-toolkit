# ADR 0012: Cost Governance via Observability Policies in Agent SRE

- Status: accepted
- Date: 2026-05-06

## Context

AI agents incur real costs through LLM API calls, tool invocations, and external service usage. Organizations need visibility into and control over agent spending, especially in multi-agent orchestration where costs can escalate quickly through cascading calls.

AGT's agent-sre module already tracks `cost_per_task` as a post-hoc metric alongside SLOs and error budgets. However, there is no policy-driven cost governance: no budget enforcement, no alerts when spending trends upward, and no way to define per-agent or global cost limits.

Industry analysts identify cost governance as a gap in agent security platforms. Our thought leadership work identified "observability policies that understand: this is a paid call, this is an unpaid call" as a key capability.

### Design constraints (from architecture review):
- Cost metadata should come from all sources (tool annotations, policy mappings, runtime metering), layered
- Budget enforcement should be tiered: soft caps at warning thresholds, hard caps at absolute maximums
- Support both per-agent budgets and global (organization-wide) budgets
- This belongs in agent-sre, not in the policy evaluator or a new module
- Enforcement should be post-action (observe cost, alert if trending over), not pre-action prediction
- Start with Python, track porting to other SDK languages

## Decision

Implement cost governance as an extension of the existing agent-sre module, using a tiered budget model with post-action enforcement.

### Cost Metadata Model (Layered)

Cost information flows from three sources, with later sources overriding earlier ones:

1. **Tool annotations** (tool author provides): tool definitions include a `cost_hint` field with estimated cost per invocation
2. **Policy cost mappings** (governance author provides): policy YAML maps tool names to cost values, overriding tool-provided hints
3. **Runtime metering** (actual observation): after execution, the actual cost is captured from billing APIs or SDK cost headers, correcting any estimates

```yaml
# Example: cost policy in agent-sre
cost_governance:
  budgets:
    - scope: agent
      agent_id: "analyst-*"
      soft_cap: 5.00       # USD, fires alert
      hard_cap: 25.00      # USD, blocks further actions
      window: 1h           # Rolling window

    - scope: global
      soft_cap: 500.00
      hard_cap: 2000.00
      window: 24h

  cost_map:
    gpt-4-turbo: 0.03      # per 1K tokens (estimate)
    database_query: 0.001
    send_email: 0.00
    web_search: 0.005
```

### Enforcement Model

Post-action enforcement: after each action completes, the cost observer records the cost and checks budget status.

- **Under soft cap**: no action, cost recorded in telemetry
- **Soft cap exceeded**: alert fires (webhook, OTel event), action is not blocked
- **Hard cap exceeded**: subsequent actions are blocked until the window rolls over or an administrator raises the cap

This is deliberately post-action rather than pre-action because:
- Pre-action cost prediction is unreliable (LLM token counts vary, tool costs depend on parameters)
- Post-action observation uses actual costs, providing accurate data
- The tiered model ensures the first action that exceeds a soft cap triggers an alert before reaching the hard cap

### Integration Point

The cost observer hooks into agent-sre's existing SLO/error budget pipeline:

```
Action executed -> Cost observer records cost -> Budget checker evaluates
                                                      |
                                              Under soft cap: log only
                                              Over soft cap: alert
                                              Over hard cap: block next action
```

### Data Model

```python
@dataclass
class CostRecord:
    agent_id: str
    action: str
    estimated_cost: float    # From tool hint or policy mapping
    actual_cost: float       # From runtime metering (if available)
    source: str              # "tool_hint", "policy_map", "runtime_meter"
    timestamp: datetime
    request_id: str

@dataclass 
class BudgetStatus:
    scope: str               # "agent" or "global"
    identifier: str          # agent_id pattern or "global"
    window_start: datetime
    total_spent: float
    soft_cap: float
    hard_cap: float
    status: str              # "ok", "soft_exceeded", "hard_exceeded"
```

## Consequences

### Benefits
- Organizations gain visibility and control over agent spending
- Tiered model provides early warning before hard limits are hit
- Post-action approach gives accurate cost data rather than estimates
- Fits naturally into agent-sre's existing observability pipeline
- No changes to the hot path (policy evaluator) or core kernel

### Tradeoffs
- Post-action means the action that crosses the hard cap still executes (one action overshoot)
- Runtime metering requires integration with billing APIs (provider-specific)
- Cost estimation accuracy depends on governance authors maintaining cost maps

### Follow-up work
- Implement CostObserver in agent-sre (Python first)
- Add cost_hint field to tool registration schema
- Add cost governance section to SRE tutorial
- Track porting to .NET, Rust, Go, TypeScript SDKs
- Consider pre-action budget check as optional "strict mode" in future iteration
