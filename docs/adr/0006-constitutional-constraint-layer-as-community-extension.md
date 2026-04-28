# ADR 0006: Constitutional constraint layer as a community extension

- Status: proposed
- Date: 2026-04-18

## Context

AGT's three-gate architecture (TrustGate → GovernanceGate → ReliabilityGate) enforces configured policy rules effectively. However, two failure modes are not addressed by the current design:

1. **Intent drift.** An agent can produce a sequence of individually policy-compliant actions that collectively diverge from the original goal. Policy rules evaluate actions in isolation — they cannot detect trajectory deviation because they lack access to the full decision context.

2. **Policy-compliant harm.** An agent operating within all configured rules can still take actions that violate the operator's intent when encountering unanticipated scenarios. GovernanceGate's default-deny posture and escalation tiers (discussed in #934) mitigate but do not eliminate this — deny rules must be enumerated in advance.

These gaps share a common structural cause: the governance layer evaluates point-in-time compliance, not goal alignment over time.

## Decision

Introduce a constitutional constraint layer as a **community extension** that hooks into GovernanceGate as a post-evaluation check. The extension evaluates trajectory alignment at decision boundaries, complementing (not replacing) the existing policy enforcement model.

### Design: Critic-with-veto pattern

The constitutional layer is implemented as a dedicated critic agent with three structural properties:

1. **Veto-only authority.** The critic can block or pause actions but never execute them. This prevents the constitutional layer from becoming a new attack surface — a compromised critic cannot take actions, only stop them.

2. **Goal re-evaluation at decision boundaries.** The critic receives the full conversation history and the original goal, and re-evaluates alignment at natural decision boundaries (phase transitions, tool calls with side effects, delegation points) — not every turn, which would be both slow and noisy.

3. **Hardcoded constitutional rules.** Three rules that apply regardless of policy configuration:
   - No irreversible actions without explicit approval
   - No actions that could compromise the system itself
   - Goal drift detection: if cumulative trajectory deviates from original intent, pause the agent loop

The constitutional check asks a question that policy rules structurally cannot answer: *"Is what we're doing right now still pointed at what we were asked to do?"*

### Blast-radius tier escalation

Actions are classified by blast radius, not just action type:

| Risk tier | Blast radius | Confirmation |
|-----------|-------------|-------------|
| Low | Read-only, no downstream dependents | No friction |
| Medium | External writes, ≤2 downstream dependents | Logged, flagged for review |
| High | Irreversible changes, ≥3 downstream dependents | Explicit confirmation required |

The key heuristic: agents whose output feeds ≥3 downstream dependents (high fanout) are automatically escalated one tier. This captures high-impact agents without over-classifying routine operations. The ≥3 threshold is based on direct downstream dependents only — second-order fanout accumulates too fast and over-escalates.

### Integration with GovernanceGate

```
Action → GovernanceGate (policy evaluation)
                    ↓
         Constitutional Extension (post-check hook)
                    ↓
              ┌─ allow (trajectory aligned)
              ├─ pause (goal drift detected)
              └─ deny (constitutional violation)
```

The constitutional extension sits as a post-check hook on GovernanceGate — **wired in, not baked in**. This keeps the core gate logic unchanged and makes the constitutional layer an explicit extension point.

### Why community extension, not core

Three reasons this belongs outside the core gates:

1. **Constitutional rules are domain-specific.** The three hardcoded rules above reflect one team's risk tolerance. Different deployments need different constitutional principles — the core should not prescribe them.

2. **The critic-with-veto pattern has a runtime cost.** Goal re-evaluation requires LLM inference at decision boundaries. Not all deployments want this latency, and the core gates are designed for deterministic, fast evaluation (ADR 0003: 200ms SLA).

3. **Separation of concerns.** The three-gate model is clean because each gate handles one concern (identity, behavior, reliability). Constitutional alignment is a different concern — it should compose with the gates, not extend them.

## Consequences

**Benefits:**
- Catches the intent-drift failure mode that policy rules cannot detect — the most common "everything was compliant but the outcome was wrong" pattern in multi-agent systems.
- Blast-radius escalation based on agent graph topology (fanout) is more precise than action-type classification alone.
- Community extension model keeps the core small while providing an explicit hook for operators who need constitutional guarantees.
- The critic-with-veto pattern has been validated in production over 4+ weeks with 6 agent types, catching goal drift that passed all policy checks.

**Tradeoffs:**
- The critic agent is itself an LLM invocation, adding latency at decision boundaries. This is acceptable for high-stakes actions but may be overkill for low-risk operations.
- The three hardcoded constitutional rules are opinionated. Teams with different risk models will need to modify or extend them.
- Blast-radius calculation requires knowledge of the agent graph topology, which may not be available in all deployment configurations.

**Follow-up work:**
- Formalize the extension hook interface so other community extensions (economic scope, audit logging) can use the same post-check pattern.
- Benchmark the latency impact of goal re-evaluation at decision boundaries.
- Explore whether the fanout threshold (≥3) should be configurable per deployment.

**Discussion:** #934
