# SpendGuard Composite Evaluator Example

> **Status: community-contributed third-party integration.** SpendGuard is an
> external project maintained at <https://github.com/m24927605/agentic-spendguard>.
> The SDK is alpha (`pip install --pre 'spendguard-sdk[agt]'`).

Demonstrates composing AGT's `PolicyEngine` with [Agentic SpendGuard](https://github.com/m24927605/agentic-spendguard)
for cryptographically-audited, out-of-process LLM budget enforcement.

AGT decides allow/deny first. On AGT-allowed actions, SpendGuard then reserves
budget atomically against an out-of-process Postgres ledger. AGT-denied actions
never touch the SpendGuard sidecar, so denied tool calls cost nothing in the
ledger.

This is different from `examples/cost-governance/`: AGT's `CostGuard` does
**in-process** budget tracking with kill switches and alerts. SpendGuard does
**out-of-process** ledger-backed reservation with a cryptographic audit chain.
They're complementary — `CostGuard` for cheap per-process alerts, SpendGuard
for compliance-grade audit + cross-process fail-closed enforcement.

See [`docs/integrations/spendguard-integration.md`](../../docs/integrations/spendguard-integration.md)
for the full positioning matrix.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Agent runtime                                                │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  SpendGuardCompositeEvaluator                          │  │
│  │    1) AGT PolicyEngine  (in-process, sub-ms)           │  │
│  │    2) on AGT-allow → SpendGuard sidecar (UDS gRPC)     │  │
│  └────────────────────────────┬───────────────────────────┘  │
└────────────────────────────────┼─────────────────────────────┘
                                 │ Unix domain socket
                                 ▼
                  ┌──────────────────────────────┐
                  │ SpendGuard sidecar (Rust)    │
                  │   • contract DSL evaluator   │
                  │   • per-pod fencing lease    │
                  └──────────────┬───────────────┘
                                 │ mTLS gRPC
                                 ▼
                  ┌──────────────────────────────┐
                  │ Postgres ledger              │
                  │   • Stripe-style auth/cap.   │
                  │   • signed append-only audit │
                  └──────────────────────────────┘
```

## Prerequisites

```bash
pip install -r examples/spendguard-composite/requirements.txt
```

For the `--mock` mode (this README's default), no API keys, no Postgres, no
sidecar — everything runs in-process against a fake SpendGuard transport.

For `--real` mode against a live sidecar:

| Step | What |
|---|---|
| 1. **SpendGuard sidecar running** | Clone <https://github.com/m24927605/agentic-spendguard> and run `make demo-up`. Brings up sidecar + ledger + Postgres on Docker Compose. |
| 2. **Tenant + budget seeded** | The `make demo-up` flow pre-seeds a demo tenant + budget. UUIDs are emitted to stdout and also baked into `deploy/demo/seed/`. |
| 3. **Sidecar socket reachable** | Default `/var/run/spendguard/adapter.sock`; the demo-up flow exposes a Docker volume mount. |

## How to Run

```bash
# Mock mode — no external services
python examples/spendguard-composite/spendguard_composite_demo.py --mock

# Real mode — requires a live SpendGuard sidecar (see prerequisites)
python examples/spendguard-composite/spendguard_composite_demo.py --real \
    --socket /var/run/spendguard/adapter.sock \
    --tenant 00000000-0000-4000-8000-000000000001 \
    --budget 44444444-4444-4444-8444-444444444444
```

## Expected Output (mock mode)

```
============================================================
  SpendGuard Composite Evaluator Demo (mock mode)
============================================================

--- Composite setup ---
  AGT PolicyEngine: 1 policy, 1 rule (deny-dangerous)
  SpendGuard transport: MOCK (in-process, no sidecar)
  Budget cap: 1000 atomic units, 800 already used

--- Path 1: AGT-deny short-circuits ---
  Tool: shell ['rm', '-rf', '/']
  allowed=False  reason="AGT_DENY: Matched rule 'deny-dangerous'"
  SpendGuard sidecar calls: 0   (verified — AGT short-circuited)

--- Path 2: AGT-allow + SpendGuard-allow ---
  Tool: web_search {q: 'agent budget control'}  (estimated 100 atomic units)
  allowed=True   reason="ALLOW (AGT + SpendGuard both PASS)"
  Reservation: 100 atomic units against budget 4444...4444
  Remaining: 100 atomic units

--- Path 3: AGT-allow + SpendGuard-deny ---
  Tool: web_search {q: 'expensive query'}  (estimated 500 atomic units)
  allowed=False  reason="SPENDGUARD_DENY: BUDGET_EXHAUSTED"
  No reservation created (deny is fail-closed)

============================================================
  All 3 paths PASS — composite evaluator working as expected
============================================================
```

## What This Demo Shows

1. **AGT-deny short-circuits.** SpendGuard is never called for AGT-denied
   actions — verifiable in mock mode by inspecting the transport's call log.
2. **AGT-allow → SpendGuard-allow.** Successful path. SpendGuard reserves the
   estimated cost atomically against the budget.
3. **AGT-allow → SpendGuard-deny.** Budget exhaustion is fail-closed; no
   reservation is created on deny, no ledger row to clean up.
4. **Two audit chains.** AGT emits its in-process audit log; SpendGuard
   emits a signed `audit_outbox` row. Both share the same `decision_id` for
   correlation.

## Real-mode notes

When `--real` mode succeeds, the equivalent SpendGuard upstream demo is
`DEMO_MODE=agent_real_agt make demo-up` — that runs this same composite logic
against a real sidecar + ledger and asserts the same 3 verdicts. Source:
[`deploy/demo/demo/run_demo.py::run_agt_composite_mode`](https://github.com/m24927605/agentic-spendguard/blob/main/deploy/demo/demo/run_demo.py).

## Learn More

- [SpendGuard integration doc](../../docs/integrations/spendguard-integration.md) — positioning vs `CostGuard`, 4-layer mapping, operational gotchas
- [Cost governance example](../cost-governance/) — for in-process budget alerts via AGT's `CostGuard`
- [Citadel integration example](../citadel-governed-agent/) — gateway-side governance pattern
- SpendGuard repo: <https://github.com/m24927605/agentic-spendguard>
- SpendGuard SDK on PyPI: `pip install --pre 'spendguard-sdk[agt]'`
