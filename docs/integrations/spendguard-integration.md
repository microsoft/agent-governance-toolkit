# Agentic SpendGuard + AGT Integration

> **Status: community-contributed third-party integration.** Maintained
> upstream at <https://github.com/m24927605/agentic-spendguard>. SpendGuard
> ships as an alpha (`pip install --pre 'spendguard-sdk[agt]'`); the AGT/SpendGuard
> audit-chain reconciler is on the SpendGuard roadmap, not yet shipped.
> Worked example: [`examples/spendguard-composite/`](../../examples/spendguard-composite/).

This document describes how the Agent Governance Toolkit (AGT) composes with
[Agentic SpendGuard](https://github.com/m24927605/agentic-spendguard), an
out-of-process, cryptographically-audited budget ledger for LLM agents.

## Positioning

AGT and Agentic SpendGuard address **different enforcement axes** that are
complementary, not competing:

| Concern | AGT `PolicyEngine` | AGT `CostGuard` (agent-sre) | Agentic SpendGuard |
|---------|--------------------|-----------------------------|--------------------|
| **What it governs** | Action allow/deny (which tool can this agent call?) | In-process budget tracking (per-task, per-agent, org-monthly) | Out-of-process budget reservation + cryptographically-signed audit chain |
| **Enforcement point** | Agent runtime (in-process) | Agent runtime (in-process) | Sidecar (UDS gRPC) + optional egress HTTP proxy + Postgres ledger |
| **Latency model** | In-process (sub-ms) | In-process (sub-ms) | Out-of-process: same-pod UDS gRPC round trip + Postgres ledger write |
| **State model** | Stateless (rules) | In-memory per-process | Postgres-backed, single-writer-per-budget invariant across processes |
| **Audit target** | AGT hash-chain audit log | Same | Independent Postgres `audit_outbox` with DB-enforced immutability triggers + Ed25519 / AWS KMS ECDSA P-256 signatures + outbox forwarder to `canonical_events` |
| **Multi-tenant** | Per-policy scoping | Per-agent scoping | First-class tenant + budget + window scoping in the ledger |
| **Approval workflow** | DENY only | Kill switch only | `REQUIRE_APPROVAL` decision → operator REST API → `resume()` round-trip → bundled commit |
| **Compliance evidence** | AGT audit log | None | Append-only audit chain → SIEM via `canonical_events` |

The decision tree:

- **Use AGT `PolicyEngine` alone** if your governance need is "which agent can call which tool, under which condition."
- **Add AGT `CostGuard`** if you additionally need lightweight in-process budget alerts and kill switches.
- **Add Agentic SpendGuard** if you additionally need (a) **compliance-grade cryptographic audit chain** for token spend, (b) **cross-process budget enforcement** so multiple agent pods can't double-spend the same budget, or (c) **operator approval workflow** on borderline calls.

The three coexist cleanly: AGT `PolicyEngine` decides "is this action allowed?", AGT `CostGuard` decides "are we approaching our soft alert threshold?", and SpendGuard decides "is this call within the cryptographically-pinned ledger budget right now?"

## Composition pattern

The standard integration wraps your existing `PolicyEvaluator` in
`SpendGuardCompositeEvaluator`. AGT decides allow/deny first; SpendGuard runs only
on AGT-allowed actions, so denied actions never consume a reservation.

```python
from agent_os.policies import PolicyEvaluator, PolicyDocument, PolicyRule, ...
from spendguard import SpendGuardClient
from spendguard.integrations.agt import SpendGuardCompositeEvaluator
from spendguard._proto.spendguard.common.v1 import common_pb2

# 1) Your existing AGT PolicyEvaluator — rules unchanged
agt = PolicyEvaluator(policies=[
    PolicyDocument(
        name="agent-policy", version="1.0",
        rules=[PolicyRule(
            name="deny-dangerous-tools",
            condition=PolicyCondition(field="tool_name",
                                      operator=PolicyOperator.IN,
                                      value=["shell", "delete_file"]),
            action=PolicyAction.DENY, priority=100,
        )],
    )
])

# 2) Connect to the SpendGuard sidecar (UDS gRPC, same-pod)
async with SpendGuardClient(
    socket_path="/var/run/spendguard/adapter.sock",
    tenant_id="<your-tenant-uuid>",
) as sg:
    await sg.handshake()

    # 3) Compose
    composite = SpendGuardCompositeEvaluator(
        agt_evaluator=agt,                       # existing AGT object, unchanged
        spendguard_client=sg,
        budget_id="<budget-uuid>",
        window_instance_id="<window-uuid>",
        unit=common_pb2.UnitRef(unit_id="<unit-uuid>"),
        pricing=common_pb2.PricingFreeze(pricing_version="..."),
        claim_estimator=lambda payload: [
            common_pb2.BudgetClaim(
                budget_id="<budget-uuid>",
                amount_atomic="500",
                unit=common_pb2.UnitRef(unit_id="<unit-uuid>"),
            )
        ],
    )

    # 4) Evaluate — single entry point gates both policy AND budget
    result = await composite.evaluate({
        "tool_name": "execute_code",
        "tool_args": {...},
        "tenant_id": "...",
    })
    # result.allowed: bool
    # result.reason: "AGT_DENY: ..." | "SPENDGUARD_DENY: ..." | "ALLOW (AGT + SpendGuard both PASS)"
    # result.matched_rule_ids: list[str]
```

A working end-to-end example with all three deny/allow paths is in
[`examples/spendguard-composite/`](../../examples/spendguard-composite/).

## How SpendGuard Maps to AGT's Architecture Layers

SpendGuard does not replace any AGT subsystem. It plugs in alongside the policy
layer and contributes a second audit chain:

```
┌───────────────────────────────────────────────────────────────────┐
│                  Application / Agent Runtime                       │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │  SpendGuardCompositeEvaluator                            │     │
│  │  ┌──────────────┐    ┌──────────────────────────────┐   │     │
│  │  │ AGT          │ ─▶ │ SpendGuard (on AGT-allow)    │   │     │
│  │  │ PolicyEngine │    │  • UDS gRPC → sidecar         │   │     │
│  │  └──────────────┘    │  • reservation against budget │   │     │
│  │         │            │  • signed audit row            │   │     │
│  │         ▼            └──────────────────────────────┘   │     │
│  │   AGT audit chain                  │                     │     │
│  └──────────────────────────────────────┼────────────────────┘     │
│                                          ▼                          │
│                              (out-of-process boundary)              │
└─────────────────────────────────────────┬─────────────────────────┘
                                          │
                                          ▼
              ┌─────────────────────────────────────────┐
              │  SpendGuard sidecar (Rust, tonic)       │
              │  • contract DSL evaluator                │
              │  • mTLS gRPC clients to ledger           │
              │  • per-pod fencing lease                  │
              └────────────────┬─────────────────────────┘
                               │ mTLS gRPC
                               ▼
              ┌─────────────────────────────────────────┐
              │  Postgres ledger                         │
              │  • Stripe-style auth/capture            │
              │  • append-only audit_outbox             │
              │  • DB-enforced immutability triggers    │
              │  • Ed25519 / KMS ECDSA signatures       │
              └─────────────────────────────────────────┘
```

Both audit chains carry the same `decision_id` so a downstream consumer can
correlate AGT and SpendGuard events for the same agent action.

## When to use which combination

| Scenario | AGT `PolicyEngine` | AGT `CostGuard` | Agentic SpendGuard |
|----------|:-----:|:-----:|:-----:|
| Single-process agent, alerts are enough | ✅ | ✅ | — |
| Multi-pod agent fleet, double-spend must not happen | ✅ | — | ✅ |
| Compliance / SOC 2 / FedRAMP audit evidence required | ✅ | — | ✅ |
| Operator must approve calls above a threshold | ✅ | — | ✅ |
| Multi-tenant SaaS where one tenant's overspend cannot affect another | ✅ | ✅ (per-agent) | ✅ (cryptographic isolation) |
| In-process kill switch on org-monthly cap | ✅ | ✅ | — (different shape; SpendGuard hard-caps PRE-call instead) |

## Audit chain reconciliation

AGT and SpendGuard write to independent audit chains:

- **AGT audit chain**: in-process hash-chain audit log per AGT's existing
  governance model (covered in `docs/integrations/external-operation-accountability-profiles.md`).
- **SpendGuard audit chain**: append-only Postgres `audit_outbox` rows, signed,
  forwarded to `canonical_events` by an outbox forwarder, downstream-consumable
  via a SIEM connector.

Both emit the same `decision_id` for a given composite evaluation, so a
reconciler that joins on `decision_id` can produce a unified view. A relay
that ingests AGT events into SpendGuard's `canonical_events` is on the
SpendGuard roadmap; in the interim, joining at the SIEM / data warehouse layer
works for both chains.

## Operational considerations

- **Sidecar deployment**: SpendGuard ships a Helm chart (`charts/spendguard/`)
  that runs the sidecar as a DaemonSet (one pod per node). AGT-using applications
  connect via UDS (`/var/run/spendguard/adapter.sock`). No extra ports.
- **Postgres**: SpendGuard requires an external Postgres for the ledger. Not
  bundled — operators provide an RDS / Cloud SQL / managed Postgres instance.
- **Reservation TTL**: defaults to 60 seconds. If the AGT-allowed tool action
  exceeds that, SpendGuard auto-releases the reservation. For long-running
  tool calls, bump `reservation_ttl_seconds` in the contract bundle.
- **Latency**: a same-pod UDS gRPC round trip plus a ledger write per evaluation.
  Order-of-magnitude lower than the LLM call it gates, but measurable for
  high-frequency tool actions. AGT-deny short-circuits the sidecar entirely.

## Related

- AGT integration upstream (this doc): [`docs/integrations/spendguard-integration.md`](spendguard-integration.md)
- Working example: [`examples/spendguard-composite/`](../../examples/spendguard-composite/)
- SpendGuard repo: <https://github.com/m24927605/agentic-spendguard>
- SpendGuard's own AGT integration guide (for SpendGuard users adding AGT):
  <https://github.com/m24927605/agentic-spendguard/blob/main/docs/site/docs/integrations/agt.md>
- AGT integration patterns: [`docs/integrations/citadel-integration.md`](citadel-integration.md)
