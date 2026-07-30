"""Agentic SpendGuard composite evaluator demo.

Demonstrates wrapping AGT's PolicyEngine with SpendGuard's out-of-process,
cryptographically-audited budget ledger. AGT decides allow/deny first; on
AGT-allowed actions, SpendGuard reserves budget atomically. AGT-denies
short-circuit the SpendGuard call.

Two modes:

* ``--mock`` (default): runs against an in-process fake SpendGuard transport.
  No external services required. Verifies the composite contract — that the
  sidecar is called for AGT-allow paths only.
* ``--real``: connects to a live SpendGuard sidecar over UDS gRPC. Requires
  the SpendGuard demo stack to be running (see README prerequisites).

Usage:
    python examples/spendguard-composite/spendguard_composite_demo.py --mock
    python examples/spendguard-composite/spendguard_composite_demo.py --real \\
        --socket /var/run/spendguard/adapter.sock \\
        --tenant 00000000-0000-4000-8000-000000000001 \\
        --budget 44444444-4444-4444-8444-444444444444
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable

from agent_os.policies import (
    PolicyAction,
    PolicyCondition,
    PolicyDefaults,
    PolicyDocument,
    PolicyEvaluator,
    PolicyOperator,
    PolicyRule,
)


# ---------------------------------------------------------------------------
# AGT setup (same for both modes)
# ---------------------------------------------------------------------------

def build_agt_evaluator() -> PolicyEvaluator:
    """The user's existing AGT policy. Untouched by SpendGuard composition."""
    return PolicyEvaluator(policies=[
        PolicyDocument(
            name="block-untrusted-tools",
            version="1.0",
            defaults=PolicyDefaults(action=PolicyAction.ALLOW),
            rules=[
                PolicyRule(
                    name="deny-dangerous",
                    condition=PolicyCondition(
                        field="tool_name",
                        operator=PolicyOperator.IN,
                        value=["shell", "delete_file"],
                    ),
                    action=PolicyAction.DENY,
                    priority=100,
                ),
            ],
        )
    ])


# ---------------------------------------------------------------------------
# Mock SpendGuard composite — mirrors what
# spendguard.integrations.agt.SpendGuardCompositeEvaluator does, but in-process
# so the demo runs without a real sidecar.
# ---------------------------------------------------------------------------

@dataclass
class CompositeResult:
    allowed: bool
    reason: str
    matched_rule_ids: list[str] = field(default_factory=list)


@dataclass
class MockSpendGuardTransport:
    """Records sidecar calls and decides allow/deny in-process."""
    budget_cap_atomic: int
    used_atomic: int = 0
    calls: list[int] = field(default_factory=list)

    def request_decision(self, claim_atomic: int) -> tuple[bool, str]:
        self.calls.append(claim_atomic)
        if self.used_atomic + claim_atomic <= self.budget_cap_atomic:
            self.used_atomic += claim_atomic
            return True, "ALLOW"
        return False, "BUDGET_EXHAUSTED"

    @property
    def remaining_atomic(self) -> int:
        return self.budget_cap_atomic - self.used_atomic


class MockComposite:
    """In-process stand-in for spendguard.integrations.agt.SpendGuardCompositeEvaluator."""

    def __init__(
        self,
        agt_evaluator: PolicyEvaluator,
        transport: MockSpendGuardTransport,
        claim_estimator: Callable[[dict[str, Any]], int],
    ) -> None:
        self.agt = agt_evaluator
        self.transport = transport
        self.claim_estimator = claim_estimator

    async def evaluate(self, payload: dict[str, Any]) -> CompositeResult:
        agt_result = self.agt.evaluate(payload)
        matched = [agt_result.matched_rule] if agt_result.matched_rule else []
        if not agt_result.allowed:
            return CompositeResult(
                allowed=False,
                reason=f"AGT_DENY: {agt_result.reason}",
                matched_rule_ids=matched,
            )

        claim = self.claim_estimator(payload)
        sg_allowed, sg_reason = self.transport.request_decision(claim)
        if sg_allowed:
            return CompositeResult(
                allowed=True,
                reason="ALLOW (AGT + SpendGuard both PASS)",
                matched_rule_ids=matched,
            )
        return CompositeResult(
            allowed=False,
            reason=f"SPENDGUARD_DENY: {sg_reason}",
            matched_rule_ids=matched,
        )


# ---------------------------------------------------------------------------
# Shared demo flow — exercises all 3 paths
# ---------------------------------------------------------------------------

async def run_three_paths(
    composite: Any,
    transport_for_assertion: MockSpendGuardTransport | None,
) -> None:
    # Path 1 — AGT-deny short-circuits
    print("\n--- Path 1: AGT-deny short-circuits ---")
    before_calls = len(transport_for_assertion.calls) if transport_for_assertion else None
    result = await composite.evaluate({
        "tool_name": "shell",
        "tool_args": ["rm", "-rf", "/"],
        "tenant_id": "00000000-0000-4000-8000-000000000001",
    })
    print(f"  Tool: shell ['rm', '-rf', '/']")
    print(f"  allowed={result.allowed}  reason={result.reason!r}")
    if transport_for_assertion is not None:
        delta = len(transport_for_assertion.calls) - (before_calls or 0)
        print(f"  SpendGuard sidecar calls: {delta}   (verified — AGT short-circuited)")
        assert delta == 0, "AGT-deny must NOT trigger SpendGuard call"
    assert not result.allowed, "Path 1 must DENY"

    # Path 2 — AGT-allow + SpendGuard-allow
    print("\n--- Path 2: AGT-allow + SpendGuard-allow ---")
    result = await composite.evaluate({
        "tool_name": "web_search",
        "tool_args": {"q": "agent budget control"},
        "tenant_id": "00000000-0000-4000-8000-000000000001",
        "estimated_cost_atomic": 100,
    })
    print(f"  Tool: web_search {{q: 'agent budget control'}}  (estimated 100 atomic units)")
    print(f"  allowed={result.allowed}   reason={result.reason!r}")
    if transport_for_assertion is not None:
        print(f"  Reservation: 100 atomic units against budget 4444...4444")
        print(f"  Remaining: {transport_for_assertion.remaining_atomic} atomic units")
    assert result.allowed, "Path 2 must ALLOW"

    # Path 3 — AGT-allow + SpendGuard-deny (budget exhausted)
    print("\n--- Path 3: AGT-allow + SpendGuard-deny ---")
    result = await composite.evaluate({
        "tool_name": "web_search",
        "tool_args": {"q": "expensive query"},
        "tenant_id": "00000000-0000-4000-8000-000000000001",
        "estimated_cost_atomic": 500,
    })
    print(f"  Tool: web_search {{q: 'expensive query'}}  (estimated 500 atomic units)")
    print(f"  allowed={result.allowed}  reason={result.reason!r}")
    print(f"  No reservation created (deny is fail-closed)")
    assert not result.allowed, "Path 3 must DENY on budget exhaustion"


# ---------------------------------------------------------------------------
# Mode entry points
# ---------------------------------------------------------------------------

async def mock_main() -> None:
    print("=" * 60)
    print("  SpendGuard Composite Evaluator Demo (mock mode)")
    print("=" * 60)

    agt = build_agt_evaluator()
    transport = MockSpendGuardTransport(budget_cap_atomic=1000, used_atomic=800)

    print("\n--- Composite setup ---")
    print("  AGT PolicyEngine: 1 policy, 1 rule (deny-dangerous)")
    print("  SpendGuard transport: MOCK (in-process, no sidecar)")
    print(f"  Budget cap: {transport.budget_cap_atomic} atomic units, "
          f"{transport.used_atomic} already used")

    composite = MockComposite(
        agt_evaluator=agt,
        transport=transport,
        claim_estimator=lambda payload: int(payload.get("estimated_cost_atomic", 100)),
    )

    await run_three_paths(composite, transport_for_assertion=transport)

    print("\n" + "=" * 60)
    print("  All 3 paths PASS — composite evaluator working as expected")
    print("=" * 60)


async def real_main(socket: str, tenant: str, budget: str) -> None:
    try:
        from spendguard import SpendGuardClient
        from spendguard.integrations.agt import SpendGuardCompositeEvaluator
        from spendguard._proto.spendguard.common.v1 import common_pb2
    except ImportError as exc:
        raise SystemExit(
            "--real mode requires the SpendGuard SDK with the [agt] extra:\n"
            "    pip install --pre 'spendguard-sdk[agt]>=0.4'\n"
            f"(import failed: {exc})"
        )

    print("=" * 60)
    print("  SpendGuard Composite Evaluator Demo (real mode)")
    print("=" * 60)

    agt = build_agt_evaluator()

    async with SpendGuardClient(socket_path=socket, tenant_id=tenant) as sg:
        await sg.handshake()

        composite = SpendGuardCompositeEvaluator(
            agt_evaluator=agt,
            spendguard_client=sg,
            budget_id=budget,
            window_instance_id="55555555-5555-4555-8555-555555555555",
            unit=common_pb2.UnitRef(
                unit_id="66666666-6666-4666-8666-666666666666",
                token_kind="output_token",
                model_family="gpt-4",
            ),
            pricing=common_pb2.PricingFreeze(pricing_version="demo-pricing-v1"),
            claim_estimator=lambda payload: [
                common_pb2.BudgetClaim(
                    budget_id=budget,
                    window_instance_id="55555555-5555-4555-8555-555555555555",
                    amount_atomic=str(int(payload.get("estimated_cost_atomic", 100))),
                    unit=common_pb2.UnitRef(unit_id="66666666-6666-4666-8666-666666666666"),
                )
            ],
        )

        await run_three_paths(composite, transport_for_assertion=None)

    print("\n" + "=" * 60)
    print("  All 3 paths PASS — real composite evaluator working")
    print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--mock", action="store_true",
                      help="run against an in-process fake transport (default)")
    mode.add_argument("--real", action="store_true",
                      help="connect to a live SpendGuard sidecar (see README prerequisites)")
    parser.add_argument("--socket", default="/var/run/spendguard/adapter.sock",
                        help="UDS path to the SpendGuard sidecar (--real only)")
    parser.add_argument("--tenant", default="00000000-0000-4000-8000-000000000001",
                        help="tenant UUID (--real only)")
    parser.add_argument("--budget", default="44444444-4444-4444-8444-444444444444",
                        help="budget UUID (--real only)")
    args = parser.parse_args()

    if args.real:
        asyncio.run(real_main(args.socket, args.tenant, args.budget))
    else:
        asyncio.run(mock_main())


if __name__ == "__main__":
    main()
