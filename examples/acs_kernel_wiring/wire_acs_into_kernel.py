# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Wire one ACS decision into the real AGT kernel through KernelBridge.

This is the end-to-end counterpart to the manual host wiring the task's
``agt_stack.py`` had to do by hand. It stands up the three real, otherwise
disconnected AGT kernel subsystems

- trust:  ``agentmesh.trust_types.TrustTracker``
- audit:  ``agent_os.event_sink.GovernanceEventProcessor`` + a sink
- rings:  ``hypervisor.rings.RingEnforcer`` + ``ActionClassifier``

and drives all three from one ``KernelBridge.apply(...)`` call. The bridge is
dependency injected, so this module is where the concrete subsystems meet it.

The audit emitter is honest about delivery. It maps the neutral
``GovernanceEventSpec`` onto a concrete ``GovernanceEvent`` and emits it
synchronously to a sink (the ``agent_os.event_sink`` SPI), returning ACCEPTED
only when the sink acknowledges it. A fail-closed gate needs a synchronous ack,
so it deliberately does NOT use the fire-and-forget async
``GovernanceEventProcessor`` for the ack (see ``SynchronousAuditEmitter``).

Run:

    PYTHONPATH=agent-governance-python/agt-policies/src \
        python examples/acs_kernel_wiring/wire_acs_into_kernel.py
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from agentmesh.trust_types import TrustTracker
from agent_os.event_sink import (
    GovernanceEvent,
    GovernanceEventKind,
    GovernanceEventSinkBase,
    SinkExportResult,
)
from hypervisor.models import ActionDescriptor, ExecutionRing, ReversibilityLevel
from hypervisor.rings.classifier import ActionClassifier
from hypervisor.rings.enforcer import RingEnforcer

from agt.policies import EvaluationResult
from agt.policies.kernel import (
    AuditEmissionResult,
    GovernanceEventSpec,
    KernelBridge,
    KernelDecision,
    KernelOutcome,
)


class RecordingSink(GovernanceEventSinkBase):
    """Governance event sink that records delivered events in memory."""

    def __init__(self) -> None:
        self.events: list[GovernanceEvent] = []

    @property
    def count(self) -> int:
        return len(self.events)

    def emit(self, events: Sequence[GovernanceEvent]) -> SinkExportResult:
        self.events.extend(events)
        return SinkExportResult.SUCCESS


class SynchronousAuditEmitter:
    """Map a GovernanceEventSpec to a GovernanceEvent and report delivery.

    A fail-closed audit gate has to KNOW whether the event was delivered before
    it decides ``proceeds``, so delivery must be synchronous and acknowledged.
    The event is emitted directly to the sink and its ``SinkExportResult`` is
    mapped to an ``AuditEmissionResult``: SUCCESS -> ACCEPTED, DROPPED ->
    DROPPED, anything else or a raise -> FAILED, and no sink -> NO_SINK.

    Note the deliberate choice NOT to route the gate ack through
    ``agent_os.event_sink.GovernanceEventProcessor``: its ``on_event`` is
    fire-and-forget (a background worker drains the queue and can drop under
    backpressure), so a gate that inferred delivery from it would race the
    worker and could report a delivered event as failed. The processor is the
    right primitive for best-effort async fan-out to downstream SIEM, not for a
    synchronous fail-closed ack.
    """

    def __init__(self, sink: RecordingSink | None) -> None:
        self._sink = sink

    def __call__(self, spec: GovernanceEventSpec) -> AuditEmissionResult:
        try:
            kind = GovernanceEventKind(spec.kind)
        except ValueError:
            kind = GovernanceEventKind.POLICY_CHECK
        event = GovernanceEvent(
            kind=kind,
            severity=spec.severity,
            agent_id=spec.agent_id,
            action=spec.action,
            decision=spec.decision,
            reason=spec.reason,
            attributes=dict(spec.attributes),
        )
        if self._sink is None:
            return AuditEmissionResult.NO_SINK
        try:
            result = self._sink.emit([event])
        except Exception:
            return AuditEmissionResult.FAILED
        if result == SinkExportResult.SUCCESS:
            return AuditEmissionResult.ACCEPTED
        if result == SinkExportResult.DROPPED:
            return AuditEmissionResult.DROPPED
        return AuditEmissionResult.FAILED


@dataclass
class WiredKernel:
    """The bridge plus the concrete subsystems it drives, for inspection."""

    bridge: KernelBridge
    trust: TrustTracker
    sink: RecordingSink | None


def build_wired_kernel(*, with_audit_sink: bool = True) -> WiredKernel:
    """Assemble the real subsystems and inject them into a KernelBridge."""
    trust = TrustTracker()
    sink = RecordingSink() if with_audit_sink else None
    emitter = SynchronousAuditEmitter(sink)
    bridge = KernelBridge(
        trust_tracker=trust,
        emit_event=emitter,
        ring_enforcer=RingEnforcer(),
        action_classifier=ActionClassifier(),
    )
    return WiredKernel(bridge=bridge, trust=trust, sink=sink)


def _reversible_tool(name: str) -> ActionDescriptor:
    """A reversible tool call. required_ring == RING_2_STANDARD."""
    return ActionDescriptor(
        action_id=name,
        name=name,
        execute_api=f"/v1/{name}:run",
        undo_api=f"/v1/{name}:undo",
        reversibility=ReversibilityLevel.FULL,
        undo_window_seconds=300,
    )


def _non_reversible_tool(name: str) -> ActionDescriptor:
    """A non-reversible tool call. required_ring == RING_1_PRIVILEGED."""
    return ActionDescriptor(
        action_id=name,
        name=name,
        execute_api=f"/v1/{name}:run",
        reversibility=ReversibilityLevel.NONE,
    )


def _acs_decision(verdict: str, reason: str = "") -> KernelDecision:
    """Build the normalized decision from a real ACS EvaluationResult.

    ``EvaluationResult`` is exactly what ``agt.policies.runtime.AgtRuntime.evaluate``
    returns, so this is the true ACS -> kernel seam without needing OPA wired up.
    """
    return KernelDecision.from_evaluation_result(
        EvaluationResult(verdict=verdict, reason=reason)
    )


def run_demo() -> dict[str, KernelOutcome]:
    """Run three scenarios and return their outcomes for inspection/tests."""
    wired = build_wired_kernel()
    bridge = wired.bridge
    outcomes: dict[str, KernelOutcome] = {}

    # A. ACS deny on a reversible tool call. One apply() lowers trust, emits a
    #    policy_violation, and demotes the agent's ring.
    outcomes["deny"] = bridge.apply(
        _acs_decision("deny", reason="blocked_pattern_input"),
        agent_id="agent-a",
        peer_id="orchestrator",
        action=_reversible_tool("send_email"),
        current_ring=ExecutionRing.RING_2_STANDARD,
    )

    # B. ACS allow, but the agent's ring is insufficient for a non-reversible
    #    action. The composite gate blocks even though ACS permitted.
    outcomes["allow_ring_blocked"] = bridge.apply(
        _acs_decision("allow"),
        agent_id="agent-b",
        peer_id="orchestrator",
        action=_non_reversible_tool("delete_account"),
        current_ring=ExecutionRing.RING_3_SANDBOX,
    )

    # C. ACS allow on a reversible action the agent's ring permits. Proceeds,
    #    trust is rewarded, and a policy_check is emitted.
    outcomes["allow_ok"] = bridge.apply(
        _acs_decision("allow"),
        agent_id="agent-c",
        peer_id="orchestrator",
        action=_reversible_tool("fetch_doc"),
        current_ring=ExecutionRing.RING_2_STANDARD,
    )

    return outcomes


def main() -> None:
    outcomes = run_demo()
    for label, out in outcomes.items():
        print(f"[{label}]")
        print(f"  effective_decision : {out.effective_decision}")
        print(f"  proceeds           : {out.proceeds}")
        print(f"  trust_score        : {out.trust_score:.3f} (delta {out.trust_delta:+.3f})")
        print(f"  ring               : {out.ring}  demoted={out.demoted}")
        print(f"  ring_allowed       : {out.ring_allowed}")
        print(f"  audit              : {out.audit.value}")
        print(f"  event.kind         : {out.event.kind}")
        if out.blocked_reason:
            print(f"  blocked_reason     : {out.blocked_reason}")
        print()


if __name__ == "__main__":
    main()
