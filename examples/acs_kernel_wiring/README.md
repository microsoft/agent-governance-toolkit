# Wiring ACS verdicts into the AGT kernel

This example shows how one ACS decision drives the three AGT kernel subsystems
that are otherwise disconnected islands a host has to wire by hand:

- **trust**  `agentmesh.trust_types.TrustTracker`
- **audit**  `agent_os.event_sink` sink SPI (`GovernanceEvent` + `SinkExportResult`)
- **rings**  `hypervisor.rings.RingEnforcer` and `ActionClassifier`

`agt.policies.kernel.KernelBridge` is the glue. It is a dependency-injected,
fail-closed composite gate. Given one `KernelDecision` (built from the
`EvaluationResult` that `AgtRuntime.evaluate` returns) it updates trust, emits one
governance event, evaluates the ring, and returns a single `KernelOutcome`.

`KernelOutcome.proceeds` is the AND of every gate:

```
proceeds = ACS permits AND ring check allows AND (audit accepted, when strict) AND no dependency error
```

An ACS `allow` is necessary but not sufficient: the action is still blocked if
the agent's ring is insufficient or the governance event could not be delivered.

## Why the bridge is dependency-injected

`agt-policies` does not depend on `agentmesh`, `agent_os` or `hypervisor`, and
`agent_os` already imports `agt.policies`. The bridge takes those subsystems as
injected Protocol implementations, so it never imports them and no import cycle
forms. This example module is where the concrete subsystems meet the bridge.

## Run

From the repository root:

```bash
PYTHONPATH=agent-governance-python/agt-policies/src \
    python examples/acs_kernel_wiring/wire_acs_into_kernel.py
```

## Expected output

Three scenarios:

| Scenario | ACS decision | Ring situation | Result |
|----------|--------------|----------------|--------|
| `deny` | deny on a reversible tool | agent at RING_2 | trust drops, `policy_violation` emitted, ring demoted to RING_3, `proceeds=False` |
| `allow_ring_blocked` | allow on a non-reversible action | agent at RING_3, action needs RING_1 | ring check blocks despite the allow, `proceeds=False` |
| `allow_ok` | allow on a reversible action | agent at RING_2, action needs RING_2 | trust rewarded, `policy_check` emitted, `proceeds=True` |

The `deny` scenario is the repro from the task flipping: a single
`KernelBridge.apply(...)` call now lowers trust, emits the governance event, and
trips the ring, instead of the host doing all three by hand.

Demotion is deliberately a reaction to a penalizing decision only. A permitting
decision never trips a ring, because agentmesh reputation and hypervisor
`eff_score` are different scales (a neutral agentmesh 0.5 is below the RING_2
floor of 0.60), and trust is never used to auto-promote a ring.

## Test

```bash
PYTHONPATH=agent-governance-python/agt-policies/src \
    python -m pytest examples/acs_kernel_wiring/test_wiring.py -q
```

## Cleanup

No files, threads, or external services are created. The audit sink is a plain
in-memory recorder and the gate delivers to it synchronously.

## Notes

The audit event is delivered SYNCHRONOUSLY to the sink so the gate can know
whether it landed before deciding `proceeds`. The example deliberately does not
route the gate ack through `agent_os.event_sink.GovernanceEventProcessor`: its
`on_event` is fire-and-forget (a background worker drains the queue and can drop
under backpressure), so a gate that inferred delivery from it would race the
worker. The processor is the right primitive for best-effort async fan-out to
downstream SIEM, not for a synchronous fail-closed ack.

`agent-hypervisor` emits a deprecation warning pointing at
`agent-governance-toolkit-core`; the example uses it because it is the module that
exposes `RingEnforcer` / `ActionClassifier` today. The bridge itself is
subsystem-agnostic, so swapping the ring implementation only changes this wiring
module, not `KernelBridge`.
