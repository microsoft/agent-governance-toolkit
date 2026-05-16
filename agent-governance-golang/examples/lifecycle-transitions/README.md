# Lifecycle Transitions

Walks an agent through `provisioning → active → suspended → active →
quarantined → decommissioning → decommissioned`, prints each recorded
event, then attempts an invalid transition (`decommissioned → active`)
to show the state machine rejecting it.

Covers [`lifecycle.go`](../../packages/agentmesh/lifecycle.go):
`NewLifecycleManager`, `State`, `Transition`, `Events`, and the eight
`State*` constants.

## Run it

```bash
go run .
```

## Expected output

```text
start state: provisioning

provisioning     -> active           reason="provisioning complete"
active           -> suspended        reason="operator paused for maintenance"
suspended        -> active           reason="maintenance complete"
active           -> quarantined      reason="anomalous traffic detected"
quarantined      -> decommissioning  reason="retiring agent"
decommissioning  -> decommissioned   reason="teardown finished"

Attempting invalid transition (decommissioned -> active):
  rejected: invalid transition from decommissioned to active

final state:   decommissioned
event count:   6
```

The valid transition graph is defined in
[`lifecycle.go`](../../packages/agentmesh/lifecycle.go) — `decommissioned`
has no outgoing edges, so any further transition request is rejected.

## Where to go next

- [`kill-switch-scopes/`](../kill-switch-scopes/) — block a *quarantined*
  agent at the gateway before its next request hits policy.
- [`trust-scoring/`](../trust-scoring/) — drive the quarantine transition
  off a falling trust score.
- [`../README.md`](../../README.md) — full SDK overview.
