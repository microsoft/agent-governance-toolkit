# Execution Rings

Configures the four built-in privilege rings — `RingAdmin` (Ring 0,
wildcard permissions), `RingStandard` (read + write), `RingRestricted`
(read-only), `RingSandboxed` (no actions) — assigns five agents
(including one *unassigned* agent), and prints a grid showing which
actions each agent can run.

Covers [`rings.go`](../../packages/agentmesh/rings.go):
`NewRingEnforcer`, `Assign`, `GetRing`, `CheckAccess`,
`SetRingPermissions`, and the `RingAdmin` / `RingStandard` /
`RingRestricted` / `RingSandboxed` constants.

## Run it

```bash
go run .
```

## Expected output

```text
agent                ring     data.read        data.write       system.shutdown
admin-agent          0        true             true             true
worker-agent         1        true             true             false
readonly-agent       2        true             false            false
sandboxed-agent      3        false            false            false
unassigned-agent     -        false            false            false
```

Note: unassigned agents are denied by default — no implicit ring,
no implicit permissions.

## Where to go next

- [`kill-switch-scopes/`](../kill-switch-scopes/) — block agents at the
  ring above, regardless of their ring assignment.
- [`policy-yaml/`](../policy-yaml/) — drive *which* ring an action falls
  into from a policy file rather than hard-coded permissions.
- [`../README.md`](../../README.md) — full SDK overview.
