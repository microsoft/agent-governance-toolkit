# Kill Switch Scopes

Activates kill switches at all three scopes in turn — agent, capability,
global — and prints `DecisionFor(agent, capability)` after each step so
you can see exactly how the scope hierarchy resolves. Ends by dumping the
recorded history.

`DecisionFor` checks the global scope first, then agent-specific, then
capability-specific. The first active match short-circuits and the
returned `Scope` tells you which one fired.

Covers [`kill_switch.go`](../../packages/agentmesh/kill_switch.go):
`NewKillSwitchRegistry`, `Activate`, `Clear`, `DecisionFor`, `History`,
and the `GlobalKillSwitchScope` / `AgentKillSwitchScope` /
`CapabilityKillSwitchScope` constructors.

## Run it

```bash
go run .
```

## Expected output

```text
baseline:                                agent=agent-A         tool=tool.run     allowed=true  blocked_by=-
baseline:                                agent=agent-B         tool=tool.run     allowed=true  blocked_by=-

[activated agent scope: agent-A]
after agent block:                       agent=agent-A         tool=tool.run     allowed=false blocked_by=agent:agent-A
after agent block:                       agent=agent-B         tool=tool.run     allowed=true  blocked_by=-

[activated capability scope: shell.exec]
after capability block:                  agent=agent-B         tool=shell.exec   allowed=false blocked_by=capability:shell.exec
after capability block:                  agent=agent-B         tool=tool.run     allowed=true  blocked_by=-

[activated global scope]
after global block:                      agent=agent-B         tool=tool.run     allowed=false blocked_by=global
after global block:                      agent=any-other-agent tool=any-tool     allowed=false blocked_by=global

History (3 events recorded):
  agent:agent-A active=true  reason=security_incident
  capability:shell.exec active=true  reason=policy_violation
  global active=true  reason=operator_request
```

## Where to go next

- [`execution-rings/`](../execution-rings/) — ring assignment is
  evaluated *after* kill switches in the pipeline; combine them for
  defence-in-depth.
- [`full-stack/`](../full-stack/) — see `KillSwitchMiddleware` wired
  into a real governance pipeline.
- [`../README.md`](../../README.md) — full SDK overview.
