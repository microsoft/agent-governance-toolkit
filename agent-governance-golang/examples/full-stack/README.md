# Full-Stack Composition

Wires seven subsystems together for a single governed agent — identity,
rings, trust, policy, kill switches, audit, and SLOs — and drives four
operations through the standard middleware stack via `GovernOperation`.

The narrative is:

1. The agent is provisioned with a DID and standard-ring permissions.
2. Three operations run: `data.read` (allowed), `data.write` (reviewed),
   `system.shutdown` (denied). Each outcome updates the trust score.
3. A capability-scoped kill switch is activated on `data.read`. The next
   `data.read` is blocked by the kill switch before policy is consulted.
4. The example prints the SLO report, audit verification, and final
   trust score.

Covers the *interaction* between these modules — the bits that aren't
visible from any individual example. If you only had time to read one
example to understand how the SDK fits together, this is it.

## Run it

```bash
go run .
```

## Expected output

```text
agent identity: did:agentmesh:worker-001

-- ordinary operation --
  read (allowed)       action=data.read     -> allow | trust=0.545 (medium)
  write (review)       action=data.write    -> policy denied action: data.write | trust=0.390 (low)
  escalate (deny)      action=system.shutdown -> policy denied action: system.shutdown | trust=0.236 (low)

-- activate capability kill switch --
  read after kill      action=data.read     -> kill switch active: capability:data.read | trust=0.083 (low)

-- summary --
  SLO data-read-availability: actual=1.00 target=0.99 met=true error_budget_remaining=0.01
  Audit chain intact: true
  Audit entries logged: 8
  Final trust score: 0.083 (low)
```

Trust numbers drift slightly with the default config; the *shape* — one
success and three failures dragging trust from `medium` deep into the
`low` tier — is what matters.

Note the SLO reports `actual=1.00`: `SLOTrackingMiddleware` is innermost
in the stack, so it only records an event when an upstream middleware
actually calls through to it. Policy-denied operations are short-circuited
by `PolicyEvaluationMiddleware` before SLO is reached. The audit log still
captures all 8 entries (start + complete for each of the 4 operations)
because `AuditTrailMiddleware` is the outermost wrapper.

## Where to go next

- [`http-middleware-fail-closed/`](../http-middleware-fail-closed/) —
  put the same governance pipeline behind a real `net/http` server with
  verified identity.
- [`policy-yaml/`](../policy-yaml/) — replace the inline `PolicyRule`
  slice with a YAML-driven ruleset.
- [`../README.md`](../../README.md) — full SDK overview.
