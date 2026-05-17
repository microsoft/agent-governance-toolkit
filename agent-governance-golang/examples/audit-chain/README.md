# Audit Chain

Appends three governance decisions to an `AuditLogger`, prints the SHA-256
hash chain linking them, and demonstrates that `Verify()` reports an intact
chain. Also shows that `GetEntries` returns *clones*: callers cannot mutate
stored records through returned pointers.

Covers [`audit.go`](../../packages/agentmesh/audit.go): `NewAuditLogger`,
`Log`, `Verify`, `GetEntries`, `ExportJSON`, `AuditFilter`.

## Why no "tamper a record" demo

The internal entries slice is unexported. There is no public `Set` or
`Update` on `AuditLogger` — the only mutator is `Log`, which appends. So
external code has no path to tamper with a stored record through the SDK
API; the design assumption is that any chain break would come from
storage-layer corruption or a buggy migration script, both of which
`Verify()` catches by recomputing each entry's hash from its fields and
comparing against the stored `Hash`.

## Run it

```bash
go run .
```

## Expected output

```text
logged data.read    decision=allow   hash=<12 hex>... prev=(genesis)
logged data.write   decision=review  hash=<12 hex>... prev=<12 hex>...
logged shell:rm     decision=deny    hash=<12 hex>... prev=<12 hex>...

Verify (clean chain): true
Verify after caller mutates a returned clone: true

Exported chain (~600 bytes): [{"timestamp":"...","agent_id":"did:agentmesh:reader",...}…
```

## Where to go next

- [`identity-sign-verify/`](../identity-sign-verify/) — sign the agent
  identities that appear in audit entries.
- [`policy-yaml/`](../policy-yaml/) — drive the `decision` field from a
  declarative ruleset rather than hand-rolled constants.
- [`../README.md`](../../README.md) — full SDK overview.
