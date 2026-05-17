# Policy: OPA & Cedar

Configures the same `PolicyEngine` with two external policy backends in
turn — OPA/Rego and Cedar — both in **builtin** mode so the example runs
without the `opa` or `cedar` CLIs installed. Then sets up a third engine
in OPA `CLI` mode without the CLI present, to demonstrate the engine's
fail-closed behaviour when a backend returns an error.

Covers
[`policy_backends.go`](../../packages/agentmesh/policy_backends.go):
`NewOPABackend`, `NewCedarBackend`, `LoadRego`, `LoadCedar`, the
`OPAOptions` / `CedarOptions` configs, and the `OPABuiltin` /
`OPACLI` / `CedarBuiltin` modes.

## Run it

```bash
go run .
```

## Expected output

```text
== OPA / Rego backend (builtin) ==
  data.read    -> allow
  data.write   -> deny

== Cedar backend (builtin) ==
  data.read    -> allow
  data.write   -> deny

== Fail-closed when backend errors ==
  data.read    -> deny  (no opa CLI available => deny)
```

> The builtin OPA evaluator is a deliberately small subset — strict
> equality, `default` rules, single-line bodies. For complex Rego, use
> `OPARemote` (against an OPA server) or `OPACLI` (with the `opa`
> binary available).

## Where to go next

- [`policy-yaml/`](../policy-yaml/) — the native, in-process equivalent
  with the same `Evaluate(...)` shape.
- [`full-stack/`](../full-stack/) — combine native rules + an external
  backend; native rules win when they match, the backend evaluates
  otherwise.
- [`../README.md`](../../README.md) — full SDK overview.
