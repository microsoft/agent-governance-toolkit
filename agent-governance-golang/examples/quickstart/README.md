# Go Quickstart

A minimal, runnable program that shows how to add the
[AgentMesh Go SDK](../../README.md) to a Go application.

In about 45 lines of [`main.go`](./main.go) it covers:

- Constructing an `agentmesh.NewClient(...)` with capabilities and a small
  set of `PolicyRule`s (allow / review / deny)
- Calling `client.ExecuteWithGovernance(action, params)` for several
  actions and printing the `Decision`, `Allowed` flag, and trust score
- Verifying the hash-chained audit log with `client.Audit.Verify()`

## Prerequisites

- [Go 1.25+](https://go.dev/dl/) — matches `go 1.25` in
  [`agent-governance-golang/go.mod`](../../go.mod).

## Run it

From this directory:

```bash
go run .
```

Or, equivalently, from the SDK root:

```bash
cd agent-governance-golang
go run ./examples/quickstart
```

You should see output similar to:

```text
Agent identity: did:agentmesh:quickstart-agent

data.read    allowed=true  decision=allow    trust=0.50 (medium)
data.write   allowed=false decision=review   trust=0.55 (medium)
shell:rm     allowed=false decision=deny     trust=0.55 (medium)

Audit chain intact: true
```

## Where to go next

- **Full feature tour** — [`agent-governance-golang/README.md`](../../README.md)
- **HTTP middleware example** — [`../http-middleware/`](../http-middleware/)
- **SLO tracking example** — [`../slo-tracking/`](../slo-tracking/)
- **Cross-language equivalents**
  - .NET — [`agent-governance-dotnet/examples/Quickstart/`](../../../agent-governance-dotnet/examples/Quickstart/)
  - Rust — [`agent-governance-rust/examples/quickstart.rs`](../../../agent-governance-rust/examples/quickstart.rs)
  - TypeScript — [`agent-governance-typescript/examples/quickstart.ts`](../../../agent-governance-typescript/examples/quickstart.ts)
  - Python — [`examples/quickstart/`](../../../examples/quickstart/)
