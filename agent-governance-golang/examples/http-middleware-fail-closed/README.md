# HTTP Middleware — Fail-Closed Migration

Walks the migration from `LegacyTrustedHeaderAgentIDResolver` to a
production-grade verified `AgentIDResolver`, with a worked HMAC-signed
example.

> **`LegacyTrustedHeaderAgentIDResolver` is a compatibility bridge, not
> a recommended default.** It marks `Verified=true` based solely on an
> attacker-controllable HTTP header — anyone who can reach the endpoint
> can claim to be any agent. This is the *only* example in the gallery
> that uses it, and only to show how to migrate away from it.

The example spins up two `httptest.NewServer` instances on local random
ports (no network listener you need to manage), driven by the same
policy engine but configured with different resolvers:

| Step | Resolver | Verifies | Production-ready |
|---|---|---|---|
| 1 | `LegacyTrustedHeaderAgentIDResolver("X-Agent-ID")` | Header presence only | ❌ |
| 2 | `signedHeaderResolver` (HMAC over agent_id\|\|timestamp) | Cryptographic signature + timestamp window | ✅ (minimum bar) |

Step 2 is intentionally minimal. JWT, mTLS, or a managed identity
provider are stronger production shapes — pick whichever fits your
infrastructure.

Covers the `AgentIDResolver` / `HTTPResolvedAgentIdentity` / `NewHTTPGovernanceMiddleware`
surfaces in [`middleware.go`](../../packages/agentmesh/middleware.go).

## Run it

```bash
go run .
```

## Expected output

```text
== STEP 1: Legacy trusted-header resolver ==
  attacker-posing-as-admin: status=200 body="legacy server: ok"
  no header:                status=403 body="verified agent identity required: ..."

== STEP 2: Signed-credential resolver (production shape) ==
  honest signed request:    status=200 body="verified server: ok"
  forged X-Agent-ID:        status=403 body="verified agent identity required"
  unsigned request:         status=403 body="verified agent identity required"
```

Step 1 returns `200` to an attacker — the whole point. Step 2 returns
`403` to anyone who can't prove they hold the signing secret.

## Migration recipe

1. **Start** with `NewHTTPGovernanceMiddleware` failing closed — it
   already does, as long as `AgentIDResolver` is set. If
   `AgentIDResolver` is `nil`, the middleware refuses to construct.
2. **Bridge** with `LegacyTrustedHeaderAgentIDResolver` *only* while
   you're rolling out a real identity story to clients. Track this with
   a deletion deadline.
3. **Replace** with a resolver that validates a cryptographic credential.
   The `signedHeaderResolver` in this example is the minimum bar; JWT or
   mTLS is preferred.
4. **Delete** the legacy import; CI will catch any straggling callers.

## Where to go next

- [`../http-middleware/`](../http-middleware/) — the original, simpler
  HTTP middleware example. Treat *that* as a reference for the
  middleware shape, and this example as the reference for identity
  verification.
- [`full-stack/`](../full-stack/) — same governance pipeline driven
  synchronously without a `net/http` server.
- [`../README.md`](../../README.md) — full SDK overview.
