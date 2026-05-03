# HTTP Middleware Example

Run a minimal `net/http` server protected by AgentMesh governance middleware.

```bash
cd agent-governance-golang
go run ./examples/http-middleware
```

Send an allowed request with a trusted migration header:

```bash
curl -H "X-Agent-ID: did:agentmesh:demo" http://localhost:8080/run
```

Requests without `X-Agent-ID` are rejected because `NewHTTPGovernanceMiddleware` requires a verified agent identity resolver.
