# ASP.NET Core Middleware Example

A minimal ASP.NET Core 8 web app that wires the
[Microsoft.AgentGovernance](../../README.md) SDK in as **HTTP middleware**.
Every inbound request is converted to a synthetic tool call of the form
`HTTP_{METHOD}_{routeTemplate}` and evaluated by the `GovernanceKernel`
**before** it reaches any controller.

Denied requests short-circuit with a structured JSON body and the right
status code (`403` for policy denials, `429` for rate limits).

## What it shows

- Registering the kernel as a singleton in `IServiceCollection`
- A reusable `GovernanceCheckMiddleware` that:
  - resolves an agent identity (authenticated user → `X-Agent-Id` header → anonymous DID)
  - normalizes the route template (strips constraints like `{id:int}` → `{id}`)
  - calls `kernel.EvaluateToolCall(...)` and translates the decision to HTTP
  - **fails closed** if evaluation throws
- An opt-out marker (`SkipGovernanceAttribute`) for endpoints like `/healthz`
- Two controllers (`ItemsController`, `AdminController`) and a YAML policy
  exercising `allow`, `deny`, `rate_limit`, and `require_approval` actions

## Files

| File | Purpose |
|------|---------|
| `Program.cs` | Web host setup, kernel DI registration, middleware + controllers wiring, audit-event logging. |
| `GovernanceCheckMiddleware.cs` | The reusable middleware. Translates `ToolCallResult` into HTTP responses. |
| `SkipGovernanceAttribute.cs` | Endpoint metadata marker that bypasses the middleware (used by `/healthz`). |
| `Controllers/ItemsController.cs` | Tiny in-memory CRUD API (`/api/items`). |
| `Controllers/AdminController.cs` | Sensitive `/admin/reset` endpoint that requires approval. |
| `policies/aspnet.yaml` | Sample policy with deny / rate-limit / require-approval rules. |
| `appsettings.json` | Logging defaults; binds to `http://localhost:5080`. |
| `AspNetMiddleware.csproj` | `net8.0` web project; `ProjectReference` to the in-tree SDK. |

## Run it

> Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download).

From this directory:

```bash
dotnet run
```

You should see:

```text
info: Microsoft.Hosting.Lifetime[14]
      Now listening on: http://localhost:5080
info: Microsoft.Hosting.Lifetime[0]
      Application started. Press Ctrl+C to shut down.
```

In a second terminal, drive the API:

```bash
# 200 — bypasses governance via SkipGovernanceAttribute
curl -i http://localhost:5080/healthz

# 200 — read endpoints fall through to the default-allow policy
curl -i http://localhost:5080/api/items

# 403 — blocked by the deny-item-delete rule
curl -i -X DELETE http://localhost:5080/api/items/1

# 403 with action=requireapproval — admin endpoints need a human
curl -i -X POST http://localhost:5080/admin/reset

# 5 successes followed by 429 (rate-limit-item-writes is 5/minute)
for i in 1 2 3 4 5 6 7; do
  curl -s -o /dev/null -w "%{http_code} " \
    -X POST -H "Content-Type: application/json" \
    -d "{\"name\":\"n$i\"}" \
    http://localhost:5080/api/items
done
echo
```

Example denial body:

```json
{
  "error": "policy_denied",
  "agent_id": "did:agentmesh:http-anonymous",
  "tool": "HTTP_DELETE_/api/items/{id}",
  "rule": "deny-item-delete",
  "policy": "aspnet-middleware-policy",
  "action": "deny",
  "reason": "Matched rule 'deny-item-delete' with action 'Deny'.",
  "approvers": [],
  "rate_limit_reset": null
}
```

## Identifying the agent

The middleware resolves the calling agent in this order:

1. `HttpContext.User.Identity.Name` (when authentication is configured)
2. `X-Agent-Id` request header
3. Falls back to `did:agentmesh:http-anonymous`

For production, replace step 2 with a verified token (JWT / mTLS / DID auth)
and rely solely on `User.Identity`.

## Try it yourself

Edit `policies/aspnet.yaml` to:

- Switch `default_action` from `allow` to `deny` for a fail-closed posture
- Add a per-tenant rule, e.g.

  ```yaml
  - name: block-tenant-x
    condition: "agent_id == 'did:agentmesh:tenant-x'"
    action: deny
    priority: 200
  ```

- Tighten the rate limit (`limit: "1/minute"`) and rerun the curl loop

## Where to go next

- **Quickstart console app** — [`../Quickstart/`](../Quickstart/)
- **Full feature tour** — [`agent-governance-dotnet/README.md`](../../README.md)
- **MCP server integration** — `Microsoft.AgentGovernance.Extensions.ModelContextProtocol`
- **Microsoft Agent Framework integration** — `Microsoft.AgentGovernance.Extensions.Microsoft.Agents`
