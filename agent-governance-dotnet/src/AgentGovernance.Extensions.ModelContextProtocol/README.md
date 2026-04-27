# Microsoft.AgentGovernance.Extensions.ModelContextProtocol

Public Preview companion package for the official Model Context Protocol C# SDK.

## Install

```bash
dotnet add package Microsoft.AgentGovernance.Extensions.ModelContextProtocol
```

## Usage

```csharp
using System.Security.Claims;

builder.Services
    .AddMcpServer()
    .WithGovernance(options =>
    {
        options.PolicyPaths.Add("policies/mcp.yaml");
        options.AgentIdResolver = static principal =>
            principal.FindFirst("agent_id")?.Value
            ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    });
```

`WithGovernance(...)` wires governance policy evaluation, MCP tool-definition scanning, fallback tool-call governance, and response sanitization for MCP servers built with `IMcpServerBuilder`.

## Migration notes

- `RequireAuthenticatedAgentId` now defaults to `true`.
- `DefaultAgentId` is only used when you explicitly set `RequireAuthenticatedAgentId = false`.
- `context.Items["agent_id"]` is not used for governance identity resolution.
