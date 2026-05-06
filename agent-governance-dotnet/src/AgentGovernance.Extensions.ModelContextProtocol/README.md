# Microsoft.AgentGovernance.Extensions.ModelContextProtocol

Public Preview companion package for the official Model Context Protocol C# SDK.

## Install

Run `dotnet add package` from the directory that contains your `.csproj`. If you're elsewhere, pass the project path explicitly:

```bash
dotnet add YourApp.csproj package Microsoft.AgentGovernance.Extensions.ModelContextProtocol
```

In Visual Studio Package Manager Console, use:

```powershell
Install-Package Microsoft.AgentGovernance.Extensions.ModelContextProtocol
```

Make sure the correct app is selected in the **Default project** dropdown. Typing the package name by itself at the prompt fails because PowerShell treats it as a command.

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
