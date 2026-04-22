# Microsoft.AgentGovernance.Extensions.ModelContextProtocol

Public Preview companion package for the official Model Context Protocol C# SDK.

## Install

```bash
dotnet add package Microsoft.AgentGovernance.Extensions.ModelContextProtocol
```

## Usage

```csharp
builder.Services
    .AddMcpServer()
    .WithGovernance(options =>
    {
        options.PolicyPaths.Add("policies/mcp.yaml");
    });
```

`WithGovernance(...)` wires governance policy evaluation, MCP tool-definition scanning, fallback tool-call governance, and response sanitization for MCP servers built with `IMcpServerBuilder`.
